use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use anyhow::Result;
use tokio::sync::{mpsc, RwLock, broadcast};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::Mutex;
use reqwest;
use serde_json::Value;
use std::time::Duration;
use uuid::Uuid;
use tokio::time;
use futures::StreamExt;
use tokio_tungstenite::{connect_async, WebSocketStream};
use tokio_tungstenite::tungstenite::Message;
use futures::SinkExt;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub owner_id: Uuid,
    pub members: HashSet<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub settings: WorkspaceSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSettings {
    pub allow_guest_access: bool,
    pub require_approval: bool,
    pub max_members: usize,
    pub retention_period: i64, // in days
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceMember {
    pub user_id: Uuid,
    pub role: WorkspaceRole,
    pub joined_at: DateTime<Utc>,
    pub last_active: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WorkspaceRole {
    Owner,
    Admin,
    Member,
    Guest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationEvent {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    pub event_type: CollaborationEventType,
    pub timestamp: DateTime<Utc>,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CollaborationEventType {
    UserJoined,
    UserLeft,
    ScanStarted,
    ScanCompleted,
    ExploitExecuted,
    ReportGenerated,
    CommentAdded,
    StatusChanged,
}

pub struct CollaborationManager {
    workspaces: Arc<RwLock<HashMap<Uuid, Workspace>>>,
    members: Arc<RwLock<HashMap<Uuid, HashMap<Uuid, WorkspaceMember>>>>,
    active_users: Arc<RwLock<HashMap<Uuid, HashSet<Uuid>>>>,
    event_sender: broadcast::Sender<CollaborationEvent>,
}

struct WebSocketServer {
    listener: TcpListener,
    clients: Arc<Mutex<HashMap<String, WebSocketClient>>>,
}

struct WebSocketClient {
    stream: WebSocketStream<tokio::net::TcpStream>,
    user_id: String,
    workspace_id: String,
}

struct NotificationClient {
    client: reqwest::Client,
    settings: NotificationSettings,
}

impl CollaborationManager {
    pub fn new() -> Self {
        let (event_sender, _) = broadcast::channel(1000);
        Self {
            workspaces: Arc::new(RwLock::new(HashMap::new())),
            members: Arc::new(RwLock::new(HashMap::new())),
            active_users: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
        }
    }

    pub async fn create_workspace(
        &self,
        name: &str,
        description: &str,
        owner_id: Uuid,
        settings: WorkspaceSettings,
    ) -> Result<Uuid> {
        // Validate workspace name
        if name.is_empty() || name.len() > 100 {
            return Err(anyhow::anyhow!("Invalid workspace name"));
        }

        // Validate description
        if description.len() > 1000 {
            return Err(anyhow::anyhow!("Description too long"));
        }

        // Validate settings
        if settings.max_members == 0 || settings.max_members > 1000 {
            return Err(anyhow::anyhow!("Invalid max members value"));
        }

        if settings.retention_period < 0 || settings.retention_period > 365 {
            return Err(anyhow::anyhow!("Invalid retention period"));
        }

        let workspace_id = Uuid::new_v4();
        let now = Utc::now();

        let workspace = Workspace {
            id: workspace_id,
            name: name.to_string(),
            description: description.to_string(),
            owner_id,
            members: HashSet::new(),
            created_at: now,
            updated_at: now,
            settings,
        };

        // Add owner as first member
        let member = WorkspaceMember {
            user_id: owner_id,
            role: WorkspaceRole::Owner,
            joined_at: now,
            last_active: now,
        };

        let mut workspaces = self.workspaces.write().await;
        workspaces.insert(workspace_id, workspace);

        let mut members = self.members.write().await;
        members.insert(workspace_id, HashMap::new());
        members.get_mut(&workspace_id).unwrap().insert(owner_id, member);

        // Notify about workspace creation
        self.broadcast_event(
            workspace_id,
            owner_id,
            CollaborationEventType::UserJoined,
            serde_json::json!({
                "workspace_name": name,
                "role": "Owner",
                "event": "workspace_created",
            }),
        ).await?;

        Ok(workspace_id)
    }

    pub async fn join_workspace(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        role: WorkspaceRole,
    ) -> Result<()> {
        let mut workspaces = self.workspaces.write().await;
        let workspace = workspaces.get_mut(&workspace_id)
            .ok_or_else(|| anyhow::anyhow!("Workspace not found"))?;

        // Check if workspace is full
        if workspace.members.len() >= workspace.settings.max_members {
            return Err(anyhow::anyhow!("Workspace is full"));
        }

        // Check if user is already a member
        if workspace.members.contains(&user_id) {
            return Err(anyhow::anyhow!("User is already a member"));
        }

        // Check if approval is required
        if workspace.settings.require_approval {
            // TODO: Implement approval workflow
            return Err(anyhow::anyhow!("Workspace requires approval to join"));
        }

        // Add user to workspace
        workspace.members.insert(user_id);
        workspace.updated_at = Utc::now();

        let member = WorkspaceMember {
            user_id,
            role,
            joined_at: Utc::now(),
            last_active: Utc::now(),
        };

        let mut members = self.members.write().await;
        members.get_mut(&workspace_id)
            .ok_or_else(|| anyhow::anyhow!("Workspace members not found"))?
            .insert(user_id, member);

        // Update active users
        let mut active_users = self.active_users.write().await;
        active_users.entry(workspace_id)
            .or_insert_with(HashSet::new)
            .insert(user_id);

        // Notify about user joining
        self.broadcast_event(
            workspace_id,
            user_id,
            CollaborationEventType::UserJoined,
            serde_json::json!({
                "workspace_name": workspace.name,
                "role": format!("{:?}", role),
                "event": "user_joined",
            }),
        ).await?;

        Ok(())
    }

    pub async fn leave_workspace(&self, workspace_id: Uuid, user_id: Uuid) -> Result<()> {
        let mut workspaces = self.workspaces.write().await;
        let workspace = workspaces.get_mut(&workspace_id)
            .ok_or_else(|| anyhow::anyhow!("Workspace not found"))?;

        // Remove user from workspace
        workspace.members.remove(&user_id);
        workspace.updated_at = Utc::now();

        let mut members = self.members.write().await;
        members.get_mut(&workspace_id)
            .ok_or_else(|| anyhow::anyhow!("Workspace members not found"))?
            .remove(&user_id);

        // Update active users
        let mut active_users = self.active_users.write().await;
        if let Some(users) = active_users.get_mut(&workspace_id) {
            users.remove(&user_id);
        }

        // Notify about user leaving
        self.broadcast_event(
            workspace_id,
            user_id,
            CollaborationEventType::UserLeft,
            serde_json::json!({
                "workspace_name": workspace.name,
            }),
        ).await?;

        Ok(())
    }

    pub async fn update_user_presence(&self, workspace_id: Uuid, user_id: Uuid) -> Result<()> {
        let mut members = self.members.write().await;
        if let Some(workspace_members) = members.get_mut(&workspace_id) {
            if let Some(member) = workspace_members.get_mut(&user_id) {
                member.last_active = Utc::now();
            }
        }

        let mut active_users = self.active_users.write().await;
        active_users.entry(workspace_id)
            .or_insert_with(HashSet::new)
            .insert(user_id);

        Ok(())
    }

    pub async fn get_workspace_members(&self, workspace_id: Uuid) -> Result<Vec<WorkspaceMember>> {
        let members = self.members.read().await;
        let workspace_members = members.get(&workspace_id)
            .ok_or_else(|| anyhow::anyhow!("Workspace not found"))?;

        Ok(workspace_members.values().cloned().collect())
    }

    pub async fn get_active_users(&self, workspace_id: Uuid) -> Result<HashSet<Uuid>> {
        let active_users = self.active_users.read().await;
        Ok(active_users.get(&workspace_id)
            .cloned()
            .unwrap_or_default())
    }

    pub async fn broadcast_event(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        event_type: CollaborationEventType,
        details: serde_json::Value,
    ) -> Result<()> {
        let event = CollaborationEvent {
            id: Uuid::new_v4(),
            workspace_id,
            user_id,
            event_type,
            timestamp: Utc::now(),
            details,
        };

        // Send event to all subscribers
        self.event_sender.send(event.clone())?;

        // Store event for history
        self.store_event(&event).await?;

        // Send notifications if needed
        self.send_notifications(&event).await?;

        Ok(())
    }

    pub fn subscribe_to_events(&self) -> broadcast::Receiver<CollaborationEvent> {
        self.event_sender.subscribe()
    }

    pub async fn update_workspace_settings(
        &self,
        workspace_id: Uuid,
        settings: WorkspaceSettings,
        user_id: Uuid,
    ) -> Result<()> {
        let mut workspaces = self.workspaces.write().await;
        let workspace = workspaces.get_mut(&workspace_id)
            .ok_or_else(|| anyhow::anyhow!("Workspace not found"))?;

        // Check if user has permission to update settings
        let members = self.members.read().await;
        let workspace_members = members.get(&workspace_id)
            .ok_or_else(|| anyhow::anyhow!("Workspace members not found"))?;

        let member = workspace_members.get(&user_id)
            .ok_or_else(|| anyhow::anyhow!("User is not a member"))?;

        match member.role {
            WorkspaceRole::Owner | WorkspaceRole::Admin => {
                // Validate new settings
                if settings.max_members == 0 || settings.max_members > 1000 {
                    return Err(anyhow::anyhow!("Invalid max members value"));
                }

                if settings.retention_period < 0 || settings.retention_period > 365 {
                    return Err(anyhow::anyhow!("Invalid retention period"));
                }

                workspace.settings = settings;
                workspace.updated_at = Utc::now();

                // Notify about settings update
                self.broadcast_event(
                    workspace_id,
                    user_id,
                    CollaborationEventType::StatusChanged,
                    serde_json::json!({
                        "event": "settings_updated",
                        "updated_by": user_id,
                    }),
                ).await?;

                Ok(())
            }
            _ => Err(anyhow::anyhow!("Insufficient permissions")),
        }
    }

    pub async fn transfer_ownership(
        &self,
        workspace_id: Uuid,
        current_owner_id: Uuid,
        new_owner_id: Uuid,
    ) -> Result<()> {
        let mut workspaces = self.workspaces.write().await;
        let workspace = workspaces.get_mut(&workspace_id)
            .ok_or_else(|| anyhow::anyhow!("Workspace not found"))?;

        if workspace.owner_id != current_owner_id {
            return Err(anyhow::anyhow!("Only the owner can transfer ownership"));
        }

        let mut members = self.members.write().await;
        let workspace_members = members.get_mut(&workspace_id)
            .ok_or_else(|| anyhow::anyhow!("Workspace members not found"))?;

        // Update roles
        if let Some(current_owner) = workspace_members.get_mut(&current_owner_id) {
            current_owner.role = WorkspaceRole::Member;
        }

        if let Some(new_owner) = workspace_members.get_mut(&new_owner_id) {
            new_owner.role = WorkspaceRole::Owner;
        }

        workspace.owner_id = new_owner_id;
        workspace.updated_at = Utc::now();

        // Notify about ownership transfer
        self.broadcast_event(
            workspace_id,
            current_owner_id,
            CollaborationEventType::StatusChanged,
            serde_json::json!({
                "event": "ownership_transferred",
                "new_owner_id": new_owner_id,
            }),
        ).await?;

        Ok(())
    }

    async fn store_event(&self, event: &CollaborationEvent) -> Result<()> {
        // TODO: Implement event storage in database
        Ok(())
    }

    async fn send_notifications(&self, event: &CollaborationEvent) -> Result<()> {
        let notification_client = NotificationClient {
            client: reqwest::Client::new(),
            settings: NotificationSettings {
                email: true,
                slack: true,
                webhook: Some("https://webhook.example.com".to_string()),
            },
        };

        notification_client.send_notification(event).await?;
        Ok(())
    }
}

impl NotificationClient {
    async fn send_notification(&self, event: &CollaborationEvent) -> Result<()> {
        // Send email notification
        if self.settings.email {
            self.send_email_notification(event).await?;
        }
        
        // Send Slack notification
        if self.settings.slack {
            self.send_slack_notification(event).await?;
        }
        
        // Send webhook notification
        if let Some(webhook_url) = &self.settings.webhook {
            self.send_webhook_notification(event, webhook_url).await?;
        }
        
        Ok(())
    }

    async fn send_email_notification(&self, event: &CollaborationEvent) -> Result<()> {
        // TODO: Implement email notification using a proper email service
        Ok(())
    }

    async fn send_slack_notification(&self, event: &CollaborationEvent) -> Result<()> {
        // TODO: Implement Slack notification using Slack API
        Ok(())
    }

    async fn send_webhook_notification(&self, event: &CollaborationEvent, webhook_url: &str) -> Result<()> {
        let response = self.client
            .post(webhook_url)
            .json(event)
            .timeout(Duration::from_secs(10))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to send webhook notification"));
        }

        Ok(())
    }
} 