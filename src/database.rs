use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use anyhow::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn new(url: &str, max_connections: u32, min_connections: u32) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .min_connections(min_connections)
            .acquire_timeout(Duration::from_secs(30))
            .idle_timeout(Duration::from_secs(300))
            .connect(url)
            .await?;

        Ok(Self { pool })
    }

    pub async fn init(&self) -> Result<()> {
        // Create tables if they don't exist
        sqlx::query(include_str!("../migrations/init.sql"))
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    // User Management
    pub async fn create_user(&self, user: &User) -> Result<()> {
        sqlx::query(
            "INSERT INTO users (id, username, email, role, permissions, last_login, is_active)
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(user.id)
        .bind(&user.username)
        .bind(&user.email)
        .bind(&user.role)
        .bind(&user.permissions)
        .bind(user.last_login)
        .bind(user.is_active)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_user(&self, id: Uuid) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            "SELECT * FROM users WHERE id = $1",
            id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn update_user(&self, user: &User) -> Result<()> {
        sqlx::query(
            "UPDATE users 
             SET username = $1, email = $2, role = $3, permissions = $4, 
                 last_login = $5, is_active = $6
             WHERE id = $7"
        )
        .bind(&user.username)
        .bind(&user.email)
        .bind(&user.role)
        .bind(&user.permissions)
        .bind(user.last_login)
        .bind(user.is_active)
        .bind(user.id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Session Management
    pub async fn create_session(&self, session: &Session) -> Result<()> {
        sqlx::query(
            "INSERT INTO sessions (id, user_id, token, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(session.id)
        .bind(session.user_id)
        .bind(&session.token)
        .bind(session.expires_at)
        .bind(session.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_session(&self, token: &str) -> Result<Option<Session>> {
        let session = sqlx::query_as!(
            Session,
            "SELECT * FROM sessions WHERE token = $1 AND expires_at > $2",
            token,
            Utc::now()
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(session)
    }

    pub async fn delete_session(&self, token: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    // Audit Logging
    pub async fn log_audit_event(&self, event: &AuditLog) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_logs (id, timestamp, user_id, action, resource, details, ip_address, success)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
        )
        .bind(event.id)
        .bind(event.timestamp)
        .bind(event.user_id)
        .bind(&event.action)
        .bind(&event.resource)
        .bind(&event.details)
        .bind(&event.ip_address)
        .bind(event.success)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_audit_logs(
        &self,
        user_id: Option<Uuid>,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        limit: Option<i64>,
    ) -> Result<Vec<AuditLog>> {
        let mut query = String::from(
            "SELECT * FROM audit_logs WHERE 1=1"
        );

        if let Some(user_id) = user_id {
            query.push_str(&format!(" AND user_id = '{}'", user_id));
        }

        if let Some(start_time) = start_time {
            query.push_str(&format!(" AND timestamp >= '{}'", start_time));
        }

        if let Some(end_time) = end_time {
            query.push_str(&format!(" AND timestamp <= '{}'", end_time));
        }

        query.push_str(" ORDER BY timestamp DESC");

        if let Some(limit) = limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }

        let logs = sqlx::query_as::<_, AuditLog>(&query)
            .fetch_all(&self.pool)
            .await?;

        Ok(logs)
    }

    // Workspace Management
    pub async fn create_workspace(&self, workspace: &Workspace) -> Result<()> {
        sqlx::query(
            "INSERT INTO workspaces (id, name, description, owner_id, created_at, updated_at, settings)
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(workspace.id)
        .bind(&workspace.name)
        .bind(&workspace.description)
        .bind(workspace.owner_id)
        .bind(workspace.created_at)
        .bind(workspace.updated_at)
        .bind(&workspace.settings)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_workspace(&self, id: Uuid) -> Result<Option<Workspace>> {
        let workspace = sqlx::query_as!(
            Workspace,
            "SELECT * FROM workspaces WHERE id = $1",
            id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(workspace)
    }

    pub async fn update_workspace(&self, workspace: &Workspace) -> Result<()> {
        sqlx::query(
            "UPDATE workspaces 
             SET name = $1, description = $2, owner_id = $3, 
                 updated_at = $4, settings = $5
             WHERE id = $6"
        )
        .bind(&workspace.name)
        .bind(&workspace.description)
        .bind(workspace.owner_id)
        .bind(workspace.updated_at)
        .bind(&workspace.settings)
        .bind(workspace.id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Plugin Management
    pub async fn store_plugin(&self, plugin: &Plugin) -> Result<()> {
        sqlx::query(
            "INSERT INTO plugins (id, name, version, description, author, entry_point, 
                                category, min_sarissa_version, license, repository, tags, verified)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"
        )
        .bind(plugin.id)
        .bind(&plugin.name)
        .bind(&plugin.version)
        .bind(&plugin.description)
        .bind(&plugin.author)
        .bind(&plugin.entry_point)
        .bind(&plugin.category)
        .bind(&plugin.min_sarissa_version)
        .bind(&plugin.license)
        .bind(&plugin.repository)
        .bind(&plugin.tags)
        .bind(plugin.verified)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_plugin(&self, id: Uuid) -> Result<Option<Plugin>> {
        let plugin = sqlx::query_as!(
            Plugin,
            "SELECT * FROM plugins WHERE id = $1",
            id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(plugin)
    }

    pub async fn list_plugins(&self) -> Result<Vec<Plugin>> {
        let plugins = sqlx::query_as!(
            Plugin,
            "SELECT * FROM plugins ORDER BY name"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(plugins)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub role: String,
    pub permissions: Vec<String>,
    pub last_login: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditLog {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub user_id: Uuid,
    pub action: String,
    pub resource: String,
    pub details: serde_json::Value,
    pub ip_address: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Workspace {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub owner_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub settings: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Plugin {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub entry_point: String,
    pub category: String,
    pub min_sarissa_version: String,
    pub license: String,
    pub repository: Option<String>,
    pub tags: Vec<String>,
    pub verified: bool,
} 