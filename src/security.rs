use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::Mutex;
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use argon2::{self, Config};
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use std::path::PathBuf;
use tokio::fs;
use serde_json::Value;
use uuid::Uuid;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    SecurityAnalyst,
    Operator,
    Viewer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub role: UserRole,
    pub permissions: Vec<String>,
    pub last_login: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub token_expiry: i64,
    pub refresh_token_expiry: i64,
    pub password_hash_cost: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub user_id: Uuid,
    pub action: String,
    pub resource: String,
    pub details: Value,
    pub ip_address: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub severity: SecuritySeverity,
    pub category: SecurityCategory,
    pub description: String,
    pub source: String,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityCategory {
    Authentication,
    Authorization,
    DataAccess,
    System,
    Network,
    Other,
}

pub struct SecurityManager {
    users: Arc<RwLock<HashMap<Uuid, User>>>,
    auth_config: AuthConfig,
    audit_logs: Arc<RwLock<Vec<AuditLog>>>,
    security_events: Arc<RwLock<Vec<SecurityEvent>>>,
    session_tokens: Arc<RwLock<HashMap<String, Uuid>>>,
}

impl SecurityManager {
    pub fn new(auth_config: AuthConfig) -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            auth_config,
            audit_logs: Arc::new(RwLock::new(Vec::new())),
            security_events: Arc::new(RwLock::new(Vec::new())),
            session_tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // User Management
    pub async fn create_user(&self, username: &str, email: &str, password: &str, role: UserRole) -> Result<Uuid> {
        let mut users = self.users.write().await;
        
        // Check if user already exists
        if users.values().any(|u| u.username == username || u.email == email) {
            return Err(anyhow::anyhow!("User already exists"));
        }

        // Hash password
        let salt: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .collect();
        
        let config = Config {
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
            mem_cost: self.auth_config.password_hash_cost,
            time_cost: 3,
            lanes: 4,
            thread_mode: argon2::ThreadMode::Parallel,
            secret: &[],
            ad: &[],
            hash_length: 32,
        };

        let password_hash = argon2::hash_encoded(
            password.as_bytes(),
            salt.as_bytes(),
            &config,
        )?;

        let user = User {
            id: Uuid::new_v4(),
            username: username.to_string(),
            email: email.to_string(),
            role,
            permissions: Vec::new(),
            last_login: None,
            is_active: true,
        };

        users.insert(user.id, user.clone());
        Ok(user.id)
    }

    // Authentication
    pub async fn authenticate_user(&self, username: &str, password: &str, ip_address: &str) -> Result<String> {
        let users = self.users.read().await;
        let user = users.values()
            .find(|u| u.username == username && u.is_active)
            .ok_or_else(|| anyhow::anyhow!("Invalid credentials"))?;

        // Check for failed login attempts
        let failed_attempts = self.get_failed_login_attempts(username).await?;
        if failed_attempts >= 5 {
            self.log_security_event(
                SecuritySeverity::High,
                SecurityCategory::Authentication,
                "Account locked due to multiple failed login attempts",
                "authentication",
                serde_json::json!({
                    "username": username,
                    "ip_address": ip_address,
                    "failed_attempts": failed_attempts,
                }),
            ).await?;
            return Err(anyhow::anyhow!("Account locked due to multiple failed login attempts"));
        }

        // Verify password
        let config = Config {
            variant: argon2::Variant::Argon2id,
            version: argon2::Version::Version13,
            mem_cost: self.auth_config.password_hash_cost,
            time_cost: 3,
            lanes: 4,
            thread_mode: argon2::ThreadMode::Parallel,
            secret: &[],
            ad: &[],
            hash_length: 32,
        };

        let password_hash = argon2::hash_encoded(
            password.as_bytes(),
            &[], // Salt should be stored with the hash
            &config,
        )?;

        if !argon2::verify_encoded(&password_hash, password.as_bytes())? {
            self.increment_failed_login_attempts(username).await?;
            self.log_audit_event(
                user.id,
                "login_failed",
                "authentication",
                serde_json::json!({
                    "username": username,
                    "ip_address": ip_address,
                    "failed_attempts": failed_attempts + 1,
                }),
                ip_address,
                false,
            ).await?;
            return Err(anyhow::anyhow!("Invalid credentials"));
        }

        // Reset failed login attempts on successful login
        self.reset_failed_login_attempts(username).await?;

        // Generate session token with expiration
        let token = Uuid::new_v4().to_string();
        let expiry = Utc::now() + chrono::Duration::seconds(self.auth_config.token_expiry);
        
        let mut session_tokens = self.session_tokens.write().await;
        session_tokens.insert(token.clone(), user.id);

        // Update last login
        let mut users = self.users.write().await;
        if let Some(user) = users.get_mut(&user.id) {
            user.last_login = Some(Utc::now());
        }

        // Log successful login
        self.log_audit_event(
            user.id,
            "login_success",
            "authentication",
            serde_json::json!({
                "username": username,
                "ip_address": ip_address,
                "session_id": token,
                "expiry": expiry,
            }),
            ip_address,
            true,
        ).await?;

        Ok(token)
    }

    async fn get_failed_login_attempts(&self, username: &str) -> Result<u32> {
        // TODO: Implement proper storage of failed login attempts
        // For now, return 0
        Ok(0)
    }

    async fn increment_failed_login_attempts(&self, username: &str) -> Result<()> {
        // TODO: Implement proper storage of failed login attempts
        Ok(())
    }

    async fn reset_failed_login_attempts(&self, username: &str) -> Result<()> {
        // TODO: Implement proper storage of failed login attempts
        Ok(())
    }

    pub async fn log_security_event(
        &self,
        severity: SecuritySeverity,
        category: SecurityCategory,
        description: &str,
        source: &str,
        details: Value,
    ) -> Result<()> {
        let event = SecurityEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            severity,
            category,
            description: description.to_string(),
            source: source.to_string(),
            details,
        };

        let mut security_events = self.security_events.write().await;
        security_events.push(event.clone());

        // Persist to file
        let log_dir = PathBuf::from("logs");
        fs::create_dir_all(&log_dir).await?;
        
        let log_file = log_dir.join(format!(
            "security_{}.json",
            Utc::now().format("%Y%m%d")
        ));

        let mut events = if log_file.exists().await {
            let content = fs::read_to_string(&log_file).await?;
            serde_json::from_str(&content)?
        } else {
            Vec::new()
        };

        events.push(event);
        fs::write(&log_file, serde_json::to_string_pretty(&events)?).await?;

        // Check for critical events that need immediate attention
        if severity == SecuritySeverity::Critical {
            self.handle_critical_event(&event).await?;
        }

        Ok(())
    }

    async fn handle_critical_event(&self, event: &SecurityEvent) -> Result<()> {
        // TODO: Implement critical event handling (e.g., notifications, alerts)
        Ok(())
    }

    pub async fn validate_token(&self, token: &str) -> Result<User> {
        let session_tokens = self.session_tokens.read().await;
        let user_id = session_tokens.get(token)
            .ok_or_else(|| anyhow::anyhow!("Invalid session token"))?;

        let users = self.users.read().await;
        let user = users.get(user_id)
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        // Check if user is still active
        if !user.is_active {
            return Err(anyhow::anyhow!("User account is inactive"));
        }

        // Check if token has expired
        let validation = Validation::new(Algorithm::HS256);
        let token_data = decode::<Value>(
            token,
            &DecodingKey::from_secret(self.auth_config.jwt_secret.as_bytes()),
            &validation,
        )?;

        let expiry = token_data.claims["exp"].as_i64()
            .ok_or_else(|| anyhow::anyhow!("Invalid token expiry"))?;

        if expiry < Utc::now().timestamp() {
            return Err(anyhow::anyhow!("Token has expired"));
        }

        Ok(user.clone())
    }

    pub async fn revoke_token(&self, token: &str) -> Result<()> {
        let mut session_tokens = self.session_tokens.write().await;
        if let Some(user_id) = session_tokens.remove(token) {
            self.log_audit_event(
                user_id,
                "token_revoked",
                "authentication",
                serde_json::json!({
                    "token": token,
                }),
                "system",
                true,
            ).await?;
        }
        Ok(())
    }

    // Audit Logging
    pub async fn log_audit_event(
        &self,
        user_id: Uuid,
        action: &str,
        resource: &str,
        details: Value,
        ip_address: &str,
        success: bool,
    ) -> Result<()> {
        let log = AuditLog {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            user_id,
            action: action.to_string(),
            resource: resource.to_string(),
            details,
            ip_address: ip_address.to_string(),
            success,
        };

        let mut audit_logs = self.audit_logs.write().await;
        audit_logs.push(log);

        // Persist to file
        let log_dir = PathBuf::from("logs");
        fs::create_dir_all(&log_dir).await?;
        
        let log_file = log_dir.join(format!(
            "audit_{}.json",
            Utc::now().format("%Y%m%d")
        ));

        let mut logs = if log_file.exists().await {
            let content = fs::read_to_string(&log_file).await?;
            serde_json::from_str(&content)?
        } else {
            Vec::new()
        };

        logs.push(log);
        fs::write(&log_file, serde_json::to_string_pretty(&logs)?).await?;

        Ok(())
    }

    // Role-based Access Control
    pub async fn verify_permission(&self, token: &str, permission: &str) -> Result<bool> {
        let session_tokens = self.session_tokens.read().await;
        let user_id = session_tokens.get(token)
            .ok_or_else(|| anyhow::anyhow!("Invalid session token"))?;

        let users = self.users.read().await;
        let user = users.get(user_id)
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;

        Ok(user.permissions.contains(&permission.to_string()))
    }

    // Session Management
    pub async fn create_session(&self, user_id: &str) -> Result<String> {
        let refresh_token: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .collect();

        // Store refresh token with expiry
        let expiry = Utc::now() + chrono::Duration::seconds(self.auth_config.refresh_token_expiry);
        
        // TODO: Store refresh token in database/cache
        
        Ok(refresh_token)
    }

    pub async fn validate_session(&self, refresh_token: &str) -> Result<String> {
        // TODO: Validate refresh token from database/cache
        // For now, just return a new JWT token
        let users = self.users.read().await;
        let user = users.values()
            .find(|u| u.is_active)
            .ok_or_else(|| anyhow::anyhow!("No active users found"))?;

        let claims = serde_json::json!({
            "sub": user.id,
            "exp": (Utc::now() + chrono::Duration::seconds(self.auth_config.token_expiry)).timestamp(),
            "role": user.role,
        });

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.auth_config.jwt_secret.as_bytes()),
        )?;

        Ok(token)
    }

    pub async fn get_audit_logs(
        &self,
        user_id: Option<Uuid>,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
    ) -> Result<Vec<AuditLog>> {
        let audit_logs = self.audit_logs.read().await;
        let mut filtered_logs = audit_logs.clone();

        if let Some(user_id) = user_id {
            filtered_logs.retain(|log| log.user_id == user_id);
        }

        if let Some(start_time) = start_time {
            filtered_logs.retain(|log| log.timestamp >= start_time);
        }

        if let Some(end_time) = end_time {
            filtered_logs.retain(|log| log.timestamp <= end_time);
        }

        Ok(filtered_logs)
    }

    pub async fn get_security_events(
        &self,
        severity: Option<SecuritySeverity>,
        category: Option<SecurityCategory>,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
    ) -> Result<Vec<SecurityEvent>> {
        let security_events = self.security_events.read().await;
        let mut filtered_events = security_events.clone();

        if let Some(severity) = severity {
            filtered_events.retain(|event| event.severity == severity);
        }

        if let Some(category) = category {
            filtered_events.retain(|event| event.category == category);
        }

        if let Some(start_time) = start_time {
            filtered_events.retain(|event| event.timestamp >= start_time);
        }

        if let Some(end_time) = end_time {
            filtered_events.retain(|event| event.timestamp <= end_time);
        }

        Ok(filtered_events)
    }

    pub async fn update_user_role(&self, user_id: Uuid, new_role: UserRole) -> Result<()> {
        let mut users = self.users.write().await;
        if let Some(user) = users.get_mut(&user_id) {
            user.role = new_role;
            Ok(())
        } else {
            Err(anyhow::anyhow!("User not found"))
        }
    }

    pub async fn deactivate_user(&self, user_id: Uuid) -> Result<()> {
        let mut users = self.users.write().await;
        if let Some(user) = users.get_mut(&user_id) {
            user.is_active = false;
            Ok(())
        } else {
            Err(anyhow::anyhow!("User not found"))
        }
    }
} 