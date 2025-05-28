use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use anyhow::Result;
use std::fs;
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
    pub server: ServerConfig,
    pub plugins: PluginConfig,
    pub exploits: ExploitConfig,
    pub collaboration: CollaborationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout: u64,
    pub idle_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub jwt_secret: String,
    pub token_expiry: i64,
    pub refresh_token_expiry: i64,
    pub password_hash_cost: u32,
    pub rate_limit_requests: u32,
    pub rate_limit_duration: u64,
    pub allowed_origins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: PathBuf,
    pub max_size: u64,
    pub max_files: u32,
    pub rotation_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
    pub max_connections: u32,
    pub keep_alive: u64,
    pub timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub marketplace_url: String,
    pub plugin_dir: PathBuf,
    pub max_plugins: usize,
    pub update_check_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitConfig {
    pub metasploit_path: Option<PathBuf>,
    pub metasploit_api_key: Option<String>,
    pub sandbox_dir: PathBuf,
    pub timeout: u64,
    pub memory_limit: u64,
    pub cpu_limit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationConfig {
    pub max_workspaces: usize,
    pub max_members_per_workspace: usize,
    pub event_retention_days: u32,
    pub notification_webhook: Option<String>,
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = env::var("SARISSA_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("config.toml"));

        let config_str = fs::read_to_string(config_path)?;
        let config: Config = toml::from_str(&config_str)?;

        // Validate configuration
        config.validate()?;

        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        // Validate database configuration
        if self.database.max_connections < self.database.min_connections {
            return Err(anyhow::anyhow!("Invalid database connection pool settings"));
        }

        // Validate security configuration
        if self.security.jwt_secret.is_empty() {
            return Err(anyhow::anyhow!("JWT secret cannot be empty"));
        }

        if self.security.token_expiry <= 0 {
            return Err(anyhow::anyhow!("Token expiry must be positive"));
        }

        // Validate logging configuration
        if self.logging.max_size == 0 {
            return Err(anyhow::anyhow!("Log file max size must be positive"));
        }

        // Validate server configuration
        if self.server.port == 0 {
            return Err(anyhow::anyhow!("Server port cannot be 0"));
        }

        if self.server.workers == 0 {
            return Err(anyhow::anyhow!("Number of workers must be positive"));
        }

        // Validate plugin configuration
        if self.plugins.max_plugins == 0 {
            return Err(anyhow::anyhow!("Max plugins must be positive"));
        }

        // Validate exploit configuration
        if self.exploits.timeout == 0 {
            return Err(anyhow::anyhow!("Exploit timeout must be positive"));
        }

        if self.exploits.memory_limit == 0 {
            return Err(anyhow::anyhow!("Memory limit must be positive"));
        }

        // Validate collaboration configuration
        if self.collaboration.max_workspaces == 0 {
            return Err(anyhow::anyhow!("Max workspaces must be positive"));
        }

        if self.collaboration.max_members_per_workspace == 0 {
            return Err(anyhow::anyhow!("Max members per workspace must be positive"));
        }

        Ok(())
    }

    pub fn get_database_url(&self) -> String {
        self.database.url.clone()
    }

    pub fn get_jwt_secret(&self) -> &str {
        &self.security.jwt_secret
    }

    pub fn get_log_level(&self) -> &str {
        &self.logging.level
    }

    pub fn get_server_address(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }
} 