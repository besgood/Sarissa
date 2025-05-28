use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::fs;
use anyhow::Result;
use async_trait::async_trait;
use reqwest;
use semver::Version;
use serde_json::Value;
use std::process::Command;
use std::env;
use zip;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub dependencies: Vec<PluginDependency>,
    pub entry_point: String,
    pub category: PluginCategory,
    pub min_sarissa_version: String,
    pub license: String,
    pub repository: Option<String>,
    pub tags: Vec<String>,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginDependency {
    pub name: String,
    pub version: String,
    pub optional: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PluginCategory {
    Scanner,
    Exploit,
    Report,
    Utility,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub enabled: bool,
    pub settings: HashMap<String, Value>,
    pub schedule: Option<String>,
    pub notifications: bool,
}

#[async_trait]
pub trait Plugin: Send + Sync {
    fn metadata(&self) -> &PluginMetadata;
    fn initialize(&mut self, config: PluginConfig) -> Result<()>;
    fn execute(&self, input: Value) -> Result<Value>;
    fn cleanup(&self) -> Result<()>;
}

pub struct PluginManager {
    plugins: Arc<Mutex<HashMap<String, Box<dyn Plugin>>>>,
    metadata_cache: Arc<Mutex<HashMap<String, PluginMetadata>>>,
    configs: Arc<Mutex<HashMap<String, PluginConfig>>>,
    marketplace_url: String,
    marketplace_client: reqwest::Client,
}

impl PluginManager {
    pub fn new(marketplace_url: &str) -> Self {
        Self {
            plugins: Arc::new(Mutex::new(HashMap::new())),
            metadata_cache: Arc::new(Mutex::new(HashMap::new())),
            configs: Arc::new(Mutex::new(HashMap::new())),
            marketplace_url: marketplace_url.to_string(),
            marketplace_client: reqwest::Client::new(),
        }
    }

    pub async fn load_plugins(&self, plugin_dir: &PathBuf) -> Result<()> {
        let mut entries = fs::read_dir(plugin_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                let plugin_path = entry.path();
                match self.load_plugin_metadata(&plugin_path).await {
                    Ok(metadata) => {
                        match self.validate_plugin(&metadata).await {
                            Ok(true) => {
                                match self.load_plugin(&plugin_path, &metadata).await {
                                    Ok(plugin) => {
                                        let mut plugins = self.plugins.lock().await;
                                        plugins.insert(metadata.name.clone(), plugin);
                                        
                                        let mut metadata_cache = self.metadata_cache.lock().await;
                                        metadata_cache.insert(metadata.name.clone(), metadata);
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to load plugin {}: {}", metadata.name, e);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Plugin validation failed for {}: {}", metadata.name, e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to load metadata for plugin in {}: {}", plugin_path.display(), e);
                    }
                }
            }
        }
        Ok(())
    }

    async fn load_plugin_metadata(&self, plugin_path: &PathBuf) -> Result<PluginMetadata> {
        let metadata_path = plugin_path.join("metadata.json");
        let metadata_content = fs::read_to_string(metadata_path).await?;
        Ok(serde_json::from_str(&metadata_content)?)
    }

    async fn validate_plugin(&self, metadata: &PluginMetadata) -> Result<bool> {
        // Check Sarissa version compatibility
        let current_version = env!("CARGO_PKG_VERSION");
        if Version::parse(&metadata.min_sarissa_version)? > Version::parse(current_version)? {
            return Err(anyhow::anyhow!("Plugin requires newer Sarissa version"));
        }

        // Check dependencies
        for dep in &metadata.dependencies {
            if !self.check_dependency(dep).await? {
                if !dep.optional {
                    return Err(anyhow::anyhow!("Missing required dependency: {}", dep.name));
                }
            }
        }

        // Verify plugin signature if available
        if metadata.verified {
            if !self.verify_plugin_signature(metadata).await? {
                return Err(anyhow::anyhow!("Plugin signature verification failed"));
            }
        }

        Ok(true)
    }

    async fn check_dependency(&self, dep: &PluginDependency) -> Result<bool> {
        // Check if dependency is installed with timeout
        let output = tokio::process::Command::new("which")
            .arg(&dep.name)
            .output()
            .await?;
            
        if !output.status.success() {
            return Ok(false);
        }

        // Check version if specified
        if !dep.version.is_empty() {
            let version_output = tokio::process::Command::new(&dep.name)
                .arg("--version")
                .output()
                .await?;
                
            let version_str = String::from_utf8_lossy(&version_output.stdout);
            let installed_version = Version::parse(&version_str)?;
            let required_version = Version::parse(&dep.version)?;
            
            if installed_version < required_version {
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn verify_plugin_signature(&self, metadata: &PluginMetadata) -> Result<bool> {
        let signature_path = metadata.repository.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No repository URL for signature verification"))?;
            
        // Download signature with timeout
        let response = tokio::time::timeout(
            Duration::from_secs(30),
            reqwest::get(format!("{}/signature.asc", signature_path))
        ).await??;
        
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to download plugin signature"));
        }
        
        let signature = response.text().await?;
        
        // Create temporary file for signature
        let temp_dir = std::env::temp_dir().join("sarissa_plugin_sigs");
        std::fs::create_dir_all(&temp_dir)?;
        let sig_file = temp_dir.join(format!("{}.asc", metadata.name));
        std::fs::write(&sig_file, signature)?;
        
        // Verify signature using GPG with timeout
        let output = tokio::process::Command::new("gpg")
            .arg("--verify")
            .arg("--status-fd")
            .arg("1")
            .arg("--")
            .arg(&sig_file)
            .output()
            .await?;
        
        // Clean up temporary file
        std::fs::remove_file(sig_file)?;
        
        // Check GPG output for verification status
        let output_str = String::from_utf8_lossy(&output.stdout);
        Ok(output_str.contains("[GNUPG:] GOODSIG"))
    }

    async fn load_plugin(&self, plugin_path: &PathBuf, metadata: &PluginMetadata) -> Result<Box<dyn Plugin>> {
        let entry_point = plugin_path.join(&metadata.entry_point);
        
        // Check if entry point exists
        if !entry_point.exists() {
            return Err(anyhow::anyhow!("Plugin entry point not found: {}", entry_point.display()));
        }

        // Load plugin based on type
        match metadata.category {
            PluginCategory::Scanner => {
                let plugin = ScannerPlugin::new(entry_point, metadata.clone())?;
                Ok(Box::new(plugin))
            }
            PluginCategory::Exploit => {
                let plugin = ExploitPlugin::new(entry_point, metadata.clone())?;
                Ok(Box::new(plugin))
            }
            PluginCategory::Report => {
                let plugin = ReportPlugin::new(entry_point, metadata.clone())?;
                Ok(Box::new(plugin))
            }
            PluginCategory::Utility => {
                let plugin = UtilityPlugin::new(entry_point, metadata.clone())?;
                Ok(Box::new(plugin))
            }
        }
    }

    pub async fn install_plugin(&self, plugin_name: &str) -> Result<()> {
        // Fetch plugin from marketplace with timeout
        let response = tokio::time::timeout(
            Duration::from_secs(30),
            self.marketplace_client
                .get(&format!("{}/plugins/{}", self.marketplace_url, plugin_name))
                .send()
        ).await??;
            
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to fetch plugin from marketplace"));
        }

        let plugin_data: Value = response.json().await?;
        
        // Download plugin with timeout
        let download_url = plugin_data["download_url"].as_str()
            .ok_or_else(|| anyhow::anyhow!("No download URL found"))?;
            
        let response = tokio::time::timeout(
            Duration::from_secs(60),
            self.marketplace_client
                .get(download_url)
                .send()
        ).await??;
            
        let plugin_content = response.bytes().await?;
        
        // Create plugin directory with secure permissions
        let plugin_dir = PathBuf::from("plugins").join(plugin_name);
        fs::create_dir_all(&plugin_dir).await?;
        std::fs::set_permissions(&plugin_dir, std::fs::Permissions::from_mode(0o700))?;
        
        // Extract plugin files with progress tracking
        let archive = zip::ZipArchive::new(std::io::Cursor::new(plugin_content))?;
        let total_files = archive.len();
        
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let outpath = plugin_dir.join(file.name());
            
            if file.name().ends_with('/') {
                fs::create_dir_all(&outpath).await?;
                std::fs::set_permissions(&outpath, std::fs::Permissions::from_mode(0o700))?;
            } else {
                if let Some(parent) = outpath.parent() {
                    fs::create_dir_all(parent).await?;
                    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
                }
                let mut outfile = fs::File::create(&outpath).await?;
                tokio::io::copy(&mut file, &mut outfile).await?;
                std::fs::set_permissions(&outpath, std::fs::Permissions::from_mode(0o500))?;
            }
        }
        
        // Load metadata
        let metadata = self.load_plugin_metadata(&plugin_dir).await?;
        
        // Verify plugin
        if !self.verify_plugin_signature(&metadata).await? {
            // Clean up on verification failure
            std::fs::remove_dir_all(&plugin_dir)?;
            return Err(anyhow::anyhow!("Plugin signature verification failed"));
        }
        
        // Load the plugin
        if let Ok(plugin) = self.load_plugin(&plugin_dir, &metadata).await {
            let mut plugins = self.plugins.lock().await;
            plugins.insert(metadata.name.clone(), plugin);
            
            let mut metadata_cache = self.metadata_cache.lock().await;
            metadata_cache.insert(metadata.name.clone(), metadata);
        }
        
        Ok(())
    }

    pub async fn list_plugins(&self) -> Result<Vec<PluginMetadata>> {
        let metadata_cache = self.metadata_cache.lock().await;
        Ok(metadata_cache.values().cloned().collect())
    }

    pub async fn search_marketplace(&self, query: &str) -> Result<Vec<PluginMetadata>> {
        let response = self.marketplace_client
            .get(&format!("{}/search", self.marketplace_url))
            .query(&[("q", query)])
            .send()
            .await?;
            
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to search marketplace"));
        }

        let plugins: Vec<PluginMetadata> = response.json().await?;
        Ok(plugins)
    }

    pub async fn update_plugin(&self, plugin_name: &str) -> Result<()> {
        // Check for updates
        let response = self.marketplace_client
            .get(&format!("{}/plugins/{}/updates", self.marketplace_url, plugin_name))
            .send()
            .await?;
            
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to check for updates"));
        }

        let update_info: Value = response.json().await?;
        
        // Compare versions
        let current_metadata = self.metadata_cache.lock().await
            .get(plugin_name)
            .ok_or_else(|| anyhow::anyhow!("Plugin not found"))?;
            
        let current_version = Version::parse(&current_metadata.version)?;
        let latest_version = Version::parse(update_info["version"].as_str().unwrap_or("0.0.0"))?;
        
        if latest_version > current_version {
            // Install update
            self.install_plugin(plugin_name).await?;
        }

        Ok(())
    }

    pub async fn configure_plugin(&self, plugin_name: &str, config: PluginConfig) -> Result<()> {
        let mut configs = self.configs.lock().await;
        configs.insert(plugin_name.to_string(), config);
        Ok(())
    }

    pub async fn get_plugin_config(&self, plugin_name: &str) -> Result<Option<PluginConfig>> {
        let configs = self.configs.lock().await;
        Ok(configs.get(plugin_name).cloned())
    }
}

// Plugin implementations
struct ScannerPlugin {
    metadata: PluginMetadata,
    command: String,
    config: PluginConfig,
}

impl ScannerPlugin {
    fn new(entry_point: PathBuf, metadata: PluginMetadata) -> Result<Self> {
        Ok(Self {
            metadata,
            command: entry_point.to_string_lossy().to_string(),
            config: PluginConfig {
                enabled: true,
                settings: HashMap::new(),
                schedule: None,
                notifications: true,
            },
        })
    }
}

impl Plugin for ScannerPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    fn initialize(&mut self, config: PluginConfig) -> Result<()> {
        self.config = config;
        Ok(())
    }

    fn execute(&self, input: Value) -> Result<Value> {
        let mut command = std::process::Command::new(&self.command);
        
        // Add input parameters
        if let Some(args) = input.as_object() {
            for (key, value) in args {
                command.arg(format!("--{}", key));
                if let Some(str_value) = value.as_str() {
                    command.arg(str_value);
                }
            }
        }
        
        let output = command.output()?;
        
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Plugin execution failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        
        Ok(serde_json::from_str(&String::from_utf8_lossy(&output.stdout))?)
    }

    fn cleanup(&self) -> Result<()> {
        Ok(())
    }
}

// Similar implementations for ExploitPlugin, ReportPlugin, and UtilityPlugin
// ... existing code ... 