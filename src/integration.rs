use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use anyhow::Result;
use reqwest::Client;
use tokio::sync::mpsc;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    pub name: String,
    pub api_key: Option<String>,
    pub base_url: String,
    pub enabled: bool,
    pub webhook_url: Option<String>,
    pub rate_limit: Option<u32>,
    pub timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityData {
    pub cve_id: String,
    pub description: String,
    pub cvss_score: f32,
    pub affected_products: Vec<String>,
    pub references: Vec<String>,
    pub published_date: DateTime<Utc>,
    pub last_modified_date: DateTime<Utc>,
}

pub struct IntegrationManager {
    configs: Arc<Mutex<HashMap<String, IntegrationConfig>>>,
    client: Client,
    webhook_sender: mpsc::Sender<WebhookEvent>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookEvent {
    pub event_type: String,
    pub payload: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

impl IntegrationManager {
    pub fn new() -> Self {
        let (tx, _) = mpsc::channel(100);
        Self {
            configs: Arc::new(Mutex::new(HashMap::new())),
            client: Client::new(),
            webhook_sender: tx,
        }
    }

    pub async fn add_integration(&self, config: IntegrationConfig) -> Result<()> {
        let mut configs = self.configs.lock().await;
        configs.insert(config.name.clone(), config);
        Ok(())
    }

    pub async fn remove_integration(&self, name: &str) -> Result<()> {
        let mut configs = self.configs.lock().await;
        configs.remove(name);
        Ok(())
    }

    pub async fn get_integration(&self, name: &str) -> Option<IntegrationConfig> {
        let configs = self.configs.lock().await;
        configs.get(name).cloned()
    }

    pub async fn list_integrations(&self) -> Vec<IntegrationConfig> {
        let configs = self.configs.lock().await;
        configs.values().cloned().collect()
    }

    // NVD API Integration
    pub async fn fetch_cve_details(&self, cve_id: &str) -> Result<VulnerabilityData> {
        let config = self.get_integration("nvd").await
            .ok_or_else(|| anyhow::anyhow!("NVD integration not configured"))?;

        let url = format!("{}/rest/json/cve/2.0?cveId={}", config.base_url, cve_id);
        let response = self.client
            .get(&url)
            .header("apiKey", config.api_key.unwrap_or_default())
            .timeout(std::time::Duration::from_secs(config.timeout))
            .send()
            .await?;

        let data: serde_json::Value = response.json().await?;
        
        // Parse NVD response
        let vuln = data["vulnerabilities"][0]["cve"].clone();
        Ok(VulnerabilityData {
            cve_id: cve_id.to_string(),
            description: vuln["descriptions"][0]["value"].as_str().unwrap_or("").to_string(),
            cvss_score: vuln["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
                .as_f64()
                .unwrap_or(0.0) as f32,
            affected_products: vuln["configurations"][0]["nodes"][0]["cpeMatch"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .map(|cpe| cpe["criteria"].as_str().unwrap_or("").to_string())
                .collect(),
            references: vuln["references"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .map(|ref_| ref_["url"].as_str().unwrap_or("").to_string())
                .collect(),
            published_date: DateTime::parse_from_rfc3339(
                vuln["published"].as_str().unwrap_or("")
            ).unwrap_or_else(|_| Utc::now()).into(),
            last_modified_date: DateTime::parse_from_rfc3339(
                vuln["lastModified"].as_str().unwrap_or("")
            ).unwrap_or_else(|_| Utc::now()).into(),
        })
    }

    // Vulners API Integration
    pub async fn search_vulnerabilities(&self, query: &str) -> Result<Vec<VulnerabilityData>> {
        let config = self.get_integration("vulners").await
            .ok_or_else(|| anyhow::anyhow!("Vulners integration not configured"))?;

        let url = format!("{}/api/v3/search/lucene/", config.base_url);
        let response = self.client
            .post(&url)
            .header("X-Vulners-Api-Key", config.api_key.unwrap_or_default())
            .json(&serde_json::json!({
                "query": query,
                "size": 10
            }))
            .timeout(std::time::Duration::from_secs(config.timeout))
            .send()
            .await?;

        let data: serde_json::Value = response.json().await?;
        
        // Parse Vulners response
        let vulns = data["data"]["search"].as_array()
            .ok_or_else(|| anyhow::anyhow!("Invalid response format"))?;

        let mut results = Vec::new();
        for vuln in vulns {
            results.push(VulnerabilityData {
                cve_id: vuln["cve"]["id"].as_str().unwrap_or("").to_string(),
                description: vuln["description"].as_str().unwrap_or("").to_string(),
                cvss_score: vuln["cvss"]["score"].as_f64().unwrap_or(0.0) as f32,
                affected_products: vuln["affectedSoftware"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|sw| sw["name"].as_str().unwrap_or("").to_string())
                    .collect(),
                references: vuln["references"]
                    .as_array()
                    .unwrap_or(&vec![])
                    .iter()
                    .map(|ref_| ref_["url"].as_str().unwrap_or("").to_string())
                    .collect(),
                published_date: DateTime::parse_from_rfc3339(
                    vuln["published"].as_str().unwrap_or("")
                ).unwrap_or_else(|_| Utc::now()).into(),
                last_modified_date: DateTime::parse_from_rfc3339(
                    vuln["modified"].as_str().unwrap_or("")
                ).unwrap_or_else(|_| Utc::now()).into(),
            });
        }

        Ok(results)
    }

    // Webhook Integration
    pub async fn send_webhook(&self, event: WebhookEvent) -> Result<()> {
        let configs = self.configs.lock().await;
        for config in configs.values() {
            if let Some(webhook_url) = &config.webhook_url {
                let response = self.client
                    .post(webhook_url)
                    .json(&event)
                    .timeout(std::time::Duration::from_secs(config.timeout))
                    .send()
                    .await?;

                if !response.status().is_success() {
                    eprintln!("Failed to send webhook to {}: {}", webhook_url, response.status());
                }
            }
        }
        Ok(())
    }

    // CI/CD Integration
    pub async fn export_to_ci(&self, data: &serde_json::Value, format: &str) -> Result<()> {
        let config = self.get_integration("ci").await
            .ok_or_else(|| anyhow::anyhow!("CI integration not configured"))?;

        let url = format!("{}/api/v1/security/scan", config.base_url);
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", config.api_key.unwrap_or_default()))
            .json(&serde_json::json!({
                "format": format,
                "data": data
            }))
            .timeout(std::time::Duration::from_secs(config.timeout))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to export to CI: {}",
                response.status()
            ));
        }

        Ok(())
    }

    // Export to Security Tools
    pub async fn export_to_security_tool(&self, data: &serde_json::Value, tool: &str) -> Result<()> {
        let config = self.get_integration(tool).await
            .ok_or_else(|| anyhow::anyhow!("{} integration not configured", tool))?;

        let url = format!("{}/api/v1/import", config.base_url);
        let response = self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", config.api_key.unwrap_or_default()))
            .json(data)
            .timeout(std::time::Duration::from_secs(config.timeout))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to export to {}: {}",
                tool,
                response.status()
            ));
        }

        Ok(())
    }
} 