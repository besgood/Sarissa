use std::sync::Arc;
use tokio::sync::RwLock;
use prometheus::{
    Counter, Gauge, Histogram, IntCounter, IntGauge, Registry,
    opts, Encoder, TextEncoder,
};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use anyhow::Result;
use tracing::{info, warn, error};

#[derive(Debug, Clone)]
pub struct Metrics {
    // System metrics
    cpu_usage: Gauge,
    memory_usage: Gauge,
    disk_usage: Gauge,
    active_connections: IntGauge,
    
    // Application metrics
    total_scans: IntCounter,
    active_scans: IntGauge,
    scan_duration: Histogram,
    vulnerabilities_found: IntCounter,
    critical_vulnerabilities: IntCounter,
    
    // Plugin metrics
    plugin_loads: IntCounter,
    plugin_errors: IntCounter,
    plugin_execution_time: Histogram,
    
    // Security metrics
    failed_logins: IntCounter,
    security_events: IntCounter,
    audit_logs: IntCounter,
    
    // Collaboration metrics
    active_users: IntGauge,
    workspace_operations: IntCounter,
    real_time_events: IntCounter,
}

impl Metrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            cpu_usage: Gauge::with_opts(opts!(
                "sarissa_cpu_usage",
                "CPU usage percentage"
            )).unwrap(),
            
            memory_usage: Gauge::with_opts(opts!(
                "sarissa_memory_usage",
                "Memory usage in bytes"
            )).unwrap(),
            
            disk_usage: Gauge::with_opts(opts!(
                "sarissa_disk_usage",
                "Disk usage in bytes"
            )).unwrap(),
            
            active_connections: IntGauge::with_opts(opts!(
                "sarissa_active_connections",
                "Number of active connections"
            )).unwrap(),
            
            total_scans: IntCounter::with_opts(opts!(
                "sarissa_total_scans",
                "Total number of scans performed"
            )).unwrap(),
            
            active_scans: IntGauge::with_opts(opts!(
                "sarissa_active_scans",
                "Number of currently active scans"
            )).unwrap(),
            
            scan_duration: Histogram::with_opts(opts!(
                "sarissa_scan_duration_seconds",
                "Scan duration in seconds"
            )).unwrap(),
            
            vulnerabilities_found: IntCounter::with_opts(opts!(
                "sarissa_vulnerabilities_found",
                "Total number of vulnerabilities found"
            )).unwrap(),
            
            critical_vulnerabilities: IntCounter::with_opts(opts!(
                "sarissa_critical_vulnerabilities",
                "Number of critical vulnerabilities found"
            )).unwrap(),
            
            plugin_loads: IntCounter::with_opts(opts!(
                "sarissa_plugin_loads",
                "Number of plugin loads"
            )).unwrap(),
            
            plugin_errors: IntCounter::with_opts(opts!(
                "sarissa_plugin_errors",
                "Number of plugin errors"
            )).unwrap(),
            
            plugin_execution_time: Histogram::with_opts(opts!(
                "sarissa_plugin_execution_seconds",
                "Plugin execution time in seconds"
            )).unwrap(),
            
            failed_logins: IntCounter::with_opts(opts!(
                "sarissa_failed_logins",
                "Number of failed login attempts"
            )).unwrap(),
            
            security_events: IntCounter::with_opts(opts!(
                "sarissa_security_events",
                "Number of security events"
            )).unwrap(),
            
            audit_logs: IntCounter::with_opts(opts!(
                "sarissa_audit_logs",
                "Number of audit log entries"
            )).unwrap(),
            
            active_users: IntGauge::with_opts(opts!(
                "sarissa_active_users",
                "Number of active users"
            )).unwrap(),
            
            workspace_operations: IntCounter::with_opts(opts!(
                "sarissa_workspace_operations",
                "Number of workspace operations"
            )).unwrap(),
            
            real_time_events: IntCounter::with_opts(opts!(
                "sarissa_real_time_events",
                "Number of real-time events"
            )).unwrap(),
        }
    }

    pub fn record_scan_start(&self) {
        self.active_scans.inc();
        self.total_scans.inc();
    }

    pub fn record_scan_end(&self, duration: Duration) {
        self.active_scans.dec();
        self.scan_duration.observe(duration.as_secs_f64());
    }

    pub fn record_vulnerability(&self, is_critical: bool) {
        self.vulnerabilities_found.inc();
        if is_critical {
            self.critical_vulnerabilities.inc();
        }
    }

    pub fn record_plugin_load(&self) {
        self.plugin_loads.inc();
    }

    pub fn record_plugin_error(&self) {
        self.plugin_errors.inc();
    }

    pub fn record_plugin_execution(&self, duration: Duration) {
        self.plugin_execution_time.observe(duration.as_secs_f64());
    }

    pub fn record_failed_login(&self) {
        self.failed_logins.inc();
    }

    pub fn record_security_event(&self) {
        self.security_events.inc();
    }

    pub fn record_audit_log(&self) {
        self.audit_logs.inc();
    }

    pub fn update_active_users(&self, count: i64) {
        self.active_users.set(count);
    }

    pub fn record_workspace_operation(&self) {
        self.workspace_operations.inc();
    }

    pub fn record_real_time_event(&self) {
        self.real_time_events.inc();
    }
}

#[derive(Debug, Clone)]
pub struct HealthCheck {
    name: String,
    status: Arc<RwLock<HealthStatus>>,
    last_check: Arc<RwLock<Instant>>,
    check_interval: Duration,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy(String),
    Unknown,
}

impl HealthCheck {
    pub fn new(name: &str, check_interval: Duration) -> Self {
        Self {
            name: name.to_string(),
            status: Arc::new(RwLock::new(HealthStatus::Unknown)),
            last_check: Arc::new(RwLock::new(Instant::now())),
            check_interval,
        }
    }

    pub async fn update_status(&self, status: HealthStatus) {
        let mut current_status = self.status.write().await;
        *current_status = status;
        let mut last_check = self.last_check.write().await;
        *last_check = Instant::now();
    }

    pub async fn get_status(&self) -> HealthStatus {
        let status = self.status.read().await;
        status.clone()
    }

    pub async fn is_healthy(&self) -> bool {
        let status = self.status.read().await;
        matches!(*status, HealthStatus::Healthy)
    }

    pub async fn needs_check(&self) -> bool {
        let last_check = self.last_check.read().await;
        last_check.elapsed() >= self.check_interval
    }
}

#[derive(Debug, Clone)]
pub struct MonitoringSystem {
    metrics: Metrics,
    health_checks: Arc<RwLock<HashMap<String, HealthCheck>>>,
    registry: Registry,
}

impl MonitoringSystem {
    pub fn new() -> Self {
        let registry = Registry::new();
        let metrics = Metrics::new(&registry);
        
        Self {
            metrics,
            health_checks: Arc::new(RwLock::new(HashMap::new())),
            registry,
        }
    }

    pub fn get_metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub async fn register_health_check(&self, name: &str, check_interval: Duration) {
        let mut checks = self.health_checks.write().await;
        checks.insert(
            name.to_string(),
            HealthCheck::new(name, check_interval),
        );
    }

    pub async fn update_health_status(&self, name: &str, status: HealthStatus) {
        if let Some(check) = self.health_checks.read().await.get(name) {
            check.update_status(status).await;
        }
    }

    pub async fn get_health_status(&self) -> HashMap<String, HealthStatus> {
        let checks = self.health_checks.read().await;
        checks
            .iter()
            .map(|(name, check)| (name.clone(), check.get_status().await))
            .collect()
    }

    pub async fn get_metrics_text(&self) -> Result<String> {
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }

    pub async fn run_health_checks(&self) {
        let checks = self.health_checks.read().await;
        for (name, check) in checks.iter() {
            if check.needs_check().await {
                // Perform health check
                let status = self.perform_health_check(name).await;
                check.update_status(status).await;
            }
        }
    }

    async fn perform_health_check(&self, name: &str) -> HealthStatus {
        match name {
            "database" => self.check_database().await,
            "plugin_system" => self.check_plugin_system().await,
            "security_manager" => self.check_security_manager().await,
            "collaboration" => self.check_collaboration().await,
            _ => HealthStatus::Unknown,
        }
    }

    async fn check_database(&self) -> HealthStatus {
        // Implement database health check
        HealthStatus::Healthy
    }

    async fn check_plugin_system(&self) -> HealthStatus {
        // Implement plugin system health check
        HealthStatus::Healthy
    }

    async fn check_security_manager(&self) -> HealthStatus {
        // Implement security manager health check
        HealthStatus::Healthy
    }

    async fn check_collaboration(&self) -> HealthStatus {
        // Implement collaboration system health check
        HealthStatus::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_metrics() {
        let monitoring = MonitoringSystem::new();
        let metrics = monitoring.get_metrics();

        metrics.record_scan_start();
        assert_eq!(metrics.active_scans.get(), 1);

        metrics.record_scan_end(Duration::from_secs(5));
        assert_eq!(metrics.active_scans.get(), 0);

        metrics.record_vulnerability(true);
        assert_eq!(metrics.vulnerabilities_found.get(), 1);
        assert_eq!(metrics.critical_vulnerabilities.get(), 1);
    }

    #[tokio::test]
    async fn test_health_checks() {
        let monitoring = MonitoringSystem::new();
        
        monitoring.register_health_check("test", Duration::from_secs(1)).await;
        monitoring.update_health_status("test", HealthStatus::Healthy).await;
        
        let status = monitoring.get_health_status().await;
        assert_eq!(status.get("test"), Some(&HealthStatus::Healthy));
        
        sleep(Duration::from_secs(2)).await;
        monitoring.run_health_checks().await;
        
        let status = monitoring.get_health_status().await;
        assert_eq!(status.get("test"), Some(&HealthStatus::Unknown));
    }
} 