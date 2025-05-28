use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;
use std::net::{SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use regex;
use chrono::{DateTime, Utc, Duration as ChronoDuration};
use std::collections::HashMap;
use std::path::PathBuf;
use std::fs;
use csv::Writer;
use rust_xlsxwriter::{Workbook, Format};
use ipnetwork::IpNetwork;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::sync::mpsc;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid;
use reqwest;
use serde_json::Value;
use std::io::Write;
use xml::reader::{EventReader, XmlEvent};

/// The result of a network scan, including open ports, OS info, and host enrichment.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanResult {
    pub target: String,
    pub open_ports: Vec<PortInfo>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub os_info: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub reverse_dns: Option<String>,
    pub geoip: Option<String>,
}

/// Information about an open port and its detected service/version.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: Protocol,
    pub service: Option<String>,
    pub version: Option<String>,
    pub state: PortState,
}

/// A known vulnerability (CVE) affecting a service/port.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vulnerability {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub cve: Option<String>,
    pub affected_ports: Vec<u16>,
}

/// A known vulnerability (CVE) affecting a service/port.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Protocol {
    TCP,
    UDP,
}

/// A known vulnerability (CVE) affecting a service/port.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

/// A known vulnerability (CVE) affecting a service/port.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Asynchronous network scanner using nmap as a backend.
pub struct NetworkScanner {
    scan_timeout: Duration,
    max_concurrent_scans: usize,
    targets: Arc<Mutex<HashMap<String, Target>>>,
    scan_config: ScanConfig,
    active_scans: Arc<Mutex<HashMap<String, mpsc::Sender<ScanProgress>>>>,
    nmap_path: PathBuf,
    vuln_db_path: PathBuf,
}

impl NetworkScanner {
    /// Create a new scanner instance.
    pub fn new(nmap_path: PathBuf, vuln_db_path: PathBuf) -> Self {
        Self {
            scan_timeout: Duration::from_secs(5),
            max_concurrent_scans: 100,
            targets: Arc::new(Mutex::new(HashMap::new())),
            scan_config: ScanConfig {
                ports: Vec::new(),
                scan_type: ScanType::Quick,
                timeout: Duration::from_secs(5).as_secs() as u64,
                threads: 100,
                os_detection: true,
                service_detection: true,
                vulnerability_scan: true,
                custom_scripts: Vec::new(),
                nmap_args: Vec::new(),
                output_format: OutputFormat::XML,
                output_dir: PathBuf::new(),
            },
            active_scans: Arc::new(Mutex::new(HashMap::new())),
            nmap_path,
            vuln_db_path,
        }
    }

    /// Parse a target string that may contain IP ranges or CIDR notation
    pub fn parse_target(&self, target: &str) -> Vec<String> {
        let mut targets = Vec::new();
        
        // Try parsing as CIDR
        if let Ok(network) = target.parse::<IpNetwork>() {
            for ip in network.iter() {
                targets.push(ip.to_string());
            }
            return targets;
        }
        
        // Try parsing as IP range (e.g., 192.168.1.1-192.168.1.254)
        if target.contains('-') {
            let parts: Vec<&str> = target.split('-').collect();
            if parts.len() == 2 {
                if let (Ok(start), Ok(end)) = (parts[0].parse::<Ipv4Addr>(), parts[1].parse::<Ipv4Addr>()) {
                    let start_int = u32::from(start);
                    let end_int = u32::from(end);
                    for ip_int in start_int..=end_int {
                        targets.push(Ipv4Addr::from(ip_int).to_string());
                    }
                    return targets;
                }
            }
        }
        
        // If not a range or CIDR, treat as single target
        targets.push(target.to_string());
        targets
    }

    /// Scan multiple targets
    pub async fn scan_targets(&self, targets: Vec<String>, options: &ScanOptions) -> Vec<ScanResult> {
        let mut results = Vec::new();
        let mut handles = Vec::new();
        
        for target in targets {
            let scanner = self.clone();
            let options = options.clone();
            let handle = tokio::spawn(async move {
                scanner.scan_target(&target, &options).await
            });
            handles.push(handle);
        }
        
        for handle in handles {
            if let Ok(result) = handle.await {
                results.push(result);
            }
        }
        
        results
    }

    /// Scan a target IP/hostname and return a ScanResult.
    pub async fn scan_target(&mut self, target: &str) -> Result<ScanResult> {
        // Validate target
        let addr = IpAddr::from_str(target)
            .context("Invalid target IP address")?;
        // Reverse DNS lookup
        let reverse_dns = match tokio::net::lookup_host((target, 0)).await {
            Ok(mut iter) => iter.next().and_then(|sock| {
                let ip = sock.ip();
                dns_lookup::lookup_addr(&ip).ok()
            }),
            Err(_) => None,
        };
        // Geolocation stub (expand with real API if desired)
        let geoip = Some("(GeoIP lookup not implemented)".to_string());
        // Run nmap command
        let output = Command::new("nmap")
            .args(["-sS", "-sV", "-O", "--version-intensity", "5", target])
            .output()
            .context("Failed to execute nmap command. Is nmap installed?")?;
        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Nmap scan failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        let output_str = String::from_utf8_lossy(&output.stdout);
        
        // Parse the output
        let mut scan_result = ScanResult {
            target: target.to_string(),
            open_ports: Vec::new(),
            vulnerabilities: Vec::new(),
            os_info: None,
            timestamp: chrono::Utc::now(),
            reverse_dns,
            geoip,
        };

        // Parse nmap output
        for line in output_str.lines() {
            // Parse port information
            if line.contains("/tcp") || line.contains("/udp") {
                if let Some(port) = self.parse_port_line(line) {
                    scan_result.open_ports.push(port);
                }
            }
            // Parse OS information
            else if line.contains("OS details:") {
                if let Some(os) = line.split("OS details:").nth(1) {
                    scan_result.os_info = Some(os.trim().to_string());
                }
            }
        }

        // Perform vulnerability scan
        let vulns = self.scan_vulnerabilities(&addr, &scan_result.open_ports).await?;
        scan_result.vulnerabilities = vulns;

        Ok(scan_result)
    }

    /// Parse a single nmap output line into a PortInfo struct.
    fn parse_port_line(&self, line: &str) -> Option<PortInfo> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }

        // Parse port/protocol
        let port_proto: Vec<&str> = parts[0].split('/').collect();
        if port_proto.len() != 2 {
            return None;
        }

        let number = port_proto[0].parse().ok()?;
        let protocol = if port_proto[1] == "tcp" { Protocol::TCP } else { Protocol::UDP };
        let state = if parts[1].contains("open") { PortState::Open } else { PortState::Closed };
        let service = parts.get(2).map_or("unknown".to_string(), |s| s.to_string());
        // Version info is usually in the rest of the line after service
        let version = if parts.len() > 3 {
            Some(parts[3..].join(" "))
        } else {
            None
        };

        Some(PortInfo {
            port: number,
            protocol,
            service: Some(service),
            version,
            state,
        })
    }

    async fn scan_vulnerabilities(&self, ip: &IpAddr, ports: &[PortInfo]) -> Result<Vec<Vulnerability>> {
        let mut vulnerabilities = Vec::new();

        for port in ports {
            match port.port {
                21 => {
                    // Check for anonymous FTP
                    if let Some(service) = &port.service {
                        if service.to_lowercase().contains("ftp") {
                            vulnerabilities.push(Vulnerability {
                                name: "Anonymous FTP Access".to_string(),
                                description: "Anonymous FTP access is enabled".to_string(),
                                severity: Severity::Medium,
                                cve: None,
                                affected_ports: vec![port.port],
                            });
                        }
                    }
                }
                22 => {
                    // Check for default SSH credentials
                    if let Some(service) = &port.service {
                        if service.to_lowercase().contains("ssh") {
                            vulnerabilities.push(Vulnerability {
                                name: "Default SSH Credentials".to_string(),
                                description: "SSH service is running with default credentials".to_string(),
                                severity: Severity::High,
                                cve: None,
                                affected_ports: vec![port.port],
                            });
                        }
                    }
                }
                445 => {
                    // Check for SMB vulnerabilities
                    if let Some(service) = &port.service {
                        if service.to_lowercase().contains("microsoft-ds") {
                            vulnerabilities.push(Vulnerability {
                                name: "SMB Remote Code Execution".to_string(),
                                description: "Potential SMB vulnerability (EternalBlue)".to_string(),
                                severity: Severity::Critical,
                                cve: Some("CVE-2017-0144".to_string()),
                                affected_ports: vec![port.port],
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(vulnerabilities)
    }

    pub async fn run_scheduled_scan(&mut self, scheduled_scan: &ScheduledScan) -> Result<ScanReport> {
        let start_time = Utc::now();
        let result = self.scan_target(&scheduled_scan.target).await?;
        let duration = start_time.signed_duration_since(Utc::now());

        let summary = ScanSummary {
            total_ports_scanned: 1000, // This would be calculated from actual scan
            open_ports: result.open_ports.len(),
            vulnerabilities_found: result.vulnerabilities.len(),
            critical_vulns: result.vulnerabilities.iter()
                .filter(|v| matches!(v.severity, Severity::Critical))
                .count(),
            high_vulns: result.vulnerabilities.iter()
                .filter(|v| matches!(v.severity, Severity::High))
                .count(),
            medium_vulns: result.vulnerabilities.iter()
                .filter(|v| matches!(v.severity, Severity::Medium))
                .count(),
            low_vulns: result.vulnerabilities.iter()
                .filter(|v| matches!(v.severity, Severity::Low))
                .count(),
        };

        let report = ScanReport {
            scan_id: format!("scan_{}", start_time.timestamp()),
            target: result.target,
            timestamp: start_time,
            duration: Duration::from_secs(duration.num_seconds() as u64),
            open_ports: result.open_ports,
            vulnerabilities: result.vulnerabilities,
            summary,
        };

        // Save report
        self.save_report(&report)?;

        Ok(report)
    }

    pub fn save_report(&self, report: &ScanReport) -> Result<()> {
        let reports_dir = PathBuf::from("reports");
        fs::create_dir_all(&reports_dir)?;

        let filename = format!("scan_report_{}.json", report.scan_id);
        let filepath = reports_dir.join(filename);

        let json = serde_json::to_string_pretty(report)?;
        fs::write(filepath, json)?;

        Ok(())
    }

    pub fn load_report(&self, scan_id: &str) -> Result<ScanReport> {
        let filepath = PathBuf::from("reports").join(format!("scan_report_{}.json", scan_id));
        let json = fs::read_to_string(filepath)?;
        let report = serde_json::from_str(&json)?;
        Ok(report)
    }

    pub fn list_reports(&self) -> Result<Vec<String>> {
        let reports_dir = PathBuf::from("reports");
        if !reports_dir.exists() {
            return Ok(Vec::new());
        }

        let mut reports = Vec::new();
        for entry in fs::read_dir(reports_dir)? {
            let entry = entry?;
            if entry.path().extension().map_or(false, |ext| ext == "json") {
                if let Some(filename) = entry.file_name().to_str() {
                    reports.push(filename.to_string());
                }
            }
        }

        Ok(reports)
    }

    pub fn export_report_csv(&self, report: &ScanReport, filepath: &PathBuf) -> Result<()> {
        let mut wtr = Writer::from_path(filepath)?;
        
        // Write header
        wtr.write_record(&["Scan ID", "Target", "Timestamp", "Duration (s)", "Total Ports", "Open Ports", "Vulnerabilities"])?;
        
        // Write summary
        wtr.write_record(&[
            &report.scan_id,
            &report.target,
            &report.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
            &report.duration.as_secs().to_string(),
            &report.summary.total_ports_scanned.to_string(),
            &report.summary.open_ports.to_string(),
            &report.summary.vulnerabilities_found.to_string(),
        ])?;

        // Write ports
        wtr.write_record(&[])?; // Empty line
        wtr.write_record(&["Port", "Protocol", "Service", "Version", "State"])?;
        for port in &report.open_ports {
            wtr.write_record(&[
                &port.port.to_string(),
                &format!("{:?}", port.protocol),
                &port.service.as_deref().unwrap_or("unknown"),
                &port.version.as_deref().unwrap_or("unknown"),
                &format!("{:?}", port.state),
            ])?;
        }

        // Write vulnerabilities
        wtr.write_record(&[])?; // Empty line
        wtr.write_record(&["Vulnerability", "Description", "Severity", "CVE", "Affected Ports"])?;
        for vuln in &report.vulnerabilities {
            wtr.write_record(&[
                &vuln.name,
                &vuln.description,
                &format!("{:?}", vuln.severity),
                &vuln.cve.as_deref().unwrap_or("N/A"),
                &vuln.affected_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "),
            ])?;
        }

        wtr.flush()?;
        Ok(())
    }

    pub fn export_report_xlsx(&self, report: &ScanReport, filepath: &PathBuf) -> Result<()> {
        let mut workbook = Workbook::new();
        let mut sheet = workbook.add_worksheet();

        // Add formats
        let header_format = Format::new()
            .set_bold()
            .set_background_color(rust_xlsxwriter::Color::Gray);
        
        let severity_format = |severity: &Severity| {
            let color = match severity {
                Severity::Critical => rust_xlsxwriter::Color::Red,
                Severity::High => rust_xlsxwriter::Color::Orange,
                Severity::Medium => rust_xlsxwriter::Color::Yellow,
                Severity::Low => rust_xlsxwriter::Color::Green,
            };
            Format::new().set_background_color(color)
        };

        // Write summary
        sheet.write_string_with_format(0, 0, "Scan Summary", &header_format)?;
        sheet.write_string(1, 0, "Scan ID")?;
        sheet.write_string(1, 1, &report.scan_id)?;
        sheet.write_string(2, 0, "Target")?;
        sheet.write_string(2, 1, &report.target)?;
        sheet.write_string(3, 0, "Timestamp")?;
        sheet.write_string(3, 1, &report.timestamp.format("%Y-%m-%d %H:%M:%S").to_string())?;
        sheet.write_string(4, 0, "Duration (s)")?;
        sheet.write_number(4, 1, report.duration.as_secs() as f64)?;
        sheet.write_string(5, 0, "Total Ports")?;
        sheet.write_number(5, 1, report.summary.total_ports_scanned as f64)?;
        sheet.write_string(6, 0, "Open Ports")?;
        sheet.write_number(6, 1, report.summary.open_ports as f64)?;
        sheet.write_string(7, 0, "Vulnerabilities")?;
        sheet.write_number(7, 1, report.summary.vulnerabilities_found as f64)?;

        // Write ports
        let mut row = 10;
        sheet.write_string_with_format(row, 0, "Open Ports", &header_format)?;
        row += 1;
        sheet.write_string_with_format(row, 0, "Port", &header_format)?;
        sheet.write_string_with_format(row, 1, "Protocol", &header_format)?;
        sheet.write_string_with_format(row, 2, "Service", &header_format)?;
        sheet.write_string_with_format(row, 3, "Version", &header_format)?;
        sheet.write_string_with_format(row, 4, "State", &header_format)?;
        row += 1;

        for port in &report.open_ports {
            sheet.write_number(row, 0, port.port as f64)?;
            sheet.write_string(row, 1, &format!("{:?}", port.protocol))?;
            sheet.write_string(row, 2, port.service.as_deref().unwrap_or("unknown"))?;
            sheet.write_string(row, 3, port.version.as_deref().unwrap_or("unknown"))?;
            sheet.write_string(row, 4, &format!("{:?}", port.state))?;
            row += 1;
        }

        // Write vulnerabilities
        row += 2;
        sheet.write_string_with_format(row, 0, "Vulnerabilities", &header_format)?;
        row += 1;
        sheet.write_string_with_format(row, 0, "Name", &header_format)?;
        sheet.write_string_with_format(row, 1, "Description", &header_format)?;
        sheet.write_string_with_format(row, 2, "Severity", &header_format)?;
        sheet.write_string_with_format(row, 3, "CVE", &header_format)?;
        sheet.write_string_with_format(row, 4, "Affected Ports", &header_format)?;
        row += 1;

        for vuln in &report.vulnerabilities {
            let severity_fmt = severity_format(&vuln.severity);
            sheet.write_string(row, 0, &vuln.name)?;
            sheet.write_string(row, 1, &vuln.description)?;
            sheet.write_string_with_format(row, 2, &format!("{:?}", vuln.severity), &severity_fmt)?;
            sheet.write_string(row, 3, vuln.cve.as_deref().unwrap_or("N/A"))?;
            sheet.write_string(row, 4, &vuln.affected_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "))?;
            row += 1;
        }

        // Auto-fit columns
        sheet.autofit();

        // Save the workbook
        workbook.save(filepath)?;
        Ok(())
    }

    pub async fn add_target(&self, target: Target) -> Result<()> {
        let mut targets = self.targets.lock().await;
        targets.insert(target.id.clone(), target);
        Ok(())
    }

    pub async fn add_targets_from_cidr(&self, cidr: &str) -> Result<()> {
        let ips = self.expand_cidr(cidr)?;
        for ip in ips {
            let target = Target {
                id: uuid::Uuid::new_v4().to_string(),
                name: ip.to_string(),
                ip,
                hostname: None,
                tags: Vec::new(),
                metadata: HashMap::new(),
                last_scan: None,
                status: TargetStatus::Pending,
            };
            self.add_target(target).await?;
        }
        Ok(())
    }

    fn expand_cidr(&self, cidr: &str) -> Result<Vec<IpAddr>> {
        let mut ips = Vec::new();
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid CIDR format"));
        }

        let ip = IpAddr::from_str(parts[0])?;
        let prefix = parts[1].parse::<u8>()?;

        match ip {
            IpAddr::V4(ipv4) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::max_value() << (32 - prefix)
                };
                let network = u32::from(ipv4) & mask;
                let broadcast = network | !mask;
                for i in network..=broadcast {
                    ips.push(IpAddr::V4(Ipv4Addr::from(i)));
                }
            }
            IpAddr::V6(ipv6) => {
                // IPv6 CIDR expansion is more complex
                // For now, we'll just add the single IP
                ips.push(IpAddr::V6(ipv6));
            }
        }

        Ok(ips)
    }

    pub async fn start_scan(&self, target_id: &str) -> Result<mpsc::Receiver<ScanProgress>> {
        let (tx, rx) = mpsc::channel(100);
        let mut active_scans = self.active_scans.lock().await;
        active_scans.insert(target_id.to_string(), tx);

        let targets = self.targets.lock().await;
        let target = targets.get(target_id).ok_or_else(|| anyhow::anyhow!("Target not found"))?;

        let scan_config = self.scan_config.clone();
        let target_id = target_id.to_string();
        let active_scans = self.active_scans.clone();

        tokio::spawn(async move {
            let result = Self::perform_scan(&target, &scan_config).await;
            
            // Update target status
            let mut targets = self.targets.lock().await;
            if let Some(target) = targets.get_mut(&target_id) {
                target.status = match result.status {
                    ScanStatus::Completed => TargetStatus::Completed,
                    ScanStatus::Failed => TargetStatus::Failed,
                    _ => TargetStatus::Pending,
                };
                target.last_scan = Some(Utc::now());
            }

            // Remove from active scans
            let mut active_scans = active_scans.lock().await;
            active_scans.remove(&target_id);
        });

        Ok(rx)
    }

    async fn perform_scan(target: &Target, config: &ScanConfig) -> ScanResult {
        let start_time = Utc::now();
        let mut result = ScanResult {
            target_id: target.id.clone(),
            start_time,
            end_time: Utc::now(),
            status: ScanStatus::Running,
            open_ports: Vec::new(),
            services: Vec::new(),
            vulnerabilities: Vec::new(),
            os_info: None,
            error: None,
            nmap_output: None,
            scan_config: config.clone(),
        };

        // Port scanning
        let ports = Self::scan_ports(&target.ip, &config.ports).await;
        result.open_ports = ports;

        // Service detection
        if config.service_detection {
            result.services = Self::detect_services(&target.ip, &result.open_ports).await;
        }

        // OS detection
        if config.os_detection {
            result.os_info = Self::detect_os(&target.ip).await;
        }

        // Vulnerability scanning
        if config.vulnerability_scan {
            result.vulnerabilities = Self::scan_vulnerabilities(&target.ip, &result.services).await;
        }

        result.end_time = Utc::now();
        result.status = ScanStatus::Completed;

        result
    }

    async fn scan_ports(ip: &IpAddr, ports: &[u16]) -> Vec<PortInfo> {
        let mut open_ports = Vec::new();
        
        // Use tokio::net::TcpStream for async port scanning
        let futures = ports.iter().map(|&port| {
            let ip = *ip;
            async move {
                match timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(format!("{}:{}", ip, port))).await {
                    Ok(Ok(_)) => Some(PortInfo {
                        port: port,
                        protocol: Protocol::TCP,
                        service: None,
                        version: None,
                        state: PortState::Open,
                    }),
                    _ => None,
                }
            }
        });

        let results = stream::iter(futures)
            .buffer_unordered(100)
            .collect::<Vec<_>>()
            .await;

        for result in results {
            if let Some(port) = result {
                open_ports.push(port);
            }
        }

        open_ports
    }

    async fn detect_services(ip: &IpAddr, ports: &[PortInfo]) -> Vec<PortInfo> {
        let mut services = Vec::new();
        
        for port in ports {
            if let Ok(stream) = tokio::net::TcpStream::connect(format!("{}:{}", ip, port.port)).await {
                let mut buf = [0u8; 1024];
                if let Ok(n) = stream.read(&mut buf).await {
                    let banner = String::from_utf8_lossy(&buf[..n]).to_string();
                    services.push(PortInfo {
                        port: port.port,
                        protocol: port.protocol,
                        service: Some(Self::identify_service(&banner)),
                        version: None,
                        state: PortState::Open,
                    });
                }
            }
        }

        services
    }

    async fn detect_os(ip: &IpAddr) -> Option<String> {
        // Implement OS detection logic here
        // This is a simplified version
        Some("Unknown".to_string())
    }

    async fn scan_vulnerabilities(ip: &IpAddr, services: &[PortInfo]) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Implement vulnerability scanning logic here
        // This is a simplified version
        for service in services {
            if service.service.as_ref().map_or(false, |s| s.to_lowercase().contains("http") || s.to_lowercase().contains("https")) {
                vulnerabilities.push(Vulnerability {
                    name: "Potential XSS".to_string(),
                    description: "Possible cross-site scripting vulnerability".to_string(),
                    severity: Severity::Medium,
                    cve: None,
                    affected_ports: vec![service.port],
                });
            }
        }

        vulnerabilities
    }

    fn identify_service(banner: &str) -> String {
        // Implement service identification logic here
        // This is a simplified version
        if banner.contains("SSH") {
            "ssh".to_string()
        } else if banner.contains("HTTP") {
            "http".to_string()
        } else {
            "unknown".to_string()
        }
    }

    pub async fn get_target(&self, target_id: &str) -> Option<Target> {
        let targets = self.targets.lock().await;
        targets.get(target_id).cloned()
    }

    pub async fn list_targets(&self) -> Vec<Target> {
        let targets = self.targets.lock().await;
        targets.values().cloned().collect()
    }

    pub async fn remove_target(&self, target_id: &str) -> Result<()> {
        let mut targets = self.targets.lock().await;
        targets.remove(target_id);
        Ok(())
    }

    pub async fn update_target(&self, target: Target) -> Result<()> {
        let mut targets = self.targets.lock().await;
        targets.insert(target.id.clone(), target);
        Ok(())
    }
}

impl Default for NetworkScanner {
    fn default() -> Self {
        Self::new(PathBuf::new(), PathBuf::new())
    }
}

/// Return a list of built-in vulnerabilities for matching against scan results.
pub fn get_builtin_vulnerabilities() -> Vec<Vulnerability> {
    vec![
        Vulnerability {
            name: "CVE-2017-0144".to_string(),
            description: "SMB Remote Code Execution (EternalBlue)".to_string(),
            severity: Severity::Critical,
            cve: Some("CVE-2017-0144".to_string()),
            affected_ports: vec![445],
        },
        Vulnerability {
            name: "CVE-2014-0160".to_string(),
            description: "OpenSSL Heartbleed".to_string(),
            severity: Severity::High,
            cve: Some("CVE-2014-0160".to_string()),
            affected_ports: vec![443],
        },
        // Add more as needed
    ]
}

impl ScanResult {
    /// Find vulnerabilities in the scan result based on open ports/services.
    pub fn find_vulnerabilities(&self) -> Vec<Vulnerability> {
        let vulns = get_builtin_vulnerabilities();
        let mut found = Vec::new();
        for port in &self.open_ports {
            for vuln in &vulns {
                if port.service.as_ref().map_or(false, |s| s.to_lowercase().contains(&vuln.name))
                    && vuln.affected_ports.contains(&port.port)
                {
                    found.push(vuln.clone());
                }
            }
        }
        found
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledScan {
    pub target: String,
    pub schedule: ScanSchedule,
    pub scan_type: String,
    pub last_run: Option<DateTime<Utc>>,
    pub next_run: DateTime<Utc>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanSchedule {
    Once(DateTime<Utc>),
    Daily(DateTime<Utc>),
    Weekly(DateTime<Utc>, u8), // Day of week (0-6)
    Monthly(DateTime<Utc>, u8), // Day of month (1-31)
}

impl ScheduledScan {
    pub fn calculate_next_run(&self) -> DateTime<Utc> {
        match &self.schedule {
            ScanSchedule::Once(_) => self.next_run,
            ScanSchedule::Daily(time) => {
                let mut next = self.next_run;
                while next <= Utc::now() {
                    next = next + ChronoDuration::days(1);
                }
                next
            }
            ScanSchedule::Weekly(time, day) => {
                let mut next = self.next_run;
                while next <= Utc::now() || next.weekday().num_days_from_monday() != *day as u32 {
                    next = next + ChronoDuration::days(1);
                }
                next
            }
            ScanSchedule::Monthly(time, day) => {
                let mut next = self.next_run;
                while next <= Utc::now() || next.day() != *day {
                    next = next + ChronoDuration::days(1);
                }
                next
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scan_id: String,
    pub target: String,
    pub timestamp: DateTime<Utc>,
    pub duration: Duration,
    pub open_ports: Vec<PortInfo>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub summary: ScanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_ports_scanned: usize,
    pub open_ports: usize,
    pub vulnerabilities_found: usize,
    pub critical_vulns: usize,
    pub high_vulns: usize,
    pub medium_vulns: usize,
    pub low_vulns: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub id: String,
    pub name: String,
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, Value>,
    pub last_scan: Option<DateTime<Utc>>,
    pub status: TargetStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TargetStatus {
    Pending,
    Scanning,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub ports: Vec<u16>,
    pub scan_type: ScanType,
    pub timeout: u64,
    pub threads: u32,
    pub os_detection: bool,
    pub service_detection: bool,
    pub vulnerability_scan: bool,
    pub custom_scripts: Vec<String>,
    pub nmap_args: Vec<String>,
    pub output_format: OutputFormat,
    pub output_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanType {
    Quick,
    Full,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OutputFormat {
    XML,
    JSON,
    Text,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub number: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<Service>,
    pub scripts: Vec<ScriptResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
    pub cpe: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_score: Option<f32>,
    pub cve: Option<String>,
    pub affected_components: Vec<String>,
    pub references: Vec<String>,
    pub evidence: String,
    pub false_positive: bool,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: String,
    pub version: Option<String>,
    pub type_: String,
    pub cpe: Vec<String>,
    pub accuracy: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptResult {
    pub id: String,
    pub output: String,
    pub elements: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub target_id: String,
    pub status: ScanStatus,
    pub progress: f32,
    pub current_task: String,
    pub findings: Vec<Finding>,
} 