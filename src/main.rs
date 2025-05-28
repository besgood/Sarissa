mod scanner;
mod exploit;
mod plugin;
mod report;
mod exploit_executor;

use eframe::egui;
use egui::{Color32, RichText, Ui, ColorImage, TextureHandle};
use std::sync::Arc;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use scanner::{NetworkScanner, ScanResult, Vulnerability};
use exploit::{Exploit, ExploitManager, RiskLevel, ExploitResult, ExploitModule};
use plugin::{PluginManager, PluginMetadata};
use report::{ReportGenerator, Report};
use exploit_executor::{ExploitExecutor, ExploitConfig, ResourceLimits};
use std::fs;
use std::path::PathBuf;
use directories::UserDirs;
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration as ChronoDuration};
use plotters::prelude::*;
use std::io::Cursor;
use eframe::egui::{self, ScrollArea, TextEdit, Button, ComboBox, Label, Separator, Layout, Direction, Align};
use tokio::sync::Mutex;
use anyhow::Result;
use tokio::signal;
use tracing::{info, error};

mod config;
mod database;
mod logging;
mod monitoring;
mod security;
mod collaboration;
mod ui;

use config::Config;
use database::Database;
use logging::{LoggingConfig, init_logging, cleanup_old_logs};
use monitoring::{MonitoringSystem, HealthStatus};

// Main application state
struct SarissaApp {
    runtime: Arc<Runtime>,
    current_tab: Tab,
    scan_target: String,
    scan_results: Option<ScanResult>,
    scan_in_progress: bool,
    scanner: NetworkScanner,
    exploit_manager: Arc<Mutex<ExploitManager>>,
    selected_exploit: Option<String>,
    last_exploit_result: Option<ExploitResult>,
    error_message: Option<String>,
    ctx: Option<egui::Context>,
    state_update_rx: Option<mpsc::UnboundedReceiver<StateUpdate>>,
    settings: Settings,
    selected_module: Option<String>,
    selected_port: Option<u16>,
    scheduled_scans: Vec<ScheduledScan>,
    reports: Vec<String>,
    selected_report: Option<String>,
    selected_tab: Tab,
    exploit_chain: Vec<String>,
    payload_template: String,
    payload_values: String,
    exploit_chain_results: String,
    custom_payload_results: String,
    exploit_chains: Vec<ExploitChain>,
    selected_chain: Option<usize>,
    new_chain_name: String,
    new_chain_description: String,
    scan_progress: Option<ScanProgress>,
    scan_history: Vec<ScanResult>,
    selected_scan: Option<usize>,
    dashboard_stats: DashboardStats,
    modules: Vec<Module>,
    selected_category: Option<ModuleCategory>,
    module_output: String,
    module_executions: Vec<ModuleExecution>,
    current_execution: Option<usize>,
    module_target: String,
    module_arguments: String,
    module_configs: Vec<ModuleConfig>,
    module_templates: Vec<ModuleTemplate>,
    module_stats: std::collections::HashMap<String, ModuleExecutionStats>,
    module_chain: Vec<String>,
    module_chain_results: String,
    plugin_manager: PluginManager,
    exploit_executor: ExploitExecutor,
    report_generator: ReportGenerator,
}

enum StateUpdate {
    ScanComplete(ScanResult),
    ScanError(String),
    ScanProgress(ScanProgress),
}

// Available tabs in the application
#[derive(PartialEq)]
enum Tab {
    Dashboard,
    Scan,
    Exploits,
    Reports,
    Settings,
    Basic,
    Advanced,
    Modules,
}

#[derive(Serialize, Deserialize, Clone)]
struct Settings {
    pub default_scan_type: String,
    pub dark_mode: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_scan_type: "-sS -sV -O --version-intensity 5".to_string(),
            dark_mode: false,
        }
    }
}

impl Settings {
    fn settings_path() -> PathBuf {
        let user_dirs = UserDirs::new().unwrap();
        let home = user_dirs.home_dir();
        home.join(".sarissa_settings.json")
    }
    fn load() -> Self {
        let path = Self::settings_path();
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(settings) = serde_json::from_str(&data) {
                return settings;
            }
        }
        Self::default()
    }
    fn save(&self) {
        let path = Self::settings_path();
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, json);
        }
    }
}

impl Default for SarissaApp {
    fn default() -> Self {
        let mut exploit_manager = ExploitManager::new();
        exploit_manager.load_default_exploits();
        
        Self {
            runtime: Arc::new(Runtime::new().unwrap()),
            current_tab: Tab::Dashboard,
            scan_target: String::new(),
            scan_results: None,
            scan_in_progress: false,
            scanner: NetworkScanner::new(),
            exploit_manager: Arc::new(Mutex::new(exploit_manager)),
            selected_exploit: None,
            last_exploit_result: None,
            error_message: None,
            ctx: None,
            state_update_rx: None,
            settings: Settings::load(),
            selected_module: None,
            selected_port: None,
            scheduled_scans: Vec::new(),
            reports: Vec::new(),
            selected_report: None,
            selected_tab: Tab::Basic,
            exploit_chain: Vec::new(),
            payload_template: String::new(),
            payload_values: String::new(),
            exploit_chain_results: String::new(),
            custom_payload_results: String::new(),
            exploit_chains: Vec::new(),
            selected_chain: None,
            new_chain_name: String::new(),
            new_chain_description: String::new(),
            scan_progress: None,
            scan_history: Vec::new(),
            selected_scan: None,
            dashboard_stats: DashboardStats {
                total_scans: 0,
                total_vulnerabilities: 0,
                critical_vulns: 0,
                high_vulns: 0,
                medium_vulns: 0,
                low_vulns: 0,
                successful_exploits: 0,
                last_scan_time: None,
                average_scan_duration: chrono::Duration::seconds(0),
            },
            modules: Vec::new(),
            selected_category: None,
            module_output: String::new(),
            module_executions: Vec::new(),
            current_execution: None,
            module_target: String::new(),
            module_arguments: String::new(),
            module_configs: Vec::new(),
            module_templates: Vec::new(),
            module_stats: std::collections::HashMap::new(),
            module_chain: Vec::new(),
            module_chain_results: String::new(),
            plugin_manager: PluginManager::new(PathBuf::new()),
            exploit_executor: ExploitExecutor::new(PathBuf::new()),
            report_generator: ReportGenerator::new(PathBuf::new(), PathBuf::new()),
        }
    }
}

impl SarissaApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut style = (*cc.egui_ctx.style()).clone();
        style.text_styles = [
            (egui::TextStyle::Heading, egui::FontId::new(30.0, egui::FontFamily::Proportional)),
            (egui::TextStyle::Body, egui::FontId::new(16.0, egui::FontFamily::Proportional)),
            (egui::TextStyle::Button, egui::FontId::new(16.0, egui::FontFamily::Proportional)),
        ]
        .into();
        cc.egui_ctx.set_style(style);

        let mut app = Self::default();
        app.ctx = Some(cc.egui_ctx.clone());
        
        // Create channel for state updates
        let (_state_tx, state_rx) = mpsc::unbounded_channel();
        app.state_update_rx = Some(state_rx);
        app
    }

    fn render_top_panel(&mut self, ui: &mut Ui) {
        egui::TopBottomPanel::top("top_panel").show_inside(ui, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Sarissa");
                    ui.separator();
                    if ui.button("Dashboard").clicked() {
                        self.current_tab = Tab::Dashboard;
                    }
                    if ui.button("Scan").clicked() {
                        self.current_tab = Tab::Scan;
                    }
                    if ui.button("Exploits").clicked() {
                        self.current_tab = Tab::Exploits;
                    }
                    if ui.button("Modules").clicked() {
                        self.current_tab = Tab::Modules;
                    }
                    if ui.button("Reports").clicked() {
                        self.current_tab = Tab::Reports;
                    }
                    if ui.button("Settings").clicked() {
                        self.current_tab = Tab::Settings;
                    }
                });
            });
        });
    }

    fn render_dashboard(&mut self, ui: &mut Ui) {
        ui.heading("Dashboard");
        ui.add_space(20.0);

        // Statistics overview
        ui.group(|ui| {
            ui.heading("Statistics");
            ui.horizontal(|ui| {
                // Left column - Scan statistics
                ui.vertical(|ui| {
                    ui.label(RichText::new("Scan Statistics").size(18.0).strong());
                    ui.add_space(5.0);
                    ui.label(format!("Total Scans: {}", self.dashboard_stats.total_scans));
                    ui.label(format!("Last Scan: {}", 
                        self.dashboard_stats.last_scan_time
                            .map_or("Never".to_string(), |t| t.format("%Y-%m-%d %H:%M:%S").to_string())));
                    ui.label(format!("Average Duration: {} seconds", 
                        self.dashboard_stats.average_scan_duration.num_seconds()));
                });
                
                ui.separator();
                
                // Middle column - Vulnerability statistics
                ui.vertical(|ui| {
                    ui.label(RichText::new("Vulnerability Statistics").size(18.0).strong());
                    ui.add_space(5.0);
                    ui.label(format!("Total Vulnerabilities: {}", self.dashboard_stats.total_vulnerabilities));
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Critical:").color(Color32::RED));
                        ui.label(format!("{}", self.dashboard_stats.critical_vulns));
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("High:").color(Color32::from_rgb(255, 69, 0)));
                        ui.label(format!("{}", self.dashboard_stats.high_vulns));
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Medium:").color(Color32::YELLOW));
                        ui.label(format!("{}", self.dashboard_stats.medium_vulns));
                    });
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Low:").color(Color32::GREEN));
                        ui.label(format!("{}", self.dashboard_stats.low_vulns));
                    });
                });
                
                ui.separator();
                
                // Right column - Exploit statistics
                ui.vertical(|ui| {
                    ui.label(RichText::new("Exploit Statistics").size(18.0).strong());
                    ui.add_space(5.0);
                    ui.label(format!("Successful Exploits: {}", self.dashboard_stats.successful_exploits));
                    ui.label(format!("Success Rate: {:.1}%", 
                        if self.dashboard_stats.total_scans > 0 {
                            (self.dashboard_stats.successful_exploits as f32 / self.dashboard_stats.total_scans as f32) * 100.0
                        } else {
                            0.0
                        }));
                });
            });
        });

        ui.add_space(20.0);

        // Charts and graphs
        ui.horizontal(|ui| {
            // Vulnerability distribution chart
            ui.group(|ui| {
                ui.heading("Vulnerability Distribution");
                let data = vec![
                    ("Critical", self.dashboard_stats.critical_vulns, Color32::RED),
                    ("High", self.dashboard_stats.high_vulns, Color32::from_rgb(255, 69, 0)),
                    ("Medium", self.dashboard_stats.medium_vulns, Color32::YELLOW),
                    ("Low", self.dashboard_stats.low_vulns, Color32::GREEN),
                ];

                let mut chart = Chart::new(ui);
                chart.set_size(300.0, 200.0);
                chart.set_data(data);
                chart.draw();
            });

            // Scan timeline chart
            ui.group(|ui| {
                ui.heading("Scan Timeline");
                // In a real implementation, show a timeline of recent scans
                ui.label("Scan activity over time");
                // Add timeline visualization here
            });
        });

        ui.add_space(20.0);

        // Recent activity
        ui.group(|ui| {
            ui.heading("Recent Activity");
            ScrollArea::vertical().show(ui, |ui| {
                for scan in self.scan_history.iter().rev().take(5) {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(format!("{}", scan.timestamp.format("%Y-%m-%d %H:%M:%S")));
                            ui.label(format!("Target: {}", scan.target));
                        });
                        ui.label(format!("Open ports: {}", scan.open_ports.len()));
                        ui.label(format!("Vulnerabilities found: {}", scan.vulnerabilities.len()));
                        
                        // Show top vulnerabilities
                        if !scan.vulnerabilities.is_empty() {
                            ui.collapsing("Top Vulnerabilities", |ui| {
                                for vuln in scan.vulnerabilities.iter().take(3) {
                                    let color = match vuln.severity {
                                        Severity::Critical => Color32::RED,
                                        Severity::High => Color32::from_rgb(255, 69, 0),
                                        Severity::Medium => Color32::YELLOW,
                                        Severity::Low => Color32::GREEN,
                                    };
                                    ui.label(RichText::new(&vuln.name).color(color));
                                }
                            });
                        }
                    });
                }
            });
        });

        ui.add_space(20.0);

        // Quick actions
        ui.group(|ui| {
            ui.heading("Quick Actions");
            ui.horizontal(|ui| {
                if ui.button("New Scan").clicked() {
                    self.current_tab = Tab::Scan;
                }
                if ui.button("View Exploits").clicked() {
                    self.current_tab = Tab::Exploits;
                }
                if ui.button("Generate Report").clicked() {
                    self.current_tab = Tab::Reports;
                }
            });
        });
    }

    fn render_scan_panel(&mut self, ui: &mut Ui) {
        ui.heading("Network Scan");
        ui.add_space(20.0);

        // Scan configuration
        ui.group(|ui| {
            ui.heading("Scan Configuration");
            ui.horizontal(|ui| {
                ui.label("Target IP:");
                ui.text_edit_singleline(&mut self.scan_target)
                    .on_hover_text("Enter the IP address or hostname to scan");
            });

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.label("Scan Type:");
                if ui.button("Quick").clicked() {
                    self.settings.default_scan_type = "-sS -sV --top-ports 100".to_string();
                }
                if ui.button("Standard").clicked() {
                    self.settings.default_scan_type = "-sS -sV -O --version-intensity 5".to_string();
                }
                if ui.button("Comprehensive").clicked() {
                    self.settings.default_scan_type = "-sS -sU -sV -O --version-intensity 9 -p-".to_string();
                }
                if ui.button("Custom").clicked() {
                    // Show custom scan options dialog
                }
            });

            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button("Start Scan").clicked() && !self.scan_in_progress {
                    self.start_scan();
                }
                if self.scan_in_progress {
                    if let Some(progress) = &self.scan_progress {
                        ui.spinner();
                        ui.label(format!("{}: {:.1}%", progress.current_phase, progress.progress * 100.0));
                        ui.label(format!("Elapsed: {}", 
                            (chrono::Utc::now() - progress.start_time).num_seconds()));
                    }
                }
            });
        });

        // Scan History
        ui.add_space(20.0);
        ui.group(|ui| {
            ui.heading("Scan History");
            ScrollArea::vertical().show(ui, |ui| {
                for (i, scan) in self.scan_history.iter().enumerate() {
                    let is_selected = self.selected_scan == Some(i);
                    if ui.selectable_label(is_selected, 
                        format!("{} - {} ({})", 
                            scan.timestamp.format("%Y-%m-%d %H:%M:%S"),
                            scan.target,
                            scan.open_ports.len()))
                        .clicked() {
                        self.selected_scan = Some(i);
                        self.scan_results = Some(scan.clone());
                    }
                }
            });
        });

        // Show scan results
        if let Some(result) = &self.scan_results {
            ui.add_space(20.0);
            ui.group(|ui| {
                ui.heading("Scan Results");
                
                // Summary section
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(format!("Target: {}", result.target));
                        if let Some(host) = &result.reverse_dns {
                            ui.label(format!("Reverse DNS: {}", host));
                        }
                        if let Some(geo) = &result.geoip {
                            ui.label(format!("Geolocation: {}", geo));
                        }
                    });
                    ui.vertical(|ui| {
                        ui.label(format!("Scan Time: {}", result.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));
                        if let Some(os) = &result.os_info {
                            ui.label(format!("Operating System: {}", os));
                        }
                    });
                });

                ui.add_space(10.0);
                
                // Ports and Services
                ui.collapsing("Open Ports and Services", |ui| {
                    egui::Grid::new("ports_grid")
                        .num_columns(4)
                        .striped(true)
                        .show(ui, |ui| {
                            ui.label("Port");
                            ui.label("Protocol");
                            ui.label("Service");
                            ui.label("Version");
                            ui.end_row();

                            for port in &result.open_ports {
                                ui.label(format!("{}", port.port));
                                ui.label(format!("{:?}", port.protocol));
                                ui.label(port.service.as_deref().unwrap_or("unknown"));
                                ui.label(port.version.as_deref().unwrap_or("unknown"));
                                ui.end_row();
                            }
                        });
                });

                ui.add_space(10.0);
                
                // Vulnerabilities
                ui.collapsing("Vulnerabilities", |ui| {
                    for vuln in &result.vulnerabilities {
                        let color = match vuln.severity {
                            Severity::Critical => Color32::RED,
                            Severity::High => Color32::from_rgb(255, 69, 0),
                            Severity::Medium => Color32::YELLOW,
                            Severity::Low => Color32::GREEN,
                        };
                        
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&vuln.name).color(color).strong());
                                ui.label(format!("Severity: {:?}", vuln.severity));
                            });
                            ui.label(&vuln.description);
                            if let Some(cve) = &vuln.cve {
                                ui.horizontal(|ui| {
                                    ui.label("CVE:");
                                    ui.hyperlink_to(cve, format!("https://nvd.nist.gov/vuln/detail/{}", cve));
                                });
                            }
                        });
                    }
                });

                ui.add_space(10.0);
                
                // Export options
                ui.horizontal(|ui| {
                    if ui.button("Export as CSV").clicked() {
                        // Export to CSV
                    }
                    if ui.button("Export as PDF").clicked() {
                        // Export to PDF
                    }
                    if ui.button("Export as JSON").clicked() {
                        // Export to JSON
                    }
                });
            });
        }
    }

    fn render_exploits_panel(&mut self, ui: &mut Ui) {
        ui.heading("Exploits");
        ui.add_space(20.0);
        egui::Grid::new("exploits_grid").num_columns(2).show(ui, |ui| {
            // Left column - Exploit list
            ui.vertical(|ui| {
                ui.heading("Available Exploits");
                ui.add_space(10.0);
                for exploit in self.exploit_manager.lock().await.get_exploits() {
                    let is_selected = self.selected_exploit.as_ref().map_or(false, |id| id == &exploit.id);
                    ui.horizontal(|ui| {
                        if ui.selectable_label(is_selected, &exploit.name).on_hover_text("View details and run this exploit").clicked() {
                            self.selected_exploit = Some(exploit.id.clone());
                            self.last_exploit_result = None;
                        }
                        let (risk_text, risk_color) = match exploit.risk_level {
                            RiskLevel::Critical => ("Critical", Color32::RED),
                            RiskLevel::High => ("High", Color32::from_rgb(255, 140, 0)),
                            RiskLevel::Medium => ("Medium", Color32::YELLOW),
                            RiskLevel::Low => ("Low", Color32::GREEN),
                        };
                        ui.label(RichText::new(risk_text).color(risk_color)).on_hover_text("Exploit risk level");
                    });
                }
                ui.separator();
                ui.heading("Real Exploit Modules");
                for module in self.exploit_manager.lock().await.get_modules() {
                    let is_selected = self.selected_module.as_ref().map_or(false, |id| id == module.id());
                    if ui.selectable_label(is_selected, module.name()).on_hover_text(module.description()).clicked() {
                        self.selected_module = Some(module.id().to_string());
                        self.last_exploit_result = None;
                    }
                }
            });
            ui.vertical(|ui| {
                if let Some(exploit_id) = &self.selected_exploit {
                    if let Some(exploit) = self.exploit_manager.lock().await.get_exploit(exploit_id) {
                        ui.heading(&exploit.name);
                        ui.add_space(10.0);
                        ui.label("Description:");
                        ui.label(&exploit.description);
                        ui.add_space(5.0);
                        if let Some(cve) = &exploit.cve {
                            ui.label(format!("CVE: {}", cve)).on_hover_text("Common Vulnerabilities and Exposures ID");
                        }
                        ui.label(format!("Target Service: {}", exploit.target_service));
                        if let Some(port) = exploit.target_port {
                            ui.label(format!("Target Port: {}", port));
                        }
                        ui.add_space(10.0);
                        ui.label("Requirements:");
                        for req in &exploit.requirements {
                            ui.label(format!("• {}", req));
                        }
                        ui.add_space(20.0);
                        if ui.button("Run Exploit").on_hover_text("Execute this exploit against the last scanned target").clicked() {
                            if let Some(target) = self.scan_results.as_ref().map(|r| r.target.clone()) {
                                let exploit = exploit.clone();
                                let runtime = self.runtime.clone();
                                let ctx = self.ctx.clone();
                                let last_exploit_result = &mut self.last_exploit_result;
                                let error_message = &mut self.error_message;
                                // Show spinner while running exploit
                                self.error_message = None;
                                self.last_exploit_result = None;
                                let fut = async move {
                                    match self.exploit_manager.lock().await.run_exploit(&exploit, &target).await {
                                        Ok(result) => {
                                            *last_exploit_result = Some(result);
                                        }
                                        Err(e) => {
                                            *error_message = Some(format!("Exploit failed: {}", e));
                                        }
                                    }
                                    if let Some(ctx) = ctx {
                                        ctx.request_repaint();
                                    }
                                };
                                runtime.spawn(fut);
                            } else {
                                self.error_message = Some("No scan target available. Please run a scan first.".to_string());
                            }
                        }
                        if self.last_exploit_result.is_none() && self.error_message.is_none() {
                            ui.label(RichText::new("Running exploit...").color(Color32::YELLOW));
                            ui.spinner();
                        }
                        if let Some(result) = &self.last_exploit_result {
                            ui.separator();
                            ui.label(RichText::new("Last Exploit Result:").strong());
                            ui.label(format!("Success: {}", result.success));
                            ui.label(format!("Output: {}", result.output));
                            if let Some(err) = &result.error {
                                ui.label(RichText::new(format!("Error: {}", err)).color(Color32::RED));
                            }
                        }
                    }
                }
                // Real exploit module details and runner
                if let Some(module_id) = &self.selected_module {
                    if let Some(module) = self.exploit_manager.lock().await.get_modules().iter().find(|m| m.id() == module_id) {
                        ui.heading(module.name());
                        ui.label(module.description());
                        // Select open port from last scan
                        if let Some(scan) = &self.scan_results {
                            ui.add_space(10.0);
                            ui.label("Select open port:");
                            for port in &scan.open_ports {
                                let is_selected = self.selected_port == Some(port.number);
                                if ui.selectable_label(is_selected, format!("{} ({})", port.number, port.service)).clicked() {
                                    self.selected_port = Some(port.number);
                                    self.last_exploit_result = None;
                                }
                            }
                        } else {
                            ui.label("No scan results available. Run a scan first.");
                        }
                        if self.selected_port.is_some() && self.scan_results.is_some() {
                            if ui.button("Run Module").on_hover_text("Run this exploit module against the selected port").clicked() {
                                let module = module_id.clone();
                                let port = self.selected_port.unwrap();
                                let target = self.scan_results.as_ref().unwrap().target.clone();
                                let exploit_manager = &self.exploit_manager;
                                let ctx = self.ctx.clone();
                                let last_exploit_result = &mut self.last_exploit_result;
                                let error_message = &mut self.error_message;
                                self.error_message = None;
                                self.last_exploit_result = None;
                                let fut = async move {
                                    if let Some(module) = exploit_manager.lock().await.get_modules().iter().find(|m| m.id() == module) {
                                        match module.run(&target, port).await {
                                            Ok(result) => {
                                                *last_exploit_result = Some(result);
                                            }
                                            Err(e) => {
                                                *error_message = Some(format!("Module failed: {}", e));
                                            }
                                        }
                                    }
                                    if let Some(ctx) = ctx {
                                        ctx.request_repaint();
                                    }
                                };
                                self.runtime.spawn(fut);
                            }
                            if self.last_exploit_result.is_none() && self.error_message.is_none() {
                                ui.label(RichText::new("Running module...").color(Color32::YELLOW));
                                ui.spinner();
                            }
                            if let Some(result) = &self.last_exploit_result {
                                ui.separator();
                                ui.label(RichText::new("Module Result:").strong());
                                ui.label(format!("Success: {}", result.success));
                                ui.label(format!("Output: {}", result.output));
                                if let Some(err) = &result.error {
                                    ui.label(RichText::new(format!("Error: {}", err)).color(Color32::RED));
                                }
                            }
                        }
                    }
                }
                if self.selected_exploit.is_none() && self.selected_module.is_none() {
                    ui.heading("Select an exploit or module to view details");
                }
            });
        });
    }

    fn render_reports_panel(&mut self, ui: &mut Ui) {
        ui.heading("Scan Reports");
        ui.add_space(20.0);

        // Refresh reports list
        if ui.button("Refresh Reports").clicked() {
            if let Ok(reports) = self.scanner.list_reports() {
                self.reports = reports;
            }
        }

        ui.add_space(10.0);
        egui::Grid::new("reports_grid").num_columns(2).show(ui, |ui| {
            // Left column - Report list
            ui.vertical(|ui| {
                ui.heading("Available Reports");
                ui.add_space(10.0);
                for report in &self.reports {
                    let is_selected = self.selected_report.as_ref().map_or(false, |r| r == report);
                    if ui.selectable_label(is_selected, report).clicked() {
                        self.selected_report = Some(report.clone());
                    }
                }
            });

            // Right column - Report details
            ui.vertical(|ui| {
                if let Some(report_id) = &self.selected_report {
                    if let Ok(report) = self.scanner.load_report(report_id) {
                        ui.heading("Report Details");
                        ui.add_space(10.0);
                        ui.label(format!("Target: {}", report.target));
                        ui.label(format!("Scan Time: {}", report.timestamp.format("%Y-%m-%d %H:%M:%S")));
                        ui.label(format!("Duration: {} seconds", report.duration.as_secs()));
                        
                        ui.add_space(10.0);
                        ui.heading("Summary");
                        ui.label(format!("Total Ports Scanned: {}", report.summary.total_ports_scanned));
                        ui.label(format!("Open Ports: {}", report.summary.open_ports));
                        ui.label(format!("Vulnerabilities Found: {}", report.summary.vulnerabilities_found));
                        ui.label(format!("Critical: {}", report.summary.critical_vulns));
                        ui.label(format!("High: {}", report.summary.high_vulns));
                        ui.label(format!("Medium: {}", report.summary.medium_vulns));
                        ui.label(format!("Low: {}", report.summary.low_vulns));

                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            if ui.button("Export CSV").clicked() {
                                let filepath = PathBuf::from(format!("reports/scan_report_{}.csv", report.scan_id));
                                if let Err(e) = self.scanner.export_report_csv(&report, &filepath) {
                                    self.error_message = Some(format!("Failed to export CSV: {}", e));
                                }
                            }
                            if ui.button("Export XLSX").clicked() {
                                let filepath = PathBuf::from(format!("reports/scan_report_{}.xlsx", report.scan_id));
                                if let Err(e) = self.scanner.export_report_xlsx(&report, &filepath) {
                                    self.error_message = Some(format!("Failed to export XLSX: {}", e));
                                }
                            }
                        });

                        // Vulnerability distribution chart
                        ui.add_space(20.0);
                        ui.heading("Vulnerability Distribution");
                        let data = vec![
                            ("Critical", report.summary.critical_vulns, Color32::RED),
                            ("High", report.summary.high_vulns, Color32::from_rgb(255, 69, 0)),
                            ("Medium", report.summary.medium_vulns, Color32::YELLOW),
                            ("Low", report.summary.low_vulns, Color32::GREEN),
                        ];

                        let mut chart = Chart::new(ui);
                        chart.set_size(400.0, 200.0);
                        chart.set_data(data);
                        chart.draw();
                    }
                } else {
                    ui.heading("Select a report to view details");
                }
            });
        });
    }

    fn render_settings_panel(&mut self, ui: &mut Ui) {
        ui.heading("Settings");
        ui.add_space(20.0);

        ui.group(|ui| {
            ui.heading("Appearance");
            ui.checkbox(&mut self.settings.dark_mode, "Dark Mode");
            if ui.button("Apply Theme").clicked() {
                if self.settings.dark_mode {
                    ui.ctx().set_visuals(egui::Visuals::dark());
                } else {
                    ui.ctx().set_visuals(egui::Visuals::light());
                }
                self.settings.save();
            }
        });

        ui.add_space(20.0);
        ui.group(|ui| {
            ui.heading("Scan Settings");
            ui.horizontal(|ui| {
                ui.label("Default Scan Type:");
                ui.text_edit_singleline(&mut self.settings.default_scan_type);
            });
            if ui.button("Save Settings").clicked() {
                self.settings.save();
            }
        });
    }

    fn start_scan(&mut self) {
        if self.scan_target.is_empty() {
            self.error_message = Some("Please enter a target IP address".to_string());
            return;
        }

        self.scan_in_progress = true;
        self.error_message = None;
        self.scan_progress = Some(ScanProgress {
            current_phase: "Initializing scan...".to_string(),
            progress: 0.0,
            details: String::new(),
            start_time: chrono::Utc::now(),
        });

        let target = self.scan_target.clone();
        let ctx = self.ctx.clone();
        let runtime = self.runtime.clone();
        let (state_tx, state_rx) = mpsc::unbounded_channel();

        // Spawn the scanning task
        runtime.spawn(async move {
            let mut scanner = NetworkScanner::new();
            
            // Update progress for port scanning
            let _ = state_tx.send(StateUpdate::ScanProgress(ScanProgress {
                current_phase: "Port scanning...".to_string(),
                progress: 0.3,
                details: "Scanning common ports".to_string(),
                start_time: chrono::Utc::now(),
            }));

            match scanner.scan_target(&target).await {
                Ok(result) => {
                    let _ = state_tx.send(StateUpdate::ScanComplete(result));
                }
                Err(e) => {
                    let _ = state_tx.send(StateUpdate::ScanError(e.to_string()));
                }
            }
            
            if let Some(ctx) = ctx {
                ctx.request_repaint();
            }
        });

        self.state_update_rx = Some(state_rx);
    }

    fn check_state_updates(&mut self) {
        if let Some(rx) = &mut self.state_update_rx {
            while let Ok(update) = rx.try_recv() {
                match update {
                    StateUpdate::ScanComplete(result) => {
                        self.scan_results = Some(result.clone());
                        self.scan_history.push(result.clone());
                        self.scan_in_progress = false;
                        self.scan_progress = None;
                        
                        // Update dashboard statistics
                        self.dashboard_stats.total_scans += 1;
                        self.dashboard_stats.last_scan_time = Some(chrono::Utc::now());
                        self.dashboard_stats.total_vulnerabilities += result.vulnerabilities.len();
                        
                        // Update vulnerability counts
                        for vuln in &result.vulnerabilities {
                            match vuln.severity {
                                Severity::Critical => self.dashboard_stats.critical_vulns += 1,
                                Severity::High => self.dashboard_stats.high_vulns += 1,
                                Severity::Medium => self.dashboard_stats.medium_vulns += 1,
                                Severity::Low => self.dashboard_stats.low_vulns += 1,
                            }
                        }
                        
                        // Update average scan duration
                        if let Some(duration) = result.duration {
                            let total_duration = self.dashboard_stats.average_scan_duration * 
                                (self.dashboard_stats.total_scans - 1) as i32 + duration;
                            self.dashboard_stats.average_scan_duration = total_duration / 
                                self.dashboard_stats.total_scans as i32;
                        }
                    }
                    StateUpdate::ScanError(error) => {
                        self.error_message = Some(error);
                        self.scan_in_progress = false;
                        self.scan_progress = None;
                    }
                    StateUpdate::ScanProgress(progress) => {
                        self.scan_progress = Some(progress);
                    }
                }
            }
        }
    }

    fn initialize_modules(&mut self) {
        self.modules = vec![
            // Information Gathering
            Module {
                id: "dns_enum".to_string(),
                name: "DNS Enumeration".to_string(),
                description: "Enumerate DNS records and subdomains".to_string(),
                category: ModuleCategory::InformationGathering,
                command: "dnsrecon".to_string(),
                dependencies: vec!["dnsrecon".to_string()],
                is_installed: false,
            },
            Module {
                id: "subdomain_enum".to_string(),
                name: "Subdomain Enumeration".to_string(),
                description: "Discover subdomains using various techniques".to_string(),
                category: ModuleCategory::InformationGathering,
                command: "subfinder".to_string(),
                dependencies: vec!["subfinder".to_string()],
                is_installed: false,
            },
            Module {
                id: "port_scan".to_string(),
                name: "Port Scanning".to_string(),
                description: "Advanced port scanning with service detection".to_string(),
                category: ModuleCategory::InformationGathering,
                command: "nmap".to_string(),
                dependencies: vec!["nmap".to_string()],
                is_installed: false,
            },
            
            // Vulnerability Analysis
            Module {
                id: "vuln_scan".to_string(),
                name: "Vulnerability Scanner".to_string(),
                description: "Scan for known vulnerabilities".to_string(),
                category: ModuleCategory::VulnerabilityAnalysis,
                command: "nmap -sV --script vuln".to_string(),
                dependencies: vec!["nmap".to_string()],
                is_installed: false,
            },
            Module {
                id: "web_vuln_scan".to_string(),
                name: "Web Vulnerability Scanner".to_string(),
                description: "Scan web applications for vulnerabilities".to_string(),
                category: ModuleCategory::VulnerabilityAnalysis,
                command: "nikto".to_string(),
                dependencies: vec!["nikto".to_string()],
                is_installed: false,
            },
            
            // Web Application
            Module {
                id: "web_dir_scan".to_string(),
                name: "Directory Scanner".to_string(),
                description: "Scan for web directories and files".to_string(),
                category: ModuleCategory::WebApplication,
                command: "dirb".to_string(),
                dependencies: vec!["dirb".to_string()],
                is_installed: false,
            },
            Module {
                id: "web_crawl".to_string(),
                name: "Web Crawler".to_string(),
                description: "Crawl web applications for content".to_string(),
                category: ModuleCategory::WebApplication,
                command: "gospider".to_string(),
                dependencies: vec!["gospider".to_string()],
                is_installed: false,
            },
            
            // Database Assessment
            Module {
                id: "sql_injection".to_string(),
                name: "SQL Injection Scanner".to_string(),
                description: "Scan for SQL injection vulnerabilities".to_string(),
                category: ModuleCategory::DatabaseAssessment,
                command: "sqlmap".to_string(),
                dependencies: vec!["sqlmap".to_string()],
                is_installed: false,
            },
            Module {
                id: "db_enum".to_string(),
                name: "Database Enumeration".to_string(),
                description: "Enumerate database information".to_string(),
                category: ModuleCategory::DatabaseAssessment,
                command: "sqlninja".to_string(),
                dependencies: vec!["sqlninja".to_string()],
                is_installed: false,
            },
            
            // Password Attacks
            Module {
                id: "password_spray".to_string(),
                name: "Password Spray Attack".to_string(),
                description: "Perform password spray attacks".to_string(),
                category: ModuleCategory::PasswordAttacks,
                command: "sprayhound".to_string(),
                dependencies: vec!["sprayhound".to_string()],
                is_installed: false,
            },
            Module {
                id: "hash_crack".to_string(),
                name: "Hash Cracker".to_string(),
                description: "Crack password hashes".to_string(),
                category: ModuleCategory::PasswordAttacks,
                command: "hashcat".to_string(),
                dependencies: vec!["hashcat".to_string()],
                is_installed: false,
            },
            
            // Wireless Attacks
            Module {
                id: "wifi_scan".to_string(),
                name: "WiFi Scanner".to_string(),
                description: "Scan for wireless networks".to_string(),
                category: ModuleCategory::WirelessAttacks,
                command: "airmon-ng".to_string(),
                dependencies: vec!["aircrack-ng".to_string()],
                is_installed: false,
            },
            Module {
                id: "wpa_crack".to_string(),
                name: "WPA Cracker".to_string(),
                description: "Crack WPA/WPA2 networks".to_string(),
                category: ModuleCategory::WirelessAttacks,
                command: "aircrack-ng".to_string(),
                dependencies: vec!["aircrack-ng".to_string()],
                is_installed: false,
            },
            
            // Exploitation Tools
            Module {
                id: "exploit_search".to_string(),
                name: "Exploit Search".to_string(),
                description: "Search for exploits".to_string(),
                category: ModuleCategory::ExploitationTools,
                command: "searchsploit".to_string(),
                dependencies: vec!["exploitdb".to_string()],
                is_installed: false,
            },
            Module {
                id: "exploit_dev".to_string(),
                name: "Exploit Development".to_string(),
                description: "Tools for exploit development".to_string(),
                category: ModuleCategory::ExploitationTools,
                command: "msfvenom".to_string(),
                dependencies: vec!["metasploit-framework".to_string()],
                is_installed: false,
            },
            
            // Post Exploitation
            Module {
                id: "priv_esc".to_string(),
                name: "Privilege Escalation".to_string(),
                description: "Tools for privilege escalation".to_string(),
                category: ModuleCategory::PostExploitation,
                command: "linpeas".to_string(),
                dependencies: vec!["linpeas".to_string()],
                is_installed: false,
            },
            Module {
                id: "persistence".to_string(),
                name: "Persistence".to_string(),
                description: "Tools for maintaining access".to_string(),
                category: ModuleCategory::PostExploitation,
                command: "msfvenom".to_string(),
                dependencies: vec!["metasploit-framework".to_string()],
                is_installed: false,
            },
            
            // Reporting
            Module {
                id: "report_gen".to_string(),
                name: "Report Generator".to_string(),
                description: "Generate detailed reports".to_string(),
                category: ModuleCategory::Reporting,
                command: "reportgen".to_string(),
                dependencies: vec![],
                is_installed: false,
            },
        ];
        
        // Check for installed dependencies
        for module in &mut self.modules {
            module.is_installed = module.dependencies.iter().all(|dep| {
                std::process::Command::new("which")
                    .arg(dep)
                    .output()
                    .map(|output| output.status.success())
                    .unwrap_or(false)
            });
        }

        // Initialize plugin manager
        let plugin_dir = Self::config_path().join("plugins");
        let plugin_manager = PluginManager::new(plugin_dir);
        self.runtime.block_on(async {
            if let Err(e) = plugin_manager.load_plugins().await {
                eprintln!("Failed to load plugins: {}", e);
            }
        });

        // Initialize exploit executor
        let sandbox_dir = Self::config_path().join("sandbox");
        let exploit_executor = ExploitExecutor::new(sandbox_dir);
        
        // Register some example exploits
        let config = ExploitConfig {
            name: "example-exploit".to_string(),
            description: "An example exploit".to_string(),
            command: "echo".to_string(),
            arguments: vec!["Hello".to_string()],
            timeout: 30,
            sandbox: true,
            resource_limits: ResourceLimits {
                max_memory: 1024 * 1024 * 100, // 100MB
                max_cpu_time: 30 * 1000000, // 30 seconds
                max_file_size: 1024 * 1024, // 1MB
                max_processes: 10,
                network_access: false,
                filesystem_access: true,
            },
        };
        
        self.runtime.block_on(async {
            exploit_executor.register_exploit(config).await;
        });

        // Initialize report generator
        let template_dir = Self::config_path().join("templates");
        let output_dir = Self::config_path().join("reports");
        let report_generator = ReportGenerator::new(template_dir, output_dir);
    }

    fn render_modules_panel(&mut self, ui: &mut Ui) {
        ui.heading("Modules");
        ui.add_space(20.0);
        
        ui.horizontal(|ui| {
            // Left side - Categories
            ui.vertical(|ui| {
                ui.heading("Categories");
                for category in [
                    ModuleCategory::InformationGathering,
                    ModuleCategory::VulnerabilityAnalysis,
                    ModuleCategory::WebApplication,
                    ModuleCategory::DatabaseAssessment,
                    ModuleCategory::PasswordAttacks,
                    ModuleCategory::WirelessAttacks,
                    ModuleCategory::ExploitationTools,
                    ModuleCategory::PostExploitation,
                    ModuleCategory::Reporting,
                ].iter() {
                    let is_selected = self.selected_category.as_ref() == Some(category);
                    if ui.selectable_label(is_selected, format!("{:?}", category)).clicked() {
                        self.selected_category = Some(category.clone());
                    }
                }
            });
            
            ui.separator();
            
            // Right side - Modules
            ui.vertical(|ui| {
                if let Some(category) = &self.selected_category {
                    ui.heading(format!("{:?} Modules", category));
                    ScrollArea::vertical().show(ui, |ui| {
                        for module in self.modules.iter().filter(|m| m.category == *category) {
                            let is_selected = self.selected_module.as_ref() == Some(&module.id);
                            ui.horizontal(|ui| {
                                if ui.selectable_label(is_selected, &module.name).clicked() {
                                    self.selected_module = Some(module.id.clone());
                                }
                                if !module.is_installed {
                                    ui.label(RichText::new("⚠").color(Color32::YELLOW))
                                        .on_hover_text("Dependencies not installed");
                                }
                            });
                        }
                    });
                }
                
                if let Some(module_id) = &self.selected_module {
                    if let Some(module) = self.modules.iter().find(|m| m.id == *module_id) {
                        ui.add_space(10.0);
                        ui.group(|ui| {
                            ui.heading("Module Details");
                            ui.label(format!("Name: {}", module.name));
                            ui.label(format!("Description: {}", module.description));
                            ui.label(format!("Command: {}", module.command));
                            
                            if !module.dependencies.is_empty() {
                                ui.label("Dependencies:");
                                for dep in &module.dependencies {
                                    ui.label(format!("• {}", dep));
                                }
                            }
                            
                            ui.add_space(10.0);
                            ui.horizontal(|ui| {
                                ui.label("Target:");
                                ui.text_edit_singleline(&mut self.module_target);
                            });
                            ui.horizontal(|ui| {
                                ui.label("Arguments:");
                                ui.text_edit_singleline(&mut self.module_arguments);
                            });
                            
                            if ui.button("Run Module").clicked() {
                                let arguments: Vec<String> = self.module_arguments
                                    .split_whitespace()
                                    .map(String::from)
                                    .collect();
                                
                                self.execute_module(&module.id, &self.module_target, &arguments);
                            }
                        });
                        
                        ui.add_space(10.0);
                        
                        // Show execution history
                        ui.group(|ui| {
                            ui.heading("Execution History");
                            ScrollArea::vertical().show(ui, |ui| {
                                for (i, execution) in self.module_executions.iter().enumerate() {
                                    if execution.module_id == *module_id {
                                        let is_selected = self.current_execution == Some(i);
                                        if ui.selectable_label(is_selected, 
                                            format!("{} - {} - {:?}", 
                                                execution.start_time.format("%Y-%m-%d %H:%M:%S"),
                                                execution.target,
                                                execution.status))
                                            .clicked() {
                                            self.current_execution = Some(i);
                                        }
                                    }
                                }
                            });
                        });
                        
                        // Show current execution output
                        if let Some(execution_idx) = self.current_execution {
                            if let Some(execution) = self.module_executions.get(execution_idx) {
                                if execution.module_id == *module_id {
                                    ui.add_space(10.0);
                                    ui.label("Execution Output:");
                                    ui.text_edit_multiline(&mut execution.output.clone());
                                }
                            }
                        }

                        // Add Module Configuration
                        ui.add_space(10.0);
                        ui.heading("Module Configuration");
                        let config = self.module_configs.iter_mut()
                            .find(|c| c.module_id == *module_id)
                            .unwrap_or_else(|| {
                                self.module_configs.push(ModuleConfig {
                                    module_id: module_id.clone(),
                                    default_arguments: Vec::new(),
                                    default_target: String::new(),
                                    enabled: true,
                                    last_used: None,
                                });
                                self.module_configs.last_mut().unwrap()
                            });

                        ui.checkbox(&mut config.enabled, "Enabled");
                        ui.horizontal(|ui| {
                            ui.label("Default Target:");
                            ui.text_edit_singleline(&mut config.default_target);
                        });
                        ui.horizontal(|ui| {
                            ui.label("Default Arguments:");
                            ui.text_edit_singleline(&mut config.default_arguments.join(" "));
                        });

                        // Add Module Statistics
                        if let Some(stats) = self.module_stats.get(module_id) {
                            ui.add_space(10.0);
                            ui.heading("Module Statistics");
                            ui.label(format!("Total Runs: {}", stats.total_runs));
                            ui.label(format!("Successful: {}", stats.successful_runs));
                            ui.label(format!("Failed: {}", stats.failed_runs));
                            ui.label(format!("Success Rate: {:.1}%", 
                                if stats.total_runs > 0 {
                                    (stats.successful_runs as f32 / stats.total_runs as f32) * 100.0
                                } else {
                                    0.0
                                }));
                            ui.label(format!("Average Duration: {} seconds", 
                                stats.average_duration.num_seconds()));

                            if !stats.common_errors.is_empty() {
                                ui.collapsing("Common Errors", |ui| {
                                    for (error, count) in &stats.common_errors {
                                        ui.label(format!("{} ({} occurrences)", error, count));
                                    }
                                });
                            }
                        }

                        // Add Module Templates
                        ui.add_space(10.0);
                        ui.heading("Module Templates");
                        for template in self.module_templates.iter_mut() {
                            if template.module_id == *module_id {
                                ui.collapsing(&template.name, |ui| {
                                    ui.label(&template.description);
                                    ui.label("Arguments:");
                                    for arg in &template.arguments {
                                        ui.label(format!("• {}", arg));
                                    }
                                    if ui.button("Use Template").clicked() {
                                        self.module_arguments = template.arguments.join(" ");
                                    }
                                });
                            }
                        }

                        // Add Export Options
                        if let Some(execution_idx) = self.current_execution {
                            if let Some(execution) = self.module_executions.get(execution_idx) {
                                if execution.module_id == *module_id {
                                    ui.add_space(10.0);
                                    ui.heading("Export Options");
                                    ui.horizontal(|ui| {
                                        if ui.button("Export as TXT").clicked() {
                                            if let Err(e) = self.export_module_output(execution, "txt") {
                                                self.error_message = Some(format!("Failed to export: {}", e));
                                            }
                                        }
                                        if ui.button("Export as JSON").clicked() {
                                            if let Err(e) = self.export_module_output(execution, "json") {
                                                self.error_message = Some(format!("Failed to export: {}", e));
                                            }
                                        }
                                        if ui.button("Export as HTML").clicked() {
                                            if let Err(e) = self.export_module_output(execution, "html") {
                                                self.error_message = Some(format!("Failed to export: {}", e));
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    });
                }
            });
        });

        // Add Module Chain Builder
        ui.add_space(20.0);
        ui.group(|ui| {
            ui.heading("Module Chain Builder");
            ui.horizontal(|ui| {
                // Left side - Available modules
                ui.vertical(|ui| {
                    ui.label("Available Modules");
                    ScrollArea::vertical().show(ui, |ui| {
                        for module in &self.modules {
                            if ui.button(&module.name).clicked() {
                                self.module_chain.push(module.id.clone());
                            }
                        }
                    });
                });

                // Right side - Current chain
                ui.vertical(|ui| {
                    ui.label("Current Chain");
                    ScrollArea::vertical().show(ui, |ui| {
                        for (i, module_id) in self.module_chain.iter().enumerate() {
                            if let Some(module) = self.modules.iter().find(|m| m.id == *module_id) {
                                ui.horizontal(|ui| {
                                    ui.label(format!("{}. {}", i + 1, module.name));
                                    if ui.button("↑").clicked() && i > 0 {
                                        self.module_chain.swap(i, i - 1);
                                    }
                                    if ui.button("↓").clicked() && i < self.module_chain.len() - 1 {
                                        self.module_chain.swap(i, i + 1);
                                    }
                                    if ui.button("×").clicked() {
                                        self.module_chain.remove(i);
                                    }
                                });
                            }
                        }
                    });

                    if !self.module_chain.is_empty() {
                        ui.add_space(10.0);
                        if ui.button("Run Chain").clicked() {
                            self.run_module_chain(&self.module_chain, &self.module_target);
                        }
                    }
                });
            });

            // Chain Results
            if !self.module_chain_results.is_empty() {
                ui.add_space(10.0);
                ui.label("Chain Execution Results:");
                ui.text_edit_multiline(&mut self.module_chain_results);
            }
        });

        // Add plugin management section
        ui.add_space(10.0);
        ui.heading("Plugins");
        ScrollArea::vertical().show(ui, |ui| {
            for plugin in self.plugin_manager.list_plugins().await {
                ui.collapsing(&plugin.name, |ui| {
                    ui.label(format!("Version: {}", plugin.version));
                    ui.label(format!("Description: {}", plugin.description));
                    ui.label(format!("Author: {}", plugin.author));
                    ui.label(format!("Category: {}", plugin.category));
                    
                    if !plugin.dependencies.is_empty() {
                        ui.label("Dependencies:");
                        for dep in &plugin.dependencies {
                            ui.label(format!("• {}", dep));
                        }
                    }
                });
            }
        });

        // Add exploit execution section
        ui.add_space(10.0);
        ui.heading("Exploit Execution");
        if let Some(exploit) = &self.selected_exploit {
            if ui.button("Execute Exploit").clicked() {
                let target = self.scan_target.clone();
                let exploit = exploit.clone();
                let executor = self.exploit_executor.clone();
                
                self.runtime.spawn(async move {
                    match executor.execute_exploit(&exploit, &target, &[]).await {
                        Ok(output) => {
                            // Handle successful execution
                        }
                        Err(e) => {
                            // Handle execution error
                        }
                    }
                });
            }
        }

        // Add reporting section
        ui.add_space(10.0);
        ui.heading("Reports");
        if ui.button("Generate PDF Report").clicked() {
            if let Some(scan_result) = &self.scan_results {
                let report = Report {
                    title: "Scan Report".to_string(),
                    timestamp: Utc::now(),
                    target: self.scan_target.clone(),
                    scan_results: vec![scan_result.clone()],
                    vulnerabilities: scan_result.vulnerabilities.clone(),
                    executive_summary: "Summary of findings".to_string(),
                    recommendations: vec!["Fix vulnerabilities".to_string()],
                    metadata: std::collections::HashMap::new(),
                };
                
                let generator = self.report_generator.clone();
                self.runtime.spawn(async move {
                    if let Ok(path) = generator.generate_pdf(&report).await {
                        // Handle successful report generation
                    }
                });
            }
        }
    }

    fn execute_module(&mut self, module_id: &str, target: &str, arguments: &[String]) {
        if let Some(module) = self.modules.iter().find(|m| m.id == module_id) {
            if !module.is_installed {
                self.error_message = Some(format!("Module {} is not installed. Please install dependencies first.", module.name));
                return;
            }

            let execution = ModuleExecution {
                module_id: module_id.to_string(),
                target: target.to_string(),
                arguments: arguments.to_vec(),
                status: ExecutionStatus::Running,
                output: String::new(),
                start_time: chrono::Utc::now(),
                end_time: None,
            };

            self.module_executions.push(execution);
            self.current_execution = Some(self.module_executions.len() - 1);

            let module = module.clone();
            let runtime = self.runtime.clone();
            let ctx = self.ctx.clone();
            let module_executions = &mut self.module_executions;
            let current_execution = self.current_execution.unwrap();

            runtime.spawn(async move {
                let mut command = std::process::Command::new(&module.command);
                
                // Add target and arguments
                command.arg(&target);
                for arg in arguments {
                    command.arg(arg);
                }

                match command.output() {
                    Ok(output) => {
                        let status = if output.status.success() {
                            ExecutionStatus::Completed
                        } else {
                            ExecutionStatus::Failed
                        };

                        let output_str = String::from_utf8_lossy(&output.stdout).to_string();
                        let error_str = String::from_utf8_lossy(&output.stderr).to_string();

                        if let Some(execution) = module_executions.get_mut(current_execution) {
                            execution.status = status;
                            execution.output = if !error_str.is_empty() {
                                format!("{}\nError: {}", output_str, error_str)
                            } else {
                                output_str
                            };
                            execution.end_time = Some(chrono::Utc::now());
                        }
                    }
                    Err(e) => {
                        if let Some(execution) = module_executions.get_mut(current_execution) {
                            execution.status = ExecutionStatus::Failed;
                            execution.output = format!("Failed to execute command: {}", e);
                            execution.end_time = Some(chrono::Utc::now());
                        }
                    }
                }

                if let Some(ctx) = ctx {
                    ctx.request_repaint();
                }
            });
        }
    }

    fn load_module_configs(&mut self) {
        let config_path = Self::config_path().join("module_configs.json");
        if let Ok(data) = fs::read_to_string(&config_path) {
            if let Ok(configs) = serde_json::from_str(&data) {
                self.module_configs = configs;
            }
        }
    }

    fn save_module_configs(&self) {
        let config_path = Self::config_path().join("module_configs.json");
        if let Ok(json) = serde_json::to_string_pretty(&self.module_configs) {
            let _ = fs::write(config_path, json);
        }
    }

    fn load_module_templates(&mut self) {
        let templates_path = Self::config_path().join("module_templates.json");
        if let Ok(data) = fs::read_to_string(&templates_path) {
            if let Ok(templates) = serde_json::from_str(&data) {
                self.module_templates = templates;
            }
        }
    }

    fn save_module_templates(&self) {
        let templates_path = Self::config_path().join("module_templates.json");
        if let Ok(json) = serde_json::to_string_pretty(&self.module_templates) {
            let _ = fs::write(templates_path, json);
        }
    }

    fn config_path() -> PathBuf {
        let user_dirs = UserDirs::new().unwrap();
        let home = user_dirs.home_dir();
        home.join(".sarissa")
    }

    fn update_module_stats(&mut self, module_id: &str, execution: &ModuleExecution) {
        let stats = self.module_stats.entry(module_id.to_string())
            .or_insert(ModuleExecutionStats {
                total_runs: 0,
                successful_runs: 0,
                failed_runs: 0,
                average_duration: chrono::Duration::seconds(0),
                last_success: None,
                last_failure: None,
                common_errors: Vec::new(),
            });

        stats.total_runs += 1;
        match execution.status {
            ExecutionStatus::Completed => {
                stats.successful_runs += 1;
                stats.last_success = Some(chrono::Utc::now());
            }
            ExecutionStatus::Failed => {
                stats.failed_runs += 1;
                stats.last_failure = Some(chrono::Utc::now());
                
                // Update common errors
                if let Some(error) = execution.output.lines().next() {
                    if let Some((_, count)) = stats.common_errors.iter_mut()
                        .find(|(msg, _)| msg == error) {
                        *count += 1;
                    } else {
                        stats.common_errors.push((error.to_string(), 1));
                    }
                }
            }
            _ => {}
        }

        // Update average duration
        if let Some(end_time) = execution.end_time {
            let duration = end_time - execution.start_time;
            stats.average_duration = (stats.average_duration * (stats.total_runs - 1) as i32 + duration) 
                / stats.total_runs as i32;
        }
    }

    fn export_module_output(&self, execution: &ModuleExecution, format: &str) -> Result<(), String> {
        let export_dir = Self::config_path().join("exports");
        fs::create_dir_all(&export_dir).map_err(|e| e.to_string())?;

        let filename = format!("{}_{}_{}", 
            execution.module_id,
            execution.start_time.format("%Y%m%d_%H%M%S"),
            format);

        match format {
            "txt" => {
                let content = format!(
                    "Module: {}\nTarget: {}\nArguments: {}\nStatus: {:?}\nStart Time: {}\nEnd Time: {}\n\nOutput:\n{}",
                    execution.module_id,
                    execution.target,
                    execution.arguments.join(" "),
                    execution.status,
                    execution.start_time,
                    execution.end_time.unwrap_or(chrono::Utc::now()),
                    execution.output
                );
                fs::write(export_dir.join(filename), content)
                    .map_err(|e| e.to_string())
            }
            "json" => {
                let content = serde_json::to_string_pretty(execution)
                    .map_err(|e| e.to_string())?;
                fs::write(export_dir.join(filename), content)
                    .map_err(|e| e.to_string())
            }
            "html" => {
                let content = format!(
                    "<html><body>
                    <h1>Module Execution Report</h1>
                    <h2>Details</h2>
                    <ul>
                        <li>Module: {}</li>
                        <li>Target: {}</li>
                        <li>Arguments: {}</li>
                        <li>Status: {:?}</li>
                        <li>Start Time: {}</li>
                        <li>End Time: {}</li>
                    </ul>
                    <h2>Output</h2>
                    <pre>{}</pre>
                    </body></html>",
                    execution.module_id,
                    execution.target,
                    execution.arguments.join(" "),
                    execution.status,
                    execution.start_time,
                    execution.end_time.unwrap_or(chrono::Utc::now()),
                    execution.output
                );
                fs::write(export_dir.join(filename), content)
                    .map_err(|e| e.to_string())
            }
            _ => Err("Unsupported export format".to_string())
        }
    }

    fn run_module_chain(&mut self, chain: &[String], target: &str) {
        self.module_chain_results = "Starting module chain execution...\n".to_string();
        let chain = chain.to_vec();
        let target = target.to_string();
        let runtime = self.runtime.clone();
        let ctx = self.ctx.clone();
        let module_executions = &mut self.module_executions;
        let module_chain_results = &mut self.module_chain_results;

        runtime.spawn(async move {
            for module_id in chain {
                if let Some(module) = self.modules.iter().find(|m| m.id == module_id) {
                    let execution = ModuleExecution {
                        module_id: module_id.clone(),
                        target: target.clone(),
                        arguments: Vec::new(),
                        status: ExecutionStatus::Running,
                        output: String::new(),
                        start_time: chrono::Utc::now(),
                        end_time: None,
                    };

                    module_executions.push(execution);
                    let current_execution = module_executions.len() - 1;

                    let mut command = std::process::Command::new(&module.command);
                    command.arg(&target);

                    match command.output() {
                        Ok(output) => {
                            let status = if output.status.success() {
                                ExecutionStatus::Completed
                            } else {
                                ExecutionStatus::Failed
                            };

                            let output_str = String::from_utf8_lossy(&output.stdout).to_string();
                            let error_str = String::from_utf8_lossy(&output.stderr).to_string();

                            if let Some(execution) = module_executions.get_mut(current_execution) {
                                execution.status = status;
                                execution.output = if !error_str.is_empty() {
                                    format!("{}\nError: {}", output_str, error_str)
                                } else {
                                    output_str
                                };
                                execution.end_time = Some(chrono::Utc::now());
                            }

                            module_chain_results.push_str(&format!(
                                "\nModule {} completed with status: {:?}\nOutput:\n{}\n",
                                module_id, status, output_str
                            ));
                        }
                        Err(e) => {
                            if let Some(execution) = module_executions.get_mut(current_execution) {
                                execution.status = ExecutionStatus::Failed;
                                execution.output = format!("Failed to execute command: {}", e);
                                execution.end_time = Some(chrono::Utc::now());
                            }

                            module_chain_results.push_str(&format!(
                                "\nModule {} failed: {}\n",
                                module_id, e
                            ));
                        }
                    }
                }
            }

            if let Some(ctx) = ctx {
                ctx.request_repaint();
            }
        });
    }
}

// Chart widget for visualization
struct Chart<'a> {
    ui: &'a mut Ui,
    size: [f32; 2],
    data: Vec<(&'static str, usize, Color32)>,
}

impl<'a> Chart<'a> {
    fn new(ui: &'a mut Ui) -> Self {
        Self {
            ui,
            size: [400.0, 200.0],
            data: Vec::new(),
        }
    }

    fn set_size(&mut self, width: f32, height: f32) {
        self.size = [width, height];
    }

    fn set_data(&mut self, data: Vec<(&'static str, usize, Color32)>) {
        self.data = data;
    }

    fn draw(&mut self) {
        let (response, painter) = self.ui.allocate_painter(self.size, egui::Sense::hover());
        let rect = response.rect;

        // Draw background
        painter.rect_filled(rect, 0.0, Color32::from_gray(240));

        // Calculate bar width and spacing
        let bar_width = (rect.width() - 40.0) / self.data.len() as f32;
        let spacing = 10.0;

        // Find maximum value for scaling
        let max_value = self.data.iter().map(|(_, value, _)| *value).max().unwrap_or(1) as f32;

        // Draw bars
        for (i, (label, value, color)) in self.data.iter().enumerate() {
            let x = rect.left() + 20.0 + (i as f32 * (bar_width + spacing));
            let height = (*value as f32 / max_value) * (rect.height() - 40.0);
            let y = rect.bottom() - height - 20.0;

            // Draw bar
            painter.rect_filled(
                egui::Rect::from_min_size(
                    egui::pos2(x, y),
                    egui::vec2(bar_width, height),
                ),
                0.0,
                *color,
            );

            // Draw label
            painter.text(
                egui::pos2(x + bar_width / 2.0, rect.bottom() - 10.0),
                egui::Align2::CENTER_TOP,
                *label,
                egui::FontId::new(12.0, egui::FontFamily::Proportional),
                Color32::BLACK,
            );

            // Draw value
            painter.text(
                egui::pos2(x + bar_width / 2.0, y - 5.0),
                egui::Align2::CENTER_BOTTOM,
                value.to_string(),
                egui::FontId::new(12.0, egui::FontFamily::Proportional),
                Color32::BLACK,
            );
        }
    }
}

// Add these new structs near the top with other structs
#[derive(Clone, Serialize, Deserialize)]
struct ModuleConfig {
    module_id: String,
    default_arguments: Vec<String>,
    default_target: String,
    enabled: bool,
    last_used: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ModuleTemplate {
    name: String,
    description: String,
    module_id: String,
    arguments: Vec<String>,
    variables: Vec<String>,
}

#[derive(Clone)]
struct ModuleExecutionStats {
    total_runs: usize,
    successful_runs: usize,
    failed_runs: usize,
    average_duration: chrono::Duration,
    last_success: Option<chrono::DateTime<chrono::Utc>>,
    last_failure: Option<chrono::DateTime<chrono::Utc>>,
    common_errors: Vec<(String, usize)>, // (error message, count)
}

// Add these new enums near the top with other enums
#[derive(PartialEq, Clone)]
enum ModuleCategory {
    InformationGathering,
    VulnerabilityAnalysis,
    WebApplication,
    DatabaseAssessment,
    PasswordAttacks,
    WirelessAttacks,
    ExploitationTools,
    PostExploitation,
    Reporting,
}

#[derive(Clone)]
struct Module {
    id: String,
    name: String,
    description: String,
    category: ModuleCategory,
    command: String,
    dependencies: Vec<String>,
    is_installed: bool,
}

#[derive(Clone)]
struct ModuleExecution {
    module_id: String,
    target: String,
    arguments: Vec<String>,
    status: ExecutionStatus,
    output: String,
    start_time: chrono::DateTime<chrono::Utc>,
    end_time: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, PartialEq)]
enum ExecutionStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

impl eframe::App for SarissaApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.check_state_updates();

        // Check scheduled scans
        for scan in &mut self.scheduled_scans {
            if scan.enabled && scan.next_run <= Utc::now() {
                let scan = scan.clone();
                let scanner = &mut self.scanner;
                let runtime = self.runtime.clone();
                runtime.spawn(async move {
                    let _ = scanner.run_scheduled_scan(&scan).await;
                });
                scan.last_run = Some(Utc::now());
                scan.next_run = scan.calculate_next_run();
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            self.render_top_panel(ui);
            
            match self.current_tab {
                Tab::Dashboard => {
                    self.render_dashboard(ui);
                }
                Tab::Scan => {
                    self.render_scan_panel(ui);
                }
                Tab::Exploits => {
                    self.render_exploits_panel(ui);
                }
                Tab::Reports => {
                    self.render_reports_panel(ui);
                }
                Tab::Settings => {
                    self.render_settings_panel(ui);
                }
                Tab::Modules => {
                    self.render_modules_panel(ui);
                }
                Tab::Basic => {
                    ui.heading("Basic Exploits");
                    // Display basic exploits here
                }
                Tab::Advanced => {
                    ui.heading("Advanced Tools");
                    ui.add_space(10.0);
                    
                    // Exploit Chain Builder Section
                    ui.group(|ui| {
                        ui.heading("Exploit Chain Builder");
                        ui.add_space(5.0);
                        
                        // Chain Management
                        ui.horizontal(|ui| {
                            if ui.button("New Chain").clicked() {
                                self.new_chain_name.clear();
                                self.new_chain_description.clear();
                                self.exploit_chain.clear();
                            }
                            if ui.button("Save Chain").clicked() && !self.exploit_chain.is_empty() {
                                let chain = ExploitChain {
                                    name: self.new_chain_name.clone(),
                                    exploits: self.exploit_chain.clone(),
                                    description: self.new_chain_description.clone(),
                                    created_at: chrono::Utc::now(),
                                };
                                self.exploit_chains.push(chain);
                            }
                        });
                        
                        ui.add_space(10.0);
                        
                        // Chain Editor
                        ui.horizontal(|ui| {
                            // Left side - Chain list and details
                            ui.vertical(|ui| {
                                ui.heading("Saved Chains");
                                ScrollArea::vertical().show(ui, |ui| {
                                    for (i, chain) in self.exploit_chains.iter().enumerate() {
                                        let is_selected = self.selected_chain == Some(i);
                                        if ui.selectable_label(is_selected, &chain.name).clicked() {
                                            self.selected_chain = Some(i);
                                            self.exploit_chain = chain.exploits.clone();
                                            self.new_chain_name = chain.name.clone();
                                            self.new_chain_description = chain.description.clone();
                                        }
                                    }
                                });
                                
                                ui.add_space(10.0);
                                ui.label("Chain Details");
                                ui.horizontal(|ui| {
                                    ui.label("Name:");
                                    ui.text_edit_singleline(&mut self.new_chain_name);
                                });
                                ui.horizontal(|ui| {
                                    ui.label("Description:");
                                    ui.text_edit_singleline(&mut self.new_chain_description);
                                });
                            });
                            
                            // Right side - Exploit selection and chain building
                            ui.vertical(|ui| {
                                ui.heading("Build Chain");
                                ui.horizontal(|ui| {
                                    if ui.button("Add Exploit").clicked() {
                                        // Show exploit selection dialog
                                        let available_exploits: Vec<String> = self.exploit_manager.lock().await
                                            .get_modules()
                                            .iter()
                                            .map(|m| m.id().to_string())
                                            .collect();
                                        
                                        // In a real implementation, show a popup with the list
                                        if !available_exploits.is_empty() {
                                            self.exploit_chain.push(available_exploits[0].clone());
                                        }
                                    }
                                    if ui.button("Clear Chain").clicked() {
                                        self.exploit_chain.clear();
                                    }
                                });
                                
                                ui.add_space(5.0);
                                ui.label("Current Chain:");
                                ScrollArea::vertical().show(ui, |ui| {
                                    for (i, exploit_id) in self.exploit_chain.iter().enumerate() {
                                        ui.horizontal(|ui| {
                                            ui.label(format!("{}. {}", i + 1, exploit_id));
                                            if ui.button("↑").clicked() && i > 0 {
                                                self.exploit_chain.swap(i, i - 1);
                                            }
                                            if ui.button("↓").clicked() && i < self.exploit_chain.len() - 1 {
                                                self.exploit_chain.swap(i, i + 1);
                                            }
                                            if ui.button("×").clicked() {
                                                self.exploit_chain.remove(i);
                                            }
                                        });
                                    }
                                });
                                
                                ui.add_space(10.0);
                                if ui.button("Run Chain").clicked() && !self.exploit_chain.is_empty() {
                                    // Execute the chain
                                    let chain = self.exploit_chain.clone();
                                    let exploit_manager = self.exploit_manager.clone();
                                    let target = self.scan_results.as_ref().map(|r| r.target.clone());
                                    
                                    if let Some(target) = target {
                                        self.exploit_chain_results = "Running exploit chain...\n".to_string();
                                        let runtime = self.runtime.clone();
                                        let ctx = self.ctx.clone();
                                        
                                        runtime.spawn(async move {
                                            for exploit_id in chain {
                                                if let Some(module) = exploit_manager.lock().await.get_modules()
                                                    .iter()
                                                    .find(|m| m.id() == &exploit_id) {
                                                    match module.run(&target, 0).await {
                                                        Ok(result) => {
                                                            // Update results
                                                            if let Some(ctx) = &ctx {
                                                                ctx.request_repaint();
                                                            }
                                                        }
                                                        Err(e) => {
                                                            // Handle error
                                                            if let Some(ctx) = &ctx {
                                                                ctx.request_repaint();
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        });
                                    } else {
                                        self.error_message = Some("No target available. Please run a scan first.".to_string());
                                    }
                                }
                            });
                        });
                        
                        ui.add_space(10.0);
                        ui.label("Chain Execution Results:");
                        ui.text_edit_multiline(&mut self.exploit_chain_results);
                    });
                    
                    ui.add_space(20.0);
                    ui.add(Separator::default());
                    ui.add_space(10.0);
                    
                    // Custom Payload Generator Section
                    ui.group(|ui| {
                        ui.heading("Custom Payload Generator");
                        ui.add_space(5.0);
                        
                        // Payload Template Editor
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label("Payload Template:");
                                ui.text_edit_multiline(&mut self.payload_template);
                                ui.label("Available Variables:");
                                ui.label("• {value} - Current value from the list");
                                ui.label("• {target} - Target hostname/IP");
                                ui.label("• {port} - Target port");
                                ui.label("• {timestamp} - Current timestamp");
                            });
                            
                            ui.vertical(|ui| {
                                ui.label("Payload Values (one per line):");
                                ui.text_edit_multiline(&mut self.payload_values);
                                ui.horizontal(|ui| {
                                    if ui.button("Load from File").clicked() {
                                        // In a real implementation, show file dialog
                                    }
                                    if ui.button("Clear Values").clicked() {
                                        self.payload_values.clear();
                                    }
                                });
                            });
                        });
                        
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            if ui.button("Generate and Test").clicked() {
                                let values: Vec<String> = self.payload_values.lines()
                                    .map(String::from)
                                    .filter(|s| !s.trim().is_empty())
                                    .collect();
                                
                                if values.is_empty() {
                                    self.error_message = Some("No payload values provided".to_string());
                                    return;
                                }
                                
                                if let Some(target) = &self.scan_results.as_ref().map(|r| r.target.clone()) {
                                    self.custom_payload_results = "Testing custom payloads...\n".to_string();
                                    
                                    for value in values {
                                        let payload = self.payload_template
                                            .replace("{value}", &value)
                                            .replace("{target}", target)
                                            .replace("{timestamp}", &chrono::Utc::now().to_rfc3339());
                                        
                                        // In a real implementation, send the payload to the target
                                        self.custom_payload_results.push_str(&format!(
                                            "Payload: {}\nResponse: Simulated response\n\n",
                                            payload
                                        ));
                                    }
                                } else {
                                    self.error_message = Some("No target available. Please run a scan first.".to_string());
                                }
                            }
                            
                            if ui.button("Export Results").clicked() {
                                // In a real implementation, save results to file
                            }
                        });
                        
                        ui.add_space(10.0);
                        ui.label("Payload Test Results:");
                        ui.text_edit_multiline(&mut self.custom_payload_results);
                    });
                }
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = Config::load("config.yaml")?;

    // Initialize logging
    let logging_config = LoggingConfig {
        log_dir: config.logging.log_dir,
        log_level: config.logging.log_level,
        max_file_size: config.logging.max_file_size,
        max_files: config.logging.max_files,
    };
    init_logging(&logging_config)?;

    // Initialize monitoring
    let monitoring = Arc::new(MonitoringSystem::new());
    
    // Register health checks
    monitoring.register_health_check("database", config.monitoring.health_check_interval).await;
    monitoring.register_health_check("plugin_system", config.monitoring.health_check_interval).await;
    monitoring.register_health_check("security_manager", config.monitoring.health_check_interval).await;
    monitoring.register_health_check("collaboration", config.monitoring.health_check_interval).await;

    // Initialize database
    let db = Arc::new(Database::new(
        &config.database.url,
        config.database.max_connections,
        config.database.min_connections,
    ).await?);
    db.init().await?;

    // Initialize security manager
    let security_manager = Arc::new(security::SecurityManager::new(
        db.clone(),
        monitoring.get_metrics(),
    ));

    // Initialize plugin manager
    let plugin_manager = Arc::new(plugin::PluginManager::new(
        &config.plugin.plugin_dir,
        db.clone(),
        monitoring.get_metrics(),
    ));

    // Initialize collaboration manager
    let collaboration_manager = Arc::new(collaboration::CollaborationManager::new(
        db.clone(),
        monitoring.get_metrics(),
    ));

    // Start health check loop
    let monitoring_clone = monitoring.clone();
    tokio::spawn(async move {
        loop {
            monitoring_clone.run_health_checks().await;
            tokio::time::sleep(config.monitoring.health_check_interval).await;
        }
    });

    // Start metrics collection loop
    let monitoring_clone = monitoring.clone();
    tokio::spawn(async move {
        loop {
            // Collect system metrics
            if let Ok(cpu_usage) = sys_info::cpu_usage() {
                monitoring_clone.get_metrics().cpu_usage.set(cpu_usage);
            }
            if let Ok(mem_info) = sys_info::mem_info() {
                monitoring_clone.get_metrics().memory_usage.set(mem_info.total as f64);
            }
            if let Ok(disk_info) = sys_info::disk_info() {
                monitoring_clone.get_metrics().disk_usage.set(disk_info.total as f64);
            }

            tokio::time::sleep(config.monitoring.metrics_interval).await;
        }
    });

    // Start log cleanup loop
    let logging_config = logging_config.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = cleanup_old_logs(&logging_config) {
                error!("Failed to cleanup old logs: {}", e);
            }
            tokio::time::sleep(config.logging.cleanup_interval).await;
        }
    });

    // Start UI
    let ui = ui::Dashboard::new(
        db.clone(),
        security_manager.clone(),
        plugin_manager.clone(),
        collaboration_manager.clone(),
        monitoring.clone(),
    );

    // Run UI in a separate thread
    std::thread::spawn(move || {
        let options = eframe::NativeOptions {
            initial_window_size: Some(egui::vec2(1280.0, 720.0)),
            ..Default::default()
        };
        eframe::run_native("Sarissa", options, Box::new(|cc| Box::new(ui)));
    });

    // Wait for shutdown signal
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("Shutting down...");
            
            // Update health status
            monitoring.update_health_status("database", HealthStatus::Unhealthy("Shutting down".to_string())).await;
            monitoring.update_health_status("plugin_system", HealthStatus::Unhealthy("Shutting down".to_string())).await;
            monitoring.update_health_status("security_manager", HealthStatus::Unhealthy("Shutting down".to_string())).await;
            monitoring.update_health_status("collaboration", HealthStatus::Unhealthy("Shutting down".to_string())).await;

            // Cleanup
            if let Err(e) = cleanup_old_logs(&logging_config) {
                error!("Failed to cleanup logs during shutdown: {}", e);
            }
        }
        Err(err) => {
            error!("Unable to listen for shutdown signal: {}", err);
        }
    }

    Ok(())
}
