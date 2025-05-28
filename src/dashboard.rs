use eframe::egui;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::Mutex;
use serde_json::Value;
use std::time::Duration;
use tokio::time;
use futures::StreamExt;
use tokio_tungstenite::{connect_async, WebSocketStream};
use tokio_tungstenite::tungstenite::Message;
use futures::SinkExt;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use std::str::FromStr;
use plotters::prelude::*;
use plotters_egui::PlotterEgui;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    pub theme: Theme,
    pub layout: Layout,
    pub refresh_interval: Duration,
    pub notification_settings: NotificationSettings,
    pub auto_refresh: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Theme {
    Light,
    Dark,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Layout {
    Default,
    Compact,
    Detailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardState {
    pub active_tab: Tab,
    pub selected_target: Option<String>,
    pub filter_criteria: FilterCriteria,
    pub sort_order: SortOrder,
    pub view_mode: ViewMode,
    pub metrics: Metrics,
    pub notifications: Vec<Notification>,
    pub charts: HashMap<String, ChartData>,
    pub real_time_data: RealTimeData,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Tab {
    Overview,
    Scans,
    Vulnerabilities,
    Reports,
    Settings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterCriteria {
    pub severity: Option<Severity>,
    pub status: Option<Status>,
    pub date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    pub search_term: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Status {
    Active,
    Completed,
    Failed,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SortOrder {
    DateAsc,
    DateDesc,
    SeverityAsc,
    SeverityDesc,
    NameAsc,
    NameDesc,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ViewMode {
    List,
    Grid,
    Timeline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    pub total_scans: u32,
    pub active_scans: u32,
    pub total_vulnerabilities: u32,
    pub critical_vulnerabilities: u32,
    pub high_vulnerabilities: u32,
    pub medium_vulnerabilities: u32,
    pub low_vulnerabilities: u32,
    pub scan_success_rate: f64,
    pub average_scan_time: Duration,
    pub last_scan_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub title: String,
    pub message: String,
    pub severity: Severity,
    pub timestamp: DateTime<Utc>,
    pub read: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartData {
    pub title: String,
    pub data_type: ChartDataType,
    pub data: Vec<DataPoint>,
    pub options: ChartOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChartDataType {
    Line,
    Bar,
    Pie,
    Scatter,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPoint {
    pub x: f64,
    pub y: f64,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartOptions {
    pub color: String,
    pub show_grid: bool,
    pub show_legend: bool,
    pub animation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealTimeData {
    pub active_scans: Vec<ScanStatus>,
    pub recent_events: Vec<Event>,
    pub system_metrics: SystemMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatus {
    pub id: String,
    pub target: String,
    pub progress: f64,
    pub status: Status,
    pub start_time: DateTime<Utc>,
    pub estimated_completion: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub type_: String,
    pub data: Value,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_usage: f64,
}

pub struct Dashboard {
    config: DashboardConfig,
    state: DashboardState,
    ws_client: Option<WebSocketClient>,
    plotter: PlotterEgui,
}

struct WebSocketClient {
    stream: WebSocketStream<tokio::net::TcpStream>,
    workspace_id: String,
}

impl Dashboard {
    pub fn new(config: DashboardConfig) -> Self {
        Self {
            config,
            state: DashboardState {
                active_tab: Tab::Overview,
                selected_target: None,
                filter_criteria: FilterCriteria {
                    severity: None,
                    status: None,
                    date_range: None,
                    search_term: None,
                },
                sort_order: SortOrder::DateDesc,
                view_mode: ViewMode::List,
                metrics: Metrics {
                    total_scans: 0,
                    active_scans: 0,
                    total_vulnerabilities: 0,
                    critical_vulnerabilities: 0,
                    high_vulnerabilities: 0,
                    medium_vulnerabilities: 0,
                    low_vulnerabilities: 0,
                    scan_success_rate: 0.0,
                    average_scan_time: Duration::from_secs(0),
                    last_scan_time: None,
                },
                notifications: Vec::new(),
                charts: HashMap::new(),
                real_time_data: RealTimeData {
                    active_scans: Vec::new(),
                    recent_events: Vec::new(),
                    system_metrics: SystemMetrics {
                        cpu_usage: 0.0,
                        memory_usage: 0.0,
                        disk_usage: 0.0,
                        network_usage: 0.0,
                    },
                },
            },
            ws_client: None,
            plotter: PlotterEgui::new(),
        }
    }

    pub async fn connect_websocket(&mut self, workspace_id: &str) -> Result<()> {
        let url = format!("ws://localhost:8080/ws/{}", workspace_id);
        let (ws_stream, _) = connect_async(url).await?;
        
        self.ws_client = Some(WebSocketClient {
            stream: ws_stream,
            workspace_id: workspace_id.to_string(),
        });
        
        Ok(())
    }

    pub fn render(&mut self, ctx: &egui::Context) {
        self.render_top_bar(ctx);
        self.render_sidebar(ctx);
        self.render_main_content(ctx);
        self.render_notifications(ctx);
        
        // Handle real-time updates
        if let Some(client) = &mut self.ws_client {
            while let Some(msg) = client.stream.next().now_or_never() {
                if let Ok(Message::Text(text)) = msg {
                    if let Ok(event) = serde_json::from_str::<Event>(&text) {
                        self.handle_realtime_event(event);
                    }
                }
            }
        }
        
        // Auto-refresh if enabled
        if self.config.auto_refresh {
            ctx.request_repaint_after(self.config.refresh_interval);
        }
    }

    fn render_top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Sarissa Dashboard");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Settings").clicked() {
                        self.state.active_tab = Tab::Settings;
                    }
                    if ui.button("Notifications").clicked() {
                        // Show notifications panel
                    }
                });
            });
        });
    }

    fn render_sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("sidebar").show(ctx, |ui| {
            ui.vertical(|ui| {
                if ui.selectable_label(self.state.active_tab == Tab::Overview, "Overview").clicked() {
                    self.state.active_tab = Tab::Overview;
                }
                if ui.selectable_label(self.state.active_tab == Tab::Scans, "Scans").clicked() {
                    self.state.active_tab = Tab::Scans;
                }
                if ui.selectable_label(self.state.active_tab == Tab::Vulnerabilities, "Vulnerabilities").clicked() {
                    self.state.active_tab = Tab::Vulnerabilities;
                }
                if ui.selectable_label(self.state.active_tab == Tab::Reports, "Reports").clicked() {
                    self.state.active_tab = Tab::Reports;
                }
            });
        });
    }

    fn render_main_content(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.state.active_tab {
                Tab::Overview => self.render_overview(ui),
                Tab::Scans => self.render_scans(ui),
                Tab::Vulnerabilities => self.render_vulnerabilities(ui),
                Tab::Reports => self.render_reports(ui),
                Tab::Settings => self.render_settings(ui),
            }
        });
    }

    fn render_overview(&mut self, ui: &mut egui::Ui) {
        ui.heading("Overview");
        
        // Metrics cards
        ui.horizontal(|ui| {
            self.render_metric_card(ui, "Total Scans", &self.state.metrics.total_scans.to_string());
            self.render_metric_card(ui, "Active Scans", &self.state.metrics.active_scans.to_string());
            self.render_metric_card(ui, "Total Vulnerabilities", &self.state.metrics.total_vulnerabilities.to_string());
        });
        
        // Charts
        ui.horizontal(|ui| {
            self.render_vulnerability_chart(ui);
            self.render_scan_trend_chart(ui);
        });
        
        // Real-time data
        ui.heading("Real-time Activity");
        self.render_realtime_data(ui);
    }

    fn render_metric_card(&mut self, ui: &mut egui::Ui, title: &str, value: &str) {
        ui.vertical(|ui| {
            ui.heading(title);
            ui.label(value);
        });
    }

    fn render_vulnerability_chart(&mut self, ui: &mut egui::Ui) {
        if let Some(chart) = self.state.charts.get("vulnerabilities") {
            self.plotter.plot(ui, |plot| {
                let mut chart = ChartBuilder::on(plot)
                    .caption(chart.title, ("sans-serif", 20))
                    .build_cartesian_2d(0f64..10f64, 0f64..10f64)?;
                
                chart.draw_series(LineSeries::new(
                    chart.data.iter().map(|p| (p.x, p.y)),
                    &RED,
                ))?;
                
                Ok(())
            });
        }
    }

    fn render_scan_trend_chart(&mut self, ui: &mut egui::Ui) {
        if let Some(chart) = self.state.charts.get("scan_trend") {
            self.plotter.plot(ui, |plot| {
                let mut chart = ChartBuilder::on(plot)
                    .caption(chart.title, ("sans-serif", 20))
                    .build_cartesian_2d(0f64..10f64, 0f64..10f64)?;
                
                chart.draw_series(BarSeries::new(
                    chart.data.iter().map(|p| (p.x, p.y)),
                    &BLUE,
                ))?;
                
                Ok(())
            });
        }
    }

    fn render_realtime_data(&mut self, ui: &mut egui::Ui) {
        // Active scans
        ui.heading("Active Scans");
        for scan in &self.state.real_time_data.active_scans {
            ui.horizontal(|ui| {
                ui.label(&scan.target);
                ui.add(egui::ProgressBar::new(scan.progress));
                ui.label(format!("{}%", (scan.progress * 100.0) as u32));
            });
        }
        
        // System metrics
        ui.heading("System Metrics");
        ui.horizontal(|ui| {
            ui.label(format!("CPU: {:.1}%", self.state.real_time_data.system_metrics.cpu_usage));
            ui.label(format!("Memory: {:.1}%", self.state.real_time_data.system_metrics.memory_usage));
            ui.label(format!("Disk: {:.1}%", self.state.real_time_data.system_metrics.disk_usage));
            ui.label(format!("Network: {:.1}%", self.state.real_time_data.system_metrics.network_usage));
        });
    }

    fn render_scans(&mut self, ui: &mut egui::Ui) {
        ui.heading("Scans");
        
        // Filter controls
        ui.horizontal(|ui| {
            ui.label("Filter:");
            egui::ComboBox::from_label("Status")
                .selected_text(format!("{:?}", self.state.filter_criteria.status))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.state.filter_criteria.status, Some(Status::Active), "Active");
                    ui.selectable_value(&mut self.state.filter_criteria.status, Some(Status::Completed), "Completed");
                    ui.selectable_value(&mut self.state.filter_criteria.status, Some(Status::Failed), "Failed");
                    ui.selectable_value(&mut self.state.filter_criteria.status, Some(Status::Pending), "Pending");
                });
        });
        
        // Scan list
        egui::ScrollArea::vertical().show(ui, |ui| {
            for scan in &self.state.real_time_data.active_scans {
                ui.horizontal(|ui| {
                    ui.label(&scan.target);
                    ui.label(format!("{:?}", scan.status));
                    ui.add(egui::ProgressBar::new(scan.progress));
                    ui.label(scan.start_time.format("%Y-%m-%d %H:%M:%S").to_string());
                });
            }
        });
    }

    fn render_vulnerabilities(&mut self, ui: &mut egui::Ui) {
        ui.heading("Vulnerabilities");
        
        // Filter controls
        ui.horizontal(|ui| {
            ui.label("Filter:");
            egui::ComboBox::from_label("Severity")
                .selected_text(format!("{:?}", self.state.filter_criteria.severity))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.state.filter_criteria.severity, Some(Severity::Critical), "Critical");
                    ui.selectable_value(&mut self.state.filter_criteria.severity, Some(Severity::High), "High");
                    ui.selectable_value(&mut self.state.filter_criteria.severity, Some(Severity::Medium), "Medium");
                    ui.selectable_value(&mut self.state.filter_criteria.severity, Some(Severity::Low), "Low");
                    ui.selectable_value(&mut self.state.filter_criteria.severity, Some(Severity::Info), "Info");
                });
        });
        
        // Vulnerability list
        egui::ScrollArea::vertical().show(ui, |ui| {
            // Render vulnerability items
        });
    }

    fn render_reports(&mut self, ui: &mut egui::Ui) {
        ui.heading("Reports");
        
        // Report generation controls
        ui.horizontal(|ui| {
            if ui.button("Generate Report").clicked() {
                // Generate report
            }
            if ui.button("Export").clicked() {
                // Export report
            }
        });
        
        // Report list
        egui::ScrollArea::vertical().show(ui, |ui| {
            // Render report items
        });
    }

    fn render_settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        
        // Theme selection
        ui.horizontal(|ui| {
            ui.label("Theme:");
            egui::ComboBox::from_label("")
                .selected_text(format!("{:?}", self.config.theme))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.config.theme, Theme::Light, "Light");
                    ui.selectable_value(&mut self.config.theme, Theme::Dark, "Dark");
                    ui.selectable_value(&mut self.config.theme, Theme::System, "System");
                });
        });
        
        // Layout selection
        ui.horizontal(|ui| {
            ui.label("Layout:");
            egui::ComboBox::from_label("")
                .selected_text(format!("{:?}", self.config.layout))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.config.layout, Layout::Default, "Default");
                    ui.selectable_value(&mut self.config.layout, Layout::Compact, "Compact");
                    ui.selectable_value(&mut self.config.layout, Layout::Detailed, "Detailed");
                });
        });
        
        // Auto-refresh toggle
        ui.checkbox(&mut self.config.auto_refresh, "Auto-refresh");
        
        // Refresh interval
        ui.horizontal(|ui| {
            ui.label("Refresh Interval:");
            ui.add(egui::Slider::new(&mut self.config.refresh_interval.as_secs(), 1..=60)
                .text("seconds"));
        });
    }

    fn render_notifications(&mut self, ui: &mut egui::Ui) {
        if !self.state.notifications.is_empty() {
            egui::Window::new("Notifications")
                .collapsible(true)
                .show(ui.ctx(), |ui| {
                    for notification in &self.state.notifications {
                        ui.horizontal(|ui| {
                            ui.label(&notification.title);
                            ui.label(&notification.message);
                            ui.label(notification.timestamp.format("%H:%M:%S").to_string());
                        });
                    }
                });
        }
    }

    fn handle_realtime_event(&mut self, event: Event) {
        match event.type_.as_str() {
            "scan_started" => {
                if let Some(scan_data) = event.data.get("scan") {
                    if let Ok(scan) = serde_json::from_value::<ScanStatus>(scan_data.clone()) {
                        self.state.real_time_data.active_scans.push(scan);
                    }
                }
            }
            "scan_progress" => {
                if let Some(scan_id) = event.data.get("scan_id").and_then(|v| v.as_str()) {
                    if let Some(progress) = event.data.get("progress").and_then(|v| v.as_f64()) {
                        if let Some(scan) = self.state.real_time_data.active_scans.iter_mut()
                            .find(|s| s.id == scan_id) {
                            scan.progress = progress;
                        }
                    }
                }
            }
            "scan_completed" => {
                if let Some(scan_id) = event.data.get("scan_id").and_then(|v| v.as_str()) {
                    self.state.real_time_data.active_scans.retain(|s| s.id != scan_id);
                }
            }
            "system_metrics" => {
                if let Ok(metrics) = serde_json::from_value::<SystemMetrics>(event.data) {
                    self.state.real_time_data.system_metrics = metrics;
                }
            }
            _ => {}
        }
        
        // Add to recent events
        self.state.real_time_data.recent_events.push(event);
        if self.state.real_time_data.recent_events.len() > 100 {
            self.state.real_time_data.recent_events.remove(0);
        }
    }
} 