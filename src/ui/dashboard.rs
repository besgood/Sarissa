use eframe::egui;
use egui::{Color32, RichText, Ui};
use egui_plot::{Plot, Line, PlotPoints, PlotUi};
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};
use serde_json::Value;
use uuid::Uuid;

use crate::security::{SecurityEvent, SecuritySeverity, SecurityCategory};
use crate::collaboration::{CollaborationEvent, CollaborationEventType};
use crate::scanning::{ScanResult, ScanStatus};

pub struct Dashboard {
    active_workspace: Option<Uuid>,
    time_range: TimeRange,
    security_events: Vec<SecurityEvent>,
    collaboration_events: Vec<CollaborationEvent>,
    scan_results: Vec<ScanResult>,
    metrics: DashboardMetrics,
    charts: DashboardCharts,
}

#[derive(Debug, Clone, Copy)]
pub enum TimeRange {
    LastHour,
    LastDay,
    LastWeek,
    LastMonth,
    Custom(DateTime<Utc>, DateTime<Utc>),
}

struct DashboardMetrics {
    total_scans: usize,
    active_scans: usize,
    vulnerabilities_found: usize,
    critical_vulnerabilities: usize,
    active_users: usize,
    security_events: usize,
}

struct DashboardCharts {
    scan_timeline: Vec<(DateTime<Utc>, usize)>,
    vulnerability_trend: Vec<(DateTime<Utc>, usize)>,
    user_activity: Vec<(DateTime<Utc>, usize)>,
    security_events_by_severity: HashMap<SecuritySeverity, usize>,
    security_events_by_category: HashMap<SecurityCategory, usize>,
}

impl Dashboard {
    pub fn new() -> Self {
        Self {
            active_workspace: None,
            time_range: TimeRange::LastDay,
            security_events: Vec::new(),
            collaboration_events: Vec::new(),
            scan_results: Vec::new(),
            metrics: DashboardMetrics {
                total_scans: 0,
                active_scans: 0,
                vulnerabilities_found: 0,
                critical_vulnerabilities: 0,
                active_users: 0,
                security_events: 0,
            },
            charts: DashboardCharts {
                scan_timeline: Vec::new(),
                vulnerability_trend: Vec::new(),
                user_activity: Vec::new(),
                security_events_by_severity: HashMap::new(),
                security_events_by_category: HashMap::new(),
            },
        }
    }

    pub fn show(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            self.show_workspace_selector(ui);
            self.show_time_range_selector(ui);
        });

        ui.add_space(10.0);

        // Metrics overview
        ui.horizontal(|ui| {
            self.show_metrics_overview(ui);
        });

        ui.add_space(10.0);

        // Charts and graphs
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                self.show_scan_timeline(ui);
                self.show_vulnerability_trend(ui);
            });
            ui.vertical(|ui| {
                self.show_user_activity(ui);
                self.show_security_events_distribution(ui);
            });
        });

        ui.add_space(10.0);

        // Recent events
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                self.show_recent_security_events(ui);
            });
            ui.vertical(|ui| {
                self.show_recent_collaboration_events(ui);
            });
        });
    }

    fn show_workspace_selector(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label("Workspace:");
            if ui.button("Select Workspace").clicked() {
                // TODO: Show workspace selection dialog
            }
            if let Some(workspace_id) = self.active_workspace {
                ui.label(format!("Current: {}", workspace_id));
            }
        });
    }

    fn show_time_range_selector(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label("Time Range:");
            if ui.button("Last Hour").clicked() {
                self.time_range = TimeRange::LastHour;
            }
            if ui.button("Last Day").clicked() {
                self.time_range = TimeRange::LastDay;
            }
            if ui.button("Last Week").clicked() {
                self.time_range = TimeRange::LastWeek;
            }
            if ui.button("Last Month").clicked() {
                self.time_range = TimeRange::LastMonth;
            }
            if ui.button("Custom").clicked() {
                // TODO: Show custom time range dialog
            }
        });
    }

    fn show_metrics_overview(&mut self, ui: &mut Ui) {
        let metrics = [
            ("Total Scans", self.metrics.total_scans, Color32::BLUE),
            ("Active Scans", self.metrics.active_scans, Color32::GREEN),
            ("Vulnerabilities", self.metrics.vulnerabilities_found, Color32::RED),
            ("Critical", self.metrics.critical_vulnerabilities, Color32::RED),
            ("Active Users", self.metrics.active_users, Color32::YELLOW),
            ("Security Events", self.metrics.security_events, Color32::ORANGE),
        ];

        for (label, value, color) in metrics {
            ui.vertical(|ui| {
                ui.label(RichText::new(label).color(color));
                ui.label(RichText::new(value.to_string()).size(24.0).strong());
            });
            ui.add_space(20.0);
        }
    }

    fn show_scan_timeline(&mut self, ui: &mut Ui) {
        ui.heading("Scan Timeline");
        let plot = Plot::new("scan_timeline")
            .view_aspect(2.0)
            .include_x(0.0)
            .include_y(0.0);

        plot.show(ui, |plot_ui| {
            let points: PlotPoints = self.charts.scan_timeline
                .iter()
                .map(|(time, count)| [time.timestamp() as f64, *count as f64])
                .collect();

            plot_ui.line(Line::new(points)
                .color(Color32::BLUE)
                .name("Scans"));
        });
    }

    fn show_vulnerability_trend(&mut self, ui: &mut Ui) {
        ui.heading("Vulnerability Trend");
        let plot = Plot::new("vulnerability_trend")
            .view_aspect(2.0)
            .include_x(0.0)
            .include_y(0.0);

        plot.show(ui, |plot_ui| {
            let points: PlotPoints = self.charts.vulnerability_trend
                .iter()
                .map(|(time, count)| [time.timestamp() as f64, *count as f64])
                .collect();

            plot_ui.line(Line::new(points)
                .color(Color32::RED)
                .name("Vulnerabilities"));
        });
    }

    fn show_user_activity(&mut self, ui: &mut Ui) {
        ui.heading("User Activity");
        let plot = Plot::new("user_activity")
            .view_aspect(2.0)
            .include_x(0.0)
            .include_y(0.0);

        plot.show(ui, |plot_ui| {
            let points: PlotPoints = self.charts.user_activity
                .iter()
                .map(|(time, count)| [time.timestamp() as f64, *count as f64])
                .collect();

            plot_ui.line(Line::new(points)
                .color(Color32::GREEN)
                .name("Active Users"));
        });
    }

    fn show_security_events_distribution(&mut self, ui: &mut Ui) {
        ui.heading("Security Events Distribution");
        
        // Events by severity
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label("By Severity");
                for (severity, count) in &self.charts.security_events_by_severity {
                    ui.horizontal(|ui| {
                        ui.label(format!("{:?}", severity));
                        ui.label(count.to_string());
                    });
                }
            });
            
            ui.vertical(|ui| {
                ui.label("By Category");
                for (category, count) in &self.charts.security_events_by_category {
                    ui.horizontal(|ui| {
                        ui.label(format!("{:?}", category));
                        ui.label(count.to_string());
                    });
                }
            });
        });
    }

    fn show_recent_security_events(&mut self, ui: &mut Ui) {
        ui.heading("Recent Security Events");
        
        for event in self.security_events.iter().take(10) {
            ui.horizontal(|ui| {
                ui.label(format!("{:?}", event.severity));
                ui.label(format!("{:?}", event.category));
                ui.label(&event.description);
                ui.label(event.timestamp.format("%H:%M:%S").to_string());
            });
        }
    }

    fn show_recent_collaboration_events(&mut self, ui: &mut Ui) {
        ui.heading("Recent Collaboration Events");
        
        for event in self.collaboration_events.iter().take(10) {
            ui.horizontal(|ui| {
                ui.label(format!("{:?}", event.event_type));
                ui.label(&event.details.to_string());
                ui.label(event.timestamp.format("%H:%M:%S").to_string());
            });
        }
    }

    pub fn update_metrics(&mut self) {
        // Update metrics based on current data
        self.metrics.total_scans = self.scan_results.len();
        self.metrics.active_scans = self.scan_results.iter()
            .filter(|scan| scan.status == ScanStatus::Running)
            .count();
        self.metrics.vulnerabilities_found = self.scan_results.iter()
            .map(|scan| scan.vulnerabilities.len())
            .sum();
        self.metrics.critical_vulnerabilities = self.scan_results.iter()
            .flat_map(|scan| &scan.vulnerabilities)
            .filter(|vuln| vuln.severity == "Critical")
            .count();
        self.metrics.security_events = self.security_events.len();
    }

    pub fn update_charts(&mut self) {
        // Update charts based on current data and time range
        let (start_time, end_time) = self.get_time_range();
        
        // Update scan timeline
        self.charts.scan_timeline = self.scan_results.iter()
            .filter(|scan| scan.start_time >= start_time && scan.start_time <= end_time)
            .fold(HashMap::new(), |mut acc, scan| {
                *acc.entry(scan.start_time).or_insert(0) += 1;
                acc
            })
            .into_iter()
            .collect();
        self.charts.scan_timeline.sort_by_key(|(time, _)| *time);

        // Update vulnerability trend
        self.charts.vulnerability_trend = self.scan_results.iter()
            .flat_map(|scan| &scan.vulnerabilities)
            .filter(|vuln| vuln.discovered_at >= start_time && vuln.discovered_at <= end_time)
            .fold(HashMap::new(), |mut acc, vuln| {
                *acc.entry(vuln.discovered_at).or_insert(0) += 1;
                acc
            })
            .into_iter()
            .collect();
        self.charts.vulnerability_trend.sort_by_key(|(time, _)| *time);

        // Update security events distribution
        self.charts.security_events_by_severity = self.security_events.iter()
            .filter(|event| event.timestamp >= start_time && event.timestamp <= end_time)
            .fold(HashMap::new(), |mut acc, event| {
                *acc.entry(event.severity.clone()).or_insert(0) += 1;
                acc
            });

        self.charts.security_events_by_category = self.security_events.iter()
            .filter(|event| event.timestamp >= start_time && event.timestamp <= end_time)
            .fold(HashMap::new(), |mut acc, event| {
                *acc.entry(event.category.clone()).or_insert(0) += 1;
                acc
            });
    }

    fn get_time_range(&self) -> (DateTime<Utc>, DateTime<Utc>) {
        let end_time = Utc::now();
        let start_time = match self.time_range {
            TimeRange::LastHour => end_time - Duration::hours(1),
            TimeRange::LastDay => end_time - Duration::days(1),
            TimeRange::LastWeek => end_time - Duration::weeks(1),
            TimeRange::LastMonth => end_time - Duration::days(30),
            TimeRange::Custom(start, end) => return (start, end),
        };
        (start_time, end_time)
    }
} 