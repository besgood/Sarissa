use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use anyhow::Result;
use rust_xlsxwriter::{Workbook, Format, Color};
use weasyprint::Document;
use handlebars::Handlebars;
use serde_json::json;
use tera::{Tera, Context};
use std::fs;
use std::io::Write;
use markdown::to_html;
use serde_json::Value;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::Mutex;
use reqwest;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub id: String,
    pub title: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub target: String,
    pub findings: Vec<Finding>,
    pub metadata: HashMap<String, Value>,
    pub format: ReportFormat,
    pub template: Option<String>,
    pub branding: Option<Branding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub evidence: String,
    pub recommendation: String,
    pub cve: Option<String>,
    pub cvss_score: Option<f32>,
    pub affected_components: Vec<String>,
    pub references: Vec<String>,
    pub remediation_steps: Vec<String>,
    pub false_positive: bool,
    pub verified: bool,
    pub tags: Vec<String>,
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
pub enum ReportFormat {
    PDF,
    HTML,
    JSON,
    Markdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branding {
    pub logo: Option<String>,
    pub company_name: String,
    pub colors: HashMap<String, String>,
    pub footer: Option<String>,
    pub header: Option<String>,
}

pub struct ReportGenerator {
    tera: Tera,
    templates_dir: PathBuf,
    output_dir: PathBuf,
    branding: Option<Branding>,
    cache: Arc<Mutex<HashMap<String, String>>>,
}

impl ReportGenerator {
    pub fn new(templates_dir: &PathBuf, output_dir: &PathBuf) -> Result<Self> {
        let mut tera = Tera::new(&templates_dir.join("**/*").to_string_lossy())?;
        
        // Register custom filters
        tera.register_filter("severity_color", severity_color_filter);
        tera.register_filter("cvss_score_color", cvss_score_color_filter);
        
        Ok(Self {
            tera,
            templates_dir: templates_dir.clone(),
            output_dir: output_dir.clone(),
            branding: None,
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn set_branding(&mut self, branding: Branding) {
        self.branding = Some(branding);
    }

    pub async fn generate_report(&self, report: &Report) -> Result<PathBuf> {
        let output_path = match report.format {
            ReportFormat::PDF => self.generate_pdf(report).await?,
            ReportFormat::HTML => self.generate_html(report).await?,
            ReportFormat::JSON => self.generate_json(report).await?,
            ReportFormat::Markdown => self.generate_markdown(report).await?,
        };
        
        Ok(output_path)
    }

    async fn generate_pdf(&self, report: &Report) -> Result<PathBuf> {
        // First generate HTML
        let html_content = self.render_template(report, "pdf.html")?;
        
        // Create temporary HTML file
        let temp_html = self.output_dir.join(format!("temp_{}.html", report.id));
        fs::write(&temp_html, html_content)?;
        
        // Generate PDF using WeasyPrint
        let output_path = self.output_dir.join(format!("{}.pdf", report.id));
        let document = Document::from_file(&temp_html)?;
        document.write_to_file(&output_path)?;
        
        // Clean up temporary file
        fs::remove_file(temp_html)?;
        
        Ok(output_path)
    }

    async fn generate_html(&self, report: &Report) -> Result<PathBuf> {
        let html_content = self.render_template(report, "html.html")?;
        let output_path = self.output_dir.join(format!("{}.html", report.id));
        fs::write(&output_path, html_content)?;
        Ok(output_path)
    }

    async fn generate_json(&self, report: &Report) -> Result<PathBuf> {
        let json_content = serde_json::to_string_pretty(report)?;
        let output_path = self.output_dir.join(format!("{}.json", report.id));
        fs::write(&output_path, json_content)?;
        Ok(output_path)
    }

    async fn generate_markdown(&self, report: &Report) -> Result<PathBuf> {
        let markdown_content = self.render_template(report, "markdown.md")?;
        let output_path = self.output_dir.join(format!("{}.md", report.id));
        fs::write(&output_path, markdown_content)?;
        Ok(output_path)
    }

    fn render_template(&self, report: &Report, template_name: &str) -> Result<String> {
        let mut context = Context::new();
        
        // Add report data
        context.insert("report", &report);
        
        // Add branding if available
        if let Some(branding) = &self.branding {
            context.insert("branding", branding);
        }
        
        // Add metadata
        context.insert("metadata", &report.metadata);
        
        // Add statistics
        context.insert("stats", &self.calculate_statistics(report));
        
        // Render template
        Ok(self.tera.render(template_name, &context)?)
    }

    fn calculate_statistics(&self, report: &Report) -> HashMap<String, Value> {
        let mut stats = HashMap::new();
        
        // Count findings by severity
        let mut severity_counts = HashMap::new();
        for finding in &report.findings {
            *severity_counts.entry(finding.severity.clone())
                .or_insert(0) += 1;
        }
        stats.insert("severity_counts".to_string(), serde_json::to_value(severity_counts).unwrap());
        
        // Calculate average CVSS score
        let cvss_scores: Vec<f32> = report.findings.iter()
            .filter_map(|f| f.cvss_score)
            .collect();
        if !cvss_scores.is_empty() {
            let avg_cvss = cvss_scores.iter().sum::<f32>() / cvss_scores.len() as f32;
            stats.insert("average_cvss".to_string(), serde_json::to_value(avg_cvss).unwrap());
        }
        
        // Count affected components
        let mut component_counts = HashMap::new();
        for finding in &report.findings {
            for component in &finding.affected_components {
                *component_counts.entry(component.clone())
                    .or_insert(0) += 1;
            }
        }
        stats.insert("component_counts".to_string(), serde_json::to_value(component_counts).unwrap());
        
        stats
    }

    pub async fn generate_executive_summary(&self, report: &Report) -> Result<String> {
        let mut context = Context::new();
        context.insert("report", report);
        context.insert("stats", &self.calculate_statistics(report));
        
        Ok(self.tera.render("executive_summary.html", &context)?)
    }

    pub async fn generate_finding_details(&self, finding: &Finding) -> Result<String> {
        let mut context = Context::new();
        context.insert("finding", finding);
        
        Ok(self.tera.render("finding_details.html", &context)?)
    }

    pub async fn generate_remediation_guide(&self, report: &Report) -> Result<String> {
        let mut context = Context::new();
        context.insert("report", report);
        
        // Group findings by severity
        let mut findings_by_severity: HashMap<Severity, Vec<&Finding>> = HashMap::new();
        for finding in &report.findings {
            findings_by_severity.entry(finding.severity.clone())
                .or_default()
                .push(finding);
        }
        context.insert("findings_by_severity", &findings_by_severity);
        
        Ok(self.tera.render("remediation_guide.html", &context)?)
    }
}

// Custom Tera filters
fn severity_color_filter(value: &Value, _: &HashMap<String, Value>) -> tera::Result<Value> {
    let severity = value.as_str().unwrap_or("");
    let color = match severity {
        "Critical" => "#FF0000",
        "High" => "#FF4500",
        "Medium" => "#FFA500",
        "Low" => "#FFFF00",
        "Info" => "#00FF00",
        _ => "#808080",
    };
    Ok(Value::String(color.to_string()))
}

fn cvss_score_color_filter(value: &Value, _: &HashMap<String, Value>) -> tera::Result<Value> {
    let score = value.as_f64().unwrap_or(0.0);
    let color = if score >= 9.0 {
        "#FF0000"
    } else if score >= 7.0 {
        "#FF4500"
    } else if score >= 4.0 {
        "#FFA500"
    } else if score >= 0.1 {
        "#FFFF00"
    } else {
        "#00FF00"
    };
    Ok(Value::String(color.to_string()))
}

// HTML template for PDF generation
const PDF_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{{ report.title }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 2cm;
        }
        .header {
            text-align: center;
            margin-bottom: 2cm;
        }
        .logo {
            max-width: 200px;
            margin-bottom: 1cm;
        }
        .section {
            margin-bottom: 1cm;
        }
        .finding {
            margin-bottom: 0.5cm;
            padding: 0.5cm;
            border: 1px solid #ccc;
        }
        .severity {
            font-weight: bold;
            color: {{ finding.severity | severity_color }};
        }
        .cvss {
            color: {{ finding.cvss_score | cvss_score_color }};
        }
        .footer {
            text-align: center;
            margin-top: 2cm;
            font-size: 0.8em;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="header">
        {% if branding.logo %}
        <img src="{{ branding.logo }}" alt="Logo" class="logo">
        {% endif %}
        <h1>{{ report.title }}</h1>
        <p>{{ report.description }}</p>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <p>Target: {{ report.target }}</p>
        <p>Scan Date: {{ report.timestamp }}</p>
        <p>Total Findings: {{ report.findings | length }}</p>
        <p>Critical Findings: {{ stats.severity_counts.Critical | default(0) }}</p>
        <p>High Findings: {{ stats.severity_counts.High | default(0) }}</p>
        <p>Medium Findings: {{ stats.severity_counts.Medium | default(0) }}</p>
        <p>Low Findings: {{ stats.severity_counts.Low | default(0) }}</p>
    </div>

    <div class="section">
        <h2>Findings</h2>
        {% for finding in report.findings %}
        <div class="finding">
            <h3>{{ finding.title }}</h3>
            <p class="severity">Severity: {{ finding.severity }}</p>
            {% if finding.cvss_score %}
            <p class="cvss">CVSS Score: {{ finding.cvss_score }}</p>
            {% endif %}
            <p>{{ finding.description }}</p>
            <h4>Evidence</h4>
            <pre>{{ finding.evidence }}</pre>
            <h4>Recommendation</h4>
            <p>{{ finding.recommendation }}</p>
            {% if finding.remediation_steps %}
            <h4>Remediation Steps</h4>
            <ol>
            {% for step in finding.remediation_steps %}
                <li>{{ step }}</li>
            {% endfor %}
            </ol>
            {% endif %}
        </div>
        {% endfor %}
    </div>

    <div class="footer">
        {% if branding.footer %}
        {{ branding.footer }}
        {% else %}
        Generated by Sarissa Security Scanner
        {% endif %}
    </div>
</body>
</html>
"#; 