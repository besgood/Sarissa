use tracing::{Level, Subscriber};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{
    fmt::{format::FmtSpan, time::UtcTime},
    prelude::*,
    EnvFilter,
};
use std::path::Path;
use anyhow::Result;

pub struct LoggingConfig {
    pub log_dir: String,
    pub log_level: Level,
    pub max_file_size: usize,
    pub max_files: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            log_dir: "logs".to_string(),
            log_level: Level::INFO,
            max_file_size: 10 * 1024 * 1024, // 10MB
            max_files: 5,
        }
    }
}

pub fn init_logging(config: &LoggingConfig) -> Result<()> {
    // Create log directory if it doesn't exist
    std::fs::create_dir_all(&config.log_dir)?;

    // Configure file appender with rotation
    let file_appender = RollingFileAppender::new(
        Rotation::DAILY,
        &config.log_dir,
        "sarissa.log",
    );

    // Configure console appender
    let console_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_file(true)
        .with_line_number(true)
        .with_span_events(FmtSpan::CLOSE)
        .with_timer(UtcTime::rfc_3339());

    // Configure file layer
    let file_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_file(true)
        .with_line_number(true)
        .with_span_events(FmtSpan::CLOSE)
        .with_timer(UtcTime::rfc_3339())
        .with_writer(file_appender);

    // Configure filter
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(format!("sarissa={}", config.log_level)))
        .unwrap();

    // Initialize subscriber
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(console_layer)
        .with(file_layer)
        .init();

    // Log initialization
    tracing::info!("Logging initialized with level: {}", config.log_level);
    tracing::info!("Log directory: {}", config.log_dir);

    Ok(())
}

pub fn cleanup_old_logs(config: &LoggingConfig) -> Result<()> {
    let log_dir = Path::new(&config.log_dir);
    if !log_dir.exists() {
        return Ok(());
    }

    let mut log_files: Vec<_> = std::fs::read_dir(log_dir)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.path().extension().map_or(false, |ext| ext == "log")
        })
        .collect();

    // Sort by modified time, newest first
    log_files.sort_by(|a, b| {
        b.metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            .cmp(
                &a.metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH),
            )
    });

    // Remove excess files
    for file in log_files.iter().skip(config.max_files) {
        if let Err(e) = std::fs::remove_file(file.path()) {
            tracing::warn!(
                "Failed to remove old log file {}: {}",
                file.path().display(),
                e
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_logging_initialization() {
        let temp_dir = tempdir().unwrap();
        let config = LoggingConfig {
            log_dir: temp_dir.path().to_str().unwrap().to_string(),
            log_level: Level::DEBUG,
            max_file_size: 1024,
            max_files: 2,
        };

        init_logging(&config).unwrap();

        // Verify log file was created
        let log_files: Vec<_> = fs::read_dir(&config.log_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry.path().extension().map_or(false, |ext| ext == "log")
            })
            .collect();

        assert!(!log_files.is_empty());
    }

    #[test]
    fn test_log_cleanup() {
        let temp_dir = tempdir().unwrap();
        let config = LoggingConfig {
            log_dir: temp_dir.path().to_str().unwrap().to_string(),
            log_level: Level::DEBUG,
            max_file_size: 1024,
            max_files: 2,
        };

        // Create some test log files
        for i in 0..3 {
            let file_path = temp_dir.path().join(format!("test{}.log", i));
            fs::write(&file_path, "test content").unwrap();
        }

        cleanup_old_logs(&config).unwrap();

        // Verify only max_files remain
        let log_files: Vec<_> = fs::read_dir(&config.log_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry.path().extension().map_or(false, |ext| ext == "log")
            })
            .collect();

        assert_eq!(log_files.len(), 2);
    }
} 