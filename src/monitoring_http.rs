use axum::{Router, routing::get, response::IntoResponse, extract::State};
use std::net::SocketAddr;
use std::sync::Arc;
use crate::monitoring::MonitoringSystem;

pub async fn start_metrics_server(monitoring: Arc<MonitoringSystem>, addr: SocketAddr) {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(monitoring);
    
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .expect("Failed to start metrics server");
}

async fn metrics_handler(State(monitoring): State<Arc<MonitoringSystem>>) -> impl IntoResponse {
    match monitoring.get_metrics_text().await {
        Ok(metrics) => ([("Content-Type", "text/plain; version=0.0.4")], metrics),
        Err(e) => ([("Content-Type", "text/plain")], format!("# error: {}", e)),
    }
} 