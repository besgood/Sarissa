use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use anyhow::Result;
use tokio::sync::{mpsc, Mutex};
use std::sync::Arc;
use chrono::{DateTime, Utc};
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerNode {
    pub id: String,
    pub address: SocketAddr,
    pub status: WorkerStatus,
    pub capabilities: Vec<String>,
    pub load: f32,
    pub last_heartbeat: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WorkerStatus {
    Available,
    Busy,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTask {
    pub id: String,
    pub target: IpAddr,
    pub ports: Vec<u16>,
    pub scan_type: String,
    pub priority: u32,
    pub assigned_worker: Option<String>,
    pub status: TaskStatus,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub result: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

pub struct DistributedScanner {
    workers: Arc<Mutex<HashMap<String, WorkerNode>>>,
    tasks: Arc<Mutex<HashMap<String, ScanTask>>>,
    task_sender: mpsc::Sender<ScanTask>,
    result_receiver: mpsc::Receiver<ScanResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub task_id: String,
    pub worker_id: String,
    pub status: TaskStatus,
    pub data: Value,
    pub error: Option<String>,
}

impl DistributedScanner {
    pub fn new() -> Self {
        let (tx, _) = mpsc::channel(1000);
        let (_, rx) = mpsc::channel(1000);
        Self {
            workers: Arc::new(Mutex::new(HashMap::new())),
            tasks: Arc::new(Mutex::new(HashMap::new())),
            task_sender: tx,
            result_receiver: rx,
        }
    }

    // Worker Management
    pub async fn register_worker(&self, address: SocketAddr, capabilities: Vec<String>) -> Result<String> {
        let worker_id = uuid::Uuid::new_v4().to_string();
        let worker = WorkerNode {
            id: worker_id.clone(),
            address,
            status: WorkerStatus::Available,
            capabilities,
            load: 0.0,
            last_heartbeat: Utc::now(),
        };

        let mut workers = self.workers.lock().await;
        workers.insert(worker_id.clone(), worker);
        Ok(worker_id)
    }

    pub async fn update_worker_status(&self, worker_id: &str, status: WorkerStatus, load: f32) -> Result<()> {
        let mut workers = self.workers.lock().await;
        if let Some(worker) = workers.get_mut(worker_id) {
            worker.status = status;
            worker.load = load;
            worker.last_heartbeat = Utc::now();
        }
        Ok(())
    }

    // Task Management
    pub async fn submit_task(&self, target: IpAddr, ports: Vec<u16>, scan_type: String, priority: u32) -> Result<String> {
        let task_id = uuid::Uuid::new_v4().to_string();
        let task = ScanTask {
            id: task_id.clone(),
            target,
            ports,
            scan_type,
            priority,
            assigned_worker: None,
            status: TaskStatus::Pending,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            result: None,
        };

        let mut tasks = self.tasks.lock().await;
        tasks.insert(task_id.clone(), task);
        
        // Send task to task queue
        self.task_sender.send(task).await?;
        
        Ok(task_id)
    }

    pub async fn assign_task(&self, task_id: &str, worker_id: &str) -> Result<()> {
        let mut tasks = self.tasks.lock().await;
        let mut workers = self.workers.lock().await;

        if let Some(task) = tasks.get_mut(task_id) {
            if let Some(worker) = workers.get_mut(worker_id) {
                task.assigned_worker = Some(worker_id.to_string());
                task.status = TaskStatus::InProgress;
                task.started_at = Some(Utc::now());
                worker.status = WorkerStatus::Busy;
            }
        }
        Ok(())
    }

    // Task Distribution
    pub async fn distribute_tasks(&self) -> Result<()> {
        let mut tasks = self.tasks.lock().await;
        let workers = self.workers.lock().await;

        // Get available workers
        let available_workers: Vec<_> = workers.values()
            .filter(|w| w.status == WorkerStatus::Available)
            .collect();

        // Get pending tasks
        let pending_tasks: Vec<_> = tasks.values()
            .filter(|t| t.status == TaskStatus::Pending)
            .collect();

        // Sort tasks by priority
        let mut sorted_tasks = pending_tasks.clone();
        sorted_tasks.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Assign tasks to workers
        for (task, worker) in sorted_tasks.iter().zip(available_workers.iter()) {
            self.assign_task(&task.id, &worker.id).await?;
        }

        Ok(())
    }

    // Result Collection
    pub async fn collect_results(&self) -> Result<Vec<ScanResult>> {
        let mut results = Vec::new();
        while let Ok(result) = self.result_receiver.try_recv() {
            results.push(result);
        }
        Ok(results)
    }

    // Worker Health Check
    pub async fn check_worker_health(&self) -> Result<()> {
        let mut workers = self.workers.lock().await;
        let now = Utc::now();

        for worker in workers.values_mut() {
            if (now - worker.last_heartbeat) > chrono::Duration::seconds(30) {
                worker.status = WorkerStatus::Offline;
                
                // Reassign tasks from offline worker
                let mut tasks = self.tasks.lock().await;
                for task in tasks.values_mut() {
                    if task.assigned_worker.as_ref() == Some(&worker.id) {
                        task.status = TaskStatus::Pending;
                        task.assigned_worker = None;
                        task.started_at = None;
                    }
                }
            }
        }
        Ok(())
    }

    // Performance Optimization
    pub async fn optimize_scan_parameters(&self, target: IpAddr) -> Result<ScanParameters> {
        // Analyze network conditions
        let rtt = self.measure_rtt(target).await?;
        let bandwidth = self.measure_bandwidth(target).await?;

        // Calculate optimal parameters
        let threads = self.calculate_optimal_threads(rtt, bandwidth);
        let batch_size = self.calculate_optimal_batch_size(rtt, bandwidth);
        let timeout = self.calculate_optimal_timeout(rtt);

        Ok(ScanParameters {
            threads,
            batch_size,
            timeout,
        })
    }

    async fn measure_rtt(&self, target: IpAddr) -> Result<Duration> {
        let start = std::time::Instant::now();
        let _ = timeout(Duration::from_secs(1), TcpStream::connect(target)).await?;
        Ok(start.elapsed())
    }

    async fn measure_bandwidth(&self, target: IpAddr) -> Result<f64> {
        // TODO: Implement bandwidth measurement
        Ok(1.0)
    }

    fn calculate_optimal_threads(&self, rtt: Duration, bandwidth: f64) -> usize {
        // Simple heuristic based on RTT and bandwidth
        let base_threads = 4;
        let rtt_factor = (rtt.as_millis() as f64 / 100.0).min(10.0);
        let bandwidth_factor = (bandwidth / 10.0).min(5.0);
        
        (base_threads as f64 * rtt_factor * bandwidth_factor) as usize
    }

    fn calculate_optimal_batch_size(&self, rtt: Duration, bandwidth: f64) -> usize {
        // Calculate batch size based on network conditions
        let base_size = 10;
        let rtt_factor = (100.0 / rtt.as_millis() as f64).min(5.0);
        let bandwidth_factor = (bandwidth / 10.0).min(3.0);
        
        (base_size as f64 * rtt_factor * bandwidth_factor) as usize
    }

    fn calculate_optimal_timeout(&self, rtt: Duration) -> Duration {
        // Calculate timeout based on RTT
        let base_timeout = Duration::from_secs(1);
        let rtt_factor = (rtt.as_millis() as f64 / 100.0).max(1.0);
        
        base_timeout * rtt_factor as u32
    }
}

#[derive(Debug, Clone)]
pub struct ScanParameters {
    pub threads: usize,
    pub batch_size: usize,
    pub timeout: Duration,
} 