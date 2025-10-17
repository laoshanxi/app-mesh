// models.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::client_http::AppMeshClient;
use crate::error::AppMeshError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppOutput {
    pub status_code: u16,
    pub output: String,
    pub output_position: i64,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct AppRun {
    pub(crate) client: Arc<AppMeshClient>,
    pub app_name: String,
    pub proc_uid: String,
}

impl AppRun {
    pub async fn wait(&self, timeout: i32, print_to_std: bool) -> Result<Option<i32>, AppMeshError> {
        self.client.wait_for_async_run(self, timeout, print_to_std).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub name: String,
    pub roles: Vec<String>,
    pub locked: bool,
    pub totp_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    pub name: Option<String>,
    pub command: Option<String>,
    pub shell: Option<bool>,
    pub session_login: Option<bool>,
    pub description: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub working_dir: Option<String>,
    pub status: Option<u32>,
    pub docker_image: Option<String>,
    pub stdout_cache_num: Option<u32>,
    pub start_time: Option<u64>,
    pub end_time: Option<u64>,
    pub start_interval_seconds: Option<u64>,
    pub cron: Option<bool>,
    pub daily_limitation: Option<DailyLimitation>,
    pub retention: Option<String>,
    pub health_check_cmd: Option<String>,
    pub permission: Option<u32>,
    pub behavior: Option<Behavior>,
    pub env: Option<HashMap<String, String>>,
    pub sec_env: Option<HashMap<String, String>>,
    pub pid: Option<u32>,
    pub resource_limit: Option<ResourceLimitation>,
    pub register_time: Option<u64>,
    pub starts: Option<u32>,
    pub owner: Option<String>,
    #[serde(rename = "pid_user")]
    pub user: Option<String>,
    pub pstree: Option<String>,
    pub container_id: Option<String>,
    pub memory: Option<u64>,
    pub cpu: Option<f64>,
    pub fd: Option<u32>,
    pub stdout_cache_size: Option<u32>,
    pub last_start_time: Option<u64>,
    pub last_exit_time: Option<u64>,
    pub last_error: Option<String>,
    pub next_start_time: Option<u64>,
    pub health: Option<u32>,
    pub version: Option<u32>,
    pub return_code: Option<u32>,
    pub task_id: Option<u32>,
    pub task_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Behavior {
    pub exit: Option<String>,
    pub control: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyLimitation {
    pub daily_start: Option<u64>,
    pub daily_end: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimitation {
    pub cpu_shares: Option<f64>,
    pub memory_mb: Option<u64>,
    pub memory_virt_mb: Option<u64>,
}
