// models.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub url: String,
    pub ssl_verify: Option<String>,
    pub ssl_client_cert: Option<String>,
    pub ssl_client_key: Option<String>,
    pub cookie_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppOutput {
    pub status_code: u16,
    pub output: String,
    pub output_position: i64,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct AppRun {
    pub app_name: String,
    pub proc_uid: String,
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
    pub name: String,
    pub command: String,
    pub working_dir: Option<String>,
    pub status: String,
    pub health_check_cmd: Option<String>,
    pub start_time: Option<i64>,
    pub pid: Option<i32>,
    #[serde(rename = "return_code")]
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResource {
    pub hostname: String,
    pub os_version: String,
    pub cpu_count: i32,
    pub total_memory: i64,
    pub free_memory: i64,
    pub load_average: Vec<f64>,
}