// models.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::client_http::AppMeshClient;
use crate::error::AppMeshError;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Application permission level for RBAC
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum Permission {
    Deny = 1,
    Read = 2,
    Write = 3,
}

/// Exit behavior action when a process terminates
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitAction {
    Restart,
    Standby,
    Keepalive,
    Remove,
}

impl ExitAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Restart => "restart",
            Self::Standby => "standby",
            Self::Keepalive => "keepalive",
            Self::Remove => "remove",
        }
    }
}

impl Serialize for ExitAction {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ExitAction {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "restart" => Ok(Self::Restart),
            "standby" => Ok(Self::Standby),
            "keepalive" => Ok(Self::Keepalive),
            "remove" => Ok(Self::Remove),
            other => Err(serde::de::Error::unknown_variant(other, &["restart", "standby", "keepalive", "remove"])),
        }
    }
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

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
    /// Wait for this async run to finish by polling through the originating client.
    ///
    /// Returns the process exit code on success, or `None` on timeout/polling failure.
    pub async fn wait(&self, timeout: i32, print_stdout: bool) -> Result<Option<i32>, AppMeshError> {
        self.client.wait_for_async_run(self, timeout, print_stdout).await
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
pub struct Behavior {
    pub exit: Option<ExitAction>,
    pub control: Option<HashMap<String, String>>,
}

impl Behavior {
    /// Set the default exit behavior
    pub fn set_exit_behavior(&mut self, action: ExitAction) {
        self.exit = Some(action);
    }

    /// Map a specific exit code to a behavior action
    pub fn set_control_behavior(&mut self, exit_code: i32, action: ExitAction) {
        self.control
            .get_or_insert_with(HashMap::new)
            .insert(exit_code.to_string(), action.as_str().to_string());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyLimitation {
    pub daily_start: Option<u64>,
    pub daily_end: Option<u64>,
}

impl DailyLimitation {
    /// Set the daily active time range (epoch timestamps)
    pub fn set_daily_range(&mut self, start: u64, end: u64) {
        self.daily_start = Some(start);
        self.daily_end = Some(end);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimitation {
    pub cpu_shares: Option<f64>,
    pub memory_mb: Option<u64>,
    pub memory_virt_mb: Option<u64>,
}

/// Comprehensive application configuration.
///
/// Use [`ApplicationBuilder`] for ergonomic construction:
/// ```no_run
/// use appmesh::{Application, ExitAction, Permission};
///
/// let app = Application::builder("myapp")
///     .command("/bin/echo hello")
///     .shell(true)
///     .exit_behavior(ExitAction::Restart)
///     .build();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

impl Application {
    /// Create a builder pre-populated with the application name.
    pub fn builder(name: &str) -> ApplicationBuilder {
        ApplicationBuilder { app: Application { name: Some(name.to_string()), ..Default::default() } }
    }
}

// ---------------------------------------------------------------------------
// ApplicationBuilder
// ---------------------------------------------------------------------------

/// Fluent builder for constructing [`Application`] instances.
pub struct ApplicationBuilder {
    app: Application,
}

impl ApplicationBuilder {
    pub fn command(mut self, cmd: &str) -> Self {
        self.app.command = Some(cmd.to_string());
        self
    }

    pub fn shell(mut self, shell: bool) -> Self {
        self.app.shell = Some(shell);
        self
    }

    pub fn session_login(mut self, enabled: bool) -> Self {
        self.app.session_login = Some(enabled);
        self
    }

    pub fn description(mut self, desc: &str) -> Self {
        self.app.description = Some(desc.to_string());
        self
    }

    pub fn metadata(mut self, meta: serde_json::Value) -> Self {
        self.app.metadata = Some(meta);
        self
    }

    pub fn working_dir(mut self, dir: &str) -> Self {
        self.app.working_dir = Some(dir.to_string());
        self
    }

    pub fn docker_image(mut self, image: &str) -> Self {
        self.app.docker_image = Some(image.to_string());
        self
    }

    pub fn stdout_cache_num(mut self, num: u32) -> Self {
        self.app.stdout_cache_num = Some(num);
        self
    }

    pub fn cron(mut self, enabled: bool) -> Self {
        self.app.cron = Some(enabled);
        self
    }

    pub fn retention(mut self, retention: &str) -> Self {
        self.app.retention = Some(retention.to_string());
        self
    }

    pub fn health_check_cmd(mut self, cmd: &str) -> Self {
        self.app.health_check_cmd = Some(cmd.to_string());
        self
    }

    pub fn start_interval_seconds(mut self, secs: u64) -> Self {
        self.app.start_interval_seconds = Some(secs);
        self
    }

    /// Set the app availability window (epoch timestamps).
    pub fn valid_time(mut self, start: u64, end: u64) -> Self {
        self.app.start_time = Some(start);
        self.app.end_time = Some(end);
        self
    }

    /// Set a plain-text environment variable.
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.app.env.get_or_insert_with(HashMap::new).insert(key.to_string(), value.to_string());
        self
    }

    /// Set an encrypted (secure) environment variable.
    pub fn sec_env(mut self, key: &str, value: &str) -> Self {
        self.app.sec_env.get_or_insert_with(HashMap::new).insert(key.to_string(), value.to_string());
        self
    }

    /// Set RBAC permission (encoded as `group_permission * 100 + others_permission`).
    pub fn permission(mut self, group: Permission, others: Permission) -> Self {
        self.app.permission = Some(group as u32 * 100 + others as u32);
        self
    }

    /// Set the default exit behavior.
    pub fn exit_behavior(mut self, action: ExitAction) -> Self {
        self.app
            .behavior
            .get_or_insert(Behavior { exit: None, control: None })
            .set_exit_behavior(action);
        self
    }

    /// Map a specific exit code to a behavior action.
    pub fn control_behavior(mut self, exit_code: i32, action: ExitAction) -> Self {
        self.app
            .behavior
            .get_or_insert(Behavior { exit: None, control: None })
            .set_control_behavior(exit_code, action);
        self
    }

    /// Set the daily active time range (epoch timestamps).
    pub fn daily_range(mut self, start: u64, end: u64) -> Self {
        self.app
            .daily_limitation
            .get_or_insert(DailyLimitation { daily_start: None, daily_end: None })
            .set_daily_range(start, end);
        self
    }

    /// Set resource limits.
    pub fn resource_limit(mut self, cpu_shares: Option<f64>, memory_mb: Option<u64>, memory_virt_mb: Option<u64>) -> Self {
        self.app.resource_limit =
            Some(ResourceLimitation { cpu_shares, memory_mb, memory_virt_mb });
        self
    }

    /// Consume the builder and return the finished [`Application`].
    pub fn build(self) -> Application {
        self.app
    }
}
