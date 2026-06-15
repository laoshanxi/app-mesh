use clap::{Parser, Subcommand};

const BUILD_TAG: &str = match option_env!("BUILD_TAG") {
    Some(tag) => tag,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Parser)]
#[command(name = "appm", about = "App Mesh CLI", version = BUILD_TAG)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Server host URL (default: last used or wss://127.0.0.1:6058)
    #[arg(short = 'H', long = "host-url", global = true)]
    pub host_url: Option<String>,

    /// Forward request to target host
    #[arg(short = 'F', long = "forward-to", global = true)]
    pub forward_to: Option<String>,

    /// Login username
    #[arg(short = 'U', long = "user", global = true)]
    pub user: Option<String>,

    /// Login password
    #[arg(short = 'X', long = "password", global = true)]
    pub password: Option<String>,

    /// Enable debug logging
    #[arg(short = 'v', long = "verbose", global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Login to App Mesh
    Logon(LogonArgs),

    /// Logout from App Mesh
    #[command(alias = "logout")]
    Logoff(LogoffArgs),

    /// Display current logged-in user
    Loginfo(LoginfoArgs),

    /// Register a new application
    #[command(alias = "reg")]
    Add(Box<AddArgs>),

    /// Remove an application
    #[command(aliases = ["remove", "unreg"])]
    Rm(RmArgs),

    /// List applications
    #[command(aliases = ["list", "ls"])]
    View(ViewArgs),

    /// Enable applications
    Enable(EnableArgs),

    /// Disable applications
    Disable(DisableArgs),

    /// Restart applications (disable then enable)
    Restart(RestartArgs),

    /// Run a command or application
    Run(RunArgs),

    /// Execute a single remote command
    Exec(ExecArgs),

    /// Interactive remote shell
    Shell(ShellArgs),

    /// Download a remote file
    Get(GetArgs),

    /// Upload a local file
    Put(PutArgs),

    /// Manage host labels
    Label(LabelArgs),

    /// Set log level
    Log(LogArgs),

    /// View server configuration
    Config(ConfigArgs),

    /// Show host resources
    Resource(ResourceArgs),

    /// Change user password
    Passwd(PasswdArgs),

    /// Lock or unlock a user
    Lock(LockArgs),

    /// Manage users
    User(UserArgs),

    /// Two-factor authentication management
    Mfa(MfaArgs),

    /// Encrypt password (local utility)
    Appmgpwd(AppmgpwdArgs),

    /// Initialize admin password (root-only)
    Appmginit(AppmginitArgs),

    /// Manage workflows
    #[command(alias = "wf")]
    Workflow(WorkflowArgs),
}

// ─── Auth ────────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct LogonArgs {
    /// Session duration (seconds or ISO 8601 duration)
    #[arg(short = 't', long = "timeout")]
    pub timeout: Option<String>,

    /// JWT audience
    #[arg(short = 'a', long = "audience")]
    pub audience: Option<String>,

    /// Display the returned JWT token
    #[arg(long = "show-token")]
    pub show_token: bool,
}

#[derive(Parser)]
pub struct LogoffArgs {}

#[derive(Parser)]
pub struct LoginfoArgs {
    /// Display current session token
    #[arg(long = "show-token")]
    pub show_token: bool,
}

// ─── App Management ──────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct AddArgs {
    /// Application name
    #[arg(short = 'a', long = "app")]
    pub app: Option<String>,

    /// Command with arguments
    #[arg(short = 'c', long = "cmd")]
    pub cmd: Option<String>,

    /// Application description
    #[arg(short = 'd', long = "description")]
    pub description: Option<String>,

    /// Working directory
    #[arg(short = 'w', long = "working-dir")]
    pub working_dir: Option<String>,

    /// Initial status (true=enabled, false=disabled)
    #[arg(short = 's', long = "status")]
    pub status: Option<bool>,

    /// Enable shell mode
    #[arg(short = 'u', long = "shell")]
    pub shell: bool,

    /// Execute with session login context
    #[arg(short = 'G', long = "session-login")]
    pub session_login: bool,

    /// Health check command
    #[arg(short = 'K', long = "health-check")]
    pub health_check: Option<String>,

    /// Docker image
    #[arg(short = 'I', long = "docker-image")]
    pub docker_image: Option<String>,

    /// Attach to existing process ID
    #[arg(short = 'P', long = "pid")]
    pub pid: Option<u32>,

    /// Start time (ISO 8601)
    #[arg(short = 'b', long = "begin-time")]
    pub begin_time: Option<String>,

    /// End time (ISO 8601)
    #[arg(short = 'x', long = "end-time")]
    pub end_time: Option<String>,

    /// Daily start time (e.g., '09:00:00+08')
    #[arg(short = 'S', long = "daily-begin")]
    pub daily_begin: Option<String>,

    /// Daily end time (e.g., '20:00:00+08')
    #[arg(short = 'E', long = "daily-end")]
    pub daily_end: Option<String>,

    /// Start interval (ISO 8601 duration or cron expression)
    #[arg(short = 'i', long = "interval")]
    pub interval: Option<String>,

    /// Use cron expression for interval
    #[arg(short = 'Y', long = "cron")]
    pub cron: bool,

    /// Memory limit in MB
    #[arg(short = 'M', long = "memory-limit")]
    pub memory_limit: Option<u64>,

    /// Virtual memory limit in MB
    #[arg(short = 'V', long = "virtual-memory")]
    pub virtual_memory: Option<u64>,

    /// CPU shares (relative weight)
    #[arg(short = 'C', long = "cpu-shares")]
    pub cpu_shares: Option<i32>,

    /// Number of stdout cache files
    #[arg(short = 'N', long = "log-cache-size")]
    pub log_cache_size: Option<u32>,

    /// Permission bits
    #[arg(short = 'p', long = "permission")]
    pub permission: Option<u32>,

    /// Metadata (string/JSON, '@' prefix for file)
    #[arg(short = 'm', long = "metadata")]
    pub metadata: Option<String>,

    /// Environment variables (repeatable: -e K=V)
    #[arg(short = 'e', long = "env")]
    pub env: Vec<String>,

    /// Encrypted environment variables (repeatable: -z K=V)
    #[arg(short = 'z', long = "security-env")]
    pub security_env: Vec<String>,

    /// Process stop timeout (ISO 8601 duration)
    #[arg(short = 'R', long = "stop-timeout")]
    pub stop_timeout: Option<String>,

    /// Exit behavior: restart|standby|keepalive|remove
    #[arg(short = 'Q', long = "exit")]
    pub exit: Option<String>,

    /// Exit code behavior (repeatable: --control CODE:ACTION)
    #[arg(short = 'T', long = "control")]
    pub control: Vec<String>,

    /// Read YAML from stdin ('std') or file
    #[arg(short = 'D', long = "stdin")]
    pub stdin: Option<String>,

    /// Skip confirmation
    #[arg(short = 'f', long = "force")]
    pub force: bool,
}

#[derive(Parser)]
pub struct RmArgs {
    /// Application name(s)
    #[arg(short = 'a', long = "app", required = true)]
    pub app: Vec<String>,

    /// Skip confirmation
    #[arg(short = 'f', long = "force")]
    pub force: bool,
}

#[derive(Parser)]
pub struct ViewArgs {
    /// Show detailed information
    #[arg(short = 'l', long = "long")]
    pub long: bool,

    /// View application output
    #[arg(short = 'o', long = "show-output")]
    pub show_output: bool,

    /// Display process tree
    #[arg(short = 'P', long = "pstree")]
    pub pstree: bool,

    /// Specific application name
    #[arg(short = 'a', long = "app")]
    pub app: Option<String>,

    /// Specify output log index
    #[arg(short = 'i', long = "log-index")]
    pub log_index: Option<i32>,

    /// Follow output in real-time
    #[arg(short = 'f', long = "follow")]
    pub follow: bool,

    /// Output in JSON format
    #[arg(short = 'j', long = "json")]
    pub json: bool,
}

#[derive(Parser)]
pub struct EnableArgs {
    /// Application name(s)
    #[arg(short = 'a', long = "app")]
    pub app: Vec<String>,

    /// Apply to all applications
    #[arg(short = 'A', long = "all")]
    pub all: bool,
}

#[derive(Parser)]
pub struct DisableArgs {
    /// Application name(s)
    #[arg(short = 'a', long = "app")]
    pub app: Vec<String>,

    /// Apply to all applications
    #[arg(short = 'A', long = "all")]
    pub all: bool,
}

#[derive(Parser)]
pub struct RestartArgs {
    /// Application name(s)
    #[arg(short = 'a', long = "app")]
    pub app: Vec<String>,

    /// Apply to all applications
    #[arg(short = 'A', long = "all")]
    pub all: bool,
}

// ─── Execution ───────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct RunArgs {
    /// Application name (optional, auto-generated if empty)
    #[arg(short = 'a', long = "app")]
    pub app: Option<String>,

    /// Full command line
    #[arg(short = 'c', long = "cmd")]
    pub cmd: Option<String>,

    /// Application description
    #[arg(short = 'd', long = "description")]
    pub description: Option<String>,

    /// Working directory
    #[arg(short = 'w', long = "working-dir")]
    pub working_dir: Option<String>,

    /// Metadata input (passed to stdin, '@' for file)
    #[arg(short = 'm', long = "metadata")]
    pub metadata: Option<String>,

    /// Environment variables (repeatable: -e K=V)
    #[arg(short = 'e', long = "env")]
    pub env: Vec<String>,

    /// Enable shell mode
    #[arg(short = 'u', long = "shell")]
    pub shell: bool,

    /// Execute with session login context
    #[arg(short = 'G', long = "session-login")]
    pub session_login: bool,

    /// Max lifecycle (seconds or ISO 8601)
    #[arg(short = 'T', long = "lifetime", default_value = "216000")]
    pub lifetime: String,

    /// Max wait time (seconds or ISO 8601; >0: poll, <0: wait until exit)
    #[arg(short = 't', long = "timeout", default_value = "172800", allow_hyphen_values = true)]
    pub timeout: String,
}

#[derive(Parser)]
pub struct ExecArgs {
    /// Enable shell mode
    #[arg(short = 'u', long = "shell")]
    pub shell: bool,

    /// Execute with session login context
    #[arg(short = 'G', long = "session-login")]
    pub session_login: bool,

    /// Max lifecycle (seconds or ISO 8601)
    #[arg(short = 'T', long = "lifetime", default_value = "216000")]
    pub lifetime: String,

    /// Max wait time (seconds or ISO 8601)
    #[arg(short = 't', long = "timeout", default_value = "172800", allow_hyphen_values = true)]
    pub timeout: String,

    /// Retry until success
    #[arg(short = 'r', long = "retry")]
    pub retry: bool,

    /// Environment variables (repeatable: -e K=V)
    #[arg(short = 'e', long = "env")]
    pub env: Vec<String>,

    /// Command to execute
    #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

#[derive(Parser)]
pub struct ShellArgs {
    /// Execute with session login context
    #[arg(short = 'G', long = "session-login")]
    pub session_login: bool,

    /// Max lifecycle (seconds or ISO 8601)
    #[arg(short = 'T', long = "lifetime", default_value = "216000")]
    pub lifetime: String,

    /// Max wait time (seconds or ISO 8601)
    #[arg(short = 't', long = "timeout", default_value = "172800")]
    pub timeout: String,

    /// Retry until success
    #[arg(short = 'r', long = "retry")]
    pub retry: bool,

    /// Environment variables (repeatable: -e K=V)
    #[arg(short = 'e', long = "env")]
    pub env: Vec<String>,

    /// Initial command to execute
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

// ─── File Operations ─────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct GetArgs {
    /// Remote file path
    #[arg(short = 'r', long = "remote", required = true)]
    pub remote: String,

    /// Local file path
    #[arg(short = 'l', long = "local", required = true)]
    pub local: String,

    /// Don't copy file attributes
    #[arg(short = 'a', long = "no-attr")]
    pub no_attr: bool,
}

#[derive(Parser)]
pub struct PutArgs {
    /// Remote file path
    #[arg(short = 'r', long = "remote", required = true)]
    pub remote: String,

    /// Local file to upload
    #[arg(short = 'l', long = "local", required = true)]
    pub local: String,

    /// Don't copy file attributes
    #[arg(short = 'a', long = "no-attr")]
    pub no_attr: bool,
}

// ─── System Management ──────────────────────────────────────────────────────

#[derive(Parser)]
pub struct LabelArgs {
    /// List labels
    #[arg(long = "view")]
    pub view: bool,

    /// Add labels
    #[arg(short = 'a', long = "add")]
    pub add: bool,

    /// Remove labels
    #[arg(short = 'd', long = "delete")]
    pub delete: bool,

    /// Labels (repeatable: -l key=value)
    #[arg(short = 'l', long = "label")]
    pub label: Vec<String>,
}

#[derive(Parser)]
pub struct LogArgs {
    /// Log level: DEBUG, INFO, NOTICE, WARN, ERROR
    #[arg(short = 'L', long = "level", required = true)]
    pub level: String,
}

#[derive(Parser)]
pub struct ConfigArgs {}

#[derive(Parser)]
pub struct ResourceArgs {}

// ─── User Management ────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct PasswdArgs {
    /// Target user (default: self)
    #[arg(short = 't', long = "target")]
    pub target: Option<String>,
}

#[derive(Parser)]
pub struct LockArgs {
    /// Target user
    #[arg(short = 't', long = "target", required = true)]
    pub target: String,

    /// Lock (true) or unlock (false)
    #[arg(short = 'k', long = "lock", required = true)]
    pub lock: bool,
}

#[derive(Parser)]
pub struct UserArgs {
    /// Path to JSON file with user definition
    #[arg(short = 'j', long = "json")]
    pub json: Option<String>,

    /// List all users
    #[arg(short = 'A', long = "all")]
    pub all: bool,

    /// Skip confirmation
    #[arg(short = 'f', long = "force")]
    pub force: bool,
}

#[derive(Parser)]
pub struct MfaArgs {
    /// Activate MFA
    #[arg(short = 'a', long = "add")]
    pub add: bool,

    /// Deactivate MFA
    #[arg(short = 'd', long = "delete")]
    pub delete: bool,
}

// ─── Admin ──────────────────────────────────────────────────────────────────

#[derive(Parser)]
pub struct AppmgpwdArgs {
    /// Passwords to encrypt
    pub passwords: Vec<String>,
}

#[derive(Parser)]
pub struct AppmginitArgs {}

// ─── Workflow Management ───────────────────────────────────────────────────

#[derive(Parser)]
pub struct WorkflowArgs {
    #[command(subcommand)]
    pub command: WorkflowCommand,
}

#[derive(Subcommand)]
pub enum WorkflowCommand {
    /// Register a workflow from a YAML file
    Add(WorkflowAddArgs),

    /// Show a workflow definition
    Get(WorkflowGetArgs),

    /// List all registered workflows
    #[command(alias = "ls")]
    List(WorkflowListArgs),

    /// Remove a workflow
    #[command(alias = "remove")]
    Rm(WorkflowRmArgs),

    /// Trigger a workflow run
    Run(WorkflowRunArgs),

    /// List run history for a workflow
    Runs(WorkflowRunsArgs),

    /// View workflow run flow log
    Logs(WorkflowLogsArgs),

    /// View step stdout output
    Output(WorkflowOutputArgs),

    /// Cancel a running workflow
    Cancel(WorkflowCancelArgs),

    /// Re-run a previous workflow run with the same inputs
    Rerun(WorkflowRerunArgs),

    /// Show detailed run status (per-job/step breakdown)
    Detail(WorkflowDetailArgs),

    /// Show input parameters for a workflow
    Inputs(WorkflowInputsArgs),
}

#[derive(Parser)]
pub struct WorkflowAddArgs {
    /// Path to workflow YAML file
    #[arg(short = 'f', long = "file", required = true)]
    pub file: String,
}

#[derive(Parser)]
pub struct WorkflowGetArgs {
    /// Workflow name
    #[arg(required = true)]
    pub name: String,
}

#[derive(Parser)]
pub struct WorkflowListArgs {}

#[derive(Parser)]
pub struct WorkflowRmArgs {
    /// Workflow name
    #[arg(required = true)]
    pub name: String,
}

#[derive(Parser)]
pub struct WorkflowRunArgs {
    /// Workflow name
    #[arg(required = true)]
    pub name: String,

    /// Input values (repeatable: -e key=value)
    #[arg(short = 'e', long = "input")]
    pub input: Vec<String>,

    /// Follow output in real-time
    #[arg(short = 'f', long = "follow")]
    pub follow: bool,
}

#[derive(Parser)]
pub struct WorkflowRunsArgs {
    /// Workflow name
    #[arg(required = true)]
    pub name: String,
}

pub type WorkflowLogsArgs = WorkflowRunRef;

#[derive(Parser)]
pub struct WorkflowOutputArgs {
    /// Workflow name
    #[arg(short = 'w', long = "workflow", required = true)]
    pub workflow: String,

    /// Run ID
    #[arg(required = true)]
    pub run_id: String,

    /// Job name
    #[arg(short = 'j', long = "job", required = true)]
    pub job: String,

    /// Step name
    #[arg(short = 's', long = "step", required = true)]
    pub step: String,
}

/// Shared args for commands that operate on a specific workflow run.
#[derive(Parser)]
pub struct WorkflowRunRef {
    /// Workflow name
    #[arg(short = 'w', long = "workflow", required = true)]
    pub workflow: String,

    /// Run ID
    #[arg(required = true)]
    pub run_id: String,
}

pub type WorkflowCancelArgs = WorkflowRunRef;
pub type WorkflowRerunArgs = WorkflowRunRef;
pub type WorkflowDetailArgs = WorkflowRunRef;

#[derive(Parser)]
pub struct WorkflowInputsArgs {
    /// Workflow name
    #[arg(required = true)]
    pub name: String,
}
