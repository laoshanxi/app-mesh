// constants.rs

// HTTP headers
pub const HTTP_HEADER_JWT_AUTHORIZATION: &str = "Authorization";
pub const HTTP_HEADER_AUTH_BEARER: &str = "Bearer ";
pub const HTTP_HEADER_KEY_FORWARDING_HOST: &str = "X-Target-Host";
pub const HTTP_HEADER_KEY_OUTPUT_POS: &str = "X-Output-Position";
pub const HTTP_HEADER_KEY_EXIT_CODE: &str = "X-Exit-Code";
pub const HTTP_HEADER_KEY_USER_AGENT: &str = "User-Agent";
pub const HTTP_HEADER_KEY_X_FILE_PATH: &str = "X-File-Path";
#[cfg(unix)]
pub const HTTP_HEADER_KEY_X_FILE_MODE: &str = "X-File-Mode";
#[cfg(unix)]
pub const HTTP_HEADER_KEY_X_FILE_USER: &str = "X-File-User";
#[cfg(unix)]
pub const HTTP_HEADER_KEY_X_FILE_GROUP: &str = "X-File-Group";
pub const HTTP_HEADER_CONTENT_TYPE: &str = "Content-Type";
pub const HTTP_HEADER_CONTENT_LENGTH: &str = "Content-Length";
pub const HTTP_HEADER_KEY_X_SEND_FILE_SOCKET: &str = "X-Send-File-Socket";
pub const HTTP_HEADER_KEY_X_RECV_FILE_SOCKET: &str = "X-Recv-File-Socket";

// Query parameters
pub const HTTP_QUERY_KEY_STDOUT_INDEX: &str = "stdout_index";
pub const HTTP_QUERY_KEY_STDOUT_POSITION: &str = "stdout_position";
pub const HTTP_QUERY_KEY_STDOUT_MAXSIZE: &str = "stdout_maxsize";
pub const HTTP_QUERY_KEY_PROCESS_UUID: &str = "process_uuid";
pub const HTTP_QUERY_KEY_STDOUT_TIMEOUT: &str = "timeout";
pub const HTTP_QUERY_KEY_TIMEOUT: &str = "timeout";
pub const HTTP_QUERY_KEY_LIFECYCLE: &str = "lifecycle";
pub const HTTP_QUERY_KEY_VALUE: &str = "value";

// JSON keys
pub const JSON_KEY_APP_NAME: &str = "name";
pub const JSON_KEY_PROCESS_UUID: &str = "process_uuid";
pub const JSON_KEY_BASE_CONFIG: &str = "BaseConfig";
pub const JSON_KEY_LOG_LEVEL: &str = "LogLevel";

// Other constants
pub const HTTP_USER_AGENT: &str = "appmesh/rust";
pub const HTTP_USER_AGENT_TCP: &str = "appmesh/rust/tcp";
pub const HTTP_USER_AGENT_WSS: &str = "appmesh/rust/wss";
pub const DEFAULT_SSL_CA_CERT_PATH: &str = "/opt/appmesh/ssl/ca.pem";
pub const DEFAULT_HTTP_URL: &str = "https://127.0.0.1:6060";
pub const DEFAULT_TCP_HOST: &str = "127.0.0.1";
pub const DEFAULT_TCP_PORT: u16 = 6059;
pub const DEFAULT_WSS_PORT: u16 = 6058;

// Event subscription
pub const EVENT_URI: &str = "/appmesh/event";

/// Synthetic event_type pushed to every registered callback when the demuxer
/// stops or the underlying transport disconnects. Lets long-running waits
/// (e.g. wait_for_async_run) unblock instead of hanging forever.
pub const EVENT_TYPE_DISCONNECTED: &str = "__disconnected__";

// TCP file transfer
pub const TCP_BLOCK_SIZE: usize = 16 * 1024 - 128;

// Auto-refresh pacing: poll every TOKEN_REFRESH_INTERVAL_SECS, but renew only once the
// token has burned TOKEN_REFRESH_LIFETIME_RATIO of its lifetime.
/// Poll cap, NOT a renew interval.
#[allow(dead_code)]
pub const TOKEN_REFRESH_INTERVAL_SECS: u64 = 300;
/// Floor for the pre-expiry margin.
#[allow(dead_code)]
pub const TOKEN_REFRESH_MARGIN_SECS: u64 = 30;
/// Lifetime fraction to consume before renewing; the rest is retry budget.
#[allow(dead_code)]
pub const TOKEN_REFRESH_LIFETIME_RATIO: f64 = 0.6;
/// Jitter, as a fraction of the margin, so clients don't renew in lockstep.
#[allow(dead_code)]
pub const TOKEN_REFRESH_JITTER_RATIO: f64 = 0.1;
#[allow(dead_code)]
pub const TOKEN_REFRESH_RETRY_BASE_SECS: u64 = 5;
#[allow(dead_code)]
pub const TOKEN_REFRESH_RETRY_MAX_SECS: u64 = 60;
/// Log the 1st renewal failure, then every Nth.
#[allow(dead_code)]
pub const TOKEN_REFRESH_LOG_EVERY: u32 = 10;
