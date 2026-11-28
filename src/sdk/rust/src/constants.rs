// constants.rs

// HTTP headers
pub const HTTP_HEADER_JWT_AUTHORIZATION: &str = "Authorization";
pub const HTTP_HEADER_AUTH_BEARER: &str = "Bearer ";
pub const HTTP_HEADER_KEY_FORWARDING_HOST: &str = "X-Target-Host";
pub const HTTP_HEADER_KEY_OUTPUT_POS: &str = "X-Output-Position";
pub const HTTP_HEADER_KEY_EXIT_CODE: &str = "X-Exit-Code";
pub const HTTP_HEADER_KEY_X_APP_NAME: &str = "X-App-Name";
pub const HTTP_HEADER_KEY_OUTPUT_TRUNCATED: &str = "X-Output-Truncated";
pub const HTTP_HEADER_KEY_USER_AGENT: &str = "User-Agent";
pub const HTTP_HEADER_KEY_X_FILE_PATH: &str = "X-File-Path";
pub const HTTP_HEADER_KEY_X_FILE_OVERWRITE: &str = "X-File-Overwrite";
#[cfg(unix)]
pub const HTTP_HEADER_KEY_X_FILE_MODE: &str = "X-File-Mode";
#[cfg(unix)]
pub const HTTP_HEADER_KEY_X_FILE_USER: &str = "X-File-User";
#[cfg(unix)]
pub const HTTP_HEADER_KEY_X_FILE_GROUP: &str = "X-File-Group";
pub const HTTP_HEADER_CONTENT_TYPE: &str = "Content-Type";
pub const HTTP_HEADER_KEY_X_SEND_FILE_SOCKET: &str = "X-Send-File-Socket";
pub const HTTP_HEADER_KEY_X_RECV_FILE_SOCKET: &str = "X-Recv-File-Socket";
pub const HTTP_HEADER_KEY_X_INPUT_CLOSE: &str = "X-Input-Close";
pub const HTTP_HEADER_KEY_X_APPMESH_PROCESS_KEY: &str = "X-AppMesh-Process-Key";
pub const HTTP_HEADER_KEY_X_SUBSCRIPTION_ID: &str = "X-Subscription-Id";

// HMAC request signature headers (docs/source/Security.md,
// "Request replay protection and signatures"); names match the daemon's
// HTTP_HEADER_KEY_X_* definitions.
pub const HTTP_HEADER_KEY_X_REQUEST_KEY: &str = "X-Request-Key";
pub const HTTP_HEADER_KEY_X_TIMESTAMP: &str = "X-Timestamp";
pub const HTTP_HEADER_KEY_X_NONCE: &str = "X-Nonce";
pub const HTTP_HEADER_KEY_X_SIGNATURE: &str = "X-Signature";

// Query parameters
pub const HTTP_QUERY_KEY_STDOUT_INDEX: &str = "stdout_index";
pub const HTTP_QUERY_KEY_STDOUT_POSITION: &str = "stdout_position";
pub const HTTP_QUERY_KEY_STDOUT_MAXSIZE: &str = "stdout_maxsize";
pub const HTTP_QUERY_KEY_PROCESS_UUID: &str = "process_uuid";
pub const HTTP_QUERY_KEY_TIMEOUT: &str = "timeout";
pub const HTTP_QUERY_KEY_LIFECYCLE: &str = "lifecycle";
pub const HTTP_QUERY_KEY_VALUE: &str = "value";
pub const HTTP_QUERY_KEY_FOLLOW: &str = "follow";

/// One sync-run reply carries at most one page; a full page continues on the output endpoint.
pub const SYNC_RUN_OUTPUT_PAGE_BYTES: usize = 5 * 1024 * 1024;
/// How long the daemon keeps a truncated run instance (and its remaining output).
pub const SYNC_RUN_TRUNCATED_RETENTION_SECONDS: u64 = 600;

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
pub const DEFAULT_TCP_PORT: u16 = 6062;
pub const DEFAULT_WSS_PORT: u16 = 6063;
/// REST listener the TCP/WSS clients use for their SSE streaming side channel.
pub const DEFAULT_REST_PORT: u16 = 6063;
/// Agent REST listener on the same host that a forwarded SSE side channel dials: the
/// engine listener answers `X-Target-Host` on a stream route with 400.
pub const DEFAULT_AGENT_PORT: u16 = 6060;

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
pub const TOKEN_REFRESH_INTERVAL_SECS: u64 = 300;
/// Floor for the pre-expiry margin.
pub const TOKEN_REFRESH_MARGIN_SECS: u64 = 30;
/// Lifetime fraction to consume before renewing; the rest is retry budget.
pub const TOKEN_REFRESH_LIFETIME_RATIO: f64 = 0.6;
/// Jitter, as a fraction of the margin, so clients don't renew in lockstep.
pub const TOKEN_REFRESH_JITTER_RATIO: f64 = 0.1;
pub const TOKEN_REFRESH_RETRY_BASE_SECS: u64 = 5;
pub const TOKEN_REFRESH_RETRY_MAX_SECS: u64 = 60;
/// Log the 1st renewal failure, then every Nth.
pub const TOKEN_REFRESH_LOG_EVERY: u32 = 10;
