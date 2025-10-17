// constants.rs

// HTTP headers
pub const HTTP_HEADER_JWT_AUTHORIZATION: &str = "Authorization";
pub const HTTP_HEADER_JWT_SET_COOKIE: &str = "X-Set-Cookie";
pub const HTTP_HEADER_JWT_EXPIRE_SECONDS: &str = "X-Expire-Seconds";
pub const HTTP_HEADER_JWT_AUDIENCE: &str = "X-Audience";
pub const HTTP_HEADER_JWT_TOTP: &str = "X-Totp-Code";
pub const HTTP_HEADER_JWT_AUTH_PERMISSION: &str = "X-Permission";
pub const HTTP_HEADER_NAME_CSRF_TOKEN: &str = "X-CSRF-Token";
pub const HTTP_HEADER_AUTH_BASIC: &str = "Basic ";
pub const HTTP_HEADER_AUTH_BEARER: &str = "Bearer ";
pub const HTTP_HEADER_KEY_FORWARDING_HOST: &str = "X-Target-Host";
pub const HTTP_HEADER_KEY_OUTPUT_POS: &str = "X-Output-Position";
pub const HTTP_HEADER_KEY_EXIT_CODE: &str = "X-Exit-Code";
pub const HTTP_HEADER_KEY_USER_AGENT: &str = "User-Agent";
pub const HTTP_HEADER_KEY_X_FILE_PATH: &str = "X-File-Path";
pub const HTTP_HEADER_KEY_X_FILE_NAME: &str = "X-File-Name";
pub const HTTP_HEADER_KEY_X_FILE_MODE: &str = "X-File-Mode";
pub const HTTP_HEADER_KEY_X_FILE_USER: &str = "X-File-User";
pub const HTTP_HEADER_KEY_X_FILE_GROUP: &str = "X-File-Group";
pub const HTTP_HEADER_CONTENT_TYPE: &str = "Content-Type";

// Cookie names
pub const COOKIE_CSRF_TOKEN: &str = "appmesh_csrf_token";
pub const COOKIE_TOKEN: &str = "appmesh_auth_token";

// Body keys
pub const HTTP_BODY_KEY_JWT_USERNAME: &str = "user_name";
pub const HTTP_BODY_KEY_JWT_TOTP: &str = "totp_code";
pub const HTTP_BODY_KEY_JWT_TOTP_CHALLENGE: &str = "totp_challenge";
pub const HTTP_BODY_KEY_JWT_EXPIRE_SECONDS: &str = "expire_seconds";
pub const HTTP_BODY_KEY_MFA_URI: &str = "mfa_uri";
pub const HTTP_BODY_KEY_OLD_PASSWORD: &str = "old_password";
pub const HTTP_BODY_KEY_NEW_PASSWORD: &str = "new_password";
pub const HTTP_BODY_KEY_ACCESS_TOKEN: &str = "access_token";

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
pub const REST_TEXT_TOTP_CHALLENGE_JSON_KEY: &str = "totp_challenge";
pub const HTTP_USER_AGENT: &str = "appmesh/rust";
pub const DEFAULT_SSL_CA_CERT_PATH: &str = "/opt/appmesh/ssl/ca.pem";
pub const DEFAULT_HTTP_URL: &str = "https://127.0.0.1:6060";
pub const DEFAULT_TCP_URL: (&str, u16) = ("127.0.0.1", 6059);
