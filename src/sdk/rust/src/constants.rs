// constants.rs

// HTTP headers
pub const HTTP_HEADER_JWT_AUTHORIZATION: &str = "Authorization";
pub const HTTP_HEADER_JWT_SET_COOKIE: &str = "X-Set-Cookie";
pub const HTTP_HEADER_JWT_EXPIRE_SECONDS: &str = "X-Jwt-Expire-Seconds";
pub const HTTP_HEADER_JWT_AUDIENCE: &str = "X-Jwt-Audience";
pub const HTTP_HEADER_JWT_TOTP: &str = "X-Jwt-Totp";
pub const HTTP_HEADER_JWT_AUTH_PERMISSION: &str = "X-Auth-Permission";
pub const HTTP_HEADER_NAME_CSRF_TOKEN: &str = "X-CSRF-Token";
pub const HTTP_HEADER_AUTH_BASIC: &str = "Basic ";
pub const HTTP_HEADER_AUTH_BEARER: &str = "Bearer ";
pub const HTTP_HEADER_KEY_FORWARDING_HOST: &str = "X-Forwarding-Host";
pub const HTTP_HEADER_KEY_OUTPUT_POS: &str = "X-Output-Position";
pub const HTTP_HEADER_KEY_EXIT_CODE: &str = "X-Exit-Code";

// Cookie names
pub const COOKIE_CSRF_TOKEN: &str = "appmesh_csrf_token";

// Body keys
pub const HTTP_BODY_KEY_JWT_USERNAME: &str = "username";
pub const HTTP_BODY_KEY_JWT_TOTP: &str = "totp";
pub const HTTP_BODY_KEY_JWT_TOTP_CHALLENGE: &str = "totp_challenge";
pub const HTTP_BODY_KEY_JWT_EXPIRE_SECONDS: &str = "expire_seconds";
pub const HTTP_BODY_KEY_MFA_URI: &str = "uri";
pub const HTTP_BODY_KEY_OLD_PASSWORD: &str = "old_password";
pub const HTTP_BODY_KEY_NEW_PASSWORD: &str = "new_password";

// Query parameters
pub const HTTP_QUERY_KEY_STDOUT_INDEX: &str = "stdout_index";
pub const HTTP_QUERY_KEY_STDOUT_POSITION: &str = "stdout_position";
pub const HTTP_QUERY_KEY_STDOUT_MAXSIZE: &str = "stdout_maxsize";
pub const HTTP_QUERY_KEY_PROCESS_UUID: &str = "process_uuid";
pub const HTTP_QUERY_KEY_STDOUT_TIMEOUT: &str = "stdout_timeout";
pub const HTTP_QUERY_KEY_TIMEOUT: &str = "timeout";
pub const HTTP_QUERY_KEY_LIFECYCLE: &str = "lifecycle";

// JSON keys
pub const JSON_KEY_APP_NAME: &str = "name";
pub const JSON_KEY_PROCESS_UUID: &str = "process_uuid";
pub const JSON_KEY_BASE_CONFIG: &str = "BaseConfig";
pub const JSON_KEY_LOG_LEVEL: &str = "LogLevel";

// Other constants
pub const REST_TEXT_TOTP_CHALLENGE_JSON_KEY: &str = "totp_challenge";