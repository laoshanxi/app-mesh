// oauth.rs
//! Direct-Keycloak OAuth2 support for the App Mesh Rust SDK.
//!
//! Mirrors the Python SDK's `AppMeshClientOAuth` (`client_http_oauth.py`): the client
//! authenticates against Keycloak directly (password grant or the RFC 8628 device
//! authorization grant) and installs the resulting `access_token` as the Bearer token
//! on an existing [`AppMeshClient`] for daemon API calls.
//!
//! # Example
//!
//! ```no_run
//! use appmesh::{AppMeshClientOAuth, ClientBuilder, OAuth2Config};
//!
//! # async fn example() -> Result<(), appmesh::AppMeshError> {
//! let appmesh = ClientBuilder::new().url("https://127.0.0.1:6060").build()?;
//! let oauth = AppMeshClientOAuth::new(
//!     OAuth2Config {
//!         auth_server_url: "https://keycloak.example.com".into(),
//!         realm: "appmesh-realm".into(),
//!         client_id: "appmesh-client".into(),
//!         client_secret: std::env::var("APPMESH_Keycloak_client_secret").ok(),
//!     },
//!     appmesh,
//! )?;
//! oauth.login("username", "password", None).await?;
//! let apps = oauth.list_apps().await?; // daemon call with the Keycloak access token
//! # Ok(())
//! # }
//! ```

use log::warn;
use serde::Deserialize;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::client_http::AppMeshClient;
use crate::error::AppMeshError;

type Result<T> = std::result::Result<T, AppMeshError>;

/// Default OAuth2 scopes: request identity claims so userinfo returns
/// `preferred_username` / `email` (same as the Python SDK).
pub const DEFAULT_OAUTH_SCOPE: &str = "openid profile email";

const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const DEFAULT_DEVICE_EXPIRES_IN: u64 = 600;
const DEFAULT_DEVICE_INTERVAL: u64 = 5;

fn default_device_expires_in() -> u64 {
    DEFAULT_DEVICE_EXPIRES_IN
}

fn default_device_interval() -> u64 {
    DEFAULT_DEVICE_INTERVAL
}

/// Keycloak OAuth2 configuration (mirrors the Python SDK's `oauth2` dict).
#[derive(Debug, Clone)]
pub struct OAuth2Config {
    /// Keycloak server URL (e.g. `https://keycloak.example.com` or `.../auth` for legacy).
    pub auth_server_url: String,
    /// Keycloak realm.
    pub realm: String,
    /// Keycloak client ID.
    pub client_id: String,
    /// Keycloak client secret (confidential clients only).
    pub client_secret: Option<String>,
}

/// Device authorization response (RFC 8628 §3.2).
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    #[serde(default)]
    pub verification_uri: Option<String>,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    /// Lifetime of the device code in seconds.
    #[serde(default = "default_device_expires_in")]
    pub expires_in: u64,
    /// Minimum polling interval in seconds.
    #[serde(default = "default_device_interval")]
    pub interval: u64,
}

/// Extract the OAuth2 `error` code from an error response body.
fn oauth_error_code(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .unwrap_or_default()
}

/// Outcome of a single device-grant token poll (RFC 8628 §3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevicePoll {
    /// Authorization is still pending — keep polling at the current interval.
    Pending,
    /// The server asked to slow down — increase the polling interval by 5 seconds.
    SlowDown,
    /// The token was issued (and stored on the client).
    Token,
}

/// RFC 8628 §3.5 error classification: `authorization_pending` and `slow_down`
/// are retryable; anything else (`access_denied`, `expired_token`, ...) is terminal.
fn classify_device_poll_error(error_code: &str) -> Option<DevicePoll> {
    match error_code {
        "authorization_pending" => Some(DevicePoll::Pending),
        "slow_down" => Some(DevicePoll::SlowDown),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// KeycloakClient
// ---------------------------------------------------------------------------

/// Minimal Keycloak OpenID Connect client (the Rust counterpart of the
/// `python-keycloak` `KeycloakOpenID` usage in the Python SDK).
///
/// Stores the complete token response from the last successful grant; Keycloak
/// rotates the refresh token on every renewal, so the whole response is replaced.
pub struct KeycloakClient {
    config: OAuth2Config,
    http: reqwest::Client,
    token: Mutex<Option<Value>>,
}

impl std::fmt::Debug for KeycloakClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose client_secret or tokens.
        f.debug_struct("KeycloakClient")
            .field("auth_server_url", &self.config.auth_server_url)
            .field("realm", &self.config.realm)
            .field("client_id", &self.config.client_id)
            .finish()
    }
}

impl KeycloakClient {
    /// Create a Keycloak client with a default HTTP client (60s timeout, system CAs).
    pub fn new(config: OAuth2Config) -> Result<Self> {
        // reqwest is built with `rustls-no-provider`; install the process default.
        crate::tls_config::ensure_crypto_provider();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()?;
        Ok(Self::with_http_client(config, http))
    }

    /// Create a Keycloak client with a custom `reqwest::Client`
    /// (e.g. for a private CA or custom timeout).
    pub fn with_http_client(config: OAuth2Config, http: reqwest::Client) -> Self {
        Self { config, http, token: Mutex::new(None) }
    }

    /// Build an OpenID Connect endpoint URL: `{server}/realms/{realm}/protocol/openid-connect/{suffix}`.
    fn endpoint(&self, suffix: &str) -> String {
        format!(
            "{}/realms/{}/protocol/openid-connect/{}",
            self.config.auth_server_url.trim_end_matches('/'),
            self.config.realm,
            suffix
        )
    }

    fn lock_token(&self) -> std::sync::MutexGuard<'_, Option<Value>> {
        self.token.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The full token response from the last successful grant, if any.
    pub fn token(&self) -> Option<Value> {
        self.lock_token().clone()
    }

    /// The current access token, if any.
    pub fn access_token(&self) -> Option<String> {
        self.lock_token()
            .as_ref()
            .and_then(|t| t.get("access_token").and_then(|v| v.as_str()).map(str::to_string))
    }

    /// The current refresh token, if any.
    pub fn refresh_token(&self) -> Option<String> {
        self.lock_token()
            .as_ref()
            .and_then(|t| t.get("refresh_token").and_then(|v| v.as_str()).map(str::to_string))
    }

    /// Clear the stored token response.
    pub fn clear_token(&self) {
        *self.lock_token() = None;
    }

    /// POST a form to the token endpoint; store and return the full token response on success.
    async fn request_token(&self, form: &[(&str, &str)]) -> Result<Value> {
        let resp = self.http.post(self.endpoint("token")).form(form).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;
        if !status.is_success() {
            return Err(AppMeshError::AuthenticationFailed(format!(
                "Keycloak token request failed ({}): {}",
                status,
                String::from_utf8_lossy(&body)
            )));
        }
        let token: Value = serde_json::from_slice(&body)?;
        *self.lock_token() = Some(token.clone());
        Ok(token)
    }

    /// Login with username/password (Direct Access Grant).
    ///
    /// `totp` is passed verbatim as a string: converting to an integer would strip
    /// leading zeros (e.g. `"012345"` -> `12345`) and break authentication.
    pub async fn login(&self, username: &str, password: &str, totp: Option<&str>) -> Result<Value> {
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "password"),
            ("client_id", &self.config.client_id),
            ("username", username),
            ("password", password),
            ("scope", DEFAULT_OAUTH_SCOPE),
        ];
        if let Some(secret) = &self.config.client_secret {
            form.push(("client_secret", secret));
        }
        if let Some(totp_code) = totp {
            form.push(("totp", totp_code));
        }
        self.request_token(&form).await
    }

    /// Start the OAuth 2.0 Device Authorization Grant (RFC 8628 §3.1/§3.2).
    pub async fn request_device_authorization(&self, scope: &str) -> Result<DeviceAuthorization> {
        let mut form: Vec<(&str, &str)> =
            vec![("client_id", &self.config.client_id), ("scope", scope)];
        if let Some(secret) = &self.config.client_secret {
            form.push(("client_secret", secret));
        }
        let resp = self.http.post(self.endpoint("auth/device")).form(&form).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;
        if !status.is_success() {
            return Err(AppMeshError::AuthenticationFailed(format!(
                "Keycloak device authorization failed ({}): {}",
                status,
                String::from_utf8_lossy(&body)
            )));
        }
        Ok(serde_json::from_slice(&body)?)
    }

    /// Login via the OAuth 2.0 Device Authorization Grant (RFC 8628).
    ///
    /// The user opens `verification_uri_complete` (or `verification_uri` + `user_code`)
    /// on another device; this call polls the token endpoint until approval, denial,
    /// or expiry. `on_prompt` presents the instructions (default: print to stdout).
    ///
    /// Requires "OAuth 2.0 Device Authorization Grant" enabled on the Keycloak client.
    pub async fn login_device_flow(
        &self,
        scope: Option<&str>,
        on_prompt: Option<&(dyn Fn(&DeviceAuthorization) + Send + Sync)>,
    ) -> Result<Value> {
        let device = self
            .request_device_authorization(scope.unwrap_or(DEFAULT_OAUTH_SCOPE))
            .await?;

        if let Some(prompt) = on_prompt {
            prompt(&device);
        } else {
            let uri = device
                .verification_uri_complete
                .as_deref()
                .or(device.verification_uri.as_deref())
                .unwrap_or_default();
            println!("To sign in, open {} and enter code: {}", uri, device.user_code);
        }

        // RFC 8628 §3.5: poll no faster than `interval`, stop once the device code expires.
        let mut interval = device.interval;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(device.expires_in);

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(AppMeshError::AuthenticationFailed(
                    "Device authorization expired before the user approved the request".into(),
                ));
            }
            // Never overshoot the hard deadline.
            tokio::time::sleep(Duration::from_secs(interval).min(remaining)).await;

            match self.poll_device_token(&device).await? {
                DevicePoll::Token => {
                    return Ok(self.token().unwrap_or(Value::Null));
                }
                DevicePoll::Pending => {}
                DevicePoll::SlowDown => interval += 5, // RFC 8628 §3.5: back off by 5 seconds
            }
        }
    }

    /// Poll the token endpoint once for a pending device authorization (RFC 8628 §3.4).
    ///
    /// Returns [`DevicePoll::Token`] and stores the full token response on success;
    /// [`DevicePoll::Pending`] / [`DevicePoll::SlowDown`] while the user has not yet
    /// approved; any other OAuth2 error (`access_denied`, `expired_token`, ...) is
    /// returned as [`AppMeshError::AuthenticationFailed`].
    pub async fn poll_device_token(&self, device: &DeviceAuthorization) -> Result<DevicePoll> {
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", DEVICE_CODE_GRANT_TYPE),
            ("device_code", &device.device_code),
            ("client_id", &self.config.client_id),
        ];
        if let Some(secret) = &self.config.client_secret {
            form.push(("client_secret", secret));
        }

        let resp = self.http.post(self.endpoint("token")).form(&form).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;
        if status.is_success() {
            let token: Value = serde_json::from_slice(&body)?;
            *self.lock_token() = Some(token);
            return Ok(DevicePoll::Token);
        }

        let error_code = oauth_error_code(&body);
        classify_device_poll_error(&error_code).ok_or_else(|| {
            let detail = if error_code.is_empty() {
                String::from_utf8_lossy(&body).to_string()
            } else {
                error_code
            };
            AppMeshError::AuthenticationFailed(format!("Device authorization failed: {}", detail))
        })
    }

    /// Renew the token via `grant_type=refresh_token`.
    ///
    /// Keycloak rotates the refresh token on every renewal, so the complete
    /// new token response replaces the stored one.
    pub async fn refresh(&self) -> Result<Value> {
        let refresh_token = self.refresh_token().ok_or_else(|| {
            AppMeshError::AuthenticationFailed("No Keycloak refresh token available to renew".into())
        })?;
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
            ("client_id", &self.config.client_id),
        ];
        if let Some(secret) = &self.config.client_secret {
            form.push(("client_secret", secret));
        }
        self.request_token(&form).await
    }

    /// Log out from Keycloak (invalidates the session bound to the refresh token).
    pub async fn logout(&self) -> Result<()> {
        let refresh_token = self.refresh_token().ok_or_else(|| {
            AppMeshError::AuthenticationFailed("No Keycloak refresh token available to logout".into())
        })?;
        let mut form: Vec<(&str, &str)> =
            vec![("client_id", &self.config.client_id), ("refresh_token", &refresh_token)];
        if let Some(secret) = &self.config.client_secret {
            form.push(("client_secret", secret));
        }
        let resp = self.http.post(self.endpoint("logout")).form(&form).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.bytes().await.unwrap_or_default();
            return Err(AppMeshError::AuthenticationFailed(format!(
                "Keycloak logout failed ({}): {}",
                status,
                String::from_utf8_lossy(&body)
            )));
        }
        Ok(())
    }

    /// Get OIDC userinfo for the current access token, directly from Keycloak.
    pub async fn userinfo(&self) -> Result<Value> {
        let access_token = self.access_token().ok_or_else(|| {
            AppMeshError::AuthenticationFailed("No Keycloak access token available".into())
        })?;
        let resp = self
            .http
            .get(self.endpoint("userinfo"))
            .bearer_auth(access_token)
            .send()
            .await?;
        let status = resp.status();
        let body = resp.bytes().await?;
        if !status.is_success() {
            return Err(AppMeshError::AuthenticationFailed(format!(
                "Keycloak userinfo failed ({}): {}",
                status,
                String::from_utf8_lossy(&body)
            )));
        }
        Ok(serde_json::from_slice(&body)?)
    }
}

// ---------------------------------------------------------------------------
// AppMeshClientOAuth
// ---------------------------------------------------------------------------

/// [`AppMeshClient`] with Keycloak as the identity provider
/// (the Rust counterpart of the Python SDK's `AppMeshClientOAuth`).
///
/// Login (password or device flow) authenticates against Keycloak directly and
/// installs the access token on the wrapped [`AppMeshClient`], so all daemon API
/// calls (available through `Deref`) carry it as the Bearer token.
///
/// Token renewal must go through [`AppMeshClientOAuth::renew_token`] (Keycloak
/// `refresh_token` grant). Do not enable the wrapped client's background
/// auto-refresh: that renews against the daemon endpoint, not Keycloak.
pub struct AppMeshClientOAuth {
    client: Arc<AppMeshClient>,
    keycloak: KeycloakClient,
}

impl std::ops::Deref for AppMeshClientOAuth {
    type Target = AppMeshClient;

    fn deref(&self) -> &AppMeshClient {
        &self.client
    }
}

impl std::fmt::Debug for AppMeshClientOAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppMeshClientOAuth")
            .field("client", &self.client)
            .field("keycloak", &self.keycloak)
            .finish()
    }
}

impl AppMeshClientOAuth {
    /// Wrap an existing [`AppMeshClient`] (built via [`crate::ClientBuilder`]) with
    /// Keycloak authentication.
    pub fn new(oauth2: OAuth2Config, client: Arc<AppMeshClient>) -> Result<Self> {
        Ok(Self { client, keycloak: KeycloakClient::new(oauth2)? })
    }

    /// Same as [`Self::new`] but with a custom `reqwest::Client` for Keycloak requests
    /// (e.g. a private CA or custom timeout).
    pub fn with_http_client(
        oauth2: OAuth2Config,
        client: Arc<AppMeshClient>,
        http: reqwest::Client,
    ) -> Self {
        Self { client, keycloak: KeycloakClient::with_http_client(oauth2, http) }
    }

    /// The wrapped App Mesh client.
    pub fn appmesh(&self) -> &Arc<AppMeshClient> {
        &self.client
    }

    /// The underlying Keycloak client.
    pub fn keycloak(&self) -> &KeycloakClient {
        &self.keycloak
    }

    /// Install the current Keycloak access token as the App Mesh Bearer token.
    fn apply_access_token(&self) -> Result<()> {
        let access_token = self.keycloak.access_token().ok_or_else(|| {
            AppMeshError::AuthenticationFailed("Keycloak response contained no access_token".into())
        })?;
        self.client.set_token(&access_token);
        Ok(())
    }

    /// Login with username/password against Keycloak (Direct Access Grant) and
    /// install the access token on the wrapped App Mesh client.
    ///
    /// `totp` is passed verbatim as a string (leading zeros matter).
    pub async fn login(&self, username: &str, password: &str, totp: Option<&str>) -> Result<()> {
        self.keycloak.login(username, password, totp).await?;
        self.apply_access_token()
    }

    /// Login via the Device Authorization Grant (RFC 8628) and install the access
    /// token on the wrapped App Mesh client. See [`KeycloakClient::login_device_flow`].
    pub async fn login_device_flow(
        &self,
        scope: Option<&str>,
        on_prompt: Option<&(dyn Fn(&DeviceAuthorization) + Send + Sync)>,
    ) -> Result<()> {
        self.keycloak.login_device_flow(scope, on_prompt).await?;
        self.apply_access_token()
    }

    /// Renew the Keycloak token (`grant_type=refresh_token`) and install the new
    /// access token on the wrapped App Mesh client. Keycloak rotates the refresh
    /// token, so the complete new response is stored.
    pub async fn renew_token(&self) -> Result<()> {
        self.keycloak.refresh().await?;
        self.apply_access_token()
    }

    /// Get Keycloak OIDC userinfo for the current access token, directly from
    /// Keycloak (the daemon is not involved).
    pub async fn get_oauth_userinfo(&self) -> Result<Value> {
        self.keycloak.userinfo().await
    }

    /// Log out from Keycloak and from the App Mesh daemon session.
    ///
    /// Returns `true` only when both logouts succeeded (mirrors the Python SDK);
    /// failures are logged as warnings.
    pub async fn logout(&self) -> bool {
        let keycloak_ok = if self.keycloak.refresh_token().is_some() {
            match self.keycloak.logout().await {
                Ok(()) => true,
                Err(e) => {
                    warn!("Failed to logout from Keycloak: {}", e);
                    false
                }
            }
        } else {
            false
        };

        // Log off the daemon session BEFORE clearing the token, so the daemon can
        // still see and revoke the current access token.
        let daemon_ok = match self.client.logout().await {
            Ok(()) => true,
            Err(e) => {
                warn!("Failed to logout from App Mesh daemon: {}", e);
                false
            }
        };
        self.keycloak.clear_token();

        keycloak_ok && daemon_ok
    }

    /// Close the client and release resources, including a best-effort Keycloak logout.
    pub async fn close(&self) {
        if self.keycloak.refresh_token().is_some() {
            if let Err(e) = self.keycloak.logout().await {
                warn!("Failed to logout from Keycloak during close: {}", e);
            }
        }
        self.keycloak.clear_token();
        self.client.close();
    }
}

// ---------------------------------------------------------------------------
// Tests (pure logic; HTTP flows are covered in tests/oauth_test.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_poll_error_classification() {
        // RFC 8628 §3.5: pending/slow_down are retryable, anything else is terminal.
        assert_eq!(classify_device_poll_error("authorization_pending"), Some(DevicePoll::Pending));
        assert_eq!(classify_device_poll_error("slow_down"), Some(DevicePoll::SlowDown));
        assert_eq!(classify_device_poll_error("access_denied"), None);
        assert_eq!(classify_device_poll_error("expired_token"), None);
        assert_eq!(classify_device_poll_error(""), None);
    }

    #[test]
    fn test_oauth_error_code_extraction() {
        assert_eq!(oauth_error_code(br#"{"error":"authorization_pending"}"#), "authorization_pending");
        assert_eq!(oauth_error_code(b"not json"), "");
        assert_eq!(oauth_error_code(br#"{"other":"x"}"#), "");
    }

    #[test]
    fn test_endpoint_url_handles_trailing_slash() {
        let make = |url: &str| {
            // KeycloakClient::new installs the rustls crypto provider that the
            // `rustls-no-provider` reqwest build requires.
            KeycloakClient::new(OAuth2Config {
                auth_server_url: url.to_string(),
                realm: "r1".to_string(),
                client_id: "c1".to_string(),
                client_secret: None,
            })
            .expect("build KeycloakClient")
        };
        assert_eq!(
            make("https://kc.example.com/").endpoint("token"),
            "https://kc.example.com/realms/r1/protocol/openid-connect/token"
        );
        assert_eq!(
            make("https://kc.example.com").endpoint("auth/device"),
            "https://kc.example.com/realms/r1/protocol/openid-connect/auth/device"
        );
    }
}
