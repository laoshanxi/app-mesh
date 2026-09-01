// client_http.rs

use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use log::{debug, error, info, warn};
use reqwest::{Client as ReqwestClient, Method, StatusCode};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::task::JoinHandle;

use crate::constants::*;
use crate::error::AppMeshError;
use crate::models::*;
use crate::oauth::TokenProvider;
use crate::requester::Requester;
use crate::response_ext::ResponseExt;
use crate::subscribe::EventCallback;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[cfg(unix)]
use nix::unistd::{chown, Gid, Group, Uid, User as UnixUser};

type Result<T> = std::result::Result<T, AppMeshError>;

// ---------------------------------------------------------------------------
// Helper: build small header/query maps without per-call HashMap::new boilerplate
// ---------------------------------------------------------------------------
macro_rules! hmap {
    () => { HashMap::new() };
    ($($k:expr => $v:expr),+ $(,)?) => {{
        let mut m = HashMap::with_capacity(8);
        $(m.insert($k.to_string(), $v.to_string());)+
        m
    }};
}

// ---------------------------------------------------------------------------
// HTTPRequester
// ---------------------------------------------------------------------------

/// HTTP-based requester implementation
pub struct HTTPRequester {
    url: String,
    client: ReqwestClient,
    access_token: Arc<RwLock<Option<String>>>,
    forward_to: Arc<Mutex<Option<String>>>,
}

impl HTTPRequester {
    pub fn new(
        url: String,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
        timeout: Option<Duration>,
        danger_accept_invalid_certs: bool,
    ) -> Result<Self> {
        let timeout = timeout.unwrap_or(Duration::from_secs(60));
        // reqwest uses `rustls-no-provider`; install a process-default provider to avoid panics.
        crate::tls_config::ensure_crypto_provider();
        // Engine SDK sessions deliberately have no cookie store. Browser application
        // state is a separate concern; SDK authentication is RFC 6750 Bearer-only.
        let mut client_builder = ReqwestClient::builder().timeout(timeout);

        // SSL setup. Verification is disabled only on explicit intent (danger
        // flag or the legacy empty CA path). A configured-but-missing CA is a hard
        // error; auto uses the App Mesh CA bundle if installed, else system CAs.
        if danger_accept_invalid_certs || ssl_verify.as_deref() == Some("") {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        } else {
            let ca_path = ssl_verify.or_else(|| {
                std::path::Path::new(DEFAULT_SSL_CA_CERT_PATH)
                    .exists()
                    .then(|| DEFAULT_SSL_CA_CERT_PATH.to_string())
            });
            if let Some(ca_path) = ca_path {
                let cert_bytes = std::fs::read(&ca_path).map_err(|e| {
                    AppMeshError::ConfigurationError(format!("Failed to read CA certificate '{}': {}", ca_path, e))
                })?;
                let cert = reqwest::Certificate::from_pem(&cert_bytes).map_err(|e| {
                    AppMeshError::ConfigurationError(format!("Invalid CA certificate '{}': {}", ca_path, e))
                })?;
                client_builder = client_builder.add_root_certificate(cert);
            }
        }

        if let Some((cert, key)) = &ssl_client_cert {
            let cert_content = std::fs::read_to_string(cert).map_err(|e| {
                AppMeshError::ConfigurationError(format!("Failed to read client certificate '{}': {}", cert, e))
            })?;
            let key_content = std::fs::read_to_string(key).map_err(|e| {
                AppMeshError::ConfigurationError(format!("Failed to read client key '{}': {}", key, e))
            })?;
            let pem = format!("{}\n{}", cert_content, key_content);
            let identity = reqwest::Identity::from_pem(pem.as_bytes()).map_err(|e| {
                AppMeshError::ConfigurationError(format!("Invalid client certificate/key: {}", e))
            })?;
            client_builder = client_builder.identity(identity);
        }

        Ok(Self {
            url,
            client: client_builder.build()?,
            access_token: Arc::new(RwLock::new(None)),
            forward_to: Arc::new(Mutex::new(None)),
        })
    }

    /// Convert reqwest::Response to http::Response<Bytes>
    async fn to_http_response(resp: reqwest::Response) -> Result<http::Response<Bytes>> {
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.bytes().await?;

        let mut builder = http::Response::builder().status(status);
        if let Some(header_map) = builder.headers_mut() {
            *header_map = headers;
        }

        builder.body(body).map_err(|e| AppMeshError::RequestFailed {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: format!("Failed to build response: {}", e),
        })
    }

    fn add_common_headers(&self, headers: &mut HashMap<String, String>) {
        headers
            .entry(HTTP_HEADER_KEY_USER_AGENT.to_string())
            .or_insert_with(|| HTTP_USER_AGENT.to_string());

        if let Some(token) = self.access_token.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            headers
                .entry(HTTP_HEADER_JWT_AUTHORIZATION.to_string())
                .or_insert_with(|| format!("{}{}", HTTP_HEADER_AUTH_BEARER, token));
        }

        // Poisoning is benign here (guarded state stays valid), so recover the guard.
        if let Some(forward_to) = self.forward_to.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            let forward_host = if forward_to.contains(':') {
                forward_to.clone()
            } else {
                format!("{}:{}", forward_to, Self::parse_url_port(&self.url))
            };
            headers.insert(HTTP_HEADER_KEY_FORWARDING_HOST.to_string(), forward_host);
        }
    }

    fn parse_url_port(url: &str) -> String {
        url.parse::<url::Url>()
            .ok()
            .and_then(|parsed| parsed.port_or_known_default())
            .map(|port| port.to_string())
            .unwrap_or_else(|| "6060".to_string())
    }

    /// Execute a request and return the raw `reqwest::Response` without buffering the body.
    async fn execute(
        &self,
        method: Method,
        path: &str,
        body: Option<reqwest::Body>,
        headers: Option<HashMap<String, String>>,
        query: Option<HashMap<String, String>>,
        fail_on_error: bool,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.url, path);
        debug!("{} {} {}", method, path, url);

        let mut req = self.client.request(method.clone(), &url);

        let mut all_headers = headers.unwrap_or_default();
        self.add_common_headers(&mut all_headers);
        for (k, v) in all_headers {
            req = req.header(k, v);
        }

        if let Some(body) = body {
            req = req.body(body)
        }

        if let Some(query) = query {
            req = req.query(&query);
        }

        let resp = req.send().await?;

        if fail_on_error && !resp.status().is_success() && resp.status() != StatusCode::PRECONDITION_REQUIRED {
            let status = resp.status();
            let text = resp.text().await?;
            error!("HTTP {} error for {} {}", status, method, path);
            return Err(AppMeshError::RequestFailed { status, message: text });
        }

        Ok(resp)
    }
}

#[async_trait]
impl Requester for HTTPRequester {
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        headers: Option<HashMap<String, String>>,
        query: Option<HashMap<String, String>>,
        fail_on_error: bool,
    ) -> Result<http::Response<Bytes>> {
        let body = body.map(|b| reqwest::Body::from(b.to_vec()));
        let resp = self.execute(method, path, body, headers, query, fail_on_error).await?;
        Self::to_http_response(resp).await
    }

    async fn send_streaming(
        &self,
        method: Method,
        path: &str,
        body: Option<reqwest::Body>,
        headers: Option<HashMap<String, String>>,
        query: Option<HashMap<String, String>>,
        fail_on_error: bool,
    ) -> Result<Option<reqwest::Response>> {
        Ok(Some(self.execute(method, path, body, headers, query, fail_on_error).await?))
    }

    fn set_forward_to(&self, url: Option<String>) {
        *self.forward_to.lock().unwrap_or_else(|e| e.into_inner()) = url;
    }

    fn handle_token_update(&self, token: Option<String>) {
        *self.access_token.write().unwrap_or_else(|e| e.into_inner()) = token;
    }

    fn get_access_token(&self) -> Option<String> {
        self.access_token.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

// ---------------------------------------------------------------------------
// AppMeshClient
// ---------------------------------------------------------------------------

/// Main AppMesh client for interacting with the AppMesh service.
///
/// Construct via [`crate::ClientBuilder`].
pub struct AppMeshClient {
    pub(crate) req: Box<dyn Requester>,
    url: String,
    /// Whether automatic token refresh is enabled.
    auto_refresh: AtomicBool,
    /// Handle to the background token-refresh task (if running).
    refresh_handle: Mutex<Option<JoinHandle<()>>>,
    /// Serializes renewals. Rotation makes a refresh token single-use, so two concurrent
    /// renewals would present the same one and the loser would be told it is revoked.
    renew_lock: tokio::sync::Mutex<()>,
    /// Optional external token source. It owns refresh/revocation; the Engine client
    /// receives only the current access token.
    token_provider: Mutex<Option<Arc<dyn TokenProvider>>>,
}

impl std::fmt::Debug for AppMeshClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppMeshClient")
            .field("url", &self.url)
            .field("requester", &"<dyn Requester>")
            .field("auto_refresh", &self.auto_refresh.load(Ordering::Relaxed))
            .finish()
    }
}

// -- Construction -----------------------------------------------------------

impl AppMeshClient {
    /// Create a new HTTP-backed client (crate-internal; public construction
    /// goes through [`crate::ClientBuilder`], which validates inputs).
    pub(crate) fn new(
        url: Option<String>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
        timeout: Option<Duration>,
        danger_accept_invalid_certs: bool,
    ) -> Result<Arc<Self>> {
        let url = url.unwrap_or_else(|| DEFAULT_HTTP_URL.to_string());
        let requester =
            HTTPRequester::new(url.clone(), ssl_verify, ssl_client_cert, timeout, danger_accept_invalid_certs)?;
        Ok(Arc::new(Self {
            req: Box::new(requester),
            url,
            auto_refresh: AtomicBool::new(false),
            refresh_handle: Mutex::new(None),
            renew_lock: tokio::sync::Mutex::new(()),
            token_provider: Mutex::new(None),
        }))
    }

    /// Create an `AppMeshClient` with a custom [`Requester`] (for TCP / WSS).
    pub(crate) fn with_requester(requester: Box<dyn Requester>, url: String) -> Arc<Self> {
        Arc::new(Self {
            req: requester,
            url,
            auto_refresh: AtomicBool::new(false),
            refresh_handle: Mutex::new(None),
            renew_lock: tokio::sync::Mutex::new(()),
            token_provider: Mutex::new(None),
        })
    }

    /// Enable or disable background token auto-refresh.
    pub fn set_provider_auto_refresh(self: &Arc<Self>, enable: bool) {
        self.auto_refresh.store(enable, Ordering::Relaxed);
        if !enable {
            self.cancel_refresh_task();
        } else if self.get_access_token().is_some() {
            self.schedule_token_refresh();
        }
    }

    /// Close the client and release resources.
    pub fn close(&self) {
        self.cancel_refresh_task();
        self.req.close();
    }

    /// Cancel the running refresh task, if any.
    fn cancel_refresh_task(&self) {
        if let Some(h) = self.refresh_handle.lock().unwrap_or_else(|e| e.into_inner()).take() {
            h.abort();
        }
    }

    /// Set the cluster forwarding host.
    pub fn set_forward_to(&self, url: Option<String>) {
        self.req.set_forward_to(url);
    }

    /// Execute a raw request (useful for advanced use cases).
    pub async fn raw_request(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        headers: Option<HashMap<String, String>>,
        query: Option<HashMap<String, String>>,
        fail_on_error: bool,
    ) -> Result<http::Response<Bytes>> {
        self.send(method, path, body, headers, query, fail_on_error).await
    }

    /// Install an external access-token provider. The provider is consulted before
    /// every request, and only its access token is ever attached to Engine traffic.
    pub fn set_token_provider(&self, provider: Option<Arc<dyn TokenProvider>>) {
        *self.token_provider.lock().unwrap_or_else(|error| error.into_inner()) = provider;
    }

    async fn prepare_bearer(&self) -> Result<Option<Arc<dyn TokenProvider>>> {
        let provider = self
            .token_provider
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        if let Some(provider) = provider.as_ref() {
            self.req.handle_token_update(Some(provider.access_token().await?));
        }
        Ok(provider)
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        headers: Option<HashMap<String, String>>,
        query: Option<HashMap<String, String>>,
        fail_on_error: bool,
    ) -> Result<http::Response<Bytes>> {
        let provider = self.prepare_bearer().await?;
        let Some(provider) = provider else {
            return self.req.send(method, path, body, headers, query, fail_on_error).await;
        };

        // Keep the first response available so a static/non-refreshable provider still
        // reports the Engine's 401. Retry only safe, replayable methods.
        let response = self
            .req
            .send(method.clone(), path, body, headers.clone(), query.clone(), false)
            .await?;
        let replayable = method == Method::GET || method == Method::HEAD || method == Method::OPTIONS;
        if response.status() == StatusCode::UNAUTHORIZED && replayable {
            if let Ok(tokens) = provider.force_refresh().await {
                self.req.handle_token_update(Some(tokens.access_token));
                return self.req.send(method, path, body, headers, query, fail_on_error).await;
            }
        }
        if fail_on_error
            && !response.status().is_success()
            && response.status() != StatusCode::PRECONDITION_REQUIRED
        {
            return Err(AppMeshError::RequestFailed {
                status: response.status(),
                message: String::from_utf8_lossy(response.body()).into_owned(),
            });
        }
        Ok(response)
    }
}

// -- Authentication ---------------------------------------------------------

impl AppMeshClient {
    /// Get the current access token, if any.
    pub fn get_access_token(&self) -> Option<String> {
        self.req.get_access_token()
    }

    /// Set a caller-owned access token without contacting Engine.
    /// Engine validates it when an API request is made.
    pub fn set_token(self: &Arc<Self>, token: &str) {
        self.req.handle_token_update(Some(token.to_string()));
        if self.auto_refresh.load(Ordering::Relaxed) {
            self.schedule_token_refresh();
        }
    }

    /// Clear the locally attached bearer without calling Engine or the authentication service.
    pub fn clear_token(&self) {
        self.cancel_refresh_task();
        self.req.handle_token_update(None);
    }

    /// Revoke through the installed token provider and clear local bearer state.
    pub async fn revoke_provider_tokens(&self) -> Result<()> {
        self.cancel_refresh_task();
        let provider = self.token_provider.lock().unwrap_or_else(|e| e.into_inner()).take();
        let result = match provider {
            Some(provider) => provider.revoke().await.map(|_| ()),
            None => Ok(()),
        };
        self.req.handle_token_update(None);
        result
    }

    /// Refresh through the installed provider. Refresh tokens never go to Engine.
    pub async fn refresh_provider_token(&self) -> Result<()> {
        let _guard = self.renew_lock.lock().await;
        let provider = self
            .token_provider
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
            .ok_or_else(|| AppMeshError::AuthenticationFailed("no token provider is installed".into()))?;
        let tokens = provider.force_refresh().await?;
        self.req.handle_token_update(Some(tokens.access_token));
        Ok(())
    }

    /// Start background token auto-refresh.
    ///
    /// Renews once the token has consumed `TOKEN_REFRESH_LIFETIME_RATIO` of its lifetime;
    /// failed renewals retry with bounded backoff.
    pub fn schedule_token_refresh(self: &Arc<Self>) {
        if !self.auto_refresh.load(Ordering::Relaxed) {
            return;
        }

        // Cancel any existing refresh task first
        self.cancel_refresh_task();

        let weak = Arc::downgrade(self);

        let handle = tokio::spawn(async move {
            let mut failures: u32 = 0;
            loop {
                let (mut sleep_duration, mut due) = {
                    let Some(client) = weak.upgrade() else { break };
                    if !client.auto_refresh.load(Ordering::Relaxed) { break }
                    Self::compute_refresh_plan(&client)
                };
                if failures > 0 {
                    // Retry on the backoff schedule, not the stale plan.
                    sleep_duration = Self::refresh_retry_delay(failures);
                    due = true;
                }

                tokio::time::sleep(sleep_duration).await;

                // Re-acquire the client (it may have been dropped)
                let Some(client) = weak.upgrade() else { break };
                if !client.auto_refresh.load(Ordering::Relaxed) { break }
                if !due {
                    continue;
                }

                debug!("Auto-refresh: attempting token renewal");
                match client.refresh_provider_token().await {
                    Ok(()) => {
                        if failures > 0 {
                            info!("Auto-refresh: token renewal recovered after {} failure(s)", failures);
                        }
                        failures = 0;
                        debug!("Auto-refresh: token renewed successfully");
                    }
                    Err(e) => {
                        failures = failures.saturating_add(1);
                        // Log sparsely: a daemon outage must not flood at the backoff rate.
                        // Not is_multiple_of: that needs Rust 1.87 and this crate declares
                        // no MSRV, so it would silently raise the bar for consumers.
                        #[allow(clippy::manual_is_multiple_of)]
                        if failures == 1 || failures % TOKEN_REFRESH_LOG_EVERY == 0 {
                            warn!("Auto-refresh: token renewal failed (attempt {}): {}", failures, e);
                        }
                    }
                }
            }
            debug!("Auto-refresh: background task exiting");
        });

        *self.refresh_handle.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
    }

    /// Seconds before expiry at which to renew: a fraction of the token's own lifetime,
    /// floored at `TOKEN_REFRESH_MARGIN_SECS`.
    fn refresh_margin(token: &str, exp: u64, iat: u64, now: u64) -> u64 {
        let lifetime = if iat > 0 && exp > iat {
            exp - iat
        } else {
            exp.saturating_sub(now)
        };
        let margin =
            ((lifetime as f64 * (1.0 - TOKEN_REFRESH_LIFETIME_RATIO)) as u64).max(TOKEN_REFRESH_MARGIN_SECS);

        // Jitter derived from the token: stable across polls, distinct per client.
        let mut hash: u32 = 2166136261; // FNV-1a
        for b in token.as_bytes() {
            hash ^= *b as u32;
            hash = hash.wrapping_mul(16777619);
        }
        let spread = margin as f64 * TOKEN_REFRESH_JITTER_RATIO;
        let offset = ((hash % 2001) as f64 / 1000.0 - 1.0) * spread;
        let jittered = ((margin as f64) + offset).max(1.0) as u64;

        // Clamp last: the floor (and its jitter) must never exceed the token's own life,
        // or the loop would spin at ~1Hz.
        if lifetime > 0 { jittered.min(lifetime / 2) } else { jittered }
    }

    /// How long to sleep, and whether a renewal is due afterwards. Sleep is capped at
    /// `TOKEN_REFRESH_INTERVAL_SECS` so a token replaced elsewhere is noticed.
    fn compute_refresh_plan(client: &AppMeshClient) -> (Duration, bool) {
        let poll = Duration::from_secs(TOKEN_REFRESH_INTERVAL_SECS);

        let Some(jwt_str) = client.get_access_token() else {
            // A held refresh token can still mint a new access token; with neither
            // credential there is nothing to renew, so just idle.
            let has_provider = client
                .token_provider
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .is_some();
            return if has_provider { (Duration::from_secs(1), true) } else { (poll, false) };
        };

        // Unreadable lifetime: fall back to the fixed cadence.
        let Some((exp, iat)) = Self::decode_jwt_times(&jwt_str) else {
            return (poll, true);
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let refresh_at = exp.saturating_sub(Self::refresh_margin(&jwt_str, exp, iat, now));
        if refresh_at <= now {
            return (Duration::from_secs(1), true); // at or past the refresh point
        }
        let wait = refresh_at - now;
        if wait > TOKEN_REFRESH_INTERVAL_SECS {
            (poll, false) // not due yet; wake up only to re-evaluate
        } else {
            (Duration::from_secs(wait), true)
        }
    }

    /// Bounded exponential backoff for the nth consecutive renewal failure (n >= 1).
    fn refresh_retry_delay(failures: u32) -> Duration {
        let shift = failures.saturating_sub(1).min(16);
        let secs = TOKEN_REFRESH_RETRY_BASE_SECS
            .saturating_mul(1u64 << shift)
            .min(TOKEN_REFRESH_RETRY_MAX_SECS);
        Duration::from_secs(secs)
    }

    /// Decode the `exp` and `iat` claims from a JWT without signature verification.
    /// `iat` is 0 when the claim is absent; callers must cope.
    fn decode_jwt_times(token: &str) -> Option<(u64, u64)> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        // Decode the payload (second part) using base64 URL-safe no-pad
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .ok()?;
        let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;
        let exp = payload.get("exp")?.as_u64()?;
        let iat = payload.get("iat").and_then(|v| v.as_u64()).unwrap_or(0);
        Some((exp, iat))
    }

}

// -- Principal and authorization management --------------------------------

impl AppMeshClient {
    pub async fn get_current_principal(&self) -> Result<Value> {
        let resp = self.send(Method::GET, "/appmesh/principal/self", None, None, None, true).await?;
        resp.json()
    }

    pub async fn list_principals(&self) -> Result<Value> {
        let resp = self.send(Method::GET, "/appmesh/principals", None, None, None, true).await?;
        resp.json()
    }

    pub async fn update_principal(&self, principal_id: &str, policy: Value) -> Result<()> {
        let body_bytes = serde_json::to_vec(&policy)?;
        self.send(
            Method::POST,
            &format!("/appmesh/principal/{}", encode_path_segment(principal_id)),
            Some(&body_bytes),
            None,
            None,
            true,
        )
        .await?;
        Ok(())
    }

    pub async fn delete_principal(&self, principal_id: &str) -> Result<()> {
        self.send(
            Method::DELETE,
            &format!("/appmesh/principal/{}", encode_path_segment(principal_id)),
            None,
            None,
            None,
            true,
        )
        .await?;
        Ok(())
    }

    pub async fn get_principal_permissions(&self) -> Result<Vec<String>> {
        let resp = self
            .send(Method::GET, "/appmesh/principal/self/permissions", None, None, None, true)
            .await?;
        json_string_array(&resp.json()?)
    }

    pub async fn list_permissions(&self) -> Result<Vec<String>> {
        let resp = self.send(Method::GET, "/appmesh/permissions", None, None, None, true).await?;
        json_string_array(&resp.json()?)
    }

    pub async fn list_roles(&self) -> Result<HashMap<String, Vec<String>>> {
        let resp = self.send(Method::GET, "/appmesh/roles", None, None, None, true).await?;
        let json: Value = resp.json()?;
        let mut roles = HashMap::new();
        if let Some(obj) = json.as_object() {
            for (key, value) in obj {
                if let Some(arr) = value.as_array() {
                    let perms: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(String::from)).collect();
                    roles.insert(key.clone(), perms);
                }
            }
        }
        Ok(roles)
    }

    pub async fn update_role(&self, role: &str, permissions: Vec<String>) -> Result<()> {
        let body_bytes = serde_json::to_vec(&permissions)?;
        self.send(Method::POST, &format!("/appmesh/role/{}", role), Some(&body_bytes), None, None, true)
            .await?;
        Ok(())
    }

    pub async fn delete_role(&self, role: &str) -> Result<()> {
        self.send(Method::DELETE, &format!("/appmesh/role/{}", role), None, None, None, true).await?;
        Ok(())
    }
}

/// Parse a JSON array of strings, failing loudly on a malformed (non-array) body.
fn json_string_array(json: &Value) -> Result<Vec<String>> {
    json.as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .ok_or_else(|| AppMeshError::SerializationError(format!("Expected JSON array, got: {}", json)))
}

fn encode_path_segment(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

// -- Application Management -------------------------------------------------

impl AppMeshClient {
    /// List all applications.
    pub async fn list_apps(&self) -> Result<Vec<Application>> {
        let resp = self.send(Method::GET, "/appmesh/applications", None, None, None, true).await?;
        let apps: Vec<Application> = resp.json()?;
        Ok(apps)
    }

    /// Get a single application by name.
    pub async fn get_app(&self, name: &str) -> Result<Application> {
        let resp =
            self.send(Method::GET, &format!("/appmesh/app/{}", name), None, None, None, true).await?;
        resp.json()
    }

    /// Get incremental stdout/stderr for a running or completed process.
    ///
    /// `output_position` is the next cursor to read from, and `exit_code` is populated once the
    /// process has already finished. `timeout` controls server-side long polling.
    pub async fn get_app_output(
        &self,
        name: &str,
        stdout_position: i64,
        stdout_index: i32,
        stdout_maxsize: i32,
        process_uuid: Option<&str>,
        timeout: Option<i32>,
    ) -> Result<AppOutput> {
        let mut query = hmap!();
        if stdout_index > 0 {
            query.insert(HTTP_QUERY_KEY_STDOUT_INDEX.into(), stdout_index.to_string());
        }
        if stdout_position > 0 {
            query.insert(HTTP_QUERY_KEY_STDOUT_POSITION.into(), stdout_position.to_string());
        }
        if stdout_maxsize > 0 {
            query.insert(HTTP_QUERY_KEY_STDOUT_MAXSIZE.into(), stdout_maxsize.to_string());
        }
        if let Some(uuid) = process_uuid {
            query.insert(HTTP_QUERY_KEY_PROCESS_UUID.into(), uuid.to_string());
        }
        if let Some(t) = timeout {
            query.insert(HTTP_QUERY_KEY_STDOUT_TIMEOUT.into(), t.to_string());
        }

        let resp = self.send(Method::GET, &format!("/appmesh/app/{}/output", name), None, None, Some(query), false)
            .await?;

        // Now we can read headers *and* body without cloning, thanks to &self on ResponseExt
        let mut out = AppOutput {
            status_code: resp.status().as_u16(),
            output: resp.text()?,
            output_position: 0,
            exit_code: None,
        };

        if let Some(pos) = resp.headers().get(HTTP_HEADER_KEY_OUTPUT_POS) {
            if let Ok(s) = pos.to_str() {
                out.output_position = s.parse().unwrap_or(0);
            }
        }
        if let Some(code) = resp.headers().get(HTTP_HEADER_KEY_EXIT_CODE) {
            if let Ok(s) = code.to_str() {
                out.exit_code = Some(s.parse().unwrap_or(0));
            }
        }

        Ok(out)
    }

    /// Check application health (returns `true` if healthy).
    pub async fn check_app_health(&self, name: &str) -> Result<bool> {
        let resp =
            self.send(Method::GET, &format!("/appmesh/app/{}/health", name), None, None, None, true).await?;
        let text = resp.text()?;
        Ok(text.trim() == "0")
    }

    /// Add or update an application (type-safe), optionally subscribing to events atomically.
    ///
    /// When `subscribe_events` is `Some`, a subscription is created before the app starts,
    /// ensuring no events are missed. The returned `Application.subscription_id` will be set.
    /// Requires TCP or WebSocket transport.
    pub async fn add_app(&self, app: &Application, subscribe_events: Option<&[&str]>) -> Result<Application> {
        let name = app
            .name
            .as_deref()
            .ok_or_else(|| AppMeshError::ConfigurationError("App name required".into()))?;
        let body_bytes = serde_json::to_vec(app)?;
        if subscribe_events.is_some() {
            // START may arrive before the add-app response on a persistent
            // connection, so the demuxer must own the read side first.
            self.req.enable_demuxer().await?;
        }
        let query = subscribe_events.map(|events| {
            let mut q = HashMap::new();
            q.insert("subscribe_events".to_string(), events.join(","));
            q
        });
        let resp =
            self.send(Method::PUT, &format!("/appmesh/app/{}", name), Some(&body_bytes), None, query, true).await?;
        resp.json()
    }

    /// Add or update an application from raw JSON (advanced).
    pub async fn add_app_raw(&self, app: Value) -> Result<Application> {
        let name = app[JSON_KEY_APP_NAME]
            .as_str()
            .ok_or_else(|| AppMeshError::ConfigurationError("App name required".into()))?;
        let body_bytes = serde_json::to_vec(&app)?;
        let resp =
            self.send(Method::PUT, &format!("/appmesh/app/{}", name), Some(&body_bytes), None, None, true).await?;
        resp.json()
    }

    /// Subscribe to real-time events for a specific app (or all apps if name is "*" or empty).
    ///
    /// When a `callback` is provided the underlying transport's message demuxer is
    /// enabled (TCP/WSS only) and the callback is registered for the returned
    /// subscription ID.  Events will be dispatched asynchronously until
    /// [`Self::unsubscribe`] is called.
    pub async fn subscribe(
        &self,
        app_name: &str,
        events: Option<&[&str]>,
        callback: Option<EventCallback>,
    ) -> Result<SubscriptionResult> {
        let path = if !app_name.is_empty() && app_name != "*" {
            format!("/appmesh/app/{}/subscribe", app_name)
        } else {
            "/appmesh/subscribe".to_string()
        };
        let query = events.map(|e| {
            let mut q = HashMap::new();
            q.insert("events".to_string(), e.join(","));
            q
        });
        // Enable the demuxer before the request even when no callback was supplied:
        // otherwise an event racing the response can be consumed by the direct reader.
        self.req.enable_demuxer().await?;

        // Pre-register callback state before sending. Events use the actual server
        // subscription ID and are buffered until that ID is registered below.
        // (The "__pending_" prefix cannot collide with server-issued UUID sub ids.)
        let pending_key = format!("__pending_{}", uuid::Uuid::new_v4());
        if let Some(ref cb) = callback {
            if let Some(demuxer) = self.req.get_demuxer() {
                demuxer.register_event_callback(&pending_key, cb.clone());
            }
        }

        let resp = self.send(Method::POST, &path, None, None, query, true).await?;
        let result: SubscriptionResult = resp.json()?;

        // Re-register callback with the actual subscription_id from server
        if let Some(cb) = callback {
            if let Some(demuxer) = self.req.get_demuxer() {
                // Register new key first, then remove pending — no gap where neither exists
                demuxer.register_event_callback(&result.subscription_id, cb);
                demuxer.unregister_event_callback(&pending_key);
            }
        }

        Ok(result)
    }

    /// Unsubscribe from events by subscription ID.
    ///
    /// Also unregisters the event callback from the demuxer (if active).
    pub async fn unsubscribe(&self, subscription_id: &str) -> Result<bool> {
        // Unregister from demuxer first
        if let Some(demuxer) = self.req.get_demuxer() {
            demuxer.unregister_event_callback(subscription_id);
        }

        let mut query = HashMap::new();
        query.insert("subscription_id".to_string(), subscription_id.to_string());
        let resp = self.send(Method::DELETE, "/appmesh/subscribe", None, None, Some(query), false).await?;
        Ok(resp.status() == StatusCode::OK)
    }

    pub async fn delete_app(&self, name: &str) -> Result<bool> {
        let resp =
            self.send(Method::DELETE, &format!("/appmesh/app/{}", name), None, None, None, false).await?;
        match resp.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            status => {
                let text = resp.text()?;
                Err(crate::error::AppMeshError::RequestFailed { status, message: text })
            }
        }
    }

    pub async fn enable_app(&self, name: &str) -> Result<()> {
        self.send(Method::POST, &format!("/appmesh/app/{}/enable", name), None, None, None, true).await?;
        Ok(())
    }

    pub async fn disable_app(&self, name: &str) -> Result<()> {
        self.send(Method::POST, &format!("/appmesh/app/{}/disable", name), None, None, None, true).await?;
        Ok(())
    }
}

// -- Run Application --------------------------------------------------------

impl AppMeshClient {
    /// Run an application synchronously and return `(exit_code, stdout)`.
    ///
    /// `exit_code` is populated from the `X-Exit-Code` header when present.
    pub async fn run_app_sync(
        &self,
        app: &Application,
        max_time: i32,
        lifecycle: i32,
    ) -> Result<(Option<i32>, String)> {
        let query = hmap! {
            HTTP_QUERY_KEY_TIMEOUT => max_time,
            HTTP_QUERY_KEY_LIFECYCLE => lifecycle,
        };
        let body_bytes = serde_json::to_vec(app)?;

        let resp = self.send(Method::POST, "/appmesh/app/syncrun", Some(&body_bytes), None, Some(query), false)
            .await?;

        let mut code = None;
        if resp.status() == StatusCode::OK {
            if let Some(h) = resp.headers().get(HTTP_HEADER_KEY_EXIT_CODE) {
                if let Ok(s) = h.to_str() {
                    code = Some(s.parse().unwrap_or(0));
                }
            }
        }
        Ok((code, resp.text()?))
    }

    /// Convenience: run a shell command synchronously. No app name is sent, so
    /// the daemon assigns a unique temporary name per call.
    pub async fn run_sync(
        &self,
        command: &str,
        max_time: i32,
        lifecycle: i32,
    ) -> Result<(Option<i32>, String)> {
        let app = Application {
            command: Some(command.to_string()),
            shell: Some(true),
            ..Default::default()
        };
        self.run_app_sync(&app, max_time, lifecycle).await
    }

    /// Run an application asynchronously and return an [`AppRun`] handle.
    ///
    /// The handle captures the current forwarding target so later polling can keep talking to the
    /// same cluster node.
    pub async fn run_app_async(
        self: &Arc<Self>,
        app: &Application,
        max_time: i32,
        lifecycle: i32,
    ) -> Result<AppRun> {
        let query = hmap! {
            HTTP_QUERY_KEY_TIMEOUT => max_time,
            HTTP_QUERY_KEY_LIFECYCLE => lifecycle,
        };
        let body_bytes = serde_json::to_vec(app)?;

        let resp =
            self.send(Method::POST, "/appmesh/app/run", Some(&body_bytes), None, Some(query), true).await?;

        let json: Value = resp.json()?;
        Ok(AppRun {
            client: Arc::clone(self),
            app_name: json[JSON_KEY_APP_NAME]
                .as_str()
                .ok_or_else(|| AppMeshError::Other("Missing app name".into()))?
                .to_string(),
            proc_uid: json[JSON_KEY_PROCESS_UUID]
                .as_str()
                .ok_or_else(|| AppMeshError::Other("Missing process UUID".into()))?
                .to_string(),
        })
    }

    /// Convenience: run a shell command asynchronously. No app name is sent, so
    /// the daemon assigns a unique temporary name per call; [`AppRun::app_name`]
    /// carries the server-assigned name.
    pub async fn run_async(
        self: &Arc<Self>,
        command: &str,
        max_time: i32,
        lifecycle: i32,
    ) -> Result<AppRun> {
        let app = Application {
            command: Some(command.to_string()),
            shell: Some(true),
            ..Default::default()
        };
        self.run_app_async(&app, max_time, lifecycle).await
    }

    /// Wait for an async run to complete, optionally invoking a callback with incremental stdout.
    /// Uses the subscribe-based wait on TCP/WSS; HTTP falls back to polling.
    ///
    /// Returns:
    /// - `Ok(Some(code))` — process exited (code may be negative for signal kills)
    /// - `Ok(None)` — caller-side timeout
    /// - `Err(AppMeshError::AppRemoved)` — app removed before EXIT was observed
    /// - `Err(AppMeshError::TransportDisconnected)` — TCP/WSS connection lost
    ///
    /// On success, this method makes a best-effort attempt to delete the temporary run app.
    pub async fn wait_for_async_run(
        &self,
        run: &AppRun,
        stdout_handler: OutputHandler,
        timeout: i32,
    ) -> Result<Option<i32>> {
        if self.req.supports_demuxer() {
            return crate::wait_subscribe::wait_for_async_run_subscribe(self, run, stdout_handler, timeout).await;
        }

        let mut last_output_position = 0i64;
        let start_time = std::time::Instant::now();

        loop {
            let app_out = self
                .get_app_output(&run.app_name, last_output_position, 0, 10240, Some(&run.proc_uid), Some(1))
                .await?;

            last_output_position = app_out.output_position;

            if !app_out.output.is_empty() {
                if let Some(ref handler) = stdout_handler {
                    handler(&app_out.output, last_output_position);
                }
            }

            // Real completion: clean up the temp run app.
            if app_out.exit_code.is_some() {
                let _ = self.delete_app(&run.app_name).await;
                return Ok(app_out.exit_code);
            }

            // Transport error or timeout: the app may still be running, so do not
            // delete it (matches the Go SDK, which removes the app only on a real exit).
            if app_out.status_code != StatusCode::OK.as_u16()
                || (timeout > 0 && start_time.elapsed().as_secs() >= timeout as u64)
            {
                return Ok(None);
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// Run a task by sending JSON data to a running app and returning its response body.
    pub async fn run_task(&self, name: &str, data: Value, timeout: i32) -> Result<String> {
        let timeout = if timeout <= 0 { 300 } else { timeout };
        let query = hmap! { HTTP_QUERY_KEY_TIMEOUT => timeout };
        let body_bytes = serde_json::to_vec(&data)?;

        let resp = self.send(Method::POST, &format!("/appmesh/app/{}/task", name), Some(&body_bytes), None, Some(query), true)
            .await?;
        resp.text()
    }

    /// Cancel a running task.
    pub async fn cancel_task(&self, name: &str) -> Result<bool> {
        let resp =
            self.send(Method::DELETE, &format!("/appmesh/app/{}/task", name), None, None, None, false).await?;
        Ok(resp.status() == StatusCode::OK)
    }
}

// -- System Management ------------------------------------------------------

impl AppMeshClient {
    /// Return the public OAuth/OIDC configuration advertised by the Engine.
    /// Login, refresh, and revocation still go directly to the authentication service.
    pub async fn get_auth_config(&self) -> Result<Value> {
        let resp = self.send(Method::GET, "/appmesh/auth/config", None, None, None, true).await?;
        resp.json()
    }

    /// Atomically enroll the current verified packaged administrator as the
    /// first App Mesh administrator. The Engine accepts this only from loopback
    /// on a built-in auth owner while the one-time enrollment window is open.
    pub async fn enroll_first_admin(&self) -> Result<Value> {
        let resp = self
            .send(Method::POST, "/appmesh/auth/enroll-first-admin", None, None, None, true)
            .await?;
        resp.json()
    }

    pub async fn get_host_resources(&self) -> Result<Value> {
        let resp = self.send(Method::GET, "/appmesh/resources", None, None, None, true).await?;
        resp.json()
    }

    pub async fn get_config(&self) -> Result<Value> {
        let resp = self.send(Method::GET, "/appmesh/config", None, None, None, true).await?;
        resp.json()
    }

    pub async fn set_config(&self, config: Value) -> Result<Value> {
        let body_bytes = serde_json::to_vec(&config)?;
        let resp =
            self.send(Method::POST, "/appmesh/config", Some(&body_bytes), None, None, true).await?;
        resp.json()
    }

    pub async fn set_log_level(&self, level: &str) -> Result<String> {
        let cfg = json!({ JSON_KEY_BASE_CONFIG: { JSON_KEY_LOG_LEVEL: level } });
        let resp = self.set_config(cfg).await?;
        Ok(resp[JSON_KEY_BASE_CONFIG][JSON_KEY_LOG_LEVEL].as_str().unwrap_or(level).to_string())
    }

    pub async fn get_metrics(&self) -> Result<String> {
        let resp = self.send(Method::GET, "/appmesh/metrics", None, None, None, true).await?;
        resp.text()
    }
}

// -- Label Management -------------------------------------------------------

impl AppMeshClient {
    pub async fn list_labels(&self) -> Result<Value> {
        let resp = self.send(Method::GET, "/appmesh/labels", None, None, None, true).await?;
        resp.json()
    }


    pub async fn add_label(&self, label: &str, value: &str) -> Result<()> {
        let query = hmap! { HTTP_QUERY_KEY_VALUE => value };
        self.send(Method::PUT, &format!("/appmesh/label/{}", label), None, None, Some(query), true).await?;
        Ok(())
    }


    pub async fn delete_label(&self, label: &str) -> Result<()> {
        self.send(Method::DELETE, &format!("/appmesh/label/{}", label), None, None, None, true).await?;
        Ok(())
    }

}

// -- File Management --------------------------------------------------------

impl AppMeshClient {
    /// Download a file from the remote server.
    ///
    /// When `preserve_permissions` is true, POSIX mode/owner/group metadata from response headers
    /// is applied locally on a best-effort basis.
    ///
    /// An empty `local_file` defaults to the basename of `remote_file`.
    pub async fn download_file(
        &self,
        remote_file: &str,
        local_file: &str,
        preserve_permissions: bool,
    ) -> Result<()> {
        // Empty local_file: derive the local path from the remote file's basename.
        let local_file = if local_file.is_empty() {
            Path::new(remote_file).file_name().and_then(|n| n.to_str()).unwrap_or(remote_file)
        } else {
            local_file
        };
        let headers = hmap! { HTTP_HEADER_KEY_X_FILE_PATH => remote_file };
        let local_path = Path::new(local_file);

        // Stream response chunks to disk (bounded memory) when the transport supports it.
        self.prepare_bearer().await?;
        if let Some(mut resp) = self
            .req
            .send_streaming(Method::GET, "/appmesh/file/download", None, Some(headers.clone()), None, true)
            .await?
        {
            let mut file = fs::File::create(local_path)?;
            while let Some(chunk) = resp.chunk().await? {
                file.write_all(&chunk)?;
            }
            file.flush()?;

            if preserve_permissions {
                let _ = Self::apply_file_attributes(local_path, resp.headers());
            }
            return Ok(());
        }

        // Buffered fallback for transports without HTTP streaming.
        let resp =
            self.send(Method::GET, "/appmesh/file/download", None, Some(headers), None, true).await?;
        fs::write(local_path, resp.bytes())?;

        if preserve_permissions {
            let _ = Self::apply_file_attributes(local_path, resp.headers());
        }
        Ok(())
    }

    /// Upload a file to the remote server.
    ///
    /// When `preserve_permissions` is true, local POSIX metadata is sent in headers so the server
    /// can recreate permissions/ownership when supported.
    ///
    /// An empty `remote_file` defaults to the local file's basename.
    pub async fn upload_file(
        &self,
        local_file: &str,
        remote_file: &str,
        preserve_permissions: bool,
    ) -> Result<()> {
        let remote_file = if remote_file.is_empty() {
            Path::new(local_file).file_name().and_then(|n| n.to_str()).unwrap_or(local_file)
        } else {
            remote_file
        };
        let local_path = Path::new(local_file);
        if !local_path.exists() {
            return Err(AppMeshError::NotFound(format!("Local file not found: {}", local_file)));
        }

        let mut headers = hmap! {
            HTTP_HEADER_KEY_X_FILE_PATH => remote_file,
            HTTP_HEADER_CONTENT_TYPE => "application/octet-stream",
        };
        if preserve_permissions {
            Self::get_file_attributes(local_path, &mut headers);
        }

        // Stream the file as the request body (bounded memory) when the transport supports it.
        // Explicit Content-Length keeps the wire format identical to the buffered upload.
        self.prepare_bearer().await?;
        let file = tokio::fs::File::open(local_path).await?;
        let file_len = file.metadata().await?.len();
        let mut streaming_headers = headers.clone();
        streaming_headers.insert(HTTP_HEADER_CONTENT_LENGTH.to_string(), file_len.to_string());
        if self
            .req
            .send_streaming(
                Method::POST,
                "/appmesh/file/upload",
                Some(reqwest::Body::from(file)),
                Some(streaming_headers),
                None,
                true,
            )
            .await?
            .is_some()
        {
            return Ok(());
        }

        // Buffered fallback for transports without HTTP streaming.
        let file_content = fs::read(local_file)?;
        self.send(Method::POST, "/appmesh/file/upload", Some(&file_content), Some(headers), None, true)
            .await?;
        Ok(())
    }

    /// Apply file attributes (mode, owner, group) from HTTP headers — Unix only.
    pub(crate) fn apply_file_attributes(
        #[cfg_attr(not(unix), allow(unused))] local_file: &Path,
        #[cfg_attr(not(unix), allow(unused))] headers: &http::HeaderMap,
    ) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            if let (Some(u), Some(g)) = (
                headers.get(HTTP_HEADER_KEY_X_FILE_USER).and_then(|v| v.to_str().ok()),
                headers.get(HTTP_HEADER_KEY_X_FILE_GROUP).and_then(|v| v.to_str().ok()),
            ) {
                let uid = UnixUser::from_name(u)
                    .ok()
                    .flatten()
                    .map(|x| x.uid)
                    .or_else(|| u.parse().ok().map(Uid::from_raw));

                let gid = Group::from_name(g)
                    .ok()
                    .flatten()
                    .map(|x| x.gid)
                    .or_else(|| g.parse().ok().map(Gid::from_raw));

                if let (Some(uid), Some(gid)) = (uid, gid) {
                    chown(local_file, Some(uid), Some(gid)).map_err(|e| {
                        AppMeshError::Other(format!("Failed to chown '{}': {}", local_file.display(), e))
                    })?;
                }
            }

            if let Some(mode) = headers
                .get(HTTP_HEADER_KEY_X_FILE_MODE)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|m| *m <= 0o777)
            {
                fs::set_permissions(local_file, fs::Permissions::from_mode(mode))?;
            }
        }

        Ok(())
    }

    /// Extract file attributes and populate headers — Unix only.
    pub(crate) fn get_file_attributes(
        #[cfg_attr(not(unix), allow(unused))] local_file: &Path,
        #[cfg_attr(not(unix), allow(unused))] headers: &mut HashMap<String, String>,
    ) {
        #[cfg(unix)]
        {
            let m = match fs::metadata(local_file) {
                Ok(m) => m,
                Err(_) => return,
            };

            headers.insert(HTTP_HEADER_KEY_X_FILE_MODE.into(), (m.permissions().mode() & 0o777).to_string());

            let uid = m.uid();
            let gid = m.gid();

            headers.insert(
                HTTP_HEADER_KEY_X_FILE_USER.into(),
                UnixUser::from_uid(Uid::from_raw(uid))
                    .ok()
                    .flatten()
                    .map(|u| u.name)
                    .unwrap_or_else(|| uid.to_string()),
            );

            headers.insert(
                HTTP_HEADER_KEY_X_FILE_GROUP.into(),
                Group::from_gid(Gid::from_raw(gid))
                    .ok()
                    .flatten()
                    .map(|g| g.name)
                    .unwrap_or_else(|| gid.to_string()),
            );
        }
    }
}

// -- ISO 8601 Duration Parsing ----------------------------------------------

impl AppMeshClient {
    /// Parse a timeout value that can be either integer seconds or an ISO 8601
    /// duration string (e.g., `"P1W"`, `"P2DT12H"`).
    pub fn parse_duration(timeout: &str) -> Result<i32> {
        // Try integer first
        if let Ok(secs) = timeout.parse::<i32>() {
            return Ok(secs);
        }
        // Try ISO 8601
        let dur = iso8601_duration::Duration::parse(timeout)
            .map_err(|e| AppMeshError::ConfigurationError(format!("Invalid duration '{}': {:?}", timeout, e)))?;
        // Approximate conversion (months ≈ 30 days, years ≈ 365 days)
        let secs = dur.year * 365.0 * 86400.0
            + dur.month * 30.0 * 86400.0
            + dur.day * 86400.0
            + dur.hour * 3600.0
            + dur.minute * 60.0
            + dur.second;
        Ok(secs as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_jwt_exp_valid() {
        // Build a minimal JWT: header.payload.signature
        // payload: {"sub":"admin","exp":1700000000}
        let payload = serde_json::json!({"sub": "admin", "exp": 1700000000u64});
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(b"{\"alg\":\"HS256\"}");
        let token = format!("{}.{}.fake_sig", header_b64, payload_b64);

        let times = AppMeshClient::decode_jwt_times(&token);
        assert_eq!(times, Some((1700000000, 0)));
    }

    #[test]
    fn test_decode_jwt_exp_missing() {
        let payload = serde_json::json!({"sub": "admin"});
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(b"{\"alg\":\"HS256\"}");
        let token = format!("{}.{}.fake_sig", header_b64, payload_b64);

        assert_eq!(AppMeshClient::decode_jwt_times(&token), None);
    }

    #[test]
    fn test_decode_jwt_exp_invalid_token() {
        assert_eq!(AppMeshClient::decode_jwt_times("not-a-jwt"), None);
        assert_eq!(AppMeshClient::decode_jwt_times("a.b"), None);
        assert_eq!(AppMeshClient::decode_jwt_times(""), None);
    }

    /// Build an unsigned JWT carrying iat/exp, all the refresh pacing logic reads.
    fn make_jwt(iat: u64, exp: u64) -> String {
        let mut claims = serde_json::json!({ "exp": exp });
        if iat > 0 {
            claims["iat"] = serde_json::json!(iat);
        }
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&claims).unwrap());
        let header_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{\"alg\":\"HS256\"}");
        format!("{}.{}.fake_sig", header_b64, payload_b64)
    }

    #[test]
    fn test_refresh_margin_scales_with_lifetime() {
        let now = 1_700_000_000u64;
        // 40% of lifetime, +/-10% of that margin.
        for (lifetime, low, high) in [(1800u64, 648u64, 792u64), (604_800, 217_728, 266_112)] {
            let exp = now + lifetime;
            let margin = AppMeshClient::refresh_margin(&make_jwt(now, exp), exp, now, now);
            assert!(margin >= low && margin <= high, "margin {} outside [{}, {}]", margin, low, high);
        }
        // Short tokens are floored at the 30s offset, not at 40% (= 24s).
        let exp = now + 60;
        let margin = AppMeshClient::refresh_margin(&make_jwt(now, exp), exp, now, now);
        assert!((27..=33).contains(&margin), "short-token margin {} not floored", margin);
    }

    #[test]
    fn test_refresh_margin_is_deterministic_per_token() {
        let now = 1_700_000_000u64;
        let exp = now + 3600;
        let token = make_jwt(now, exp);
        let first = AppMeshClient::refresh_margin(&token, exp, now, now);
        for _ in 0..10 {
            assert_eq!(AppMeshClient::refresh_margin(&token, exp, now, now), first);
        }
    }

    #[test]
    fn test_refresh_margin_spreads_across_tokens() {
        let now = 1_700_000_000u64;
        let exp = now + 3600;
        let distinct: std::collections::HashSet<u64> = (0..20)
            .map(|i| AppMeshClient::refresh_margin(&format!("{}{}", make_jwt(now, exp), i), exp, now, now))
            .collect();
        assert!(distinct.len() > 5, "jitter must spread renewals, got {} distinct", distinct.len());
    }

    #[test]
    fn test_refresh_retry_delay_is_bounded() {
        let got: Vec<u64> = (1..=7).map(|n| AppMeshClient::refresh_retry_delay(n).as_secs()).collect();
        assert_eq!(got, vec![5, 10, 20, 40, 60, 60, 60]);
    }
}
