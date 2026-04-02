// client_http.rs

use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use log::{debug, error, warn};
use reqwest::{cookie::CookieStore, cookie::Jar, header::HeaderValue, Client as ReqwestClient, Method, StatusCode};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinHandle;

use crate::constants::*;
use crate::error::AppMeshError;
use crate::models::*;
use crate::persistent_jar::PersistentJar;
use crate::requester::Requester;
use crate::response_ext::ResponseExt;

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
    pub persistent_jar: Option<PersistentJar>,
    pub cookie_jar: Arc<Jar>,
    forward_to: Arc<Mutex<Option<String>>>,
}

impl HTTPRequester {
    pub fn new(
        url: String,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
        cookie_file: Option<String>,
        timeout: Option<Duration>,
        danger_accept_invalid_certs: bool,
    ) -> Result<Self> {
        // Cookie setup
        let (cookie_jar, persistent_jar) = match &cookie_file {
            Some(f) if !f.is_empty() => {
                let pj = PersistentJar::new(&url, f)?;
                (pj.jar(), Some(pj))
            }
            _ => (Arc::new(Jar::default()), None),
        };

        let timeout = timeout.unwrap_or(Duration::from_secs(60));
        let mut client_builder = ReqwestClient::builder()
            .cookie_provider(cookie_jar.clone())
            .timeout(timeout);

        // SSL setup
        if danger_accept_invalid_certs {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        } else {
            let ca_path = ssl_verify.unwrap_or_else(|| DEFAULT_SSL_CA_CERT_PATH.to_string());
            if let Ok(cert_bytes) = std::fs::read(&ca_path) {
                if let Ok(cert) = reqwest::Certificate::from_pem(&cert_bytes) {
                    client_builder = client_builder.add_root_certificate(cert);
                }
            } else {
                // CA file not found, skip verification
                client_builder = client_builder.danger_accept_invalid_certs(true);
            }
        }

        if let Some((cert, key)) = &ssl_client_cert {
            if let (Ok(cert_content), Ok(key_content)) =
                (std::fs::read_to_string(cert), std::fs::read_to_string(key))
            {
                let pem = format!("{}\n{}", cert_content, key_content);
                if let Ok(identity) = reqwest::Identity::from_pem(pem.as_bytes()) {
                    client_builder = client_builder.identity(identity);
                }
            }
        }

        Ok(Self {
            url,
            client: client_builder.build()?,
            persistent_jar,
            cookie_jar,
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

    fn get_cookie(&self, name: &str) -> Option<String> {
        let url = self.url.parse().ok()?;
        self.cookie_jar.cookies(&url).and_then(|header_value: HeaderValue| {
            let s = header_value.to_str().ok()?;
            s.split(';')
                .map(|s| s.trim())
                .find(|s| s.starts_with(&format!("{name}=")))
                .map(|s| s[name.len() + 1..].to_string())
        })
    }

    fn add_common_headers(&self, headers: &mut HashMap<String, String>) {
        headers
            .entry(HTTP_HEADER_KEY_USER_AGENT.to_string())
            .or_insert_with(|| HTTP_USER_AGENT.to_string());

        if let Ok(forward_to) = self.forward_to.lock() {
            if let Some(forward_to) = forward_to.as_ref() {
                let forward_host = if forward_to.contains(':') {
                    forward_to.clone()
                } else {
                    format!("{}:{}", forward_to, Self::parse_url_port(&self.url))
                };
                headers.insert(HTTP_HEADER_KEY_FORWARDING_HOST.to_string(), forward_host);
            }
        }

        if let Some(csrf_token) = self.get_cookie(COOKIE_CSRF_TOKEN) {
            if !csrf_token.is_empty() && !headers.contains_key(HTTP_HEADER_NAME_CSRF_TOKEN) {
                headers.insert(HTTP_HEADER_NAME_CSRF_TOKEN.to_string(), csrf_token);
            }
        }
    }

    fn parse_url_port(url: &str) -> String {
        url.parse::<url::Url>()
            .ok()
            .and_then(|parsed| parsed.port_or_known_default())
            .map(|port| port.to_string())
            .unwrap_or_else(|| "6060".to_string())
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
        let url = format!("{}{}", self.url, path);
        debug!("{} {} {}", method, path, url);

        let mut req = self.client.request(method.clone(), &url);

        let mut all_headers = headers.unwrap_or_default();
        self.add_common_headers(&mut all_headers);
        for (k, v) in all_headers {
            req = req.header(k, v);
        }

        if let Some(body) = body {
            req = req.body(body.to_vec())
        }

        if let Some(query) = query {
            req = req.query(&query);
        }

        // Snapshot token before request for change detection
        let old_token = self.get_access_token();

        let resp = req.send().await?;

        if fail_on_error && !resp.status().is_success() && resp.status() != StatusCode::PRECONDITION_REQUIRED {
            let status = resp.status();
            let text = resp.text().await?;
            error!("HTTP {} error: {}", status, text);
            return Err(AppMeshError::RequestFailed { status, message: text });
        }

        // Auto-detect token changes from server Set-Cookie responses
        let new_token = self.get_access_token();
        if new_token != old_token {
            self.handle_token_update(new_token);
        }

        Self::to_http_response(resp).await
    }

    fn set_forward_to(&mut self, url: Option<String>) {
        if let Ok(mut forward) = self.forward_to.lock() {
            *forward = url;
        }
    }

    fn handle_token_update(&self, _token: Option<String>) {
        if let Some(pj) = &self.persistent_jar {
            if let Err(e) = pj.save() {
                error!("Failed to save cookies after token update: {}", e);
            }
        }
    }

    fn set_cookie(&self, cookie_str: &str) {
        if let Ok(url) = self.url.parse() {
            self.cookie_jar.add_cookie_str(cookie_str, &url);
        }
    }

    fn get_access_token(&self) -> Option<String> {
        self.get_cookie(COOKIE_TOKEN)
    }
}

// ---------------------------------------------------------------------------
// AppMeshClient
// ---------------------------------------------------------------------------

/// Main AppMesh client for interacting with the AppMesh service.
///
/// Construct via [`crate::ClientBuilder`] (recommended) or [`AppMeshClient::new`].
pub struct AppMeshClient {
    pub(crate) req: Box<dyn Requester>,
    url: String,
    /// Whether automatic token refresh is enabled.
    auto_refresh: AtomicBool,
    /// Handle to the background token-refresh task (if running).
    refresh_handle: Mutex<Option<JoinHandle<()>>>,
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
    /// Create a new HTTP-backed client.
    pub fn new(
        url: Option<String>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
        cookie_file: Option<String>,
        timeout: Option<Duration>,
        danger_accept_invalid_certs: bool,
    ) -> Result<Arc<Self>> {
        let url = url.unwrap_or_else(|| DEFAULT_HTTP_URL.to_string());
        let requester =
            HTTPRequester::new(url.clone(), ssl_verify, ssl_client_cert, cookie_file, timeout, danger_accept_invalid_certs)?;
        Ok(Arc::new(Self {
            req: Box::new(requester),
            url,
            auto_refresh: AtomicBool::new(false),
            refresh_handle: Mutex::new(None),
        }))
    }

    /// Create an `AppMeshClient` with a custom [`Requester`] (for TCP / WSS).
    pub fn with_requester(requester: Box<dyn Requester>, url: String) -> Arc<Self> {
        Arc::new(Self {
            req: requester,
            url,
            auto_refresh: AtomicBool::new(false),
            refresh_handle: Mutex::new(None),
        })
    }

    /// Enable or disable background token auto-refresh.
    pub fn set_auto_refresh_token(self: &Arc<Self>, enable: bool) {
        self.auto_refresh.store(enable, Ordering::Relaxed);
        if !enable {
            self.cancel_refresh_task();
        } else if self.get_stored_token().is_some() {
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
        if let Ok(mut handle) = self.refresh_handle.lock() {
            if let Some(h) = handle.take() {
                h.abort();
            }
        }
    }

    /// Set the cluster forwarding host.
    pub fn forward_to(&mut self, url: Option<String>) {
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
        self.req.send(method, path, body, headers, query, fail_on_error).await
    }
}

// -- Authentication ---------------------------------------------------------

impl AppMeshClient {
    /// Login with username/password and update this client session on success.
    ///
    /// Returns the TOTP challenge string when the server replies with HTTP 428 and no valid code
    /// was supplied; otherwise returns an empty string after storing the issued JWT/cookie.
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        totp: Option<&str>,
        token_expire: Option<i32>,
        audience: Option<&str>,
    ) -> Result<String> {
        let mut headers = hmap! {
            HTTP_HEADER_JWT_AUTHORIZATION => format!(
                "{}{}",
                HTTP_HEADER_AUTH_BASIC,
                base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, password))
            ),
            HTTP_HEADER_JWT_SET_COOKIE => "true"
        };

        if let Some(seconds) = token_expire {
            headers.insert(HTTP_HEADER_JWT_EXPIRE_SECONDS.into(), seconds.to_string());
        }
        if let Some(aud) = audience {
            headers.insert(HTTP_HEADER_JWT_AUDIENCE.into(), aud.to_string());
        }
        if let Some(totp_code) = totp {
            headers.insert(HTTP_HEADER_JWT_TOTP.into(), totp_code.to_string());
        }

        let resp = self.req.send(Method::POST, "/appmesh/login", None, Some(headers), None, false).await?;

        // Handle TOTP challenge (HTTP 428)
        if resp.status() == StatusCode::PRECONDITION_REQUIRED {
            let json: Value = resp.json()?;
            if let Some(challenge) = json.get(REST_TEXT_TOTP_CHALLENGE_JSON_KEY) {
                return Ok(challenge.as_str().unwrap_or("").to_string());
            }
            return Err(AppMeshError::AuthenticationFailed(json.to_string()));
        } else if resp.status() != StatusCode::OK {
            let text = resp.text()?;
            return Err(AppMeshError::AuthenticationFailed(text));
        }

        Ok(String::new())
    }

    /// Login and automatically start token refresh if `auto_refresh_token` is enabled.
    ///
    /// This is the recommended way to login when using `Arc<AppMeshClient>`, as it
    /// schedules the background refresh task after a successful login.
    pub async fn login_and_refresh(
        self: &Arc<Self>,
        username: &str,
        password: &str,
        totp: Option<&str>,
        token_expire: Option<i32>,
        audience: Option<&str>,
    ) -> Result<String> {
        let result = self.login(username, password, totp, token_expire, audience).await?;
        if result.is_empty() && self.auto_refresh.load(Ordering::Relaxed) {
            self.schedule_token_refresh();
        }
        Ok(result)
    }

    /// Validate a TOTP challenge and store the returned JWT in this client session.
    pub async fn validate_totp(
        &self,
        username: &str,
        challenge: &str,
        totp: &str,
        token_expire: i32,
    ) -> Result<()> {
        let headers = hmap! { HTTP_HEADER_JWT_SET_COOKIE => "true" };

        let body = json!({
            HTTP_BODY_KEY_JWT_USERNAME: username,
            HTTP_BODY_KEY_JWT_TOTP: totp,
            HTTP_BODY_KEY_JWT_TOTP_CHALLENGE: challenge,
            HTTP_BODY_KEY_JWT_EXPIRE_SECONDS: token_expire
        });
        let body_bytes = serde_json::to_vec(&body)?;

        self.req.send(Method::POST, "/appmesh/totp/validate", Some(&body_bytes), Some(headers), None, true).await?;
        Ok(())
    }

    /// Get the current access token, if any.
    pub fn get_access_token(&self) -> Option<String> {
        self.req.get_access_token()
    }

    /// Set a JWT token directly without server-side verification.
    /// Use when the token is already known to be valid.
    /// For server-side verification, use [`authenticate()`] instead.
    pub fn set_token(self: &Arc<Self>, token: &str) {
        let cookie_str = format!("{}={}", COOKIE_TOKEN, token);
        self.req.set_cookie(&cookie_str);
        self.req.handle_token_update(Some(token.to_string()));
        if self.auto_refresh.load(Ordering::Relaxed) {
            self.schedule_token_refresh();
        }
    }

    /// Verify the supplied JWT token with the server and optionally update this client session.
    pub async fn authenticate(
        &self,
        token: &str,
        permission: Option<&str>,
        audience: Option<&str>,
        update_session: bool,
    ) -> Result<(bool, String)> {
        let mut headers =
            hmap! { HTTP_HEADER_JWT_AUTHORIZATION => format!("{}{}", HTTP_HEADER_AUTH_BEARER, token) };

        if let Some(perm) = permission {
            headers.insert(HTTP_HEADER_JWT_AUTH_PERMISSION.into(), perm.to_string());
        }
        if let Some(aud) = audience {
            headers.insert(HTTP_HEADER_JWT_AUDIENCE.into(), aud.to_string());
        }
        if update_session {
            headers.insert(HTTP_HEADER_JWT_SET_COOKIE.into(), "true".into());
        }
        let resp = self.req.send(Method::POST, "/appmesh/auth", None, Some(headers), None, false).await?;

        let is_ok = resp.status() == StatusCode::OK;
        let text = resp.text()?;
        Ok((is_ok, text))
    }

    /// Logout from the current session.
    pub async fn logout(&self) -> Result<()> {
        self.cancel_refresh_task();
        self.req.send(Method::POST, "/appmesh/self/logoff", None, None, None, true).await?;
        Ok(())
    }

    /// Renew the current JWT token already attached to this client.
    pub async fn renew_token(&self, token_expire: Option<i32>) -> Result<()> {
        let headers = token_expire.map(|sec| hmap! { HTTP_HEADER_JWT_EXPIRE_SECONDS => sec });

        self.req.send(Method::POST, "/appmesh/token/renew", None, headers, None, true).await?;
        Ok(())
    }

    /// Start background token auto-refresh.
    ///
    /// The refresh loop decodes the JWT `exp` claim and renews shortly before expiry.
    pub fn schedule_token_refresh(self: &Arc<Self>) {
        if !self.auto_refresh.load(Ordering::Relaxed) {
            return;
        }

        // Cancel any existing refresh task first
        self.cancel_refresh_task();

        let weak = Arc::downgrade(self);

        let handle = tokio::spawn(async move {
            loop {
                // Determine how long to sleep
                let sleep_duration = {
                    let Some(client) = weak.upgrade() else { break };
                    if !client.auto_refresh.load(Ordering::Relaxed) { break }
                    Self::compute_refresh_delay(&client)
                };

                tokio::time::sleep(sleep_duration).await;

                // Re-acquire the client (it may have been dropped)
                let Some(client) = weak.upgrade() else { break };
                if !client.auto_refresh.load(Ordering::Relaxed) { break }

                debug!("Auto-refresh: attempting token renewal");
                match client.renew_token(None).await {
                    Ok(()) => {
                        debug!("Auto-refresh: token renewed successfully");
                        // After renewal, re-schedule via the new token's exp
                        // (loop continues, will recompute delay)
                    }
                    Err(e) => {
                        warn!("Auto-refresh: token renewal failed: {}", e);
                        // Back off and retry after the regular interval
                    }
                }
            }
            debug!("Auto-refresh: background task exiting");
        });

        if let Ok(mut h) = self.refresh_handle.lock() {
            *h = Some(handle);
        }
    }

    /// Compute how long to sleep before the next refresh attempt.
    ///
    /// Decodes the JWT `exp` claim (without verifying the signature) to
    /// determine time-to-expiry.  Returns a shorter delay if the token is
    /// close to expiring, or falls back to `TOKEN_REFRESH_INTERVAL_SECS`
    /// if the token cannot be decoded.
    fn compute_refresh_delay(client: &AppMeshClient) -> Duration {
        let default_interval = Duration::from_secs(TOKEN_REFRESH_INTERVAL_SECS);

        let Some(jwt_str) = client.get_stored_token() else {
            return default_interval;
        };

        match Self::decode_jwt_exp(&jwt_str) {
            Some(exp) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if exp <= now {
                    // Already expired — refresh immediately (small delay to avoid tight loop)
                    Duration::from_secs(1)
                } else {
                    let time_to_expiry = exp - now;
                    if time_to_expiry <= TOKEN_REFRESH_MARGIN_SECS {
                        Duration::from_secs(1)
                    } else {
                        // Sleep until TOKEN_REFRESH_MARGIN_SECS before expiry,
                        // but no longer than TOKEN_REFRESH_INTERVAL_SECS
                        let wait = time_to_expiry - TOKEN_REFRESH_MARGIN_SECS;
                        Duration::from_secs(wait.min(TOKEN_REFRESH_INTERVAL_SECS))
                    }
                }
            }
            None => default_interval,
        }
    }

    /// Retrieve the current access token from the underlying transport.
    fn get_stored_token(&self) -> Option<String> {
        self.req.get_access_token()
    }

    /// Decode the `exp` field from a JWT without signature verification.
    ///
    /// JWT format: `header.payload.signature` — we only decode the payload (part 1).
    fn decode_jwt_exp(token: &str) -> Option<u64> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        // Decode the payload (second part) using base64 URL-safe no-pad
        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .ok()?;
        let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;
        payload.get("exp")?.as_u64()
    }

    /// Get the raw TOTP secret for MFA setup.
    ///
    /// The server returns a base64-encoded provisioning URI; this helper extracts and returns
    /// only the `secret` query parameter.
    pub async fn get_totp_secret(&self) -> Result<String> {
        let resp = self.req.send(Method::POST, "/appmesh/totp/secret", None, None, None, true).await?;

        let val: Value = resp.json()?;
        let encoded =
            val[HTTP_BODY_KEY_MFA_URI].as_str().ok_or_else(|| AppMeshError::Other("Invalid MFA URI".into()))?;

        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded)?;
        let totp_uri = String::from_utf8_lossy(&decoded).to_string();
        Self::parse_totp_uri(&totp_uri)
    }

    fn parse_totp_uri(uri: &str) -> Result<String> {
        if let Some(query_start) = uri.find('?') {
            for param in uri[query_start + 1..].split('&') {
                if let Some(eq_pos) = param.find('=') {
                    if &param[..eq_pos] == "secret" {
                        return Ok(param[eq_pos + 1..].to_string());
                    }
                }
            }
        }
        Err(AppMeshError::Other("TOTP URI does not contain a 'secret' field".into()))
    }

    /// Enable TOTP with a verification code.
    pub async fn enable_totp(&self, totp: &str) -> Result<()> {
        let headers = hmap! { HTTP_HEADER_JWT_TOTP => totp };

        self.req.send(Method::POST, "/appmesh/totp/setup", None, Some(headers), None, true).await?;
        Ok(())
    }

    /// Disable TOTP for a user (`None` = current user).
    pub async fn disable_totp(&self, user: Option<&str>) -> Result<()> {
        let user = user.unwrap_or("self");
        self.req.send(Method::POST, &format!("/appmesh/totp/{}/disable", user), None, None, None, true).await?;
        Ok(())
    }
}

// -- User Management --------------------------------------------------------

impl AppMeshClient {
    pub async fn update_password(&self, old: &str, new: &str, user: Option<&str>) -> Result<()> {
        let user = user.unwrap_or("self");
        let body = json!({
            HTTP_BODY_KEY_OLD_PASSWORD: base64::engine::general_purpose::STANDARD.encode(old),
            HTTP_BODY_KEY_NEW_PASSWORD: base64::engine::general_purpose::STANDARD.encode(new)
        });
        let body_bytes = serde_json::to_vec(&body)?;

        self.req
            .send(Method::POST, &format!("/appmesh/user/{}/passwd", user), Some(&body_bytes), None, None, true)
            .await?;
        Ok(())
    }

    pub async fn get_current_user(&self) -> Result<Value> {
        let resp = self.req.send(Method::GET, "/appmesh/user/self", None, None, None, true).await?;
        Ok(resp.json()?)
    }

    pub async fn list_users(&self) -> Result<Value> {
        let resp = self.req.send(Method::GET, "/appmesh/users", None, None, None, true).await?;
        Ok(resp.json()?)
    }

    pub async fn add_user(&self, user: Value) -> Result<()> {
        let name =
            user["name"].as_str().ok_or_else(|| AppMeshError::ConfigurationError("Missing username".into()))?;
        let body_bytes = serde_json::to_vec(&user)?;
        self.req.send(Method::PUT, &format!("/appmesh/user/{}", name), Some(&body_bytes), None, None, true).await?;
        Ok(())
    }

    pub async fn delete_user(&self, user: &str) -> Result<()> {
        self.req.send(Method::DELETE, &format!("/appmesh/user/{}", user), None, None, None, true).await?;
        Ok(())
    }

    pub async fn lock_user(&self, user: &str) -> Result<()> {
        self.req.send(Method::POST, &format!("/appmesh/user/{}/lock", user), None, None, None, true).await?;
        Ok(())
    }

    pub async fn unlock_user(&self, user: &str) -> Result<()> {
        self.req.send(Method::POST, &format!("/appmesh/user/{}/unlock", user), None, None, None, true).await?;
        Ok(())
    }

    pub async fn list_groups(&self) -> Result<Vec<String>> {
        let resp = self.req.send(Method::GET, "/appmesh/user/groups", None, None, None, true).await?;
        let json: Value = resp.json()?;
        Ok(json.as_array().unwrap_or(&vec![]).iter().filter_map(|v| v.as_str().map(String::from)).collect())
    }

    pub async fn get_user_permissions(&self) -> Result<Vec<String>> {
        let resp = self.req.send(Method::GET, "/appmesh/user/permissions", None, None, None, true).await?;
        let json: Value = resp.json()?;
        Ok(json.as_array().unwrap_or(&vec![]).iter().filter_map(|v| v.as_str().map(String::from)).collect())
    }

    pub async fn list_permissions(&self) -> Result<Vec<String>> {
        let resp = self.req.send(Method::GET, "/appmesh/permissions", None, None, None, true).await?;
        let json: Value = resp.json()?;
        Ok(json.as_array().unwrap_or(&vec![]).iter().filter_map(|v| v.as_str().map(String::from)).collect())
    }

    pub async fn list_roles(&self) -> Result<HashMap<String, Vec<String>>> {
        let resp = self.req.send(Method::GET, "/appmesh/roles", None, None, None, true).await?;
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
        self.req
            .send(Method::POST, &format!("/appmesh/role/{}", role), Some(&body_bytes), None, None, true)
            .await?;
        Ok(())
    }

    pub async fn delete_role(&self, role: &str) -> Result<()> {
        self.req.send(Method::DELETE, &format!("/appmesh/role/{}", role), None, None, None, true).await?;
        Ok(())
    }
}

// -- Application Management -------------------------------------------------

impl AppMeshClient {
    /// List all applications.
    pub async fn list_apps(&self) -> Result<Vec<Application>> {
        let resp = self.req.send(Method::GET, "/appmesh/applications", None, None, None, true).await?;
        let apps: Vec<Application> = resp.json()?;
        Ok(apps)
    }

    /// Get a single application by name.
    pub async fn get_app(&self, name: &str) -> Result<Application> {
        let resp =
            self.req.send(Method::GET, &format!("/appmesh/app/{}", name), None, None, None, true).await?;
        Ok(resp.json()?)
    }

    /// Get incremental stdout/stderr for a running or completed process.
    ///
    /// `output_position` is the next cursor to read from, and `exit_code` is populated once the
    /// process has already finished. `timeout` controls server-side long polling.
    pub async fn get_app_output(
        &self,
        app: &str,
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

        let resp = self
            .req
            .send(Method::GET, &format!("/appmesh/app/{}/output", app), None, None, Some(query), false)
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
    pub async fn check_app_health(&self, app: &str) -> Result<bool> {
        let resp =
            self.req.send(Method::GET, &format!("/appmesh/app/{}/health", app), None, None, None, true).await?;
        let text = resp.text()?;
        Ok(text.trim() == "0")
    }

    /// Add or update an application (type-safe).
    pub async fn add_app(&self, app: &Application) -> Result<Application> {
        let name = app
            .name
            .as_deref()
            .ok_or_else(|| AppMeshError::ConfigurationError("App name required".into()))?;
        let body_bytes = serde_json::to_vec(app)?;
        let resp =
            self.req.send(Method::PUT, &format!("/appmesh/app/{}", name), Some(&body_bytes), None, None, true).await?;
        Ok(resp.json()?)
    }

    /// Add or update an application from raw JSON (advanced).
    pub async fn add_app_raw(&self, app: Value) -> Result<Application> {
        let name = app[JSON_KEY_APP_NAME]
            .as_str()
            .ok_or_else(|| AppMeshError::ConfigurationError("App name required".into()))?;
        let body_bytes = serde_json::to_vec(&app)?;
        let resp =
            self.req.send(Method::PUT, &format!("/appmesh/app/{}", name), Some(&body_bytes), None, None, true).await?;
        Ok(resp.json()?)
    }

    pub async fn delete_app(&self, name: &str) -> Result<bool> {
        let resp =
            self.req.send(Method::DELETE, &format!("/appmesh/app/{}", name), None, None, None, false).await?;
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
        self.req.send(Method::POST, &format!("/appmesh/app/{}/enable", name), None, None, None, true).await?;
        Ok(())
    }

    pub async fn disable_app(&self, name: &str) -> Result<()> {
        self.req.send(Method::POST, &format!("/appmesh/app/{}/disable", name), None, None, None, true).await?;
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

        let resp = self
            .req
            .send(Method::POST, "/appmesh/app/syncrun", Some(&body_bytes), None, Some(query), false)
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

    /// Convenience: run a shell command synchronously.
    pub async fn run_sync(
        &self,
        command: &str,
        max_time: i32,
        lifecycle: i32,
    ) -> Result<(Option<i32>, String)> {
        let app = Application::builder("_run_cmd_")
            .command(command)
            .shell(true)
            .build();
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
            self.req.send(Method::POST, "/appmesh/app/run", Some(&body_bytes), None, Some(query), true).await?;

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

    /// Convenience: run a shell command asynchronously.
    pub async fn run_async(
        self: &Arc<Self>,
        command: &str,
        max_time: i32,
        lifecycle: i32,
    ) -> Result<AppRun> {
        let app = Application::builder("_run_cmd_")
            .command(command)
            .shell(true)
            .build();
        self.run_app_async(&app, max_time, lifecycle).await
    }

    /// Wait for an async run to complete, optionally printing incremental stdout.
    ///
    /// On success, this method makes a best-effort attempt to delete the temporary run app.
    pub async fn wait_for_async_run(
        &self,
        run: &AppRun,
        timeout: i32,
        print_stdout: bool,
    ) -> Result<Option<i32>> {
        let mut last_output_position = 0i64;
        let start_time = std::time::Instant::now();

        loop {
            let app_out = self
                .get_app_output(&run.app_name, last_output_position, 0, 10240, Some(&run.proc_uid), Some(1))
                .await?;

            last_output_position = app_out.output_position;

            if print_stdout && !app_out.output.is_empty() {
                print!("{}", app_out.output);
                use std::io::Write;
                std::io::stdout().flush().ok();
            }

            if app_out.exit_code.is_some()
                || app_out.status_code != StatusCode::OK.as_u16()
                || (timeout > 0 && start_time.elapsed().as_secs() >= timeout as u64)
            {
                let _ = self.delete_app(&run.app_name).await;
                return Ok(app_out.exit_code);
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// Run a task by sending JSON data to a running app and returning its response body.
    pub async fn run_task(&self, app: &str, data: Value, timeout: i32) -> Result<String> {
        let query = hmap! { HTTP_QUERY_KEY_TIMEOUT => timeout };
        let body_bytes = serde_json::to_vec(&data)?;

        let resp = self
            .req
            .send(Method::POST, &format!("/appmesh/app/{}/task", app), Some(&body_bytes), None, Some(query), true)
            .await?;
        Ok(resp.text()?)
    }

    /// Cancel a running task.
    pub async fn cancel_task(&self, app: &str) -> Result<bool> {
        let resp =
            self.req.send(Method::DELETE, &format!("/appmesh/app/{}/task", app), None, None, None, false).await?;
        Ok(resp.status() == StatusCode::OK)
    }
}

// -- System Management ------------------------------------------------------

impl AppMeshClient {
    pub async fn get_host_resources(&self) -> Result<Value> {
        let resp = self.req.send(Method::GET, "/appmesh/resources", None, None, None, true).await?;
        Ok(resp.json()?)
    }

    pub async fn get_config(&self) -> Result<Value> {
        let resp = self.req.send(Method::GET, "/appmesh/config", None, None, None, true).await?;
        Ok(resp.json()?)
    }

    pub async fn set_config(&self, config: Value) -> Result<Value> {
        let body_bytes = serde_json::to_vec(&config)?;
        let resp =
            self.req.send(Method::POST, "/appmesh/config", Some(&body_bytes), None, None, true).await?;
        Ok(resp.json()?)
    }

    pub async fn set_log_level(&self, level: &str) -> Result<String> {
        let cfg = json!({ JSON_KEY_BASE_CONFIG: { JSON_KEY_LOG_LEVEL: level } });
        let resp = self.set_config(cfg).await?;
        Ok(resp[JSON_KEY_BASE_CONFIG][JSON_KEY_LOG_LEVEL].as_str().unwrap_or(level).to_string())
    }

    pub async fn get_metrics(&self) -> Result<String> {
        let resp = self.req.send(Method::GET, "/appmesh/metrics", None, None, None, true).await?;
        Ok(resp.text()?)
    }
}

// -- Label Management -------------------------------------------------------

impl AppMeshClient {
    pub async fn list_labels(&self) -> Result<Value> {
        let resp = self.req.send(Method::GET, "/appmesh/labels", None, None, None, true).await?;
        Ok(resp.json()?)
    }


    pub async fn add_label(&self, label: &str, value: &str) -> Result<()> {
        let query = hmap! { HTTP_QUERY_KEY_VALUE => value };
        self.req.send(Method::PUT, &format!("/appmesh/label/{}", label), None, None, Some(query), true).await?;
        Ok(())
    }


    pub async fn delete_label(&self, label: &str) -> Result<()> {
        self.req.send(Method::DELETE, &format!("/appmesh/label/{}", label), None, None, None, true).await?;
        Ok(())
    }

}

// -- File Management --------------------------------------------------------

impl AppMeshClient {
    /// Download a file from the remote server.
    ///
    /// When `preserve_permissions` is true, POSIX mode/owner/group metadata from response headers
    /// is applied locally on a best-effort basis.
    pub async fn download_file(
        &self,
        remote_file: &str,
        local_file: &str,
        preserve_permissions: bool,
    ) -> Result<()> {
        let headers = hmap! { HTTP_HEADER_KEY_X_FILE_PATH => remote_file };

        let resp =
            self.req.send(Method::GET, "/appmesh/file/download", None, Some(headers), None, true).await?;

        let local_path = Path::new(local_file);
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
    pub async fn upload_file(
        &self,
        local_file: &str,
        remote_file: &str,
        preserve_permissions: bool,
    ) -> Result<()> {
        let local_path = Path::new(local_file);
        if !local_path.exists() {
            return Err(AppMeshError::NotFound(format!("Local file not found: {}", local_file)));
        }

        let file_content = fs::read(local_file)?;
        let file_name = local_path.file_name().and_then(|n| n.to_str()).unwrap_or("file");

        let mut headers = hmap! {
            HTTP_HEADER_KEY_X_FILE_PATH => remote_file,
            HTTP_HEADER_CONTENT_TYPE => "application/octet-stream",
            HTTP_HEADER_KEY_X_FILE_NAME => file_name,
        };
        if preserve_permissions {
            Self::get_file_attributes(local_path, &mut headers);
        }

        self.req
            .send(Method::POST, "/appmesh/file/upload", Some(&file_content), Some(headers), None, true)
            .await?;
        Ok(())
    }

    /// Apply file attributes (mode, owner, group) from HTTP headers — Unix only.
    pub(crate) fn apply_file_attributes(
        local_file: &Path,
        headers: &http::HeaderMap,
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
    pub(crate) fn get_file_attributes(local_file: &Path, headers: &mut HashMap<String, String>) {
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

        let exp = AppMeshClient::decode_jwt_exp(&token);
        assert_eq!(exp, Some(1700000000));
    }

    #[test]
    fn test_decode_jwt_exp_missing() {
        let payload = serde_json::json!({"sub": "admin"});
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(b"{\"alg\":\"HS256\"}");
        let token = format!("{}.{}.fake_sig", header_b64, payload_b64);

        assert_eq!(AppMeshClient::decode_jwt_exp(&token), None);
    }

    #[test]
    fn test_decode_jwt_exp_invalid_token() {
        assert_eq!(AppMeshClient::decode_jwt_exp("not-a-jwt"), None);
        assert_eq!(AppMeshClient::decode_jwt_exp("a.b"), None);
        assert_eq!(AppMeshClient::decode_jwt_exp(""), None);
    }
}
