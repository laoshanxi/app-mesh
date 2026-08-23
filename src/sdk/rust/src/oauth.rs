//! Standards-based OAuth 2.0 and OpenID Connect support.
//!
//! Authentication and token lifecycle operations go directly to the authentication service. App Mesh is a
//! resource server: callers install only the resulting access token on an App Mesh
//! client and never send refresh tokens, authorization codes, or credentials to the
//! Engine.

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::StatusCode;
use ring::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as AsyncMutex;
use url::Url;
use uuid::Uuid;

use crate::client_http::AppMeshClient;
use crate::error::AppMeshError;

type Result<T> = std::result::Result<T, AppMeshError>;

pub const DEFAULT_OAUTH_SCOPES: &[&str] =
    &["openid", "profile", "email", "groups", "offline_access"];
pub const DEFAULT_OAUTH_SCOPE: &str = "openid profile email groups offline_access";

const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const DEFAULT_DEVICE_EXPIRES_IN: u64 = 600;
const DEFAULT_DEVICE_INTERVAL: u64 = 5;
const DEFAULT_REFRESH_LEEWAY: u64 = 60;

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn default_device_expires_in() -> u64 {
    DEFAULT_DEVICE_EXPIRES_IN
}

fn default_device_interval() -> u64 {
    DEFAULT_DEVICE_INTERVAL
}

/// Canonical issuer and the independently selected network route used by this
/// process to reach it. `issuer` is an identity and must exactly match discovery;
/// `access_url` is routing only and never changes token `iss` validation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthConfig {
    pub issuer: String,
    pub access_url: String,
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

/// Compatibility alias for SDK 3.0 applications.
#[doc(hidden)]
pub type DexOAuthConfig = OAuthConfig;

impl OAuthConfig {
    pub fn new(
        issuer: impl Into<String>,
        access_url: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            access_url: access_url.into(),
            client_id: client_id.into(),
            audience: None,
            scopes: DEFAULT_OAUTH_SCOPES.iter().map(|scope| (*scope).to_string()).collect(),
        }
    }

    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    pub fn scopes(mut self, scopes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    fn validate_and_normalize(mut self) -> Result<Self> {
        self.issuer = normalize_base_url(&self.issuer, "issuer")?;
        self.access_url = normalize_base_url(&self.access_url, "access_url")?;
        if self.client_id.trim().is_empty() {
            return Err(AppMeshError::ConfigurationError("OAuth client_id is required".into()));
        }
        self.client_id = self.client_id.trim().to_string();
        if self.scopes.is_empty() {
            self.scopes = DEFAULT_OAUTH_SCOPES.iter().map(|scope| (*scope).to_string()).collect();
        }
        Ok(self)
    }
}

/// Subset of OIDC discovery metadata used by App Mesh clients.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct JsonWebKeySet {
    keys: Vec<JsonWebKey>,
}

#[derive(Debug, Clone, Deserialize)]
struct JsonWebKey {
    #[serde(default)]
    kid: String,
    #[serde(default)]
    kty: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    key_use: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

/// Persistable OAuth token set. It intentionally excludes ID tokens: App Mesh APIs
/// accept access tokens only, and the CLI has no reason to retain an ID token after
/// validating the authorization response nonce.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenSet {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default = "default_bearer_token_type")]
    pub token_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

fn default_bearer_token_type() -> String {
    "Bearer".into()
}

impl TokenSet {
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now_epoch_seconds())
    }

    pub fn needs_refresh(&self, leeway: Duration) -> bool {
        self.expires_at
            .is_some_and(|expires_at| expires_at <= now_epoch_seconds().saturating_add(leeway.as_secs()))
    }

    fn from_response(value: &Value, previous_refresh_token: Option<String>) -> Result<Self> {
        let access_token = value
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| {
                AppMeshError::AuthenticationFailed(
                    "The token response did not include an access_token".into(),
                )
            })?
            .to_string();
        let token_type = value
            .get("token_type")
            .and_then(Value::as_str)
            .unwrap_or("Bearer")
            .to_string();
        if !token_type.eq_ignore_ascii_case("bearer") {
            return Err(AppMeshError::AuthenticationFailed(format!(
                "The authentication service returned unsupported token type '{}'",
                token_type
            )));
        }
        let refresh_token = value
            .get("refresh_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .map(str::to_string)
            .or(previous_refresh_token);
        let expires_at = value
            .get("expires_in")
            .and_then(Value::as_u64)
            .map(|seconds| now_epoch_seconds().saturating_add(seconds));
        let scope = value.get("scope").and_then(Value::as_str).map(str::to_string);
        Ok(Self { access_token, refresh_token, expires_at, token_type, scope })
    }
}

/// Authorization URL plus the private values needed to validate and exchange its
/// loopback callback. Callers must keep this value out of logs and persistent state.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    pub authorization_url: String,
    pub redirect_uri: String,
    pub state: String,
    pub nonce: String,
    code_verifier: String,
}

/// Device authorization response (RFC 8628 section 3.2).
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceAuthorization {
    pub device_code: String,
    pub user_code: String,
    #[serde(default)]
    pub verification_uri: Option<String>,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    #[serde(default = "default_device_expires_in")]
    pub expires_in: u64,
    #[serde(default = "default_device_interval")]
    pub interval: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevicePoll {
    Pending,
    SlowDown,
    Token(TokenSet),
}

/// Common SDK token-source contract. Provider implementations own refresh/revocation;
/// Engine clients consume only the returned access token.
#[async_trait]
pub trait TokenProvider: Send + Sync {
    async fn access_token(&self) -> Result<String>;
    async fn force_refresh(&self) -> Result<TokenSet>;
    async fn revoke(&self) -> Result<bool>;
    fn snapshot(&self) -> Option<TokenSet>;
}

/// Provider for externally managed access tokens. It never attempts refresh or
/// revocation because it has no grant credentials or refresh token.
#[derive(Debug, Clone)]
pub struct StaticAccessTokenProvider {
    token: String,
}

impl StaticAccessTokenProvider {
    pub fn new(token: impl Into<String>) -> Result<Self> {
        let token = token.into();
        if token.trim().is_empty() {
            return Err(AppMeshError::ConfigurationError("access token is empty".into()));
        }
        Ok(Self { token })
    }
}

#[async_trait]
impl TokenProvider for StaticAccessTokenProvider {
    async fn access_token(&self) -> Result<String> {
        Ok(self.token.clone())
    }

    async fn force_refresh(&self) -> Result<TokenSet> {
        Err(AppMeshError::AuthenticationFailed(
            "static access tokens cannot be refreshed".into(),
        ))
    }

    async fn revoke(&self) -> Result<bool> {
        Ok(false)
    }

    fn snapshot(&self) -> Option<TokenSet> {
        Some(TokenSet {
            access_token: self.token.clone(),
            refresh_token: None,
            expires_at: None,
            token_type: default_bearer_token_type(),
            scope: None,
        })
    }
}

/// Discovered OAuth client and refresh-capable token provider.
pub struct OAuthClient {
    config: OAuthConfig,
    metadata: OidcMetadata,
    http: reqwest::Client,
    tokens: Mutex<Option<TokenSet>>,
    jwks: Mutex<JsonWebKeySet>,
    refresh_lock: AsyncMutex<()>,
    token_update_callback: Mutex<Option<Arc<TokenUpdateCallback>>>,
    token_update_pending: AtomicBool,
}

/// Compatibility alias for SDK 3.0 applications.
#[doc(hidden)]
pub type DexOAuthClient = OAuthClient;

type TokenUpdateCallback =
    dyn Fn(&TokenSet) -> std::result::Result<(), AppMeshError> + Send + Sync;

impl std::fmt::Debug for OAuthClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthClient")
            .field("issuer", &self.config.issuer)
            .field("access_url", &self.config.access_url)
            .field("client_id", &self.config.client_id)
            .field("audience", &self.config.audience)
            .finish_non_exhaustive()
    }
}

impl OAuthClient {
    /// Discover the authentication service with system trust roots and a bounded HTTP timeout.
    pub async fn discover(config: OAuthConfig) -> Result<Self> {
        crate::tls_config::ensure_crypto_provider();
        let http = reqwest::Client::builder().timeout(Duration::from_secs(60)).build()?;
        Self::with_http_client(config, http).await
    }

    /// Discover the authentication service using a caller-provided HTTP client. This is the supported hook
    /// for private CAs, proxies, and application-specific timeouts.
    pub async fn with_http_client(config: OAuthConfig, http: reqwest::Client) -> Result<Self> {
        let config = config.validate_and_normalize()?;
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            config.access_url.trim_end_matches('/')
        );
        let response = http.get(discovery_url).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(oauth_http_error("Authentication service discovery", status, &response.bytes().await?));
        }
        let metadata: OidcMetadata = response.json().await?;
        // Normalize both sides so an issuer that publishes "https://host/"
        // matches the configured value "https://host".
        if metadata.issuer.trim_end_matches('/') != config.issuer {
            return Err(AppMeshError::AuthenticationFailed(
                "The discovered issuer does not match the configured issuer".into(),
            ));
        }
        validate_published_endpoint(&config, &metadata.authorization_endpoint)?;
        validate_published_endpoint(&config, &metadata.token_endpoint)?;
        validate_published_endpoint(&config, &metadata.jwks_uri)?;
        for endpoint in [
            metadata.device_authorization_endpoint.as_deref(),
            metadata.revocation_endpoint.as_deref(),
            metadata.userinfo_endpoint.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_published_endpoint(&config, endpoint)?;
        }
        Ok(Self {
            config,
            metadata,
            http,
            tokens: Mutex::new(None),
            jwks: Mutex::new(JsonWebKeySet { keys: Vec::new() }),
            refresh_lock: AsyncMutex::new(()),
            token_update_callback: Mutex::new(None),
            token_update_pending: AtomicBool::new(false),
        })
    }

    pub fn config(&self) -> &OAuthConfig {
        &self.config
    }

    pub fn metadata(&self) -> &OidcMetadata {
        &self.metadata
    }

    pub fn restore(&self, tokens: TokenSet) -> Result<()> {
        if tokens.access_token.trim().is_empty() {
            return Err(AppMeshError::ConfigurationError("stored access token is empty".into()));
        }
        *self.lock_tokens() = Some(tokens);
        self.token_update_pending.store(false, Ordering::Release);
        Ok(())
    }

    pub fn clear(&self) {
        *self.lock_tokens() = None;
    }

    /// Register application-owned persistence for rotated token sets. The SDK calls
    /// this synchronously after every successful token response; applications
    /// remain responsible for choosing and securing their storage.
    pub fn set_token_update_callback<F>(&self, callback: F)
    where
        F: Fn(&TokenSet) -> std::result::Result<(), AppMeshError> + Send + Sync + 'static,
    {
        *self
            .token_update_callback
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(Arc::new(callback));
    }

    pub fn authorization_request(&self, redirect_uri: &str) -> Result<AuthorizationRequest> {
        let redirect = Url::parse(redirect_uri).map_err(|error| {
            AppMeshError::ConfigurationError(format!("invalid OAuth redirect URI: {}", error))
        })?;
        if redirect.scheme() != "http"
            || !redirect.host_str().is_some_and(is_loopback_host)
            || !redirect.username().is_empty()
            || redirect.password().is_some()
            || redirect.fragment().is_some()
        {
            return Err(AppMeshError::ConfigurationError(
                "native OAuth redirect URI must use HTTP on a loopback address".into(),
            ));
        }

        let code_verifier = random_urlsafe(4);
        let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        let state = random_urlsafe(2);
        let nonce = random_urlsafe(2);
        let scope = self.user_scope();
        // Authorization is a front-channel navigation. Preserve the canonical URL
        // published by the issuer; access_url is only for SDK back-channel HTTP requests.
        let mut authorization_url = Url::parse(&self.metadata.authorization_endpoint)?;
        authorization_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &scope)
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(AuthorizationRequest {
            authorization_url: authorization_url.to_string(),
            redirect_uri: redirect_uri.to_string(),
            state,
            nonce,
            code_verifier,
        })
    }

    pub async fn exchange_authorization_code(
        &self,
        code: &str,
        request: &AuthorizationRequest,
    ) -> Result<TokenSet> {
        if code.trim().is_empty() {
            return Err(AppMeshError::AuthenticationFailed("authorization code is empty".into()));
        }
        let response = self
            .post_form(
                &self.metadata.token_endpoint,
                &[
                    ("grant_type", "authorization_code"),
                    ("client_id", &self.config.client_id),
                    ("code", code),
                    ("redirect_uri", &request.redirect_uri),
                    ("code_verifier", &request.code_verifier),
                ],
            )
            .await?;
        self.validate_id_token(&response, &request.nonce).await?;
        self.install_response(response, None)
    }

    pub async fn request_device_authorization(&self) -> Result<DeviceAuthorization> {
        let endpoint = self.metadata.device_authorization_endpoint.as_deref().ok_or_else(|| {
            AppMeshError::UnsupportedFeature {
                feature: "OAuth device authorization".into(),
                transport: "authentication service discovery metadata".into(),
            }
        })?;
        let scope = self.user_scope();
        let response = self
            .post_form(endpoint, &[("client_id", &self.config.client_id), ("scope", &scope)])
            .await?;
        let mut device: DeviceAuthorization = serde_json::from_value(response)?;
        let verification_uri = device
            .verification_uri
            .as_deref()
            .filter(|uri| !uri.is_empty())
            .ok_or_else(|| {
                AppMeshError::AuthenticationFailed(
                    "The device response did not include a verification_uri".into(),
                )
            })?;
        validate_published_endpoint(&self.config, verification_uri)?;
        if let Some(uri) = device.verification_uri_complete.as_deref() {
            validate_published_endpoint(&self.config, uri)?;
        }
        if device.device_code.is_empty() || device.user_code.is_empty() {
            return Err(AppMeshError::AuthenticationFailed(
                "The authentication service returned an incomplete device authorization response".into(),
            ));
        }
        device.interval = device.interval.max(1);
        Ok(device)
    }

    pub async fn poll_device_token(&self, device: &DeviceAuthorization) -> Result<DevicePoll> {
        let endpoint = self.access_endpoint(&self.metadata.token_endpoint)?;
        let request = self.http.post(endpoint).form(&[
            ("grant_type", DEVICE_CODE_GRANT_TYPE),
            ("device_code", device.device_code.as_str()),
            ("client_id", self.config.client_id.as_str()),
        ]);
        let response = request.send().await?;
        let status = response.status();
        let body = response.bytes().await?;
        if status.is_success() {
            let value: Value = serde_json::from_slice(&body)?;
            return Ok(DevicePoll::Token(self.install_response(value, None)?));
        }
        let (code, description) = oauth_error(&body);
        match code.as_str() {
            "authorization_pending" => Ok(DevicePoll::Pending),
            "slow_down" => Ok(DevicePoll::SlowDown),
            _ => Err(AppMeshError::AuthenticationFailed(oauth_error_message(
                &code,
                description.as_deref(),
            ))),
        }
    }

    pub async fn wait_for_device_authorization(
        &self,
        device: &DeviceAuthorization,
    ) -> Result<TokenSet> {
        let mut interval = device.interval.max(1);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(device.expires_in);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(AppMeshError::AuthenticationFailed(
                    "device authorization expired before approval".into(),
                ));
            }
            tokio::time::sleep(Duration::from_secs(interval).min(remaining)).await;
            match self.poll_device_token(device).await? {
                DevicePoll::Token(tokens) => return Ok(tokens),
                DevicePoll::Pending => {}
                DevicePoll::SlowDown => interval = interval.saturating_add(5),
            }
        }
    }

    /// Exchange a built-in username and password directly at the authentication service. The
    /// credential is borrowed only for the request and is never sent to an App
    /// Mesh Engine. Deployments must expose this only with a controlled local
    /// password source. External identities use PKCE or device authorization.
    pub async fn password_login(&self, username: &str, password: &str) -> Result<TokenSet> {
        if username.trim().is_empty() || password.is_empty() {
            return Err(AppMeshError::AuthenticationFailed(
                "A username and password are required".into(),
            ));
        }
        let scope = self.user_scope();
        let endpoint = self.access_endpoint(&self.metadata.token_endpoint)?;
        let response = self
            .http
            .post(endpoint)
            // A public native client authenticates with an empty secret.
            .basic_auth(self.config.client_id.as_str(), Some(""))
            .form(&[
                ("grant_type", "password"),
                ("username", username.trim()),
                ("password", password),
                ("scope", scope.as_str()),
            ])
            .send()
            .await?;
        let status = response.status();
        let body = response.bytes().await?;
        if !status.is_success() {
            return Err(oauth_http_error("Password login", status, &body));
        }
        let response: Value = serde_json::from_slice(&body)?;
        self.install_response(response, None)
    }

    pub async fn refresh(&self) -> Result<TokenSet> {
        let _guard = self.refresh_lock.lock().await;
        let previous = self.snapshot_tokens().ok_or_else(|| {
            AppMeshError::AuthenticationFailed("no token set is available".into())
        })?;
        let refresh_token = previous.refresh_token.clone().ok_or_else(|| {
            AppMeshError::AuthenticationFailed("no refresh token is available".into())
        })?;
        let response = self
            .post_form(
                &self.metadata.token_endpoint,
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh_token.as_str()),
                    ("client_id", self.config.client_id.as_str()),
                ],
            )
            .await?;
        self.install_response(response, Some(refresh_token))
    }

    /// Revoke refresh and access tokens directly at the authentication service. Returns `false` when it does
    /// not advertise RFC 7009 revocation or when no token set is held (in both cases
    /// nothing was revoked). Provider-local state is cleared on every path,
    /// including unsupported revocation and network failure.
    pub async fn revoke_tokens(&self) -> Result<bool> {
        let result = async {
            let Some(endpoint) = self.metadata.revocation_endpoint.as_deref() else {
                return Ok(false);
            };
            let Some(tokens) = self.snapshot_tokens() else {
                return Ok(false);
            };
            for (token, hint) in [
                (tokens.refresh_token.as_deref(), "refresh_token"),
                (Some(tokens.access_token.as_str()), "access_token"),
            ] {
                let Some(token) = token else { continue };
                let endpoint = self.access_endpoint(endpoint)?;
                let request = self.http.post(endpoint).form(&[
                    ("token", token),
                    ("token_type_hint", hint),
                    ("client_id", self.config.client_id.as_str()),
                ]);
                let response = request.send().await?;
                if !response.status().is_success() {
                    let status = response.status();
                    return Err(oauth_http_error("Token revocation", status, &response.bytes().await?));
                }
            }
            Ok(true)
        }
        .await;
        self.clear();
        result
    }

    pub async fn userinfo(&self) -> Result<Value> {
        let endpoint = self.metadata.userinfo_endpoint.as_deref().ok_or_else(|| {
            AppMeshError::UnsupportedFeature {
                feature: "OIDC userinfo".into(),
                transport: "authentication service discovery metadata".into(),
            }
        })?;
        let token = <Self as TokenProvider>::access_token(self).await?;
        let response = self.http.get(self.access_endpoint(endpoint)?).bearer_auth(token).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(oauth_http_error("User information request", status, &response.bytes().await?));
        }
        Ok(response.json().await?)
    }

    /// Install only the current access token on an Engine client. Refresh tokens stay
    /// exclusively inside this provider (and, if the application chooses, its secure
    /// persistence layer).
    pub async fn install_on(&self, client: &Arc<AppMeshClient>) -> Result<String> {
        let access_token = <Self as TokenProvider>::access_token(self).await?;
        client.set_token(&access_token);
        Ok(access_token)
    }

    fn lock_tokens(&self) -> std::sync::MutexGuard<'_, Option<TokenSet>> {
        self.tokens.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn lock_jwks(&self) -> std::sync::MutexGuard<'_, JsonWebKeySet> {
        self.jwks.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn snapshot_tokens(&self) -> Option<TokenSet> {
        self.lock_tokens().clone()
    }

    /// Install a fresh token response. The token set is stored in memory first,
    /// then the application persistence callback (if any) runs. When that callback
    /// fails, `Err` is returned even though login itself already succeeded: the new
    /// tokens are active in memory, and `token_update_pending` stays set so the next
    /// `access_token()` call retries the persistence.
    fn install_response(
        &self,
        response: Value,
        previous_refresh_token: Option<String>,
    ) -> Result<TokenSet> {
        let tokens = TokenSet::from_response(&response, previous_refresh_token)?;
        *self.lock_tokens() = Some(tokens.clone());
        self.token_update_pending.store(true, Ordering::Release);
        self.persist_token_update(&tokens)?;
        Ok(tokens)
    }

    fn persist_token_update(&self, tokens: &TokenSet) -> Result<()> {
        let callback = self
            .token_update_callback
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        if let Some(callback) = callback {
            callback(tokens)?;
        }
        self.token_update_pending.store(false, Ordering::Release);
        Ok(())
    }

    fn user_scope(&self) -> String {
        let mut scopes = self.config.scopes.clone();
        if !scopes.iter().any(|scope| scope == "openid") {
            scopes.insert(0, "openid".into());
        }
        if let Some(audience) = self.config.audience.as_deref() {
            let scope = format!("audience:server:client_id:{}", audience);
            if !scopes.contains(&scope) {
                scopes.push(scope);
            }
        }
        scopes.sort();
        scopes.dedup();
        scopes.join(" ")
    }

    fn access_endpoint(&self, published: &str) -> Result<String> {
        validate_published_endpoint(&self.config, published)?;
        let published = Url::parse(published)?;
        let issuer = Url::parse(&self.config.issuer)?;
        let mut access = Url::parse(&self.config.access_url)?;
        let issuer_path = issuer.path().trim_end_matches('/');
        let suffix = published.path().strip_prefix(issuer_path).ok_or_else(|| {
            AppMeshError::AuthenticationFailed("The endpoint is outside the configured issuer path".into())
        })?;
        let access_path = access.path().trim_end_matches('/');
        access.set_path(&format!("{}{}", access_path, suffix));
        access.set_query(published.query());
        access.set_fragment(None);
        Ok(access.to_string())
    }

    async fn fetch_jwks(&self) -> Result<JsonWebKeySet> {
        let response = self.http.get(self.access_endpoint(&self.metadata.jwks_uri)?).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(oauth_http_error("Signing-key request", status, &response.bytes().await?));
        }
        let jwks: JsonWebKeySet = response.json().await?;
        if jwks.keys.is_empty() {
            return Err(AppMeshError::AuthenticationFailed("The signing-key set contains no keys".into()));
        }
        Ok(jwks)
    }

    async fn validate_id_token(&self, response: &Value, expected_nonce: &str) -> Result<()> {
        let id_token = response.get("id_token").and_then(Value::as_str).ok_or_else(|| {
            AppMeshError::AuthenticationFailed(
                "The authorization response did not include an ID token".into(),
            )
        })?;
        let (header, claims, signing_input, signature) = decode_jwt(id_token)?;
        if header.alg != "RS256" || header.kid.is_empty() {
            return Err(AppMeshError::AuthenticationFailed(
                "The ID token must use RS256 with a kid".into(),
            ));
        }

        let mut jwk = self.find_signing_key(&header.kid);
        if jwk.is_none() {
            let refreshed = self.fetch_jwks().await?;
            *self.lock_jwks() = refreshed;
            jwk = self.find_signing_key(&header.kid);
        }
        let jwk = jwk.ok_or_else(|| {
            AppMeshError::AuthenticationFailed("The ID token kid is not present in the signing-key set".into())
        })?;
        if jwk.kty != "RSA"
            || jwk.alg.as_deref().is_some_and(|alg| alg != "RS256")
            || jwk.key_use.as_deref().is_some_and(|key_use| key_use != "sig")
        {
            return Err(AppMeshError::AuthenticationFailed(
                "The selected key is not an RS256 signing key".into(),
            ));
        }
        let modulus = URL_SAFE_NO_PAD.decode(
            jwk.n
                .as_deref()
                .ok_or_else(|| {
                    AppMeshError::AuthenticationFailed("The RSA signing key has no modulus".into())
                })?
                .as_bytes(),
        )?;
        let exponent = URL_SAFE_NO_PAD.decode(
            jwk.e
                .as_deref()
                .ok_or_else(|| {
                    AppMeshError::AuthenticationFailed("The RSA signing key has no exponent".into())
                })?
                .as_bytes(),
        )?;
        RsaPublicKeyComponents { n: &modulus, e: &exponent }
            .verify(&RSA_PKCS1_2048_8192_SHA256, signing_input.as_bytes(), &signature)
            .map_err(|_| AppMeshError::AuthenticationFailed("The ID token signature is invalid".into()))?;
        validate_id_token_claims(&claims, &self.config, expected_nonce)
    }

    fn find_signing_key(&self, kid: &str) -> Option<JsonWebKey> {
        self.lock_jwks().keys.iter().find(|key| key.kid == kid).cloned()
    }

    async fn post_form(&self, published_endpoint: &str, form: &[(&str, &str)]) -> Result<Value> {
        let endpoint = self.access_endpoint(published_endpoint)?;
        let request = self.http.post(endpoint).form(form);
        let response = request.send().await?;
        let status = response.status();
        let body = response.bytes().await?;
        if !status.is_success() {
            return Err(oauth_http_error("OAuth request", status, &body));
        }
        Ok(serde_json::from_slice(&body)?)
    }
}

#[async_trait]
impl TokenProvider for OAuthClient {
    async fn access_token(&self) -> Result<String> {
        let tokens = self.snapshot_tokens().ok_or_else(|| {
            AppMeshError::AuthenticationFailed("no token set is available".into())
        })?;
        if self.token_update_pending.load(Ordering::Acquire) {
            self.persist_token_update(&tokens)?;
        }
        if tokens.needs_refresh(Duration::from_secs(DEFAULT_REFRESH_LEEWAY)) {
            if tokens.refresh_token.is_some() {
                return Ok(self.refresh().await?.access_token);
            }
            if tokens.is_expired() {
                return Err(AppMeshError::AuthenticationFailed(
                    "The access token expired and no refresh token is available".into(),
                ));
            }
        }
        Ok(tokens.access_token)
    }

    async fn force_refresh(&self) -> Result<TokenSet> {
        if self.snapshot_tokens().and_then(|tokens| tokens.refresh_token).is_some() {
            self.refresh().await
        } else {
            Err(AppMeshError::AuthenticationFailed(
                "the token provider has no refresh grant".into(),
            ))
        }
    }

    async fn revoke(&self) -> Result<bool> {
        self.revoke_tokens().await
    }

    fn snapshot(&self) -> Option<TokenSet> {
        self.snapshot_tokens()
    }
}

fn normalize_base_url(value: &str, field: &str) -> Result<String> {
    let value = value.trim().trim_end_matches('/');
    let parsed = Url::parse(value).map_err(|error| {
        AppMeshError::ConfigurationError(format!("invalid {} URL: {}", field, error))
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(AppMeshError::ConfigurationError(format!(
            "{} must be an absolute HTTP(S) URL without credentials, query, or fragment",
            field
        )));
    }
    if parsed.scheme() == "http" && !parsed.host_str().is_some_and(is_loopback_host) {
        return Err(AppMeshError::ConfigurationError(format!(
            "{} must use HTTPS unless it targets loopback",
            field
        )));
    }
    Ok(value.to_string())
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<std::net::IpAddr>().is_ok_and(|address| address.is_loopback())
}

fn validate_published_endpoint(config: &OAuthConfig, endpoint: &str) -> Result<()> {
    let endpoint = Url::parse(endpoint).map_err(|error| {
        AppMeshError::AuthenticationFailed(format!("The authentication service published an invalid endpoint: {}", error))
    })?;
    let issuer = Url::parse(&config.issuer)?;
    if endpoint.scheme() != issuer.scheme()
        || endpoint.host_str() != issuer.host_str()
        || endpoint.port_or_known_default() != issuer.port_or_known_default()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(AppMeshError::AuthenticationFailed(
            "The authentication service published an endpoint outside the configured issuer origin".into(),
        ));
    }
    let issuer_path = issuer.path().trim_end_matches('/');
    if !issuer_path.is_empty()
        && endpoint.path() != issuer_path
        && !endpoint.path().starts_with(&format!("{}/", issuer_path))
    {
        return Err(AppMeshError::AuthenticationFailed(
            "The authentication service published an endpoint outside the configured issuer path".into(),
        ));
    }
    Ok(())
}

fn random_urlsafe(uuid_count: usize) -> String {
    (0..uuid_count).map(|_| Uuid::new_v4().simple().to_string()).collect()
}

fn oauth_error(body: &[u8]) -> (String, Option<String>) {
    let value = serde_json::from_slice::<Value>(body).unwrap_or(Value::Null);
    let code = value
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("oauth_request_failed")
        .to_string();
    let description = value
        .get("error_description")
        .and_then(Value::as_str)
        .map(|description| sanitize_oauth_text(description, 512));
    (code, description)
}

fn sanitize_oauth_text(value: &str, limit: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control() || *character == ' ')
        .take(limit)
        .collect()
}

fn oauth_error_message(code: &str, description: Option<&str>) -> String {
    match description {
        Some(description) if !description.is_empty() => format!("{}: {}", code, description),
        _ => code.to_string(),
    }
}

fn oauth_http_error(operation: &str, status: StatusCode, body: &[u8]) -> AppMeshError {
    let (code, description) = oauth_error(body);
    AppMeshError::RequestFailed {
        status,
        message: format!("{} failed: {}", operation, oauth_error_message(&code, description.as_deref())),
    }
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    kid: String,
}

fn decode_jwt(token: &str) -> Result<(JwtHeader, Value, String, Vec<u8>)> {
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(AppMeshError::AuthenticationFailed(
            "The authentication service returned a malformed ID token".into(),
        ));
    }
    let header: JwtHeader = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
    let signature = URL_SAFE_NO_PAD.decode(parts[2])?;
    Ok((header, claims, format!("{}.{}", parts[0], parts[1]), signature))
}

/// Validate the claims in an ID token whose RS256 signature was already verified
/// against the issuer's discovered JWKS. The ID token is never retained or sent to
/// App Mesh.
fn validate_id_token_claims(
    claims: &Value,
    config: &OAuthConfig,
    expected_nonce: &str,
) -> Result<()> {
    if claims.get("nonce").and_then(Value::as_str) != Some(expected_nonce) {
        return Err(AppMeshError::AuthenticationFailed("ID token nonce mismatch".into()));
    }
    if claims.get("iss").and_then(Value::as_str) != Some(config.issuer.as_str()) {
        return Err(AppMeshError::AuthenticationFailed("ID token issuer mismatch".into()));
    }
    let audience_matches = match claims.get("aud") {
        Some(Value::String(audience)) => audience == &config.client_id,
        Some(Value::Array(audiences)) => audiences.iter().any(|audience| audience.as_str() == Some(&config.client_id)),
        _ => false,
    };
    if !audience_matches {
        return Err(AppMeshError::AuthenticationFailed("ID token audience mismatch".into()));
    }
    if let Some(Value::Array(audiences)) = claims.get("aud") {
        if audiences.len() > 1
            && claims.get("azp").and_then(Value::as_str) != Some(config.client_id.as_str())
        {
            return Err(AppMeshError::AuthenticationFailed(
                "ID token authorized-party mismatch".into(),
            ));
        }
    }
    let expiry = claims.get("exp").and_then(Value::as_u64).ok_or_else(|| {
        AppMeshError::AuthenticationFailed("ID token has no valid expiration".into())
    })?;
    if expiry <= now_epoch_seconds() {
        return Err(AppMeshError::AuthenticationFailed("ID token is expired".into()));
    }
    if claims
        .get("nbf")
        .and_then(Value::as_u64)
        .is_some_and(|not_before| not_before > now_epoch_seconds())
    {
        return Err(AppMeshError::AuthenticationFailed(
            "ID token is not valid yet".into(),
        ));
    }
    Ok(())
}
