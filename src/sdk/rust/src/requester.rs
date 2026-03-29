// requester.rs

use crate::constants::*;
use crate::error::AppMeshError;
use async_trait::async_trait;
use bytes::Bytes;
use reqwest::Method;
use std::collections::HashMap;

type Result<T> = std::result::Result<T, AppMeshError>;

/// Trait for different request implementations (HTTP, TCP, WSS)
#[async_trait]
pub trait Requester: Send + Sync {
    /// Execute an HTTP-style request over the underlying transport
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        headers: Option<HashMap<String, String>>,
        query: Option<HashMap<String, String>>,
        fail_on_error: bool,
    ) -> Result<http::Response<Bytes>>;

    /// Handle token updates (called after successful authentication)
    fn handle_token_update(&self, token: Option<String>);

    /// Set the forward_to URL (TCP/WSS implementations may ignore this)
    fn set_forward_to(&mut self, _url: Option<String>) {}

    /// Close the requester (if applicable)
    fn close(&self) {}

    /// Set a cookie value directly into the transport's cookie store.
    /// HTTP transport sets it in the cookie jar; TCP/WSS store the token in memory.
    fn set_cookie(&self, _cookie_str: &str) {}

    /// Retrieve the current access token (if stored by this transport).
    ///
    /// HTTP transport reads from the cookie jar; TCP/WSS from an in-memory field.
    fn get_access_token(&self) -> Option<String> {
        None
    }
}

/// Auth endpoints where the server returns a new access_token in the JSON body.
/// Login/auth/totp_validate: apply token only when X-Set-Cookie header is present.
const AUTH_SET_COOKIE_PATHS: &[&str] = &["/appmesh/login", "/appmesh/auth", "/appmesh/totp/validate"];
/// Renew/setup: always apply (client already has an active session).
const AUTH_RENEW_PATHS: &[&str] = &["/appmesh/token/renew", "/appmesh/totp/setup"];
const LOGOFF_PATH: &str = "/appmesh/self/logoff";

/// Extract and apply token from auth endpoint responses (TCP/WSS only).
/// HTTP transport relies on Set-Cookie for automatic cookie jar updates.
pub fn sync_transport_token(
    resp: &http::Response<Bytes>,
    path: &str,
    request_headers: &Option<HashMap<String, String>>,
    requester: &dyn Requester,
) {
    if resp.status() != http::StatusCode::OK {
        return;
    }

    if path == LOGOFF_PATH {
        requester.handle_token_update(None);
        return;
    }

    if AUTH_SET_COOKIE_PATHS.contains(&path) {
        // Apply only when client requested cookie mode
        let wants_cookie = request_headers
            .as_ref()
            .and_then(|h| h.get(HTTP_HEADER_JWT_SET_COOKIE))
            .is_some_and(|v| v == "true");
        if !wants_cookie {
            return;
        }
    } else if !AUTH_RENEW_PATHS.contains(&path) {
        return;
    }

    // Extract access_token from JSON body
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(resp.body()) {
        if let Some(token) = json.get(HTTP_BODY_KEY_ACCESS_TOKEN).and_then(|v| v.as_str()) {
            requester.handle_token_update(Some(token.to_string()));
        }
    }
}
