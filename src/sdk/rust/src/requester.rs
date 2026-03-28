// requester.rs

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
