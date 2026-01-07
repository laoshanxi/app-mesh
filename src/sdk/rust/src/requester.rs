// requester.rs

use crate::error::AppMeshError;
use async_trait::async_trait;
use bytes::Bytes;
use reqwest::Method;
use std::any::Any;
use std::collections::HashMap;

type Result<T> = std::result::Result<T, AppMeshError>;

/// Trait for different request implementations (HTTP, TCP, etc.)
#[async_trait]
pub trait Requester: Send + Sync {
    /// Execute an HTTP request
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        headers: Option<HashMap<String, String>>,
        query: Option<HashMap<String, String>>,
        fail_on_error: bool,
    ) -> Result<http::Response<Bytes>>;

    /// Downcast to concrete type for type-specific operations
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Handle token updates (called after successful authentication)
    fn handle_token_update(&self, token: Option<String>);

    /// Set the forward_to URL (TCP implementation should ignore this (no-op))
    fn set_forward_to(&mut self, url: Option<String>) {}

    /// Close the requester (if applicable)
    fn close(&self) {}
}
