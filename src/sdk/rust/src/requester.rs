// requester.rs

use crate::error::AppMeshError;
use async_trait::async_trait;
use bytes::Bytes;
use http::Response;
use reqwest::Method;
use std::collections::HashMap;

#[async_trait]
pub trait Requester: Send + Sync {
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        headers: Option<HashMap<String, String>>,
        query: Option<HashMap<String, String>>,
        fail_on_error: bool,
    ) -> Result<Response<Bytes>, AppMeshError>;

    /// Allow downcasting to concrete types (for accessing type-specific methods)
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;

    /// Optional: Set forwarding host (only implemented by HTTP requester)
    fn set_forward_to(&mut self, _url: Option<String>) {
        // Default implementation: do nothing (for HTTP)
    }

    /// Handle token update after authentication operations
    /// This is used to store/update the access token in the requester
    fn handle_token_update(&self, _token: Option<String>) {
        // Default implementation: do nothing (for HTTP, cookies are handled automatically)
    }
}
