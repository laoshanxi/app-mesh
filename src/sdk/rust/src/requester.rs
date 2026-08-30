// requester.rs

use crate::error::AppMeshError;
use crate::subscribe::MessageDemuxer;
use async_trait::async_trait;
use bytes::Bytes;
use reqwest::Method;
use std::collections::HashMap;
use std::sync::Arc;

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

    /// Execute a request and return the raw streaming `reqwest::Response`
    /// so large bodies can be consumed chunk-by-chunk (bounded memory).
    ///
    /// Only the HTTP transport supports this; other transports return
    /// `Ok(None)` and callers fall back to the buffered [`Requester::send`].
    async fn send_streaming(
        &self,
        _method: Method,
        _path: &str,
        _body: Option<reqwest::Body>,
        _headers: Option<HashMap<String, String>>,
        _query: Option<HashMap<String, String>>,
        _fail_on_error: bool,
    ) -> Result<Option<reqwest::Response>> {
        Ok(None)
    }

    /// Handle token updates (called after successful authentication)
    fn handle_token_update(&self, token: Option<String>);

    /// Set the forward_to URL
    fn set_forward_to(&self, _url: Option<String>) {}

    /// Close the requester (if applicable)
    fn close(&self) {}

    /// Retrieve the current access token (if stored by this transport).
    ///
    /// All transports keep the access token in memory and send it as Bearer authorization.
    fn get_access_token(&self) -> Option<String> {
        None
    }

    /// Enable the message demuxer for this transport.
    ///
    /// Only TCP and WSS transports support this; HTTP is a no-op.
    async fn enable_demuxer(&self) -> Result<()> {
        Ok(())
    }

    /// Whether this transport supports the message demuxer (TCP/WSS: `true`,
    /// HTTP: `false`); picks the subscribe-based wait over polling.
    fn supports_demuxer(&self) -> bool {
        false
    }

    /// Get the message demuxer, if enabled.
    fn get_demuxer(&self) -> Option<Arc<MessageDemuxer>> {
        None
    }
}
