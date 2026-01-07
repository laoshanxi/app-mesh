// client_wss.rs

use crate::client_http::AppMeshClient;
use crate::constants::*;
use crate::error::AppMeshError;
use crate::models::*;
use crate::requester::Requester;
use crate::tcp_messages::{RequestMessage, ResponseMessage};
use crate::tcp_transport::{ClientCert, SslVerify};
use crate::wss_transport::WSSTransport;

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::{Method, StatusCode};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

const HTTP_USER_AGENT_WSS: &str = "appmesh/rust/wss";

/// WSS-based requester implementation
pub struct WSSRequester {
    transport: Arc<Mutex<WSSTransport>>,
    token: Arc<Mutex<Option<String>>>,
}

impl WSSRequester {
    pub fn new(
        address: Option<(String, u16)>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Self, AppMeshError> {
        let address = address.unwrap_or_else(|| (DEFAULT_TCP_URL.0.to_string(), 6058)); // Default WSS port

        // Convert SSL verify option
        let ssl_verify = ssl_verify.unwrap_or_else(|| DEFAULT_SSL_CA_CERT_PATH.to_string());
        let verify = if ssl_verify.is_empty() { SslVerify::True } else { SslVerify::Path(ssl_verify) };

        // Convert client certificate
        let ssl_client_cert = ssl_client_cert.map(|(cert, key)| ClientCert::Pair(cert, key));

        let transport = WSSTransport::new(address, verify, ssl_client_cert);

        Ok(Self { transport: Arc::new(Mutex::new(transport)), token: Arc::new(Mutex::new(None)) })
    }

    fn to_http_response(resp: ResponseMessage) -> Result<http::Response<Bytes>, AppMeshError> {
        let mut builder = http::Response::builder().status(resp.http_status as u16);

        for (k, v) in &resp.headers {
            builder = builder.header(k, v);
        }

        if !resp.body_msg_type.is_empty() && !resp.headers.contains_key(HTTP_HEADER_CONTENT_TYPE) {
            builder = builder.header(HTTP_HEADER_CONTENT_TYPE, &resp.body_msg_type);
        }

        Ok(builder.body(Bytes::from(resp.body)).expect("Building http::Response should not fail"))
    }
}

#[async_trait]
impl Requester for WSSRequester {
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        headers: Option<HashMap<String, String>>,
        query: Option<HashMap<String, String>>,
        fail_on_error: bool,
    ) -> Result<http::Response<Bytes>, AppMeshError> {
        let mut transport = self.transport.lock().await;

        if !transport.connected() {
            transport.connect().await?;
        }

        // 1. Prepare RequestMessage
        let mut req = RequestMessage::new();
        req.uuid = Uuid::new_v4().to_string();
        req.http_method = method.to_string();
        req.request_uri = path.to_string();
        req.client_addr = "wss-client".to_string(); //
        req.headers.insert(HTTP_HEADER_KEY_USER_AGENT.into(), HTTP_USER_AGENT_WSS.into());

        // Add Auth Token
        if let Some(token) = self.token.lock().await.clone() {
            req.headers.insert(HTTP_HEADER_JWT_AUTHORIZATION.into(), token);
        }

        if let Some(h) = headers {
            req.headers.extend(h);
        }
        if let Some(q) = query {
            req.query.extend(q);
        }
        if let Some(b) = body {
            req.body = b.to_vec();
        }

        // 2. Serialize and Send
        let data = req.serialize().map_err(|e| AppMeshError::SerializationError(e.to_string()))?;
        transport.send_message(&data).await?;

        // 3. Receive Response
        let resp_data = match transport.receive_message().await? {
            Some(data) if !data.is_empty() => data,
            _ => {
                transport.close().await;
                return Err(AppMeshError::ConnectionError("WebSocket connection broken".into()));
            }
        };

        // 4. Deserialize Response
        let resp =
            ResponseMessage::deserialize(&resp_data).map_err(|e| AppMeshError::SerializationError(e.to_string()))?;

        let status = StatusCode::from_u16(resp.http_status as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        if fail_on_error && status != StatusCode::PRECONDITION_REQUIRED && !status.is_success() {
            return Err(AppMeshError::RequestFailed {
                status,
                message: String::from_utf8_lossy(&resp.body).to_string(),
            });
        }

        Self::to_http_response(resp)
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn handle_token_update(&self, token: Option<String>) {
        if let Ok(mut t) = self.token.try_lock() {
            *t = token;
        }
    }
}

/// WSS-based AppMesh client
pub struct AppMeshClientWSS {
    client: Arc<AppMeshClient>,
    // Transport kept here if needed for direct access, similar to TCP client
    transport: Arc<Mutex<WSSTransport>>,
}

impl AppMeshClientWSS {
    pub fn new(
        address: Option<(String, u16)>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Arc<Self>, AppMeshError> {
        let address_val = address.clone().unwrap_or_else(|| (DEFAULT_TCP_URL.0.to_string(), 6058));

        // Create the requester
        let wss_requester = WSSRequester::new(address, ssl_verify, ssl_client_cert)?;
        let transport_ref = Arc::clone(&wss_requester.transport);

        // Create base AppMeshClient
        // Note: The Base URL is informational here, requests go through WS Requester
        let url = format!("https://{}:{}", address_val.0, address_val.1);
        let client = AppMeshClient::with_requester(Box::new(wss_requester), url);

        Ok(Arc::new(Self { client, transport: transport_ref }))
    }

    pub async fn close(&self) {
        let mut transport = self.transport.lock().await;
        transport.close().await;
    }

    /// Override: Run application asynchronously
    ///
    /// IMPORTANT: This method must be explicitly implemented because it has a special
    /// receiver type `self: &Arc<Self>` which cannot be automatically delegated through Deref.
    pub async fn run_app_async(
        self: &Arc<Self>,
        app: Value,
        max_timeout: i32,
        lifecycle: i32,
    ) -> Result<AppRun, AppMeshError> {
        // Delegate to the inner client
        self.client.run_app_async(app, max_timeout, lifecycle).await
    }
}

// Enable Deref to access AppMeshClient methods directly (e.g., login, run_app)
impl std::ops::Deref for AppMeshClientWSS {
    type Target = AppMeshClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}
