// client_tcp.rs

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::{Method, StatusCode};
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::client_http::AppMeshClient;
use crate::constants::*;
use crate::error::AppMeshError;
use crate::models::*;
use crate::requester::Requester;
use crate::tcp_messages::{RequestMessage, ResponseMessage};
use crate::tcp_transport::{ClientCert, SslVerify, TCPTransport};

const TCP_BLOCK_SIZE: usize = 16 * 1024 - 128;
const HTTP_USER_AGENT_TCP: &str = "appmesh/rust/tcp";
const HTTP_HEADER_KEY_X_SEND_FILE_SOCKET: &str = "X-Send-File-Socket";
const HTTP_HEADER_KEY_X_RECV_FILE_SOCKET: &str = "X-Recv-File-Socket";
const HTTP_HEADER_KEY_USER_AGENT: &str = "User-Agent";
const HTTP_HEADER_KEY_AUTH: &str = "Authorization";
const HTTP_HEADER_KEY_X_FILE_PATH: &str = "X-File-Path";

pub type Result<T> = std::result::Result<T, AppMeshError>;

/// TCP-based requester implementation
pub struct RequesterTcp {
    tcp_transport: Arc<Mutex<TCPTransport>>,
    token: Arc<Mutex<Option<String>>>,
}

impl RequesterTcp {
    pub fn new(
        tcp_address: Option<(String, u16)>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Self> {
        let tcp_address = tcp_address.unwrap_or_else(|| (DEFAULT_TCP_URL.0.to_string(), DEFAULT_TCP_URL.1));
        // Convert SSL verify option
        let ssl_verify = ssl_verify.unwrap_or_else(|| DEFAULT_SSL_CA_CERT_PATH.to_string());
        let verify = if ssl_verify.is_empty() { SslVerify::True } else { SslVerify::Path(ssl_verify) };

        // Convert client certificate
        let ssl_client_cert = ssl_client_cert.map(|(cert, key)| ClientCert::Pair(cert, key));
        let tcp_transport = TCPTransport::new(tcp_address, verify, ssl_client_cert);

        Ok(Self { tcp_transport: Arc::new(Mutex::new(tcp_transport)), token: Arc::new(Mutex::new(None)) })
    }

    /// Create TcpRequester with shared transport (used internally by AppMeshClientTCP)
    pub fn with_shared_transport(tcp_transport: Arc<Mutex<TCPTransport>>) -> Self {
        Self { tcp_transport, token: Arc::new(Mutex::new(None)) }
    }

    pub fn close(&self) {
        if let Ok(mut transport) = self.tcp_transport.lock() {
            transport.close();
        }
    }

    pub fn set_token(&self, token: Option<String>) {
        if let Ok(mut t) = self.token.lock() {
            *t = token;
        }
    }

    pub fn get_access_token(&self) -> Option<String> {
        self.token.lock().ok().and_then(|t| t.clone())
    }

    /// Convert internal TCP `ResponseMessage` into an `http::Response`
    fn to_http_response(resp: ResponseMessage) -> Result<http::Response<Bytes>> {
        let mut builder = http::Response::builder().status(resp.http_status as u16);

        // Copy headers from response
        for (k, v) in &resp.headers {
            builder = builder.header(k, v);
        }

        // Set Content-Type from body_msg_type if available and not already set
        if !resp.body_msg_type.is_empty() && !resp.headers.contains_key(HTTP_HEADER_CONTENT_TYPE) {
            builder = builder.header(HTTP_HEADER_CONTENT_TYPE, &resp.body_msg_type);
        }

        Ok(builder.body(Bytes::from(resp.body)).expect("Building http::Response should not fail"))
    }
}

#[async_trait]
impl Requester for RequesterTcp {
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        headers: Option<HashMap<String, String>>,
        query: Option<HashMap<String, String>>,
        fail_on_error: bool,
    ) -> Result<http::Response<Bytes>> {
        let mut transport = self.tcp_transport.lock().map_err(|e| AppMeshError::ConnectionError(e.to_string()))?;

        if !transport.connected() {
            transport.connect().map_err(|e| AppMeshError::ConnectionError(e.to_string()))?;
        }

        let mut req = RequestMessage::new();
        req.uuid = Uuid::new_v4().to_string();
        req.http_method = method.to_string();
        req.request_uri = path.to_string();
        req.client_addr = hostname::get().ok().and_then(|h| h.into_string().ok()).unwrap_or_else(|| "unknown".into());
        req.headers.insert(HTTP_HEADER_KEY_USER_AGENT.into(), HTTP_USER_AGENT_TCP.into());

        if let Some(token) = self.get_access_token() {
            req.headers.insert(HTTP_HEADER_KEY_AUTH.into(), token);
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

        let data = req.serialize().map_err(|e| AppMeshError::SerializationError(e.to_string()))?;
        transport.send_message(&data).map_err(|e| AppMeshError::ConnectionError(e.to_string()))?;

        // Receive response with proper empty check
        let resp_data = match transport.receive_message().map_err(|e| AppMeshError::ConnectionError(e.to_string()))? {
            Some(data) if !data.is_empty() => data,
            _ => {
                // Close connection on empty or None response
                transport.close();
                return Err(AppMeshError::ConnectionError("Socket connection broken".into()));
            }
        };

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
        // Store token for TCP authentication
        self.set_token(token);
    }
}

/// TCP-based AppMesh client
pub struct AppMeshClientTCP {
    client: Arc<AppMeshClient>,
    tcp_transport: Arc<Mutex<TCPTransport>>,
}

impl AppMeshClientTCP {
    /// Create new TCP client with optional SSL parameters
    pub fn new(
        tcp_address: Option<(String, u16)>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Arc<Self>> {
        let tcp_address = tcp_address.unwrap_or_else(|| (DEFAULT_TCP_URL.0.to_string(), DEFAULT_TCP_URL.1));

        // Convert SSL verify option
        let ssl_verify_path = ssl_verify.unwrap_or_else(|| DEFAULT_SSL_CA_CERT_PATH.to_string());
        let verify = if ssl_verify_path.is_empty() { SslVerify::True } else { SslVerify::Path(ssl_verify_path) };

        // Convert client certificate
        let ssl_client_cert_pair = ssl_client_cert.map(|(cert, key)| ClientCert::Pair(cert, key));

        // Create shared transport
        let tcp_transport = Arc::new(Mutex::new(TCPTransport::new(tcp_address.clone(), verify, ssl_client_cert_pair)));

        // Create TcpRequester with shared transport
        let tcp_requester = RequesterTcp::with_shared_transport(Arc::clone(&tcp_transport));

        // Create URL for the client (used for informational purposes)
        let url = format!("tcp://{}:{}", tcp_address.0, tcp_address.1);

        // Create AppMeshClient with TCP requester
        let client = AppMeshClient::with_requester(Box::new(tcp_requester), url);

        Ok(Arc::new(Self { client, tcp_transport }))
    }

    /// Close the TCP connection
    pub fn close(&self) {
        if let Ok(mut transport) = self.tcp_transport.lock() {
            transport.close();
        }
    }

    /// Get reference to the underlying AppMeshClient
    pub fn client(&self) -> &Arc<AppMeshClient> {
        &self.client
    }

    /// Override: Download file using TCP streaming
    pub async fn download_file(&self, remote_file: &str, local_file: &str, preserve_permissions: bool) -> Result<()> {
        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_KEY_X_FILE_PATH.into(), remote_file.to_string());
        headers.insert(HTTP_HEADER_KEY_X_RECV_FILE_SOCKET.into(), "true".into());

        let resp =
            self.client.raw_request(Method::GET, "/appmesh/file/download", None, Some(headers), None, true).await?;

        // Validate server supports socket transfer
        if !resp.headers().contains_key(HTTP_HEADER_KEY_X_RECV_FILE_SOCKET) {
            return Err(AppMeshError::RequestFailed {
                status: resp.status(),
                message: format!(
                    "Server did not respond with socket transfer option: {}",
                    HTTP_HEADER_KEY_X_RECV_FILE_SOCKET
                ),
            });
        }

        let local_path = Path::new(local_file);
        let mut file = File::create(local_path)?;

        // Get the transport to receive file chunks
        let mut transport = self.tcp_transport.lock().map_err(|e| AppMeshError::ConnectionError(e.to_string()))?;

        loop {
            match transport.receive_message().map_err(|e| AppMeshError::ConnectionError(e.to_string()))? {
                Some(data) if data.is_empty() => break, // EOF signal
                Some(data) => file.write_all(&data)?,
                None => break, // Connection closed, treat as EOF
            }
        }

        file.flush()?;

        if preserve_permissions {
            AppMeshClient::apply_file_attributes(local_path, resp.headers());
        }

        Ok(())
    }

    /// Override: Upload file using TCP streaming
    pub async fn upload_file(&self, local_file: &str, remote_file: &str, preserve_permissions: bool) -> Result<()> {
        let local_path = Path::new(local_file);
        if !local_path.exists() {
            return Err(AppMeshError::FileNotFound(local_file.to_string()));
        }

        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_KEY_X_FILE_PATH.into(), remote_file.to_string());
        headers.insert(HTTP_HEADER_CONTENT_TYPE.into(), "application/octet-stream".into());
        headers.insert(HTTP_HEADER_KEY_X_SEND_FILE_SOCKET.into(), "true".into());

        if preserve_permissions {
            AppMeshClient::get_file_attributes(local_path, &mut headers);
        }

        let resp =
            self.client.raw_request(Method::POST, "/appmesh/file/upload", None, Some(headers), None, true).await?;

        // Validate server supports socket transfer
        if !resp.headers().contains_key(HTTP_HEADER_KEY_X_SEND_FILE_SOCKET) {
            return Err(AppMeshError::RequestFailed {
                status: resp.status(),
                message: format!(
                    "Server did not respond with socket transfer option: {}",
                    HTTP_HEADER_KEY_X_SEND_FILE_SOCKET
                ),
            });
        }

        let mut file = File::open(local_path)?;
        let mut buffer = vec![0u8; TCP_BLOCK_SIZE];

        // Get the transport to send file chunks
        let mut transport = self.tcp_transport.lock().map_err(|e| AppMeshError::ConnectionError(e.to_string()))?;

        loop {
            match file.read(&mut buffer)? {
                0 => {
                    // EOF - send empty message to signal completion
                    transport.send_message(&[]).map_err(|e| AppMeshError::ConnectionError(e.to_string()))?;
                    break;
                }
                n => {
                    transport.send_message(&buffer[..n]).map_err(|e| AppMeshError::ConnectionError(e.to_string()))?;
                }
            }
        }

        Ok(())
    }

    /// Override: Run application asynchronously
    ///
    /// IMPORTANT: This method must be explicitly implemented because it has a special
    /// receiver type `self: &Arc<Self>` which cannot be automatically delegated through Deref.
    pub async fn run_app_async(self: &Arc<Self>, app: Value, max_timeout: i32, lifecycle: i32) -> Result<AppRun> {
        // Delegate to the inner client
        self.client.run_app_async(app, max_timeout, lifecycle).await
    }
}

impl std::ops::Deref for AppMeshClientTCP {
    type Target = AppMeshClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl Drop for AppMeshClientTCP {
    fn drop(&mut self) {
        self.close();
    }
}
