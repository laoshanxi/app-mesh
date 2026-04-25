// client_tcp.rs

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::{Method, StatusCode};
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
use crate::subscribe::{MessageDemuxer, MessageReader};
use crate::tcp_messages::{RequestMessage, ResponseMessage};
use crate::tcp_transport::TCPTransport;
use crate::tls_config::{ClientCert, SslVerify};

pub type Result<T> = std::result::Result<T, AppMeshError>;

/// Adapts the synchronous `TCPTransport` to the async `MessageReader` trait.
///
/// Each `read_message` call acquires the lock, reads one framed message, and
/// releases the lock so other operations (send) can proceed.
struct TCPMessageReader {
    transport: Arc<Mutex<TCPTransport>>,
}

#[async_trait]
impl MessageReader for TCPMessageReader {
    async fn read_message(&self) -> Result<Option<Vec<u8>>> {
        // Offload the blocking TLS read to a thread-pool thread so we do not
        // block the tokio runtime.
        let transport = Arc::clone(&self.transport);
        tokio::task::spawn_blocking(move || {
            let mut t = transport.lock().map_err(|e| AppMeshError::ConnectionError(e.to_string()))?;
            t.receive_message().map_err(AppMeshError::from)
        })
        .await
        .map_err(|e| AppMeshError::ConnectionError(format!("reader task panicked: {}", e)))?
    }
}

/// TCP-based requester implementation
pub struct TCPRequester {
    tcp_transport: Arc<Mutex<TCPTransport>>,
    token: Arc<Mutex<Option<String>>>,
    demuxer: Mutex<Option<Arc<MessageDemuxer>>>,
}

impl TCPRequester {
    #[allow(dead_code)]
    pub fn new(
        tcp_address: Option<(String, u16)>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Self> {
        let tcp_address =
            tcp_address.unwrap_or_else(|| (DEFAULT_TCP_HOST.to_string(), DEFAULT_TCP_PORT));
        let ssl_verify_str = ssl_verify.unwrap_or_else(|| DEFAULT_SSL_CA_CERT_PATH.to_string());
        let verify = if ssl_verify_str.is_empty() { SslVerify::False } else { SslVerify::Path(ssl_verify_str) };
        let client_cert = ssl_client_cert.map(|(cert, key)| ClientCert::Pair(cert, key));

        let tcp_transport = TCPTransport::new(tcp_address, verify, client_cert);

        Ok(Self {
            tcp_transport: Arc::new(Mutex::new(tcp_transport)),
            token: Arc::new(Mutex::new(None)),
            demuxer: Mutex::new(None),
        })
    }

    /// Create TCPRequester with shared transport (used internally by AppMeshClientTCP)
    pub fn with_shared_transport(tcp_transport: Arc<Mutex<TCPTransport>>) -> Self {
        Self {
            tcp_transport,
            token: Arc::new(Mutex::new(None)),
            demuxer: Mutex::new(None),
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

        for (k, v) in &resp.headers {
            builder = builder.header(k, v);
        }
        if !resp.body_msg_type.is_empty() && !resp.headers.contains_key(HTTP_HEADER_CONTENT_TYPE) {
            builder = builder.header(HTTP_HEADER_CONTENT_TYPE, &resp.body_msg_type);
        }

        Ok(builder.body(Bytes::from(resp.body)).expect("Building http::Response should not fail"))
    }

    /// Direct (legacy) read path: lock the transport and read one response.
    fn read_response_direct(&self) -> Result<ResponseMessage> {
        let mut transport =
            self.tcp_transport.lock().map_err(|e| AppMeshError::ConnectionError(e.to_string()))?;

        let resp_data = match transport.receive_message()? {
            Some(data) if !data.is_empty() => data,
            _ => {
                transport.close();
                return Err(AppMeshError::ConnectionError("Socket connection broken".into()));
            }
        };

        ResponseMessage::deserialize(&resp_data)
            .map_err(|e| AppMeshError::SerializationError(e.to_string()))
    }
}

#[async_trait]
impl Requester for TCPRequester {
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        headers: Option<HashMap<String, String>>,
        query: Option<HashMap<String, String>>,
        fail_on_error: bool,
    ) -> Result<http::Response<Bytes>> {
        // Build the request message and send it while holding the transport lock.
        let (req_uuid, req_headers) = {
            let mut transport =
                self.tcp_transport.lock().map_err(|e| AppMeshError::ConnectionError(e.to_string()))?;

            if !transport.connected() {
                transport.connect()?; // TransportError → AppMeshError via From
            }

            let mut req = RequestMessage::new();
            req.uuid = Uuid::new_v4().to_string();
            req.http_method = method.to_string();
            req.request_uri = path.to_string();
            req.client_addr =
                hostname::get().ok().and_then(|h| h.into_string().ok()).unwrap_or_else(|| "unknown".into());
            req.headers.insert(HTTP_HEADER_KEY_USER_AGENT.into(), HTTP_USER_AGENT_TCP.into());

            if let Some(token) = self.get_access_token() {
                req.headers.insert(HTTP_HEADER_JWT_AUTHORIZATION.into(), token);
            }
            // Save headers ref before consuming for token sync
            let req_headers = headers.clone();
            if let Some(h) = headers {
                req.headers.extend(h);
            }
            if let Some(q) = query {
                req.query.extend(q);
            }
            if let Some(b) = body {
                req.body = b.to_vec();
            }

            let uuid = req.uuid.clone();
            let data = req.serialize().map_err(|e| AppMeshError::SerializationError(e.to_string()))?;
            transport.send_message(&data)?;

            (uuid, req_headers)
        };
        // Transport lock released here.

        // Check if demuxer is active — if so, route through channel-based response.
        let demuxer_opt = {
            self.demuxer.lock().map_err(|e| AppMeshError::ConnectionError(e.to_string()))?.clone()
        };

        let resp = if let Some(ref demuxer) = demuxer_opt {
            if demuxer.is_running() {
                let rx = demuxer.register_request(&req_uuid).await;
                match rx.await {
                    Ok(resp) => resp,
                    Err(_) => {
                        return Err(AppMeshError::ConnectionError(
                            "Connection closed while waiting for response".into(),
                        ));
                    }
                }
            } else {
                self.read_response_direct()?
            }
        } else {
            self.read_response_direct()?
        };

        let status = StatusCode::from_u16(resp.http_status as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        if fail_on_error && status != StatusCode::PRECONDITION_REQUIRED && !status.is_success() {
            return Err(AppMeshError::RequestFailed {
                status,
                message: String::from_utf8_lossy(&resp.body).to_string(),
            });
        }

        let http_resp = Self::to_http_response(resp)?;

        // Auto-sync token from auth endpoint responses
        crate::requester::sync_transport_token(&http_resp, path, &req_headers, self);

        Ok(http_resp)
    }

    fn handle_token_update(&self, token: Option<String>) {
        self.set_token(token);
    }

    fn get_access_token(&self) -> Option<String> {
        self.token.lock().ok().and_then(|t| t.clone())
    }

    fn close(&self) {
        // Stop the demuxer first
        if let Ok(guard) = self.demuxer.lock() {
            if let Some(ref d) = *guard {
                d.stop();
            }
        }
        if let Ok(mut t) = self.tcp_transport.lock() {
            t.close();
        }
    }

    fn enable_demuxer(&self) {
        let mut guard = self.demuxer.lock().expect("demuxer lock poisoned");
        if guard.is_some() {
            return; // already enabled
        }
        let demuxer = Arc::new(MessageDemuxer::new());
        let reader = Arc::new(TCPMessageReader {
            transport: Arc::clone(&self.tcp_transport),
        });
        demuxer.start(reader);
        *guard = Some(demuxer);
    }

    fn get_demuxer(&self) -> Option<Arc<MessageDemuxer>> {
        self.demuxer.lock().ok().and_then(|g| g.clone())
    }
}

/// TCP-based AppMesh client.
///
/// This transport reuses the standard [`AppMeshClient`] API for control requests and switches to
/// raw TCP streaming only for large file transfer payloads.
pub struct AppMeshClientTCP {
    client: Arc<AppMeshClient>,
    tcp_transport: Arc<Mutex<TCPTransport>>,
}

impl AppMeshClientTCP {
    /// Create a TCP transport client. Defaults to `127.0.0.1:6059`.
    pub fn new(
        tcp_address: Option<(String, u16)>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Arc<Self>> {
        let tcp_address =
            tcp_address.unwrap_or_else(|| (DEFAULT_TCP_HOST.to_string(), DEFAULT_TCP_PORT));
        let ssl_verify_path = ssl_verify.unwrap_or_else(|| DEFAULT_SSL_CA_CERT_PATH.to_string());
        let verify = if ssl_verify_path.is_empty() { SslVerify::False } else { SslVerify::Path(ssl_verify_path) };
        let client_cert = ssl_client_cert.map(|(cert, key)| ClientCert::Pair(cert, key));

        let tcp_transport = Arc::new(Mutex::new(TCPTransport::new(tcp_address.clone(), verify, client_cert)));
        let tcp_requester = TCPRequester::with_shared_transport(Arc::clone(&tcp_transport));
        let url = format!("tcp://{}:{}", tcp_address.0, tcp_address.1);
        let client = AppMeshClient::with_requester(Box::new(tcp_requester), url);

        Ok(Arc::new(Self { client, tcp_transport }))
    }

    /// Get the underlying generic client for shared auth/app/task APIs.
    pub fn client(&self) -> &Arc<AppMeshClient> {
        &self.client
    }

    /// Download a file using the TCP file-socket side channel.
    ///
    /// When `preserve_permissions` is true, returned POSIX metadata is applied locally best-effort.
    pub async fn download_file(
        &self,
        remote_file: &str,
        local_file: &str,
        preserve_permissions: bool,
    ) -> Result<()> {
        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_KEY_X_FILE_PATH.into(), remote_file.to_string());
        headers.insert(HTTP_HEADER_KEY_X_RECV_FILE_SOCKET.into(), "true".into());

        let resp = self
            .client
            .raw_request(Method::GET, "/appmesh/file/download", None, Some(headers), None, true)
            .await?;

        if !resp.headers().contains_key(HTTP_HEADER_KEY_X_RECV_FILE_SOCKET) {
            return Err(AppMeshError::RequestFailed {
                status: resp.status(),
                message: format!("Server did not respond with socket transfer option: {}", HTTP_HEADER_KEY_X_RECV_FILE_SOCKET),
            });
        }

        let local_path = Path::new(local_file);
        let mut file = File::create(local_path)?;

        let mut transport =
            self.tcp_transport.lock().map_err(|e| AppMeshError::ConnectionError(e.to_string()))?;

        loop {
            match transport.receive_message()? {
                Some(data) if data.is_empty() => break, // EOF signal
                Some(data) => file.write_all(&data)?,
                None => break,
            }
        }
        file.flush()?;

        if preserve_permissions {
            let _ = AppMeshClient::apply_file_attributes(local_path, resp.headers());
        }
        Ok(())
    }

    /// Upload a file using the TCP file-socket side channel.
    ///
    /// When `preserve_permissions` is true, local POSIX metadata is sent so the server can
    /// recreate permissions/ownership when supported.
    pub async fn upload_file(
        &self,
        local_file: &str,
        remote_file: &str,
        preserve_permissions: bool,
    ) -> Result<()> {
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

        let resp = self
            .client
            .raw_request(Method::POST, "/appmesh/file/upload", None, Some(headers), None, true)
            .await?;

        if !resp.headers().contains_key(HTTP_HEADER_KEY_X_SEND_FILE_SOCKET) {
            return Err(AppMeshError::RequestFailed {
                status: resp.status(),
                message: format!("Server did not respond with socket transfer option: {}", HTTP_HEADER_KEY_X_SEND_FILE_SOCKET),
            });
        }

        let mut file = File::open(local_path)?;
        let mut buffer = vec![0u8; TCP_BLOCK_SIZE];

        let mut transport =
            self.tcp_transport.lock().map_err(|e| AppMeshError::ConnectionError(e.to_string()))?;

        loop {
            match file.read(&mut buffer)? {
                0 => {
                    transport.send_message(&[])?;
                    break;
                }
                n => {
                    transport.send_message(&buffer[..n])?;
                }
            }
        }
        Ok(())
    }

    /// Run an application asynchronously and return the standard [`AppRun`] handle.
    ///
    /// This method exists explicitly because the `&Arc<Self>` receiver cannot be delegated through
    /// `Deref`.
    pub async fn run_app_async(
        self: &Arc<Self>,
        app: &Application,
        max_time: i32,
        lifecycle: i32,
    ) -> Result<AppRun> {
        self.client.run_app_async(app, max_time, lifecycle).await
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
