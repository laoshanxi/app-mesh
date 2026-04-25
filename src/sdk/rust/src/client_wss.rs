// client_wss.rs

use crate::client_http::AppMeshClient;
use crate::constants::*;
use crate::error::AppMeshError;
use crate::models::*;
use crate::requester::Requester;
use crate::subscribe::{MessageDemuxer, MessageReader};
use crate::tcp_messages::{RequestMessage, ResponseMessage};
use crate::tls_config::{ClientCert, SslVerify};
use crate::wss_transport::WSSTransport;

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::{Method, StatusCode};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Adapts the async `WSSTransport` to the `MessageReader` trait.
///
/// Each `read_message` call acquires the tokio mutex, reads one message, and
/// releases the lock.
struct WSSMessageReader {
    transport: Arc<Mutex<WSSTransport>>,
}

#[async_trait]
impl MessageReader for WSSMessageReader {
    async fn read_message(&self) -> Result<Option<Vec<u8>>, AppMeshError> {
        let mut t = self.transport.lock().await;
        t.receive_message().await
    }
}

/// WSS-based requester implementation.
///
/// Uses `tokio::sync::watch` for token updates so that `handle_token_update`
/// (called from a synchronous trait method) never silently drops a token.
pub struct WSSRequester {
    transport: Arc<Mutex<WSSTransport>>,
    token: Arc<std::sync::RwLock<Option<String>>>,
    demuxer: std::sync::Mutex<Option<Arc<MessageDemuxer>>>,
}

impl WSSRequester {
    pub fn new(
        address: Option<(String, u16)>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Self, AppMeshError> {
        let address = address.unwrap_or_else(|| (DEFAULT_TCP_HOST.to_string(), DEFAULT_WSS_PORT));
        let ssl_verify_str = ssl_verify.unwrap_or_else(|| DEFAULT_SSL_CA_CERT_PATH.to_string());
        let verify = if ssl_verify_str.is_empty() { SslVerify::False } else { SslVerify::Path(ssl_verify_str) };
        let client_cert = ssl_client_cert.map(|(cert, key)| ClientCert::Pair(cert, key));

        let transport = WSSTransport::new(address, verify, client_cert);

        Ok(Self {
            transport: Arc::new(Mutex::new(transport)),
            token: Arc::new(std::sync::RwLock::new(None)),
            demuxer: std::sync::Mutex::new(None),
        })
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
        // Build and send the request message.
        let req_uuid;
        let req_headers;
        {
            let mut transport = self.transport.lock().await;

            if !transport.connected() {
                transport.connect().await?;
            }

            let mut req = RequestMessage::new();
            req.uuid = Uuid::new_v4().to_string();
            req.http_method = method.to_string();
            req.request_uri = path.to_string();
            req.client_addr = "wss-client".to_string();
            req.headers.insert(HTTP_HEADER_KEY_USER_AGENT.into(), HTTP_USER_AGENT_WSS.into());

            if let Some(token) = self.token.read().expect("token lock poisoned").clone() {
                req.headers.insert(HTTP_HEADER_JWT_AUTHORIZATION.into(), token);
            }

            // Save headers ref before consuming for token sync
            req_headers = headers.clone();
            if let Some(h) = headers {
                req.headers.extend(h);
            }
            if let Some(q) = query {
                req.query.extend(q);
            }
            if let Some(b) = body {
                req.body = b.to_vec();
            }

            req_uuid = req.uuid.clone();
            let data = req.serialize().map_err(|e| AppMeshError::SerializationError(e.to_string()))?;
            transport.send_message(&data).await?;
        }
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
                self.read_response_direct().await?
            }
        } else {
            self.read_response_direct().await?
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
        let mut guard = self.token.write().expect("token lock poisoned");
        *guard = token;
    }

    fn get_access_token(&self) -> Option<String> {
        self.token.read().expect("token lock poisoned").clone()
    }

    fn close(&self) {
        // Stop the demuxer first
        if let Ok(guard) = self.demuxer.lock() {
            if let Some(ref d) = *guard {
                d.stop();
            }
        }
        let transport = self.transport.clone();
        tokio::spawn(async move {
            let mut t = transport.lock().await;
            t.close().await;
        });
    }

    fn enable_demuxer(&self) {
        let mut guard = self.demuxer.lock().expect("demuxer lock poisoned");
        if guard.is_some() {
            return; // already enabled
        }
        let demuxer = Arc::new(MessageDemuxer::new());
        let reader = Arc::new(WSSMessageReader {
            transport: Arc::clone(&self.transport),
        });
        demuxer.start(reader);
        *guard = Some(demuxer);
    }

    fn get_demuxer(&self) -> Option<Arc<MessageDemuxer>> {
        self.demuxer.lock().ok().and_then(|g| g.clone())
    }
}

impl WSSRequester {
    /// Direct (legacy) read path: lock the transport and read one response.
    async fn read_response_direct(&self) -> Result<ResponseMessage, AppMeshError> {
        let mut transport = self.transport.lock().await;

        let resp_data = match transport.receive_message().await? {
            Some(data) if !data.is_empty() => data,
            _ => {
                transport.close().await;
                return Err(AppMeshError::ConnectionError("WebSocket connection broken".into()));
            }
        };

        ResponseMessage::deserialize(&resp_data)
            .map_err(|e| AppMeshError::SerializationError(e.to_string()))
    }
}

/// WSS-based AppMesh client.
///
/// Control messages go over WebSocket; file transfers use an HTTPS side-channel.
pub struct AppMeshClientWSS {
    client: Arc<AppMeshClient>,
    http_client: reqwest::Client,
    base_url: String,
}

impl AppMeshClientWSS {
    /// Create a WSS transport client. Defaults to `127.0.0.1:6058`.
    pub fn new(
        address: Option<(String, u16)>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Arc<Self>, AppMeshError> {
        let address_val = address.clone().unwrap_or_else(|| (DEFAULT_TCP_HOST.to_string(), DEFAULT_WSS_PORT));

        let wss_requester = WSSRequester::new(address, ssl_verify.clone(), ssl_client_cert.clone())?;

        let base_url = format!("https://{}:{}", address_val.0, address_val.1);
        let client = AppMeshClient::with_requester(Box::new(wss_requester), base_url.clone());

        // Build HTTP client with matching SSL settings for the file-transfer side-channel
        let mut client_builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120));

        let ssl_verify_path = ssl_verify.unwrap_or_else(|| DEFAULT_SSL_CA_CERT_PATH.to_string());
        if ssl_verify_path.is_empty() {
            client_builder = client_builder.danger_accept_invalid_certs(true);
        } else {
            let mut buf = Vec::new();
            File::open(&ssl_verify_path)
                .and_then(|mut f| f.read_to_end(&mut buf))
                .map_err(|e| AppMeshError::IoError(e.to_string()))?;
            let cert = reqwest::Certificate::from_pem(&buf)
                .map_err(|e| AppMeshError::SerializationError(format!("Invalid CA Cert: {}", e)))?;
            client_builder = client_builder.add_root_certificate(cert);
        }

        if let Some((cert_path, key_path)) = ssl_client_cert {
            let mut cert_buf = Vec::new();
            let mut key_buf = Vec::new();
            File::open(&cert_path).and_then(|mut f| f.read_to_end(&mut cert_buf)).ok();
            File::open(&key_path).and_then(|mut f| f.read_to_end(&mut key_buf)).ok();
            let mut combined = cert_buf;
            combined.extend_from_slice(b"\n");
            combined.extend_from_slice(&key_buf);
            if let Ok(identity) = reqwest::Identity::from_pem(&combined) {
                client_builder = client_builder.identity(identity);
            }
        }

        let http_client = client_builder
            .build()
            .map_err(|e| AppMeshError::ConnectionError(format!("Failed to build HTTP client: {}", e)))?;

        Ok(Arc::new(Self { client, http_client, base_url }))
    }

    /// Get the underlying generic client for shared auth/app/task APIs.
    pub fn client(&self) -> &Arc<AppMeshClient> {
        &self.client
    }

    /// Download a file using WSS control messages plus an HTTPS data side channel.
    ///
    /// When `preserve_permissions` is true, returned POSIX metadata is applied locally best-effort.
    pub async fn download_file(
        &self,
        remote_file: &str,
        local_file: &str,
        preserve_permissions: bool,
    ) -> Result<(), AppMeshError> {
        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_KEY_X_FILE_PATH.into(), remote_file.to_string());

        let resp = self
            .client
            .raw_request(Method::GET, "/appmesh/file/download", None, Some(headers), None, true)
            .await?;

        let auth_token = resp
            .headers()
            .get(HTTP_HEADER_JWT_AUTHORIZATION)
            .ok_or_else(|| AppMeshError::RequestFailed {
                status: StatusCode::UNAUTHORIZED,
                message: "Server did not respond with file transfer authentication".into(),
            })?
            .to_str()
            .unwrap_or_default()
            .to_string();

        let url = format!("{}/appmesh/file/download/ws", self.base_url);
        let mut response = self
            .http_client
            .get(&url)
            .header(HTTP_HEADER_KEY_X_FILE_PATH, remote_file)
            .header(HTTP_HEADER_JWT_AUTHORIZATION, &auth_token)
            .send()
            .await
            .map_err(|e| AppMeshError::RequestFailed {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: e.to_string(),
            })?;

        if !response.status().is_success() {
            return Err(AppMeshError::RequestFailed {
                status: response.status(),
                message: "Download request failed".into(),
            });
        }

        let local_path = Path::new(local_file);
        let mut file = File::create(local_path)?;
        while let Some(chunk) = response.chunk().await.map_err(|e| AppMeshError::ConnectionError(e.to_string()))? {
            file.write_all(&chunk)?;
        }
        file.flush()?;

        if preserve_permissions {
            let _ = AppMeshClient::apply_file_attributes(local_path, resp.headers());
        }
        Ok(())
    }

    /// Upload a file using WSS control messages plus an HTTPS data side channel.
    ///
    /// When `preserve_permissions` is true, local POSIX metadata is sent so the server can
    /// recreate permissions/ownership when supported.
    pub async fn upload_file(
        &self,
        local_file: &str,
        remote_file: &str,
        preserve_permissions: bool,
    ) -> Result<(), AppMeshError> {
        let local_path = Path::new(local_file);
        if !local_path.exists() {
            return Err(AppMeshError::FileNotFound(local_file.to_string()));
        }

        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_KEY_X_FILE_PATH.into(), remote_file.to_string());

        let resp = self
            .client
            .raw_request(Method::POST, "/appmesh/file/upload", None, Some(headers), None, true)
            .await?;

        let auth_token = resp
            .headers()
            .get(HTTP_HEADER_JWT_AUTHORIZATION)
            .ok_or_else(|| AppMeshError::RequestFailed {
                status: StatusCode::UNAUTHORIZED,
                message: "Server did not respond with file transfer authentication".into(),
            })?
            .to_str()
            .unwrap_or_default()
            .to_string();

        let mut upload_headers = reqwest::header::HeaderMap::new();
        upload_headers.insert(
            reqwest::header::HeaderName::from_static("authorization"),
            auth_token.parse().unwrap(),
        );
        upload_headers.insert(
            reqwest::header::HeaderName::from_bytes(HTTP_HEADER_KEY_X_FILE_PATH.as_bytes()).unwrap(),
            remote_file.parse().unwrap(),
        );

        if preserve_permissions {
            let mut attr_headers = HashMap::new();
            AppMeshClient::get_file_attributes(local_path, &mut attr_headers);
            for (k, v) in attr_headers {
                if let Ok(hname) = reqwest::header::HeaderName::from_bytes(k.as_bytes()) {
                    if let Ok(hval) = reqwest::header::HeaderValue::from_str(&v) {
                        upload_headers.insert(hname, hval);
                    }
                }
            }
        }

        let file_content = std::fs::read(local_path)?;
        let url = format!("{}/appmesh/file/upload/ws", self.base_url);

        let response = self
            .http_client
            .post(&url)
            .headers(upload_headers)
            .body(file_content)
            .send()
            .await
            .map_err(|e| AppMeshError::RequestFailed {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: e.to_string(),
            })?;

        if !response.status().is_success() {
            return Err(AppMeshError::RequestFailed {
                status: response.status(),
                message: "Upload request failed".into(),
            });
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
    ) -> Result<AppRun, AppMeshError> {
        self.client.run_app_async(app, max_time, lifecycle).await
    }
}

impl std::ops::Deref for AppMeshClientWSS {
    type Target = AppMeshClient;
    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl Drop for AppMeshClientWSS {
    fn drop(&mut self) {
        self.close();
    }
}
