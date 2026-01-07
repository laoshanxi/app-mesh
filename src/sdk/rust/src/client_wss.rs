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
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

const HTTP_USER_AGENT_WSS: &str = "appmesh/rust/wss";
const HTTP_HEADER_KEY_X_FILE_PATH: &str = "X-File-Path";
const HTTP_HEADER_KEY_AUTH: &str = "Authorization";

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

    fn close(&self) {
        // Clone the arc to move it into the background task
        let transport = self.transport.clone();

        // Use tokio::spawn to bridge the Sync function signature with the Async implementation
        tokio::spawn(async move {
            let mut t = transport.lock().await;
            t.close().await;
        });
    }
}

/// WSS-based AppMesh client
pub struct AppMeshClientWSS {
    client: Arc<AppMeshClient>,
    // Internal HTTP client for side-channel file transfers (upload/download)
    http_client: reqwest::Client,
    // Base URL for HTTP side-channel requests
    base_url: String,
}

impl AppMeshClientWSS {
    pub fn new(
        address: Option<(String, u16)>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Arc<Self>, AppMeshError> {
        let address_val = address.clone().unwrap_or_else(|| (DEFAULT_TCP_URL.0.to_string(), 6058));

        // Create the requester
        let wss_requester = WSSRequester::new(address, ssl_verify.clone(), ssl_client_cert.clone())?;

        // Create base AppMeshClient
        // Note: The Base URL is informational here, requests go through WS Requester
        let base_url = format!("https://{}:{}", address_val.0, address_val.1);
        let client = AppMeshClient::with_requester(Box::new(wss_requester), base_url.clone());

        // Build a reqwest::Client that matches the SSL settings of the WS transport
        // This is needed for the upload/download "side-channel" which uses standard HTTPS
        let mut client_builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120));

        // Configure SSL Verification
        let ssl_verify_path = ssl_verify.unwrap_or_else(|| DEFAULT_SSL_CA_CERT_PATH.to_string());
        if ssl_verify_path.is_empty() {
            // True in our logic implies use system CA, which reqwest does by default.
            // If we wanted to "disable" verification (SslVerify::False), we would need a way to flag that.
            // Assuming empty string means system CA here based on other code.
        } else {
            // Load custom CA
            let mut buf = Vec::new();
            File::open(&ssl_verify_path)
                .and_then(|mut f| f.read_to_end(&mut buf))
                .map_err(|e| AppMeshError::IoError(e.to_string()))?;
            let cert = reqwest::Certificate::from_pem(&buf)
                .map_err(|e| AppMeshError::SerializationError(format!("Invalid CA Cert: {}", e)))?;
            client_builder = client_builder.add_root_certificate(cert);
        }

        // Configure Client Certificate (if provided)
        if let Some((cert_path, key_path)) = ssl_client_cert {
            // Attempt to load client cert. Note: reqwest Identity handling can vary by backend (native-tls vs rustls).
            // We read both files and attempt to create an Identity.
            // This is a best-effort implementation assuming PEM format.
            let mut cert_buf = Vec::new();
            let mut key_buf = Vec::new();

            File::open(&cert_path).and_then(|mut f| f.read_to_end(&mut cert_buf)).ok();
            File::open(&key_path).and_then(|mut f| f.read_to_end(&mut key_buf)).ok();

            // Combine them for identity parsing if needed, or parse separately.
            // Reqwest Identity::from_pem expects the PEM to contain the key as well.
            let mut combined = cert_buf;
            combined.extend_from_slice(&b"\n"[..]);
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

    /// Get reference to the underlying AppMeshClient
    pub fn client(&self) -> &Arc<AppMeshClient> {
        &self.client
    }

    /// Override: Download file using WSS protocol (WSS control + HTTPS data)
    pub async fn download_file(
        &self,
        remote_file: &str,
        local_file: &str,
        preserve_permissions: bool,
    ) -> Result<(), AppMeshError> {
        // 1. Send WSS request to prepare download and get auth token
        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_KEY_X_FILE_PATH.into(), remote_file.to_string());

        let resp =
            self.client.raw_request(Method::GET, "/appmesh/file/download", None, Some(headers), None, true).await?;

        // 2. Extract Authorization token
        let auth_token = resp
            .headers()
            .get(HTTP_HEADER_KEY_AUTH)
            .ok_or_else(|| AppMeshError::RequestFailed {
                status: StatusCode::UNAUTHORIZED,
                message: "Server did not respond with file transfer authentication".into(),
            })?
            .to_str()
            .unwrap_or_default()
            .to_string();

        // 3. Initiate HTTPS GET for the actual file data
        let url = format!("{}/appmesh/file/download/ws", self.base_url);
        let mut response = self
            .http_client
            .get(&url)
            .header(HTTP_HEADER_KEY_X_FILE_PATH, remote_file)
            .header(HTTP_HEADER_KEY_AUTH, auth_token)
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

        // 4. Stream body to local file
        let local_path = Path::new(local_file);
        let mut file = File::create(local_path).map_err(AppMeshError::from)?;

        while let Some(chunk) = response.chunk().await.map_err(|e| AppMeshError::ConnectionError(e.to_string()))? {
            file.write_all(&chunk).map_err(AppMeshError::from)?;
        }
        file.flush().map_err(AppMeshError::from)?;

        // 5. Apply file attributes if requested
        if preserve_permissions {
            AppMeshClient::apply_file_attributes(local_path, resp.headers());
        }

        Ok(())
    }

    /// Override: Upload file using WSS protocol (WSS control + HTTPS data)
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

        // 1. Send WSS request to prepare upload
        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_KEY_X_FILE_PATH.into(), remote_file.to_string());

        let resp =
            self.client.raw_request(Method::POST, "/appmesh/file/upload", None, Some(headers), None, true).await?;

        // 2. Extract Authorization token
        let auth_token = resp
            .headers()
            .get(HTTP_HEADER_KEY_AUTH)
            .ok_or_else(|| AppMeshError::RequestFailed {
                status: StatusCode::UNAUTHORIZED,
                message: "Server did not respond with file transfer authentication".into(),
            })?
            .to_str()
            .unwrap_or_default()
            .to_string();

        // 3. Prepare headers for HTTPS POST
        let mut upload_headers = reqwest::header::HeaderMap::new();
        upload_headers.insert(HTTP_HEADER_KEY_AUTH, auth_token.parse().unwrap());
        upload_headers.insert(HTTP_HEADER_KEY_X_FILE_PATH, remote_file.parse().unwrap());

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

        // 4. Read file and send via HTTPS POST
        // Note: For very large files, this reads into memory.
        // A production improvement would be to use `tokio::fs::File` and `Body::wrap_stream`.
        let file_content = std::fs::read(local_path).map_err(AppMeshError::from)?;
        let url = format!("{}/appmesh/file/upload/ws", self.base_url);

        let response =
            self.http_client.post(&url).headers(upload_headers).body(file_content).send().await.map_err(|e| {
                AppMeshError::RequestFailed { status: StatusCode::INTERNAL_SERVER_ERROR, message: e.to_string() }
            })?;

        if !response.status().is_success() {
            return Err(AppMeshError::RequestFailed {
                status: response.status(),
                message: "Upload request failed".into(),
            });
        }

        Ok(())
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
