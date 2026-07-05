// client_wss.rs

use crate::client_http::AppMeshClient;
use crate::constants::*;
use crate::error::AppMeshError;
use crate::models::*;
use crate::requester::Requester;
use crate::subscribe::{MessageDemuxer, MessageReader};
use crate::wire_messages::{RequestMessage, ResponseMessage};
use crate::tls_config::ClientCert;
use crate::wss_transport::WSSTransport;

use async_trait::async_trait;
use bytes::Bytes;
use reqwest::{Method, StatusCode};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Adapts the async `WSSTransport` to the `MessageReader` trait.
///
/// Each `read_message` call acquires the tokio mutex, reads one message, and
/// releases the lock.
struct WSSMessageReader {
    reader: Arc<Mutex<Option<crate::wss_transport::SplitStream>>>,
}

#[async_trait]
impl MessageReader for WSSMessageReader {
    async fn read_message(&self) -> Result<Option<Vec<u8>>, AppMeshError> {
        loop {
            {
                let mut guard = self.reader.lock().await;
                if let Some(stream) = guard.as_mut() {
                    return crate::wss_transport::read_one(stream).await;
                }
            }
            // Reader not yet available (connect() hasn't run); back off to avoid busy-spin
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }
}

/// WSS-based requester implementation.
///
/// Uses `tokio::sync::watch` for token updates so that `handle_token_update`
/// (called from a synchronous trait method) never silently drops a token.
pub struct WSSRequester {
    transport: Arc<Mutex<WSSTransport>>,
    reader_handle: Arc<Mutex<Option<crate::wss_transport::SplitStream>>>,
    token: Arc<std::sync::RwLock<Option<String>>>,
    forward_to: std::sync::Mutex<Option<String>>,
    demuxer: std::sync::Mutex<Option<Arc<MessageDemuxer>>>,
}

impl WSSRequester {
    pub fn new(
        address: Option<(String, u16)>,
        verify: crate::tls_config::SslVerify,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Self, AppMeshError> {
        let address = address.unwrap_or_else(|| (DEFAULT_TCP_HOST.to_string(), DEFAULT_WSS_PORT));
        let client_cert = ssl_client_cert.map(|(cert, key)| ClientCert::Pair(cert, key));

        let transport = WSSTransport::new(address, verify, client_cert);
        let reader_handle = transport.reader_handle();

        Ok(Self {
            transport: Arc::new(Mutex::new(transport)),
            reader_handle,
            token: Arc::new(std::sync::RwLock::new(None)),
            forward_to: std::sync::Mutex::new(None),
            demuxer: std::sync::Mutex::new(None),
        })
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
        let req_uuid = Uuid::new_v4().to_string();

        // Register the pending request BEFORE sending so the demuxer read loop
        // cannot drop the response before a receiver exists (Go/Java SDK ordering).
        let demuxer_opt = self.demuxer.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let active_demuxer = demuxer_opt.filter(|d| d.is_running());
        let rx = match &active_demuxer {
            Some(demuxer) => Some(demuxer.register_request(&req_uuid).await),
            None => None,
        };

        // Build and send the request message.
        let send_result: Result<Option<HashMap<String, String>>, AppMeshError> = async {
            let mut transport = self.transport.lock().await;

            if !transport.connected() {
                transport.connect().await?;
            }

            let mut req = RequestMessage::new();
            req.uuid = req_uuid.clone();
            req.http_method = method.to_string();
            req.request_uri = path.to_string();
            // Informational; "wss-client" on WSS vs hostname on TCP, per the Python reference SDK.
            req.client_addr = "wss-client".to_string();
            req.headers.insert(HTTP_HEADER_KEY_USER_AGENT.into(), HTTP_USER_AGENT_WSS.into());

            // Poisoning is benign here (guarded state stays valid), so recover the guard.
            if let Some(token) = self.token.read().unwrap_or_else(|e| e.into_inner()).clone() {
                req.headers.insert(HTTP_HEADER_JWT_AUTHORIZATION.into(), token);
            }
            if let Some(ref fwd) = *self.forward_to.lock().unwrap_or_else(|e| e.into_inner()) {
                req.headers.insert(HTTP_HEADER_KEY_FORWARDING_HOST.into(), fwd.clone());
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

            let data = req.serialize().map_err(|e| AppMeshError::SerializationError(e.to_string()))?;
            transport.send_message(&data).await?;

            Ok(req_headers)
        }
        .await;
        // Transport lock released here.

        let req_headers = match send_result {
            Ok(h) => h,
            Err(e) => {
                // Nothing was sent; remove the pending entry so it cannot leak.
                if let Some(ref demuxer) = active_demuxer {
                    demuxer.unregister_request(&req_uuid).await;
                }
                return Err(e);
            }
        };

        let resp = if let Some(rx) = rx {
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
        };

        let status = StatusCode::from_u16(resp.http_status as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        if fail_on_error && status != StatusCode::PRECONDITION_REQUIRED && !status.is_success() {
            return Err(AppMeshError::RequestFailed {
                status,
                message: String::from_utf8_lossy(&resp.body).to_string(),
            });
        }

        let http_resp = resp.into_http_response()?;

        // Auto-sync token from auth endpoint responses
        crate::requester::sync_transport_token(&http_resp, path, &req_headers, self);

        Ok(http_resp)
    }

    fn set_forward_to(&self, url: Option<String>) {
        *self.forward_to.lock().unwrap_or_else(|e| e.into_inner()) = url;
    }

    fn handle_token_update(&self, token: Option<String>) {
        *self.token.write().unwrap_or_else(|e| e.into_inner()) = token;
    }

    fn get_access_token(&self) -> Option<String> {
        self.token.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn close(&self) {
        // Stop the demuxer first
        if let Some(ref d) = *self.demuxer.lock().unwrap_or_else(|e| e.into_inner()) {
            d.stop();
        }
        // Spawn the async transport close only when a tokio runtime is available
        // (may run in Drop outside a runtime — never panic; dropping the writer closes the socket).
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let transport = self.transport.clone();
            handle.spawn(async move {
                let mut t = transport.lock().await;
                t.close().await;
            });
        }
    }

    fn enable_demuxer(&self) {
        let mut guard = self.demuxer.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return; // already enabled
        }
        let demuxer = Arc::new(MessageDemuxer::new());
        // Use the split reader handle — reads are independent from sends (no lock contention)
        let reader = Arc::new(WSSMessageReader { reader: Arc::clone(&self.reader_handle) });
        demuxer.start(reader);
        *guard = Some(demuxer);
    }

    fn get_demuxer(&self) -> Option<Arc<MessageDemuxer>> {
        self.demuxer.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn supports_demuxer(&self) -> bool {
        true
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
    /// Shared handle to the WSS transport so `close_async` can await the close handshake.
    transport: Arc<Mutex<WSSTransport>>,
}

impl AppMeshClientWSS {
    /// Create a WSS transport client. Defaults to `127.0.0.1:6058`.
    /// An empty `ssl_verify` path is the legacy verification-disable form; prefer
    /// [`crate::ClientBuilderWSS`]'s explicit `danger_accept_invalid_certs(true)`.
    pub fn new(
        address: Option<(String, u16)>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Arc<Self>, AppMeshError> {
        let verify = crate::tls_config::resolve_ssl_verify(ssl_verify)?;
        Self::new_with_verify(address, verify, ssl_client_cert)
    }

    /// Create a WSS transport client with an explicit `SslVerify` mode (used by the
    /// builder so insecure mode is an explicit flag, never an empty-string sentinel).
    pub(crate) fn new_with_verify(
        address: Option<(String, u16)>,
        verify: crate::tls_config::SslVerify,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Arc<Self>, AppMeshError> {
        let address_val = address.clone().unwrap_or_else(|| (DEFAULT_TCP_HOST.to_string(), DEFAULT_WSS_PORT));

        let wss_requester = WSSRequester::new(address, verify.clone(), ssl_client_cert.clone())?;
        let transport = Arc::clone(&wss_requester.transport);

        let base_url = format!("https://{}:{}", address_val.0, address_val.1);
        let client = AppMeshClient::with_requester(Box::new(wss_requester), base_url.clone());

        // Build HTTP client with matching SSL settings for the file-transfer side-channel
        let mut client_builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(120));

        // SslVerify::False only carries explicit intent; a configured CA that is
        // missing/invalid is a hard error, never a silent no-verify fallback.
        // SslVerify::True means auto resolution already chose the system store.
        match &verify {
            crate::tls_config::SslVerify::False => {
                client_builder = client_builder.danger_accept_invalid_certs(true);
            }
            crate::tls_config::SslVerify::Path(ssl_verify_path) => {
                let buf = std::fs::read(ssl_verify_path).map_err(|e| {
                    AppMeshError::ConfigurationError(format!(
                        "Failed to read CA certificate '{}': {}",
                        ssl_verify_path, e
                    ))
                })?;
                let cert = reqwest::Certificate::from_pem(&buf).map_err(|e| {
                    AppMeshError::ConfigurationError(format!(
                        "Invalid CA certificate '{}': {}",
                        ssl_verify_path, e
                    ))
                })?;
                client_builder = client_builder.add_root_certificate(cert);
            }
            crate::tls_config::SslVerify::True => {}
        }

        if let Some((cert_path, key_path)) = ssl_client_cert {
            let mut combined = std::fs::read(&cert_path).map_err(|e| {
                AppMeshError::ConfigurationError(format!(
                    "Failed to read client certificate '{}': {}",
                    cert_path, e
                ))
            })?;
            combined.extend_from_slice(b"\n");
            combined.extend_from_slice(&std::fs::read(&key_path).map_err(|e| {
                AppMeshError::ConfigurationError(format!("Failed to read client key '{}': {}", key_path, e))
            })?);
            let identity = reqwest::Identity::from_pem(&combined).map_err(|e| {
                AppMeshError::ConfigurationError(format!("Invalid client certificate/key: {}", e))
            })?;
            client_builder = client_builder.identity(identity);
        }

        let http_client = client_builder
            .build()
            .map_err(|e| AppMeshError::ConnectionError(format!("Failed to build HTTP client: {}", e)))?;

        Ok(Arc::new(Self { client, http_client, base_url, transport }))
    }

    /// Get the underlying generic client for shared auth/app/task APIs.
    pub fn client(&self) -> &Arc<AppMeshClient> {
        &self.client
    }

    /// Gracefully close the client, awaiting the WebSocket close handshake.
    /// The synchronous `close()` (also invoked by `Drop`) can only fire-and-forget the
    /// transport close; use this to be sure the close frame is sent. Safe to call repeatedly.
    pub async fn close_async(&self) {
        // Cancels token refresh and stops the demuxer; transport close is idempotent.
        self.client.close();
        self.transport.lock().await.close().await;
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
            reqwest::header::HeaderValue::from_str(&auth_token).map_err(|e| {
                AppMeshError::ConfigurationError(format!("Invalid authorization header value: {}", e))
            })?,
        );
        upload_headers.insert(
            reqwest::header::HeaderName::from_bytes(HTTP_HEADER_KEY_X_FILE_PATH.as_bytes()).unwrap(),
            reqwest::header::HeaderValue::from_str(remote_file).map_err(|e| {
                AppMeshError::ConfigurationError(format!("Invalid remote file path header value: {}", e))
            })?,
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

    /// Run an application and wait for completion using subscribe.
    /// Subscribe is established BEFORE the app is started, so no events are missed.
    ///
    /// Returns:
    ///   `Ok((run, Some(code)))` -- process exited (code may be negative for signal kills)
    ///   `Ok((run, None))`       -- caller-side timeout
    ///   `Err(AppMeshError::AppRemoved)`            -- app removed before EXIT observed
    ///   `Err(AppMeshError::TransportDisconnected)` -- transport failure
    pub async fn run_and_wait(
        &self,
        app: &Application,
        max_time: i32,
        lifecycle: i32,
        stdout_handler: OutputHandler,
        timeout: i32,
    ) -> Result<(AppRun, Option<i32>), AppMeshError> {
        crate::wait_subscribe::run_and_wait_subscribe(
            &self.client, app, max_time, lifecycle, stdout_handler, timeout,
        )
        .await
    }

    /// Subscribe-based wait for an async run (WSS override).
    ///
    /// Instead of polling `get_app_output` in a loop, subscribes to STDOUT/EXIT/REMOVED
    /// events and does a one-shot backfill to cover output emitted before the subscribe
    /// took effect.  Deduplicates by byte-position offset.
    ///
    /// Returns:
    ///   `Ok(Some(code))` -- process exited (code may be negative for signal kills)
    ///   `Ok(None)`       -- caller-side timeout
    ///   `Err(AppMeshError::AppRemoved)`            -- REMOVED before EXIT observed
    ///   `Err(AppMeshError::TransportDisconnected)` -- demuxer disconnected (transport failure)
    pub async fn wait_for_async_run(
        &self,
        run: &AppRun,
        stdout_handler: OutputHandler,
        timeout: i32,
    ) -> Result<Option<i32>, AppMeshError> {
        crate::wait_subscribe::wait_for_async_run_subscribe(&self.client, run, stdout_handler, timeout).await
    }
}

/// NOTE: Deref gives ergonomic access to the shared [`AppMeshClient`] API.
/// Inherent methods here (e.g. `wait_for_async_run`) shadow same-named deref-target
/// methods, but both resolve to the same subscribe-based wait semantics.
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
