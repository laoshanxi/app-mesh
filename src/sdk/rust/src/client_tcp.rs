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

use crate::client_http::{
    build_sse_side_channel, encode_path_segment, open_sse_side_channel, task_body_bytes, AppMeshClient, RunStream,
    SseKind, SseStream,
};
use crate::constants::*;
use crate::error::AppMeshError;
use crate::models::*;
use crate::request_signature::{sign_wire_message, RequestSigner};
use crate::requester::Requester;
use crate::subscribe::{MessageDemuxer, MessageReader};
use crate::tcp_transport::{ReceivePoll, TCPTransport};
use crate::tls_config::ClientCert;
use crate::wire_messages::{RequestMessage, ResponseMessage};

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
        loop {
            // Bound each blocking TLS read so the transport mutex is released
            // regularly; the writer can then send requests while this reader owns
            // response/event routing. TCPTransport retains partial frames.
            let transport = Arc::clone(&self.transport);
            let polled = tokio::task::spawn_blocking(move || {
                let mut t = transport.lock().unwrap_or_else(|e| e.into_inner());
                t.poll_message(std::time::Duration::from_millis(50)).map_err(AppMeshError::from)
            })
            .await
            .map_err(|e| AppMeshError::ConnectionError(format!("reader task panicked: {}", e)))??;

            match polled {
                ReceivePoll::Message(data) => return Ok(Some(data)),
                ReceivePoll::Closed => return Ok(None),
                ReceivePoll::Pending => tokio::task::yield_now().await,
            }
        }
    }
}

/// TCP-based requester implementation
pub struct TCPRequester {
    tcp_transport: Arc<Mutex<TCPTransport>>,
    token: Arc<Mutex<Option<String>>>,
    forward_to: Arc<Mutex<Option<String>>>,
    demuxer: Mutex<Option<Arc<MessageDemuxer>>>,
    signer: std::sync::RwLock<Option<RequestSigner>>,
}

impl TCPRequester {
    /// Create TCPRequester with shared transport (used internally by AppMeshClientTCP)
    pub fn with_shared_transport(tcp_transport: Arc<Mutex<TCPTransport>>) -> Self {
        Self {
            tcp_transport,
            token: Arc::new(Mutex::new(None)),
            forward_to: Arc::new(Mutex::new(None)),
            demuxer: Mutex::new(None),
            signer: std::sync::RwLock::new(None),
        }
    }

    pub fn set_token(&self, token: Option<String>) {
        *self.token.lock().unwrap_or_else(|e| e.into_inner()) = token;
    }

    pub fn get_access_token(&self) -> Option<String> {
        self.token.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Direct (legacy) read path: lock the transport and read one response.
    fn read_response_direct(&self) -> Result<ResponseMessage> {
        let mut transport = self.tcp_transport.lock().unwrap_or_else(|e| e.into_inner());

        let resp_data = match transport.receive_message() {
            Ok(Some(data)) if !data.is_empty() => data,
            Ok(_) => {
                transport.close();
                return Err(AppMeshError::ConnectionError("Socket connection broken".into()));
            }
            // A receive error (framing/IO) leaves the stream desynchronized; close
            // so the next request reconnects instead of writing into a garbage
            // stream (the Python SDK closes on any receive error too).
            Err(e) => {
                transport.close();
                return Err(e.into());
            }
        };

        ResponseMessage::deserialize(&resp_data).map_err(|e| AppMeshError::SerializationError(e.to_string()))
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
        let req_uuid = Uuid::new_v4().to_string();

        // Register the pending request BEFORE sending so the demuxer read loop
        // cannot drop the response before a receiver exists (Go/Java SDK ordering).
        let demuxer_opt = self.demuxer.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let active_demuxer = demuxer_opt.filter(|d| d.is_running());
        let rx = match &active_demuxer {
            Some(demuxer) => Some(demuxer.register_request(&req_uuid).await),
            None => None,
        };

        // Build the request message and send it while holding the transport lock.
        let send_result: Result<()> = (|| {
            let mut transport = self.tcp_transport.lock().unwrap_or_else(|e| e.into_inner());

            if !transport.connected() {
                transport.connect()?; // TransportError → AppMeshError via From
            }

            let mut req = RequestMessage::new();
            req.uuid = req_uuid.clone();
            req.http_method = method.to_string();
            req.request_uri = path.to_string();
            // Informational; hostname on TCP vs "wss-client" on WSS, per the Python reference SDK.
            req.client_addr = hostname::get().ok().and_then(|h| h.into_string().ok()).unwrap_or_else(|| "unknown".into());
            req.headers.insert(HTTP_HEADER_KEY_USER_AGENT.into(), HTTP_USER_AGENT_TCP.into());

            if let Some(token) = self.get_access_token() {
                req.headers.insert(HTTP_HEADER_JWT_AUTHORIZATION.into(), format!("{}{}", HTTP_HEADER_AUTH_BEARER, token));
            }
            if let Some(target) = self.forward_to.lock().unwrap_or_else(|e| e.into_inner()).clone() {
                req.headers.insert(HTTP_HEADER_KEY_FORWARDING_HOST.into(), target);
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

            // HMAC request signature (opt-in): the framed message uuid serves
            // as the nonce, matching the daemon's replay-protection fallback.
            if let Some(signer) = self.signer.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
                sign_wire_message(signer, &mut req);
            }

            let data = req.serialize().map_err(|e| AppMeshError::SerializationError(e.to_string()))?;
            if let Err(e) = transport.send_message(&data) {
                // A failed write leaves the stream unusable; drop it so the
                // next request reconnects instead of writing into a dead socket.
                transport.close();
                return Err(e.into());
            }

            Ok(())
        })();
        // Transport lock released here.

        match send_result {
            Ok(()) => {}
            Err(e) => {
                // Nothing was sent; remove the pending entry so it cannot leak.
                if let Some(ref demuxer) = active_demuxer {
                    demuxer.unregister_request(&req_uuid).await;
                }
                return Err(e);
            }
        }

        let resp = if let Some(rx) = rx {
            match rx.await {
                Ok(resp) => resp,
                Err(_) => {
                    // Demuxer stopped (read error/EOF): drop the transport so the
                    // next request reconnects instead of sending into a dead socket.
                    self.tcp_transport.lock().unwrap_or_else(|e| e.into_inner()).close();
                    return Err(AppMeshError::ConnectionError("Connection closed while waiting for response".into()));
                }
            }
        } else {
            self.read_response_direct()?
        };

        let status = StatusCode::from_u16(resp.http_status as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        if fail_on_error && status != StatusCode::PRECONDITION_REQUIRED && !status.is_success() {
            return Err(AppMeshError::RequestFailed { status, message: String::from_utf8_lossy(&resp.body).to_string() });
        }

        resp.into_http_response()
    }

    fn handle_token_update(&self, token: Option<String>) {
        self.set_token(token);
    }

    fn set_request_signer(&self, signer: Option<RequestSigner>) {
        *self.signer.write().unwrap_or_else(|e| e.into_inner()) = signer;
    }

    fn request_signer(&self) -> Option<RequestSigner> {
        self.signer.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_forward_to(&self, url: Option<String>) {
        *self.forward_to.lock().unwrap_or_else(|e| e.into_inner()) = url;
    }

    fn get_forward_to(&self) -> Option<String> {
        self.forward_to.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn get_access_token(&self) -> Option<String> {
        self.token.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn close(&self) {
        // Stop the demuxer first
        if let Some(ref d) = *self.demuxer.lock().unwrap_or_else(|e| e.into_inner()) {
            d.stop();
        }
        self.tcp_transport.lock().unwrap_or_else(|e| e.into_inner()).close();
    }

    async fn enable_demuxer(&self) -> Result<()> {
        {
            let mut transport = self.tcp_transport.lock().unwrap_or_else(|e| e.into_inner());
            if !transport.connected() {
                transport.connect()?;
            }
        }
        let mut guard = self.demuxer.lock().unwrap_or_else(|e| e.into_inner());
        if guard.as_ref().map(|d| d.is_running()).unwrap_or(false) {
            return Ok(()); // already enabled
        }
        let demuxer = Arc::new(MessageDemuxer::new());
        let reader = Arc::new(TCPMessageReader { transport: Arc::clone(&self.tcp_transport) });
        demuxer.start(reader);
        *guard = Some(demuxer);
        Ok(())
    }

    fn get_demuxer(&self) -> Option<Arc<MessageDemuxer>> {
        self.demuxer.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn supports_demuxer(&self) -> bool {
        true
    }
}

/// TCP-based AppMesh client.
///
/// This transport reuses the standard [`AppMeshClient`] API for control requests and switches to
/// raw TCP streaming only for large file transfer payloads.
pub struct AppMeshClientTCP {
    client: Arc<AppMeshClient>,
    tcp_transport: Arc<Mutex<TCPTransport>>,
    /// Direct HTTPS connection to the daemon's REST listener for SSE streams
    /// (a framed transport cannot carry a chunked event stream).
    rest_client: reqwest::Client,
    rest_base_url: String,
}

impl AppMeshClientTCP {
    /// Create a TCP transport client. Defaults to `127.0.0.1:6059` with the
    /// SSE side channel on the standard REST port 6058.
    /// An empty `ssl_verify` path is the legacy verification-disable form; prefer
    /// [`crate::ClientBuilderTCP`]'s explicit `danger_accept_invalid_certs(true)`.
    pub fn new(
        tcp_address: Option<(String, u16)>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Arc<Self>> {
        let verify = crate::tls_config::resolve_ssl_verify(ssl_verify)?;
        Self::new_with_verify(tcp_address, verify, ssl_client_cert, false, None)
    }

    /// Create a TCP transport client with an explicit `SslVerify` mode (used by the
    /// builder so insecure mode is an explicit flag, never an empty-string sentinel).
    /// `plain` selects the TLS-at-gateway shape: a plaintext TCP connection.
    /// `rest_port` overrides the SSE side channel's REST port (default 6058) for shifted-port daemons.
    pub(crate) fn new_with_verify(
        tcp_address: Option<(String, u16)>,
        verify: crate::tls_config::SslVerify,
        ssl_client_cert: Option<(String, String)>,
        plain: bool,
        rest_port: Option<u16>,
    ) -> Result<Arc<Self>> {
        let tcp_address = tcp_address.unwrap_or_else(|| (DEFAULT_TCP_HOST.to_string(), DEFAULT_TCP_PORT));
        let client_cert = ssl_client_cert.clone().map(|(cert, key)| ClientCert::Pair(cert, key));

        let tcp_transport =
            Arc::new(Mutex::new(TCPTransport::new(tcp_address.clone(), verify.clone(), client_cert, plain)));
        let tcp_requester = TCPRequester::with_shared_transport(Arc::clone(&tcp_transport));
        let url = format!("tcp://{}:{}", tcp_address.0, tcp_address.1);
        let client = AppMeshClient::with_requester(Box::new(tcp_requester), url);

        let (rest_client, rest_base_url) =
            build_sse_side_channel(&tcp_address.0, rest_port, &verify, ssl_client_cert, plain)?;

        Ok(Arc::new(Self { client, tcp_transport, rest_client, rest_base_url }))
    }

    /// Get the underlying generic client for shared auth/app/task APIs.
    pub fn client(&self) -> &Arc<AppMeshClient> {
        &self.client
    }

    /// Reject TCP file transfers while the event demuxer owns the read side: the
    /// demuxer read loop would steal the raw (non-msgpack) chunk frames and
    /// corrupt the transfer (mirrors the Python SDK).
    fn ensure_no_active_demuxer(&self) -> Result<()> {
        if self.client.demuxer_running() {
            return Err(AppMeshError::Other(
                "file transfer is not supported while an event subscription is active over the same TCP \
						 connection; use a separate client instance"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Download a file using the TCP file-socket side channel.
    ///
    /// When `preserve_permissions` is true, returned POSIX metadata is applied locally best-effort.
    ///
    /// An empty `local_file` defaults to the basename of `remote_file`.
    pub async fn download_file(&self, remote_file: &str, local_file: &str, preserve_permissions: bool) -> Result<()> {
        self.ensure_no_active_demuxer()?;
        // Empty local_file: derive the local path from the remote file's basename.
        let local_file = if local_file.is_empty() {
            Path::new(remote_file).file_name().and_then(|n| n.to_str()).unwrap_or(remote_file)
        } else {
            local_file
        };
        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_KEY_X_FILE_PATH.into(), remote_file.to_string());
        headers.insert(HTTP_HEADER_KEY_X_RECV_FILE_SOCKET.into(), "true".into());

        let resp = self.client.raw_request(Method::GET, "/appmesh/file/download", None, Some(headers), None, true).await?;

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

        let mut transport = self.tcp_transport.lock().unwrap_or_else(|e| e.into_inner());

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

    /// Delete a remote file. The same path validation as upload/download applies
    /// on the daemon; a missing file fails with 404.
    pub async fn delete_file(&self, remote_file: &str) -> Result<()> {
        self.ensure_no_active_demuxer()?;
        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_KEY_X_FILE_PATH.into(), remote_file.to_string());
        self.client.raw_request(Method::DELETE, "/appmesh/file/delete", None, Some(headers), None, true).await?;
        Ok(())
    }

    /// Upload a file using the TCP file-socket side channel.
    ///
    /// When `preserve_permissions` is true, local POSIX metadata is sent so the server can
    /// recreate permissions/ownership when supported.
    ///
    /// An empty `remote_file` defaults to the local file's basename.
    pub async fn upload_file(&self, local_file: &str, remote_file: &str, preserve_permissions: bool) -> Result<()> {
        self.upload_file_with(local_file, remote_file, preserve_permissions, false).await
    }

    /// [`Self::upload_file`] with `overwrite`: the daemon refuses an existing
    /// remote file with 409 unless the caller opts into replacing it.
    pub async fn upload_file_with(
        &self,
        local_file: &str,
        remote_file: &str,
        preserve_permissions: bool,
        overwrite: bool,
    ) -> Result<()> {
        self.ensure_no_active_demuxer()?;
        let remote_file = if remote_file.is_empty() {
            Path::new(local_file).file_name().and_then(|n| n.to_str()).unwrap_or(local_file)
        } else {
            remote_file
        };
        let local_path = Path::new(local_file);
        if !local_path.exists() {
            return Err(AppMeshError::FileNotFound(local_file.to_string()));
        }

        let mut headers = HashMap::new();
        headers.insert(HTTP_HEADER_KEY_X_FILE_PATH.into(), remote_file.to_string());
        headers.insert(HTTP_HEADER_CONTENT_TYPE.into(), "application/octet-stream".into());
        headers.insert(HTTP_HEADER_KEY_X_SEND_FILE_SOCKET.into(), "true".into());
        if overwrite {
            headers.insert(HTTP_HEADER_KEY_X_FILE_OVERWRITE.into(), "true".into());
        }
        if preserve_permissions {
            AppMeshClient::get_file_attributes(local_path, &mut headers);
        }

        let resp = self.client.raw_request(Method::POST, "/appmesh/file/upload", None, Some(headers), None, true).await?;

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

        let mut transport = self.tcp_transport.lock().unwrap_or_else(|e| e.into_inner());

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
    pub async fn run_app_async(self: &Arc<Self>, app: &Application, max_time: i32, lifecycle: i32) -> Result<AppRun> {
        self.client.run_app_async(app, max_time, lifecycle).await
    }

    /// Subscribe-based wait for an async run (TCP override).
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
    ) -> Result<Option<i32>> {
        self.client.wait_for_async_run(run, stdout_handler, timeout).await
    }

    /// Push a fresh provider-managed bearer, then read the token the SSE side
    /// channel needs (the daemon rejects tokenless streams with 401).
    async fn sse_token(&self) -> Result<String> {
        self.client.prepare_bearer().await?;
        self.client.get_access_token().ok_or_else(|| AppMeshError::RequestFailed {
            status: StatusCode::UNAUTHORIZED,
            message: "Streaming requires a bearer token".into(),
        })
    }

    /// Stream an application's stdout over the REST side channel (SSE cannot
    /// ride the framed TCP transport); see [`AppMeshClient::follow_output`].
    pub async fn follow_output(
        &self,
        app_name: &str,
        stdout_position: i64,
        process_uuid: &str,
        follow: bool,
        timeout: i32,
    ) -> Result<SseStream> {
        let path = format!("/appmesh/app/{}/output/stream", encode_path_segment(app_name));
        let query = AppMeshClient::output_stream_query(stdout_position, process_uuid, follow, timeout);
        let resp = open_sse_side_channel(
            &self.rest_client,
            &self.rest_base_url,
            &self.sse_token().await?,
            self.client.req.request_signer().as_ref(),
            HTTP_USER_AGENT_TCP,
            Method::GET,
            &path,
            Some(&query),
            None,
        )
        .await?;
        Ok(SseStream::new(SseKind::Output, resp))
    }

    /// Streaming task RPC over the REST side channel; see [`AppMeshClient::run_task_stream`].
    pub async fn run_task_stream(&self, app_name: &str, data: Value, timeout: i32) -> Result<SseStream> {
        let timeout = if timeout <= 0 { 300 } else { timeout };
        let path = format!("/appmesh/app/{}/task/stream", encode_path_segment(app_name));
        let query = AppMeshClient::task_stream_query(timeout);
        let body = task_body_bytes(data)?;
        let resp = open_sse_side_channel(
            &self.rest_client,
            &self.rest_base_url,
            &self.sse_token().await?,
            self.client.req.request_signer().as_ref(),
            HTTP_USER_AGENT_TCP,
            Method::POST,
            &path,
            Some(&query),
            Some(&body),
        )
        .await?;
        Ok(SseStream::new(SseKind::Task, resp))
    }

    /// One-shot run + stdout stream over the REST side channel; see [`AppMeshClient::stream_run`].
    /// The temporary app is always deleted when the stream terminates or is dropped.
    pub async fn stream_run(self: &Arc<Self>, app: &Application, max_time: i32, lifecycle: i32) -> Result<RunStream> {
        let run = self.run_app_async(app, max_time, lifecycle).await?;
        let stream = self.follow_output(&run.app_name, 0, &run.proc_uid, true, max_time.max(lifecycle)).await?;
        Ok(RunStream::new(stream, Arc::clone(&self.client), run.app_name))
    }
}

/// NOTE: Deref gives ergonomic access to the shared [`AppMeshClient`] API.
/// Inherent methods here (e.g. `wait_for_async_run`) shadow same-named deref-target
/// methods, but both resolve to the same subscribe-based wait semantics.
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
