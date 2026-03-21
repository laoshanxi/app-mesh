// wss_transport.rs
//! WebSocket Secure transport using tokio-tungstenite with shared TLS configuration.

use crate::error::AppMeshError;
pub use crate::tls_config::{ClientCert, SslVerify};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, protocol::Message};
use tokio_tungstenite::{connect_async_tls_with_config, Connector, WebSocketStream};
use url::Url;

type WebSocketStreamType = WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

pub struct WSSTransport {
    address: (String, u16),
    ssl_verify: SslVerify,
    ssl_client_cert: Option<ClientCert>,
    socket: Option<WebSocketStreamType>,
}

impl WSSTransport {
    pub fn new(address: (String, u16), ssl_verify: SslVerify, ssl_client_cert: Option<ClientCert>) -> Self {
        Self { address, ssl_verify, ssl_client_cert, socket: None }
    }

    pub async fn connect(&mut self) -> Result<(), AppMeshError> {
        // Always use wss:// — even when SslVerify::False the server requires TLS.
        // SslVerify::False builds a permissive connector that skips all cert checks.
        let url_str = format!("wss://{}:{}/", self.address.0, self.address.1);
        let url = Url::parse(&url_str).map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?;

        let mut request =
            url.to_string().into_client_request().map_err(|e| AppMeshError::ConnectionError(e.to_string()))?;
        request.headers_mut().insert("Sec-WebSocket-Protocol", "appmesh-ws".parse().unwrap());

        let tls = crate::tls_config::build_tls_connector(&self.ssl_verify, self.ssl_client_cert.as_ref())
            .map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?;
        let connector = Some(Connector::NativeTls(tls));

        let (ws_stream, _) = connect_async_tls_with_config(request, None, false, connector)
            .await
            .map_err(|e| AppMeshError::ConnectionError(format!("WebSocket connect failed: {}", e)))?;

        self.socket = Some(ws_stream);
        Ok(())
    }

    pub async fn close(&mut self) {
        if let Some(mut socket) = self.socket.take() {
            let _ = socket.close(None).await;
        }
    }

    pub fn connected(&self) -> bool {
        self.socket.is_some()
    }

    pub async fn send_message(&mut self, data: &[u8]) -> Result<(), AppMeshError> {
        let socket = self.socket.as_mut().ok_or(AppMeshError::ConnectionError("Not connected".into()))?;

        let msg = Message::Binary(Bytes::copy_from_slice(data));
        socket.send(msg).await.map_err(|e| AppMeshError::ConnectionError(format!("Send failed: {}", e)))?;
        Ok(())
    }

    pub async fn receive_message(&mut self) -> Result<Option<Vec<u8>>, AppMeshError> {
        let socket = self.socket.as_mut().ok_or(AppMeshError::ConnectionError("Not connected".into()))?;

        match socket.next().await {
            Some(Ok(Message::Binary(data))) => Ok(Some(data.to_vec())),
            Some(Ok(Message::Text(text))) => Ok(Some(text.bytes().collect())),
            Some(Ok(Message::Close(_))) => Ok(None),
            Some(Err(e)) => Err(AppMeshError::ConnectionError(e.to_string())),
            None => Ok(None),
            _ => Ok(Some(vec![])), // Ping/Pong ignored
        }
    }
}
