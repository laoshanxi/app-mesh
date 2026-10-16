// wss_transport.rs
//! WebSocket Secure transport using tokio-tungstenite with rustls TLS backend.
//! Read and write halves are split so the demuxer can read concurrently with sends.

use crate::error::AppMeshError;
pub use crate::tls_config::{ClientCert, SslVerify};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, protocol::Message};
use tokio_tungstenite::{connect_async_tls_with_config, Connector};
use url::Url;

type WsStream = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type SplitSink = futures_util::stream::SplitSink<WsStream, Message>;
pub(crate) type SplitStream = futures_util::stream::SplitStream<WsStream>;

pub struct WSSTransport {
    address: (String, u16),
    ssl_verify: SslVerify,
    ssl_client_cert: Option<ClientCert>,
    writer: Option<SplitSink>,
    reader: Arc<Mutex<Option<SplitStream>>>,
    bearer_token: Option<String>,
}

impl WSSTransport {
    pub fn new(address: (String, u16), ssl_verify: SslVerify, ssl_client_cert: Option<ClientCert>) -> Self {
        crate::tls_config::ensure_crypto_provider();
        Self { address, ssl_verify, ssl_client_cert, writer: None, reader: Arc::new(Mutex::new(None)), bearer_token: None }
    }

    pub fn set_bearer_token(&mut self, token: Option<String>) {
        self.bearer_token = token.filter(|value| !value.is_empty());
    }

    pub async fn connect(&mut self) -> Result<(), AppMeshError> {
        let url_str = format!("wss://{}:{}/", self.address.0, self.address.1);
        let url = Url::parse(&url_str).map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?;

        let mut request = url.to_string().into_client_request().map_err(|e| AppMeshError::ConnectionError(e.to_string()))?;
        request.headers_mut().insert("Sec-WebSocket-Protocol", "appmesh-ws".parse().unwrap());
        if let Some(token) = &self.bearer_token {
            let value = format!("Bearer {}", token)
                .parse::<http::HeaderValue>()
                .map_err(|e| AppMeshError::ConfigurationError(format!("Invalid WebSocket authorization header: {}", e)))?;
            request.headers_mut().insert("Authorization", value);
        }

        let connector = build_rustls_connector(&self.ssl_verify, self.ssl_client_cert.as_ref())?;

        let (ws_stream, _) = connect_async_tls_with_config(request, None, false, Some(connector))
            .await
            .map_err(|e| AppMeshError::ConnectionError(format!("WebSocket connect failed: {}", e)))?;

        let (write, read) = ws_stream.split();
        self.writer = Some(write);
        *self.reader.lock().await = Some(read);
        Ok(())
    }

    pub async fn close(&mut self) {
        if let Some(mut writer) = self.writer.take() {
            let _ = writer.close().await;
        }
        *self.reader.lock().await = None;
    }

    pub fn connected(&self) -> bool {
        self.writer.is_some()
    }

    /// Get a clone of the reader handle for the demuxer.
    pub fn reader_handle(&self) -> Arc<Mutex<Option<SplitStream>>> {
        Arc::clone(&self.reader)
    }

    pub async fn send_message(&mut self, data: &[u8]) -> Result<(), AppMeshError> {
        let writer = self.writer.as_mut().ok_or(AppMeshError::ConnectionError("Not connected".into()))?;
        let msg = Message::Binary(Bytes::copy_from_slice(data));
        writer.send(msg).await.map_err(|e| AppMeshError::ConnectionError(format!("Send failed: {}", e)))?;
        Ok(())
    }

    pub async fn receive_message(&mut self) -> Result<Option<Vec<u8>>, AppMeshError> {
        let mut guard = self.reader.lock().await;
        let reader = guard.as_mut().ok_or(AppMeshError::ConnectionError("Not connected".into()))?;
        read_one(reader).await
    }
}

/// Read one message from the stream (used by both direct read and demuxer).
/// WebSocket control frames (Ping/Pong) are skipped: an intermediary's
/// keepalive ping must not be mistaken for EOF — that would broadcast a
/// synthetic disconnect to every subscription.
pub(crate) async fn read_one<St>(reader: &mut St) -> Result<Option<Vec<u8>>, AppMeshError>
where
    St: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        match reader.next().await {
            Some(Ok(Message::Binary(data))) => return Ok(Some(data.to_vec())),
            Some(Ok(Message::Text(text))) => return Ok(Some(text.bytes().collect())),
            Some(Ok(Message::Close(_))) | None => return Ok(None),
            Some(Err(e)) => return Err(AppMeshError::ConnectionError(e.to_string())),
            // Ping/Pong: tungstenite queues the pong reply automatically;
            // keep reading for the next data frame.
            Some(Ok(_)) => continue,
        }
    }
}

fn build_rustls_connector(ssl_verify: &SslVerify, ssl_client_cert: Option<&ClientCert>) -> Result<Connector, AppMeshError> {
    let config = crate::tls_config::build_rustls_client_config(ssl_verify, ssl_client_cert)
        .map_err(AppMeshError::ConfigurationError)?;
    Ok(Connector::Rustls(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::read_one;
    use tokio::io::AsyncWriteExt;
    use tokio_tungstenite::tungstenite::protocol::Role;

    // An intermediary's keepalive Ping must be skipped, not mistaken for EOF —
    // treating it as a close would broadcast a synthetic disconnect to every
    // subscription.
    #[tokio::test]
    async fn read_one_skips_ping_frames() {
        let (client_side, mut server_side) = tokio::io::duplex(64);
        let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(client_side, Role::Client, None).await;

        // Server -> client: empty Ping, then a Binary [1, 2] (server frames are unmasked).
        server_side.write_all(&[0x89, 0x00]).await.unwrap();
        server_side.write_all(&[0x82, 0x02, 0x01, 0x02]).await.unwrap();

        let data = read_one(&mut ws).await.expect("read failed");
        assert_eq!(data, Some(vec![1, 2]), "ping frame must be skipped, not read as EOF");
    }
}
