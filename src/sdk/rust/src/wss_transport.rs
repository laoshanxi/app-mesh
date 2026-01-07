// wss_transport.rs

use crate::error::AppMeshError;
use crate::tcp_transport::{ClientCert, SslVerify};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use native_tls::{Certificate, Identity, TlsConnector};
use std::fs;
use std::path::Path;
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

    /// Create the TLS Connector (Reuse logic from tcp_transport but for Async)
    fn create_tls_connector(&self) -> Result<TlsConnector, AppMeshError> {
        let mut builder = TlsConnector::builder();

        match &self.ssl_verify {
            SslVerify::True => {} // Use system defaults
            SslVerify::False => {
                builder.danger_accept_invalid_certs(true);
                builder.danger_accept_invalid_hostnames(true);
            }
            SslVerify::Path(path) => {
                let p = Path::new(path);
                if p.is_file() {
                    let bytes = fs::read(p).map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?;
                    let cert =
                        Certificate::from_pem(&bytes).map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?;
                    builder.add_root_certificate(cert);
                } else if p.is_dir() {
                    for entry in fs::read_dir(p).map_err(|e| AppMeshError::ConfigurationError(e.to_string()))? {
                        let path = entry.map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?.path();
                        if path.extension().and_then(|s| s.to_str()) == Some("pem") {
                            if let Ok(bytes) = fs::read(&path) {
                                if let Ok(cert) = Certificate::from_pem(&bytes) {
                                    builder.add_root_certificate(cert);
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some(cert) = &self.ssl_client_cert {
            match cert {
                ClientCert::Single(path) => {
                    let pem = fs::read(path).map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?;
                    let identity =
                        Identity::from_pkcs8(&pem, &[]).map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?;
                    builder.identity(identity);
                }
                ClientCert::Pair(cert_path, key_path) => {
                    let cert =
                        fs::read_to_string(cert_path).map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?;
                    let key =
                        fs::read_to_string(key_path).map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?;
                    let combined = format!("{}\n{}", cert, key);
                    let identity = Identity::from_pkcs8(combined.as_bytes(), &[])
                        .map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?;
                    builder.identity(identity);
                }
            }
        }

        let connector = builder.build().map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?;
        Ok(connector)
    }

    pub async fn connect(&mut self) -> Result<(), AppMeshError> {
        let protocol = if let SslVerify::False = self.ssl_verify { "ws" } else { "wss" };

        let url_str = format!("{}://{}:{}/", protocol, self.address.0, self.address.1);
        let url = Url::parse(&url_str).map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?;

        // Prepare request with subprotocols
        let mut request =
            url.to_string().into_client_request().map_err(|e| AppMeshError::ConnectionError(e.to_string()))?;
        request.headers_mut().insert("Sec-WebSocket-Protocol", "appmesh-ws".parse().unwrap());

        // Prepare TLS connector
        let connector = if protocol == "wss" {
            let tls = self.create_tls_connector()?;
            Some(Connector::NativeTls(tls))
        } else {
            None
        };

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

        // Python sends empty list for EOF, but here we just send Binary frames
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
            None => Ok(None),      // Stream ended
            _ => Ok(Some(vec![])), // Ping/Pong/Frame ignored
        }
    }
}
