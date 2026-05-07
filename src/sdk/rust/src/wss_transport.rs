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
}

impl WSSTransport {
    pub fn new(address: (String, u16), ssl_verify: SslVerify, ssl_client_cert: Option<ClientCert>) -> Self {
        Self {
            address,
            ssl_verify,
            ssl_client_cert,
            writer: None,
            reader: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn connect(&mut self) -> Result<(), AppMeshError> {
        let url_str = format!("wss://{}:{}/", self.address.0, self.address.1);
        let url = Url::parse(&url_str).map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?;

        let mut request =
            url.to_string().into_client_request().map_err(|e| AppMeshError::ConnectionError(e.to_string()))?;
        request.headers_mut().insert("Sec-WebSocket-Protocol", "appmesh-ws".parse().unwrap());

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
pub(crate) async fn read_one(reader: &mut SplitStream) -> Result<Option<Vec<u8>>, AppMeshError> {
    match reader.next().await {
        Some(Ok(Message::Binary(data))) => Ok(Some(data.to_vec())),
        Some(Ok(Message::Text(text))) => Ok(Some(text.bytes().collect())),
        Some(Ok(Message::Close(_))) => Ok(None),
        Some(Err(e)) => Err(AppMeshError::ConnectionError(e.to_string())),
        None => Ok(None),
        _ => Ok(Some(vec![])),
    }
}

fn build_rustls_connector(
    ssl_verify: &SslVerify,
    _ssl_client_cert: Option<&ClientCert>,
) -> Result<Connector, AppMeshError> {
    let disable_verify = matches!(ssl_verify, SslVerify::False)
        || matches!(ssl_verify, SslVerify::Path(p) if !std::path::Path::new(p).exists());

    if disable_verify {
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        Ok(Connector::Rustls(Arc::new(crypto)))
    } else if let SslVerify::Path(path) = ssl_verify {
        let p = std::path::Path::new(path);
        let mut root_store = rustls::RootCertStore::empty();
        if p.is_file() {
            let pem_data = std::fs::read(p)
                .map_err(|e| AppMeshError::ConfigurationError(format!("Failed to read CA cert: {}", e)))?;
            for cert in rustls_pemfile::certs(&mut &pem_data[..]).flatten() {
                root_store.add(cert).map_err(|e| {
                    AppMeshError::ConfigurationError(format!("Invalid CA cert: {}", e))
                })?;
            }
        } else if p.is_dir() {
            for entry in std::fs::read_dir(p)
                .map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?
            {
                let path = entry.map_err(|e| AppMeshError::ConfigurationError(e.to_string()))?.path();
                if path.extension().and_then(|s| s.to_str()) == Some("pem") {
                    if let Ok(pem_data) = std::fs::read(&path) {
                        for cert in rustls_pemfile::certs(&mut &pem_data[..]).flatten() {
                            let _ = root_store.add(cert);
                        }
                    }
                }
            }
        }
        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok(Connector::Rustls(Arc::new(crypto)))
    } else {
        let root_store = rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        );
        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok(Connector::Rustls(Arc::new(crypto)))
    }
}

#[derive(Debug)]
pub struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self, _: &rustls::pki_types::CertificateDer<'_>, _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>, _: &[u8], _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
