// tcp_transport.rs
//! TLS-enabled TCP transport with simple framed messaging protocol.
//!
//! Framing format:
//!     4 bytes magic (u32 big-endian)
//!   + 4 bytes length (u32 big-endian)
//!   + payload bytes

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rustls::StreamOwned;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use crate::error::TransportError;
pub use crate::tls_config::{ClientCert, SslVerify};

/// Protocol constants
const TCP_MESSAGE_MAGIC: u32 = 0x07C707F8;
const TCP_MAX_BLOCK_SIZE: usize = 1024 * 1024 * 1024; // 1 GB

pub type Result<T> = std::result::Result<T, TransportError>;

/// Main TCP transport
pub struct TCPTransport {
    address: (String, u16),
    ssl_verify: SslVerify,
    ssl_client_cert: Option<ClientCert>,
    socket: Option<StreamOwned<rustls::ClientConnection, TcpStream>>,
}

impl TCPTransport {
    pub fn new(address: (String, u16), ssl_verify: SslVerify, ssl_client_cert: Option<ClientCert>) -> Self {
        crate::tls_config::ensure_crypto_provider();
        Self { address, ssl_verify, ssl_client_cert, socket: None }
    }

    /// Establishes a TCP+TLS connection.
    pub fn connect(&mut self) -> Result<()> {
        let tcp = TcpStream::connect((&self.address.0[..], self.address.1))
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        tcp.set_nodelay(true).map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let tls_config = build_rustls_client_config(&self.ssl_verify, self.ssl_client_cert.as_ref())?;
        let server_name = rustls::pki_types::ServerName::try_from(self.address.0.clone())
            .map_err(|e| TransportError::ConfigError(format!("Invalid server name: {}", e)))?;
        let tls_conn = rustls::ClientConnection::new(Arc::new(tls_config), server_name)
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        let tls_stream = StreamOwned::new(tls_conn, tcp);

        self.socket = Some(tls_stream);
        Ok(())
    }

    pub fn close(&mut self) {
        if let Some(mut socket) = self.socket.take() {
            socket.conn.send_close_notify();
            let _ = socket.conn.complete_io(&mut socket.sock);
        }
    }

    pub fn connected(&self) -> bool {
        self.socket.is_some()
    }

    /// Send a framed message
    pub fn send_message(&mut self, data: &[u8]) -> Result<()> {
        let stream = self.socket.as_mut().ok_or(TransportError::NotConnected)?;

        if data.len() > TCP_MAX_BLOCK_SIZE {
            return Err(TransportError::MessageTooLarge(data.len()));
        }

        let mut header = [0u8; 8];
        {
            let mut cursor = std::io::Cursor::new(&mut header[..]);
            cursor.write_u32::<BigEndian>(TCP_MESSAGE_MAGIC)?;
            cursor.write_u32::<BigEndian>(data.len() as u32)?;
        }

        stream.write_all(&header)?;
        if !data.is_empty() {
            stream.write_all(data)?;
        }
        stream.flush()?;
        Ok(())
    }

    /// Receive a framed message
    pub fn receive_message(&mut self) -> Result<Option<Vec<u8>>> {
        let stream = self.socket.as_mut().ok_or(TransportError::NotConnected)?;

        let magic = match stream.read_u32::<BigEndian>() {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(TransportError::ConnectionClosed)
            }
            Err(e) => return Err(TransportError::ReceiveError(e.to_string())),
        };

        if magic != TCP_MESSAGE_MAGIC {
            return Err(TransportError::InvalidMagic(magic));
        }

        let len = stream.read_u32::<BigEndian>()? as usize;
        if len > TCP_MAX_BLOCK_SIZE {
            return Err(TransportError::MessageTooLarge(len));
        }
        if len == 0 {
            return Ok(Some(Vec::new()));
        }

        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;
        Ok(Some(buf))
    }
}

impl Drop for TCPTransport {
    fn drop(&mut self) {
        self.close();
    }
}

fn build_rustls_client_config(
    ssl_verify: &SslVerify,
    ssl_client_cert: Option<&ClientCert>,
) -> Result<rustls::ClientConfig> {
    let builder = if matches!(ssl_verify, SslVerify::False) {
        // Insecure mode is only reachable via the explicit SslVerify::False flag
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls_config::NoVerifier))
    } else if let SslVerify::Path(path) = ssl_verify {
        let p = std::path::Path::new(path);
        let mut root_store = rustls::RootCertStore::empty();
        if p.is_file() {
            let pem = std::fs::read(p)
                .map_err(|e| TransportError::ConfigError(format!("Failed to read CA certificate '{}': {}", path, e)))?;
            for cert in rustls_pemfile::certs(&mut &pem[..]) {
                let cert = cert
                    .map_err(|e| TransportError::ConfigError(format!("Invalid CA certificate '{}': {}", path, e)))?;
                root_store.add(cert).map_err(|e| TransportError::ConfigError(e.to_string()))?;
            }
        } else if p.is_dir() {
            // Directory of PEM files (see SslVerify::Path doc); mirrors the WSS transport.
            for entry in std::fs::read_dir(p).map_err(|e| TransportError::ConfigError(e.to_string()))? {
                let entry_path = entry.map_err(|e| TransportError::ConfigError(e.to_string()))?.path();
                if entry_path.extension().and_then(|s| s.to_str()) == Some("pem") {
                    let pem = std::fs::read(&entry_path).map_err(|e| {
                        TransportError::ConfigError(format!(
                            "Failed to read CA certificate '{}': {}",
                            entry_path.display(),
                            e
                        ))
                    })?;
                    for cert in rustls_pemfile::certs(&mut &pem[..]).flatten() {
                        let _ = root_store.add(cert);
                    }
                }
            }
        } else {
            // A configured CA path that is missing/unreadable is a hard error,
            // never a silent fallback to no-verification.
            return Err(TransportError::ConfigError(format!(
                "CA certificate path '{}' not found",
                path
            )));
        }
        if root_store.is_empty() {
            return Err(TransportError::ConfigError(format!(
                "CA certificate path '{}' contains no valid certificates",
                path
            )));
        }
        rustls::ClientConfig::builder().with_root_certificates(root_store)
    } else {
        let root_store = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder().with_root_certificates(root_store)
    };

    match ssl_client_cert {
        Some(client_cert) => {
            let (chain, key) =
                crate::tls_config::load_client_auth(client_cert).map_err(TransportError::ConfigError)?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| TransportError::ConfigError(format!("Invalid client certificate/key: {}", e)))
        }
        None => Ok(builder.with_no_client_auth()),
    }
}
