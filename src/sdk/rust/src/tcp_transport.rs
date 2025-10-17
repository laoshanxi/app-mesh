// tcp_transport.rs

//! TLS-enabled TCP transport with simple framed messaging protocol.
//!
//! Framing format:
//!     4 bytes magic (u32 big-endian)
//!   + 4 bytes length (u32 big-endian)
//!   + payload bytes
//!
//! Config parameters:
//! - `address`: (host, port)
//! - `ssl_verify`: SSL verification mode
//!     * `SslVerify::True`    → system CA (default)
//!     * `SslVerify::False`   → disable verification (insecure)
//!     * `SslVerify::Path(s)` → custom CA bundle or directory
//! - `ssl_client_cert`: client certificate (optional)
//!     * `ClientCert::Single(path)` → PEM file with both cert+key
//!     * `ClientCert::Pair(cert_path, key_path)` → separate cert/key files

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use native_tls::{Certificate, Identity, TlsConnector, TlsStream};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;

/// Protocol constants
const TCP_MESSAGE_MAGIC: u32 = 0x07C707F8;
const TCP_MAX_BLOCK_SIZE: usize = 100 * 1024 * 1024; // 100 MB

/// Unified error type
#[derive(Debug)]
pub enum TransportError {
    NotConnected,
    ConnectionFailed(String),
    ReceiveError(String),
    InvalidMagic(u32),
    MessageTooLarge(usize),
    ConnectionClosed,
    ConfigError(String),
    IoError(std::io::Error),
    TlsError(native_tls::Error),
}

impl From<std::io::Error> for TransportError {
    fn from(err: std::io::Error) -> Self {
        TransportError::IoError(err)
    }
}

impl From<native_tls::Error> for TransportError {
    fn from(err: native_tls::Error) -> Self {
        TransportError::TlsError(err)
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use TransportError::*;
        match self {
            NotConnected => write!(f, "Not connected"),
            ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            ReceiveError(msg) => write!(f, "Receive error: {}", msg),
            InvalidMagic(magic) => write!(f, "Invalid magic number: 0x{:08X}", magic),
            MessageTooLarge(sz) => write!(f, "Message too large: {} bytes", sz),
            ConnectionClosed => write!(f, "Connection closed by peer"),
            ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            IoError(err) => write!(f, "IO error: {}", err),
            TlsError(err) => write!(f, "TLS error: {}", err),
        }
    }
}

impl std::error::Error for TransportError {}

pub type Result<T> = std::result::Result<T, TransportError>;

/// SSL verification configuration
#[derive(Clone, Debug)]
pub enum SslVerify {
    True,         // use system CA
    False,        // disable verification
    Path(String), // custom CA file or directory
}

/// Client certificate
#[derive(Clone, Debug)]
pub enum ClientCert {
    Single(String),       // PEM file containing both cert + key
    Pair(String, String), // Separate PEM files for cert and key
}

/// Main TCP transport
pub struct TCPTransport {
    address: (String, u16),
    ssl_verify: SslVerify,
    ssl_client_cert: Option<ClientCert>,
    socket: Option<TlsStream<TcpStream>>,
}

impl TCPTransport {
    pub fn new(address: (String, u16), ssl_verify: SslVerify, ssl_client_cert: Option<ClientCert>) -> Self {
        Self { address, ssl_verify, ssl_client_cert, socket: None }
    }

    /// Establishes a TCP+TLS connection.
    pub fn connect(&mut self) -> Result<()> {
        let tcp = TcpStream::connect((&self.address.0[..], self.address.1))
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;
        tcp.set_nodelay(true).map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let tls_connector = self.create_tls_connector()?;
        let tls_stream =
            tls_connector.connect(&self.address.0, tcp).map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        self.socket = Some(tls_stream);
        Ok(())
    }

    fn create_tls_connector(&self) -> Result<TlsConnector> {
        let mut builder = TlsConnector::builder();

        match &self.ssl_verify {
            SslVerify::True => {} // use system defaults
            SslVerify::False => {
                builder.danger_accept_invalid_certs(true);
                builder.danger_accept_invalid_hostnames(true);
            }
            SslVerify::Path(path) => {
                let p = Path::new(path);
                if p.is_file() {
                    let bytes = fs::read(p).map_err(|e| TransportError::ConfigError(e.to_string()))?;
                    let cert = Certificate::from_pem(&bytes).map_err(|e| TransportError::ConfigError(e.to_string()))?;
                    builder.add_root_certificate(cert);
                } else if p.is_dir() {
                    // Load all PEM files in directory
                    for entry in fs::read_dir(p).map_err(|e| TransportError::ConfigError(e.to_string()))? {
                        let path = entry.map_err(|e| TransportError::ConfigError(e.to_string()))?.path();
                        if path.extension().and_then(|s| s.to_str()) == Some("pem") {
                            if let Ok(bytes) = fs::read(&path) {
                                if let Ok(cert) = Certificate::from_pem(&bytes) {
                                    builder.add_root_certificate(cert);
                                }
                            }
                        }
                    }
                } else {
                    return Err(TransportError::ConfigError(format!("Invalid ssl_verify path: '{}'", path)));
                }
            }
        }

        if let Some(cert) = &self.ssl_client_cert {
            match cert {
                ClientCert::Single(path) => {
                    let pem = fs::read(path).map_err(|e| TransportError::ConfigError(e.to_string()))?;
                    let identity =
                        Identity::from_pkcs8(&pem, &[]).map_err(|e| TransportError::ConfigError(e.to_string()))?;
                    builder.identity(identity);
                }
                ClientCert::Pair(cert_path, key_path) => {
                    let cert = fs::read_to_string(cert_path).map_err(|e| TransportError::ConfigError(e.to_string()))?;
                    let key = fs::read_to_string(key_path).map_err(|e| TransportError::ConfigError(e.to_string()))?;
                    let combined = format!("{}\n{}", cert, key);
                    let identity = Identity::from_pkcs8(combined.as_bytes(), &[])
                        .map_err(|e| TransportError::ConfigError(e.to_string()))?;
                    builder.identity(identity);
                }
            }
        }

        builder.build().map_err(TransportError::from)
    }

    pub fn close(&mut self) {
        if let Some(mut socket) = self.socket.take() {
            let _ = socket.shutdown();
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
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(TransportError::ConnectionClosed),
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
