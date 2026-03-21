// error.rs

use reqwest::StatusCode;
use std::fmt;

/// Main error type for AppMesh SDK operations
#[derive(Debug)]
pub enum AppMeshError {
    /// Parse URL failed
    InvalidUrl(String),
    /// HTTP request failed with status code and message
    RequestFailed { status: StatusCode, message: String },
    /// Authentication failed
    AuthenticationFailed(String),
    /// Invalid configuration
    ConfigurationError(String),
    /// Resource not found
    NotFound(String),
    /// Operation not permitted
    PermissionDenied(String),
    /// Network/connection error (e.g., timeout, DNS failure)
    ConnectionError(String),
    /// JSON or data serialization/deserialization error
    SerializationError(String),
    /// File not found (e.g., config or cert file)
    FileNotFound(String),
    /// Generic IO error wrapper
    IoError(String),
    /// Feature not supported by this transport
    UnsupportedFeature { feature: String, transport: String },
    /// Transport-level protocol errors (invalid magic, message too large, etc.)
    Transport(TransportError),
    /// Generic error (use sparingly)
    Other(String),
}

/// Transport-level error for TCP/WSS framing protocol
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

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl fmt::Display for AppMeshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(msg) => write!(f, "Invalid URL: {}", msg),
            Self::RequestFailed { status, message } => {
                write!(f, "HTTP request failed with status {}: {}", status, message)
            }
            Self::AuthenticationFailed(msg) => write!(f, "Authentication failed: {}", msg),
            Self::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            Self::NotFound(msg) => write!(f, "Not found: {}", msg),
            Self::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            Self::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Self::FileNotFound(msg) => write!(f, "File not found: {}", msg),
            Self::IoError(msg) => write!(f, "IO error: {}", msg),
            Self::UnsupportedFeature { feature, transport } => {
                write!(f, "Feature '{}' is not supported by {} transport", feature, transport)
            }
            Self::Transport(err) => write!(f, "Transport error: {}", err),
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for AppMeshError {}

// Conversion implementations
impl From<url::ParseError> for AppMeshError {
    fn from(e: url::ParseError) -> Self {
        Self::InvalidUrl(e.to_string())
    }
}

impl From<reqwest::Error> for AppMeshError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_connect() || err.is_timeout() || err.is_request() {
            Self::ConnectionError(err.to_string())
        } else if let Some(status) = err.status() {
            Self::RequestFailed { status, message: err.to_string() }
        } else {
            Self::Other(err.to_string())
        }
    }
}

impl From<std::io::Error> for AppMeshError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::NotFound => Self::FileNotFound(err.to_string()),
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied(err.to_string()),
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::TimedOut => Self::ConnectionError(err.to_string()),
            _ => Self::IoError(err.to_string()),
        }
    }
}

impl From<serde_json::Error> for AppMeshError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

impl From<base64::DecodeError> for AppMeshError {
    fn from(err: base64::DecodeError) -> Self {
        Self::SerializationError(format!("Base64 decode error: {}", err))
    }
}

impl From<TransportError> for AppMeshError {
    fn from(err: TransportError) -> Self {
        Self::Transport(err)
    }
}
