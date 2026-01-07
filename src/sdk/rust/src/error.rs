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
    /// Generic error (use sparingly)
    Other(String),
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
