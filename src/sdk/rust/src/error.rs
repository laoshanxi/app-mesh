// error.rs

use std::fmt;
use reqwest::StatusCode;

#[derive(Debug)]
pub enum AppMeshError {
    /// HTTP request failed
    RequestFailed {
        status: StatusCode,
        message: String,
    },
    /// Authentication failed
    AuthenticationFailed(String),
    /// Invalid configuration
    ConfigurationError(String),
    /// Resource not found
    NotFound(String),
    /// Operation not permitted
    PermissionDenied(String),
    /// Generic error
    Other(String),
}

impl fmt::Display for AppMeshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppMeshError::RequestFailed { status, message } => {
                write!(f, "HTTP request failed with status {}: {}", status, message)
            }
            AppMeshError::AuthenticationFailed(msg) => write!(f, "Authentication failed: {}", msg),
            AppMeshError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            AppMeshError::NotFound(msg) => write!(f, "Not found: {}", msg),
            AppMeshError::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            AppMeshError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for AppMeshError {}

impl From<reqwest::Error> for AppMeshError {
    fn from(err: reqwest::Error) -> Self {
        AppMeshError::Other(err.to_string())
    }
}

impl From<std::io::Error> for AppMeshError {
    fn from(err: std::io::Error) -> Self {
        AppMeshError::Other(err.to_string())
    }
}

impl From<serde_json::Error> for AppMeshError {
    fn from(err: serde_json::Error) -> Self {
        AppMeshError::Other(err.to_string())
    }
}

impl From<base64::DecodeError> for AppMeshError {
    fn from(err: base64::DecodeError) -> Self {
        AppMeshError::Other(err.to_string())
    }
}