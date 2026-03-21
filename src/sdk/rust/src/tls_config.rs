// tls_config.rs
//! Shared TLS configuration used by both TCP and WSS transports.

use native_tls::{Certificate, Identity, TlsConnector};
use std::fs;
use std::path::Path;

use crate::error::TransportError;

/// SSL verification configuration
#[derive(Clone, Debug)]
pub enum SslVerify {
    /// Use system CA store
    True,
    /// Disable verification (insecure — development only)
    False,
    /// Custom CA file or directory of PEM files
    Path(String),
}

/// Client certificate for mutual TLS
#[derive(Clone, Debug)]
pub enum ClientCert {
    /// Single PEM file containing both cert and key
    Single(String),
    /// Separate PEM files for cert and key
    Pair(String, String),
}

/// Build a `native_tls::TlsConnector` from the given SSL configuration.
///
/// This is the single source of truth for TLS setup across TCP and WSS transports.
pub fn build_tls_connector(
    ssl_verify: &SslVerify,
    ssl_client_cert: Option<&ClientCert>,
) -> Result<TlsConnector, TransportError> {
    let mut builder = TlsConnector::builder();

    match ssl_verify {
        SslVerify::True => {} // system defaults
        SslVerify::False => {
            builder.danger_accept_invalid_certs(true);
            builder.danger_accept_invalid_hostnames(true);
        }
        SslVerify::Path(path) => {
            let p = Path::new(path);
            if p.is_file() {
                let bytes = fs::read(p).map_err(|e| TransportError::ConfigError(e.to_string()))?;
                let cert =
                    Certificate::from_pem(&bytes).map_err(|e| TransportError::ConfigError(e.to_string()))?;
                builder.add_root_certificate(cert);
            } else if p.is_dir() {
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
                // Path not found, skip verification
                builder.danger_accept_invalid_certs(true);
                builder.danger_accept_invalid_hostnames(true);
            }
        }
    }

    if let Some(cert) = ssl_client_cert {
        match cert {
            ClientCert::Single(path) => {
                let pem = fs::read(path).map_err(|e| TransportError::ConfigError(e.to_string()))?;
                let identity =
                    Identity::from_pkcs8(&pem, &pem).map_err(|e: native_tls::Error| TransportError::ConfigError(e.to_string()))?;
                builder.identity(identity);
            }
            ClientCert::Pair(cert_path, key_path) => {
                let cert_pem =
                    fs::read(cert_path).map_err(|e| TransportError::ConfigError(e.to_string()))?;
                let key_pem =
                    fs::read(key_path).map_err(|e| TransportError::ConfigError(e.to_string()))?;
                let identity = Identity::from_pkcs8(&cert_pem, &key_pem)
                    .map_err(|e| TransportError::ConfigError(e.to_string()))?;
                builder.identity(identity);
            }
        }
    }

    builder.build().map_err(TransportError::from)
}
