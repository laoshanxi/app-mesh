// client_builder.rs
//! Builder pattern for constructing AppMesh clients with better ergonomics and validation

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::client_http::AppMeshClient;
use crate::client_tcp::AppMeshClientTCP;
use crate::client_wss::AppMeshClientWSS;
use crate::constants::*;
use crate::error::AppMeshError;

type Result<T> = std::result::Result<T, AppMeshError>;

/// Builder for creating AppMesh HTTP clients
///
/// # Examples
///
/// ```no_run
/// use appmesh_sdk::ClientBuilder;
///
/// let client = ClientBuilder::new()
///     .url("https://appmesh.example.com:6060")
///     .ssl_ca_cert("/path/to/ca.pem")
///     .cookie_file("/tmp/cookies.txt")
///     .timeout_secs(30)
///     .build()?;
/// ```
#[derive(Default)]
pub struct ClientBuilder {
    url: Option<String>,
    ssl_ca_cert: Option<String>,
    ssl_client_cert: Option<PathBuf>,
    ssl_client_key: Option<PathBuf>,
    cookie_file: Option<String>,
    timeout: Option<Duration>,
}

impl ClientBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the AppMesh server URL
    ///
    /// Default: `https://127.0.0.1:6060`
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Set the SSL CA certificate path for server verification
    ///
    /// Default: `/opt/appmesh/ssl/ca.pem`
    pub fn ssl_ca_cert(mut self, path: impl Into<String>) -> Self {
        self.ssl_ca_cert = Some(path.into());
        self
    }

    /// Set the SSL client certificate for mutual TLS
    pub fn ssl_client_cert(mut self, cert_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_cert = Some(cert_path.into());
        self
    }

    /// Set the SSL client key for mutual TLS
    pub fn ssl_client_key(mut self, key_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_key = Some(key_path.into());
        self
    }

    /// Set both client certificate and key at once
    pub fn ssl_client_auth(mut self, cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_cert = Some(cert_path.into());
        self.ssl_client_key = Some(key_path.into());
        self
    }

    /// Enable cookie persistence to a file
    pub fn cookie_file(mut self, path: impl Into<String>) -> Self {
        self.cookie_file = Some(path.into());
        self
    }

    /// Set request timeout in seconds
    ///
    /// Default: 60 seconds
    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.timeout = Some(Duration::from_secs(secs));
        self
    }

    /// Set request timeout
    ///
    /// Default: 60 seconds
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    /// Validate the configuration before building
    fn validate(&self) -> Result<()> {
        // Validate that if one client cert field is set, both are set
        match (&self.ssl_client_cert, &self.ssl_client_key) {
            (Some(_), None) => {
                return Err(AppMeshError::ConfigurationError("SSL client certificate provided without key".to_string()))
            }
            (None, Some(_)) => {
                return Err(AppMeshError::ConfigurationError("SSL client key provided without certificate".to_string()))
            }
            _ => {}
        }

        // Validate URL if provided
        if let Some(url) = &self.url {
            url::Url::parse(url)
                .map_err(|e| AppMeshError::ConfigurationError(format!("Invalid URL '{}': {}", url, e)))?;
        }

        Ok(())
    }

    /// Build the HTTP client
    pub fn build(self) -> Result<Arc<AppMeshClient>> {
        self.validate()?;

        let url = self.url;
        let ssl_verify = self.ssl_ca_cert;
        let ssl_client_cert = match (self.ssl_client_cert, self.ssl_client_key) {
            (Some(cert), Some(key)) => Some((cert.to_string_lossy().to_string(), key.to_string_lossy().to_string())),
            _ => None,
        };
        let cookie_file = self.cookie_file;

        AppMeshClient::new(url, ssl_verify, ssl_client_cert, cookie_file)
    }
}

/// Builder for creating AppMesh TCP clients
///
/// # Examples
///
/// ```no_run
/// use appmesh_sdk::TcpClientBuilder;
///
/// let client = TcpClientBuilder::new()
///     .address("appmesh.example.com", 6059)
///     .ssl_ca_cert("/path/to/ca.pem")
///     .build()?;
/// ```
#[derive(Default)]
pub struct ClientBuilderTCP {
    host: Option<String>,
    port: Option<u16>,
    ssl_ca_cert: Option<String>,
    ssl_client_cert: Option<PathBuf>,
    ssl_client_key: Option<PathBuf>,
}

impl ClientBuilderTCP {
    /// Create a new TCP client builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the server address
    ///
    /// Default: `127.0.0.1:6059`
    pub fn address(mut self, host: impl Into<String>, port: u16) -> Self {
        self.host = Some(host.into());
        self.port = Some(port);
        self
    }

    /// Set the host (uses default port 6059)
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Set the port (uses default host 127.0.0.1)
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set the SSL CA certificate path
    pub fn ssl_ca_cert(mut self, path: impl Into<String>) -> Self {
        self.ssl_ca_cert = Some(path.into());
        self
    }

    /// Set the SSL client certificate for mutual TLS
    pub fn ssl_client_cert(mut self, cert_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_cert = Some(cert_path.into());
        self
    }

    /// Set the SSL client key for mutual TLS
    pub fn ssl_client_key(mut self, key_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_key = Some(key_path.into());
        self
    }

    /// Set both client certificate and key at once
    pub fn ssl_client_auth(mut self, cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_cert = Some(cert_path.into());
        self.ssl_client_key = Some(key_path.into());
        self
    }

    /// Validate configuration
    fn validate(&self) -> Result<()> {
        match (&self.ssl_client_cert, &self.ssl_client_key) {
            (Some(_), None) => {
                return Err(AppMeshError::ConfigurationError("SSL client certificate provided without key".to_string()))
            }
            (None, Some(_)) => {
                return Err(AppMeshError::ConfigurationError("SSL client key provided without certificate".to_string()))
            }
            _ => {}
        }
        Ok(())
    }

    /// Build the TCP client
    pub fn build(self) -> Result<Arc<AppMeshClientTCP>> {
        self.validate()?;

        let address =
            Some((self.host.unwrap_or_else(|| DEFAULT_TCP_URL.0.to_string()), self.port.unwrap_or(DEFAULT_TCP_URL.1)));

        let ssl_verify = self.ssl_ca_cert;
        let ssl_client_cert = match (self.ssl_client_cert, self.ssl_client_key) {
            (Some(cert), Some(key)) => Some((cert.to_string_lossy().to_string(), key.to_string_lossy().to_string())),
            _ => None,
        };

        AppMeshClientTCP::new(address, ssl_verify, ssl_client_cert)
    }
}

/// Builder for creating AppMesh WSS clients
///
/// # Examples
///
/// ```no_run
/// use appmesh_sdk::ClientBuilderWSS;
///
/// let client = ClientBuilderWSS::new()
///     .address("appmesh.example.com", 6058)
///     .ssl_ca_cert("/path/to/ca.pem")
///     .build()?;
/// ```
#[derive(Default)]
pub struct ClientBuilderWSS {
    host: Option<String>,
    port: Option<u16>,
    ssl_ca_cert: Option<String>,
    ssl_client_cert: Option<PathBuf>,
    ssl_client_key: Option<PathBuf>,
}

impl ClientBuilderWSS {
    /// Create a new WSS client builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the server address
    ///
    /// Default: `127.0.0.1:6058`
    pub fn address(mut self, host: impl Into<String>, port: u16) -> Self {
        self.host = Some(host.into());
        self.port = Some(port);
        self
    }

    /// Set the host (uses default port 6058)
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Set the port (uses default host 127.0.0.1)
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set the SSL CA certificate path
    pub fn ssl_ca_cert(mut self, path: impl Into<String>) -> Self {
        self.ssl_ca_cert = Some(path.into());
        self
    }

    /// Set the SSL client certificate for mutual TLS
    pub fn ssl_client_cert(mut self, cert_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_cert = Some(cert_path.into());
        self
    }

    /// Set the SSL client key for mutual TLS
    pub fn ssl_client_key(mut self, key_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_key = Some(key_path.into());
        self
    }

    /// Set both client certificate and key at once
    pub fn ssl_client_auth(mut self, cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_cert = Some(cert_path.into());
        self.ssl_client_key = Some(key_path.into());
        self
    }

    /// Validate configuration
    fn validate(&self) -> Result<()> {
        match (&self.ssl_client_cert, &self.ssl_client_key) {
            (Some(_), None) => {
                return Err(AppMeshError::ConfigurationError("SSL client certificate provided without key".to_string()))
            }
            (None, Some(_)) => {
                return Err(AppMeshError::ConfigurationError("SSL client key provided without certificate".to_string()))
            }
            _ => {}
        }
        Ok(())
    }

    /// Build the WSS client
    pub fn build(self) -> Result<Arc<AppMeshClientWSS>> {
        self.validate()?;

        // Default WSS port is 6058, whereas TCP was 6059
        let address = Some((self.host.unwrap_or_else(|| "127.0.0.1".to_string()), self.port.unwrap_or(6058)));

        let ssl_verify = self.ssl_ca_cert;
        let ssl_client_cert = match (self.ssl_client_cert, self.ssl_client_key) {
            (Some(cert), Some(key)) => Some((cert.to_string_lossy().to_string(), key.to_string_lossy().to_string())),
            _ => None,
        };

        AppMeshClientWSS::new(address, ssl_verify, ssl_client_cert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_validation() {
        // Should fail: cert without key
        let result = ClientBuilder::new().ssl_client_cert("/path/to/cert.pem").build();
        assert!(result.is_err());

        // Should fail: key without cert
        let result = ClientBuilder::new().ssl_client_key("/path/to/key.pem").build();
        assert!(result.is_err());
    }

    #[test]
    fn test_tcp_builder_validation() {
        let result = ClientBuilderTCP::new().ssl_client_cert("/path/to/cert.pem").build();
        assert!(result.is_err());
    }

    #[test]
    fn test_wss_builder_validation() {
        let result = ClientBuilderWSS::new().ssl_client_cert("/path/to/cert.pem").build();
        assert!(result.is_err());
    }
}
