// client_builder.rs
//! Builder pattern for constructing AppMesh clients with better ergonomics and validation.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::client_http::AppMeshClient;
use crate::client_tcp::AppMeshClientTCP;
use crate::client_wss::AppMeshClientWSS;
use crate::constants::*;
use crate::error::AppMeshError;

type Result<T> = std::result::Result<T, AppMeshError>;

/// Builder for creating AppMesh HTTP clients.
///
/// # Examples
///
/// ```no_run
/// use appmesh::ClientBuilder;
///
/// let client = ClientBuilder::new()
///     .url("https://appmesh.example.com:6060")
///     .ssl_ca_cert("/path/to/ca.pem")
///     .cookie_file("/tmp/cookies.txt")
///     .timeout_secs(30)
///     .build()?;
/// # Ok::<(), appmesh::AppMeshError>(())
/// ```
#[derive(Default)]
pub struct ClientBuilder {
    url: Option<String>,
    ssl_ca_cert: Option<String>,
    ssl_client_cert: Option<PathBuf>,
    ssl_client_key: Option<PathBuf>,
    cookie_file: Option<String>,
    jwt_token: Option<String>,
    timeout: Option<Duration>,
    danger_accept_invalid_certs: bool,
    auto_refresh_token: bool,
}

impl ClientBuilder {
    /// Create a builder for the HTTP/HTTPS App Mesh client.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the AppMesh server URL (default: `https://127.0.0.1:6060`).
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Set the SSL CA certificate path (default: `/opt/appmesh/ssl/ca.pem`).
    pub fn ssl_ca_cert(mut self, path: impl Into<String>) -> Self {
        self.ssl_ca_cert = Some(path.into());
        self
    }

    /// Set the SSL client certificate for mutual TLS.
    pub fn ssl_client_cert(mut self, cert_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_cert = Some(cert_path.into());
        self
    }

    /// Set the SSL client key for mutual TLS.
    pub fn ssl_client_key(mut self, key_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_key = Some(key_path.into());
        self
    }

    /// Set both client certificate and key at once.
    pub fn ssl_client_auth(mut self, cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_cert = Some(cert_path.into());
        self.ssl_client_key = Some(key_path.into());
        self
    }

    /// Disable SSL certificate verification (insecure — development only).
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.danger_accept_invalid_certs = accept;
        self
    }

    /// Enable automatic JWT token refresh before expiration.
    ///
    /// When enabled, a background tokio task periodically checks the token's
    /// `exp` claim and calls `renew_token` ~30 seconds before it expires.
    /// Call [`AppMeshClient::schedule_token_refresh`] after login to start
    /// the refresh loop, or it will be started automatically after the first
    /// successful login.
    pub fn auto_refresh_token(mut self, enable: bool) -> Self {
        self.auto_refresh_token = enable;
        self
    }

    /// Set a JWT token directly without server verification (no network call).
    pub fn jwt_token(mut self, token: impl Into<String>) -> Self {
        self.jwt_token = Some(token.into());
        self
    }

    /// Enable cookie persistence to a file.
    pub fn cookie_file(mut self, path: impl Into<String>) -> Self {
        self.cookie_file = Some(path.into());
        self
    }

    /// Set request timeout in seconds (default: 60).
    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.timeout = Some(Duration::from_secs(secs));
        self
    }

    /// Set request timeout (default: 60 seconds).
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    fn validate(&self) -> Result<()> {
        match (&self.ssl_client_cert, &self.ssl_client_key) {
            (Some(_), None) => {
                return Err(AppMeshError::ConfigurationError(
                    "SSL client certificate provided without key".into(),
                ))
            }
            (None, Some(_)) => {
                return Err(AppMeshError::ConfigurationError(
                    "SSL client key provided without certificate".into(),
                ))
            }
            _ => {}
        }

        if let Some(url) = &self.url {
            url::Url::parse(url)
                .map_err(|e| AppMeshError::ConfigurationError(format!("Invalid URL '{}': {}", url, e)))?;
        }

        Ok(())
    }

    /// Build the HTTP client.
    ///
    /// If `jwt_token()` was provided, the token is attached locally without a verification request.
    /// If `auto_refresh_token(true)` was set, refresh is enabled but still requires a successful
    /// login (or another stored token) before the refresh loop can do useful work.
    pub fn build(self) -> Result<Arc<AppMeshClient>> {
        self.validate()?;

        let ssl_client_cert = match (self.ssl_client_cert, self.ssl_client_key) {
            (Some(cert), Some(key)) => {
                Some((cert.to_string_lossy().to_string(), key.to_string_lossy().to_string()))
            }
            _ => None,
        };

        let client = AppMeshClient::new(
            self.url,
            self.ssl_ca_cert,
            ssl_client_cert,
            self.cookie_file,
            self.timeout,
            self.danger_accept_invalid_certs,
        )?;

        if let Some(token) = &self.jwt_token {
            client.set_token(token);
        }

        if self.auto_refresh_token {
            client.set_auto_refresh_token(true);
        }

        Ok(client)
    }
}

/// Builder for creating AppMesh TCP clients.
///
/// # Examples
///
/// ```no_run
/// use appmesh::ClientBuilderTCP;
///
/// let client = ClientBuilderTCP::new()
///     .address("appmesh.example.com", 6059)
///     .ssl_ca_cert("/path/to/ca.pem")
///     .build()?;
/// # Ok::<(), appmesh::AppMeshError>(())
/// ```
#[derive(Default)]
pub struct ClientBuilderTCP {
    host: Option<String>,
    port: Option<u16>,
    ssl_ca_cert: Option<String>,
    ssl_client_cert: Option<PathBuf>,
    ssl_client_key: Option<PathBuf>,
    danger_accept_invalid_certs: bool,
}

impl ClientBuilderTCP {
    /// Create a builder for the TCP transport client.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the server address (default: `127.0.0.1:6059`).
    pub fn address(mut self, host: impl Into<String>, port: u16) -> Self {
        self.host = Some(host.into());
        self.port = Some(port);
        self
    }

    /// Set the TCP host (default: `127.0.0.1`).
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Set the TCP port (default: `6059`).
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn ssl_ca_cert(mut self, path: impl Into<String>) -> Self {
        self.ssl_ca_cert = Some(path.into());
        self
    }

    pub fn ssl_client_cert(mut self, cert_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_cert = Some(cert_path.into());
        self
    }

    pub fn ssl_client_key(mut self, key_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_key = Some(key_path.into());
        self
    }

    pub fn ssl_client_auth(mut self, cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_cert = Some(cert_path.into());
        self.ssl_client_key = Some(key_path.into());
        self
    }

    /// Disable all TLS certificate verification (insecure — development/testing only).
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.danger_accept_invalid_certs = accept;
        self
    }

    fn validate(&self) -> Result<()> {
        match (&self.ssl_client_cert, &self.ssl_client_key) {
            (Some(_), None) => {
                return Err(AppMeshError::ConfigurationError(
                    "SSL client certificate provided without key".into(),
                ))
            }
            (None, Some(_)) => {
                return Err(AppMeshError::ConfigurationError(
                    "SSL client key provided without certificate".into(),
                ))
            }
            _ => {}
        }
        Ok(())
    }

    pub fn build(self) -> Result<Arc<AppMeshClientTCP>> {
        self.validate()?;

        let address = Some((
            self.host.unwrap_or_else(|| DEFAULT_TCP_HOST.to_string()),
            self.port.unwrap_or(DEFAULT_TCP_PORT),
        ));
        let ssl_client_cert = match (self.ssl_client_cert, self.ssl_client_key) {
            (Some(cert), Some(key)) => {
                Some((cert.to_string_lossy().to_string(), key.to_string_lossy().to_string()))
            }
            _ => None,
        };

        // When danger_accept_invalid_certs is set, pass an empty string to signal
        // SslVerify::False in the transport layer.
        let ssl_ca_cert = if self.danger_accept_invalid_certs {
            Some(String::new())
        } else {
            self.ssl_ca_cert
        };

        AppMeshClientTCP::new(address, ssl_ca_cert, ssl_client_cert)
    }
}

/// Builder for creating AppMesh WSS clients.
///
/// # Examples
///
/// ```no_run
/// use appmesh::ClientBuilderWSS;
///
/// let client = ClientBuilderWSS::new()
///     .address("appmesh.example.com", 6058)
///     .ssl_ca_cert("/path/to/ca.pem")
///     .build()?;
/// # Ok::<(), appmesh::AppMeshError>(())
/// ```
#[derive(Default)]
pub struct ClientBuilderWSS {
    host: Option<String>,
    port: Option<u16>,
    ssl_ca_cert: Option<String>,
    ssl_client_cert: Option<PathBuf>,
    ssl_client_key: Option<PathBuf>,
    danger_accept_invalid_certs: bool,
}

impl ClientBuilderWSS {
    /// Create a builder for the WSS transport client.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the server address (default: `127.0.0.1:6058`).
    pub fn address(mut self, host: impl Into<String>, port: u16) -> Self {
        self.host = Some(host.into());
        self.port = Some(port);
        self
    }

    /// Set the WSS host (default: `127.0.0.1`).
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Set the WSS port (default: `6058`).
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn ssl_ca_cert(mut self, path: impl Into<String>) -> Self {
        self.ssl_ca_cert = Some(path.into());
        self
    }

    pub fn ssl_client_cert(mut self, cert_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_cert = Some(cert_path.into());
        self
    }

    pub fn ssl_client_key(mut self, key_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_key = Some(key_path.into());
        self
    }

    pub fn ssl_client_auth(mut self, cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        self.ssl_client_cert = Some(cert_path.into());
        self.ssl_client_key = Some(key_path.into());
        self
    }

    /// Disable all TLS certificate verification (insecure — development/testing only).
    pub fn danger_accept_invalid_certs(mut self, accept: bool) -> Self {
        self.danger_accept_invalid_certs = accept;
        self
    }

    fn validate(&self) -> Result<()> {
        match (&self.ssl_client_cert, &self.ssl_client_key) {
            (Some(_), None) => {
                return Err(AppMeshError::ConfigurationError(
                    "SSL client certificate provided without key".into(),
                ))
            }
            (None, Some(_)) => {
                return Err(AppMeshError::ConfigurationError(
                    "SSL client key provided without certificate".into(),
                ))
            }
            _ => {}
        }
        Ok(())
    }

    pub fn build(self) -> Result<Arc<AppMeshClientWSS>> {
        self.validate()?;

        let address = Some((
            self.host.unwrap_or_else(|| DEFAULT_TCP_HOST.to_string()),
            self.port.unwrap_or(DEFAULT_WSS_PORT),
        ));
        let ssl_client_cert = match (self.ssl_client_cert, self.ssl_client_key) {
            (Some(cert), Some(key)) => {
                Some((cert.to_string_lossy().to_string(), key.to_string_lossy().to_string()))
            }
            _ => None,
        };

        // When danger_accept_invalid_certs is set, pass an empty string to signal
        // SslVerify::False in the transport layer.
        let ssl_ca_cert = if self.danger_accept_invalid_certs {
            Some(String::new())
        } else {
            self.ssl_ca_cert
        };

        AppMeshClientWSS::new(address, ssl_ca_cert, ssl_client_cert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_validation_cert_without_key() {
        let result = ClientBuilder::new().ssl_client_cert("/path/to/cert.pem").build();
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_validation_key_without_cert() {
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
