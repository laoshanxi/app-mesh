// tls_config.rs
//! Shared TLS type definitions used by TCP and WSS transports.

/// SSL verification configuration
#[derive(Clone, Debug)]
pub enum SslVerify {
    /// Use system/webpki CA store
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
