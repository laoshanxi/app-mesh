// tls_config.rs
//! Shared TLS type definitions used by TCP and WSS transports.

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;

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

/// Resolve the constructor-level CA option to an [`SslVerify`] mode.
/// `Some(path)` pins a CA file/dir (missing path is a hard error in the transports);
/// `None` (auto) uses the App Mesh CA bundle if installed, else the system/webpki
/// store (matches the Python SDK); `Some("")` is the legacy explicit-disable form.
pub(crate) fn resolve_ssl_verify(
    ssl_verify: Option<String>,
) -> Result<SslVerify, crate::error::AppMeshError> {
    match ssl_verify {
        Some(s) if s.is_empty() => Ok(SslVerify::False),
        Some(path) => Ok(SslVerify::Path(path)),
        None => {
            if std::path::Path::new(crate::constants::DEFAULT_SSL_CA_CERT_PATH).exists() {
                Ok(SslVerify::Path(crate::constants::DEFAULT_SSL_CA_CERT_PATH.to_string()))
            } else {
                Ok(SslVerify::True)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_ca_path_is_legacy_explicit_disable() {
        assert!(matches!(resolve_ssl_verify(Some(String::new())), Ok(SslVerify::False)));
    }
    #[test]
    fn load_private_key_reads_pkcs8_and_sec1() {
        // Keys must load as PrivateKeyDer regardless of PEM encoding, or mutual TLS fails at connect time.
        const PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3LaVdCLGXM4mlGY2
mkgNk37uPSZdkXfcVKzreVKfNOmhRANCAASXmzeuIAcNLhtT0l8OMZUIZYSriby7
YSdAnsxpYaKuG7gII3dhHJcMT0/s/muVW7z2sCoGxJrizXXnRXJ/KTyy
-----END PRIVATE KEY-----";
        const SEC1: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINy2lXQixlzOJpRmNppIDZN+7j0mXZF33FSs63lSnzTpoAoGCCqGSM49
AwEHoUQDQgAEl5s3riAHDS4bU9JfDjGVCGWEq4m8u2EnQJ7MaWGirhu4CCN3YRyX
DE9P7P5rlVu89rAqBsSa4s1150Vyfyk8sg==
-----END EC PRIVATE KEY-----";
        assert!(matches!(load_private_key(PKCS8.as_bytes()), Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(_))));
        assert!(matches!(load_private_key(SEC1.as_bytes()), Ok(rustls::pki_types::PrivateKeyDer::Sec1(_))));
        assert!(load_private_key(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").is_err());
    }
    #[test]
    fn explicit_ca_path_is_pinned() {
        assert!(matches!(resolve_ssl_verify(Some("/x/ca.pem".into())), Ok(SslVerify::Path(p)) if p == "/x/ca.pem"));
    }
    #[test]
    fn auto_never_disables_and_never_errors() {
        // No CA expressed: default bundle if present, else system/webpki roots — verification stays on.
        assert!(matches!(resolve_ssl_verify(None), Ok(SslVerify::Path(_)) | Ok(SslVerify::True)));
    }
}

/// Install the ring rustls crypto provider once per process (reqwest is built
/// with `rustls-no-provider`; without a default, client construction panics).
/// `Err` from `install_default` means the app already installed one — keep it.
pub(crate) fn ensure_crypto_provider() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Client certificate for mutual TLS
#[derive(Clone, Debug)]
pub enum ClientCert {
    /// Single PEM file containing both cert and key
    Single(String),
    /// Separate PEM files for cert and key
    Pair(String, String),
}

/// Certificate verifier that accepts any server certificate.
/// Only reachable via the explicit [`SslVerify::False`] flag; shared by the
/// TCP and WSS transports.
#[derive(Debug)]
pub(crate) struct NoVerifier;

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

/// Load a client certificate chain and private key for mutual TLS.
/// Errors with a message on unreadable/invalid PEM (caller maps it to its own error type).
pub(crate) fn load_client_auth(
    client_cert: &ClientCert,
) -> Result<
    (
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ),
    String,
> {
    let (cert_pem, key_pem) = match client_cert {
        ClientCert::Pair(cert_path, key_path) => (
            std::fs::read(cert_path)
                .map_err(|e| format!("Failed to read client certificate '{}': {}", cert_path, e))?,
            std::fs::read(key_path)
                .map_err(|e| format!("Failed to read client key '{}': {}", key_path, e))?,
        ),
        ClientCert::Single(path) => {
            // Concatenated PEM: parse cert(s) and key from the same file
            let buf = std::fs::read(path)
                .map_err(|e| format!("Failed to read client certificate '{}': {}", path, e))?;
            (buf.clone(), buf)
        }
    };

    let chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<Result<_, _>>()
            .map_err(|e| format!("Invalid client certificate PEM: {}", e))?;
    if chain.is_empty() {
        return Err("Client certificate PEM contains no certificates".into());
    }

    let key = load_private_key(&key_pem)?;

    Ok((chain, key))
}

/// Extract the first unencrypted private key (PKCS#8, PKCS#1 RSA, or SEC1 EC) from PEM bytes.
fn load_private_key(pem: &[u8]) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    use rustls::pki_types::pem::{PemObject, SectionKind};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};

    for item in <(SectionKind, Vec<u8>)>::pem_slice_iter(pem) {
        let (kind, der) = item.map_err(|e| format!("Invalid client key PEM: {}", e))?;
        let key = match kind {
            SectionKind::PrivateKey => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
            SectionKind::RsaPrivateKey => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)),
            SectionKind::EcPrivateKey => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der)),
            _ => continue,
        };
        return Ok(key);
    }
    Err("Client key PEM contains no private key".into())
}
