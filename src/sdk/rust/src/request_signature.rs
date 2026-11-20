// request_signature.rs
//! HMAC-SHA256 request signing (anti-tamper layer).
//!
//! Mirrors the daemon's `src/daemon/security/RequestSignature.cpp` byte-for-byte;
//! the canonical string is, per `docs/source/Security.md` ("Request replay
//! protection and signatures"):
//!
//! ```text
//! METHOD + "\n" + path + "\n" + sortedQuery + "\n" + sha256hex(body) + "\n"
//! + timestamp + "\n" + nonce
//! ```
//!
//! - `path`: the request path without the query, exactly as sent (not
//!   percent-decoded). The WSS data-channel file routes sign the route WITHOUT
//!   the trailing `/ws` — the suffix selects the transfer channel, not the
//!   signed resource (daemon `canonicalFileRoute`).
//! - `sortedQuery`: decoded `key=value` pairs joined with `&`, sorted by key
//!   then value; an empty query is an empty string.
//! - `sha256hex(body)`: lowercase hex SHA-256 of the raw body bytes; a request
//!   without a body hashes the empty string.
//! - Streamed file endpoints (`/appmesh/file/download|upload|delete` and their
//!   `/ws` side-channel variants) sign the empty string in place of the body
//!   hash (documented exemption: the signature binds method, path, query,
//!   timestamp, and nonce, but not the file content).
//!
//! The signature is an integrity layer on top of bearer authentication — it
//! does not replace the bearer token. Signing is opt-in: install a
//! [`RequestSigner`] on a client with `set_request_signer` (or the
//! `request_signer` builder method).

use crate::constants::{
    HTTP_HEADER_KEY_X_NONCE, HTTP_HEADER_KEY_X_REQUEST_KEY, HTTP_HEADER_KEY_X_SIGNATURE, HTTP_HEADER_KEY_X_TIMESTAMP,
};
use crate::error::AppMeshError;
use ring::hmac::{self, Key};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// HMAC-SHA256 request signer for one API key (key id + secret).
///
/// The secret is kept in memory only, never exposed through `Debug`, and never
/// logged by this crate. Create one per principal API key and install it on the
/// HTTP, TCP, or WSS client:
///
/// ```no_run
/// use appmesh::{ClientBuilder, RequestSigner};
///
/// let signer = RequestSigner::new("ak-3f9c2a81b0d4", "the-secret-once-issued")?;
/// let client = ClientBuilder::new()
///     .url("https://127.0.0.1:6060")
///     .request_signer(signer)
///     .build()?;
/// # Ok::<(), appmesh::AppMeshError>(())
/// ```
#[derive(Clone)]
pub struct RequestSigner {
    key_id: String,
    secret: String,
}

impl std::fmt::Debug for RequestSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the secret, not even in debug dumps.
        f.debug_struct("RequestSigner").field("key_id", &self.key_id).finish()
    }
}

impl RequestSigner {
    /// Create a signer for `key_id` with the secret issued by
    /// `POST /appmesh/security/apikeys` (returned exactly once). An empty key
    /// id or secret is rejected here (same wording as the sibling SDKs) instead
    /// of producing a signer whose every request would 401.
    pub fn new(key_id: impl Into<String>, secret: impl Into<String>) -> Result<Self, AppMeshError> {
        let key_id = key_id.into();
        let secret = secret.into();
        if key_id.trim().is_empty() {
            return Err(AppMeshError::ConfigurationError("key_id must be a non-empty string".into()));
        }
        if secret.is_empty() {
            return Err(AppMeshError::ConfigurationError("secret must be a non-empty string".into()));
        }
        Ok(Self { key_id, secret })
    }

    /// The API key id sent as `X-Request-Key`.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// HMAC-SHA256 over `canonical` with the key secret, lowercase hex
    /// (same construction as the daemon's `RequestSignature::sign`).
    pub fn sign(&self, canonical: &str) -> String {
        let key = Key::new(hmac::HMAC_SHA256, self.secret.as_bytes());
        let tag = hmac::sign(&key, canonical.as_bytes());
        hex_encode(tag.as_ref())
    }

    /// Constant-time verification of a lowercase-hex signature over
    /// `canonical` (mirrors the daemon's `Utility::secureCompare` check).
    pub fn verify(&self, canonical: &str, signature_hex: &str) -> bool {
        let Some(signature) = hex_decode(signature_hex) else { return false };
        let key = Key::new(hmac::HMAC_SHA256, self.secret.as_bytes());
        hmac::verify(&key, canonical.as_bytes(), &signature).is_ok()
    }

    /// The four signature headers for a request: `X-Request-Key`,
    /// `X-Timestamp` (unix seconds), `X-Nonce` (fresh uuid4 hex), and
    /// `X-Signature`. `body` hashes per the file-endpoint exemption.
    pub fn sign_request(
        &self,
        method: &str,
        path: &str,
        query: Option<&HashMap<String, String>>,
        body: Option<&[u8]>,
    ) -> HashMap<String, String> {
        let nonce = new_nonce();
        self.sign_request_with_nonce(method, path, query, body, &nonce)
    }

    /// [`RequestSigner::sign_request`] with a caller-supplied nonce (the TCP
    /// and WSS transports reuse the framed message uuid, which the daemon also
    /// uses as the replay-protection nonce).
    pub fn sign_request_with_nonce(
        &self,
        method: &str,
        path: &str,
        query: Option<&HashMap<String, String>>,
        body: Option<&[u8]>,
        nonce: &str,
    ) -> HashMap<String, String> {
        let body_sha256_hex = Self::body_sha256_hex(path, body);
        self.sign_request_with_body_hash(method, path, query, &body_sha256_hex, nonce)
    }

    /// The four signature headers over a precomputed body hash. Used by the
    /// streaming HTTP path, where the body is not buffered for hashing.
    pub fn sign_request_with_body_hash(
        &self,
        method: &str,
        path: &str,
        query: Option<&HashMap<String, String>>,
        body_sha256_hex: &str,
        nonce: &str,
    ) -> HashMap<String, String> {
        let timestamp = unix_timestamp();
        let sorted_query = canonical_query(query.unwrap_or(&HashMap::new()));
        let canonical =
            canonical_string(method, canonical_signing_path(path), &sorted_query, body_sha256_hex, &timestamp, nonce);
        let signature = self.sign(&canonical);

        let mut headers = HashMap::with_capacity(4);
        headers.insert(HTTP_HEADER_KEY_X_REQUEST_KEY.to_string(), self.key_id.clone());
        headers.insert(HTTP_HEADER_KEY_X_TIMESTAMP.to_string(), timestamp);
        headers.insert(HTTP_HEADER_KEY_X_NONCE.to_string(), nonce.to_string());
        headers.insert(HTTP_HEADER_KEY_X_SIGNATURE.to_string(), signature);
        headers
    }

    /// Lowercase hex SHA-256 of the body bytes with the file/stream-endpoint
    /// exemption applied: the streamed file and SSE endpoints always sign the
    /// empty string, regardless of the actual body.
    pub fn body_sha256_hex(path: &str, body: Option<&[u8]>) -> String {
        if is_file_endpoint(path) || is_stream_endpoint(path) {
            return sha256_hex(b"");
        }
        sha256_hex(body.unwrap_or(&[]))
    }
}

/// Signed-query form of the canonical string: decoded `k=v` pairs joined with
/// `&`, sorted by key then value. Byte-wise ordering, like the daemon's
/// `RequestSignature::canonicalQuery`.
pub fn canonical_query(query: &HashMap<String, String>) -> String {
    let mut pairs: Vec<(&String, &String)> = query.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(b.1)));
    let mut canonical = String::new();
    for (key, value) in pairs {
        if !canonical.is_empty() {
            canonical.push('&');
        }
        canonical.push_str(key);
        canonical.push('=');
        canonical.push_str(value);
    }
    canonical
}

/// Build the exact string-to-sign. Both sides (client and daemon) must
/// construct this byte-for-byte.
pub fn canonical_string(
    method: &str,
    path: &str,
    sorted_query: &str,
    body_sha256_hex: &str,
    timestamp: &str,
    nonce: &str,
) -> String {
    // Same layout/reserve pattern as the daemon's canonicalString().
    let mut canonical = String::with_capacity(
        method.len() + path.len() + sorted_query.len() + body_sha256_hex.len() + timestamp.len() + nonce.len() + 6,
    );
    canonical.push_str(method);
    canonical.push('\n');
    canonical.push_str(path);
    canonical.push('\n');
    canonical.push_str(sorted_query);
    canonical.push('\n');
    canonical.push_str(body_sha256_hex);
    canonical.push('\n');
    canonical.push_str(timestamp);
    canonical.push('\n');
    canonical.push_str(nonce);
    canonical
}

/// Lowercase hex SHA-256 digest of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&Sha256::digest(data))
}

/// The streamed file endpoints sign the empty string in place of the body
/// hash. The set matches the daemon's file-hardening routes (including the
/// WSS HTTPS side-channel variants).
pub fn is_file_endpoint(path: &str) -> bool {
    matches!(
        path,
        "/appmesh/file/download" | "/appmesh/file/upload" | "/appmesh/file/delete" | "/appmesh/file/download/ws"
            | "/appmesh/file/upload/ws"
    )
}

/// The streamed SSE endpoints (`GET .../output/stream`, `POST .../task/stream`)
/// sign the empty string in place of the body hash, like the streamed file
/// endpoints (docs/source/Streaming.md, "Limits and scope").
pub fn is_stream_endpoint(path: &str) -> bool {
    path.starts_with("/appmesh/app/") && (path.ends_with("/output/stream") || path.ends_with("/task/stream"))
}

/// The canonical path the daemon signs: the trailing "/ws" of the WSS HTTPS
/// data-channel file routes selects the transfer channel, not the signed
/// resource, so it is dropped (the daemon's
/// `RequestHardening::canonicalFileRoute`; docs/source/Security.md, "Request
/// replay protection and signatures"). Every other path passes through.
pub fn canonical_signing_path(path: &str) -> &str {
    match path {
        "/appmesh/file/download/ws" => "/appmesh/file/download",
        "/appmesh/file/upload/ws" => "/appmesh/file/upload",
        other => other,
    }
}

/// Percent-only wire encoding of the query (space → `%20`, never `+`): the
/// daemon decodes `%XX` but keeps a literal `+` untouched, so the daemon-visible
/// decoded values must equal the values that were signed. Mirrors the Python
/// SDK's `request_signature.encode_query`. Returns `None` for an empty query.
pub fn encode_query(query: &HashMap<String, String>) -> Option<String> {
    if query.is_empty() {
        return None;
    }
    let mut encoded = String::new();
    for (key, value) in query {
        if !encoded.is_empty() {
            encoded.push('&');
        }
        percent_encode_into(&mut encoded, key);
        encoded.push('=');
        percent_encode_into(&mut encoded, value);
    }
    Some(encoded)
}

/// Append `value` percent-encoded, keeping only unreserved characters
/// (letters, digits and `-._~`) literal — the exact set Python's
/// `urllib.parse.quote(safe='')` keeps. Uppercase hex digits, like Python's
/// `quote` and Go's `url.QueryEscape`.
fn percent_encode_into(out: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            _ => {
                out.push('%');
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0x0F) as usize] as char);
            }
        }
    }
}

/// Fresh per-request nonce: uuid4 in hex form (no dashes).
pub(crate) fn new_nonce() -> String {
    Uuid::new_v4().simple().to_string()
}

/// Whether a 401 may spend the single-use refresh token: only an unsigned request
/// (bearer problem) or an `invalid_token` challenge qualifies; a signature failure
/// must not burn the session.
pub(crate) fn should_refresh_on_unauthorized(signed: bool, www_authenticate: Option<&str>) -> bool {
    !signed || www_authenticate.is_some_and(|v| v.contains("invalid_token"))
}

/// Unix time in seconds, as the `X-Timestamp` string.
pub(crate) fn unix_timestamp() -> String {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().to_string()
}

/// Sign a framed TCP/WSS request message in place: the four signature headers
/// go into the message header map, and the framed message uuid serves as the
/// nonce (the daemon uses the same uuid for replay protection). Called after
/// method, path, query, body, and headers are populated.
pub(crate) fn sign_wire_message(signer: &RequestSigner, message: &mut crate::wire_messages::RequestMessage) {
    let nonce = message.uuid.clone();
    let headers = signer.sign_request_with_nonce(
        message.http_method.as_str(),
        message.request_uri.as_str(),
        Some(&message.query),
        Some(&message.body),
        &nonce,
    );
    for (key, value) in headers {
        message.headers.insert(key, value);
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Decode lowercase-or-uppercase hex; `None` on odd length or non-hex input.
// Not is_multiple_of: that needs Rust 1.87 and this crate declares no MSRV
// (same reasoning as the existing allow in client_http.rs).
#[allow(clippy::manual_is_multiple_of)]
fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() % 2 != 0 {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Daemon test vector (test/security/request_hardening.cpp): the empty-body
    // hash and the exact canonical layout are pinned by the server side.
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn sha256_hex_empty_body_known_answer() {
        assert_eq!(sha256_hex(b""), EMPTY_SHA256);
        // And a non-empty body hashes its raw bytes.
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn canonical_string_is_exact_and_stable() {
        let canonical = canonical_string("GET", "/appmesh/applications", "a=1&b=2", EMPTY_SHA256, "1000", "nonce-1");
        assert_eq!(canonical, format!("GET\n/appmesh/applications\na=1&b=2\n{}\n1000\nnonce-1", EMPTY_SHA256));
    }

    #[test]
    fn canonical_query_sorts_by_key_then_value() {
        let mut query = HashMap::new();
        query.insert("b".to_string(), "2".to_string());
        query.insert("a".to_string(), "1".to_string());
        assert_eq!(canonical_query(&query), "a=1&b=2");

        // Same key, several values: sorted by value.
        let mut repeated = HashMap::new();
        repeated.insert("k".to_string(), "z".to_string());
        assert_eq!(canonical_query(&repeated), "k=z");

        // Byte-wise ordering: uppercase sorts before lowercase, '10' before '9'.
        let mut mixed = HashMap::new();
        mixed.insert("B".to_string(), "1".to_string());
        mixed.insert("a".to_string(), "1".to_string());
        mixed.insert("n".to_string(), "10".to_string());
        mixed.insert("m".to_string(), "9".to_string());
        assert_eq!(canonical_query(&mixed), "B=1&a=1&m=9&n=10");

        // Empty query is an empty string.
        assert_eq!(canonical_query(&HashMap::new()), "");
    }

    #[test]
    fn sign_matches_openssl_known_answer_vector() {
        // openssl dgst -sha256 -hmac 'test-secret' over the canonical string
        // below produces this digest; pins key handling and hex encoding.
        let signer = RequestSigner::new("ak-test", "test-secret").expect("signer");
        let canonical = canonical_string("GET", "/appmesh/applications", "a=1&b=2", EMPTY_SHA256, "1000", "nonce-1");
        assert_eq!(signer.sign(&canonical), "6e48966b712f5b5e762f3d934b9cdd8d103ab889c238d84c2098e32093e860c2");
    }

    #[test]
    fn sign_verify_roundtrip_and_rejection() {
        let signer = RequestSigner::new("ak-test", "test-secret").expect("signer");
        let canonical = canonical_string("PUT", "/appmesh/app/example", "k=v", EMPTY_SHA256, "1700000000", "abc123");
        let signature = signer.sign(&canonical);

        assert!(signer.verify(&canonical, &signature));
        // Tampered canonical string is rejected.
        let tampered = canonical_string("DELETE", "/appmesh/app/example", "k=v", EMPTY_SHA256, "1700000000", "abc123");
        assert!(!signer.verify(&tampered, &signature));
        // Wrong secret is rejected.
        assert!(!RequestSigner::new("ak-test", "other-secret").expect("signer").verify(&canonical, &signature));
        // Malformed signature values are rejected, not mis-parsed.
        assert!(!signer.verify(&canonical, "not-hex-!!"));
        assert!(!signer.verify(&canonical, ""));
    }

    #[test]
    fn file_endpoints_sign_the_empty_string_body_hash() {
        let body = b"file-bytes";
        let body_hash = sha256_hex(body);
        assert_ne!(body_hash, EMPTY_SHA256);

        for path in ["/appmesh/file/download", "/appmesh/file/upload", "/appmesh/file/delete", "/appmesh/file/upload/ws"] {
            assert_eq!(RequestSigner::body_sha256_hex(path, Some(body)), EMPTY_SHA256, "{} must sign empty", path);
            assert_eq!(RequestSigner::body_sha256_hex(path, None), EMPTY_SHA256);
        }
        // A non-file endpoint hashes the actual body; no body hashes "".
        assert_eq!(RequestSigner::body_sha256_hex("/appmesh/app/example", Some(body)), body_hash);
        assert_eq!(RequestSigner::body_sha256_hex("/appmesh/app/example", None), EMPTY_SHA256);
    }

    #[test]
    fn stream_endpoints_sign_the_empty_string_body_hash() {
        // The SSE task stream signs the empty string despite its payload body
        // (docs/source/Streaming.md); the buffered stdin route hashes its real body.
        let body = b"task-payload";
        let body_hash = sha256_hex(body);
        assert_eq!(RequestSigner::body_sha256_hex("/appmesh/app/agent/output/stream", None), EMPTY_SHA256);
        assert_eq!(RequestSigner::body_sha256_hex("/appmesh/app/agent/task/stream", Some(body)), EMPTY_SHA256);
        assert_eq!(RequestSigner::body_sha256_hex("/appmesh/app/chat/input", Some(body)), body_hash);
    }

    #[test]
    fn ws_data_channel_routes_sign_the_stripped_path() {
        // The trailing "/ws" selects the WSS transfer channel, not the signed
        // resource: the canonical signing path drops it (daemon
        // canonicalFileRoute, docs/source/Security.md).
        assert_eq!(canonical_signing_path("/appmesh/file/download/ws"), "/appmesh/file/download");
        assert_eq!(canonical_signing_path("/appmesh/file/upload/ws"), "/appmesh/file/upload");
        assert_eq!(canonical_signing_path("/appmesh/file/download"), "/appmesh/file/download");
        assert_eq!(canonical_signing_path("/appmesh/file/delete"), "/appmesh/file/delete");
        assert_eq!(canonical_signing_path("/appmesh/applications"), "/appmesh/applications");

        let signer = RequestSigner::new("ak-ws", "test-secret").expect("signer");
        let ws = signer.sign_request("GET", "/appmesh/file/download/ws", None, Some(b"file-bytes"));
        let timestamp = ws.get(HTTP_HEADER_KEY_X_TIMESTAMP).expect("timestamp").clone();
        let nonce = ws.get(HTTP_HEADER_KEY_X_NONCE).expect("nonce").clone();
        let signature = ws.get(HTTP_HEADER_KEY_X_SIGNATURE).expect("signature");
        // Signs exactly as the stripped route with the empty-body hash — even
        // though a body was supplied.
        let expected = signer.sign(&canonical_string(
            "GET",
            "/appmesh/file/download",
            "",
            EMPTY_SHA256,
            &timestamp,
            &nonce,
        ));
        assert_eq!(signature, &expected);
    }

    #[test]
    fn encode_query_is_percent_only() {
        // Space → %20 (never '+'), everything outside the unreserved set is
        // encoded; the daemon's %-only decode returns exactly the signed values.
        let mut query = HashMap::new();
        query.insert("q".to_string(), "two words".to_string());
        query.insert("name".to_string(), "a&b=c".to_string());
        let encoded = encode_query(&query).expect("non-empty query encodes");
        assert!(!encoded.contains('+'), "no '+' may appear: {}", encoded);
        assert!(encoded.contains("q=two%20words"), "got: {}", encoded);
        assert!(encoded.contains("name=a%26b%3Dc"), "got: {}", encoded);

        // Round-trip with a %-only decode (the daemon's rule): the decoded map
        // must equal the signed map.
        let mut decoded = HashMap::new();
        for pair in encoded.split('&') {
            let (k, v) = pair.split_once('=').expect("key=value");
            decoded.insert(percent_decode_only(k), percent_decode_only(v));
        }
        assert_eq!(decoded, query);

        assert_eq!(encode_query(&HashMap::new()), None);
    }

    /// %-only decode for the round-trip check (a minimal mirror of the daemon).
    fn percent_decode_only(value: &str) -> String {
        let bytes = value.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push(((hi << 4) | lo) as u8);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn sign_request_attaches_the_four_headers() {
        let signer = RequestSigner::new("ak-3f9c2a81b0d4", "test-secret").expect("signer");
        let body = br#"{"command":"echo hi"}"#;
        let mut query = HashMap::new();
        query.insert("b".to_string(), "2".to_string());
        query.insert("a".to_string(), "1".to_string());

        let headers = signer.sign_request("PUT", "/appmesh/app/example", Some(&query), Some(body));

        assert_eq!(headers.len(), 4);
        assert_eq!(headers.get(HTTP_HEADER_KEY_X_REQUEST_KEY).unwrap(), "ak-3f9c2a81b0d4");
        let timestamp = headers.get(HTTP_HEADER_KEY_X_TIMESTAMP).unwrap();
        assert!(timestamp.chars().all(|c| c.is_ascii_digit()), "timestamp must be unix seconds");
        let nonce = headers.get(HTTP_HEADER_KEY_X_NONCE).unwrap();
        assert_eq!(nonce.len(), 32, "nonce is uuid4 hex");
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
        let signature = headers.get(HTTP_HEADER_KEY_X_SIGNATURE).unwrap();
        assert_eq!(signature.len(), 64);
        assert!(!signature.bytes().any(|b| b.is_ascii_uppercase()), "signature is lowercase hex");

        // The signature verifies against the canonical string rebuilt from the
        // same signed material.
        let canonical = canonical_string(
            "PUT",
            "/appmesh/app/example",
            &canonical_query(&query),
            &sha256_hex(body),
            timestamp,
            nonce,
        );
        assert!(signer.verify(&canonical, signature));

        // Two calls never reuse a nonce (replay protection).
        let second = signer.sign_request("PUT", "/appmesh/app/example", Some(&query), Some(body));
        assert_ne!(second.get(HTTP_HEADER_KEY_X_NONCE).unwrap(), nonce);
    }

    #[test]
    fn sign_wire_message_fills_framed_request_headers() {
        use crate::wire_messages::RequestMessage;

        let signer = RequestSigner::new("ak-wire", "test-secret").expect("signer");
        let mut message = RequestMessage::new();
        message.uuid = "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string();
        message.http_method = "PUT".to_string();
        message.request_uri = "/appmesh/app/example".to_string();
        message.query.insert("a".to_string(), "1".to_string());
        message.body = br#"{"command":"echo"}"#.to_vec();

        sign_wire_message(&signer, &mut message);

        assert_eq!(message.headers.get(HTTP_HEADER_KEY_X_REQUEST_KEY).unwrap(), "ak-wire");
        // The framed uuid doubles as the nonce.
        assert_eq!(message.headers.get(HTTP_HEADER_KEY_X_NONCE).unwrap(), &message.uuid);
        let signature = message.headers.get(HTTP_HEADER_KEY_X_SIGNATURE).unwrap().clone();
        let timestamp = message.headers.get(HTTP_HEADER_KEY_X_TIMESTAMP).unwrap().clone();

        let canonical = canonical_string(
            "PUT",
            "/appmesh/app/example",
            "a=1",
            &sha256_hex(&message.body),
            &timestamp,
            &message.uuid,
        );
        assert!(signer.verify(&canonical, &signature));
    }

    #[test]
    fn debug_never_renders_the_secret() {
        let signer = RequestSigner::new("ak-debug", "super-secret-value").expect("signer");
        let rendered = format!("{:?}", signer);
        assert!(rendered.contains("ak-debug"));
        assert!(!rendered.contains("super-secret-value"));
    }

    #[test]
    fn new_rejects_empty_key_id_or_secret() {
        assert!(RequestSigner::new("ak-test", "test-secret").is_ok());
        assert!(RequestSigner::new("", "test-secret").is_err());
        assert!(RequestSigner::new("ak-test", "").is_err());
    }

    #[test]
    fn cross_language_golden_signature_vectors() {
        // The same five vectors are pinned by the daemon C++, Go, Java,
        // JavaScript, and Python test suites; path/query are the wire-encoded
        // forms fed straight into the canonical layer (fixed timestamp and
        // nonce, so no time window is involved).
        let vectors: &[(&str, &str, &str, &[u8], &str, &str, &str)] = &[
            (
                "GET",
                "/appmesh/app/100%25",
                "",
                b"",
                "1700000000",
                "nonce-golden-0001",
                "1036298fce978dab3ca5393a17c8dbeafcd22e8394585a96ce5a60ad39694d8c",
            ),
            (
                "GET",
                "/appmesh/app/list",
                "flag=true&name=dh-bot",
                b"",
                "1700000001",
                "nonce-golden-0002",
                "0c9287088c6ca609fad7436f3f4646451faa8e180733e28e10e4eee11f34a9c5",
            ),
            (
                "POST",
                "/appmesh/file/download",
                "",
                b"",
                "1700000002",
                "nonce-golden-0003",
                "dea6aa318b1fc84f8ffaadc859e4b36a90a9d6c5619f737dd037c78e5d17ac7d",
            ),
            (
                "GET",
                "/appmesh/app/%E4%B8%AD%E6%96%87",
                "a=1%26b%3D2",
                b"",
                "1700000003",
                "nonce-golden-0004",
                "6cf618bfb9264d61d5b23dbaa42d366f59054bce99b9addab3253f98aaadb0ab",
            ),
            (
                "POST",
                "/appmesh/appmesh/run",
                "",
                b"{\"command\":\"echo hi\"}",
                "1700000004",
                "nonce-golden-0005",
                "0a8de849eda2abf6389d40f11299aaf09e7b440615a6ee0c7e01012a92a1f876",
            ),
        ];
        let signer = RequestSigner::new("ak-golden", "golden-secret").expect("signer");
        for (method, path, query, body, timestamp, nonce, expected) in vectors {
            let canonical = canonical_string(method, path, query, &sha256_hex(body), timestamp, nonce);
            assert_eq!(signer.sign(&canonical), *expected, "vector {nonce}");
        }
    }

    #[test]
    fn unauthorized_refresh_gate_is_bearer_blame_only() {
        // Unsigned 401s always justify a refresh; a signed 401 only when the
        // server pins the blame on the bearer (invalid_token challenge).
        assert!(should_refresh_on_unauthorized(false, None));
        assert!(should_refresh_on_unauthorized(false, Some("Basic")));
        assert!(!should_refresh_on_unauthorized(true, None));
        assert!(!should_refresh_on_unauthorized(true, Some("Bearer error=\"invalid_request\"")));
        assert!(should_refresh_on_unauthorized(true, Some("Bearer error=\"invalid_token\"")));
    }
}
