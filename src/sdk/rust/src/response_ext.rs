// response_ext.rs

use crate::error::AppMeshError;
use bytes::Bytes;
use encoding_rs::{Encoding, UTF_8};
use http;
use serde::de::DeserializeOwned;
use serde_json;

/// Extension trait for working with `http::Response<Bytes>`.
pub trait ResponseExt {
    /// Extracts the response body as `Bytes`.
    fn bytes(self) -> Bytes;

    /// Reads the response body as UTF-8 text with charset detection from Content-Type.
    /// On Windows, converts UTF-8 to local encoding if needed.
    fn text(self) -> Result<String, AppMeshError>;

    /// Deserializes the response body as JSON.
    fn json<T: DeserializeOwned>(self) -> Result<T, AppMeshError>;
}

impl ResponseExt for http::Response<Bytes> {
    fn bytes(self) -> Bytes {
        self.into_body()
    }

    fn text(self) -> Result<String, AppMeshError> {
        #[cfg(unix)]
        {
            // Unix/Linux: Simple UTF-8 with lossy fallback
            let body = self.into_body();

            // Try UTF-8 first
            String::from_utf8(body.to_vec()).or_else(|_| Ok(String::from_utf8_lossy(&body).into_owned()))
        }

        #[cfg(windows)]
        {
            // Windows: Handle local encoding conversion
            let status = self.status();
            let headers = self.headers().clone();
            let body = self.into_body();

            // Extract charset from Content-Type header
            let charset = extract_charset_from_content_type(&headers);

            // Decode with detected or default charset
            let mut text = decode_with_charset(&body, charset)?;

            // Windows-specific encoding conversion for UTF-8 text/plain responses
            if status == http::StatusCode::OK && is_utf8_text_content(&headers) {
                if let Some(local_encoding) = get_local_encoding() {
                    // Only convert if local encoding is not UTF-8
                    if !is_utf8_encoding(&local_encoding) {
                        if let Some(converted) = convert_utf8_to_local(&text, &local_encoding) {
                            text = converted;
                        }
                    }
                }
            }

            Ok(text)
        }
    }

    fn json<T: DeserializeOwned>(self) -> Result<T, AppMeshError> {
        let body = self.into_body();

        if body.is_empty() {
            return Err(AppMeshError::SerializationError("Empty response body".to_string()));
        }

        serde_json::from_slice::<T>(&body).map_err(|e| {
            let preview_len = body.len().min(100);
            let preview = String::from_utf8_lossy(&body[..preview_len]);
            AppMeshError::SerializationError(format!("Failed to deserialize JSON: {}. Body preview: {}", e, preview))
        })
    }
}

/// Extract charset from Content-Type header (e.g., "text/plain; charset=utf-8")
#[cfg(windows)]
fn extract_charset_from_content_type(headers: &http::HeaderMap) -> Option<&'static Encoding> {
    headers.get(http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).and_then(|content_type| {
        // Look for charset parameter
        content_type.split(';').find_map(|part| {
            let part = part.trim();
            if part.starts_with("charset=") {
                let charset = part["charset=".len()..].trim();
                Encoding::for_label(charset.as_bytes())
            } else {
                None
            }
        })
    })
}

/// Check if Content-Type indicates UTF-8 text (matching Python logic)
#[cfg(windows)]
fn is_utf8_text_content(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|content_type| {
            let content_type_lower = content_type.to_lowercase();
            content_type_lower.contains("text/plain") && content_type_lower.contains("utf-8")
        })
        .unwrap_or(false)
}

/// Decode bytes with specified charset, fallback to UTF-8 lossy
#[cfg(windows)]
fn decode_with_charset(bytes: &[u8], charset: Option<&'static Encoding>) -> Result<String, AppMeshError> {
    let encoding = charset.unwrap_or(UTF_8);

    // Try to decode with the specified encoding
    let (decoded, encoding_used, had_errors) = encoding.decode(bytes);

    if had_errors {
        // If there were errors, try UTF-8 first
        if encoding_used != UTF_8 {
            if let Ok(utf8_str) = String::from_utf8(bytes.to_vec()) {
                return Ok(utf8_str);
            }
        }
        // Fall back to lossy UTF-8 conversion
        Ok(String::from_utf8_lossy(bytes).into_owned())
    } else {
        Ok(decoded.into_owned())
    }
}

/// Get local/system encoding (Windows-specific)
#[cfg(target_os = "windows")]
fn get_local_encoding() -> Option<&'static Encoding> {
    use windows::Win32::Globalization::GetACP;

    // Get the system's ANSI code page
    let code_page = unsafe { GetACP() };

    // Map common Windows code pages to encoding_rs encodings
    match code_page {
        936 => Some(encoding_rs::GBK),           // Simplified Chinese
        950 => Some(encoding_rs::BIG5),          // Traditional Chinese
        932 => Some(encoding_rs::SHIFT_JIS),     // Japanese
        949 => Some(encoding_rs::EUC_KR),        // Korean
        1252 => Some(encoding_rs::WINDOWS_1252), // Western European
        1251 => Some(encoding_rs::WINDOWS_1251), // Cyrillic
        1250 => Some(encoding_rs::WINDOWS_1250), // Central European
        1254 => Some(encoding_rs::WINDOWS_1254), // Turkish
        1253 => Some(encoding_rs::WINDOWS_1253), // Greek
        1255 => Some(encoding_rs::WINDOWS_1255), // Hebrew
        1256 => Some(encoding_rs::WINDOWS_1256), // Arabic
        1257 => Some(encoding_rs::WINDOWS_1257), // Baltic
        1258 => Some(encoding_rs::WINDOWS_1258), // Vietnamese
        874 => Some(encoding_rs::WINDOWS_874),   // Thai
        _ => None,                               // Unknown or UTF-8 (65001)
    }
}

/// Check if encoding name represents UTF-8
#[cfg(windows)]
fn is_utf8_encoding(encoding: &Encoding) -> bool {
    encoding == UTF_8
}

/// Convert UTF-8 string to local encoding (for Windows compatibility)
#[cfg(windows)]
fn convert_utf8_to_local(utf8_text: &str, local_encoding: &'static Encoding) -> Option<String> {
    // Encode UTF-8 string to local encoding bytes
    let (encoded_bytes, _, had_errors) = local_encoding.encode(utf8_text);

    if had_errors {
        return None;
    }

    // Decode back to string using the same encoding (to simulate Python's behavior)
    let (decoded, _, decode_errors) = local_encoding.decode(&encoded_bytes);

    if decode_errors {
        None
    } else {
        Some(decoded.into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_ext_bytes() {
        let body = Bytes::from("test body");
        let response = http::Response::builder().status(200).body(body.clone()).unwrap();

        let extracted = response.bytes();
        assert_eq!(extracted, body);
    }

    #[test]
    fn test_response_ext_text_utf8() {
        let body = Bytes::from("test body");
        let response = http::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(body)
            .unwrap();

        let text = response.text();
        assert!(text.is_ok());
        assert_eq!(text.unwrap(), "test body");
    }

    #[test]
    fn test_response_ext_text_utf8_with_unicode() {
        let body = Bytes::from("Hello, 世界!");
        let response = http::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(body)
            .unwrap();

        let text = response.text();
        assert!(text.is_ok());
        assert_eq!(text.unwrap(), "Hello, 世界!");
    }

    #[test]
    fn test_response_ext_text_invalid_utf8() {
        // Invalid UTF-8 sequence - should fall back to lossy conversion
        let body = Bytes::from(vec![0xFF, 0xFE, 0xFD]);
        let response = http::Response::builder().status(200).body(body).unwrap();

        let text = response.text();
        assert!(text.is_ok());
        // Lossy conversion replaces invalid bytes with replacement character
        assert!(text.unwrap().contains('�'));
    }

    #[test]
    fn test_response_ext_json() {
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        struct TestData {
            message: String,
            code: i32,
        }

        let test_data = TestData { message: "success".to_string(), code: 200 };
        let json_str = serde_json::to_string(&test_data).unwrap();
        let body = Bytes::from(json_str);

        let response = http::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(body)
            .unwrap();

        let parsed: Result<TestData, _> = response.json();
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap(), test_data);
    }

    #[test]
    fn test_response_ext_json_empty() {
        let body = Bytes::new();
        let response = http::Response::builder().status(200).body(body).unwrap();

        let parsed: Result<serde_json::Value, _> = response.json();
        assert!(parsed.is_err());
        if let Err(AppMeshError::SerializationError(msg)) = parsed {
            assert!(msg.contains("Empty response body"));
        } else {
            panic!("Expected SerializationError for empty body");
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_charset_extraction() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("text/plain; charset=utf-8"));

        let charset = extract_charset_from_content_type(&headers);
        assert!(charset.is_some());
        assert_eq!(charset.unwrap(), encoding_rs::UTF_8);
    }

    #[cfg(windows)]
    #[test]
    fn test_is_utf8_text_content() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("text/plain; charset=utf-8"));

        assert!(is_utf8_text_content(&headers));
    }

    #[cfg(windows)]
    #[test]
    fn test_decode_with_charset() {
        let utf8_bytes = "Hello, 世界!".as_bytes();
        let result = decode_with_charset(utf8_bytes, Some(encoding_rs::UTF_8));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Hello, 世界!");
    }
}
