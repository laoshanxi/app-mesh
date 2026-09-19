// response_ext.rs

use crate::error::AppMeshError;
use bytes::Bytes;
use serde::de::DeserializeOwned;

/// Extension trait for working with `http::Response<Bytes>`.
///
/// `text()` and `json()` take `&self` so callers can inspect headers
/// before (or after) reading the body — no need to clone the header map.
/// `into_bytes()` is the only consuming method.
pub trait ResponseExt {
    /// Reads the response body as UTF-8 text. Invalid bytes become U+FFFD;
    /// the text is never converted to a local code page.
    fn text(&self) -> Result<String, AppMeshError>;

    /// Deserializes the response body as JSON.
    fn json<T: DeserializeOwned>(&self) -> Result<T, AppMeshError>;

    /// Consumes the response and returns the raw body bytes.
    fn into_bytes(self) -> Bytes;

    /// Returns a reference to the body bytes without consuming the response.
    fn bytes(&self) -> &Bytes;
}

impl ResponseExt for http::Response<Bytes> {
    fn bytes(&self) -> &Bytes {
        self.body()
    }

    fn into_bytes(self) -> Bytes {
        self.into_body()
    }

    fn text(&self) -> Result<String, AppMeshError> {
        // Always UTF-8 (ADR 0010 C2): no local code page conversion.
        Ok(String::from_utf8_lossy(self.body()).into_owned())
    }

    fn json<T: DeserializeOwned>(&self) -> Result<T, AppMeshError> {
        let body = self.body();

        if body.is_empty() {
            return Err(AppMeshError::SerializationError("Empty response body".to_string()));
        }

        serde_json::from_slice::<T>(body).map_err(|e| {
            let preview_len = body.len().min(100);
            let preview = String::from_utf8_lossy(&body[..preview_len]);
            AppMeshError::SerializationError(format!(
                "Failed to deserialize JSON: {}. Body preview: {}",
                e, preview
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_ext_bytes() {
        let body = Bytes::from("test body");
        let response = http::Response::builder().status(200).body(body.clone()).unwrap();
        assert_eq!(response.bytes(), &body);
    }

    #[test]
    fn test_response_ext_into_bytes() {
        let body = Bytes::from("test body");
        let response = http::Response::builder().status(200).body(body.clone()).unwrap();
        assert_eq!(response.into_bytes(), body);
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
        // ADR 0010 C2: UTF-8 text passes through unchanged on every platform,
        // including Windows with a non-UTF-8 local code page.
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
        let body = Bytes::from(vec![0xFF, 0xFE, 0xFD]);
        let response = http::Response::builder().status(200).body(body).unwrap();

        let text = response.text();
        assert!(text.is_ok());
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
}
