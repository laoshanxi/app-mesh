// wire_messages.rs
//! MessagePack wire protocol messages (`RequestMessage`/`ResponseMessage`)
//! shared by both the TCP and WSS transports.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::constants::HTTP_HEADER_CONTENT_TYPE;
use crate::error::AppMeshError;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestMessage {
    #[serde(default)]
    pub uuid: String,

    #[serde(default)]
    pub request_uri: String,

    #[serde(default)]
    pub http_method: String,

    #[serde(default)]
    pub client_addr: String,

    #[serde(default, with = "serde_bytes")]
    pub body: Vec<u8>,

    #[serde(default)]
    pub headers: HashMap<String, String>,

    #[serde(default)]
    pub query: HashMap<String, String>,
}

impl RequestMessage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialize to MessagePack format with struct-as-map encoding
    /// This matches Python's msgpack.packb(self.__dict__, use_bin_type=True)
    pub fn serialize(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> {
        let mut buf = Vec::new();
        {
            // Use struct_map mode to serialize as a map with string keys
            // This matches Python's dictionary serialization
            let mut serializer = rmp_serde::Serializer::new(&mut buf).with_struct_map();
            use serde::Serialize;
            Serialize::serialize(self, &mut serializer)?;
        }
        Ok(buf)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseMessage {
    #[serde(default)]
    pub uuid: String,

    #[serde(default)]
    pub request_uri: String,

    #[serde(default)]
    pub http_status: i32,

    #[serde(default)]
    pub body_msg_type: String,

    #[serde(default, with = "serde_bytes")]
    pub body: Vec<u8>,

    #[serde(default)]
    pub headers: HashMap<String, String>,
}

impl ResponseMessage {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Deserialize from MessagePack format
    pub fn deserialize(buf: &[u8]) -> Result<Self, rmp_serde::decode::Error> {
        rmp_serde::from_slice(buf)
    }

    /// Convert this transport-level response into an `http::Response` (shared by TCP/WSS).
    pub(crate) fn into_http_response(self) -> Result<http::Response<Bytes>, AppMeshError> {
        let mut builder = http::Response::builder().status(self.http_status as u16);
        for (k, v) in &self.headers {
            builder = builder.header(k, v);
        }
        if !self.body_msg_type.is_empty() && !self.headers.contains_key(HTTP_HEADER_CONTENT_TYPE) {
            builder = builder.header(HTTP_HEADER_CONTENT_TYPE, &self.body_msg_type);
        }
        Ok(builder.body(Bytes::from(self.body)).expect("Building http::Response should not fail"))
    }
}
