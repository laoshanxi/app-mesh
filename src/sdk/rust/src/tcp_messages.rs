// tcp_messages.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for RequestMessage {
    fn default() -> Self {
        Self {
            uuid: String::new(),
            request_uri: String::new(),
            http_method: String::new(),
            client_addr: String::new(),
            body: Vec::new(),
            headers: HashMap::new(),
            query: HashMap::new(),
        }
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for ResponseMessage {
    fn default() -> Self {
        Self {
            uuid: String::new(),
            request_uri: String::new(),
            http_status: 0,
            body_msg_type: String::new(),
            body: Vec::new(),
            headers: HashMap::new(),
        }
    }
}

impl ResponseMessage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Deserialize from MessagePack format
    pub fn deserialize(buf: &[u8]) -> Result<Self, rmp_serde::decode::Error> {
        rmp_serde::from_slice(buf)
    }
}
