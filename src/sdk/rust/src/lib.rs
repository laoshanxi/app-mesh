// lib.rs
//! AppMesh SDK for Rust

mod client_http;
mod constants;
mod error;
mod models;
mod persistent_jar;

pub use client_http::AppMeshClient;
pub use constants::*;
pub use error::AppMeshError;
pub use models::{AppOutput, AppRun, Application, ClientConfig, User};
pub use persistent_jar::PersistentJar;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let config = ClientConfig {
            url: "https://127.0.0.1:6060".to_string(),
            ssl_verify: None,
            ssl_client_cert: None,
            ssl_client_key: None,
            cookie_file: None,
        };

        let _client = AppMeshClient::new(config);
    }
}
