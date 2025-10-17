// lib.rs
//! AppMesh SDK for Rust
//! 
//! This SDK provides a complete interface to interact with AppMesh services,
//! including authentication, application management, and system operations.
//! 
//! For more information about AppMesh, visit:
//! [AppMesh GitHub Repository](https://github.com/laoshanxi/app-mesh)

mod client;
mod models;
mod error;
mod constants;

pub use client::Client;
pub use models::{ClientConfig, AppOutput, AppRun, User, Application, HostResource};
pub use error::AppMeshError;
pub use constants::*;

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
        
        let _client = Client::new(config);
    }
}