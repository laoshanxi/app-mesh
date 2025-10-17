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
}





