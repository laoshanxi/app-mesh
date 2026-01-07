// server_tcp.rs
// Server SDK implementation for App Mesh (TCP)

use std::sync::Arc;

use crate::client_tcp::AppMeshClientTCP;
use crate::error::AppMeshError;
use crate::server_http::AppMeshServer;

/// Server-side helper for applications using TCP transport
pub struct AppMeshServerTCP {
    server: Arc<AppMeshServer>,
}

impl AppMeshServerTCP {
    pub fn new(
        tcp_address: Option<(String, u16)>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Arc<Self>, AppMeshError> {
        let client = AppMeshClientTCP::new(tcp_address, ssl_verify, ssl_client_cert)?;
        Ok(Arc::new(Self { server: AppMeshServer::with_client(client.client().clone()) }))
    }
}

impl std::ops::Deref for AppMeshServerTCP {
    type Target = AppMeshServer;

    fn deref(&self) -> &Self::Target {
        &self.server
    }
}
