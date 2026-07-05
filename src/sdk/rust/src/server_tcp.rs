// server_tcp.rs
// Server SDK implementation for App Mesh (TCP)

use std::sync::Arc;

use crate::client_tcp::AppMeshClientTCP;
use crate::error::AppMeshError;
use crate::server_http::AppMeshWorker;

/// Server-side helper for applications using TCP transport
pub struct AppMeshWorkerTCP {
    server: Arc<AppMeshWorker>,
}

impl AppMeshWorkerTCP {
    pub fn new(
        tcp_address: Option<(String, u16)>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Arc<Self>, AppMeshError> {
        let client = AppMeshClientTCP::new(tcp_address, ssl_verify, ssl_client_cert)?;
        // Server endpoints use APP_MESH_PROCESS_KEY; no JWT refresh needed.
        client.client().set_auto_refresh_token(false);
        Ok(Arc::new(Self { server: AppMeshWorker::with_client(client.client().clone()) }))
    }
}

impl std::ops::Deref for AppMeshWorkerTCP {
    type Target = AppMeshWorker;

    fn deref(&self) -> &Self::Target {
        &self.server
    }
}
