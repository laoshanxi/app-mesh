// server_wss.rs
// Server SDK implementation for App Mesh (WSS)

use std::sync::Arc;

use crate::client_wss::AppMeshClientWSS;
use crate::error::AppMeshError;
use crate::server_http::AppMeshWorker;

/// Server-side helper for applications using WSS transport
pub struct AppMeshWorkerWSS {
    server: Arc<AppMeshWorker>,
}

impl AppMeshWorkerWSS {
    pub fn new(
        wss_address: Option<(String, u16)>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Arc<Self>, AppMeshError> {
        let client = AppMeshClientWSS::new(wss_address, ssl_verify, ssl_client_cert)?;
        // Server endpoints use APP_MESH_PROCESS_KEY; no JWT refresh needed.
        client.client().set_auto_refresh_token(false);
        Ok(Arc::new(Self { server: AppMeshWorker::with_client(client.client().clone()) }))
    }
}

impl std::ops::Deref for AppMeshWorkerWSS {
    type Target = AppMeshWorker;

    fn deref(&self) -> &Self::Target {
        &self.server
    }
}
