// server_wss.rs
// Server SDK implementation for App Mesh (WSS)

use std::sync::Arc;

use crate::client_wss::AppMeshClientWSS;
use crate::error::AppMeshError;
use crate::server_http::AppMeshServer;

/// Server-side helper for applications using WSS transport
pub struct AppMeshServerWSS {
    server: Arc<AppMeshServer>,
}

impl AppMeshServerWSS {
    pub fn new(
        wss_address: Option<(String, u16)>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Arc<Self>, AppMeshError> {
        let client = AppMeshClientWSS::new(wss_address, ssl_verify, ssl_client_cert)?;
        Ok(Arc::new(Self { server: AppMeshServer::with_client(client.client().clone()) }))
    }
}

impl std::ops::Deref for AppMeshServerWSS {
    type Target = AppMeshServer;

    fn deref(&self) -> &Self::Target {
        &self.server
    }
}
