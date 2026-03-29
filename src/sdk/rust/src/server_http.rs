// server_http.rs
// Server SDK implementation for App Mesh (HTTP)

use bytes::Bytes;
use http::StatusCode;
use log::{error, warn};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use crate::client_http::AppMeshClient;
use crate::error::AppMeshError;
use crate::response_ext::ResponseExt;

/// Server-side helper for applications to fetch tasks and return results.
pub struct AppMeshServer {
    client: Arc<AppMeshClient>,
    retry_delay: Duration,
}

impl AppMeshServer {
    /// Create a new server-side task context backed by the HTTP client.
    pub fn new(
        rest_url: Option<String>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Arc<Self>, AppMeshError> {
        let client = AppMeshClient::new(rest_url, ssl_verify, ssl_client_cert, None, None, false)?;
        Ok(AppMeshServer::with_client(client))
    }

    fn get_runtime_env() -> Result<(String, String), AppMeshError> {
        let process_key = env::var("APP_MESH_PROCESS_KEY").map_err(|_| {
            AppMeshError::ConfigurationError(
                "Missing environment variable: APP_MESH_PROCESS_KEY. This must be set by App Mesh service.".into(),
            )
        })?;
        let app_name = env::var("APP_MESH_APPLICATION_NAME").map_err(|_| {
            AppMeshError::ConfigurationError(
                "Missing environment variable: APP_MESH_APPLICATION_NAME. This must be set by App Mesh service."
                    .into(),
            )
        })?;
        Ok((process_key, app_name))
    }

    /// Create `AppMeshServer` with a pre-built client.
    pub fn with_client(client: Arc<AppMeshClient>) -> Arc<Self> {
        Arc::new(Self { client, retry_delay: Duration::from_millis(100) })
    }

    /// Fetch a task payload for the current application process.
    ///
    /// Retries indefinitely until successful. If a request fails within 100ms,
    /// sleeps briefly before retrying; otherwise retries immediately.
    pub async fn task_fetch(&self) -> Result<Bytes, AppMeshError> {
        use reqwest::Method;
        use tokio::time::sleep;

        let (pkey, app_name) = Self::get_runtime_env()?;
        let path = format!("/appmesh/app/{}/task", app_name);

        let mut query = HashMap::new();
        query.insert("process_key".to_string(), pkey);

        let mut attempts: u32 = 0;
        loop {
            let attempt_start = Instant::now();
            match self.client.raw_request(Method::GET, &path, None, None, Some(query.clone()), false).await {
                Ok(resp) => {
                    if resp.status() == StatusCode::OK {
                        return Ok(resp.into_bytes());
                    }
                    let status = resp.status();
                    let text = resp.text()?;
                    warn!("task_fetch attempt {} failed with status {}: retrying...", attempts + 1, status);
                    let _ = (status, text);
                }
                Err(e) => {
                    warn!("task_fetch attempt {} request failed: {}: retrying...", attempts + 1, e);
                }
            }

            attempts += 1;
            if let Some(remaining) = self.retry_delay.checked_sub(attempt_start.elapsed()) {
                sleep(remaining).await;
            }
        }
    }

    /// Return the processed result bytes back to App Mesh so the invoker can receive them.
    pub async fn task_return(&self, result: &[u8]) -> Result<(), AppMeshError> {
        use reqwest::Method;

        let (pkey, app_name) = Self::get_runtime_env()?;
        let path = format!("/appmesh/app/{}/task", app_name);

        let mut query = HashMap::new();
        query.insert("process_key".to_string(), pkey);

        let resp =
            self.client.raw_request(Method::PUT, &path, Some(result), None, Some(query), false).await?;

        let status = resp.status();
        if status != StatusCode::OK {
            let text = resp.text()?;
            error!("task_return failed with status {}: {}", status, text);
            return Err(AppMeshError::RequestFailed { status, message: text });
        }
        Ok(())
    }
}
