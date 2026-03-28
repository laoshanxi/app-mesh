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

/// Default maximum number of retries for `task_fetch` before giving up.
const DEFAULT_MAX_RETRIES: u32 = 0; // 0 = unlimited (original behavior)

/// Server-side helper for applications to fetch tasks and return results.
pub struct AppMeshServer {
    client: Arc<AppMeshClient>,
    retry_delay: Duration,
    max_retries: u32,
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
        Arc::new(Self { client, retry_delay: Duration::from_millis(100), max_retries: DEFAULT_MAX_RETRIES })
    }

    /// Create AppMeshServer with a pre-built client and custom retry settings.
    pub fn with_client_and_retries(client: Arc<AppMeshClient>, max_retries: u32, retry_delay: Duration) -> Arc<Self> {
        Arc::new(Self { client, retry_delay, max_retries })
    }

    /// Fetch a task payload for the current application process.
    ///
    /// Retries on non-OK responses up to `max_retries` times (0 = unlimited).
    pub async fn task_fetch(&self) -> Result<Bytes, AppMeshError> {
        use reqwest::Method;
        use tokio::time::sleep;

        let (pkey, app_name) = Self::get_runtime_env()?;
        let path = format!("/appmesh/app/{}/task", app_name);

        let mut query = HashMap::new();
        query.insert("process_key".to_string(), pkey);

        let mut attempts: u32 = 0;
        let mut last_status = None;
        let mut last_message: Option<String>;
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
                    last_status = Some(status);
                    last_message = Some(text);
                }
                Err(e) => {
                    warn!("task_fetch attempt {} request failed: {}: retrying...", attempts + 1, e);
                    last_message = Some(e.to_string());
                }
            }

            attempts += 1;
            if self.max_retries > 0 && attempts >= self.max_retries {
                return Err(AppMeshError::RequestFailed {
                    status: last_status.unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                    message: last_message.unwrap_or_else(|| format!("task_fetch failed after {} retries", attempts)),
                });
            }

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
