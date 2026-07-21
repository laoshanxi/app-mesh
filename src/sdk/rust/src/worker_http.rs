// worker_http.rs
// Server SDK implementation for App Mesh (HTTP)

use bytes::Bytes;
use http::StatusCode;
use log::{error, warn};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::watch;

use crate::client_http::AppMeshClient;
use crate::error::AppMeshError;
use crate::response_ext::ResponseExt;

/// Server-side helper for applications to fetch tasks and return results.
pub struct AppMeshWorker {
    client: Arc<AppMeshClient>,
    retry_delay: Duration,
    stop_tx: watch::Sender<bool>,
}

impl AppMeshWorker {
    /// Create a new server-side task context backed by the HTTP client.
    pub fn new(
        base_url: Option<String>,
        ssl_verify: Option<String>,
        ssl_client_cert: Option<(String, String)>,
    ) -> Result<Arc<Self>, AppMeshError> {
        let client = AppMeshClient::new(base_url, ssl_verify, ssl_client_cert, None, None, false)?;
        // Server endpoints use APP_MESH_PROCESS_KEY; no JWT refresh needed.
        client.set_auto_refresh_token(false);
        Ok(AppMeshWorker::with_client(client))
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

    /// Create `AppMeshWorker` with a pre-built client.
    pub fn with_client(client: Arc<AppMeshClient>) -> Arc<Self> {
        let (stop_tx, _) = watch::channel(false);
        Arc::new(Self { client, retry_delay: Duration::from_millis(100), stop_tx })
    }

    /// Cancel any in-flight or future `fetch_task` retry loop; a cancelled
    /// `fetch_task` returns `Err(AppMeshError::Cancelled)`.
    pub fn stop(&self) {
        // send_replace updates the value even with no live receivers, so a stop()
        // before/between fetches is still seen by the next fetch_task's borrow check.
        self.stop_tx.send_replace(true);
    }

    /// Fetch a task payload for the current application process.
    ///
    /// Retries until successful. If a request fails within 100ms, sleeps
    /// briefly before retrying; otherwise retries immediately.
    ///
    /// Returns `Err(AppMeshError::ProcessSuperseded)` when the daemon reports
    /// this process key is stale (HTTP 412), and `Err(AppMeshError::Cancelled)`
    /// when [`AppMeshWorker::stop`] is called.
    pub async fn fetch_task(&self) -> Result<Bytes, AppMeshError> {
        use reqwest::Method;
        use tokio::time::sleep;

        let (pkey, app_name) = Self::get_runtime_env()?;
        let path = format!("/appmesh/app/{}/task", app_name);

        let mut query = HashMap::new();
        query.insert("process_key".to_string(), pkey);

        let mut stop_rx = self.stop_tx.subscribe();
        let mut attempts: u32 = 0;
        loop {
            if *stop_rx.borrow() {
                return Err(AppMeshError::Cancelled);
            }
            let attempt_start = Instant::now();
            let result = tokio::select! {
                r = self.client.raw_request(Method::GET, &path, None, None, Some(query.clone()), false) => r,
                _ = stop_rx.changed() => return Err(AppMeshError::Cancelled),
            };
            match result {
                Ok(resp) => {
                    if resp.status() == StatusCode::OK {
                        return Ok(resp.into_bytes());
                    }
                    let status = resp.status();
                    if status == StatusCode::PRECONDITION_FAILED {
                        // Library code must never exit the host process; surface a typed error.
                        error!("Process key mismatch (412): this process has been superseded");
                        return Err(AppMeshError::ProcessSuperseded(
                            "process key mismatch (412): this process has been superseded".into(),
                        ));
                    }
                    warn!("fetch_task attempt {} failed with status {}: retrying...", attempts + 1, status);
                }
                Err(e) => {
                    warn!("fetch_task attempt {} request failed: {}: retrying...", attempts + 1, e);
                }
            }

            attempts += 1;
            if let Some(remaining) = self.retry_delay.checked_sub(attempt_start.elapsed()) {
                tokio::select! {
                    _ = sleep(remaining) => {}
                    _ = stop_rx.changed() => return Err(AppMeshError::Cancelled),
                }
            }
        }
    }

    /// Return the processed result bytes back to App Mesh so the invoker can receive them.
    pub async fn send_task_result(&self, result: &[u8]) -> Result<(), AppMeshError> {
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
            error!("send_task_result failed with status {}: {}", status, text);
            return Err(AppMeshError::RequestFailed { status, message: text });
        }
        Ok(())
    }
}
