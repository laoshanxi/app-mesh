use appmesh::AppMeshClientWSS;
use std::sync::Arc;
use tokio::task::JoinHandle;

static CLEANUP_APP: std::sync::Mutex<Option<(Arc<AppMeshClientWSS>, String)>> =
    std::sync::Mutex::new(None);
static CLEANUP_HANDLE: std::sync::Mutex<Option<JoinHandle<()>>> = std::sync::Mutex::new(None);

pub fn register_cleanup(client: Arc<AppMeshClientWSS>, app_name: String) {
    // Cancel previous cleanup task
    if let Ok(mut handle) = CLEANUP_HANDLE.lock() {
        if let Some(h) = handle.take() {
            h.abort();
        }
    }

    if let Ok(mut guard) = CLEANUP_APP.lock() {
        *guard = Some((client, app_name));
    }

    let handle = tokio::spawn(async move {
        // Use tokio's signal handling — works reliably within the async runtime
        #[cfg(unix)]
        {
            let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .expect("failed to register SIGINT handler");
            sig.recv().await;
        }
        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c().await.ok();
        }

        let pair = { CLEANUP_APP.lock().ok().and_then(|mut guard| guard.take()) };
        if let Some((client, app_name)) = pair {
            // Bound the cleanup so a stuck connection can never block the exit.
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                client.delete_app(&app_name),
            )
            .await;
        }
        std::process::exit(130);
    });

    if let Ok(mut h) = CLEANUP_HANDLE.lock() {
        *h = Some(handle);
    }
}

pub fn clear_cleanup() {
    if let Ok(mut handle) = CLEANUP_HANDLE.lock() {
        if let Some(h) = handle.take() {
            h.abort();
        }
    }
    if let Ok(mut guard) = CLEANUP_APP.lock() {
        *guard = None;
    }
}
