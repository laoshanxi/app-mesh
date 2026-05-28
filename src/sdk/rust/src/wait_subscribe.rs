// wait_subscribe.rs
//! Subscribe-based `wait_for_async_run` shared by TCP and WSS transports.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use log::warn;
use tokio::sync::watch;

use crate::client_http::AppMeshClient;
use crate::constants::EVENT_TYPE_DISCONNECTED;
use crate::error::AppMeshError;
use crate::models::{AppEvent, AppRun, Application, OutputHandler};

/// Run an application asynchronously and wait for completion using subscribe.
///
/// Runs the app, then immediately subscribes and backfills output.
/// The split reader/writer transport ensures the demuxer can receive events
/// concurrently with API calls, so EXIT events are not lost.
pub(crate) async fn run_and_wait_subscribe(
    client: &Arc<AppMeshClient>,
    app: &Application,
    max_time: i32,
    lifecycle: i32,
    stdout_handler: OutputHandler,
    timeout: i32,
) -> Result<(AppRun, Option<i32>), AppMeshError> {
    let delivered_until = Arc::new(AtomicI64::new(0));
    let (done_tx, done_rx) = watch::channel(None::<i32>);
    let done_tx = Arc::new(Mutex::new(Some(done_tx)));

    let delivered_until_cb = Arc::clone(&delivered_until);
    let done_tx_cb = Arc::clone(&done_tx);
    let stdout_handler_cb = stdout_handler.clone();

    let on_event: crate::subscribe::EventCallback = Arc::new(move |event: AppEvent| {
        match event.event_type.as_str() {
            "STDOUT" => {
                let pos = event.data.get("position").and_then(|v| v.as_i64()).unwrap_or(0);
                let output = event.data.get("output").and_then(|v| v.as_str()).unwrap_or("");
                if !output.is_empty() {
                    deliver(output.as_bytes(), pos, &delivered_until_cb, &stdout_handler_cb);
                }
            }
            "EXIT" => {
                let code = event.data.get("exit_code").and_then(|v| v.as_i64()).map(|v| v as i32).unwrap_or(-1);
                if let Some(tx) = done_tx_cb.lock().ok().and_then(|mut g| g.take()) {
                    let _ = tx.send(Some(code));
                }
            }
            "REMOVED" => {
                if let Some(tx) = done_tx_cb.lock().ok().and_then(|mut g| g.take()) {
                    let _ = tx.send(Some(-1));
                }
            }
            t if t == EVENT_TYPE_DISCONNECTED => {
                if let Some(tx) = done_tx_cb.lock().ok().and_then(|mut g| g.take()) {
                    let _ = tx.send(Some(-2));
                }
            }
            _ => {}
        }
    });

    // Run the app, then subscribe with specific app_name
    let app_run = client.run_app_async(app, max_time, lifecycle).await?;

    // Subscribe with specific app_name (no wildcard permission needed)
    let sub = client.subscribe(&app_run.app_name, Some(&["STDOUT", "EXIT", "REMOVED"]), Some(on_event)).await?;

    let mut done_rx_owned = done_rx;

    let result = async {
        // Backfill output emitted before subscribe events start flowing
        match client
            .get_app_output(&app_run.app_name, 0, 0, 0, Some(&app_run.proc_uid), Some(0))
            .await
        {
            Ok(backfill) => {
                if !backfill.output.is_empty() {
                    deliver(backfill.output.as_bytes(), 0, &delivered_until, &stdout_handler);
                }
                if let Some(code) = backfill.exit_code {
                    if let Some(tx) = done_tx.lock().ok().and_then(|mut g| g.take()) {
                        let _ = tx.send(Some(code));
                    }
                }
            }
            Err(e) => {
                warn!("backfill failed for {}: {}", app_run.app_name, e);
            }
        }

        // Wait for done signal
        let wait_fut = done_rx_owned.wait_for(|v| v.is_some());
        if timeout > 0 {
            match tokio::time::timeout(std::time::Duration::from_secs(timeout as u64), wait_fut).await {
                Ok(Ok(v)) => *v,
                _ => None,
            }
        } else {
            match wait_fut.await {
                Ok(v) => *v,
                Err(_) => None,
            }
        }
    }
    .await;

    // Cleanup: unsubscribe + delete app (skip delete only for REMOVED sentinel)
    let _ = client.unsubscribe(&sub.subscription_id).await;
    match result {
        Some(-1) => {} // REMOVED — app already gone
        _ => { let _ = client.delete_app(&app_run.app_name).await; }
    }

    Ok((app_run, result))
}

/// Legacy entry point used by `AppMeshClientWSS::wait_for_async_run`.
pub(crate) async fn wait_for_async_run_subscribe(
    client: &Arc<AppMeshClient>,
    run: &AppRun,
    stdout_handler: OutputHandler,
    timeout: i32,
) -> Result<Option<i32>, AppMeshError> {
    let delivered_until = Arc::new(AtomicI64::new(0));
    let (done_tx, done_rx) = watch::channel(None::<i32>);
    let done_tx = Arc::new(Mutex::new(Some(done_tx)));

    let delivered_until_cb = Arc::clone(&delivered_until);
    let done_tx_cb = Arc::clone(&done_tx);
    let stdout_handler_cb = stdout_handler.clone();

    let on_event: crate::subscribe::EventCallback = Arc::new(move |event: AppEvent| {
        match event.event_type.as_str() {
            "STDOUT" => {
                let pos = event.data.get("position").and_then(|v| v.as_i64()).unwrap_or(0);
                let output = event.data.get("output").and_then(|v| v.as_str()).unwrap_or("");
                if !output.is_empty() {
                    deliver(output.as_bytes(), pos, &delivered_until_cb, &stdout_handler_cb);
                }
            }
            "EXIT" => {
                let code = event.data.get("exit_code").and_then(|v| v.as_i64()).map(|v| v as i32).unwrap_or(-1);
                if let Some(tx) = done_tx_cb.lock().ok().and_then(|mut g| g.take()) {
                    let _ = tx.send(Some(code));
                }
            }
            "REMOVED" => {
                if let Some(tx) = done_tx_cb.lock().ok().and_then(|mut g| g.take()) {
                    let _ = tx.send(Some(-1));
                }
            }
            t if t == EVENT_TYPE_DISCONNECTED => {
                if let Some(tx) = done_tx_cb.lock().ok().and_then(|mut g| g.take()) {
                    let _ = tx.send(Some(-2));
                }
            }
            _ => {}
        }
    });

    let sub = client.subscribe(&run.app_name, Some(&["STDOUT", "EXIT", "REMOVED"]), Some(on_event)).await?;

    let mut done_rx_owned = done_rx;

    let result = async {
        match client.get_app_output(&run.app_name, 0, 0, 0, Some(&run.proc_uid), Some(0)).await {
            Ok(backfill) => {
                if !backfill.output.is_empty() {
                    deliver(backfill.output.as_bytes(), 0, &delivered_until, &stdout_handler);
                }
                if let Some(code) = backfill.exit_code {
                    if let Some(tx) = done_tx.lock().ok().and_then(|mut g| g.take()) {
                        let _ = tx.send(Some(code));
                    }
                }
            }
            Err(e) => {
                warn!("backfill failed for {}: {}", run.app_name, e);
            }
        }

        let wait_fut = done_rx_owned.wait_for(|v| v.is_some());
        if timeout > 0 {
            match tokio::time::timeout(std::time::Duration::from_secs(timeout as u64), wait_fut).await {
                Ok(Ok(v)) => *v,
                _ => None,
            }
        } else {
            match wait_fut.await {
                Ok(v) => *v,
                Err(_) => None,
            }
        }
    }
    .await;

    let _ = client.unsubscribe(&sub.subscription_id).await;
    match result {
        Some(-1) => {} // REMOVED — app already gone
        _ => { let _ = client.delete_app(&run.app_name).await; }
    }

    Ok(result)
}

fn deliver(chunk: &[u8], pos: i64, delivered_until: &AtomicI64, stdout_handler: &OutputHandler) {
    if chunk.is_empty() {
        return;
    }
    let end = pos + chunk.len() as i64;

    loop {
        let current = delivered_until.load(Ordering::Acquire);
        if end <= current {
            return;
        }
        if delivered_until
            .compare_exchange(current, end, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            if let Some(ref handler) = stdout_handler {
                let start = if pos < current { (current - pos) as usize } else { 0 };
                let start_pos = if pos < current { current } else { pos };
                let text = String::from_utf8_lossy(&chunk[start..]);
                handler(&text, start_pos);
            }
            return;
        }
    }
}
