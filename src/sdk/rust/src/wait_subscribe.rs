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

/// Terminal outcome observed by the event callback. Typed (not sentinel exit
/// codes like -1/-2) so real negative exit codes can never be confused with app
/// removal or transport failure — mirrors the Go SDK's typed errors.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WaitDone {
    Exit(i32),
    MissingExitCode,
    Removed,
    Disconnected,
}

type DoneSender = Arc<Mutex<Option<watch::Sender<Option<WaitDone>>>>>;

fn make_event_callback(
    delivered_until: Arc<AtomicI64>,
    done_tx: DoneSender,
    stdout_handler: OutputHandler,
) -> crate::subscribe::EventCallback {
    Arc::new(move |event: AppEvent| {
        let send_done = |done: WaitDone| {
            // Poisoning is benign here (guarded state stays valid), so recover the guard.
            if let Some(tx) = done_tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
                let _ = tx.send(Some(done));
            }
        };
        match event.event_type.as_str() {
            "STDOUT" => {
                let pos = event.data.get("position").and_then(|v| v.as_i64()).unwrap_or(0);
                let output = event.data.get("output").and_then(|v| v.as_str()).unwrap_or("");
                if !output.is_empty() {
                    deliver(output.as_bytes(), pos, &delivered_until, &stdout_handler);
                }
            }
            "EXIT" => match event.data.get("exit_code").and_then(|v| v.as_i64()) {
                Some(code) => send_done(WaitDone::Exit(code as i32)),
                None => send_done(WaitDone::MissingExitCode),
            },
            "REMOVED" => send_done(WaitDone::Removed),
            t if t == EVENT_TYPE_DISCONNECTED => send_done(WaitDone::Disconnected),
            _ => {}
        }
    })
}

/// Map the observed outcome to the public result and clean up the run app.
///
/// Returns:
/// - `Ok(Some(code))` — process exited (code may be negative for signal kills)
/// - `Ok(None)` — caller-side timeout
/// - `Err(AppMeshError::AppRemoved)` — app removed before EXIT observed
/// - `Err(AppMeshError::TransportDisconnected)` — transport failure
async fn finish(
    client: &AppMeshClient,
    app_name: &str,
    subscription_id: &str,
    result: Option<WaitDone>,
) -> Result<Option<i32>, AppMeshError> {
    // On Disconnected the demuxer is stopped, so skip unsubscribe (it could never
    // get a response — matches the Go SDK). Delete the run app only on a real exit:
    // on timeout/disconnect it may still be running; on REMOVED it is already gone.
    if result != Some(WaitDone::Disconnected) {
        let _ = client.unsubscribe(subscription_id).await;
    }
    if matches!(result, Some(WaitDone::Exit(_)) | Some(WaitDone::MissingExitCode)) {
        let _ = client.delete_app(app_name).await;
    }

    match result {
        Some(WaitDone::Exit(code)) => Ok(Some(code)),
        Some(WaitDone::MissingExitCode) => Err(AppMeshError::Other("EXIT event missing exit_code".into())),
        Some(WaitDone::Removed) => Err(AppMeshError::AppRemoved),
        Some(WaitDone::Disconnected) => Err(AppMeshError::TransportDisconnected),
        None => Ok(None), // timeout
    }
}

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
    let (done_tx, done_rx) = watch::channel(None::<WaitDone>);
    let done_tx: DoneSender = Arc::new(Mutex::new(Some(done_tx)));

    let on_event =
        make_event_callback(Arc::clone(&delivered_until), Arc::clone(&done_tx), stdout_handler.clone());

    // Run the app, then subscribe with specific app_name
    let app_run = client.run_app_async(app, max_time, lifecycle).await?;

    // Subscribe with specific app_name (no wildcard permission needed)
    let sub = client.subscribe(&app_run.app_name, Some(&["STDOUT", "EXIT", "REMOVED"]), Some(on_event)).await?;

    let result = backfill_and_wait(client, &app_run, &delivered_until, &done_tx, &stdout_handler, done_rx, timeout)
        .await;

    let code = finish(client, &app_run.app_name, &sub.subscription_id, result).await?;
    Ok((app_run, code))
}

/// Subscribe-based wait used by `AppMeshClient::wait_for_async_run` on TCP/WSS transports.
pub(crate) async fn wait_for_async_run_subscribe(
    client: &AppMeshClient,
    run: &AppRun,
    stdout_handler: OutputHandler,
    timeout: i32,
) -> Result<Option<i32>, AppMeshError> {
    let delivered_until = Arc::new(AtomicI64::new(0));
    let (done_tx, done_rx) = watch::channel(None::<WaitDone>);
    let done_tx: DoneSender = Arc::new(Mutex::new(Some(done_tx)));

    let on_event =
        make_event_callback(Arc::clone(&delivered_until), Arc::clone(&done_tx), stdout_handler.clone());

    let sub = client.subscribe(&run.app_name, Some(&["STDOUT", "EXIT", "REMOVED"]), Some(on_event)).await?;

    let result =
        backfill_and_wait(client, run, &delivered_until, &done_tx, &stdout_handler, done_rx, timeout).await;

    finish(client, &run.app_name, &sub.subscription_id, result).await
}

/// Backfill output emitted before subscribe events start flowing, then wait for
/// a terminal event (or the caller-side timeout).
async fn backfill_and_wait(
    client: &AppMeshClient,
    run: &AppRun,
    delivered_until: &Arc<AtomicI64>,
    done_tx: &DoneSender,
    stdout_handler: &OutputHandler,
    mut done_rx: watch::Receiver<Option<WaitDone>>,
    timeout: i32,
) -> Option<WaitDone> {
    match client.get_app_output(&run.app_name, 0, 0, 0, Some(&run.proc_uid), Some(0)).await {
        Ok(backfill) => {
            if !backfill.output.is_empty() {
                deliver(backfill.output.as_bytes(), 0, delivered_until, stdout_handler);
            }
            if let Some(code) = backfill.exit_code {
                if let Some(tx) = done_tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
                    let _ = tx.send(Some(WaitDone::Exit(code)));
                }
            }
        }
        Err(e) => {
            warn!("backfill failed for {}: {}", run.app_name, e);
        }
    }

    // Wait for done signal
    let wait_fut = done_rx.wait_for(|v| v.is_some());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::EVENT_TYPE_DISCONNECTED;
    use serde_json::json;

    /// Feed one event through the wait callback and return the observed outcome.
    fn fire(event_type: &str, data: serde_json::Value) -> Option<WaitDone> {
        let (tx, rx) = watch::channel(None::<WaitDone>);
        let done_tx: DoneSender = Arc::new(Mutex::new(Some(tx)));
        let callback = make_event_callback(Arc::new(AtomicI64::new(0)), done_tx, None);
        callback(AppEvent {
            subscription_id: "sub-1".to_string(),
            event_type: event_type.to_string(),
            app_name: "waitapp".to_string(),
            timestamp: 0,
            sequence: 0,
            data,
        });
        let outcome = *rx.borrow();
        outcome
    }

    // Conformance: S6 (partial) — a negative exit code (signal kill, e.g. -2 =
    // SIGINT) classifies as a real exit, never as an error sentinel; see
    // docs/source/SDKContract.md.
    #[test]
    fn conformance_s6_negative_exit_code_is_exit() {
        assert!(matches!(fire("EXIT", json!({"exit_code": -2})), Some(WaitDone::Exit(-2))));
        // A missing exit_code is a distinct outcome, not a fake exit code.
        assert!(matches!(fire("EXIT", json!({})), Some(WaitDone::MissingExitCode)));
    }

    // Conformance: S2 (partial) — the synthetic __disconnected__ event maps to
    // the Disconnected outcome so the wait unblocks; see docs/source/SDKContract.md.
    #[test]
    fn conformance_s2_disconnected_event_classified() {
        assert!(matches!(fire(EVENT_TYPE_DISCONNECTED, serde_json::Value::Null), Some(WaitDone::Disconnected)));
    }
}

fn deliver(chunk: &[u8], pos: i64, delivered_until: &AtomicI64, stdout_handler: &OutputHandler) {
    if chunk.is_empty() {
        return;
    }
    let end = pos + chunk.len() as i64;

    // Live STDOUT events are serialized per subscription by the demuxer, so the
    // CAS loop only arbitrates the backfill (position 0) racing a live event.
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
