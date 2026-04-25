// wait_subscribe.rs
//! Subscribe-based `wait_for_async_run` shared by TCP and WSS transports.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use log::warn;
use tokio::sync::watch;

use crate::client_http::AppMeshClient;
use crate::constants::EVENT_TYPE_DISCONNECTED;
use crate::error::AppMeshError;
use crate::models::{AppRun, AppEvent};

/// Subscribe-based wait: subscribes to STDOUT+EXIT+REMOVED, backfills via
/// `get_app_output(position=0)`, deduplicates by position offset, and waits
/// for completion or timeout. `timeout=0` means wait indefinitely.
pub(crate) async fn wait_for_async_run_subscribe(
    client: &Arc<AppMeshClient>,
    run: &AppRun,
    timeout: i32,
    print_stdout: bool,
) -> Result<Option<i32>, AppMeshError> {
    let delivered_until = Arc::new(AtomicI64::new(0));
    // watch channel: None = not done, Some(code) = done with exit code.
    // watch stores the last sent value — no lost notifications.
    let (done_tx, done_rx) = watch::channel(None::<i32>);
    let done_tx = Arc::new(Mutex::new(Some(done_tx)));

    let delivered_until_cb = Arc::clone(&delivered_until);
    let done_tx_cb = Arc::clone(&done_tx);

    let on_event: crate::subscribe::EventCallback = Arc::new(move |event: AppEvent| {
        match event.event_type.as_str() {
            "STDOUT" => {
                let pos = event.data.get("position")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let output = event.data.get("output")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !output.is_empty() {
                    deliver(
                        output.as_bytes(),
                        pos,
                        &delivered_until_cb,
                        print_stdout,
                    );
                }
            }
            "EXIT" => {
                let code = event.data.get("exit_code")
                    .and_then(|v| v.as_i64())
                    .map(|v| v as i32)
                    .unwrap_or(-1);
                if let Some(tx) = done_tx_cb.lock().expect("lock").take() {
                    let _ = tx.send(Some(code));
                }
            }
            "REMOVED" => {
                if let Some(tx) = done_tx_cb.lock().expect("lock").take() {
                    let _ = tx.send(Some(-1));
                }
            }
            t if t == EVENT_TYPE_DISCONNECTED => {
                if let Some(tx) = done_tx_cb.lock().expect("lock").take() {
                    let _ = tx.send(Some(-2));
                }
            }
            _ => {}
        }
    });

    let sub = client
        .subscribe(&run.app_name, Some(&["STDOUT", "EXIT", "REMOVED"]), Some(on_event))
        .await?;

    let mut done_rx_owned = done_rx;

    let result = async {
        // Backfill output emitted before subscribe took effect
        match client
            .get_app_output(&run.app_name, 0, 0, 0, Some(&run.proc_uid), Some(0))
            .await
        {
            Ok(backfill) => {
                if !backfill.output.is_empty() {
                    deliver(
                        backfill.output.as_bytes(),
                        0,
                        &delivered_until,
                        print_stdout,
                    );
                }
                if let Some(code) = backfill.exit_code {
                    if let Some(tx) = done_tx.lock().expect("lock").take() {
                        let _ = tx.send(Some(code));
                    }
                }
            }
            Err(e) => {
                warn!("backfill failed for {}: {}", run.app_name, e);
            }
        }

        // Wait for the watch channel to contain Some(exit_code)
        let wait_fut = done_rx_owned.wait_for(|v| v.is_some());
        if timeout > 0 {
            match tokio::time::timeout(
                std::time::Duration::from_secs(timeout as u64),
                wait_fut,
            ).await {
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

    // Cleanup: unsubscribe + best-effort delete
    let _ = client.unsubscribe(&sub.subscription_id).await;

    if let Some(code) = result {
        if code >= 0 {
            let _ = client.delete_app(&run.app_name).await;
        }
    }

    Ok(result)
}

/// Deliver output bytes with position-based dedup.
fn deliver(chunk: &[u8], pos: i64, delivered_until: &AtomicI64, print_stdout: bool) {
    if chunk.is_empty() {
        return;
    }
    let end = pos + chunk.len() as i64;

    // Atomic CAS loop for thread-safe dedup
    loop {
        let current = delivered_until.load(Ordering::Acquire);
        if end <= current {
            return; // already delivered
        }
        if delivered_until
            .compare_exchange(current, end, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            if print_stdout {
                let start = if pos < current { (current - pos) as usize } else { 0 };
                let text = String::from_utf8_lossy(&chunk[start..]);
                print!("{}", text);
                use std::io::Write;
                std::io::stdout().flush().ok();
            }
            return;
        }
        // CAS failed — another thread updated; retry
    }
}
