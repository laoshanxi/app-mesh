// subscribe_live.rs
//
// Live-daemon tests for the sub/pub fixes (file-transfer guard, atomic
// add_app callback flush, subscribe-based wait streaming, 401 refresh-retry).
// Gated like tests/client_test.rs: run with
//   APPMESH_BEARER_TOKEN=<dex-token> cargo test --test subscribe_live -- --ignored

use appmesh::{
    AppEvent, AppMeshClientTCP, AppMeshClientWSS, Application, ClientBuilderTCP, ClientBuilderWSS, TokenProvider, TokenSet,
};
use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn bearer() -> String {
    std::env::var("APPMESH_BEARER_TOKEN").expect("APPMESH_BEARER_TOKEN is required for live tests")
}

fn tcp_client() -> Arc<AppMeshClientTCP> {
    ClientBuilderTCP::new().address("127.0.0.1", 6059).danger_accept_invalid_certs(true).build().expect("build TCP client")
}

fn static_provider(token: &str) -> Arc<dyn TokenProvider> {
    Arc::new(appmesh::StaticAccessTokenProvider::new(token).expect("non-empty token"))
}

fn unique_name(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    format!("{}-{}", prefix, nanos)
}

#[tokio::test]
#[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN"]
async fn test_live_tcp_wait_streams_stdout() {
    let client = tcp_client();
    client.set_token_provider(Some(static_provider(&bearer())));

    let name = unique_name("live-wait");
    let app = Application {
        name: Some(name.clone()),
        command: Some("echo live-rust-line-1; echo live-rust-line-2".into()),
        shell: Some(true),
        ..Default::default()
    };
    let run = client.run_app_async(&app, 10, 0).await.expect("run async");

    let collected: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let sink = collected.clone();
    let handler = Some(Arc::new(move |data: &str, _pos: i64| {
        sink.lock().unwrap().push_str(data);
    }) as appmesh::OutputFn);
    let code = client.wait_for_async_run(&run, handler, 20).await.expect("wait must not fail");
    assert_eq!(code, Some(0), "echo must exit 0");
    let out = collected.lock().unwrap().clone();
    assert!(out.contains("live-rust-line-1"), "stdout not streamed: {}", out);
    assert!(out.contains("live-rust-line-2"), "stdout not streamed: {}", out);
}

#[tokio::test]
#[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN"]
async fn test_live_tcp_atomic_add_delivers_events() {
    let client = tcp_client();
    client.set_token_provider(Some(static_provider(&bearer())));

    let name = unique_name("live-atomic");
    let app = Application {
        name: Some(name.clone()),
        command: Some("echo atomic-rust-ok".into()),
        shell: Some(true),
        ..Default::default()
    };

    let seen_start = Arc::new(AtomicUsize::new(0));
    let seen_exit = Arc::new(AtomicUsize::new(0));
    let cb = {
        let start = seen_start.clone();
        let exit = seen_exit.clone();
        Arc::new(move |event: AppEvent| {
            match event.event_type.as_str() {
                "START" => start.fetch_add(1, Ordering::SeqCst),
                "EXIT" => exit.fetch_add(1, Ordering::SeqCst),
                _ => 0,
            };
        }) as appmesh::EventCallback
    };

    let added =
        client.add_app_with_callback(&app, Some(&["START", "EXIT"]), Some(cb)).await.expect("atomic add with events");
    assert!(added.subscription_id.is_some(), "atomic add must return a subscription_id");

    client.enable_app(&name).await.expect("enable app");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while (seen_start.load(Ordering::SeqCst) == 0 || seen_exit.load(Ordering::SeqCst) == 0)
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(seen_start.load(Ordering::SeqCst) > 0, "START event not delivered");
    assert!(seen_exit.load(Ordering::SeqCst) > 0, "EXIT event not delivered");

    let _ = client.delete_app(&name).await;
}

#[tokio::test]
#[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN"]
async fn test_live_tcp_file_transfer_guard() {
    let client = tcp_client();
    client.set_token_provider(Some(static_provider(&bearer())));

    let sub = client.subscribe("*", Some(&["START"]), Some(Arc::new(|_e: AppEvent| {}))).await.expect("subscribe");

    // While the demuxer owns the read side, both transfer directions are rejected.
    let err = client
        .download_file("/opt/appmesh/bin/appmesh", "/tmp/e2e-rust-guarded", false)
        .await
        .expect_err("download must be rejected while subscribed");
    assert!(err.to_string().contains("not supported"), "got: {}", err);

    let err = client
        .upload_file("/etc/hosts", "/tmp/e2e-rust-upload", false)
        .await
        .expect_err("upload must be rejected while subscribed");
    assert!(err.to_string().contains("not supported"), "got: {}", err);

    // Unsubscribe removes the callback but the demuxer keeps the read side
    // (Python semantics); a separate client instance transfers fine.
    client.unsubscribe(&sub.subscription_id).await.expect("unsubscribe");
    let err = client
        .download_file("/opt/appmesh/bin/appmesh", "/tmp/e2e-rust-still", false)
        .await
        .expect_err("guard must hold until close on the same connection");
    assert!(err.to_string().contains("not supported"), "got: {}", err);

    let plain = tcp_client();
    plain.set_token_provider(Some(static_provider(&bearer())));
    plain
        .download_file("/opt/appmesh/bin/appmesh", "/tmp/e2e-rust-plain", false)
        .await
        .expect("a separate client instance must be able to download");
}

#[tokio::test]
#[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN"]
async fn test_live_wss_wait_streams_stdout() {
    let client: Arc<AppMeshClientWSS> = ClientBuilderWSS::new()
        .address("127.0.0.1", 6058)
        .danger_accept_invalid_certs(true)
        .build()
        .expect("build WSS client");
    client.set_token_provider(Some(static_provider(&bearer())));

    let name = unique_name("live-wss");
    let app = Application {
        name: Some(name),
        command: Some("echo wss-rust-line".into()),
        shell: Some(true),
        ..Default::default()
    };
    let run = client.run_app_async(&app, 10, 0).await.expect("run async");

    let collected: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let sink = collected.clone();
    let handler = Some(Arc::new(move |data: &str, _pos: i64| {
        sink.lock().unwrap().push_str(data);
    }) as appmesh::OutputFn);
    let code = client.wait_for_async_run(&run, handler, 20).await.expect("wait");
    assert_eq!(code, Some(0));
    assert!(collected.lock().unwrap().contains("wss-rust-line"), "stdout not streamed");
}

struct StaleThenFreshProvider {
    valid: String,
    refreshes: AtomicUsize,
}

fn fresh_set(valid: &str) -> TokenSet {
    TokenSet {
        access_token: valid.to_string(),
        refresh_token: None,
        expires_at: None,
        refresh_at: None,
        token_type: "Bearer".to_string(),
        scope: None,
    }
}

#[async_trait]
impl TokenProvider for StaleThenFreshProvider {
    async fn access_token(&self) -> Result<String, appmesh::AppMeshError> {
        if self.refreshes.load(Ordering::SeqCst) == 0 {
            return Ok("definitely-stale-token".into());
        }
        Ok(self.valid.clone())
    }
    fn can_refresh(&self) -> bool {
        true
    }
    async fn force_refresh(&self) -> Result<TokenSet, appmesh::AppMeshError> {
        self.refreshes.fetch_add(1, Ordering::SeqCst);
        Ok(fresh_set(&self.valid))
    }
    async fn refresh_access_token(&self, _rejected: &str) -> Result<TokenSet, appmesh::AppMeshError> {
        self.refreshes.fetch_add(1, Ordering::SeqCst);
        Ok(fresh_set(&self.valid))
    }
    async fn revoke(&self) -> Result<bool, appmesh::AppMeshError> {
        Ok(false)
    }
    fn snapshot(&self) -> Option<TokenSet> {
        None
    }
}

#[tokio::test]
#[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN"]
async fn test_live_tcp_401_refresh_retry() {
    let client = tcp_client();
    let provider = Arc::new(StaleThenFreshProvider { valid: bearer(), refreshes: AtomicUsize::new(0) });
    client.set_token_provider(Some(provider.clone()));

    let apps = client.list_apps().await.expect("replay with refreshed token must succeed");
    assert!(!apps.is_empty());
    assert_eq!(provider.refreshes.load(Ordering::SeqCst), 1, "exactly one refresh");
}
