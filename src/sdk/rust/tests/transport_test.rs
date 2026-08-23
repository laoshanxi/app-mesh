// transport_test.rs
//
// Integration tests for TCP and WSS transports.
//
// Prerequisites: a live AppMesh server at:
//   TCP  127.0.0.1:6059
//   WSS  127.0.0.1:6058
//
// Run:
//   cargo test --test transport_test -- --ignored --test-threads=1

// ---------------------------------------------------------------------------
// TCP integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tcp {
    use appmesh::{Application, ClientBuilderTCP};
    use std::env;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_name(prefix: &str) -> String {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        format!("{}-{}", prefix, ts)
    }

    async fn setup_tcp() -> std::sync::Arc<appmesh::AppMeshClientTCP> {
        let client = ClientBuilderTCP::new()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("ClientBuilderTCP::build failed");

        client.client().set_token(&env::var("APPMESH_BEARER_TOKEN").expect("APPMESH_BEARER_TOKEN is required"));

        client
    }

    // -----------------------------------------------------------------------
    // 1. Bearer-authenticated list_apps
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN; run with cargo test -- --ignored"]
    async fn test_tcp_login_and_apps() {
        let client = setup_tcp().await;

        let apps = client.list_apps().await.expect("TCP list_apps failed");
        // The server may have zero or more apps registered; the call must succeed.
        let _ = apps;

    }

    // -----------------------------------------------------------------------
    // 2. Synchronous run: run_app_sync with echo
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN; run with cargo test -- --ignored"]
    async fn test_tcp_sync_run() {
        let client = setup_tcp().await;

        let app = Application::builder("_tcp_sync_run_")
            .command("echo tcp-hello")
            .shell(true)
            .build();

        let (exit_code, output) =
            client.run_app_sync(&app, 30, 60).await.expect("TCP run_app_sync failed");

        assert_eq!(exit_code, Some(0), "echo should exit 0 over TCP");
        assert!(output.contains("tcp-hello"), "output should contain 'tcp-hello', got: {}", output);
    }

    // -----------------------------------------------------------------------
    // 3. Labels: add_label, list_labels, delete_label
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN; run with cargo test -- --ignored"]
    async fn test_tcp_labels() {
        let client = setup_tcp().await;
        let label_key = unique_name("tcp-label");

        // Add a label.
        client
            .add_label(&label_key, "tcp-value")
            .await
            .expect("TCP add_label failed");

        // Read it back.
        let labels: serde_json::Value = client.list_labels().await.expect("TCP list_labels failed");
        assert!(labels.is_object(), "list_labels should return a JSON object");
        assert_eq!(
            labels.get(&label_key).and_then(|v| v.as_str()),
            Some("tcp-value"),
            "label '{}' should be 'tcp-value', got: {:?}",
            label_key,
            labels.get(&label_key)
        );

        // Cleanup.
        client.delete_label(&label_key).await.expect("TCP delete_label failed");

        // Verify removal.
        let labels_after: serde_json::Value = client.list_labels().await.expect("TCP list_labels after delete failed");
        assert!(
            labels_after.get(&label_key).is_none(),
            "label '{}' should be gone after deletion",
            label_key
        );
    }

    // -----------------------------------------------------------------------
    // 4. Config: get_config, get_host_resources, get_metrics
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN; run with cargo test -- --ignored"]
    async fn test_tcp_config() {
        let client = setup_tcp().await;

        // get_config
        let config = client.get_config().await.expect("TCP get_config failed");
        assert!(config.is_object(), "TCP get_config should return a JSON object");

        // get_host_resources
        let resources = client.get_host_resources().await.expect("TCP get_host_resources failed");
        assert!(resources.is_object(), "TCP get_host_resources should return a JSON object");
        assert_eq!(resources.get("schema_version").and_then(|v| v.as_u64()), Some(3));
        assert!(resources.get("cpu_effective_processors").is_some());
        assert!(resources.get("mem_available_bytes").is_some());
        assert!(resources.get("swap_source").is_some());
        assert!(resources.get("net").and_then(|v| v.as_array()).is_some());
        assert!(resources.get("fs").and_then(|v| v.as_array()).is_some());

        // get_metrics
        let metrics = client.get_metrics().await.expect("TCP get_metrics failed");
        assert!(metrics.contains("appmesh_metrics_scrapes_total"), "TCP get_metrics missing scrape counter");
    }
}

// ---------------------------------------------------------------------------
// WSS integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod wss {
    use appmesh::{Application, ClientBuilderWSS};
    use std::env;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_name(prefix: &str) -> String {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        format!("{}-{}", prefix, ts)
    }

    async fn setup_wss() -> std::sync::Arc<appmesh::AppMeshClientWSS> {
        let client = ClientBuilderWSS::new()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("ClientBuilderWSS::build failed");

        client.client().set_token(&env::var("APPMESH_BEARER_TOKEN").expect("APPMESH_BEARER_TOKEN is required"));

        client
    }

    // -----------------------------------------------------------------------
    // 1. Bearer-authenticated list_apps
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN; run with cargo test -- --ignored"]
    async fn test_wss_login_and_apps() {
        let client = setup_wss().await;

        let apps = client.list_apps().await.expect("WSS list_apps failed");
        let _ = apps;

    }

    // -----------------------------------------------------------------------
    // 2. Synchronous run: run_app_sync with echo
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN; run with cargo test -- --ignored"]
    async fn test_wss_sync_run() {
        let client = setup_wss().await;

        let app = Application::builder("_wss_sync_run_")
            .command("echo wss-hello")
            .shell(true)
            .build();

        let (exit_code, output) =
            client.run_app_sync(&app, 30, 60).await.expect("WSS run_app_sync failed");

        assert_eq!(exit_code, Some(0), "echo should exit 0 over WSS");
        assert!(output.contains("wss-hello"), "output should contain 'wss-hello', got: {}", output);
    }

    // -----------------------------------------------------------------------
    // 3. App management: add_app, disable_app, enable_app, delete_app
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN; run with cargo test -- --ignored"]
    async fn test_wss_app_management() {
        let client = setup_wss().await;
        let app_name = unique_name("wss-mgmt");

        // Create a persistent app.
        let app = Application::builder(&app_name)
            .command("sleep 300")
            .shell(true)
            .build();

        let created = client.add_app(&app, None).await.expect("WSS add_app failed");
        assert_eq!(
            created.name.as_deref(),
            Some(app_name.as_str()),
            "created app name should match"
        );

        // Disable it.
        client.disable_app(&app_name).await.expect("WSS disable_app failed");
        let after_disable = client.get_app(&app_name).await.expect("WSS get_app after disable failed");
        assert_eq!(after_disable.name.as_deref(), Some(app_name.as_str()));

        // Re-enable it.
        client.enable_app(&app_name).await.expect("WSS enable_app failed");
        let after_enable = client.get_app(&app_name).await.expect("WSS get_app after enable failed");
        assert_eq!(after_enable.name.as_deref(), Some(app_name.as_str()));

        // Cleanup.
        let deleted = client.delete_app(&app_name).await.expect("WSS delete_app failed");
        assert!(deleted, "WSS delete_app should return true");
    }

    // -----------------------------------------------------------------------
    // 4. Config: get_config, get_host_resources, get_metrics
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN; run with cargo test -- --ignored"]
    async fn test_wss_config() {
        let client = setup_wss().await;

        // get_config
        let config = client.get_config().await.expect("WSS get_config failed");
        assert!(config.is_object(), "WSS get_config should return a JSON object");

        // get_host_resources
        let resources = client.get_host_resources().await.expect("WSS get_host_resources failed");
        assert!(resources.is_object(), "WSS get_host_resources should return a JSON object");
        assert_eq!(resources.get("schema_version").and_then(|v| v.as_u64()), Some(3));
        assert!(resources.get("cpu_effective_processors").is_some());
        assert!(resources.get("mem_available_bytes").is_some());
        assert!(resources.get("swap_source").is_some());
        assert!(resources.get("net").and_then(|v| v.as_array()).is_some());
        assert!(resources.get("fs").and_then(|v| v.as_array()).is_some());

        // get_metrics
        let metrics = client.get_metrics().await.expect("WSS get_metrics failed");
        assert!(metrics.contains("appmesh_metrics_scrapes_total"), "WSS get_metrics missing scrape counter");
    }
}
