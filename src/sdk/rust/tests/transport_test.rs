// transport_test.rs
//
// Integration tests for TCP and WSS transports.
//
// Prerequisites: a live AppMesh server at:
//   TCP  127.0.0.1:6059
//   WSS  127.0.0.1:6058
//
// Run:
//   cargo test --test transport_test transport -- --test-threads=1

// ---------------------------------------------------------------------------
// TCP integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tcp {
    use appmesh::{Application, ClientBuilderTCP};
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

        client
            .login("admin", "admin123", None, None, None)
            .await
            .expect("TCP login failed — is AppMesh running at 127.0.0.1:6059?");

        client
    }

    // -----------------------------------------------------------------------
    // 1. Login, list_apps, logout
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_tcp_login_and_apps() {
        let client = setup_tcp().await;

        let apps = client.list_apps().await.expect("TCP list_apps failed");
        // The server may have zero or more apps registered; the call must succeed.
        let _ = apps;

        client.logout().await.expect("TCP logout failed");
    }

    // -----------------------------------------------------------------------
    // 2. Synchronous run: run_app_sync with echo
    // -----------------------------------------------------------------------

    #[tokio::test]
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
    async fn test_tcp_config() {
        let client = setup_tcp().await;

        // get_config
        let config = client.get_config().await.expect("TCP get_config failed");
        assert!(config.is_object(), "TCP get_config should return a JSON object");

        // get_host_resources
        let resources = client.get_host_resources().await.expect("TCP get_host_resources failed");
        assert!(resources.is_object(), "TCP get_host_resources should return a JSON object");
        assert!(
            resources.get("cpu_cores").is_some()
                || resources.get("cpu").is_some()
                || resources.get("memory_total_mb").is_some()
                || resources.get("mem_total").is_some()
                || resources.get("total_memory_mb").is_some(),
            "TCP get_host_resources missing expected CPU/memory field: {:?}",
            resources
        );

        // get_metrics
        let metrics = client.get_metrics().await.expect("TCP get_metrics failed");
        assert!(!metrics.is_empty(), "TCP get_metrics returned empty string");
    }
}

// ---------------------------------------------------------------------------
// WSS integration tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod wss {
    use appmesh::{Application, ClientBuilderWSS};
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

        client
            .login("admin", "admin123", None, None, None)
            .await
            .expect("WSS login failed — is AppMesh running at 127.0.0.1:6058?");

        client
    }

    // -----------------------------------------------------------------------
    // 1. Login, list_apps, logout
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_wss_login_and_apps() {
        let client = setup_wss().await;

        let apps = client.list_apps().await.expect("WSS list_apps failed");
        let _ = apps;

        client.logout().await.expect("WSS logout failed");
    }

    // -----------------------------------------------------------------------
    // 2. Synchronous run: run_app_sync with echo
    // -----------------------------------------------------------------------

    #[tokio::test]
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
    async fn test_wss_app_management() {
        let client = setup_wss().await;
        let app_name = unique_name("wss-mgmt");

        // Create a persistent app.
        let app = Application::builder(&app_name)
            .command("sleep 300")
            .shell(true)
            .build();

        let created = client.add_app(&app).await.expect("WSS add_app failed");
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
    async fn test_wss_config() {
        let client = setup_wss().await;

        // get_config
        let config = client.get_config().await.expect("WSS get_config failed");
        assert!(config.is_object(), "WSS get_config should return a JSON object");

        // get_host_resources
        let resources = client.get_host_resources().await.expect("WSS get_host_resources failed");
        assert!(resources.is_object(), "WSS get_host_resources should return a JSON object");
        assert!(
            resources.get("cpu_cores").is_some()
                || resources.get("cpu").is_some()
                || resources.get("memory_total_mb").is_some()
                || resources.get("mem_total").is_some()
                || resources.get("total_memory_mb").is_some(),
            "WSS get_host_resources missing expected CPU/memory field: {:?}",
            resources
        );

        // get_metrics
        let metrics = client.get_metrics().await.expect("WSS get_metrics failed");
        assert!(!metrics.is_empty(), "WSS get_metrics returned empty string");
    }
}
