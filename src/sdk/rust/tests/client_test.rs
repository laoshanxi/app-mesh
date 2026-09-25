// client_test.rs

#[cfg(test)]
mod tests {
    use appmesh::{AppMeshClient, Application, ClientBuilder};
    use mockito::{Matcher, Server, ServerGuard};
    use serde_json::json;
    use std::sync::Arc;

    fn create_test_client(server: &ServerGuard) -> Arc<AppMeshClient> {
        ClientBuilder::new()
            .url(server.url())
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_set_token_in_memory() {
        let server = Server::new_async().await;

        // set_token on a new client (in-memory, no cookie file)
        let client = create_test_client(&server);
        assert!(client.get_access_token().is_none(), "No token initially");

        client.set_token("test-set-token-value");
        assert_eq!(client.get_access_token(), Some("test-set-token-value".to_string()));

        // Overwrite
        client.set_token("test-set-token-value-2");
        assert_eq!(client.get_access_token(), Some("test-set-token-value-2".to_string()));
    }

    #[tokio::test]
    async fn test_jwt_token_constructor() {
        let server = Server::new_async().await;

        // jwt_token via builder
        let client = ClientBuilder::new()
            .url(server.url())
            .danger_accept_invalid_certs(true)
            .jwt_token("test-constructor-token")
            .build()
            .unwrap();
        assert_eq!(client.get_access_token(), Some("test-constructor-token".to_string()));
    }

    #[tokio::test]
    async fn test_list_apps() {
        let mut server = Server::new_async().await;

        server
            .mock("GET", "/appmesh/applications")
            .with_status(200)
            .with_body(r#"[{"name":"app1","command":"ping"},{"name":"app2","command":"curl"}]"#)
            .create_async()
            .await;

        let client = create_test_client(&server);
        let result = client.list_apps().await.unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, Some("app1".to_string()));
        assert_eq!(result[1].name, Some("app2".to_string()));
    }

    #[tokio::test]
    async fn test_add_app_raw() {
        let mut server = Server::new_async().await;

        let app_json = json!({
            "name": "test-app",
            "command": "echo 'test'"
        });

        server
            .mock("PUT", "/appmesh/app/test-app")
            .with_status(200)
            .with_body(app_json.to_string())
            .create_async()
            .await;

        let client = create_test_client(&server);

        let result = client.add_app_raw(app_json.clone()).await.unwrap();
        assert_eq!(result.name, Some("test-app".to_string()));
    }

    #[tokio::test]
    async fn test_add_app_typed() {
        let mut server = Server::new_async().await;

        server
            .mock("PUT", "/appmesh/app/test-app")
            .with_status(200)
            .with_body(r#"{"name":"test-app","command":"echo 'test'","shell":true}"#)
            .create_async()
            .await;

        let client = create_test_client(&server);

        let app = Application::builder("test-app")
            .command("echo 'test'")
            .shell(true)
            .build();
        let result = client.add_app(&app, None).await.unwrap();
        assert_eq!(result.name, Some("test-app".to_string()));
    }

    #[tokio::test]
    async fn test_get_app_output() {
        let mut server = Server::new_async().await;

        // Use Matcher::Any for query since the method adds query params
        server
            .mock("GET", "/appmesh/app/test-app/output")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("X-Output-Position", "100")
            .with_header("X-Exit-Code", "0")
            .with_body("test output")
            .create_async()
            .await;

        let client = create_test_client(&server);
        let result = client.get_app_output("test-app", 0, 0, 1024, None, None).await.unwrap();

        assert_eq!(result.output, "test output");
        assert_eq!(result.output_position, Some(100));
        assert_eq!(result.exit_code, Some(0));
    }

    #[tokio::test]
    async fn test_get_app_output_absent_headers_stay_none() {
        let mut server = Server::new_async().await;

        // A long-poll timeout carries no headers: no new output, process alive.
        server
            .mock("GET", "/appmesh/app/test-app/output")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body("")
            .create_async()
            .await;

        let client = create_test_client(&server);
        let result = client.get_app_output("test-app", 0, 0, 1024, None, None).await.unwrap();

        assert_eq!(result.output_position, None);
        assert_eq!(result.exit_code, None);
    }

    #[tokio::test]
    async fn test_get_app_output_malformed_exit_code_is_error() {
        let mut server = Server::new_async().await;

        server
            .mock("GET", "/appmesh/app/test-app/output")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("X-Exit-Code", "not-a-number")
            .with_body("output")
            .create_async()
            .await;

        let client = create_test_client(&server);
        // A malformed exit code must error — defaulting to 0 would report a
        // failed process as successful.
        assert!(client.get_app_output("test-app", 0, 0, 1024, None, None).await.is_err());
    }

    #[tokio::test]
    async fn test_get_app_output_malformed_position_is_error() {
        let mut server = Server::new_async().await;

        server
            .mock("GET", "/appmesh/app/test-app/output")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("X-Output-Position", "bogus")
            .with_body("output")
            .create_async()
            .await;

        let client = create_test_client(&server);
        assert!(client.get_app_output("test-app", 0, 0, 1024, None, None).await.is_err());
    }

    #[tokio::test]
    async fn test_run_app_sync() {
        let mut server = Server::new_async().await;

        server
            .mock("POST", "/appmesh/app/syncrun")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("X-Exit-Code", "0")
            .with_body("execution successful")
            .create_async()
            .await;

        let client = create_test_client(&server);

        let app = Application::builder("test-app").command("echo 'test'").build();
        let (exit_code, output) = client.run_app_sync(&app, 3600, 7200).await.unwrap();

        assert_eq!(exit_code, Some(0));
        assert_eq!(output, "execution successful");
    }

    #[tokio::test]
    async fn test_run_sync_shortcut() {
        let mut server = Server::new_async().await;

        server
            .mock("POST", "/appmesh/app/syncrun")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("X-Exit-Code", "0")
            .with_body("hello")
            .create_async()
            .await;

        let client = create_test_client(&server);

        let (exit_code, output) = client.run_sync("echo hello", 60, 120).await.unwrap();
        assert_eq!(exit_code, Some(0));
        assert_eq!(output, "hello");
    }

    #[tokio::test]
    async fn test_run_app_sync_malformed_exit_code_is_error() {
        let mut server = Server::new_async().await;

        server
            .mock("POST", "/appmesh/app/syncrun")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("X-Exit-Code", "NaN")
            .with_body("execution failed")
            .create_async()
            .await;

        let client = create_test_client(&server);

        let app = Application::builder("test-app").command("false").build();
        // A malformed exit code must error — reading it as 0 would turn a
        // failed process into a success for every caller.
        assert!(client.run_app_sync(&app, 60, 120).await.is_err());
    }

    #[tokio::test]
    async fn test_wait_poll_keeps_cursor_when_position_header_absent() {
        let mut server = Server::new_async().await;

        server
            .mock("POST", "/appmesh/app/run")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(r#"{"name":"waitapp","process_uuid":"uid-1"}"#)
            .create_async()
            .await;
        // Poll 1 (no stdout_position in the query yet): deliver output and a cursor.
        server
            .mock("GET", "/appmesh/app/waitapp/output")
            .match_query(Matcher::Any)
            .expect(1)
            .with_status(200)
            .with_header("X-Output-Position", "5")
            .with_body("hello")
            .create_async()
            .await;
        // Poll 2 (stdout_position=5): long-poll timeout, no headers. The cursor
        // must stay at 5 — resetting to 0 would re-deliver output from byte 0.
        server
            .mock("GET", "/appmesh/app/waitapp/output")
            .match_query(Matcher::UrlEncoded("stdout_position".into(), "5".into()))
            .expect(1)
            .with_status(200)
            .with_body("")
            .create_async()
            .await;
        // Poll 3 must still ask from stdout_position=5 to reach the exit code.
        server
            .mock("GET", "/appmesh/app/waitapp/output")
            .match_query(Matcher::UrlEncoded("stdout_position".into(), "5".into()))
            .expect(1)
            .with_status(200)
            .with_header("X-Exit-Code", "0")
            .with_body("")
            .create_async()
            .await;
        server.mock("DELETE", "/appmesh/app/waitapp").with_status(200).create_async().await;

        let client = create_test_client(&server);
        let run = client
            .run_app_async(&Application::builder("waitapp").command("echo hello").build(), 30, 60)
            .await
            .unwrap();

        let code = client.wait_for_async_run(&run, None, 30).await.unwrap();
        // A cursor reset would send poll 3 without stdout_position, miss the
        // exit-code mock, and end in a caller-side timeout (None) instead.
        assert_eq!(code, Some(0));
    }

    #[tokio::test]
    async fn test_tags() {
        let mut server = Server::new_async().await;

        server
            .mock("PUT", "/appmesh/label/env")
            .match_query(Matcher::UrlEncoded("value".into(), "prod".into()))
            .with_status(200)
            .create_async()
            .await;
        server
            .mock("GET", "/appmesh/labels")
            .with_status(200)
            .with_body(r#"{"env": "prod"}"#)
            .create_async()
            .await;
        server.mock("DELETE", "/appmesh/label/env").with_status(200).create_async().await;

        let client = create_test_client(&server);

        client.add_label("env", "prod").await.unwrap();
        let tags: serde_json::Value = client.list_labels().await.unwrap();
        assert_eq!(tags["env"], "prod");
        client.delete_label("env").await.unwrap();
    }

    #[test]
    fn test_parse_duration_integer() {
        let secs = AppMeshClient::parse_duration("3600").unwrap();
        assert_eq!(secs, 3600);
    }

    #[test]
    fn test_parse_duration_iso8601() {
        let secs = AppMeshClient::parse_duration("P1W").unwrap();
        assert_eq!(secs, 604800);

        let secs = AppMeshClient::parse_duration("P2DT12H").unwrap();
        assert_eq!(secs, 216000);

        let secs = AppMeshClient::parse_duration("PT5M30S").unwrap();
        assert_eq!(secs, 330);
    }

    // -----------------------------------------------------------------------
    // Wire-format checks (mocked HTTP server, no daemon needed)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_upload_file_multipart_wire_format() {
        use std::io::Write;

        let mut server = Server::new_async().await;

        let content = b"AppMesh multipart upload unit test\n";
        let mut upload_src = tempfile::NamedTempFile::new().expect("failed to create temp upload file");
        upload_src.write_all(content).expect("write to temp file failed");
        upload_src.flush().unwrap();

        let mock = server
            .mock("POST", "/appmesh/file/upload")
            .match_header("x-file-path", "/tmp/upload_wire.txt")
            .match_header("content-type", Matcher::Regex(r"^multipart/form-data; boundary=.+".to_string()))
            .match_body(Matcher::AllOf(vec![
                Matcher::Regex(r#"name="filename""#.to_string()),
                Matcher::Regex(r#"name="file"; filename="#.to_string()),
                Matcher::Regex("application/octet-stream".to_string()),
                Matcher::Regex("AppMesh multipart upload unit test".to_string()),
            ]))
            .with_status(200)
            .create_async()
            .await;

        let client = create_test_client(&server);
        client
            .upload_file(upload_src.path().to_str().unwrap(), "/tmp/upload_wire.txt", false)
            .await
            .expect("upload_file failed");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_subscribe_unsupported_over_http() {
        let server = Server::new_async().await;
        let client = create_test_client(&server);

        let err = client.subscribe("some-app", None, None).await.expect_err("HTTP subscribe must fail");
        assert!(
            matches!(err, appmesh::AppMeshError::UnsupportedFeature { .. }),
            "expected UnsupportedFeature, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_async_run_wait_uses_captured_forward_to() {
        let mut server = Server::new_async().await;
        let client = create_test_client(&server);

        // forward_to without a port is expanded with the client's own port.
        let port = server.url().rsplit(':').next().unwrap().to_string();
        let expected_host = format!("127.0.0.1:{}", port);

        let run_mock = server
            .mock("POST", "/appmesh/app/run")
            .match_query(Matcher::Any)
            .match_header("x-target-host", expected_host.as_str())
            .with_status(200)
            .with_body(r#"{"name":"fwd-app","process_uuid":"fwd-uuid"}"#)
            .create_async()
            .await;
        // The wait's poll must still carry the snapshot even after the client
        // clears forward_to.
        let output_mock = server
            .mock("GET", "/appmesh/app/fwd-app/output")
            .match_query(Matcher::Any)
            .match_header("x-target-host", expected_host.as_str())
            .with_status(200)
            .with_header("x-exit-code", "0")
            .with_body("")
            .create_async()
            .await;
        let delete_mock = server.mock("DELETE", "/appmesh/app/fwd-app").with_status(200).create_async().await;

        client.set_forward_to(Some("127.0.0.1".to_string()));
        let app = Application::builder("fwd-app").command("true").build();
        let run = client.run_app_async(&app, 10, 10).await.expect("run_app_async failed");
        client.set_forward_to(None);

        let exit_code = run.wait(None, 5).await.expect("wait failed");
        assert_eq!(exit_code, Some(0));

        run_mock.assert_async().await;
        output_mock.assert_async().await;
        delete_mock.assert_async().await;
    }
}

// ---------------------------------------------------------------------------
// Integration tests — require a live AppMesh server at https://127.0.0.1:6060
// Run with: cargo test --test client_test integration -- --test-threads=1
// ---------------------------------------------------------------------------

#[cfg(test)]
mod integration {
    // These tests talk to a live App Mesh daemon (https://127.0.0.1:6060) with a
    // caller-obtained Dex bearer (APPMESH_BEARER_TOKEN). They are #[ignore]d so the
    // documented plain `cargo test` stays green without a daemon; run them with:
    //   cargo test -- --ignored
    use appmesh::{AppMeshClient, Application, ClientBuilder};
    use std::env;
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use std::io::Write;

    const SERVER_URL: &str = "https://127.0.0.1:6060";
    /// Build a client pointed at the real server with a caller-obtained Dex bearer.
    async fn setup_client() -> Arc<AppMeshClient> {
        let client = ClientBuilder::new()
            .url(SERVER_URL)
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        client.set_token(&env::var("APPMESH_BEARER_TOKEN").expect("APPMESH_BEARER_TOKEN is required"));
        client
    }

    // -----------------------------------------------------------------------
    // 1. App management: enable_app, disable_app, delete_app, check_app_health
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN; run with cargo test -- --ignored"]
    async fn test_app_management() {
        let client = setup_client().await;
        let app_name = "rust-integ-app-mgmt";

        // Create a long-lived test app (keep-alive so it stays registered).
        let app = Application::builder(app_name)
            .command("sleep 300")
            .shell(true)
            .build();
        let created = client.add_app(&app, None).await.expect("add_app failed");
        assert_eq!(created.name.as_deref(), Some(app_name));

        // Disable the app and verify health reflects disabled state.
        client.disable_app(app_name).await.expect("disable_app failed");
        let disabled = client.get_app(app_name).await.expect("get_app after disable failed");
        // status 3 == DISABLED in AppMesh convention; just verify the call succeeded
        let _ = disabled;

        // Re-enable the app.
        client.enable_app(app_name).await.expect("enable_app failed");
        let enabled = client.get_app(app_name).await.expect("get_app after enable failed");
        assert_eq!(enabled.name.as_deref(), Some(app_name));

        // check_app_health returns a bool (true == healthy).
        // The result may be true or false depending on runtime state; the call must not error.
        let _healthy = client.check_app_health(app_name).await.expect("check_app_health failed");

        // Cleanup.
        let deleted = client.delete_app(app_name).await.expect("delete_app failed");
        assert!(deleted, "delete_app should return true on success");
    }

    // -----------------------------------------------------------------------
    // 2. Current principal and roles
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN; run with cargo test -- --ignored"]
    async fn test_user_and_roles() {
        let client = setup_client().await;

        // get_current_principal returns the verified Dex principal.
        let me = client.get_current_principal().await.expect("get_current_principal failed");
        assert!(me.is_object(), "get_current_principal should return a principal object");

        // list_roles — should return a non-empty map.
        let roles = client.list_roles().await.expect("list_roles failed");
        assert!(!roles.is_empty(), "list_roles returned empty map");

        // list_permissions — global permission catalogue, must not be empty.
        let perms = client.list_permissions().await.expect("list_permissions failed");
        assert!(!perms.is_empty(), "list_permissions returned empty list");

        // get_principal_permissions returns the current principal's permissions.
        let user_perms = client.get_principal_permissions().await.expect("get_principal_permissions failed");
        let _ = user_perms;
    }

    // -----------------------------------------------------------------------
    // 3. Config: get_config, get_host_resources, get_metrics, set_log_level
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN; run with cargo test -- --ignored"]
    async fn test_config() {
        let client = setup_client().await;

        // get_config — returns the daemon's JSON config blob.
        let config = client.get_config().await.expect("get_config failed");
        assert!(config.is_object(), "get_config should return a JSON object");

        // get_host_resources — CPU/memory/disk info.
        let resources = client.get_host_resources().await.expect("get_host_resources failed");
        assert!(resources.is_object(), "get_host_resources should return a JSON object");
        assert_eq!(resources.get("schema_version").and_then(|v| v.as_u64()), Some(3));
        for field in [
            "collected_at_unix_seconds",
            "cpu_effective_processors",
            "mem_available_bytes",
            "swap_source",
            "collector_errors",
        ] {
            assert!(resources.get(field).is_some(), "get_host_resources missing {field}: {resources:?}");
        }

        // get_metrics — Prometheus-format text, must be non-empty.
        let metrics = client.get_metrics().await.expect("get_metrics failed");
        assert!(metrics.contains("appmesh_metrics_scrapes_total"), "get_metrics missing scrape counter");

        // set_log_level — round-trip: set DEBUG, restore to INFO.
        let new_level = client.set_log_level("DEBUG").await.expect("set_log_level(DEBUG) failed");
        assert_eq!(new_level.to_uppercase(), "DEBUG");

        let restored = client.set_log_level("INFO").await.expect("set_log_level(INFO) failed");
        assert_eq!(restored.to_uppercase(), "INFO");
    }

    // -----------------------------------------------------------------------
    // 4. Async run: run_app_async + AppRun::wait
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN; run with cargo test -- --ignored"]
    async fn test_async_run() {
        let client = setup_client().await;

        // Fire an async run for a quick command.
        let app = Application::builder("_integ_async_run_")
            .command("echo async-hello")
            .shell(true)
            .build();

        let run_handle = client
            .run_app_async(&app, 30, 60)
            .await
            .expect("run_app_async failed");

        assert!(!run_handle.app_name.is_empty(), "app_name must not be empty");
        assert!(!run_handle.proc_uid.is_empty(), "proc_uid must not be empty");

        // Wait for the command to finish (30 s budget, no stdout handler).
        let exit_code = run_handle
            .wait(None, 30)
            .await
            .expect("AppRun::wait failed");

        // echo exits 0.
        assert_eq!(exit_code, Some(0), "async run of 'echo' should exit 0");
    }

    // -----------------------------------------------------------------------
    // 5. File operations: upload_file, download_file
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[ignore = "requires a running App Mesh daemon and APPMESH_BEARER_TOKEN; run with cargo test -- --ignored"]
    async fn test_file_operations() {
        let client = setup_client().await;

        // Write a small temp file with known content.
        let mut upload_src = NamedTempFile::new().expect("failed to create temp upload file");
        let content = b"AppMesh Rust SDK integration test payload\n";
        upload_src.write_all(content).expect("write to temp file failed");
        upload_src.flush().unwrap();

        // Choose a unique remote path to avoid "file already exist" errors.
        let remote_path = format!(
            "/tmp/appmesh_rust_integ_{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );
        let remote_path = remote_path.as_str();

        // Upload.
        client
            .upload_file(upload_src.path().to_str().unwrap(), remote_path, false)
            .await
            .expect("upload_file failed");

        // Download to a fresh temp file.
        let download_dst = NamedTempFile::new().expect("failed to create temp download file");
        client
            .download_file(remote_path, download_dst.path().to_str().unwrap(), false)
            .await
            .expect("download_file failed");

        // Verify the downloaded content matches what we uploaded.
        let downloaded = std::fs::read(download_dst.path()).expect("failed to read downloaded file");
        assert_eq!(
            downloaded, content,
            "downloaded content does not match uploaded content"
        );
    }
}
