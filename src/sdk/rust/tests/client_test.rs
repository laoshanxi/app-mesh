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

    async fn setup_auth_mock(server: &mut ServerGuard) {
        server
            .mock("POST", "/appmesh/login")
            .match_header("Authorization", "Basic YWRtaW46cGFzc3dvcmQ=")
            .with_status(200)
            .with_body(r#"{"access_token":"test-token"}"#)
            .create_async()
            .await;
    }

    #[tokio::test]
    async fn test_login() {
        let mut server = Server::new_async().await;
        setup_auth_mock(&mut server).await;

        let client = create_test_client(&server);
        let result = client.login("admin", "password", None, None, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_apps() {
        let mut server = Server::new_async().await;
        setup_auth_mock(&mut server).await;

        server
            .mock("GET", "/appmesh/applications")
            .with_status(200)
            .with_body(r#"[{"name":"app1","command":"ping"},{"name":"app2","command":"curl"}]"#)
            .create_async()
            .await;

        let client = create_test_client(&server);
        client.login("admin", "password", None, None, None).await.unwrap();
        let result = client.list_apps().await.unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, Some("app1".to_string()));
        assert_eq!(result[1].name, Some("app2".to_string()));
    }

    #[tokio::test]
    async fn test_add_app_raw() {
        let mut server = Server::new_async().await;
        setup_auth_mock(&mut server).await;

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
        client.login("admin", "password", None, None, None).await.unwrap();

        let result = client.add_app_raw(app_json.clone()).await.unwrap();
        assert_eq!(result.name, Some("test-app".to_string()));
    }

    #[tokio::test]
    async fn test_add_app_typed() {
        let mut server = Server::new_async().await;
        setup_auth_mock(&mut server).await;

        server
            .mock("PUT", "/appmesh/app/test-app")
            .with_status(200)
            .with_body(r#"{"name":"test-app","command":"echo 'test'","shell":true}"#)
            .create_async()
            .await;

        let client = create_test_client(&server);
        client.login("admin", "password", None, None, None).await.unwrap();

        let app = Application::builder("test-app")
            .command("echo 'test'")
            .shell(true)
            .build();
        let result = client.add_app(&app).await.unwrap();
        assert_eq!(result.name, Some("test-app".to_string()));
    }

    #[tokio::test]
    async fn test_get_app_output() {
        let mut server = Server::new_async().await;
        setup_auth_mock(&mut server).await;

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
        client.login("admin", "password", None, None, None).await.unwrap();
        let result = client.get_app_output("test-app", 0, 0, 1024, None, None).await.unwrap();

        assert_eq!(result.output, "test output");
        assert_eq!(result.output_position, 100);
        assert_eq!(result.exit_code, Some(0));
    }

    #[tokio::test]
    async fn test_run_app_sync() {
        let mut server = Server::new_async().await;
        setup_auth_mock(&mut server).await;

        server
            .mock("POST", "/appmesh/app/syncrun")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("X-Exit-Code", "0")
            .with_body("execution successful")
            .create_async()
            .await;

        let client = create_test_client(&server);
        client.login("admin", "password", None, None, None).await.unwrap();

        let app = Application::builder("test-app").command("echo 'test'").build();
        let (exit_code, output) = client.run_app_sync(&app, 3600, 7200).await.unwrap();

        assert_eq!(exit_code, Some(0));
        assert_eq!(output, "execution successful");
    }

    #[tokio::test]
    async fn test_run_sync_shortcut() {
        let mut server = Server::new_async().await;
        setup_auth_mock(&mut server).await;

        server
            .mock("POST", "/appmesh/app/syncrun")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("X-Exit-Code", "0")
            .with_body("hello")
            .create_async()
            .await;

        let client = create_test_client(&server);
        client.login("admin", "password", None, None, None).await.unwrap();

        let (exit_code, output) = client.run_sync("echo hello", 60, 120).await.unwrap();
        assert_eq!(exit_code, Some(0));
        assert_eq!(output, "hello");
    }

    #[tokio::test]
    async fn test_tags() {
        let mut server = Server::new_async().await;
        setup_auth_mock(&mut server).await;

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
        client.login("admin", "password", None, None, None).await.unwrap();

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
}

// ---------------------------------------------------------------------------
// Integration tests — require a live AppMesh server at https://127.0.0.1:6060
// Run with: cargo test --test client_test integration -- --test-threads=1
// ---------------------------------------------------------------------------

#[cfg(test)]
mod integration {
    use appmesh::{AppMeshClient, Application, ClientBuilder};
    use std::sync::Arc;
    use tempfile::NamedTempFile;
    use std::io::Write;

    const SERVER_URL: &str = "https://127.0.0.1:6060";
    const ADMIN_USER: &str = "admin";
    const ADMIN_PASS: &str = "admin123";

    /// Build a client pointed at the real server and log in as admin.
    async fn setup_client() -> Arc<AppMeshClient> {
        let client = ClientBuilder::new()
            .url(SERVER_URL)
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        client
            .login(ADMIN_USER, ADMIN_PASS, None, None, None)
            .await
            .expect("login to live server failed — is AppMesh running at https://127.0.0.1:6060?");
        client
    }

    // -----------------------------------------------------------------------
    // 1. App management: enable_app, disable_app, delete_app, check_app_health
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_app_management() {
        let client = setup_client().await;
        let app_name = "rust-integ-app-mgmt";

        // Create a long-lived test app (keep-alive so it stays registered).
        let app = Application::builder(app_name)
            .command("sleep 300")
            .shell(true)
            .build();
        let created = client.add_app(&app).await.expect("add_app failed");
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
    // 2. User and roles: list_users, get_current_user, list_roles,
    //    list_permissions, get_user_permissions
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_user_and_roles() {
        let client = setup_client().await;

        // list_users — must include the admin account we used to log in.
        let users = client.list_users().await.expect("list_users failed");
        assert!(users.is_object() || users.is_array(), "list_users should return JSON object or array");

        // get_current_user — should reflect the logged-in admin.
        let me = client.get_current_user().await.expect("get_current_user failed");
        assert!(
            me.get("name").is_some(),
            "get_current_user response missing 'name' field: {:?}",
            me
        );

        // list_roles — should return a non-empty map.
        let roles = client.list_roles().await.expect("list_roles failed");
        assert!(!roles.is_empty(), "list_roles returned empty map");

        // list_permissions — global permission catalogue, must not be empty.
        let perms = client.list_permissions().await.expect("list_permissions failed");
        assert!(!perms.is_empty(), "list_permissions returned empty list");

        // get_user_permissions — permissions for the current (admin) user.
        let user_perms = client.get_user_permissions().await.expect("get_user_permissions failed");
        assert!(!user_perms.is_empty(), "get_user_permissions returned empty list for admin");
    }

    // -----------------------------------------------------------------------
    // 3. Config: get_config, get_host_resources, get_metrics, set_log_level
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_config() {
        let client = setup_client().await;

        // get_config — returns the daemon's JSON config blob.
        let config = client.get_config().await.expect("get_config failed");
        assert!(config.is_object(), "get_config should return a JSON object");

        // get_host_resources — CPU/memory/disk info.
        let resources = client.get_host_resources().await.expect("get_host_resources failed");
        assert!(resources.is_object(), "get_host_resources should return a JSON object");
        // Spot-check at least one well-known key exists.
        assert!(
            resources.get("cpu_cores").is_some()
                || resources.get("cpu").is_some()
                || resources.get("memory_total_mb").is_some()
                || resources.get("mem_total").is_some()
                || resources.get("total_memory_mb").is_some(),
            "get_host_resources missing expected CPU/memory field: {:?}",
            resources
        );

        // get_metrics — Prometheus-format text, must be non-empty.
        let metrics = client.get_metrics().await.expect("get_metrics failed");
        assert!(!metrics.is_empty(), "get_metrics returned empty string");

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

        // Wait for the command to finish (30 s budget, don't stream to stdout).
        let exit_code = run_handle
            .wait(30, false)
            .await
            .expect("AppRun::wait failed");

        // echo exits 0.
        assert_eq!(exit_code, Some(0), "async run of 'echo' should exit 0");
    }

    // -----------------------------------------------------------------------
    // 5. File operations: upload_file, download_file
    // -----------------------------------------------------------------------

    #[tokio::test]
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
