#[cfg(test)]
mod tests {
    use std::env;
    use mockito::{mock, Mock};
    use serde_json::json;
    use appmesh::{Client, ClientConfig};

    // Helper function to create a test client
    fn create_test_client() -> AppMeshClient {
        let mock_url = mockito::server_url();
        let config = ClientConfig {
            url: mock_url,
            ssl_verify: None,
            ssl_client_cert: None,
            ssl_client_key: None,
            cookie_file: None,
        };
        AppMeshClient::new(config).unwrap()
    }

    // Helper function to setup common mocks
    fn setup_auth_mock() -> Mock {
        mock("POST", "/appmesh/login")
            .with_header("Authorization", "Basic YWRtaW46cGFzc3dvcmQ=") // admin:password
            .with_status(200)
            .create()
    }

    #[tokio::test]
    async fn test_login() {
        // Setup mock
        let _m = setup_auth_mock();

        let client = create_test_client();
        let result = client.login("admin", "password", None, None, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_apps() {
        // Setup auth mock
        let _auth = setup_auth_mock();

        // Setup apps list mock
        let _apps = mock("GET", "/appmesh/applications")
            .with_status(200)
            .with_body(r#"[
                {"name": "app1", "status": "running"},
                {"name": "app2", "status": "stopped"}
            ]"#)
            .create();

        let client = create_test_client();
        
        // First login
        client.login("admin", "password", None, None, None).await.unwrap();
        
        // Then list apps
        let result = client.list_apps().await.unwrap();
        assert_eq!(result.as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_add_app() {
        // Setup auth mock
        let _auth = setup_auth_mock();

        // Setup add app mock
        let app_json = json!({
            "name": "test-app",
            "command": "echo 'test'"
        });

        let _add_app = mock("PUT", "/appmesh/app/test-app")
            .with_status(200)
            .with_body(app_json.to_string())
            .create();

        let client = create_test_client();
        
        // Login first
        client.login("admin", "password", None, None, None).await.unwrap();
        
        // Add app
        let result = client.add_app(app_json.clone()).await.unwrap();
        assert_eq!(result["name"], "test-app");
    }

    #[tokio::test]
    async fn test_get_app_output() {
        // Setup auth mock
        let _auth = setup_auth_mock();

        // Setup app output mock
        let _output = mock("GET", "/appmesh/app/test-app/output")
            .with_status(200)
            .with_header("X-Output-Position", "100")
            .with_header("X-Exit-Code", "0")
            .with_body("test output")
            .create();

        let client = create_test_client();
        
        // Login first
        client.login("admin", "password", None, None, None).await.unwrap();
        
        // Get app output
        let result = client.get_app_output("test-app", 0, 0, 1024, None, None).await.unwrap();
        assert_eq!(result.output, "test output");
        assert_eq!(result.output_position, 100);
        assert_eq!(result.exit_code, Some(0));
    }

    #[tokio::test]
    async fn test_run_app_sync() {
        // Setup auth mock
        let _auth = setup_auth_mock();

        // Setup sync run mock
        let _run = mock("POST", "/appmesh/app/syncrun")
            .with_status(200)
            .with_header("X-Exit-Code", "0")
            .with_body("execution successful")
            .create();

        let client = create_test_client();
        
        // Login first
        client.login("admin", "password", None, None, None).await.unwrap();
        
        // Run app synchronously
        let app_json = json!({
            "name": "test-app",
            "command": "echo 'test'"
        });

        let (exit_code, output) = client.run_app_sync(app_json, 3600, 7200).await.unwrap();
        assert_eq!(exit_code, Some(0));
        assert_eq!(output, "execution successful");
    }

    #[tokio::test]
    async fn test_tags() {
        // Setup auth mock
        let _auth = setup_auth_mock();

        // Setup tags mocks
        let _add_tag = mock("PUT", "/appmesh/label/env")
            .with_status(200)
            .create();

        let _get_tags = mock("GET", "/appmesh/labels")
            .with_status(200)
            .with_body(r#"{"env": "prod"}"#)
            .create();

        let _del_tag = mock("DELETE", "/appmesh/label/env")
            .with_status(200)
            .create();

        let client = create_test_client();
        
        // Login first
        client.login("admin", "password", None, None, None).await.unwrap();
        
        // Test tag operations
        client.add_tag("env", "prod").await.unwrap();
        let tags = client.get_tags().await.unwrap();
        assert_eq!(tags["env"], "prod");
        client.delete_tag("env").await.unwrap();
    }
}