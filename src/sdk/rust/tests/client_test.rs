// client_test.rs

#[cfg(test)]
mod tests {
    use mockito::{Server, ServerGuard};
    use serde_json::json;
    use appmesh::{Client, ClientConfig};

    async fn create_test_client(server: &ServerGuard) -> Client {
        let config = ClientConfig {
            url: server.url(),
            ssl_verify: None,
            ssl_client_cert: None,
            ssl_client_key: None,
            cookie_file: None,
        };
        Client::new(config).unwrap()
    }

    async fn setup_auth_mock(server: &mut ServerGuard) {
        server
            .mock("POST", "/appmesh/login")
            .match_header("Authorization", "Basic YWRtaW46cGFzc3dvcmQ=")
            .with_status(200)
            .create_async()
            .await;
    }

    #[tokio::test]
    async fn test_login() {
        let mut server = Server::new_async().await;
        setup_auth_mock(&mut server).await;

        let client = create_test_client(&server).await;
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

        let client = create_test_client(&server).await;
        client.login("admin", "password", None, None, None).await.unwrap();
        let result = client.list_apps().await.unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "app1");
        assert_eq!(result[1].name, "app2");
    }

    #[tokio::test]
    async fn test_add_app() {
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

        let client = create_test_client(&server).await;
        client.login("admin", "password", None, None, None).await.unwrap();
        let result = client.add_app(app_json.clone()).await.unwrap();

        assert_eq!(result.name, "test-app");
    }

    #[tokio::test]
    async fn test_get_app_output() {
        let mut server = Server::new_async().await;
        setup_auth_mock(&mut server).await;

        server
            .mock("GET", "/appmesh/app/test-app/output")
            .with_status(200)
            .with_header("X-Output-Position", "100")
            .with_header("X-Exit-Code", "0")
            .with_body("test output")
            .create_async()
            .await;

        let client = create_test_client(&server).await;
        client.login("admin", "password", None, None, None).await.unwrap();
        let result = client
            .get_app_output("test-app", 0, 0, 1024, None, None)
            .await
            .unwrap();

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
            .with_status(200)
            .with_header("X-Exit-Code", "0")
            .with_body("execution successful")
            .create_async()
            .await;

        let client = create_test_client(&server).await;
        client.login("admin", "password", None, None, None).await.unwrap();

        let app_json = json!({
            "name": "test-app",
            "command": "echo 'test'"
        });

        let (exit_code, output) = client
            .run_app_sync(app_json, 3600, 7200)
            .await
            .unwrap();

        assert_eq!(exit_code, Some(0));
        assert_eq!(output, "execution successful");
    }

    #[tokio::test]
    async fn test_tags() {
        let mut server = Server::new_async().await;
        setup_auth_mock(&mut server).await;

        server
            .mock("PUT", "/appmesh/label/env")
            .with_status(200)
            .create_async()
            .await;
        server
            .mock("GET", "/appmesh/labels")
            .with_status(200)
            .with_body(r#"{"env": "prod"}"#)
            .create_async()
            .await;
        server
            .mock("DELETE", "/appmesh/label/env")
            .with_status(200)
            .create_async()
            .await;

        let client = create_test_client(&server).await;
        client.login("admin", "password", None, None, None).await.unwrap();

        client.add_tag("env", "prod").await.unwrap();
        let tags: serde_json::Value = client.get_tags().await.unwrap();
        assert_eq!(tags["env"], "prod");
        client.delete_tag("env").await.unwrap();
    }
}
