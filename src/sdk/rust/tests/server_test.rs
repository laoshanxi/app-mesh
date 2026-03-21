// server_test.rs

#[cfg(test)]
mod tests {
    use appmesh::{AppMeshServer, ClientBuilder};
    use mockito::{Matcher, Server};

    #[tokio::test]
    async fn test_task_fetch_success() {
        let mut server = Server::new_async().await;

        std::env::set_var("APP_MESH_PROCESS_KEY", "abc");
        std::env::set_var("APP_MESH_APPLICATION_NAME", "test-app");

        server
            .mock("GET", "/appmesh/app/test-app/task")
            .match_query(Matcher::UrlEncoded("process_key".into(), "abc".into()))
            .with_status(200)
            .with_body("payload")
            .create_async()
            .await;

        let client = ClientBuilder::new()
            .url(server.url())
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let srv = AppMeshServer::with_client(client);

        let payload = srv.task_fetch().await.unwrap();
        assert_eq!(payload, bytes::Bytes::from("payload"));
    }

    #[tokio::test]
    async fn test_task_return_error() {
        let mut server = Server::new_async().await;

        std::env::set_var("APP_MESH_PROCESS_KEY", "abc");
        std::env::set_var("APP_MESH_APPLICATION_NAME", "test-app");

        server
            .mock("PUT", "/appmesh/app/test-app/task")
            .match_query(Matcher::UrlEncoded("process_key".into(), "abc".into()))
            .with_status(500)
            .with_body("server error")
            .create_async()
            .await;

        let client = ClientBuilder::new()
            .url(server.url())
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let srv = AppMeshServer::with_client(client);

        let result = srv.task_return(b"ok").await;
        assert!(result.is_err());
    }
}
