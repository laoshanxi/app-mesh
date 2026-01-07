// server_test.rs

#[cfg(test)]
mod tests {
    use appmesh::AppMeshServer;
    use mockito::{Matcher, Server};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_task_fetch_success() {
        let mut server = Server::new_async().await;

        // Set required environment variables
        std::env::set_var("APP_MESH_PROCESS_KEY", "abc");
        std::env::set_var("APP_MESH_APPLICATION_NAME", "test-app");

        server
            .mock("GET", "/appmesh/app/test-app/task")
            .match_query(Matcher::UrlEncoded("process_key".into(), "abc".into()))
            .with_status(200)
            .with_body("payload")
            .create_async()
            .await;

        let base_url = server.url();
        let srv = AppMeshServer::new(Some(base_url), None, None).unwrap();

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

        let base_url = server.url();
        let srv = AppMeshServer::new(Some(base_url), None, None).unwrap();

        let result = srv.task_return(b"ok").await;
        assert!(result.is_err());
    }
}
