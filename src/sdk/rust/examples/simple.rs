//! Example of using AppMesh SDK
use std::error::Error;
use appmesh::{Client, ClientConfig};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Enable logging
    env_logger::init();

    // Create client configuration
    let config = ClientConfig {
        url: "https://localhost:6060".to_string(),
        ssl_verify: Some("ssl/ca.pem".to_string()),
        ssl_client_cert: Some("ssl/client.pem".to_string()),
        ssl_client_key: Some("ssl/client-key.pem".to_string()),
        cookie_file: None,
    };

    // Initialize client
    let client = Client::new(config)?;

    // Login
    client.login("admin", "password", None, None, None).await?;

    // List all applications
    let apps = client.list_apps().await?;
    println!("Current applications: {:#?}", apps);

    // Add a new application
    let new_app = json!({
        "name": "test-app",
        "command": "echo 'Hello AppMesh'",
        "working_dir": "/tmp"
    });

    let app = client.add_app(new_app).await?;
    println!("New application added: {:#?}", app);

    // Get host resources
    let resources = client.get_host_resources().await?;
    println!("Host resources: {:#?}", resources);

    Ok(())
}