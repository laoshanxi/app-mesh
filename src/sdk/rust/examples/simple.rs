//! Example of using AppMesh SDK
use appmesh::ClientBuilderTCP;
use serde_json::json;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Enable logging
    env_logger::init();

    // Initialize client
    let client = ClientBuilderTCP::new().build()?;

    // Login
    client.login("admin", "admin123", None, None, None).await?;

    // List all applications
    let apps = client.list_apps().await?;
    println!("Current applications: \n{:#?}", apps);

    // Add a new application
    let new_app = json!({
        "name": "test-app",
        "command": "echo 'Hello AppMesh'",
        "working_dir": "/tmp"
    });

    let _ = client.delete_app("test-app").await;

    let app = client.add_app(new_app).await?;
    println!("New application added: \n{:#?}", app);

    let app_output = client.get_app_output("test-app", 0, 0, 1024, None, Some(1)).await?;
    println!("Application output: \n{:#?}", app_output.output);
    client.delete_app("test-app").await?;

    // Get host resources
    let resources = client.get_host_resources().await?;
    println!("Host resources: \n{:#?}", resources);

    let run = client.run_app_async(json!({"name": "ping"}), 5, 10).await?;
    let _ = run.wait(10, true).await;

    let run_sync = client.run_app_sync(json!({"name": "ping"}), 5, 10).await?;
    println!("run_app_sync: \n{:#?}", run_sync);

    Ok(())
}
