//! Example of using AppMesh SDK
use appmesh::{Application, ClientBuilderWSS, ExitAction};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Enable logging
    env_logger::init();

    // Initialize client
    let client = ClientBuilderWSS::new().build()?;

    // Login
    client.login("admin", "admin123", None, None, None).await?;

    // List all applications
    let apps = client.list_apps().await?;
    println!("Current applications: \n{:#?}", apps);

    // Add a new application using the type-safe builder
    let new_app = Application::builder("test-app")
        .command("echo 'Hello AppMesh'")
        .working_dir("/tmp")
        .exit_behavior(ExitAction::Standby)
        .build();

    let _ = client.delete_app("test-app").await;

    let app = client.add_app(&new_app).await?;
    println!("New application added: \n{:#?}", app);

    let app_output = client.get_app_output("test-app", 0, 0, 1024, None, Some(1)).await?;
    println!("Application output: \n{:#?}", app_output.output);
    client.delete_app("test-app").await?;

    // Get host resources
    let resources = client.get_host_resources().await?;
    println!("Host resources: \n{:#?}", resources);

    // Run a command asynchronously using the convenience method
    let ping_app = Application::builder("ping").build();
    let run = client.run_app_async(&ping_app, 5, 10).await?;
    let _ = run.wait(10, true).await;

    // Run a command synchronously using the string shortcut
    let (exit_code, output) = client.run_sync("echo 'hello world'", 5, 10).await?;
    println!("run_sync exit_code={:?} output={}", exit_code, output);

    Ok(())
}
