# AppMesh Rust SDK

Rust SDK for AppMesh - A service mesh platform for application management.

## Features

- Complete AppMesh API coverage
- Async/await support
- Strong type safety
- Comprehensive error handling
- SSL/TLS support
- Cookie-based session management
- Full test coverage

## Requirements

- Rust 1.56 or higher
- CMake 3.15 or higher (for building with app-mesh)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
appmesh = { git = "https://github.com/laoshanxi/app-mesh" }
```

Or install via CMake with app-mesh:

```bash
cmake -B build
cmake --build build
cmake --install build
```

## Usage

```rust
use appmesh::{Client, ClientConfig};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create client config
    let config = ClientConfig {
        url: "https://127.0.0.1:6060".to_string(),
        ssl_verify: Some("ssl/ca.pem".to_string()),
        ssl_client_cert: Some("ssl/client.pem".to_string()),
        ssl_client_key: Some("ssl/client-key.pem".to_string()),
        cookie_file: None,
    };
    
    // Initialize client
    let client = Client::new(config)?;
    
    // Login
    client.login("admin", "password", None, None, None).await?;
    
    // List applications
    let apps = client.list_apps().await?;
    println!("Applications: {:#?}", apps);
    
    // Deploy new application
    let new_app = json!({
        "name": "test-app",
        "command": "echo 'Hello World'",
        "working_dir": "/tmp"
    });
    client.add_app(new_app).await?;
    
    Ok(())
}
```

## Testing

Run unit tests:

```bash
cargo test
```

Or via CMake:

```bash
cmake --build build --target appmesh_rust_test
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
