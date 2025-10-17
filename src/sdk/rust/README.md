# AppMesh Rust SDK

Rust SDK for AppMesh - A service mesh platform for application management.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
appmesh = { git = "https://github.com/laoshanxi/app-mesh" }
```

Or install via CMake with app-mesh:

```bash
cd src/sdk/rust
cargo run --example simple
```

## Usage

[example](examples/simple.rs)

## Testing

Run unit tests:

```bash
cargo test
```

Or via CMake:

```bash
cmake --build build --target appmesh_rust_test
```
