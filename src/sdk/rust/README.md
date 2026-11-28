# AppMesh Rust SDK

Rust SDK for AppMesh - A service mesh platform for application management.

## Run example

```bash
cd src/sdk/rust
cargo run --example simple
```

[example](https://github.com/laoshanxi/app-mesh/tree/main/src/sdk/rust/examples)

## Testing

Run unit tests:

```bash
cargo test
```

## Forwarding and streaming in a cluster

`set_forward_to` (the `X-Target-Host` header) applies to every call, the streaming ones
included (`run_task_stream`, `follow_output`, `stream_run`): the task runs on the target
node and its stream is served from there, and a target the gateway cannot reach fails the
call like any other forwarded request. The TCP and WSS clients stream over a direct HTTPS
side channel; a forwarded stream on them dials the agent REST listener on the same host
(`agent_port` on the builder, default 6060), because the engine listener itself answers a
forwarded stream with 400. An HTTP client pointed at the engine's own listener (default
port 6063) therefore cannot forward a stream: the call fails with that 400; point the
client at the agent REST listener (default port 6060) for forwarded streams. Send the
target as a bare host: an explicit port names the target's TCP listener, which serves
neither the framed API's stream routes nor the agent relay of them.

## Synchronous run output limit

`run_app_sync` / `run_sync` return the complete output of a run. The daemon answers one page
(at most 5 MiB) and the client reads any further pages from the run's output endpoint before
returning, so large outputs are not cut off; the run instance is removed afterwards (best
effort - the daemon purges it after 600 s anyway).

To bound the result, use `run_app_sync_with_max_output` / `run_sync_with_max_output` with
`max_output_bytes: Some(n)`. Once the collected output exceeds `n` the call fails with
`AppMeshError::OutputLimitExceeded` instead of returning a truncated text, and the run
instance is kept so the remaining output stays readable for 600 s (`None` means unlimited).

```rust
let (exit_code, output) = client
    .run_sync_with_max_output("cat big.log", 60, 120, Some(64 * 1024 * 1024))
    .await?;
```
