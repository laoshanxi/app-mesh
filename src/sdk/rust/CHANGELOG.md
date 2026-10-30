# Changelog

## 3.0.16

- WSS transport: the WebSocket message/frame size caps are removed (tungstenite
  defaults are 64 MiB message / 16 MiB frame), so a forwarded file download
  larger than 16 MiB no longer fails with "Message too long".
- File API: `upload_file_with(local, remote, preserve_permissions, overwrite)`
  opts into replacing an existing remote file (header `X-File-Overwrite`, daemon
  refuses with 409 otherwise); `upload_file` keeps the previous signature and
  behavior. New `delete_file(remote)` removes a remote file
  (`DELETE /appmesh/file/delete`). Available on the HTTP, WSS, and TCP clients.

## 3.0.15

- `examples/simple.rs`: the async-run application now uses a POSIX shell loop
  (`echo` + `sleep`) instead of `ping`, which is absent from the packaged image;
  the loop also keeps emitting output while sleeping so the async stdout
  streaming has content to observe.

## 3.0.14

- `examples/simple.rs`: the async-run example sets a command on the application;
  the server rejects a command-less registration with 400 "Should specify command
  to run application".

## 3.0.13

- `forward_to`: a bare host is sent as given instead of appending the client's own
  port. The server resolves its service port; the client port may be a host-side
  mapping (e.g. `16060`) that does not exist on the target node (same fix as Go,
  Python 3.0.15, Java 3.0.10 and JavaScript 3.1.10).
- `unsubscribe`: on HTTP 404 (the daemon already dropped the subscription with its
  app) the local callback is now unregistered too; the call still returns `false`.

## 3.0.12

- WSS `upload_file`/`download_file`: the HTTPS data side channel carries the
  same `X-Target-Host` as the WSS control request, so `forward_to` no longer
  lands files on the gateway node (same fix as Go, Java 3.0.9 and Python 3.0.14).
- A pinned CA verifies through a preconfigured rustls config: reqwest's
  platform-verifier default ignored `add_root_certificate`, so `ssl_ca_cert`
  never applied on macOS.
- `run_task` sends a bare string payload as-is instead of JSON-quoting it.

## 3.0.11

- `upload_file`: the legacy-placeholder check now runs on the streaming HTTP
  path. In 3.0.10 it only existed in the buffered fallback, which the HTTP
  transport never takes, so an upload to a legacy daemon still reported success
  while storing nothing.
- The buffered fallbacks of `download_file`/`upload_file` send `X-File-Path`
  again (they lost the header when the streaming path took ownership of it).

## 3.0.10

File-transfer correctness over the HTTP transport:

- `upload_file`/`uploadFile` and `download_file`/`downloadFile` now use the
  plain-HTTP file routes with HTTP-native body semantics: GET download answers
  the file bytes, POST upload streams the raw file body. The previous multipart
  request silently lost data against a bare daemon (the daemon answered the
  socket-transfer dance and never read the HTTP body while the client reported
  success).
- A legacy daemon's placeholder replies are detected on both directions and
  reported as explicit errors instead of being written as file content.

## 3.0.9

Subscription and transport reliability fixes (semantics aligned with the
Python SDK). Formatting now follows the repository-wide `rustfmt.toml`
(125-column width).

- WSS read loop no longer treats WebSocket Ping/Pong frames as EOF; previously
  a server Ping could broadcast a spurious `__disconnected__` event.
- The TCP/WSS message demuxer skips zero-length frames and stops cleanly on an
  undecodable frame; transports are closed after a send/receive error instead
  of writing to a desynchronized stream.
- **Behavior change:** `download_file`/`upload_file` on a TCP client return an
  error while a subscription demuxer is active on that client (previously they
  could corrupt the stream). Use a separate client instance for file transfers.
- **Behavior change:** subscribe-based waits (`wait_for_async_run`, and
  `run_app_sync` on the WSS client) no longer delete the run application when
  an EXIT event is missing `exit_code`; the error is returned and the app is
  left on the server for inspection.
- `unsubscribe` removes the callback only after the server confirms the DELETE,
  so a failed unsubscribe keeps the callback receiving events.
- TLS client configuration construction deduplicated
  (`build_rustls_client_config`).
- Added live subscription tests (`tests/subscribe_live.rs`, `#[ignore]`-gated).
