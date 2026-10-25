# Changelog

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
