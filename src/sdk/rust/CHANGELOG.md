# Changelog

## 3.0.20

- `ResourceLimitation.cpu` (fractional cores) mapped to container NanoCPUs.

## 3.0.19

- Builder methods `docker_ports`, `docker_volumes`, `docker_network` and
  `docker_backend` for first-class container wiring next to `docker_image`.

## 3.0.18

- Plain-transport opt-in for the TLS-at-gateway deployment shape (daemon
  `SSL.SSLEnabled=false` behind a load balancer, API gateway, or service-mesh
  sidecar on a trusted network): `ClientBuilderTCP`/`ClientBuilderWSS`
  `.plain_transport(true)` (and the client constructors' `plain` argument) dial
  the TCP frame port without TLS and `ws://` for the WebSocket transport, with
  the WSS HTTPS file side channel on plain `http://`. TLS stays the default;
  the flag never disables verification of a TLS endpoint.
- CLI (crate 3.0.3): a `-H ws://host:port` (or `http://`) endpoint selects the
  same plaintext shape for that invocation — no CA or client certificate
  applies, and a plain endpoint is never remembered as the default (a later
  bare `-H` would dial the same host over TLS). The local-daemon default
  endpoint reads the daemon's `SSL.SSLEnabled` from its own config (work
  overlay first, like the daemon), so a local plaintext daemon is dialed as
  `ws://` with no flags.


## 3.0.17

- Request signing (opt-in): `RequestSigner::new(key_id, secret)` produces the
  `X-Request-Key`/`X-Timestamp`/`X-Nonce`/`X-Signature` headers over the daemon's
  canonical string (`METHOD\npath\nsortedQuery\nsha256hex(body)\ntimestamp\nnonce`);
  the canonical construction mirrors the C++ verifier byte-for-byte. Install one
  with `ClientBuilder::request_signer` / `ClientBuilderTCP` / `ClientBuilderWSS`
  or `set_request_signer` on the HTTP, TCP, and WSS clients. The streamed file
  endpoints sign the empty-string body hash; TCP/WSS reuse the framed message
  uuid as the nonce; the WSS HTTPS file side channel is signed too. The secret
  is kept in memory only, never rendered by `Debug`, and never logged.
- Path/query canonical fixes for signed HTTP requests: the wire query is
  percent-only encoded (space → `%20`, never reqwest's `.query()` `+`, which
  the daemon keeps literal), and the WSS data-channel routes
  `/appmesh/file/{upload,download}/ws` sign the route without the trailing
  `/ws` (daemon `canonicalFileRoute`).
- CLI (crate 3.0.2): global `--api-key`/`--api-secret` (env fallback
  `APPMESH_API_KEY`/`APPMESH_API_SECRET`) attach a request signer to the
  Engine client; the secret is never persisted. `--api-secret -` reads one
  line from stdin so the secret never crosses argv (with
  `logon --password-stdin` the secret line comes first, the password second). The OAuth session lock names its holder pid
  (waiters steal only dead holders, and a holder never removes a stolen
  lock), and a cold start that lost the refresh-token rotation adopts the
  parallel CLI's live token set instead of reporting the session invalidated.

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
