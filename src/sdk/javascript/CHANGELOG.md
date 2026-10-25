# Changelog

## 3.1.9

File-attribute hardening on both transports:

- The `X-File-Mode` value from the server is validated before `chmod`. Only a
  decimal value in the range 0..0o777 is applied. Any other value is skipped
  with a warning. This matches the Python, Java and Rust SDKs.
- A malformed `X-File-Mode` header no longer fails a finished TCP download.
  The file stays on disk and the attribute step is skipped.
- `downloadFile` in Node streams the response body to disk instead of
  buffering the whole file in memory; the browser path is unchanged.

## 3.1.8

File-transfer correctness over the HTTP transport:

- `upload_file`/`uploadFile` and `download_file`/`downloadFile` now use the
  plain-HTTP file routes with HTTP-native body semantics: GET download answers
  the file bytes, POST upload streams the raw file body. The previous multipart
  request silently lost data against a bare daemon (the daemon answered the
  socket-transfer dance and never read the HTTP body while the client reported
  success).
- A legacy daemon's placeholder replies are detected on both directions and
  reported as explicit errors instead of being written as file content.

## 3.1.7

**Breaking:** the deprecated snake_case method aliases (`list_apps`,
`set_bearer_token`, `add_app`, `run_app_sync`, `fetch_task`, ...) were
removed. Public methods are camelCase only — migrate callers to the canonical
names (`listApps`, `setBearerToken`, `addApp`, `runAppSync`, `fetchTask`, ...).

Subscription and transport fixes included in this release:

- TCP read side rewritten as a persistent read pump, fixing the
  pause/resume deadlock on large file transfers.
- Zero-length frames are skipped instead of being treated as EOF.
- Concurrent demuxer startup is serialized (`_enableDemuxer` promise chain),
  preventing double read loops.
- `waitForAsyncRun` clears its timeout timer, no longer pinning the event loop.
- A 401 triggers one token refresh + retry and respects caller-managed
  Authorization headers.
- Frame length validation on the TCP read path.
- Subscribe conformance suite (`test/subscribe_test.js`, 22 cases) joined to
  `npm test`.
