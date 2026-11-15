# Changelog

## 3.0.12

- Opt-in HMAC request signing (`setRequestSignature(keyId, secret)` /
  `Builder.requestSignature(keyId, secret)`, mirror of the JavaScript 3.1.13
  feature): every request carries `X-Request-Key`, `X-Timestamp`, `X-Nonce` and
  `X-Signature` (lowercase hex HMAC-SHA256) over the daemon canonical string
  `METHOD \n path \n sortedQuery \n sha256hex(body) \n timestamp \n nonce`, on
  the HTTP, TCP and WSS transports. Streamed file endpoints
  (`/appmesh/file/download|upload|delete`) sign the empty-string body hash.
  The API key secret is never logged. Disabling (`clearRequestSignature`)
  removes the headers.
- Path/query canonical fixes for signed requests: the WSS data-channel routes
  `/appmesh/file/{upload,download}/ws` sign the route without the trailing
  `/ws` (daemon `canonicalFileRoute`), matching the updated Security.md
  signature spec.
- The TCP and WSS builders forward `requestSignature(keyId, secret)` like the
  HTTP builder, so signing can be enabled at build time on every transport.

## 3.0.10

- `forwardTo`: a bare host is sent as given instead of appending the client's own
  port. The server resolves its service port; the client port may be a host-side
  mapping (e.g. `16060`) that does not exist on the target node (same fix as Go,
  Python 3.0.15, JavaScript 3.1.10 and Rust 3.0.13).
- `unsubscribe` is idempotent: HTTP 404 (the daemon already dropped the
  subscription with its app) returns `false` instead of throwing, and the local
  callback is unregistered either way.

## 3.0.9

- WSS `uploadFile`/`downloadFile`: the HTTPS data side channel carries the same
  `X-Target-Host` as the WSS control request, so forwarding no longer lands
  files on the gateway node (same fix as Go, Python 3.0.14 and Rust 3.0.12).

## 3.0.8

File-transfer correctness over the HTTP transport (same change as Python 3.0.12,
JavaScript 3.1.9 and Rust 3.0.11):

- `uploadFile` sends the raw file bytes as the POST body on the canonical
  `/appmesh/file/upload` route and `downloadFile` reads the GET body as the file
  content. The previous multipart request silently lost data against a bare
  daemon, which answered a socket-transfer placeholder and never read the body.
- A legacy daemon's placeholder replies (200 JSON without `Content-Disposition`
  on download, 200 JSON `{"message":...}` on upload) are reported as errors
  instead of being treated as success.

## 3.0.7

Subscription and transport fixes ported from the Python SDK.

- TCP/WSS requests retry once with a refreshed token on HTTP 401 before
  failing; a second 401 is surfaced to the caller.
- The message demuxer skips zero-length frames instead of treating them as
  EOF, and half-open connections are closed.
- `downloadFile`/`uploadFile` on a TCP client are rejected while a subscription
  demuxer is active (previously they could corrupt the stream).
- `unsubscribe` removes the callback only after the server confirms the DELETE.
- WSS-forwarded requests now carry the caller's bearer semantics.

**Breaking (source compatibility):** the public fields of `RequestMessage` and
`ResponseMessage` were renamed from snake_case to camelCase (e.g.
`http_status` → `httpStatus`, `request_uri` → `requestUri`). The wire format
is unchanged — JSON property names are preserved via `@JsonProperty` — but code
reading these fields directly must be updated when upgrading.
