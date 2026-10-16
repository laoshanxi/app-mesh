# Changelog

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
