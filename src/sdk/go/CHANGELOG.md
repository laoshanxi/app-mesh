# Changelog

## 3.0.1

- Plain-transport support for the TLS-at-gateway deployment shape (daemon
  `SSL.SSLEnabled=false` behind a load balancer, gateway, or sidecar on a
  trusted network): `TCPConnection.ConnectPlain` dials the frame port without
  TLS, a `ws://` URL dials the WebSocket transport without TLS, and
  `SSLConfig` gains the `SSLEnabled` key (absent keeps TLS on, so an older
  configuration never degrades to plaintext).


## 3.0.0

- Versioning of the Go SDK starts here, aligned with the 3.x generation of the
  sibling SDKs: `SDKVersion` is the artifact the release convention bumps, and
  this CHANGELOG records what changed.
- Request signing (opt-in): `AppMeshClient.WithRequestSignature(keyID, secret)`
  (or the `Option.RequestSignatureKeyID`/`Option.RequestSignatureSecret` fields)
  produces the `X-Request-Key`/`X-Timestamp`/`X-Nonce`/`X-Signature` headers
  over the daemon's canonical string
  (`METHOD\npath\nsortedQuery\nsha256hex(body)\ntimestamp\nnonce`) on the HTTP,
  TCP, and WSS transports. The streamed file endpoints sign the empty-string
  body hash; TCP/WSS reuse the framed message uuid as the nonce; the WSS HTTPS
  file side channel is signed too. The secret is kept in memory only and never
  logged.
