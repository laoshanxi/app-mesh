# Transport Protocols

This document specifies the three client protocols of the App Mesh engine — REST over HTTPS, framed TCP, and WebSocket Secure — and when to use each. Port numbers are specified in [Port Specification](../deploy/Ports.md); the framing details of the SDK clients are specified in [SDK Behavioral Contract](../interfaces/SDKContract.md).

## 1. Listeners

| Listener | Protocol | Default port | Serves |
| --- | --- | --- | --- |
| Engine REST | HTTPS (TLS) | 6063 | REST API, SSE streams, file transfer |
| Engine framed | TCP + msgpack | 6062 | SDK request/response framing, event push, task workers |
| Agent REST front | HTTPS (TLS) | 6060 | REST and SSE relayed to the engine, including forwarded requests |

The engine serves the streaming routes (SSE output and task streams) natively on 6063 and relays them on 6060, including through node forwarding (`X-Target-Host`).

## 2. REST over HTTPS

- Every protected request carries `Authorization: Bearer`; see [Security](../security/Security.md) for validation.
- One response per request. Streaming endpoints answer `text/event-stream`.
- File transfer passes the path, mode, and overwrite options in `X-File-Path`, `X-File-Mode`, and `X-File-Overwrite` headers; see [File Management](../engine/Files.md).
- Plaintext operation is opt-in per deployment (`REST.SSL.SSLEnabled: false` behind a TLS-terminating gateway); clients opt in per connection (`http://` base URLs, `plain_transport=True`).

## 3. Framed TCP

- Wire form: an 8-byte header followed by a msgpack body. Each request carries a unique `uuid` used as the demultiplexing key.
- One connection multiplexes concurrent requests and subscriptions; event push arrives on the same connection.
- The request `uuid` doubles as the replay-protection nonce on this transport.
- TCP is the high-throughput path: event subscriptions, task worker loops, and long-running workloads.

## 4. WebSocket Secure

- The bearer is validated at the HTTP upgrade; the engine pins the authenticated principal to the connection.
- A direct frame does not repeat the bearer. A forwarded frame repeats the same bearer and must resolve to the pinned principal.
- WSS carries the same request/response and event traffic as TCP and passes through WebSocket-aware proxies; the CLI speaks WSS by default.

## 5. Choosing a transport

| Need | Use |
| --- | --- |
| Simple integration, any HTTP stack | REST |
| Browser-adjacent or proxy-friendly persistent connections | WSS |
| Highest throughput, event subscription, task workers | TCP |
| Cluster forwarding | Any; the gateway forwards over its TLS TCP channel to the target's TCP port |

## 6. Forwarding

All three transports forward with `X-Target-Host`. The gateway validates the bearer and the `host-forward` permission, strips the selector, and marks the request `X-AppMesh-Forwarded`. The sequence and the authorization rules are specified in [Cluster](../engine/Cluster.md).

## 7. Related

- [Port Specification](../deploy/Ports.md) — every listening port and the allocation rules
- [SDK Behavioral Contract](../interfaces/SDKContract.md) — framing, demultiplexing, and the synthetic `__disconnected__` event
- [TLS and certificates](../security/TLS.md) — listener configuration and client settings
