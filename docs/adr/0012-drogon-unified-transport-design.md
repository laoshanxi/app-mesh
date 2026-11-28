# ADR 0012: One transport stack on Drogon and trantor

- Status: Accepted
- Date: 2026-10-05 (implemented 2026-10-05 .. 2026-10-09 on branch `drogon`)

## Context

The daemon spoke three protocols through two async frameworks, plus libcurl for outbound HTTP:

- 6058: uWebSockets served HTTPS and WSS behind ~1900 lines of glue, most of it defending against uWS raw-pointer lifetime rules.
- 6059: an ACE SSL socket server served the msgpack TCP protocol (`SocketServer`, `SocketStream`, `SSLHelper`).
- libcurl was the only HTTP client, wrapped by `RestClient`; the C++ SDK was its only real consumer.
- The pre-C++17 tiers carried a third stack (libwebsockets) that had to stay behaviorally aligned with the others.

Constraints: every SDK (Python, Go, Rust, Java, JavaScript), the Go agent, and the workflow engine connect over the existing wire formats — those must not change.

## Decision

Serve every protocol from Drogon and trantor, and keep one platform tier: C++17 or newer.

1. **One listener per protocol.** One Drogon listener (6058) serves HTTPS and WSS; request bodies stream, so a chunked (undeclared) length is refused at the REST body limit while it arrives. The TCP port (6059) keeps its wire format — 8-byte header + msgpack — but is served by a trantor TcpServer (`rest/drogon/TcpAdaptor`) bridged into the same reply path as WSS.
2. **One ingress seam.** Every transport decodes its wire form into the msgpack `Request` and queues it to the shared worker pool; payloads are owning `std::string`s end to end.
3. **One reply seam.** `ReplyContext` carries the serialized reply for HTTP and every framed session; `EventDispatcher` addresses connections by one session-id space.
4. **One outbound seam.** A trantor TCP client (`TcpClientStream`) serves daemon-to-daemon forwarding. Connections spread over the `TransportIoThreads` event loops by host:port, present the configured client certificate (mTLS), and resolve host names through one shared resolver. Eviction is passive: dead-on-reuse, 30 s silent with pending requests, 600 s idle without subscriptions. A lost hop synthesizes `__disconnected__` events for its subscribers.
5. **Transport-blind security.** The loopback check reads the accepted socket's peer address through one predicate and overrides any self-declared client address. A WSS upgrade pins the principal; every frame's bearer must match it. First-admin enrollment requires a direct loopback client.
6. **Lifecycle.** `QuitHandler` uses sigaction plus a self-pipe; Drogon disables its own SIGTERM handling so the daemon owns its signals. Workers drain before the transports stop. Thread config is `WorkerThreads` and `TransportIoThreads` (0 = derive from the cgroup-aware CPU count; old keys warn).
7. **HTTP client.** libcurl and the C++ SDK are removed. `RestClient` keeps one synchronous API on a trantor backend with `TLSPolicy` (custom CA, client certificates).

The C++ floor rises to 17 (C++20 on Windows); the CentOS 7 and Ubuntu 18 tiers and the libwebsockets fallback are retired. See ADR 0013 for the process engine that shares the Boost 1.86 floor.

## Consequences

- uWebSockets, the ACE SSL server, libcurl, the libwebsockets stack, and the C++ SDK are gone; zlib stays only as a transitive need.
- The wire formats did not change: existing SDKs, the agent, and the workflow engine connect without modification, and the TCP port answers the same frames the ACE server did.
- Three transport-specific reply branches and three loopback checks collapse into one each.
- Container measurement against the old transports: TCP throughput 2.4x at 16 connections and 3.0x at 64, p99 down from tens of milliseconds to a few; the multi-second tail stalls are gone.

## Open items

- The streaming file endpoints and their authorization run on the IO loops; slow disk or a slow JWKS fetch can stall a loop.
- Forwarding-pool eviction runs only when a request arrives; a hung request on an otherwise idle connection waits for the client's own timeout.
