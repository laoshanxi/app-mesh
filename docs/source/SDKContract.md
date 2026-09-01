# SDK Behavioral Contract

This document is the normative cross-SDK contract for App Mesh client SDKs
(Python, Go, Rust, Java, JavaScript). Each SDK implements these guarantees
independently; when changing one SDK, update the others (or this document)
in the same change. Per-SDK code comments describe implementation detail —
**this document defines the behavior**.

Applies to the TCP and WSS transports (`AppMeshClientTCP` / `AppMeshClientWSS`
and equivalents). The HTTP transport has no demuxer; its per-request semantics
come from the HTTP library.

## TCP Wire Framing

| Constant | Value |
|---|---|
| Frame header | 8 bytes: 4-byte magic + 4-byte body length, both big-endian |
| Magic number | `0x07C707F8` |
| Max body length | 1 GiB (`1024 * 1024 * 1024`) — reject larger frames |

The length field excludes the 8-byte header. Bodies are msgpack-encoded
`Request`/`Response` messages. These constants are part of the daemon wire
protocol and must never change.

## Message Demuxer

Each subscription-capable transport runs a demuxer: one background reader that
routes every incoming `Response` either to a pending request waiter (matched by
request `uuid`) or to an event subscription callback.

### Event push identification

Server-push events are `Response` messages with `request_uri = "/appmesh/event"`
(see [EventSubscription.md](EventSubscription.md) for the body format). The
subscription ID is taken from the body's `subscription_id`, falling back to the
`X-Subscription-Id` header.

### Register pending before send

A request's `uuid` MUST be registered with the demuxer **before** the request
bytes are written to the socket. Otherwise a fast response can arrive before
the waiter exists and be dropped (conformance scenario S7).

### Request timeout policy

Requests routed through the demuxer have **no artificial client-side wait
cap**: a request slower than the transport receive timeout (e.g. > 60s) must
still complete (S1). An empty/None/closed-channel result from the demuxer means
the demuxer stopped — i.e. the transport disconnected — never "slow request".
On that signal the client closes the transport and raises/returns a
**connection error** (not a timeout).

### Event ordering

- **Guaranteed (normative):** events of one subscription are delivered to its
  callback serially, in arrival order (the server's per-subscription monotonic
  `sequence` order).
- **Not guaranteed:** cross-subscription ordering. Some implementations happen
  to provide it; callers MUST NOT rely on it.

| SDK | Dispatch mechanism | Incidental cross-subscription FIFO? |
|---|---|---|
| Python | single global dispatch thread + FIFO queue | yes |
| Go | single dispatch goroutine + FIFO channel | yes |
| JavaScript | synchronous dispatch on the event loop | yes |
| Java | one single-threaded executor per subscription | no |
| Rust | one worker task per subscription | no |

A slow callback may delay later events of its subscription but MUST never block
the socket reader.

### Synthetic `__disconnected__` event

When the demuxer stops (transport error, `close()`), it pushes a synthetic
event with `event_type = "__disconnected__"` to **every** registered callback,
carrying only `subscription_id` and `event_type`. This is client-local — the
daemon never sends it — and exists so long-running waits (e.g.
`wait_for_async_run`) unblock instead of hanging (S2). Pending request waiters
are woken with the empty/disconnect result at the same time.

Constant name per SDK: `EVENT_TYPE_DISCONNECTED` (Python/Rust/JS/Go as
`EventTypeDisconnected`, Java `MessageDemuxer.EVENT_TYPE_DISCONNECTED`).

### Pre-registration event buffering (atomic-subscribe race)

Events can arrive between server-side subscription creation and the client
registering its callback (e.g. atomic `add_app(subscribe_events=...)` on a fast
app whose output is pushed before `add_app` returns). The demuxer buffers such
events per subscription ID and flushes them — under the same lock, so buffered
events precede any later live event — when the callback registers (S4).

Bounds (identical in all SDKs, S5):

| Cap | Value | Overflow policy |
|---|---|---|
| Distinct unregistered subscription IDs | 64 | events for further IDs dropped |
| Buffered events per subscription ID | 1000 | drop oldest |

Buffers are discarded on demuxer stop and on unsubscribe.

## `wait_for_async_run` (subscribe-based wait)

Contract: subscribe to `STDOUT`, `EXIT`, `REMOVED` for the run's app; then
backfill output already emitted (`get_app_output` from position 0, which also
detects an already-exited process); deduplicate stdout by byte position to
bridge backfill and live events; wait for `EXIT` / `REMOVED` /
`__disconnected__` / caller timeout.

### Termination signaling per SDK

| Outcome | Python | Go | Rust | JavaScript | Java |
|---|---|---|---|---|---|
| Process exited | returns exit code | `(&code, nil)` | `Ok(Some(code))` | resolves exit code | returns exit code |
| Caller timeout | returns `None` | `(nil, nil)` | `Ok(None)` | resolves `null` | returns `null` |
| App removed before exit | raises `AppMeshAppRemovedError` | `(nil, ErrAppRemoved)` | `Err(AppMeshError::AppRemoved)` | throws `AppRemovedError` | throws `AppRemovedException` |
| Transport disconnected | raises `AppMeshConnectionError` | `(nil, ErrTransportDisconnected)` | `Err(AppMeshError::TransportDisconnected)` | throws `TransportDisconnectedError` | throws `TransportDisconnectedException` |

Exit codes may be **negative** (signal kills, e.g. `-2` = SIGINT) and must
round-trip as exit codes, not be conflated with error sentinels (S6).

### Cleanup policy

- **Unsubscribe:** best-effort after the wait ends — except when the transport
  is already dead (disconnect observed), where sending an unsubscribe request
  would register a waiter that never gets a response.
- **Delete-on-exit:** best-effort `delete_app` of the transient run app only
  after a **real observed exit**. Never after `REMOVED` (the app is already
  gone) and never after a disconnect (the daemon is unreachable and may still
  be running the process) (S8).

## Bearer authentication

App Mesh clients send access tokens as RFC 6750 bearer values. They do not call an Engine login, refresh, password, TOTP, user, or group endpoint. They do not get tokens from response cookies or response bodies.

The Python and Rust SDKs implement this token-provider contract:

- `AppMeshClient(base_url=..., bearer_token=...)` selects the Engine and attaches a caller-supplied access token.
- `AppMeshClient(..., token_provider=...)` asks a `TokenProvider` for a usable access token before a request.
- A client can retry one replayable request after a 401 when the provider can refresh.
- A client does not refresh or retry after a 403.
- `StaticAccessTokenProvider` keeps one caller-supplied token in memory. It does not refresh.
- `OAuthClient` supports authorization code with PKCE, device authorization, refresh, and best-effort revocation.
- The Rust `OAuthClient` also supports the built-in password exchange that the CLI uses.
- `OAuthClient.from_appmesh(..., access_url=...)` selects a separate route to the same authentication service.
- Discovery must publish the configured issuer. Route changes do not change issuer validation.
- `complete_authorization_callback` validates a single-use state before it exchanges a code.
- A nonce-bearing request requires a standards-compliant ID-token validator.
- A refresh token stays in the token provider. The SDK does not send it to the Engine.
- The SDK does not persist a token unless the application supplies persistence.

Python exports `OAuthClient` and `OAuthError`. Rust exports `OAuthConfig`, `OAuthClient`, `TokenSet`, `TokenProvider`, and `StaticAccessTokenProvider`. Provider-specific names from SDK 3.0 remain compatibility aliases. New code must use the provider-neutral names.

Rust validates authorization-flow ID tokens with discovered RS256 signing keys. It checks `alg`, `kid`, signature, issuer, audience, authorized party, expiry, not-before, and nonce. An application can register a callback to persist a rotated token set.

TCP and WSS send the same bearer as HTTP. WSS also sends it during the HTTP upgrade. The Engine pins the authenticated principal to the connection. Reconnect after a token refresh.

Go, Java, JavaScript, and C++ are bearer-only clients. They provide an in-memory token setter and clearer. Use a standards-based OAuth library when an application needs interactive sign-in or token refresh.

## Forwarding

HTTP, TCP, and WSS support forwarding for normal request methods. The client adds `X-Target-Host` to each forwarded request. The client also adds the current bearer.

WSS sends the bearer during the gateway upgrade. It also sends the bearer in each forwarded frame. The gateway checks that the frame bearer has the principal that the upgrade established. The target validates the bearer again.

The gateway validates a protected request before it opens a target connection. It removes `X-Target-Host` before it sends the request to the target. This rule prevents a forwarding loop.

The two public discovery requests can forward without a bearer:

- `GET /.well-known/oauth-protected-resource`;
- `GET /appmesh/auth/config`.

Forwarded subscriptions require TCP or WSS. The gateway keeps the subscription route after the first response. It sends all later event frames to the client that created the subscription. It removes the route after unsubscribe or disconnect. HTTP forwarding rejects a subscription request with status 405.

## File-transfer attributes

File upload/download transfers content by default. Applying or sending POSIX
mode, owner, and group metadata is opt-in because identities commonly differ
between machines and containers. Python, JavaScript, and C++ therefore default
their optional permission/attribute argument to `false`; Go, Rust, and Java
require an explicit boolean. The CLI uses `--apply-permissions` to opt in.

## Worker Task Loop (`fetch_task` / `send_task_result`)

The worker half of the client/worker model: an App Mesh-managed application
process polls the daemon for task payloads and returns results. Applies to all
transports (HTTP included — this loop has no demuxer dependency).

### Canonical type name per language

The task-loop helper's canonical name is the Worker form.

| Language | Canonical |
|---|---|
| Python | `AppMeshWorker` (+ TCP/WSS) |
| Go | `WorkerHTTPContext` (+ TCP/WSS) |
| Rust | `AppMeshWorker`/`AppMeshWorkerTCP`/`AppMeshWorkerWSS` |
| Java | `AppMeshWorker` (+ TCP/WSS) |
| JavaScript | `AppMeshWorker`/`AppMeshWorkerTCP` |

### Canonical method names per language

The two task-loop methods:

| Language | Canonical |
|---|---|
| Python | `fetch_task` / `send_task_result` |
| Go | `FetchTask`(`Context`) / `SendTaskResult` |
| Rust | `fetch_task` / `send_task_result` |
| Java | `fetchTask` / `sendTaskResult` |
| JavaScript | `fetch_task` / `send_task_result` |

| Operation | Endpoint |
|---|---|
| Fetch task | `GET /appmesh/app/{app_name}/task` |
| Return result | `PUT /appmesh/app/{app_name}/task` |

`APP_MESH_PROCESS_KEY` and `APP_MESH_APPLICATION_NAME` are injected by the
daemon; a missing variable is an immediate error, never retried. Worker SDKs
send the process proof only in `X-AppMesh-Process-Key`, never in a URL or query
string. Engine accepts it only on a direct loopback/private transport, and a
bearer-less WebSocket session is restricted to GET/PUT task RPC for the same
managed application process.

### Retry policy

Normative: except for the permanent 400 and superseded-process 412 cases below,
the fetch loop retries indefinitely with a **fixed 100 ms floor per attempt** —
if an attempt (request + failure handling) took less than 100 ms, sleep the
remainder; otherwise retry immediately. No backoff.

Python additionally accepts an optional `max_retries` cap (exhaustion raises
`AppMeshError`); the other SDKs retry forever.

### Superseded process (HTTP 412)

HTTP 412 on fetch means this process key was superseded by a newer process
instance; the loop MUST stop immediately (no retry) and surface a **typed**
error — never call `exit()` from library code:

| SDK | 412 signal |
|---|---|
| Python | raises `AppMeshProcessSupersededError` |
| Go | returns `ErrProcessSuperseded` |
| Rust | `Err(AppMeshError::ProcessSuperseded)` |
| Java | throws `ProcessSupersededException` |
| JavaScript | throws `ProcessSupersededError` |

### Permanently rejected worker request (HTTP 400)

HTTP 400 means the worker request is invalid or uses an obsolete protocol such
as `process_key` query authentication. Repeating the same request cannot recover,
so the loop MUST stop immediately and return/throw a permanent error. Library
code does not call `exit()`; a dedicated worker entry point should exit after
receiving this signal.

| SDK | 400 signal |
|---|---|
| Python | raises `AppMeshWorkerRejectedError` |
| Go | returns an error wrapping `ErrWorkerRejected` |
| Rust | `Err(AppMeshError::RequestFailed { status: 400, .. })` |
| Java | throws `IllegalStateException` |
| JavaScript | throws `WorkerRejectedError` |

### Cancellation signaling per SDK

Cancellation is checked at least once per retry iteration; SDKs whose
mechanism allows it (Python `stop_event.wait`, Go/Rust `select`) also abort
the retry sleep or the in-flight request. Java and JavaScript check a flag per
iteration, so worst-case cancel latency is one attempt plus the 100 ms floor.

| SDK | Cancel mechanism | Fetch result on cancel |
|---|---|---|
| Python | `stop_event` (`threading.Event`) argument | raises `AppMeshError` |
| Go | `context.Context` (`FetchTaskContext`) | returns wrapped `ctx.Err()` |
| Rust | `stop()` (watch channel) | `Err(AppMeshError::Cancelled)` |
| Java | `stop()` or thread interrupt | returns `null` |
| JavaScript | `stop()` (per-iteration flag) | resolves `null` |

## Conformance Scenarios

Each SDK's test suite should cover these named scenarios; when fixing a bug in
one SDK's demuxer/wait path, add or check the matching scenario in the others.

| # | Scenario | Expected behavior |
|---|---|---|
| S1 | Demuxer-routed request slower than the transport receive timeout (> 60s) | completes normally; no spurious timeout |
| S2 | Transport disconnects mid-`wait_for_async_run` | wait unblocks promptly with disconnect signaling (see matrix); no hang |
| S3 | Caller timeout mid-wait | timeout result (see matrix); subscription unsubscribed |
| S4 | Atomic `add_app(subscribe_events)` on a fast app | events pushed before callback registration are buffered and flushed in order; none lost |
| S5 | Event flood for a never-registered subscription | memory bounded by 64-sub / 1000-event caps; drop-oldest within a sub |
| S6 | Process killed by signal (negative exit code) | negative code returned as the exit code, not treated as an error/sentinel |
| S7 | Response arrives immediately after send | not dropped (pending waiter registered before send) |
| S8 | App removed while waiting | app-removed signaling; no `delete_app` attempt |

### Coverage status

Covering tests carry a greppable `Conformance: S<n>` comment (or the scenario
ID in the test name). Update this table in the same change that adds or
removes a covering test. **partial** = exercises the mechanism but not the
race/edge the scenario names; **MISSING** = no test at all.

| # | Python | Go | Rust | Java | JavaScript |
|---|---|---|---|---|---|
| S1 | MISSING | MISSING | MISSING | MISSING | MISSING |
| S2 | `test/unit/test_subscribe_conformance.py` `test_s2_disconnect_unblocks_wait` | `subscribe_test.go` `TestWaitForAsyncRunDisconnectUnblocks` | partial: `src/subscribe.rs` `conformance_s2_disconnect_broadcast_unblocks` + `src/wait_subscribe.rs` `conformance_s2_disconnected_event_classified` (wait path not driven) | `AsyncRunWaiterTest` `testDisconnectUnblocksWait` | `test/subscribe_test.js` `wait_for_async_run disconnect unblocks with typed error` |
| S3 | MISSING | MISSING | MISSING | MISSING | MISSING |
| S4 | partial: `test/integration/test_client.py` `test_66_add_app_with_subscribe_events` | MISSING | MISSING | MISSING | MISSING |
| S5 | MISSING | MISSING | MISSING | MISSING | MISSING |
| S6 | `test/unit/test_subscribe_conformance.py` `test_s6_negative_exit_code` | `subscribe_test.go` `TestWaitForAsyncRunNegativeExitCode` | partial: `src/wait_subscribe.rs` `conformance_s6_negative_exit_code_is_exit` (callback classification only) | `AsyncRunWaiterTest` `testNegativeExitCodeReturnedAsExitCode` | `test/subscribe_test.js` `wait_for_async_run returns negative exit code as-is` |
| S7 | `test/unit/test_subscribe_conformance.py` `test_s7_response_races_send` | partial: `subscribe_test.go` `TestMessageDemuxerRequestResponse` | partial: `src/subscribe.rs` `conformance_s7_response_routed_to_pre_registered_waiter` | partial: `SubscribeTest` `testDemuxerRoutesResponseToPreRegisteredWaiter` | partial: `test/subscribe_test.js` `MessageDemuxer routes responses by UUID` |
| S8 | MISSING | MISSING | MISSING | MISSING | MISSING |
| S9 | MISSING | MISSING | MISSING | MISSING | MISSING |
