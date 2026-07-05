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

## Auth Token Synchronization (TCP/WSS)

The HTTP transport relies on `Set-Cookie` and the HTTP library's cookie jar.
TCP/WSS transports must extract the new `access_token` from auth endpoint JSON
bodies themselves — only on HTTP 200, and only for these paths:

| Path | When to apply the body's `access_token` |
|---|---|
| `/appmesh/login`, `/appmesh/auth`, `/appmesh/totp/validate` | only when the **request** carried `X-Set-Cookie: true` |
| `/appmesh/token/renew`, `/appmesh/totp/setup` | always (client already has an active session) |
| `/appmesh/self/logoff` | clear the cached token |

This list is duplicated in Python (`transport_mixin.py`), Go (`requester.go`),
Rust (`requester.rs`), and JavaScript (`appmesh_tcp.js`); keep all of them —
and this table — in sync.

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
| Fetch task | `GET /appmesh/app/{app_name}/task?process_key=...` |
| Return result | `PUT /appmesh/app/{app_name}/task?process_key=...` |

`APP_MESH_PROCESS_KEY` and `APP_MESH_APPLICATION_NAME` are injected by the
daemon; a missing variable is an immediate error, never retried.

### Retry policy

Normative: the fetch loop retries indefinitely with a **fixed 100 ms floor per
attempt** — if an attempt (request + failure handling) took less than 100 ms,
sleep the remainder; otherwise retry immediately. No backoff.

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
| S9 | Token renew while other demuxer traffic is in flight | renew reply matched by UUID and applied; unrelated responses not cross-wired |

### Coverage status

Covering tests carry a greppable `Conformance: S<n>` comment (or the scenario
ID in the test name). Update this table in the same change that adds or
removes a covering test. **partial** = exercises the mechanism but not the
race/edge the scenario names; **MISSING** = no test at all.

| # | Python | Go | Rust | Java | JavaScript |
|---|---|---|---|---|---|
| S1 | MISSING | MISSING | MISSING | MISSING | MISSING |
| S2 | `test/test_appmesh_client.py` `test_s2_disconnect_unblocks_wait` | `subscribe_test.go` `TestWaitForAsyncRunDisconnectUnblocks` | partial: `src/subscribe.rs` `conformance_s2_disconnect_broadcast_unblocks` + `src/wait_subscribe.rs` `conformance_s2_disconnected_event_classified` (wait path not driven) | `AsyncRunWaiterTest` `testDisconnectUnblocksWait` | `test/subscribe_test.js` `wait_for_async_run disconnect unblocks with typed error` |
| S3 | MISSING | MISSING | MISSING | MISSING | MISSING |
| S4 | partial: `test/test_appmesh_client.py` `test_66_add_app_with_subscribe_events` | MISSING | MISSING | MISSING | MISSING |
| S5 | MISSING | MISSING | MISSING | MISSING | MISSING |
| S6 | `test/test_appmesh_client.py` `test_s6_negative_exit_code` | `subscribe_test.go` `TestWaitForAsyncRunNegativeExitCode` | partial: `src/wait_subscribe.rs` `conformance_s6_negative_exit_code_is_exit` (callback classification only) | `AsyncRunWaiterTest` `testNegativeExitCodeReturnedAsExitCode` | `test/subscribe_test.js` `wait_for_async_run returns negative exit code as-is` |
| S7 | `test/test_appmesh_client.py` `test_s7_response_races_send` | partial: `subscribe_test.go` `TestMessageDemuxerRequestResponse` | partial: `src/subscribe.rs` `conformance_s7_response_routed_to_pre_registered_waiter` | partial: `SubscribeTest` `testDemuxerRoutesResponseToPreRegisteredWaiter` | partial: `test/subscribe_test.js` `MessageDemuxer routes responses by UUID` |
| S8 | MISSING | MISSING | MISSING | MISSING | MISSING |
| S9 | MISSING | MISSING | MISSING | MISSING | MISSING |
