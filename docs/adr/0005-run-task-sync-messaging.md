# ADR 0005 — `run_task` Synchronous Task Messaging (Client ↔ Running App)

## Status

Accepted. Records the existing `run_task` mechanism, which spans the daemon and all
SDKs and had no single reference.

## Context

`run_task` lets a client send a payload to an **already-running** app and block for
its reply — a synchronous RPC into a long-lived process. Many clients may call one
app concurrently; the app consumes tasks one at a time. (Distinct from `run_async`/
`run_sync`, which spawn a new process.)

## Decision

The daemon is a **broker**: clients are producers, the app's embedded SDK server is
the single consumer. This is the classic broker-mediated task-queue pattern (cf.
Celery, AWS SQS), with the worker pulling work via **HTTP long-poll** (cf. SQS
`ReceiveMessage` long polling).

```
 client    --POST .../task-->   [ daemon: TaskRequest queue ]   <--GET .../task--  app (SDK)
 (blocks)                         per-app, mutex-guarded         --deliver body-->
   reply   <--complete held--                                   <--PUT .../task--  (result)
```

### REST surface — `…/appmesh/app/{name}/task`

| Verb | Caller | Auth | Effect |
|------|--------|------|--------|
| `POST` | client | RBAC `app-run-task` | Enqueue task; **hold the client request open** until reply/timeout |
| `GET` | app | process key | Long-poll: deliver next task (or park) |
| `PUT` | app | process key | Submit result; completes the held `POST` |
| `DELETE` | client | RBAC `app-run-task` | Cancel the in-flight task only |

### Server state (`TaskRequest`, one per `Application`)

`m_taskQueue` (FIFO of pending client `POST`s) · `m_activeTask` (dispatched to app) ·
`m_fetchTask` (parked `GET`) · `m_replyTask` (incoming `PUT`).

- **Per-client slot** — each `POST` is its own held `HttpRequestWithTimeout` with its
  own timeout, so concurrent calls queue independently.
- **Single lock** — all task methods run under the app's `m_process` recursive mutex;
  no separate task lock.
- **Lifetime** — a held request is completed by exactly one of: `replyTask`, its
  timer (`RequestTimeout`), `deleteTask` (`ExpectationFailed`), or `terminate()`.

### Exactly-once reply (the core mechanism)

A held request can be completed from several sources — worker `replyTask`, timer
`onTimerResponse`, `interrupt()`, destructor backstop — possibly racing across
threads. Correctness rests on **one-shot completion** — a single response sink that
can fire only once, the same guarantee as a complete-once promise (`CompletableFuture.
complete()`, Go `sync.Once`, Rust `oneshot::Sender`):

- All convenience `reply(status, …)` overloads delegate **unqualified** to the
  virtual 6-arg `reply(...)`.
- `HttpRequestWithTimeout` overrides that one method: it cancels the timer, then
  `m_httpRequestReplyFlag.exchange(true)` — only the first caller proceeds to the
  actual send; the rest no-op.
- Because every path goes through a convenience overload, they all hit the gate —
  even `HttpRequest::reply(RequestTimeout)` in the timer/destructor, where the
  explicit qualifier only picks the entry overload while the inner 6-arg call still
  dispatches dynamically to the override.

**Result: exactly one frame per request, on every transport, with the thread race
resolved atomically by `exchange`.** Call sites need no extra guard. Transport-level
dedup (HTTP `ReplyContext` idempotency; TCP/WS uuid correlation — cf. JMS correlation
id / HTTP/2 stream id) is a secondary backstop never actually reached twice.

### Identity

- **Client → daemon:** JWT + RBAC `app-run-task` + per-app access check.
- **App → daemon:** the spawned process authenticates `GET`/`PUT` with its **process
  key** (`AppProcess::getkey()`), an unguessable per-process capability token (cf.
  GitHub Actions runner registration token) — hence no RBAC on the app-side verbs.

### Cancel

`deleteTask` cancels only `m_activeTask`; queued tasks belong to other clients (each
with its own timeout) and must not be aborted. Full drain happens in `terminate()`.

### Client SDKs

All expose `run_task(app, data, timeout)` → `POST …/task`, blocking until reply or
timeout. Daemon default `DEFAULT_RUN_TASK_TIMEOUT_SECONDS = 300`, capped at
`MAX_RUN_APP_TIMEOUT_SECONDS = 3 days`.

## Consequences

- **+** Concurrent clients isolated (per-`POST` slot); single lock keeps the state
  machine race-free; exactly-once reply is structural, not per-call-site.
- **+** Clear authority split: RBAC for clients, capability token for the app.
- **−** App-side long-poll has no timeout (idle `GET` pinned until process exit).
- **−** Task body is copied per hop under the lock; large payloads serialize the app.
- **−** One consumer per app — fan-out needs multiple app instances.
- *Known gap:* only the Go SDK clamps non-positive `timeout` client-side; unifying it
  is a follow-up.
