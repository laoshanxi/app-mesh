# LLM Agent Workflow - Design

## Status

Proposed — first cut implemented. This document captures the agreed design for running
LLM agents on top of App Mesh, reusing the existing Workflow Engine
([WorkflowDesign.md](WorkflowDesign.md)) and the daemon's App / Task / Event substrate.
Sections marked **Deferred** or **Out of scope** are explicitly not in the first cut.

**Revision (Scenario B as a separate worker App).** Scenario A (batch) runs many
sessions in-process on one per-tenant App. Scenario B (interactive, streaming) needs
a clean per-session stdout — and App Mesh streams per App — so each interactive
session runs as its own **worker App** (the same binary with `--session-worker`).
Both Apps are **admin-provisioned**; model-env registers nothing itself (no dynamic
spawn, no `AddApp`). It also holds **no daemon credentials**: the task RPC uses the
daemon-injected `APP_MESH_PROCESS_KEY`, and every other daemon call runs under the
caller's token from the request payload. See *Process topology* and *Identity*.

The first cut lives in `src/model-env/` (Go): the per-tenant model-env App, session
store, ReAct agent loop, tool catalog, budgets, and the Task RPC loop
(`session_open` / `session_send` / `session_close`). Backends: `stub` (network-free,
for tests), `anthropic` (Messages API), `local` (OpenAI-compatible, for self-hosted
vLLM / Ollama / TGI / llama.cpp), and `remote` (forwards one model call to an external
reasoning service over HTTP). See `src/model-env/README.md`.

The guiding constraint, inherited from the workflow engine, is **reuse App Mesh as the
execution substrate with minimal (ideally zero) C++ daemon change**. The "hard" part of
an agent — the dynamic reason→act→observe loop — is deliberately confined inside a
single managed App so the daemon, the DAG engine, RBAC, concurrency, and observability
all stay unchanged.

## Two Scenarios, One Substrate

The feature serves two distinct interaction models that share the same backend.

| | Scenario A — DAG-orchestrated LLM | Scenario B — Independent LLM environment |
|---|---|---|
| Shape | LLM call is a node in a static workflow DAG | Long-lived interactive session |
| Streaming | **No** — step returns a final structured result | **Yes** — token stream, watched live by a human |
| Entry point | Workflow `message` step → engine → model-env App | **Direct** to daemon Task API + event Subscribe, **bypassing the workflow engine** |
| Result delivery | `RunTask` request/response (final structured result) | Out-of-band `Subscribe(STDOUT)` for tokens; final result via the same task call |
| Typical use | Batch / pipeline ("run a task, get a result") | Chat / agent ("a human drives a session over time") |

**Shared substrate (identical for A and B):**
- A per-tenant **model-environment App** (`model-env`) that holds the warm LLM client,
  the session store, the agent loop, and the tool catalog.
- One **session store** (per tenant).
- One **tool catalog** (registered Apps).
- One **multi-tenant authorization** model (the engine's existing L1/L2/L3).

Scenario B does not depend on the workflow engine at all — it is "a long-lived App with
a session Task API plus STDOUT streaming." The workflow engine's `message` step is just
*another client* of that same session API.

## Architecture

```
Scenario A (DAG)                         Scenario B (interactive)
  CLI/GUI/SDK                              CLI/GUI/SDK
     │ run workflow                           │ session_send / close (by app name)
     ▼                                        │ Subscribe(STDOUT)
  workflow engine ── message step ──┐         ▼
  (RunTask, final result)           │   ┌─────────────────────────────┐
                                    ▼   │  worker App (one per session)│   ◀── admin-provisioned
        ┌──────────────────────────────┐   │  model-env --session-worker  │
        │  model-env App (per tenant)  │   │  behavior: exit: remove      │
        │  Scenario A: in-process      │   │  ├── own stdout = stream     │
        │  sessions                    │   │  ├── own working dir         │
        └──────────────┬───────────────┘   │  └── idle / lifetime reaper  │
                       │                    └──────────────┬───────────────┘
   both: session store · agent loop (ReAct) · tool catalog · per-tenant budget · L1/L2/L3
                       │ tool call = RunTask (under caller token)        │
                       ▼                                                 ▼
                                  registered tool Apps (whitelist)
```

Each App is, from the daemon's point of view, an ordinary admin-provisioned App.
model-env registers nothing and holds no credentials — keeping the daemon and DAG
engine unchanged. A worker process gets its own `APP_MESH_PROCESS_KEY`, so its
`task_fetch` is scoped to itself.

## Agent Execution Model

- The reason→act→observe (ReAct) loop runs **inside** the `model-env` App. The workflow
  DAG stays **static** — a `message` step is one turn handed to a session; the loop
  iterates internally until it produces a final result. The number of iterations is
  unknown at parse time and never appears in the DAG.
- **Tools are registered App Mesh Apps only** (a whitelist — no arbitrary `command`
  execution by the model). A tool invocation is the agent calling back into App Mesh.
- Confining the dynamic loop to one App is the central decision: it resolves the
  "static DAG vs. dynamic agent" tension by making the dynamic part invisible to the
  scheduler.

### Tools

- A tool is a registered App that carries its LLM function schema in the App's
  `metadata.tool` (name, description, JSON-schema parameters) — the same pattern the
  workflow engine already uses to store workflows as Apps with `metadata.type=workflow`.
- The `model-env` App builds its tool catalog by listing Apps (periodically, like the
  engine's 30s registry scan) **filtered to those the caller's token may see/run**.
  Because tool discovery and invocation both run under the caller's token (see Identity),
  the catalog is **automatically scoped to what the tenant could already run directly** —
  the whitelist needs no separate maintenance.
- **Tool I/O contract:** tools are long-lived task Apps invoked via `RunTask`. The
  agent's JSON arguments are the task payload; the tool returns a structured JSON
  response. Request/response with structured payloads matches function-calling semantics
  and avoids the cold start of one process per tool call.

## Session Model

- A session is addressed by `session_id`, **lives across workflow runs**, and is
  reclaimed by **TTL / LRU**.
- Session state (conversation history, agent scratchpad, tool results) is **persisted to
  disk** by the `model-env` App, in the same spirit as the engine streaming step logs to
  `{job}.{step}.log`.
- **Recovery semantics:** after a `model-env` restart the session is **rebuilt from the
  persisted history** ("resume the conversation"). An in-flight turn at the moment of
  the crash is **lost and must be retried** — consistent with the engine's existing
  "mid-step crash cannot resume; the job reruns from its first step." KV-cache-level
  resume is **out of scope**.

### Process topology

- **Scenario A (batch): one shared per-tenant App.** Many sessions multiplexed
  in-process — cheap, no isolation needed for request/response steps. It is the
  entry point for `session_open`.
- **Scenario B (interactive): one admin-provisioned worker App per session.** The
  same binary run with `--session-worker --session-id=X` serves exactly that
  session; the client drives it directly (`RunTask` + `Subscribe(STDOUT)`). This
  gives a clean per-session stdout stream, a per-session working directory (tool
  file isolation), a per-session `LinuxCgroup`, and hard per-session cancel — at the
  cost of one process (and one warm backend client) per live interactive session.
  model-env does **not** spawn workers; an admin (or a provisioning layer) creates
  them (see `config/model-env-worker.yaml`).
- **Worker lifecycle is exit-driven.** Register the worker with
  `behavior: exit: remove`, so the daemon removes it whenever the process exits —
  on explicit `session_close`, an idle TTL, an absolute max-lifetime, or a crash.
  Teardown is thus a single reliable path (process exit → daemon cleanup).
- App Mesh starts each worker process, so it receives its own `APP_MESH_PROCESS_KEY`
  and its `task_fetch` is scoped to itself.

## Identity & Multi-Tenancy

Reuses the workflow engine's existing three-layer model (ADR 0006), extended to sessions.

| Layer | Question | Enforced by |
|---|---|---|
| L1 | May you talk to the App at all? | daemon RBAC (`app-run-task`) |
| L2 | May you act on *this* session? | `model-env` PDP — `session.owner == caller \|\| isAdmin` |
| L3 | What may a tool do? | the **caller's own token** runs the tool → daemon per-App ACL applies |

- **Execution identity:** every call re-authenticates with the **caller's current token**
  (taken from the task payload, validated, then stripped — never persisted). The session
  is **data owned by the `model-env` App**; whoever calls uses their own identity. This
  reuses the engine's already-implemented invoker-rights model with no new infrastructure.
- **Session authorization** mirrors L2 for workflows: the `model-env` App is its own PDP,
  and session storage is **namespaced per tenant** so cross-tenant reads are physically
  impossible.
- **Per-tenant model credentials:** each tenant has its own LLM API key / gateway.
- **No service identity:** model-env holds no daemon credentials. The task RPC
  authenticates with the daemon-injected `APP_MESH_PROCESS_KEY`; the caller's token
  from each request validates the session (a self lookup confirms the token) and runs
  the tools (L3). Identity is decided upstream and forwarded in the payload (the
  workflow engine forwards the invoker's token in Scenario A; the client sends its own
  in Scenario B); model-env validates and adopts it.
- **Token-expiry note:** because Scenario B is interactive (each turn arrives with the
  caller's then-current token), the per-call re-auth model fits naturally. The only
  exposure is a *single* agent turn whose loop outlives the token — that fails closed,
  which is the desired security semantic. A long-lived `execution_identity` / act-as
  model (cross-user shared sessions, automatic-trigger-driven long sessions) is the
  longer-term path in ADR 0004 Phase 3 and is **Deferred**.

## Streaming (Scenario B only)

- The native streaming primitive is **STDOUT events**: the engine already streams step
  stdout by `Subscribe(STDOUT)` before `RunAppAsync`, and all six SDKs expose Subscribe.
- The agent writes generated tokens to stdout → STDOUT events → the client subscribes
  and renders the stream. **Two channels, not one:** the final structured result comes
  back via the task call; the token stream comes via STDOUT events. (A single blocking
  `RunTask` cannot also stream — hence the split.)
- **The generated stream for a session is a clean per-session STDOUT stream.** Because
  each interactive session runs in its own worker process, the worker's stdout *is* the
  session's stream — a subscriber of the worker App sees only that session's tokens, with
  no demux needed. (This is what the process-per-session topology buys; the earlier
  shared-host design could only frame a shared stdout by session id.)
- The DAG (Scenario A) does **not** stream — its steps consume final results only.

## Budget & Circuit Breaking

Enforced **inside the `model-env` App** — the only place that holds the LLM client (token
counts), the loop (iteration counts), and the tenant identity together. The daemon and
engine cannot see tokens, so they cannot enforce this.

| Tier | Bounds | Guards against |
|---|---|---|
| **per-turn** | max iterations (tool-call rounds) + max tokens | a single runaway self-looping turn |
| **per-tenant** | quota / rate / cost budget + a persisted cost ledger | one tenant exhausting the platform; chargeback |

- Limits are **hard ceilings, not advisory**. On breach: **abort the current turn and
  return a structured `budget_exceeded` result** (with used/limit) — never silently
  truncate or continue.
- **Max iterations = an operator-set global ceiling; callers may only lower it, never
  raise it** — flexibility within a cost floor.
- A budget breach triggers the same abort path as cancellation (below).
- **per-session** budget is **Deferred** (first cut is per-turn + per-tenant).
- **Topology note (Scenario B):** the per-turn tier is enforced inside each worker.
  The per-tenant cumulative ledger is **shared on disk** — a per-tenant counter file
  under `MODELENV_LEDGER_DIR`, updated under an `flock`-guarded read-modify-write, so
  the Scenario A App and all workers pointed at the same dir account against one
  ceiling. (Advisory lock, Unix-only; fails open with a log on I/O error, since
  per-turn still caps a single turn.)

## Context / Memory Management

- Full history is persisted (Session Model); what is fed to the model each turn must fit
  the context window. Because sessions are long-lived (days), this is unavoidable.
- Strategy: **summarization/compaction as primary, sliding-window truncation as
  fallback.** When history exceeds a threshold the `model-env` App summarizes older turns
  into a compact memory (it already holds the LLM client, so no new component is needed);
  truncation is the cheap fallback.
- Compaction is **fully automatic and transparent** — there is **no explicit `compact`
  interface** exposed to callers or workflows.
- Compaction calls **count against the budget** (per-turn / per-tenant), so they cannot
  run away.

## Inference Backend

- The inference service (vLLM / ollama / TGI / an API gateway) is modeled as **an
  ordinary App Mesh App** — App Mesh manages **process lifecycle only**: start, health
  check, crash restart (`behavior: exit: restart`), `LinuxCgroup` limits, and **static**
  GPU pinning via env (e.g. `CUDA_VISIBLE_DEVICES`).
- **GPU-aware scheduling (multi-GPU bin-packing, fractional GPU, preemption) is out of
  scope** — App Mesh is a process manager, not a resource scheduler; that belongs to
  k8s device plugins / Volcano / Slurm.
- The `model-env` client routes to a **single backend per tenant** (external API *or* a
  local inference App), via a per-tenant routing table. Mixed routing within one tenant
  is **out of scope**. This layer is essentially configuration + a routing table, with
  almost no new code.

## Control Plane (Cancel / Interrupt)

**Deliberately minimal in the first cut** (simplicity first; no over-engineering).

- One primitive for both scenarios: **"abort the current turn for session X."**
  - Scenario A: the engine's `cancelRun` sends a cooperative control signal to the
    `model-env` App, and any in-flight tool App (a normal temporary App) is killed via
    the engine's existing `KillAll` / `RemoveApp`.
  - Scenario B: the client sends an interrupt directly to the session (chat-style "stop
    generating") — the same signal.
- **Default grain: stop the current turn, keep the session** (so the user can continue),
  consistent with long-lived sessions.
- **Scenario A** (in-process on the shared App): cancel is **cooperative** — there is
  no `RemoveApp` fallback for a single session, since removing the App would harm the
  tenant's other sessions.
- **Scenario B** (per-session worker App): a **hard per-session kill** is available —
  removing/stopping the worker terminates exactly that session and nothing else.

## Observability

First cut reuses the engine's existing facilities; no new subsystem.

- Run/step progress: the engine's `flow.log` and `step_log` (Scenario A).
- Per-turn token / iteration counts flow into the **per-tenant cost ledger**.
- Full prompt / response / tool-call trace is **Deferred** — added only if agent
  debugging needs it.

## Decisions Summary

| # | Decision |
|---|---|
| Scenarios | Two: A (DAG, no streaming) and B (interactive, streaming), sharing one design |
| Apps | Admin-provisioned; Scenario A = shared per-tenant App; Scenario B = one worker App per session (`--session-worker`, `behavior: exit: remove`). model-env spawns nothing. |
| Agent loop | Inside the App; DAG stays static; engine unchanged |
| Tools | Registered Apps only; schema in `metadata.tool`; I/O via `RunTask` (structured); session_id + workdir injected |
| Session | Cross-run + TTL; disk-persisted, rebuilt on restart; no KV-cache resume |
| Identity | No service credentials: task RPC via `APP_MESH_PROCESS_KEY`; every other call under the caller's token (validated per request); session = data owned by the App (L1/L2/L3) |
| Streaming | Scenario B only; out-of-band `Subscribe(STDOUT)` on the worker = a clean per-session stream; Scenario A never streams |
| Budget | per-turn (global iteration ceiling, caller may only lower) + per-tenant file-locked ledger; hard ceilings |
| Context | Auto, transparent summarization + truncation fallback; no explicit compact API |
| Inference | Process lifecycle only (no GPU scheduling); single backend per tenant; config-driven |
| Control | Stop-current-turn default; Scenario A cooperative; Scenario B hard per-session kill via worker removal |

## Deferred / Out of Scope

- per-session budget tier.
- `execution_identity` / act-as for cross-user shared sessions and automatic-trigger
  long sessions (ADR 0004 Phase 3).
- KV-cache-level session resume.
- GPU-aware scheduling / bin-packing.
- Mixed inference routing within a single tenant.
- Full prompt/tool-call trace observability.
- Arbitrary `command` tools (only registered Apps are tools).
- Dynamic self-service spawning of Scenario B workers — they are admin-provisioned.
- Horizontal scale-out of the Scenario A App (its in-process session map and serial
  loop are per-process); heavy interactive load uses Scenario B workers.

## References

- [WorkflowDesign.md](WorkflowDesign.md) — workflow engine (DAG, steps, `message`/RunTask, Subscribe/STDOUT, registry scan).
- [CONTEXT.md](CONTEXT.md) — domain glossary (App, Task, Event, message step).
- ADR 0006 — workflow multi-tenant authorization (L1/L2/L3, invoker rights).
- ADR 0004 — unified run / identity model (resource_owner / actor / execution_identity).
