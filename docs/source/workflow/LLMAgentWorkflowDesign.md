# LLM Agent Workflow - Design

## Status

> **⚠️ Superseded — read [`src/sdk/llm-agent/README.md`](../../../src/sdk/llm-agent/README.md) for the shipped design.**
> The implementation was later simplified to a **thin wrapper around the official Claude
> Agent SDK** (runs Claude by default; other models via Claude Code's provider env — see
> the README's *Models & providers*). The agent loop, tools (Claude Code's built-in tools), and
> conversation history are now the SDK's; llm-agent only routes `session_send`/`session_close`
> and gives each session a stable workdir. As a result the sections below describing a
> hand-rolled reason→act→observe loop, **multiple provider backends**, **tools-as-Apps**,
> **per-turn/per-tenant budgets**, and **multi-tenant L1/L2/L3 identity** no longer match the
> code — they record the original design rationale. The README is authoritative.

This document captures the originally agreed design for running LLM agents on top of App
Mesh, reusing the existing Workflow Engine ([WorkflowDesign.md](WorkflowDesign.md)) and
the daemon's App / Task / Event substrate.

**The shipped agent delegates the entire loop to the Claude Agent SDK**; the
agent loop, tools, and conversation history are the SDK's. The text below describes the
*original* cut, which delegated only LLM mechanics to provider SDKs and kept a custom App
Mesh integration (sessions, **tools-as-Apps**, budgets, multi-tenant identity, streaming) —
**none of that tools-as-Apps / budget / multi-provider machinery exists in the shipped code;
see the README.**

**Scenario B as a separate worker App.** Scenario A (batch) runs many sessions
in-process on one per-tenant App. Scenario B (interactive, streaming) needs a clean
per-session stdout — and App Mesh streams per App — so each interactive session runs as
its own **worker App** (the same binary with `--session-worker`). Both Apps are
**admin-provisioned**; `llm-agent` registers nothing itself (no dynamic spawn, no
`AddApp`). It holds **no daemon credentials**: the task RPC uses the daemon-injected
`APP_MESH_PROCESS_KEY`. A delegated daemon call may use the Engine-validated human Dex
bearer from a manual run; Engine-local workflow capabilities are never forwarded.
See *Process topology* and *Identity & Multi-Tenancy*.

The original first cut (since superseded — see the banner above) implemented: a
per-tenant handler App, a disk-persisted session store with TTL reaping, a hand-rolled
reason→act→observe loop, a tools-as-Apps catalog, per-turn + per-tenant budgets, worker
lifecycle, and the Task RPC loop (`session_open` / `session_send` / `session_close`).
Its backends were: `fake` (network-free,
for tests/dev), `anthropic` (official SDK), `openai` (official SDK; also any
OpenAI-compatible endpoint — vLLM / Ollama / TGI / DeepSeek — via `OPENAI_BASE_URL`), and
`gemini` (official `google-genai` SDK). See
[`src/sdk/llm-agent/README.md`](../../../src/sdk/llm-agent/README.md).

The guiding constraint, inherited from the workflow engine, is **reuse App Mesh as the
execution substrate with zero C++ daemon change**. The "hard" part of an agent — the
dynamic reason→act→observe loop — is confined inside a single managed App so the daemon,
the DAG engine, RBAC, concurrency, and observability all stay unchanged.

## Two Scenarios, One Substrate

The feature serves two distinct interaction models that share the same backend.

| | Scenario A — DAG-orchestrated LLM | Scenario B — Independent LLM environment |
|---|---|---|
| Shape | LLM call is a node in a static workflow DAG | Long-lived interactive session |
| Streaming | **No** — step returns a final structured result | **Yes** — token stream, watched live by a human |
| Entry point | Workflow `message` step → engine → shared App | **Direct** to daemon Task API + event Subscribe, **bypassing the workflow engine** |
| Result delivery | `RunTask` request/response (final structured result) | Out-of-band `Subscribe(STDOUT)` for tokens; final result via the same task call |
| Typical use | Batch / pipeline ("run a task, get a result") | Chat / agent ("a human drives a session over time") |

**Shared substrate (identical for A and B):**
- The **`llm_agent` runtime** that holds the LLM client, the session store, the agent
  loop, and the tool catalog (the shared per-tenant App `llm-agent-<tenant>` for A; a
  per-session worker App for B).
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
  (RunTask, final result)           │   ┌──────────────────────────────────┐
                                    ▼   │  worker App (one per session)      │  ◀── admin-provisioned
        ┌───────────────────────────────┐  │  python3 -m llm_agent              │
        │  llm-agent-<tenant> App        │  │      --session-worker              │
        │  Scenario A: in-process        │  │  behavior: exit: remove            │
        │  sessions                      │  │  ├── own stdout = stream           │
        └──────────────┬─────────────────┘  │  ├── own working dir               │
                       │                     │  └── idle / lifetime reaper        │
   both: session store · agent loop · tools catalog · per-tenant budget · L1/L2/L3
                       │ tool call = RunTask (manual caller bearer only) │
                       ▼                                                 ▼
                                  registered tool Apps (metadata.tool)
```

Each App is, from the daemon's point of view, an ordinary admin-provisioned App.
`llm-agent` registers nothing and holds no credentials — keeping the daemon and DAG
engine unchanged. A worker process gets its own `APP_MESH_PROCESS_KEY`, so its
`fetch_task` is scoped to itself.

## Agent Execution Model

- The reason→act→observe loop runs **inside** the App (`llm_agent/agent.py`). The
  workflow DAG stays **static** — a `message` step is one turn handed to a session; the
  loop iterates internally until it produces a final result. The number of iterations is
  unknown at parse time and never appears in the DAG.
- **Tools are registered App Mesh Apps only** (no arbitrary `command` execution by the
  model). A tool invocation is the agent calling back into App Mesh via `RunTask`.
- Confining the dynamic loop to one App is the central decision: it resolves the
  "static DAG vs. dynamic agent" tension by making the dynamic part invisible to the
  scheduler.

### Tools

- A tool is a registered App that carries its LLM function schema in the App's
  `metadata.tool` (description, JSON-schema parameters) — the same pattern the workflow
  engine uses to store workflows as Apps with `metadata.type=workflow`.
- The original catalog (`llm_agent/tools.py`) was built by listing Apps under a manual
  run's Dex bearer and filtering to those with a `metadata.tool` schema. Tool
  discovery and invocation therefore remained within that Principal's App Mesh RBAC.
- **Tool I/O contract:** tools are task Apps invoked via `RunTask`. The agent's JSON
  arguments are the task payload; the tool returns a structured JSON response. The
  calling session's `session_id` and a per-session `workdir` are injected into the
  arguments (the model's own value wins) so a file-writing tool can scope its side
  effects per session.

## Session Model

- A session is addressed by `session_id`, **lives across workflow runs**, and is
  reclaimed by **idle TTL**.
- **Get-or-create:** `session_send` creates an unknown `session_id` on first use
  (owner = caller), so a caller need not pre-open one or thread a session id in from
  outside. A workflow `message` step can therefore use
  `session_id: "${{ workflow.run_id }}"` for a fresh per-run session. `session_open`
  remains available to mint an explicit/long-lived id (e.g. for the direct SDK client).
- Session state (conversation history, token cost) is **persisted to disk** by the App
  (`<dir>/<tenant>/<id>.json`), namespaced per tenant.
- **Recovery semantics:** after a restart the session is **rebuilt from the persisted
  history** ("resume the conversation"). An in-flight turn at the moment of a crash is
  **lost and must be retried**. KV-cache-level resume is **out of scope**.

### Process topology

- **Scenario A (batch): one shared App per tenant** (`llm-agent` for the default tenant,
  `llm-agent-<tenant>` for a named one). Many
  sessions multiplexed in-process — cheap, no isolation needed for request/response
  steps. It serves `session_send` (which get-or-creates the session) and the optional
  `session_open`.
- **Scenario B (interactive): one admin-provisioned worker App per session.** The same
  binary run with `--session-worker --session-id=X` serves exactly that session; the
  client drives it directly (`RunTask` + `Subscribe(STDOUT)`). This gives a clean
  per-session stdout stream, a per-session working directory (tool file isolation), and
  hard per-session cancel — at the cost of one process per live interactive session.
  `llm-agent` does **not** spawn workers; an admin (or a provisioning layer) creates them
  (see `config/llm-agent-worker.yaml`).
- **Worker lifecycle is exit-driven.** Register the worker with `behavior: exit: remove`,
  so the daemon removes it whenever the process exits — on explicit `session_close`, an
  idle TTL, an absolute max-lifetime, or a crash. Teardown is thus a single reliable path
  (process exit → daemon cleanup).
- App Mesh starts each worker process, so it receives its own `APP_MESH_PROCESS_KEY` and
  its `fetch_task` is scoped to itself.

## Identity & Multi-Tenancy

Authentication follows ADR 0009 and the workflow policy in ADR 0006.

| Layer | Question | Enforced by |
|---|---|---|
| L1 | May you talk to the App at all? | daemon RBAC (`app-run-task`) |
| L2 | May you act on *this* session? | App policy keyed by immutable Principal ID |
| L3 | What may a delegated tool do? | App Mesh RBAC for the effective Dex Principal |

- **Manual workflow run:** the Engine validates the caller's Dex bearer and maps it to an
  immutable Principal ID. The bearer is ephemeral and never persisted in session state.
- **Automatic/recovered workflow run:** the local Engine issues a short-lived capability
  bound to the workflow owner, run, and current Workflow process, and re-checks the owner's
  RBAC on every operation. Registering such a trigger requires `workflow-admin`.
- **Session authorization** uses Principal IDs rather than usernames and remains
  namespaced per tenant.
- **Per-tenant model credentials:** each tenant has its own LLM API key / gateway,
  supplied as an App **secured (encrypted) env var** — never plaintext config.
- **Task transport:** `llm-agent` fetches its Task through the daemon-injected
  `APP_MESH_PROCESS_KEY`. The shipped agent does not validate a second token from the
  message body; it relies on the daemon's RBAC gate. `forward_token` can forward a manual
  run's human caller bearer to a target that explicitly needs delegated authorization. It
  is a no-op for automatic/recovered runs: internal capabilities never enter payloads.
- **Robustness:** untrusted client fields (per-turn limits) are coerced defensively, so a
  malformed payload returns a clean error rather than crashing the serving App.
- **Token expiry:** delegated calls fail closed when their Dex bearer expires. The agent
  never retains human refresh tokens.

## Streaming (Scenario B only)

- The native streaming primitive is **STDOUT events**: the engine already streams step
  stdout via `Subscribe(STDOUT)`, and all SDKs expose Subscribe.
- The agent writes generated tokens to stdout → STDOUT events → the client subscribes and
  renders the stream. **Two channels, not one:** the final structured result comes back
  via the task call; the token stream comes via STDOUT events. (A single blocking
  `RunTask` cannot also stream — hence the split.)
- **The stream for a session is a clean per-session STDOUT stream.** Because each
  interactive session runs in its own worker process, the worker's stdout *is* the
  session's stream — a subscriber sees only that session's tokens, no demux needed.
- Streaming is **rejected on the shared Scenario A App** (it multiplexes sessions on one
  stdout); the DAG (Scenario A) consumes final results only.

## Budget & Circuit Breaking

Enforced **inside the App** — the only place that holds the LLM client (token counts),
the loop (iteration counts), and the tenant identity together.

| Tier | Bounds | Guards against |
|---|---|---|
| **per-turn** | max iterations (tool-call rounds) + max tokens | a single runaway self-looping turn |
| **per-tenant** | cumulative token quota via a persisted cost ledger | one tenant exhausting the platform; chargeback |

- Limits are **hard ceilings, not advisory**. On breach: **abort the current turn and
  return a structured `budget_exceeded` result** (with iterations/tokens spent) — never
  silently truncate or continue.
- **Max iterations / tokens = operator-set ceilings; a caller may only *lower* them,
  never raise them** (`TurnLimits.clamp`) — flexibility within a cost floor.
- **per-session** budget is **Deferred** (first cut is per-turn + per-tenant).
- **Topology note (Scenario B):** the per-turn tier is enforced inside each worker. The
  per-tenant cumulative ledger is **shared on disk** — a per-tenant counter file
  (`<LLMAGENT_LEDGER_DIR>/<tenant>.ledger.json`) updated under an `flock`-guarded
  read-modify-write, so the Scenario A App and all workers pointed at the same dir
  (same tenant **and** same dir) account against one ceiling. (Advisory lock, Unix-only;
  fails open with a log on I/O error, since per-turn still caps a single turn.)

## Context / Memory Management — Design-only (not in first cut)

- Full history is persisted (Session Model); what is fed to the model each turn must fit
  the context window. The agreed strategy is **summarization/compaction as primary,
  sliding-window truncation as fallback**, run inside the App and counted against the
  budget, with **no explicit `compact` interface**.
- **First cut:** full history is persisted and sent to the model as-is; automatic
  compaction is **not yet implemented**. Long sessions are bounded operationally by the
  per-turn token ceiling and provider context limits until compaction lands.

## Inference Backend

- The first cut selects a backend per tenant via `LLMAGENT_BACKEND` (`fake` / `anthropic`
  / `openai` / `gemini`) with credentials/endpoint from the (secured) environment. A self-hosted
  OpenAI-compatible server (vLLM / Ollama / TGI) is reached by pointing `OPENAI_BASE_URL`
  at it — no extra code.
- **Design-only:** modeling the inference service as **an App Mesh App** (App Mesh
  managing its process lifecycle: start, health check, crash restart, cgroup limits,
  static GPU pinning via `CUDA_VISIBLE_DEVICES`) and a per-tenant **routing table** are
  agreed design but not part of the first cut.
- **GPU-aware scheduling** (multi-GPU bin-packing, fractional GPU, preemption) and
  **mixed routing within one tenant** are **out of scope** — App Mesh is a process
  manager, not a resource scheduler.

## Control Plane (Cancel / Interrupt) — Design-only (not in first cut)

**Deliberately minimal.** The agreed primitive is **"abort the current turn for session
X"**, default grain *stop the current turn, keep the session*:
  - Scenario A: cooperative cancel via a control signal (no `DeleteApp` fallback for one
    session — removing the shared App would harm the tenant's other sessions).
  - Scenario B: a **hard per-session kill** — removing/stopping the worker terminates
    exactly that session and nothing else.

**First cut:** an in-band cancel primitive is **not yet implemented**. A runaway turn is
bounded by the per-turn iteration/token ceilings and the tool `RunTask` timeout; a
Scenario B session can be hard-killed operationally by removing its worker App.

## Observability

First cut reuses the engine's existing facilities; no new subsystem.

- Run/step progress: the engine's `flow.log` and `step_log` (Scenario A).
- Per-turn token / iteration counts are returned in the result and accumulate in the
  **per-tenant cost ledger**.
- Full prompt / response / tool-call trace is **Deferred** — added only if agent
  debugging needs it.

## Decisions Summary

| # | Decision |
|---|---|
| Implementation | Python package `llm_agent` in `src/sdk/llm-agent/`; LLM mechanics delegated to official SDKs; **no MCP** on the core path |
| Scenarios | Two: A (DAG, no streaming) and B (interactive, streaming), sharing one design |
| Apps | Admin-provisioned; Scenario A = shared App per tenant (`llm-agent` default, `llm-agent-<tenant>` named); Scenario B = one worker App per session `<app>-sess-<id>` (`--session-worker`, `behavior: exit: remove`). `llm-agent` spawns nothing. |
| Agent loop | Inside the App; DAG stays static; engine unchanged |
| Tools | Registered Apps only; schema in `metadata.tool`; I/O via `RunTask` (structured); `session_id` + `workdir` injected |
| Session | Cross-run + idle TTL; disk-persisted, rebuilt on restart; no KV-cache resume |
| Identity | Task RPC via `APP_MESH_PROCESS_KEY`; only manual runs may delegate the Engine-validated human Dex bearer; internal workflow capabilities never leave Engine transport; session ownership uses immutable Principal IDs |
| Streaming | Scenario B only; out-of-band `Subscribe(STDOUT)` on the worker = a clean per-session stream; rejected on the shared App |
| Budget | per-turn (operator ceiling, caller may only lower) + per-tenant file-locked ledger; hard ceilings |
| Backends | `fake` / `anthropic` / `openai` (+ OpenAI-compatible via base URL) / `gemini`; key as secured env |
| Context | **Design-only**: auto summarization + truncation fallback; not in first cut |
| Inference | env-selected backend per tenant; inference-as-App + routing table **design-only**; no GPU scheduling |
| Control | **Design-only**: stop-current-turn; first cut relies on per-turn ceilings + tool timeout + worker removal |

## Deferred / Out of Scope

- per-session budget tier.
- Automatic context compaction / summarization (Context section).
- In-band cancel / interrupt primitive (Control Plane section).
- Inference-service-as-App lifecycle management + per-tenant routing table.
- KV-cache-level session resume.
- GPU-aware scheduling / bin-packing; mixed inference routing within a tenant.
- Full prompt/tool-call trace observability.
- Arbitrary `command` tools (only registered Apps are tools).
- Dynamic self-service spawning of Scenario B workers — they are admin-provisioned.
- Horizontal scale-out of the shared Scenario A App (its in-process session map and
  serial loop are per-process); heavy interactive load uses Scenario B workers.

## References

- [`src/sdk/llm-agent/README.md`](../../../src/sdk/llm-agent/README.md) — implementation: layout, env, wire protocol, install.
- [WorkflowDesign.md](WorkflowDesign.md) — workflow engine (DAG, steps, `message`/RunTask, Subscribe/STDOUT, registry scan).
- [CONTEXT.md](CONTEXT.md) — domain glossary (App, Task, Event, message step).
- ADR 0006 — workflow multi-tenant authorization (L1/L2/L3, invoker rights).
- ADR 0004 — proposed unified Run model (resource owner and actor Principal IDs).
- ADR 0009 — Dex-only authentication and Principal mapping.
