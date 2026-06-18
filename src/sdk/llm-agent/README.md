# llm-agent

A thin LLM-agent runtime that runs **as an App Mesh App**. It wraps the official
provider SDKs (`anthropic`, `openai`) in a small reason→act→observe loop and gives
that loop App Mesh's identity, RBAC, sessions, and tools — without re-implementing
provider HTTP, streaming, or tool-calling formats.

It deliberately does **not** use MCP on the core path: tools are ordinary App Mesh
Apps (see [Tools are Apps](#tools-are-apps)), invoked in-process under the caller's
token. The only genuinely custom code here is the App Mesh integration; the LLM
mechanics are delegated to the vendor SDKs.

## Two scenarios, two Apps

The same `llm_agent` binary runs in two roles. Both are **admin-provisioned Apps** —
this package registers nothing itself.

| | Scenario A — batch / DAG | Scenario B — interactive |
|---|---|---|
| App | one shared App per tenant — `llm-agent` (default tenant) or `llm-agent-<tenant>` | one worker App per session — `<app>-sess-<id>` (e.g. `llm-agent-sess-S1`) |
| Started by | daemon at boot (`status: 1`) | admin, per session |
| Sessions | many, in-process, owner-checked | exactly one, pre-assigned |
| Streaming | no (returns the final answer) | yes (worker streams to its own STDOUT) |
| Lifecycle | long-lived (`exit: restart`) | exits on close/idle/max-life → daemon removes it (`exit: remove`) |
| Config | [`config/llm-agent.yaml`](config/llm-agent.yaml) | [`config/llm-agent-worker.yaml`](config/llm-agent-worker.yaml) |

A workflow DAG step (or any batch caller) talks to the shared App and gets one final
answer. An interactive client talks to its own worker App and `Subscribe`s to its
STDOUT for token-by-token streaming — each session's worker has a clean stdout, so a
subscriber sees only that session's tokens.

## Request flow

```
client / workflow step
   │  run_task(app, {action, token, session_id, input, ...})   ← caller's JWT in payload
   ▼
App Mesh daemon ── task RPC (authenticated by daemon-injected APP_MESH_PROCESS_KEY) ──▶ llm_agent App
                                                                                          │
   handler: authenticate(token) → username                                                │
   store.get(session, owner-check)  ·  ledger.check(tenant)                                │
   agent loop:  llm.complete(messages, tools) ──▶ provider SDK                             │
                tool_calls? → ToolCatalog.invoke ── run_task(tool App) under caller token ─┘
                else → final answer
   ledger.add(tenant, tokens) · persist(session)
```

## Identity & authorization — no service credentials

The runtime holds **no daemon credentials**. Two distinct auth paths:

- **Task RPC** (`task_fetch` / `task_return`) is authenticated by the daemon-injected
  `APP_MESH_PROCESS_KEY` — no JWT needed for the App to receive tasks.
- **Every other daemon call** (validating the caller, listing/running tool Apps) runs
  under the **caller's token**, which arrives in each request payload's `token` field.

This composes with the workflow engine (ADR 0006): the engine holds the triggering
user's token and forwards it into the message payload when the DAG step sets
**`forward_token: true`** (see [Driving from a workflow](#driving-from-a-workflow-scenario-a)),
so llm-agent acts **as that user**. Authorization is layered:

- **L1** — the daemon authorizes the inbound `run_task` (app-run-task) as usual.
- **L2** — a session may be used only by its owner (the authenticated caller) or an
  admin; a non-owner gets `Forbidden`.
- **L3** — tools run under the caller's token, so the tool set is exactly what the
  caller could already see/run — RBAC-scoped automatically, no separate allowlist.

The handler validates each token by calling `get_current_user()` with it before
trusting the username decoded from its claims.

## Tools are Apps

A tool is any registered App carrying a `metadata.tool` schema:

```yaml
metadata:
  tool:
    description: Echo back the provided arguments.
    parameters: { type: object, properties: { message: { type: string } } }
```

`ToolCatalog.specs()` lists the Apps the caller's token can see and advertises those
with a `tool` schema; `invoke()` runs the chosen App via `run_task` (JSON in/out)
under the caller's identity. The calling session's `session_id` and a per-session
`workdir` are injected into the tool arguments (the model's own value wins) so a
file-writing tool can scope its side effects per session.

See [`config/echo-tool.yaml`](config/echo-tool.yaml) + [`examples/echo_tool.py`](examples/echo_tool.py).

## Budgets

- **Per-turn** — `max_iterations` / `max_tokens` bound a single turn. A request may
  only *tighten* the operator ceiling (`LLMAGENT_MAX_ITERATIONS` / `LLMAGENT_MAX_TOKENS`),
  never loosen it; a breach raises `budget_exceeded` and surfaces how far the turn got.
- **Per-tenant** — a cumulative token quota (`LLMAGENT_TENANT_QUOTA`) enforced through
  an flock-guarded ledger file at `<LLMAGENT_LEDGER_DIR>/<tenant>.ledger.json`. The
  shared App and every Scenario B worker for a tenant point at the same dir, so they
  share one quota (same tenant **and** same dir is required).

## Backends

Select with `LLMAGENT_BACKEND`:

| value | SDK | notes |
|---|---|---|
| `fake` (default) | none | deterministic `stub: <input>`, no network — for tests/dev. A `use tool <name> <json>` message drives one tool round. |
| `anthropic` | `anthropic` | reads `ANTHROPIC_API_KEY` (+ `ANTHROPIC_BASE_URL`); `LLMAGENT_MODEL` (default `claude-opus-4-8`). |
| `openai` | `openai` | reads `OPENAI_API_KEY` (+ `OPENAI_BASE_URL`); `LLMAGENT_MODEL` (default `gpt-4o`); works with any OpenAI-compatible endpoint. Note: a backend that does not report streaming usage tokens disables token budgets for streamed turns (logged as a warning). |

Credentials come from the environment, never hardcoded. Set a real key as a secured
env var on the App (e.g. `appm add -z ANTHROPIC_API_KEY=<key> ...`).

## Configuration (env)

| var | default | meaning |
|---|---|---|
| `APPMESH_TENANT` | `default` | tenant; namespaces sessions and the quota ledger |
| `APPMESH_SESSION_OWNER` | — | worker mode: the session owner (required) |
| `APPMESH_WORKFLOW_ADMINS` | `admin` | comma list of admin usernames (L2 override) |
| `LLMAGENT_BACKEND` | `fake` | `fake` \| `anthropic` \| `openai` |
| `LLMAGENT_MODEL` | per-backend | model id |
| `LLMAGENT_MAX_OUTPUT_TOKENS` | `4096` | provider max output tokens per call |
| `LLMAGENT_SESSION_DIR` | `./llm-agent-sessions` | session JSON store |
| `LLMAGENT_LEDGER_DIR` | = session dir | quota ledger dir (share across Apps) |
| `LLMAGENT_WORKSPACE_DIR` | `./llm-agent-workspace` | per-session tool workdirs |
| `LLMAGENT_MAX_ITERATIONS` | `8` | per-turn iteration ceiling |
| `LLMAGENT_MAX_TOKENS` | `0` (off) | per-turn token ceiling |
| `LLMAGENT_TENANT_QUOTA` | `0` (off) | cumulative per-tenant token quota |
| `LLMAGENT_TOOL_TIMEOUT` | `300` | tool `run_task` timeout (s) |
| `LLMAGENT_PROVIDER_TIMEOUT` | `120` | per-request provider (anthropic/openai) timeout (s) |
| `LLMAGENT_MAX_INPUT_CHARS` | `0` (off) | reject a turn whose `input` exceeds this many chars |
| `LLMAGENT_SESSION_TTL_HOURS` | `168` | shared App: idle session reap |
| `LLMAGENT_SESSION_IDLE_MINUTES` | `30` | worker: idle reap |
| `LLMAGENT_SESSION_MAX_HOURS` | `8` | worker: max lifetime |

## Wire protocol (run_task payload)

```jsonc
// session_open  — Scenario A only. On a worker App it returns an error; the worker
//                 already serves its pre-assigned session_id, so send to it directly.
{ "action": "session_open", "token": "<jwt>" }            → { "status":"ok", "data": { "session_id": "..." } }

// session_send
{ "action": "session_send", "token": "<jwt>", "session_id": "...",
  "input": "hello", "stream": false,                       // stream only on a worker App
  "max_iterations": 0, "max_tokens": 0 }                   → { "status":"ok",
                                                               "data": { "answer", "iterations", "turn_tokens", "cost_tokens" } }
// session_close   (on a worker, this also triggers worker exit → daemon removes it)
{ "action": "session_close", "token": "<jwt>", "session_id": "..." }
```

Response field semantics (`session_send`): `turn_tokens` = tokens spent on **this turn**;
`cost_tokens` = **cumulative** tokens for the whole session.

Errors come back as `{ "status":"error", "message": "...", "data": {...} }`. The
`budget_exceeded` error carries a `reason` discriminator:
- `{"reason":"turn_limit", "iterations", "turn_tokens", "max_tokens", "max_iterations"}` — the per-turn ceiling tripped (partial stats included).
- `{"reason":"tenant_quota", "tenant_used"}` — the per-tenant cumulative quota is exhausted (no turn ran).

## Install & run

Packaged by [`CMakeLists.txt`](CMakeLists.txt): the `llm_agent` package installs to
`<prefix>/lib/llm-agent` and `config/llm-agent.yaml` to `<prefix>/apps/`, so the daemon
auto-loads the Scenario A App on boot. The shipped yaml's `working_dir` is
`/opt/appmesh/lib/llm-agent` (the packaged install location); a **source install to a
custom prefix** must edit `working_dir` to `<prefix>/lib/llm-agent`.

**Prerequisite:** the daemon's `python3` must have the `appmesh` SDK importable, plus
`anthropic`/`openai` for those backends. The Docker image bundles all three out of the
box (`pip install appmesh anthropic openai`); on a bare `.deb`/`.rpm` host install them
yourself (`pip install appmesh anthropic openai`) before using a real backend. The
default `fake` backend needs only `appmesh`. Smoke-test it once the App is up:

```bash
python3 examples/user_scenarios.py a_single      # expects: answer 'stub: ...'
```

Manual registration (other tenants / a real backend):

```bash
appm add -a llm-agent-acme -z ANTHROPIC_API_KEY=<key> \
  -e APPMESH_TENANT=acme -e LLMAGENT_BACKEND=anthropic
```

Provision a Scenario B worker by editing and registering the worker template. Keep the
coupled fields consistent: the App `name`, `owner`, `working_dir`, the `--session-id` in
`command`, and `APPMESH_SESSION_OWNER`/`APPMESH_TENANT` in `env` (the session owner must
equal the App `owner`, or only an admin can use the session).

The **access gate** is the worker App's `permission`, set by the provisioning client.
The daemon's owner-permission — not the agent's L2 check — decides who may
`run_task`/`subscribe` to the worker, so set it restrictively: `permission: 11` =
owner (+admin) only; `0`/unset = **no** owner-scoping (anyone the RBAC role allows).
Encoding: ones digit = group, tens digit = other; `1`=deny `2`=read `3`=write.

```bash
appm add -D @config/llm-agent-worker.yaml      # edit name/owner/working_dir/session-id/tenant first
```

### Driving from a workflow (Scenario A)

A DAG drives the shared App with a `message` step. llm-agent reads the caller token
from the payload body, and the task RPC itself is authed by `APP_MESH_PROCESS_KEY` (not
the caller JWT) — so the step **must** set `forward_token: true`, which makes the engine
inject the run's caller JWT into the payload's `token` field:

```yaml
jobs:
  chat:
    steps:
      - name: ask
        message:
          app: llm-agent
          payload: '{"action": "session_send", "session_id": "${{ inputs.sid }}", "input": "${{ inputs.q }}"}'
          forward_token: true        # without this the agent rejects the call: "token required"
```

Only a **manual** run carries a caller token to forward; **automatic** triggers
(event/cron) have no caller identity, so they cannot drive llm-agent (the agent fails
closed with `token required`). See `message.forward_token` in the workflow schema.

An llm-agent error (`token required`, `budget_exceeded`, a tool failure, …) comes back
as the platform envelope `{"status":"error", ...}`. The engine treats that as a **failed
step** (not a swallowed success), so a DAG's `if:`/`needs`/`continue-on-error` and retry
behave correctly; the full body remains available as `${{ steps.<name>.response }}`.

### Scenario B client flow (canonical)

One worker App per user; the client subscribes to its `STDOUT` **once** and keeps that
subscription open for the whole session, then converses turn after turn:

```python
sub = client.subscribe(worker, ["STDOUT"], callback=render)   # once per session
while chatting:
    # run_task delivers the turn's input and blocks until the turn ends; it does NOT
    # stream. The live tokens arrive on `sub` (the worker's stdout) during this call.
    meta = run_task(worker, {"action": "session_send", "session_id": sid,
                             "token": jwt, "input": msg, "stream": True})
    # `render` already printed the answer from the stream; `meta` is just completion
    # info: {answer, iterations, turn_tokens, cost_tokens} (answer == the streamed text).
run_task(worker, {"action": "session_close", ...})            # worker exits → removed
```

Key points:
- **Streaming is the STDOUT subscription, not `run_task`.** `run_task` is blocking
  request/response; it carries the turn input in and the completion metadata out. The
  token stream flows concurrently on the (separately-connected) STDOUT events.
- **Subscribe once per session, not per turn** — the single open subscription receives
  every turn's tokens. Subscribe *before* the first `send`; there is no readiness
  handshake, so a very fast backend can emit tokens before a just-created subscription
  is live (the worker's `stdout_cache_num` lets a slightly-late subscriber still catch
  recent tokens). The example settles briefly after subscribing.

See `b_interactive` / `WorkerStream` in [`examples/user_scenarios.py`](examples/user_scenarios.py).

## Examples & tests

- [`examples/user_scenarios.py`](examples/user_scenarios.py) — runnable client
  journeys against a live daemon (A single/multi-turn/budget/tool, B interactive
  streaming, authz). `python3 examples/user_scenarios.py --list`.
- [`examples/echo_tool.py`](examples/echo_tool.py) — a minimal tool App.
- `tests/` — fake-backed unit tests for the agent loop, budget/clamp, session store,
  and tool catalog. Run: `python3 -m unittest discover -s tests`.

## Layout

```
llm_agent/        types · llm (backends) · session · budget · tools · agent (loop) · handler · __main__
config/           llm-agent.yaml (A) · llm-agent-worker.yaml (B) · echo-tool.yaml
examples/         user_scenarios.py · echo_tool.py
tests/            test_agent · test_budget · test_session · test_tools · test_handler · test_llm_conversion
```
