# model-env — LLM Agent Model Environment

`model-env` runs an LLM agent on top of App Mesh. It runs as ordinary,
admin-provisioned Apps that hold the LLM client, the agent loop, the session store,
the tool catalog, and per-turn/per-tenant budgets — one shared App per tenant for
batch (Scenario A) and one worker App per interactive session (Scenario B). The
dynamic agent behavior is confined to these Apps, so the daemon and the workflow
engine stay unchanged.

Design contract: [`docs/source/workflow/LLMAgentWorkflowDesign.md`](../../docs/source/workflow/LLMAgentWorkflowDesign.md).

## Two scenarios, two Apps

The two interaction models have different isolation needs, so each runs as its own
App (both built from this one binary; both **provisioned by an admin** — model-env
registers nothing itself).

| | Scenario A — DAG/batch | Scenario B — interactive |
|---|---|---|
| App | one shared App per tenant (`model-env-<tenant>`) | one worker App per session (`--session-worker`), admin-provisioned |
| Entry | workflow `message` step → `RunTask` on the tenant App | client talks **directly** to the worker App by name |
| Streaming | no (final structured result) | yes — the worker's own stdout is a clean, single-session token stream |
| Isolation | sessions share one process | one process, working dir, stdout, cgroup per session |
| Teardown | TTL reap | `behavior: exit: remove`: close / idle / lifetime / crash → exits → daemon removes it |
| Use | batch / pipeline | interactive chat / agent |

There is no dynamic spawning: an admin provisions the per-tenant App and, for each
interactive session, a worker App (see `config/model-env-worker.yaml`). App Mesh
starts each process and injects its `APP_MESH_PROCESS_KEY`, so each App's
`task_fetch` is scoped to itself. Both share the session store layout, tool catalog,
budget, and authorization model.

## Architecture

```
cmd/model-env        entry: default (Scenario A task loop + TTL reaper) | --session-worker (Scenario B)
internal/
  api/               Task RPC: session_open / session_send / session_close (+ authz, streaming, budget)
  session/           cross-run sessions: disk-persisted, TTL, per-tenant namespace, owner PDP
  agent/             ReAct loop (reason → tool → observe), hard per-turn limits, concurrent tool dispatch
  tools/             registered Apps with metadata.tool → tool catalog; RunTask invocation (session_id + workdir injected)
  budget/            per-turn (iteration/token) + per-tenant (file-locked shared quota ledger)
  llm/               provider-neutral Backend contract + stub / anthropic / local / remote backends
```

model-env holds **no daemon credentials**: the task RPC authenticates with the
daemon-injected `APP_MESH_PROCESS_KEY`, and every other daemon call (token
validation, tool listing/invocation) runs under the **caller's token** from the
request payload.

## Build

```bash
# via CMake (built and packaged with the rest of App Mesh)
cd build && cmake .. && make model-env

# or directly (dev/test only — see note below)
cd src/model-env && go build ./cmd/model-env
go test ./...
```

> **Deploying needs the *installed* binary.** The App definitions use
> `command: ../../bin/model-env`, which resolves (from the daemon's default App
> working dir) to `<install-prefix>/bin/model-env`. A bare `go build` leaves the
> binary in the source tree, not there — run `make install` / `make pack` (which
> install it to `bin/`) before `appm add`, or set each App's `command:` to your
> built binary's absolute path.

## Usage scenarios

[`examples/user_scenarios.py`](examples/user_scenarios.py) is a runnable walkthrough
of how a client actually uses model-env, end to end against a live daemon. It opens
with a small `ModelEnv` wrapper (the idiomatic shape of an integration) and then runs
narrated journeys.

### Quickstart (deploy, then run the scenarios)

```bash
# 0) Build model-env and have an App Mesh daemon running (see Build above).

# 1) Provision the per-tenant Scenario A App (default tenant, stub backend —
#    deterministic "stub: <input>" answers, no LLM key, no daemon credentials).
#    It ships status:1 and starts on boot.
appm add -D @config/model-env.yaml

# 2) (Scenario B) provision a session worker App. Edit config/model-env-worker.yaml
#    (session id, owner, tenant, backend) and register it; it serves that one session.
appm add -D @config/model-env-worker.yaml

# 3) (optional, tool scenarios) deploy echo_tool.py on the daemon host, point
#    config/echo-tool.yaml's `command` at it, then register it:
appm add -D @config/echo-tool.yaml

# 4) Install the Python SDK so the script can import `appmesh`:
pip install -e src/sdk/python      # or: pip install appmesh

# 5) Run the user scenarios:
cd src/model-env
python3 examples/user_scenarios.py --list
python3 examples/user_scenarios.py all \
  --worker-app model-env-default-sess-S1 --worker-session S1 --tool-app echo
```

Config is via flags or env (`APPMESH_TCP_HOST`, `APPMESH_TCP_PORT`, `MODELENV_TENANT`,
`MODELENV_APP`, `APPMESH_USER`/`APPMESH_PASSWORD` — default `admin`/`admin123`;
`MODELENV_WORKER_APP`/`MODELENV_WORKER_SESSION` for the Scenario B worker (B1/B2);
`MODELENV_TOOL_APP` for the tool/budget journeys (A3/A4); `APPMESH_USER2`/`APPMESH_PASSWORD2`
for the cross-user case — see the script header). The default Scenario A app name is
`model-env-<tenant>`. Journeys whose flag is omitted print a clear "skipped" line.

The client logs in as `--user`/`--password`, so that daemon user needs the
permissions for what it does: `app-run-task` (Scenario A and to send to a worker),
plus `app-subscribe` (Scenario B streaming) and `app-view` (tools). `admin` has all
of these — a non-admin user must be granted them. ("No daemon credentials" applies
to the model-env Apps themselves, not to the human client.)

### The journeys

| | Scenario | Shows |
|---|---|---|
| A1 | batch single-shot | open → ask → answer → close |
| A2 | batch multi-turn | context carried across turns in one session |
| A3 | batch with budget | `max_iterations=1` + a tool → `budget_exceeded` (needs `--tool-app`) |
| A4 | tool use | the agent calls a registered tool App (needs `--tool-app`) |
| B1 | interactive streaming | Subscribe(STDOUT) on the worker App → render tokens live |
| B2 | interactive multi-turn | back-and-forth against the worker App |
| C1 | authorization | a second user cannot touch the owner's session |

The Scenario B journeys require an admin-provisioned worker App (step 2); pass its
name + session id via `--worker-app`/`--worker-session`. Use `MODELENV_BACKEND=stub`
for deterministic answers, or a real backend for genuine agent behavior.

## Backends (one per tenant)

Select with `MODELENV_BACKEND`. Credentials/endpoints come from the environment —
nothing is hardcoded.

| `MODELENV_BACKEND` | Target | Required env |
|---|---|---|
| `stub` (default) | deterministic, no network (tests / dev) | — |
| `anthropic` | Anthropic Messages API | `ANTHROPIC_API_KEY` (opt: `MODELENV_MODEL`=`claude-opus-4-8`, `ANTHROPIC_BASE_URL`) |
| `local` | self-hosted OpenAI-compatible server (vLLM, Ollama, TGI, llama.cpp, LM Studio) | `MODELENV_LOCAL_BASE_URL`, `MODELENV_MODEL` (opt: `MODELENV_LOCAL_API_KEY`) |
| `remote` | external reasoning service (e.g. a Python agent) | `MODELENV_REMOTE_URL` (opt: `MODELENV_REMOTE_API_KEY`) |

**Local model deployment.** Run the inference server as its own App Mesh App
(App Mesh manages its process lifecycle, health, restart, and GPU pinning via
e.g. `CUDA_VISIBLE_DEVICES`; App Mesh does not do GPU scheduling). Point
`model-env` at its OpenAI-compatible endpoint:

```bash
# e.g. a vLLM App listening on :8000
MODELENV_BACKEND=local
MODELENV_LOCAL_BASE_URL=http://127.0.0.1:8000/v1
MODELENV_MODEL=meta-llama/Llama-3.1-8B-Instruct
```

### Remote backend protocol (host the reasoning layer in another language)

The `remote` backend keeps the platform layer (loop, tools, budgets, sessions,
RBAC, transport) in Go and forwards **one model call** to an external service —
the seam for writing the LLM-interaction / agent-reasoning layer in Python (or
anything) without losing Go's integration and packaging. The boundary is exactly
the `llm.Backend` contract: the service is a stateless completion provider — given
the history and tool specs, return the next assistant turn. It does **not** run
the loop or invoke tools.

```
POST {MODELENV_REMOTE_URL}/complete
  request : {"messages":[Message...], "tools":[ToolSpec...], "stream":bool}
  response (stream=false): {"message":{...}, "usage":{...}}            # a Completion
  response (stream=true) : text/event-stream of
      data: {"type":"text","text":"<chunk>"}                          # incremental, optional
      data: {"type":"completion","message":{...},"usage":{...}}        # final, authoritative
      data: {"type":"error","error":"<message>"}
```

`Message`/`ToolCall`/`ToolSpec`/`Completion`/`Usage` are the JSON shapes in
`internal/llm/llm.go`, so the service speaks the same types verbatim. A runnable
reference (Python stdlib + the Anthropic SDK) is in
[`examples/remote_agent.py`](examples/remote_agent.py).

**When to reach for `remote`:** only when the reasoning layer grows heavy or
fast-moving (RAG, multi-agent graphs, prompt experimentation, evals) and Python's
ecosystem pays for the extra runtime. For a focused ReAct loop with a couple of
backends, the in-process Go backends (`anthropic`, `local`) are simpler to operate.

## Configuration (env)

| Var | Default | Meaning |
|---|---|---|
| `APPMESH_TENANT` | `default` | tenant namespace for this App |
| `APPMESH_SESSION_OWNER` | — | (worker only) the session owner |
| `APPMESH_WORKFLOW_ADMINS` | `admin` | comma-separated admins (may access any session) |
| `MODELENV_BACKEND` | `stub` | `stub` \| `anthropic` \| `local` \| `remote` |
| `MODELENV_SESSION_DIR` | `./sessions` | session persistence directory |
| `MODELENV_LEDGER_DIR` | = `MODELENV_SESSION_DIR` | per-tenant token ledger dir. The counter file is `<dir>/<tenant>.ledger.json`, so a shared quota needs the **same tenant AND same dir** across the Scenario A App and its workers |
| `MODELENV_SESSION_TTL_HOURS` | `168` | Scenario A idle session TTL; `0` disables reaping |
| `MODELENV_WORKSPACE_DIR` | `./model-env-workspace` | root for per-session tool scratch dirs |
| `MODELENV_SESSION_IDLE_MINUTES` | `30` | worker (Scenario B) idle reap; `0` disables |
| `MODELENV_SESSION_MAX_HOURS` | `8` | worker absolute lifetime cap; `0` disables |
| `MODELENV_MAX_ITERATIONS` | `8` | per-turn tool-call ceiling (callers may only lower it) |
| `MODELENV_MAX_TOKENS` | `0` | per-turn token ceiling (agent loop); `0` = unlimited |
| `MODELENV_MAX_OUTPUT_TOKENS` | `8192` | provider API output cap per call (`anthropic` / `local`) |
| `MODELENV_TOOL_TIMEOUT` | `300` | per tool-call `RunTask` timeout (seconds); raise for long-running tools |
| `MODELENV_TENANT_QUOTA` | `0` | per-tenant cumulative token quota; `0` = unlimited |

Each App (the Scenario A App and each worker) is configured independently by the
admin. **No daemon credentials are set** — the task RPC uses `APP_MESH_PROCESS_KEY`
and every other call uses the caller's token. Only a real backend needs a secret
(`ANTHROPIC_API_KEY` etc., via `sec_env`).

## Tools

A tool is a registered App carrying `metadata.tool` (LLM function schema):

```yaml
# an App that doubles as an agent tool
name: weather
metadata:
  tool:
    description: Get current weather for a city.
    parameters:
      type: object
      properties:
        city: { type: string, description: City name }
      required: [city]
```

`model-env` lists Apps the **caller's token** can see, advertises those carrying
`metadata.tool`, and invokes a tool by `RunTask`-ing the App (structured JSON in,
structured JSON out). The tool set is therefore automatically scoped to what the
caller could already run — no separate allowlist.

Tools are **registered Apps only** — there is deliberately no arbitrary
command/shell tool (unlike a general coding agent). To give an agent file or
shell capability you register a purpose-built App as a tool.

**Per-session isolation for tools.** Each invocation has `session_id` and
`workdir` injected into its JSON arguments (the model's own value, if any, wins).
`workdir` is a per-session scratch directory
(`<MODELENV_WORKSPACE_DIR>/<tenant>/<session_id>`, created best-effort). A
file-writing tool App should write under `workdir` so two sessions invoking the
same shared tool App do not clobber each other. This matters in both scenarios:
tools run as separate Apps with their own cwd, so a worker's own working directory
does not isolate tool files — the injected `workdir` is what does.

**Agent capability envelope.** Within the registered-App tool model the agent is
broad: any capability (file read/write, code/shell execution, HTTP, search, RAG,
another workflow) is an App you register with a `metadata.tool` schema, and the
agent calls any tool the caller's token can see. The loop dispatches a turn's tool
calls **concurrently**, so a model can fan out several tools at once. Long-running
tools are supported by raising `MODELENV_TOOL_TIMEOUT`. The reasoning layer itself
is pluggable per tenant — in-process (`anthropic`/`local`) or an external service
(`remote`, e.g. a Python agent) via the `llm.Backend` HTTP contract. What is *not*
supported by design: an arbitrary ad-hoc shell/exec tool (only registered Apps are
tools), and — deferred — automatic context compaction for very long sessions and
tool-call/prompt trace observability.

## Task API

All actions are JSON sent via `run_task(<app>, payload, timeout)` — the Scenario A
App `model-env-<tenant>`, or a worker App for Scenario B. The caller's JWT goes in
`token`; it authenticates the caller, validates the session (L2), and runs tools
under their identity, then is stripped (never persisted/logged).

### `session_open` (Scenario A only)
```json
{"action": "session_open", "token": "<jwt>"}
→ {"status": "ok", "data": {"session_id": "cq1abc..."}}
```
A Scenario B worker does not use `session_open`: it materializes its single,
pre-assigned `--session-id` at startup. The client addresses that session id on the
worker App directly.

### `session_send`
```json
{"action": "session_send", "token": "<jwt>", "session_id": "cq1abc...",
 "input": "What is the weather in Paris?", "stream": false,
 "max_iterations": 5, "max_tokens": 4000}
→ {"status": "ok", "data": {"answer": "...", "iterations": 2,
                            "turn_tokens": 812, "cost_tokens": 1530}}
```
On a hard-limit breach: `{"status":"error","message":"budget_exceeded","data":{...}}`.

`stream: true` (sent to a worker App) writes generated tokens to the worker's
stdout as STDOUT events. Because the worker serves a single session, its stdout is
a clean per-session stream: the client subscribes out-of-band (`Subscribe(STDOUT)`
on the worker App) to render it live while still receiving the final result from
the task call. The Scenario A App rejects `stream:true`.

### `session_close`
```json
{"action": "session_close", "token": "<jwt>", "session_id": "cq1abc..."}
→ {"status": "ok"}
```
For a worker, close also exits the process; the daemon then removes the worker App
(`behavior: exit: remove`). A worker not closed explicitly is reclaimed by its idle
TTL / max-lifetime (also by exiting).

## Authorization (mirrors the workflow engine, ADR 0006)

- **L1** daemon RBAC (`app-run-task`) gates talking to the App. A Scenario B
  worker App is registered with the **caller as its owner**, so the caller's
  token can `RunTask` / `Subscribe` it while it stays isolated from other users.
- **L2** engine PDP: `session.owner == caller || isAdmin`; sessions are namespaced
  per tenant on disk, so cross-tenant access is impossible. A worker additionally
  serves only its one pre-assigned session id.
- **L3** tools run under the caller's own token → the daemon's per-App ACL applies.

**Capability follows the caller's token (no special role imposed):** Scenario A
needs only a valid login. A Scenario B caller needs **`app-run-task`** (to send to
the worker) and **`app-subscribe`** (to stream its STDOUT). Tool use needs
**`app-run-task`** and **`app-view`** on the caller's own token. The admin who
provisions a worker App needs the usual app-registration rights.

## Limitations / not yet implemented

See the design doc's *Deferred / Out of Scope*. Notably: context compaction,
per-session budget tier, `execution_identity` / act-as for cross-user shared and
automatic-trigger sessions, and dynamic self-service spawning of Scenario B workers
(they are admin-provisioned).

**Per-tenant quota across processes.** Because Scenario B runs each session in its
own process, the per-tenant cumulative quota (`MODELENV_TENANT_QUOTA`) is enforced
by a **file-backed ledger** shared by the Scenario A App and all workers pointed at
the same `MODELENV_LEDGER_DIR`: one JSON counter per tenant, updated under an
`flock`-guarded read-modify-write. (The lock is advisory and Unix-only; on non-Unix
platforms concurrent accounting is not serialized — see `internal/budget/lock_other.go`.
On a ledger I/O error the check fails open and logs, since per-turn budget still caps
any single turn.)

Operational notes:

- **Worker startup.** A worker materializes its session at startup; the daemon
  queues a `session_send` until the worker is serving. If the worker fails to start,
  it exits and is removed.
- **Streaming has a client-side ~60s cap (and it sticks).** The Python SDK demuxes
  `run_task` over the same connection as the STDOUT subscription with a fixed ~60s
  client timeout. Once you `Subscribe`, that ~60s cap applies to **every** subsequent
  `run_task` on that client (the demuxer stays active even after `unsubscribe`),
  regardless of the task timeout you pass — and on breach the SDK **closes the
  connection** (not just the call), so one slow turn breaks later calls on that
  client. Provision the worker **ahead of time** (so its cold start isn't on the
  streamed send), keep a streamed turn under ~60s, and use a **fresh client** for
  long non-streaming work.
- **Subscribe before send.** To not miss early tokens, `Subscribe(STDOUT)` on the
  worker App before the first streaming `session_send`; a modest stdout cache lets a
  slightly late subscriber still see recent output.
- **Disk cleanup.** On `session_close` / idle / lifetime reap the worker deletes its
  conversation history; the empty per-session working dir under `MODELENV_WORKSPACE_DIR`
  is left behind (no data) and can be swept by ops.
- **Binary path.** A worker App's command runs `model-env --session-worker …`;
  deploy the binary at a path without spaces.
