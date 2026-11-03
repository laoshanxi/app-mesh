# App Mesh Product Guide

> **In one sentence**: App Mesh is a secure, lightweight daemon that turns every machine you have into a managed compute node — where you can **host applications, execute work remotely, orchestrate pipelines, and run AI agents**.
>
> One binary. Linux / macOS / Windows (x86 + ARM). Ships as a Docker image, deb/rpm packages, a web console, a CLI, five language SDKs, and an MCP server.

---

## What problems it solves

| Today | With App Mesh |
|---|---|
| Long-running services scattered across machines, kept alive by ssh + nohup + manual restarts | Declare the app once: auto-restart on crash, recover after daemon restart, health checks built in |
| crontabs on every box, failures discovered by users | Declarative schedules and event triggers, engine-native scheduling — no missed-run backfill, no overlap surprises |
| Automation = SSH + glue scripts, debugged by hand | One command / one API call sends work to any node, output streams back in real time |
| Jenkins too heavy, GitHub Actions lives in the cloud | GitHub-Actions-style YAML workflows that run on your own machines |
| AI agents have no safe, governed place to execute | Built-in LLM agent + sandboxed nodes + RBAC isolation, credentials stored encrypted |
| Team shares an execution platform, access controlled by convention | OIDC single sign-on + role-based permissions + app-level isolation + multi-tenancy |

**Analogy**: systemd on every machine, plus an API layer. Or "serverless, on your own machines."

---

## Six capability groups (organized by what you want to do)

### 1️⃣ Application hosting — hand your processes to the platform

Declare *what* to run; the platform keeps it *running well*:

- Native processes, Docker apps, or **adopt an already-running process** — full remote lifecycle
- Auto-restart on crash (per-exit-code policies), automatic recovery after daemon restart
- Health checks, CPU/memory limits, chosen OS user, tenant isolation
- Retained output history, viewable at any time

```bash
appm add -a my-worker -c "python3 -u worker.py"   # register a resident app
appm ls -a my-worker -o -f                        # follow its live output
```

**Typical uses**: data collectors, model servers, monitoring probes — anything that must "just keep running."

### 2️⃣ Remote execution & task invocation — send work out

Two styles, covering cold starts and warm reuse:

- **One-shot execution**: run a command/script on any node; wait synchronously or stream output async
- **Task invocation**: send a message to an **already-running** app and get a response — no process startup cost, a natural lightweight RPC

```bash
appm -F appmesh_slave1 exec "df -h"               # run on slave1
appm task py-task 'print(sum(range(100)))'        # → 4950, warm-process RPC
```

**Typical uses**: remote inspections, batch jobs, sending heavy compute to specific machines, RPC into resident services.

### 3️⃣ Scheduling & automation — time- and event-driven

- Cron expressions, fixed intervals, start/end dates, daily time windows
- Exit-policy automation: standby on success / restart on failure / remove on exit, crash-loop rate limiting
- Workflows can be triggered three ways: **manual**, **app event** (an app exited / emitted output), and **engine-native schedule** (cron or `@every` — no external crontab needed)

```yaml
name: nightly-cleanup
on:
  schedule:
    - cron: "0 2 * * *"        # engine-native; 6-field or 5-field, @every works too
jobs:
  clean:
    steps:
      - name: scrub
        command: "find /data/tmp -mtime +7 -delete"
```

**Typical uses**: nightly cleanup, scheduled backups, "clean up automatically when a process dies."

### 4️⃣ Workflow orchestration — chain work into pipelines

GitHub-Actions-style YAML, executed natively by the engine (no external scheduler):

- **DAG dependencies** (`needs`), parallel fan-out/join, sub-workflows (up to 4 levels)
- Four step types: shell command, app execution, **message (call a resident app or an LLM)**, sub-workflow; a message step's `outputs.answer` exists only when the target app replies in the platform envelope (llm-agent does) — plain-text apps expose `stdout`, and an answer-less reference fails with a clear engine error instead of leaking a literal to the shell
- Failure handling: `retry` (fixed/exponential backoff), `continue-on-error`, guaranteed `finally`
- Expressions: `${{ inputs.x }}`, `${{ steps.a.stdout }}`, `${{ jobs.a.steps.b.outputs.answer }}`, safe `toJSON()`, plus `always()/success()/failure()` in conditions
- Manual triggers can declare **inputs** (required/default/typed), validated at run time
- Concurrency groups (queue/cancel policies), per-step timeouts, run logs with per-step output, cancel/re-run
- **Remote steps**: pin a whole job to a node by label or host
- Strict schema: typos are rejected at registration, not at run time

```bash
appm workflow add -f release.yaml
appm workflow run release -e env=production -f    # -f follows the run live
appm workflow detail -w release <run_id>          # per-step status/timing/exit codes
```

**Typical uses**: build-test-deploy, multi-node inspection pipelines, data pipelines — any task graph.

### 5️⃣ AI agents ⭐ — bring intelligence into your automation

A first-class capability, built on the Claude Agent SDK. **Three enterprise scenarios:**

#### Scenario 1 — An LLM chat window for every employee (Interactive mode)

Each session gets its own **worker app** with a stable working directory and **live token streaming** — your chat frontend subscribes to one STDOUT event stream, then holds a multi-turn conversation. The agent remembers context across turns; when the session ends, closing it removes the worker app and its data automatically.

```python
# one STDOUT subscription, many turns, tokens stream live
sub = client.subscribe("llm-agent-sess-S1", ["STDOUT"],
                       callback=lambda e: print(e.data.get("output", ""), end=""))
client.run_task("llm-agent-sess-S1", json.dumps(
    {"action": "session_send", "session_id": "S1",
     "input": "Hi! Remember the number 7.", "stream": True}))
```

Verified live: *"Remember the number 7"* → *"Got it — I'll remember the number **7**"* → *"What number did I give you?"* → *"You gave me the number **7**."*

Prefer existing AI clients? The built-in **MCP server** (OAuth 2.1, Streamable HTTP) lets Claude Code, Codex, or any MCP client talk to — and operate — the platform: 31 tools covering the full app lifecycle (register/start-stop/health/output/run/task invocation), host resources & metrics, config & log level, labels, and principal/role/permission management — with double token validation and no password handling. Workers run with restricted permissions (`permission: 11` — owner + admin only), and tool access can be narrowed (e.g. read-only, no Bash).

#### Scenario 2 — Formal scheduled LLM agent jobs (Unattended operations)

Combine the **engine-native schedule trigger** with an agent message step: nightly digest, periodic report generation, unattended patrol runs. Each run gets its own `session_id` (e.g. `${{ workflow.run_id }}`), and a final `session_close` step cleans the workspace — nothing accumulates.

```yaml
name: nightly-digest
on:
  schedule:
    - cron: "0 23 * * *"
jobs:
  digest:
    node_label: { host: "ai-node:6059" }
    steps:
      - name: collect
        command: "journalctl -p err --since today --no-pager | tail -n 50"
      - name: summarize
        message:
          app: llm-agent
          payload: '{"action":"session_send","session_id":"digest-${{ workflow.run_id }}",
                     "input":"Review today''s logs and propose actions: ${{ steps.collect.stdout }}"}'
        timeout: 600
      - name: deliver
        command: "echo '${{ steps.summarize.outputs.answer }}' | mail -s 'Nightly digest' ops@corp.com"
      - name: cleanup
        message:
          app: llm-agent
          payload: '{"action":"session_close","session_id":"digest-${{ workflow.run_id }}"}'
```

The model's answer is a first-class expression variable (`outputs.answer`) — gate on it, email it, or chain it into the next stage. Credentials live in **secured env** (encrypted, never echoed back, never written to disk in plain text).

#### Scenario 3 — Multi-stage workflow orchestration across models (Scenario A)

A workflow drives an agent through **stages that share one conversation**: each stage sees what the previous stages produced. Route different stages to different models by pointing message steps at different agent apps.

Real documented run (GLM via gateway, 465 s total) — the classic **design → develop → test** lifecycle in one workflow, one `session_id` throughout:

| Stage | Iterations | Tokens | What the agent produced |
|---|---|---|---|
| design | 2 | 3,320 | brief: function signature, normalization rule, edge-case decision table |
| develop | 24 | 19,690 | `palindrome.py`; installed pytest on its own; fixed a Unicode bug it hit |
| test | 6 | 6,122 | unittest suite from the brief's table — **"Ran 5 tests — OK"** |

The test stage referred back to "the brief's table" and "the encoding issue from before" — proof that one session carries context across stages. Verified patterns on top of this: **cross-job answer references**, **message→message chaining** (feed a previous answer into the next prompt), and **DAG fan-out/join** (several agent steps in parallel, a join step merges their answers).

> **Ops note**: when a manual run routes steps to remote nodes, the caller's access token is forwarded with each request (30-minute default lifetime; the engine never refreshes it). For pipelines with multi-minute stages, sign in fresh beforehand, raise the token TTL, or use a schedule trigger instead — scheduled runs execute under an engine-local capability and are not bound by the caller's token.

#### Across all three scenarios

- **Model freedom**: Claude out of the box (Anthropic API / Amazon Bedrock / Google Vertex); switch to DeepSeek, Qwen, GLM, MiniMax, or any OpenAI-compatible model through a gateway — changing models is changing environment variables
- **Skills**: drop a `SKILL.md` under the workspace and every session can use it
- **Cost control**: `max_iterations` per turn; shared app for batch, per-session workers for interactive
- **AI coding sandbox**: an official agent skill for Claude Code / Codex — edit locally, build/test on a remote Linux node via tar sync + SDK execution. No SSH keys, no rsync, works behind firewalls
- **Reference implementation — team digital human**: `src/integrations/digital-human` deploys a team-facing digital human in one command (internal Q&A, task execution, approval gate for risky operations) — all three scenarios above in one ready-to-run package. Verified live: grounded Q&A and the full approve-execute-anti-replay flow

**Typical uses**: log intelligence, AI on-call assistants, automated reporting, a shared RBAC-governed AI execution environment for the whole team.

### 6️⃣ Cluster, files & platform foundation

**Cluster & multi-node**

- Master/follower architecture (one `docker compose up -d` for the full stack), authorization state replicates to followers automatically
- Any node can be your entry point: `-F` forwards to the target node
- Node labels + workflow `node_label` route work by capability

**File distribution**

- Upload / download / delete / overwrite with attribute preservation; identical semantics across nodes and SDKs

**Event subscription**

- `START / EXIT / STDOUT / HEALTH / STATUS / REMOVED` events, server-pushed over TCP/WebSocket — no polling

**Security & multi-tenancy**

- OIDC/OAuth2 single sign-on (bundled Dex, or bring your own IdP); MFA and directory policy stay in your IdP
- Principals (users/groups/service accounts) + roles + permissions; app-level read/write control; per-tenant isolation
- TLS everywhere + internal HMAC-PSK; cluster authorization state replicated encrypted

**Observability**

- Built-in Prometheus exporter, Grafana datasource, Loki integration
- Host- and app-level metrics: CPU, memory, start counts, exit codes, health

**Access surfaces (same capabilities, six doors)**

| Surface | Who it's for |
|---|---|
| `appm` CLI | daily operations, shell completion included |
| Web console | visual app/workflow/node views, guided AI-agent registration |
| REST API | custom integrations in any language |
| Five SDKs (Python / JavaScript / Go / Rust / Java) | production integrations, one shared test matrix |
| MCP | AI clients (Claude, Codex, your own agents) |
| Event subscription (TCP/WS) | reactive integrations |

---

## Three end-to-end business scenarios

**A. Nightly multi-node inspection with an AI summary** — label-selected jobs collect disk/service state on every node, an agent step reviews everything, the answer lands in the on-call inbox. Zero human involvement.

**B. AI on-call assistant (event-driven)** — a service crashes → `app_event` fires a workflow within seconds → the agent reads the error log and drafts a diagnosis → verdict pushed to the chat channel. Unattended, credentials never leave the platform.

**C. Remote builds (cross-platform development)** — write code on a Mac with Claude Code, say "run the tests" → the sandbox skill syncs the tree to a clean Linux test node → executes → streams results back. Local machine stays whatever it is; the build environment stays reproducible.

---

## Quick start (3 minutes)

```bash
# 1. Start a node
docker run -d --restart=always --name=appmesh --net=host \
  -v appmesh-work:/opt/appmesh/work laoshanxi/appmesh:latest

# 2. Sign in (initial password from the container)
docker exec -ti appmesh bash -c \
  '/opt/appmesh/script/appmesh-auth.sh print-initial-password | appm logon -u admin@appmesh.local --password-stdin'

# 3. Run your first app
appm add -a hello -c "python3 -u -c 'import time; [print(i) or time.sleep(1) for i in range(10)]'"
appm ls -a hello -o
```

Want the full cluster? `docker compose up -d` with `script/docker/docker-compose.yaml` brings up master + two followers + web console + MCP + a dedicated LLM node.

---

## Why you can trust it

- **Production-grade engineering**: one self-contained daemon, zero external dependencies (no database, no message queue), crash recovery and resource isolation built in
- **Verified end to end**: five SDKs against one integration matrix (HTTP/TCP/WSS transports, 500+ assertions), dedicated workflow-engine testing (DAG/retries/triggers/remote/concurrency), all four reference integrations (digital human/MQTT/MCP×2) tested from the user's perspective, zero fd/memory leaks under load
- **Secure by default**: credentials encrypted and never echoed, TLS everywhere, least-privilege RBAC, AI toolsets can be narrowed (read-only, no Bash)
- **Open source**: MIT licensed, full docs at [readthedocs](https://app-mesh.readthedocs.io), images on [Docker Hub](https://hub.docker.com/r/laoshanxi/appmesh)

> Based on App Mesh 3.0.1 (2026-11). Every example here was executed on a live six-node compose cluster.
