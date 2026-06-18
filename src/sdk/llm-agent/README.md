# llm-agent

Run a **Claude Code agent on App Mesh**. A thin wrapper around the official
[Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk/python): it routes session
turns over the App Mesh task RPC, gives each session a stable working directory, and
streams a worker's output. The agent loop, tools, and conversation history are the
SDK's; access control is the daemon's.

> **Built on Claude Code — runs Claude by default, but not Claude-only.** Out of the box it
> runs Claude (Anthropic API, or Amazon Bedrock / Google Vertex). It can also drive other
> models — DeepSeek, Qwen, GLM, MiniMax, or any OpenAI-compatible model behind a gateway —
> through Claude Code's provider env. See [Models & providers](#models--providers).

## Prerequisites

The agent loop is delegated to the Claude Agent SDK, which **drives a Claude Code CLI as
a subprocess**. The App's host/image therefore needs:

- `python3` with `appmesh` and `claude-agent-sdk` importable (see [`requirements.txt`](requirements.txt)).
  The `claude-agent-sdk` wheel **bundles the Claude Code CLI** — there is no Node.js to install.
- A model credential as a **secured** env var — `ANTHROPIC_API_KEY` for the Anthropic API,
  or the equivalent for another backend (Bedrock / Vertex / a gateway). See
  [Models & providers](#models--providers).

The Docker image installs these via `requirements.txt` (see the repo `Dockerfile`).

Session history is written under `$CLAUDE_CONFIG_DIR` — llm-agent defaults it to
`<workspace>/.claude` because the daemon does not propagate `HOME`, so you don't need to
set one, but the **workspace must be writable by the App's user**.

## Two scenarios, two Apps

The same `llm_agent` binary runs in two roles — both admin-provisioned Apps (this
package registers nothing itself):

| | Scenario A — batch / DAG | Scenario B — interactive |
|---|---|---|
| App | one shared App — `llm-agent` | one worker App per session — `<app>-sess-<id>` |
| Started by | loaded at boot, `status: 0` → `appm enable -a llm-agent` | admin, per session |
| Sessions | many | exactly one, pre-assigned |
| Streaming | no (returns the final answer) | yes (worker streams to its own STDOUT) |
| Lifecycle | long-lived (`exit: restart`) | exits on close/idle/max-life → daemon removes it (`exit: remove`) |
| Config | [`config/llm-agent.yaml`](config/llm-agent.yaml) | [`config/llm-agent-worker.yaml`](config/llm-agent-worker.yaml) |

A session is just a stable working directory, `<workspace>/<session_id>`. The SDK keeps
that conversation's history on disk keyed by the directory, so **continuing a session is
simply "send again with the same `session_id`"** — llm-agent stores no history of its own.

Two things to know about that model:
- **`session_id` is an unauthenticated global namespace** on the shared App (no owner
  check inside the agent). Two callers using the same id share one conversation — use
  unguessable ids (e.g. `${{ workflow.run_id }}`), and rely on the daemon's RBAC / the
  worker App's `permission` for access control.
- **`session_close` is destructive**, not a pause: it deletes the workdir, dropping that
  conversation. There is no resume after close.

## Request flow

```
client / workflow step
   │  run_task(app, {action, session_id, input, stream?})
   ▼
App Mesh daemon ── task RPC (auth: daemon-injected APP_MESH_PROCESS_KEY; RBAC) ──▶ llm_agent App
        handler: session_send → claude-agent-sdk query() with cwd=<workspace>/<session_id>
                 (continue_conversation when that cwd already exists) → stream / final answer
```

## Access control

The handler performs **no** auth or quota of its own: the daemon already authorizes the
inbound `run_task` (RBAC), and a worker App's `permission: 11` restricts it to its owner
(+admin). The Claude key lives in the App's secured env. There is no tenant, session
owner-check, or token validation inside the agent.

## Tools

Tools are Claude Code's built-in tool set (`Read` / `Write` / `Edit` / `Glob` / `Grep` /
`Bash` / `WebSearch` / …), running in the session's workdir. By default the full set is
enabled with `permission_mode=bypassPermissions` (unattended — never blocks on a prompt).
Restrict with `LLMAGENT_ALLOWED_TOOLS` (comma list) / `LLMAGENT_PERMISSION_MODE`.

> **⚠️ Security — the default lets the model run arbitrary commands.** With the full tool
> set + `bypassPermissions`, `Bash` executes shell commands as the App's OS user, unattended,
> for anyone the daemon lets reach the App; `cwd` is only the *start* directory, not a
> sandbox. Before exposing it: run the App as an unprivileged user, tighten the worker's
> `permission`, and consider `LLMAGENT_ALLOWED_TOOLS=Read,Glob,Grep,WebSearch` (no Bash).

## Wire protocol (run_task payload)

```jsonc
// session_send — an unknown session_id is created on first use; reuse the same id to
//                continue the conversation. `stream` only takes effect on a worker App.
{ "action": "session_send", "session_id": "...", "input": "hello",
  "stream": false, "max_iterations": 0 }
  → { "status":"ok", "data": { "answer", "iterations", "turn_tokens" } }

// session_close — on a worker, also triggers worker exit → daemon removes the App
{ "action": "session_close", "session_id": "..." }
```

Errors come back as `{ "status":"error", "message":"..." }`.

## Configuration (env)

| var | default | meaning |
|---|---|---|
| `LLMAGENT_MODEL` | unset → the CLI's default model | model id/alias the CLI runs — e.g. `claude-opus-4-8`, or a provider model like `deepseek-v4-pro[1m]` (see [Models & providers](#models--providers)) |
| `LLMAGENT_SYSTEM_PROMPT` | — | system prompt prepended to the agent |
| `LLMAGENT_ALLOWED_TOOLS` | all | comma list to restrict the built-in tool set |
| `LLMAGENT_PERMISSION_MODE` | `bypassPermissions` | SDK permission mode |
| `LLMAGENT_WORKSPACE_DIR` | `./llm-agent-workspace` | parent of per-session workdirs (the SDK's cwd) |
| `LLMAGENT_MAX_ITERATIONS` | `0` (no ceiling) | per-turn SDK `max_turns` ceiling; a request may only tighten it |
| `LLMAGENT_SESSION_TTL_HOURS` | `168` | shared App: idle session-workdir reap |
| `LLMAGENT_SESSION_IDLE_MINUTES` | `30` | worker: idle reap |
| `LLMAGENT_SESSION_MAX_HOURS` | `8` | worker: max lifetime |
| `ANTHROPIC_API_KEY` | — | Anthropic API key — set as a **secured** env var, never in the App definition. Other backends use different env (see [Models & providers](#models--providers)) |

## Install & run

Packaged by [`CMakeLists.txt`](CMakeLists.txt): the `llm_agent` package installs to
`<prefix>/lib/llm-agent` and `config/llm-agent.yaml` to `<prefix>/apps/`, so the daemon
auto-loads the shared App on boot but does **not** start it (`status: 0`). The pre-loaded
definition carries **no Claude key**, so enabling it as-is fails on the first turn —
register it with a key (recommended), or attach the secured env to the pre-loaded App and
then `appm enable`. A source install to a custom prefix must also edit the yaml's
`working_dir`.

```bash
# register the shared App WITH a key (replaces the keyless pre-loaded definition), then start it:
appm add -a llm-agent -z ANTHROPIC_API_KEY=<key> -e LLMAGENT_MODEL=claude-opus-4-8
appm enable -a llm-agent
```

Smoke-test once it is up:

```bash
python3 examples/user_scenarios.py a_single
```

Provision a Scenario B worker (edit `name` / `working_dir` / `--session-id`; `permission: 11`
scopes it to the owner):

```bash
appm add -D @config/llm-agent-worker.yaml -z ANTHROPIC_API_KEY=<key>
```

### Driving from a workflow (Scenario A)

```yaml
jobs:
  chat:
    steps:
      - name: ask
        message:
          app: llm-agent
          payload: '{"action":"session_send","session_id":"${{ workflow.run_id }}","input":"${{ inputs.q }}"}'
```

`session_send` get-or-creates the session, so reuse a stable `session_id` to continue a
conversation across steps/runs (or use `"${{ workflow.run_id }}"` for a fresh per-run
session). An llm-agent error returns `{"status":"error", ...}`, which the engine treats
as a failed step.

### Scenario B client flow

One worker App per session; the client subscribes to its `STDOUT` **once** and keeps
that subscription open, then converses turn after turn. `run_task` delivers each turn's
input and blocks until the turn ends (returning completion metadata); the live tokens
arrive on the STDOUT subscription during that call. See `b_interactive` / `WorkerStream`
in [`examples/user_scenarios.py`](examples/user_scenarios.py).

## Models & providers

llm-agent runs whatever model the bundled **Claude Code CLI** is pointed at. The CLI speaks
the Anthropic Messages API, so the model/provider is chosen entirely through **env on the
App** (the SDK inherits the App's env and passes it to the CLI). Three paths:

**1. Claude — Anthropic API (default).** `ANTHROPIC_API_KEY` (secured) + optional
`LLMAGENT_MODEL` (e.g. `claude-opus-4-8`).

**2. Claude on Amazon Bedrock / Google Vertex.** In place of `ANTHROPIC_API_KEY`:
- **Bedrock:** `CLAUDE_CODE_USE_BEDROCK=1` + the AWS auth env (region, profile or keys).
- **Vertex:** `CLAUDE_CODE_USE_VERTEX=1` + the GCP project/region env and ADC.

**3. Non-Claude models (DeepSeek, Qwen, GLM, MiniMax, OpenAI, …).** Claude Code has **no
native non-Anthropic provider** — the model must be reached over an **Anthropic-Messages-API-
compatible endpoint**. Several providers ship one natively: point `ANTHROPIC_BASE_URL` at it,
with `ANTHROPIC_AUTH_TOKEN` as the credential (secured) and `LLMAGENT_MODEL` as the provider's
model name. For models without one (OpenAI/Gemini), put a translating gateway (e.g. LiteLLM)
in front and point `ANTHROPIC_BASE_URL` at the gateway.

| Provider | `ANTHROPIC_BASE_URL` | `LLMAGENT_MODEL` |
|---|---|---|
| DeepSeek | `https://api.deepseek.com/anthropic` | `deepseek-v4-pro[1m]` |
| Qwen — Model Studio (Beijing, pay-as-you-go) | `https://dashscope.aliyuncs.com/apps/anthropic` | `qwen3.7-max` |
| GLM — Zhipu | `https://open.bigmodel.cn/api/anthropic` | `glm-5.2[1m]` |
| MiniMax (China) | `https://api.minimaxi.com/anthropic` | `MiniMax-M3[1m]` |

(Region/plan variants exist — e.g. Qwen Token Plan `https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic`,
MiniMax international `https://api.minimax.io/anthropic`; see each provider's Claude Code docs or the web UI presets.)

> **Also set the model-slot aliases.** Claude Code's quick/subagent calls resolve the
> `haiku` / `sonnet` / `opus` slots to Claude ids the endpoint won't serve, so those turns
> fail unless you map them: `ANTHROPIC_DEFAULT_HAIKU_MODEL` / `_SONNET_MODEL` / `_OPUS_MODEL`
> (and `CLAUDE_CODE_SUBAGENT_MODEL`) → the provider's models. Models with a 1M context (the
> `[1m]` ids above) also want `CLAUDE_CODE_AUTO_COMPACT_WINDOW=1000000`.

> Tool-use and agentic quality vary by model — Claude Code is tuned for Claude; non-Claude
> models work, but multi-step / tool-calling fidelity may be lower.

### Register examples (`appm`)

`-z` sets a **secured** env var (encrypted at rest), `-e` a regular one. **Quote model ids
containing `[...]`** (e.g. `'glm-5.2[1m]'`) so the shell doesn't glob them. Each command
registers the shared Scenario-A App; finish with `appm enable -a llm-agent`. (For a worker
App, put the same env in `config/llm-agent-worker.yaml`.)

```bash
# Claude — Anthropic API (default)
appm add -a llm-agent -z ANTHROPIC_API_KEY=<key> -e LLMAGENT_MODEL=claude-opus-4-8

# Claude — Amazon Bedrock (AWS_ACCESS_KEY_ID is an identifier → -e; the secret key → -z.
#                          Or omit both and use an instance role.)
appm add -a llm-agent \
  -e CLAUDE_CODE_USE_BEDROCK=1 -e AWS_REGION=us-east-1 \
  -e AWS_ACCESS_KEY_ID=<id> -z AWS_SECRET_ACCESS_KEY=<secret> \
  -e LLMAGENT_MODEL='anthropic.claude-opus-4-8'

# Claude — Google Vertex (auth via ADC / a mounted service-account key)
appm add -a llm-agent \
  -e CLAUDE_CODE_USE_VERTEX=1 \
  -e ANTHROPIC_VERTEX_PROJECT_ID=<gcp-project> -e CLOUD_ML_REGION=us-east5 \
  -e GOOGLE_APPLICATION_CREDENTIALS=/opt/appmesh/work/llm-agent-workspace/sa.json \
  -e LLMAGENT_MODEL=claude-opus-4-8

# DeepSeek (native Anthropic endpoint)
appm add -a llm-agent \
  -e ANTHROPIC_BASE_URL=https://api.deepseek.com/anthropic \
  -z ANTHROPIC_AUTH_TOKEN=<deepseek-key> \
  -e LLMAGENT_MODEL='deepseek-v4-pro[1m]' \
  -e ANTHROPIC_DEFAULT_OPUS_MODEL='deepseek-v4-pro[1m]' \
  -e ANTHROPIC_DEFAULT_SONNET_MODEL='deepseek-v4-pro[1m]' \
  -e ANTHROPIC_DEFAULT_HAIKU_MODEL=deepseek-v4-flash \
  -e CLAUDE_CODE_SUBAGENT_MODEL=deepseek-v4-flash

# Qwen — Model Studio (Beijing, pay-as-you-go)
appm add -a llm-agent \
  -e ANTHROPIC_BASE_URL=https://dashscope.aliyuncs.com/apps/anthropic \
  -z ANTHROPIC_AUTH_TOKEN=<dashscope-key> \
  -e LLMAGENT_MODEL=qwen3.7-max \
  -e ANTHROPIC_DEFAULT_OPUS_MODEL=qwen3.7-max \
  -e ANTHROPIC_DEFAULT_SONNET_MODEL=qwen3.7-max \
  -e ANTHROPIC_DEFAULT_HAIKU_MODEL=qwen3.6-flash \
  -e CLAUDE_CODE_SUBAGENT_MODEL=qwen3.6-flash

# GLM — Zhipu
appm add -a llm-agent \
  -e ANTHROPIC_BASE_URL=https://open.bigmodel.cn/api/anthropic \
  -z ANTHROPIC_AUTH_TOKEN=<zhipu-key> \
  -e LLMAGENT_MODEL='glm-5.2[1m]' \
  -e ANTHROPIC_DEFAULT_OPUS_MODEL='glm-5.2[1m]' \
  -e ANTHROPIC_DEFAULT_SONNET_MODEL='glm-5.2[1m]' \
  -e ANTHROPIC_DEFAULT_HAIKU_MODEL=glm-4.5-air \
  -e CLAUDE_CODE_SUBAGENT_MODEL=glm-4.5-air \
  -e CLAUDE_CODE_AUTO_COMPACT_WINDOW=1000000

# MiniMax (China; international: api.minimax.io)
appm add -a llm-agent \
  -e ANTHROPIC_BASE_URL=https://api.minimaxi.com/anthropic \
  -z ANTHROPIC_AUTH_TOKEN=<minimax-key> \
  -e LLMAGENT_MODEL='MiniMax-M3[1m]' \
  -e ANTHROPIC_DEFAULT_OPUS_MODEL='MiniMax-M3[1m]' \
  -e ANTHROPIC_DEFAULT_SONNET_MODEL='MiniMax-M3[1m]' \
  -e ANTHROPIC_DEFAULT_HAIKU_MODEL='MiniMax-M3[1m]' \
  -e CLAUDE_CODE_SUBAGENT_MODEL='MiniMax-M3[1m]' \
  -e CLAUDE_CODE_AUTO_COMPACT_WINDOW=1000000
```

**Easiest path — the web UI.** In **app-mesh-ui → Agents → Register**, the **Provider**
selector has one-click presets for DeepSeek / Qwen / GLM / MiniMax that fill the base URL,
the latest model, and the slot aliases for you — you only enter the credential (stored
encrypted). It writes exactly the env / secured-env described here.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Every turn errors right after enabling | No `ANTHROPIC_API_KEY` on the App — the pre-loaded definition has none; register with `-z ANTHROPIC_API_KEY=…`. |
| Turn errors mentioning the CLI / spawn / config dir | The workspace (and thus `<workspace>/.claude`) isn't writable by the App's user — the App logs a warning about `CLAUDE_CONFIG_DIR` at startup. |
| `turn_tokens: 0` (with a logged warning) | The SDK returned no usage for the turn — informational; the turn still ran. |
| `streaming is only available on a session worker App` | `stream:true` was sent to the shared App — stream only on a Scenario B worker. |

## Layout

```
llm_agent/   types · claude_sdk (the SDK engine) · session (workdir utils) · handler · __main__
config/      llm-agent.yaml (A) · llm-agent-worker.yaml (B)
examples/    user_scenarios.py
tests/       test_handler · test_session   —  python3 -m unittest discover -s tests
```
