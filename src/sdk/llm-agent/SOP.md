# LLM Agent SOP — Workflow Mode and Interactive Mode

How to run and use the AI agent on App Mesh. Two modes:

| Mode | Use when | App |
|---|---|---|
| **Workflow** — [Scenario A](README.md#two-scenarios-two-apps) | unattended pipelines: develop, test, report by stages | one shared App `llm-agent` |
| **Interactive** — Scenario B | a person talks to the agent and sees tokens stream | one worker App per session |

References: [README.md](README.md) (design, wire protocol, providers) ·
[examples/user_scenarios.py](examples/user_scenarios.py) (runnable code for both modes) ·
[config/llm-agent-worker.yaml](config/llm-agent-worker.yaml) (worker template) ·
[docs/source/CLI.md](../../docs/source/CLI.md) (appm CLI)

## 1. Start the daemon

```bash
docker run -d --name appmesh laoshanxi/appmesh:llm
docker exec appmesh /opt/appmesh/script/appmesh-auth.sh service-health   # wait until OK
```

Other installs: start the daemon, then `appm enable -a llm-agent` after step 2.

## 2. Register the credential (admin, one time)

```bash
/opt/appmesh/script/appmesh-auth.sh print-initial-password   # first-time admin password
appm logon --username admin

# GLM example (more providers: README "Models & providers"):
appm add -D @/opt/appmesh/apps/llm-agent.yaml --force \
  -z ANTHROPIC_AUTH_TOKEN=<key> \
  -e ANTHROPIC_BASE_URL=https://open.bigmodel.cn/api/anthropic \
  -e 'LLMAGENT_MODEL=glm-5.3[1m]' \
  -e 'ANTHROPIC_DEFAULT_OPUS_MODEL=glm-5.3[1m]' \
  -e 'ANTHROPIC_DEFAULT_SONNET_MODEL=glm-5.3[1m]' \
  -e ANTHROPIC_DEFAULT_HAIKU_MODEL=glm-5-turbo \
  -e CLAUDE_CODE_SUBAGENT_MODEL=glm-5-turbo \
  -e LLMAGENT_SYSTEM_PROMPT='You are an AI agent served by GLM (trained by Z.ai) through the Claude Agent SDK. When asked which model you are, answer: GLM, trained by Z.ai.'

# Anthropic API:
appm add -D @/opt/appmesh/apps/llm-agent.yaml --force -z ANTHROPIC_API_KEY=<key> -e LLMAGENT_MODEL=claude-opus-4-8
```

Check: `appm ls` shows `llm-agent` as `enabled`, health `OK`.

## 3. Get an access token

CLI-only users skip this (`appm logon` did it). SDK calls need the raw token:

```bash
TOKEN=$(curl -s -u "appmesh-cli:" -X POST http://127.0.0.1:6062/auth/token \
  -d grant_type=password -d username=admin@appmesh.local -d "password=<your password>" \
  --data-urlencode "scope=openid audience:server:client_id:appmesh-api" \
  | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([A-Za-z0-9._~-]*\)".*/\1/p')
echo ${#TOKEN}   # > 0 means success; expires in ~10 minutes
```

## 4. Workflow mode — staged develop / test pipeline

One workflow simulates the classic lifecycle: **design → develop → test**. All stages share
one `session_id`, so each stage sees the previous stages' context.

```yaml
name: py-dev
on:
  manual:
    inputs:
      requirement:
        type: string
        default: "A function is_palindrome(s): ignore case and non-alphanumeric characters."
jobs:
  design:
    steps:
      - name: clarify
        message:
          app: llm-agent
          payload: '{"action":"session_send","session_id":"pydev-${{ workflow.run_id }}","input":"Requirement: ${{ inputs.requirement }} Write a short brief: function signature, edge cases, test plan. Do not code yet."}'
        timeout: 600
  develop:
    needs: [design]
    steps:
      - name: implement
        message:
          app: llm-agent
          payload: '{"action":"session_send","session_id":"pydev-${{ workflow.run_id }}","input":"Now implement it in palindrome.py exactly per your brief."}'
        timeout: 600
  test:
    needs: [develop]
    steps:
      - name: verify
        message:
          app: llm-agent
          payload: '{"action":"session_send","session_id":"pydev-${{ workflow.run_id }}","input":"Add test_palindrome.py with unittest cases per your plan, run them, and report the result."}'
        timeout: 600
  cleanup:
    needs: [test]
    steps:
      - name: close
        message:
          app: llm-agent
          payload: '{"action":"session_close","session_id":"pydev-${{ workflow.run_id }}"}'
```

Run it:

```bash
appm workflow add -f py-dev.yaml
appm workflow run py-dev -e requirement="A function is_palindrome(s): ignore case and non-alphanumerics."
appm workflow detail -w py-dev <run_id>     # run ids: appm workflow runs py-dev
```

Real run (GLM, 465 s total). Each stage's answer is in the step `response`:

| Stage | Iterations | Tokens | What the agent produced |
|---|---|---|---|
| design.clarify | 2 | 3,320 | brief: signature, normalization rule, edge-case decision table |
| develop.implement | 24 | 19,690 | `palindrome.py`; installed pytest; fixed a Unicode encoding bug it hit |
| test.verify | 6 | 6,122 | unittest suite from the brief's table — **"Ran 5 tests — OK"** |

The test stage referred back to "the brief's table" and "the encoding issue from before" —
proof that one `session_id` carries context across stages.

## 5. Interactive mode — a streaming worker per session

An admin provisions one worker App per session; the client subscribes to its STDOUT once
and then talks turn after turn, with live tokens.

```bash
# admin: register a worker for session S1 (template: config/llm-agent-worker.yaml)
appm add -D @config/llm-agent-worker.yaml --force \
  -z ANTHROPIC_AUTH_TOKEN=<key> -e ANTHROPIC_BASE_URL=<provider url> -e 'LLMAGENT_MODEL=<model>'
```

```python
import json, time
from appmesh import AppMeshClientTCP

client = AppMeshClientTCP(tcp_address=("127.0.0.1", 6059), ssl_verify=False)
client.set_bearer_token("<token>")
sub = client.subscribe("llm-agent-sess-S1", ["STDOUT"],
                       callback=lambda e: print(e.data.get("output", ""), end=""))
time.sleep(1)  # let the subscription go live
json.loads(client.run_task("llm-agent-sess-S1", json.dumps(
    {"action": "session_send", "session_id": "S1", "input": "Hi! Remember the number 7.", "stream": True}),
    timeout=180))
```

Real session (GLM): `Remember the number 7` → *"Got it — I'll remember the number **7**"* →
`What number did I give you?` → *"You gave me the number **7**."* → close removes the worker
App and its data. Full journey: `python3 examples/user_scenarios.py b_interactive
--worker-app llm-agent-sess-S1 --worker-session S1`.

## 6. Use a Skill (optional)

Put a skill under the workspace config dir — it is available to every session:

```
/opt/appmesh/lib/llm-agent/llm-agent-workspace/.claude/skills/<name>/SKILL.md
```

Works out of the box (default tool set). Verified: a `demogreet` skill answered
`SKILL-OK: hello Alice, ...` in the exact format its SKILL.md defined. Only rule: if you
set `LLMAGENT_ALLOWED_TOOLS`, keep the Skill tool in the list.

## If a turn fails

| Message | Do this |
|---|---|
| `Not logged in` | No credential on the App. Repeat step 2. |
| `403 ... app-run-task` | Your user lacks app-run-task permission. Ask the admin. |
| `401 token expired` | The token expired. Repeat step 3. |
| `streaming is only available on a session worker App` | `stream:true` only on a worker App (step 5). |
