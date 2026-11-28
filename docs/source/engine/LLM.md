# AI and LLM

This document maps the AI and LLM scenarios of App Mesh to their surfaces: the bundled llm-agent application, the streaming task RPC, workflow message steps, the MCP server, and the remote coding sandbox. Each section links to the surface that specifies it.

## 1. Surfaces

| Surface | Role | Specification |
| --- | --- | --- |
| llm-agent | The bundled LLM application: sessions, tools, model providers | [llm-agent README](https://github.com/laoshanxi/app-mesh/blob/main/src/apps/llm-agent/README.md), [operator runbook](https://github.com/laoshanxi/app-mesh/blob/main/src/apps/llm-agent/SOP.md) |
| Streaming task RPC | Live partial results from a worker (one partial per assistant message) | [Streaming interfaces](../interfaces/Streaming.md) |
| Workflow message step | An LLM call as a pipeline stage with `${{ …outputs.answer }}}` | [Workflow YAML Schema](workflow/WorkflowSchema.md) |
| MCP server | Claude Code, Codex, and other MCP clients operate the platform (31 tools, OAuth 2.1) | [MCP server README](https://github.com/laoshanxi/app-mesh/blob/main/src/integrations/mcp-server/README.md) |
| Remote sandbox | Edit locally, build and test on a remote node from a coding agent | [AI coding agent remote sandbox](RemoteSandbox.md) |

## 2. Interactive chat

One `run_task_stream` call delivers each assistant message as a partial result plus the final envelope at the end — on the shared llm-agent application or a session worker alike, with no side-channel subscription:

```python
for token in client.run_task_stream("llm-agent", json.dumps(
        {"action": "session_send", "session_id": "S1",
         "input": "Hi! Remember the number 7."}), timeout=180):
    print(token, end="", flush=True)
```

When a session needs context isolation, it gets its own worker application with a stable working directory; the agent remembers context across turns, and closing the session removes the worker application and its data automatically.

## 3. Scheduled agent jobs

Combine the engine-native schedule trigger with an agent message step: nightly digests, periodic report generation, unattended patrol runs. Each run gets its own `session_id` (for example `${{ workflow.run_id }}`), and a final `session_close` step cleans the workspace — nothing accumulates:

```yaml
name: nightly-digest
on:
  schedule:
    - cron: "0 23 * * *"
jobs:
  digest:
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

The model's answer is a first-class expression variable (`outputs.answer`): gate on it, email it, or chain it into the next stage. Credentials live in encrypted `secret_env` values — encrypted at rest, never echoed back, never written to disk in plain text.

## 4. Multi-stage orchestration across models

A workflow drives an agent through stages that share one conversation: each stage sees what the previous stages produced. Route different stages to different models by pointing message steps at different agent applications. Verified patterns: cross-job answer references, message→message chaining (feed a previous answer into the next prompt), and DAG fan-out/join (several agent steps in parallel, a join step merges their answers).

One operational rule: a manual run that routes steps to remote nodes forwards the caller's access token with each request (30-minute default lifetime; the engine never refreshes it). For pipelines with multi-minute stages, sign in fresh beforehand, raise the token TTL, or use a schedule trigger — scheduled runs execute under an engine-local capability and are not bound by the caller's token.

## 5. Models and providers

Claude out of the box (Anthropic API, Amazon Bedrock, Google Vertex); switch to DeepSeek, Qwen, GLM, MiniMax, or any OpenAI-compatible model through a gateway — changing models is changing environment variables on the llm-agent application. Cost control: `max_iterations` per turn; a shared application for batch traffic, per-session workers for interactive use. Drop a `SKILL.md` under the workspace and every session can use it.

The `src/integrations/digital-human` package deploys a team-facing digital human in one command (internal Q&A, task execution, an approval gate for risky operations) — all the scenarios above in one ready-to-run package.

## 6. Example: spec-driven development pipeline

A reference pipeline that turns a plain requirement into a reviewed, spec-backed, tested change — orchestrated as one workflow DAG. Two files ship with the engine:

| File | What it is |
| --- | --- |
| [`spec-pipeline-demo.yaml`](https://github.com/laoshanxi/app-mesh/blob/main/src/apps/workflow/docs/spec-pipeline-demo.yaml) | Runnable demo — shell-only, no external tools; same DAG as production |
| [`llm-spec-pipeline.yaml`](https://github.com/laoshanxi/app-mesh/blob/main/src/apps/workflow/docs/llm-spec-pipeline.yaml) | Production template — same DAG, real `claude`/`openspec`/build/test commands to fill in |

The pipeline separates three layers: the engine is only the orchestrator; durable artifacts (OpenSpec change proposals committed to the repo) are the contract between stages; agent discipline (TDD, review roles) lives inside a step.

```text
checkout
  └─ clarify ── spec ──┬─ review_eng  ─┐
                       ├─ review_design ┤   (parallel fan-out)
                       └─ review_devex ─┘
                            ├─ rework_spec        (if: failure()  — any reviewer REJECT)
                            └─ plan ── implement ── test ── code_review ── ship ── finalize (if: always())
```

| Job | Purpose | Engine feature used |
| --- | --- | --- |
| `checkout` | Clone the repo into a per-run workspace | Run-scoped shared directory |
| `clarify` / `spec` | Normalize the requirement, create the OpenSpec change proposal | `retry` until it validates |
| `review_eng` / `review_design` / `review_devex` | Specialist review gates | Parallel fan-out; a REJECT is a non-zero exit |
| `rework_spec` | Revise the spec if any review rejected | `if: "failure()"` |
| `plan` / `implement` / `test` / `code_review` / `ship` | Build the change against the approved spec | Dependency gating, bounded `retry`, plain steps |
| `finalize` | Status summary | `if: "always()"` |

Artifacts flow through the shared run directory; small values (change-id, verdicts, job status) flow through expressions such as `${{ jobs.spec.steps.propose.stdout }}`.

```bash
appm workflow add  -f src/apps/workflow/docs/spec-pipeline-demo.yaml
appm workflow run  spec-pipeline-demo                       # green path
appm workflow run  spec-pipeline-demo -e demo_reject=true   # exercise the rework path
```

Moving from demo to production:

1. Swap the shell bodies for real commands: `claude -p`/`codex` for the agent steps, your real `openspec` CLI flags, your repo's build/test scripts.
2. Put `ANTHROPIC_API_KEY` and similar secrets on the workflow application's `secret_env`. Never inline keys in the YAML.
3. The workflow owner needs the permissions the engine uses per step: `app-run-task`, `app-run-async`, `app-view`, `app-output-view`, `app-subscribe`, `app-delete`, `label-view`. The caller only needs the permission to trigger the run. A missing `app-subscribe` is the classic "every command step fails to start" symptom.

By design: the DAG is acyclic — bounded iteration is `retry` (one step) or re-triggering the workflow; a true multi-round loop runs inside a step's agent. Placeholder commands must exist in the daemon's environment, otherwise those steps fail at the command.

## 7. Related

- [Streaming interfaces](../interfaces/Streaming.md) — the event contract under `run_task_stream`
- [Workflow YAML Schema](workflow/WorkflowSchema.md) — the message step and `outputs.answer`
- [AI coding agent remote sandbox](RemoteSandbox.md) — remote builds for coding agents
- [Event Subscription](../interfaces/EventSubscription.md) — event-driven AI reactions
