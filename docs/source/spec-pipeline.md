# LLM Spec-Driven Development Pipeline (on the App Mesh workflow-engine)

A reference pipeline that turns a plain requirement into a reviewed, spec-backed, tested
change in a git repo — orchestrated as an App Mesh **workflow** (DAG of steps). It is the
worked example behind the design discussion of "which spec-dev framework fits the engine."

Two files:

| File | What it is | Status |
|------|-----------|--------|
| [`spec-pipeline-demo.yaml`](../../src/workflow/docs/spec-pipeline-demo.yaml) | **Runnable** demo — shell-only, no external tools; same DAG as production | ✅ runs green on a live daemon (verified, both paths) |
| [`llm-spec-pipeline.yaml`](../../src/workflow/docs/llm-spec-pipeline.yaml) | **Production template** — same DAG, real `claude`/`openspec`/build/test commands | ✅ parses against the engine; commands are placeholders to fill in |

## The three layers

This pipeline deliberately separates concerns. The engine is only the **orchestrator**;
specs are the **contract**; the agent discipline lives **inside a step**.

| Layer | Responsibility | What plays this role |
|-------|----------------|----------------------|
| **Orchestration** | sequence stages, fan-out, gates, retries, per-tenant isolation, audit | **App Mesh workflow-engine** (this DAG) |
| **Artifact / spec** | durable, diffable, git-committed source-of-truth between stages | **OpenSpec** change proposals (`specs/changes/<id>/`) |
| **Agent behavior** | how a single coding/review step thinks (TDD, review roles) | `claude`/`codex` **inside a step** (+ superpowers / gstack skills) |

Why this split: the engine is language-agnostic and runs each step as an isolated process,
so the thing that must flow between steps has to be a **durable artifact** (an OpenSpec
change committed to the repo), not in-agent state. gstack/superpowers are Claude-Code-internal
methodologies — they belong *inside* the implement/review steps, not as the backbone.

## The DAG

```
checkout
  └─ clarify ── spec ──┬─ review_eng  ─┐
                       ├─ review_design ┤   (parallel fan-out)
                       └─ review_devex ─┘
                            ├─ rework_spec        (if: failure()  — any reviewer REJECT)
                            └─ plan ── implement ── test ── code_review ── ship ── finalize (if: always())
```

| Job | Purpose | Notable engine feature |
|-----|---------|------------------------|
| `checkout` | clone repo into a per-run workspace | run-scoped shared dir (`$RUNDIR/<run_id>`) |
| `clarify` | normalize the requirement into a testable brief | — |
| `spec` | create the OpenSpec **change proposal** (the artifact) | `retry` until it validates; change-id emitted on **stdout** |
| `review_eng` / `review_design` / `review_devex` | specialist review gates | **parallel fan-out**; a REJECT = non-zero exit = job failure |
| `rework_spec` | revise spec if any review rejected | `if: "failure()"` |
| `plan` | implementation plan from the **approved** spec | runs only if all reviews passed (deps-failed ⇒ auto-skip) |
| `implement` | agent codes against the spec, then a build/acceptance gate | `retry` = bounded "until the gate passes" loop |
| `test` | the repo's own test suite | plain command step |
| `code_review` | pre-landing review gate | — |
| `ship` | `openspec archive` → commit → push/PR | — |
| `finalize` | status summary, always | `if: "always()"` + step-level `finally` |

### Cross-step data flow
- **Artifacts** (requirements.md, the OpenSpec change, plan.md) live on a shared, run-scoped
  directory so later jobs read what earlier jobs wrote.
- **Small values** (the change-id, review verdicts, job status) flow via expressions:
  `${{ jobs.spec.steps.propose.stdout }}`, `${{ jobs.review_eng.status }}`,
  `${{ workflow.run_id }}`, `${{ inputs.feature }}`.

## Run it

The engine is driven through the `run_task` Task API (the `appm` CLI and SDKs wrap this).
Every call carries the **caller's JWT**; the engine authenticates it, enforces per-workflow
ownership, and runs the steps **as the caller** (recorded as `actor`).

### Via the CLI

```bash
appm workflow add  -f src/workflow/docs/spec-pipeline-demo.yaml
appm workflow run  spec-pipeline-demo                       # green path
appm workflow run  spec-pipeline-demo -e demo_reject=true   # exercise the rework path
appm workflow runs spec-pipeline-demo                       # list runs
appm workflow logs -w spec-pipeline-demo <run_id>           # flow log
```

### Via an SDK (Python)

```python
import json
from appmesh import AppMeshClient
c = AppMeshClient(base_url="https://127.0.0.1:6060", ssl_verify=False); c.login("admin", "***")
tok = c._get_access_token()
def call(action, **kw):
    return json.loads(c.run_task("workflow", json.dumps({"action": action, "token": tok, **kw}), 90))

call("workflow_add", workflow="spec-pipeline-demo", content=open("src/workflow/docs/spec-pipeline-demo.yaml").read())
rid = call("run", workflow="spec-pipeline-demo", inputs={})["data"]["run_id"]
print(call("run_detail", workflow="spec-pipeline-demo", run_id=rid)["data"]["status"])
```

### Verified behavior

Default (all reviews approve):
```
FINAL: success   (actor=admin)
  rework_spec   skipped         # failure-path not taken
  implement     success         # step log shows "attempt 2"  -> retry fired
  ... all other jobs success
```
`demo_reject=true` (eng rejects):
```
FINAL: failure
  review_eng    failure
  plan/implement/test/code_review/ship   skipped   # dependency-failure gating
  rework_spec   success          # if: failure()
  finalize      success          # if: always()
```

## From demo to production

1. **Swap the shell bodies** in `llm-spec-pipeline.yaml` for your real commands:
   `claude -p`/`codex` for the agent steps, your real `openspec` CLI flags, and your repo's
   `build`/`test` scripts. (The demo proves the orchestration; production just changes the
   command bodies.)
2. **Secrets**: put `ANTHROPIC_API_KEY` etc. on the workflow App's `sec_env` (encrypted at
   rest; surfaced to steps as env vars). Never inline keys in the YAML.
3. **Tenant permissions**: a workflow runs steps as the triggering caller, so that user needs
   the permissions the engine uses per step:
   `app-run-task, app-run-async, app-run-sync, app-subscribe, app-output-view, app-delete`
   (plus `label-view` if you use node selectors). Missing `app-subscribe` is the classic
   "every command step fails to start" symptom.
4. **Ownership/roles**: the registrant owns the workflow; only the owner or a workflow admin
   (`APPMESH_WORKFLOW_ADMINS`) may run/manage it. Each run is isolated and audited (`actor`).

## Caveats (by design)

- **Acyclic DAG** — there is no literal review↔fix loop. Bounded iteration is `retry`
  (single step) or **re-trigger** the workflow (`rerun`); a true multi-round loop must run
  *inside* a step's agent.
- **Long runs vs token validity** — steps run with the caller's token; a run that outlives the
  token will fail closed mid-flight. Trigger with a token whose lifetime covers the run, and
  use a non-renewing (one-shot) token so a session refresh doesn't revoke it mid-run.
- **Automatic (cron/event) triggers** have no caller identity — the workflow must declare an
  `execution_identity` (see [Workflow.md](Workflow.md)) or the run fails closed; the engine's
  own identity is never used to run steps (ADR 0004).
- Placeholder commands (`claude`/`openspec`/`gh`/`./scripts/*`) must exist in the daemon's
  environment; otherwise those steps fail at the command (a useful orchestration smoke test).

## See also
- `docs/adr/0006-workflow-multi-tenant-authz.md` — ownership, caller-scoped execution, audit.
- `docs/adr/0002`, `0004`, `0005` — workflow storage, run model, the `run_task` transport.
