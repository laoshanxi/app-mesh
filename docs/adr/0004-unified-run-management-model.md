# ADR 0004 — Unified Run Management Model

## Status

Proposed (v2 design — supersedes v1 trigger/serve architecture)

## Context

The v1 workflow engine has two separate execution paths:

1. **CLI path**: `appc workflow run` → registers a temporary App running `wf-engine run` → daemon manages the process.
2. **Serve path**: `wf-engine serve` → internal goroutine calls `engine.Run` directly.

These paths have different run lifecycle management, different logging, and different cancel semantics. The cron scheduler and event listener are baked into the engine binary, making the engine responsible for both "what to run" and "when to run" — two orthogonal concerns.

GitHub Actions separates these clearly: the platform manages run creation/scheduling; the runner only executes. App Mesh should follow the same separation.

## Decision

### Core Principle

**All workflow execution goes through a single Run API. The engine only executes — it never decides when to run.**

### Run Lifecycle

```
                     ┌─────────────┐
          ┌─────────>│   pending    │
          │          └──────┬──────┘
          │                 │ engine picks up
          │          ┌──────▼──────┐
          │          │   running    │
          │          └──────┬──────┘
          │                 │
          │     ┌───────────┼───────────┐
          │     │           │           │
          │ ┌───▼───┐ ┌────▼────┐ ┌───▼──────┐
          │ │success │ │ failure │ │cancelled │
          │ └───────┘ └─────────┘ └──────────┘
          │
    create run (from any source)
```

### Unified Run API

All trigger sources produce the same action — create a Run record:

| Source | How it creates a Run |
|--------|---------------------|
| CLI | `appc workflow run <name>` → calls Run API |
| REST API | `POST /appmesh/workflow/{name}/run` (future daemon endpoint, or engine HTTP API) |
| Cron | External cron job (OS crontab, App Mesh cron app) calls Run API |
| App Event | A small event-watcher App calls Run API on matching events |
| workflow_call | Parent engine calls Run API for sub-workflow |

The engine's job is only: pick up pending Runs → execute → update status.

### Execution Model

The `wf-engine` binary has a single mode:

```
wf-engine --server 127.0.0.1:6059
```

It runs as a long-lived App Mesh App and:
1. Watches the Run queue (polls workdir or listens for notifications).
2. Picks up `pending` Runs, marks them `running`.
3. Executes the workflow DAG (reusing existing parser/expression/dag/executor).
4. Archives logs, updates checkpoint, marks Run `success`/`failure`.

No `run` vs `serve` split. No built-in cron. No built-in event listener.

### Trigger as External Wrapper

Cron and event triggers are separate lightweight Apps, not part of the engine:

```yaml
# Cron trigger — a regular App Mesh cron app
name: cron-data-pipeline
command: "appc workflow run data-pipeline"
start_interval_seconds: "0 2 * * *"
cron: true

# Event trigger — a small script that subscribes and fires
name: event-trigger-deploy
command: "workflow-event-trigger --watch collector --on EXIT --run deploy-pipeline"
behavior:
  exit: restart
```

This leverages App Mesh's existing cron and process management instead of reimplementing them.

### Identity Model

Three distinct identities per Run, following GitHub Actions semantics:

| Identity | What it is | How it's set |
|----------|-----------|-------------|
| **resource_owner** | Who owns the workflow definition | `workflow.owner` field → App Mesh App owner |
| **actor** | Who triggered this Run | Recorded in Run record: CLI user, cron app name, event source |
| **execution_identity** | What API credentials steps use | Configured per-workflow; defaults to `resource_owner` |

Step permission check: when a step references an existing App (`app: deployer`), the daemon checks whether `execution_identity` has permission to run that App, using App Mesh's existing RBAC.

### Run Record (replaces checkpoint)

```json
{
  "run_id": "abc123",
  "workflow": "data-pipeline",
  "actor": "admin",
  "source": "cli",
  "status": "running",
  "created_at": "2026-05-23T10:00:00Z",
  "started_at": "2026-05-23T10:00:01Z",
  "execution_identity": "svc-pipeline",
  "inputs": {"env": "prod"},
  "jobs": {
    "build": {"status": "success", "finished_at": "..."},
    "test":  {"status": "running"},
    "deploy": {"status": "pending"}
  }
}
```

This is the single source of truth for run state — combining the old checkpoint.json and runs.json into one record per run.

### Step Context Isolation

v1 bug: all steps share one global `expression.Context.Steps` map. If two parallel jobs both have a step named `test`, they overwrite each other.

Fix: step results are scoped by job name internally:

```
context.Steps["build.compile"] = {stdout: "...", exit_code: 0}
context.Steps["test.run-tests"] = {stdout: "...", exit_code: 1}
```

In YAML expressions, `${{ steps.compile.stdout }}` resolves within the current job's scope. Cross-job references use `${{ jobs.build.steps.compile.stdout }}`.

### Cancel Propagation

v1 limitation: cancel only checks between DAG layers. A long-running step is not interrupted.

Fix: when a Run is cancelled:
1. Set Run status to `cancelled`.
2. For each running step's temporary App, call `DELETE /appmesh/app/{name}` to kill the process.
3. The executor's `Wait` returns with error, step is marked `cancelled`.

This requires the engine to track the mapping: `{run_id, job, step} → app_name`.

## What v1 Code Gets Reused

| Module | Reuse | Changes needed |
|--------|-------|----------------|
| `parser/` | 100% | None |
| `expression/` | 95% | Add job-scoped step key prefix |
| `dag/` | 100% | None |
| `executor/` | 90% | Return app_name for cancel tracking |
| `engine/` | 70% | Remove trigger integration, add Run record management |
| `workdir/` | 90% | Run record replaces checkpoint+index |
| `logger/` | 100% | None |
| `trigger/` | **Remove** | Replaced by external wrapper Apps |
| `checkpoint/` | **Replace** | Merged into Run record |
| `concurrency/` | 80% | Move to Run API layer |

## Consequences

### Benefits

- **Single execution path**: no CLI-vs-serve divergence.
- **Separation of concerns**: engine executes, triggers are external.
- **Simpler binary**: no event subscription, no cron parsing, no registry scanning.
- **Leverages App Mesh**: cron/event triggers are just Apps, managed by the daemon.
- **Clean identity model**: actor, owner, execution_identity are explicit.
- **Correct cancel**: propagates to running processes.

### Trade-offs

- **Requires a Run queue/API**: either daemon support or a file-based queue in workdir.
- **External trigger setup**: user must register separate trigger Apps (vs v1 auto-subscribe).
- **More moving parts to deploy**: engine App + trigger App(s) vs single engine App.
