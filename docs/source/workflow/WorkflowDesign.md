# Workflow Engine - Overall Design

## Status

v1 implementation. The YAML model follows GitHub Actions conventions. All workflow operations (CRUD, run management, observability) go through a single Task RPC interface.

This document is the top-level design contract for the current implementation. The detailed schema lives in [WorkflowSchema.md](WorkflowSchema.md); ADR 0004 describes the future unified Run record model.

## Design Goals

- Provide GitHub Actions-style workflow authoring: workflow, trigger, job DAG, step, expression, reusable workflow, concurrency, logs, and run history.
- Reuse App Mesh as the execution substrate: a step can run a shell command as a temporary App Mesh App, run an existing App through `RunAppAsync`, or send a message through the App Mesh Task API.
- Zero daemon C++ changes: workflows are stored as special disabled Apps plus YAML files under the workflow workdir.
- CLI and GUI have identical behavior through the same Task API.

## Current Architecture

```
Client (CLI / GUI / SDK)
  │
  │  run_task("workflow", json_payload, timeout)
  │  (any App Mesh SDK: Rust/Python/Go/Java/JavaScript/C++)
  ▼
App Mesh daemon
  │
  │  FetchTask / SendTaskResult loop
  ▼
wf-engine (Go, single long-lived process)
  ├── Task RPC handler  — 12 actions for CRUD + run + observability
  ├── Trigger service   — event listener, concurrency manager, checkpoint recovery
  └── Engine core       — parser → DAG → expression → executor → logger/checkpoint/workdir
        │
        │  TCP transport (Go SDK)
        ▼
  App Mesh daemon APIs
        │
        │  RunAppAsync, Subscribe, GetAppOutput, RunTask, DeleteApp
```

The `wf-engine` binary is a pre-installed App (named `workflow`) that auto-starts on daemon boot. All workflow operations — registration, execution, cancellation, querying — go through the Task API. There is one execution path: goroutines.

## Architecture Layers

The engine is organized into 6 layers. Each layer has a clear responsibility boundary and communicates with adjacent layers through Go interfaces or function calls — no shared mutable state crosses layer boundaries.

```
┌─────────────────────────────────────────────────────┐
│  Layer 6: API Gateway + Observability               │
│  task_handler.go, workdir.go                        │
│  12 RPC actions, run index, log/step_log queries    │
├─────────────────────────────────────────────────────┤
│  Layer 1: Workflow Definition Management            │
│  parser/, registry.go, scanner.go, models/          │
│  YAML parse, daemon App CRUD, in-memory registry    │
├─────────────────────────────────────────────────────┤
│  Layer 2: Run Lifecycle                             │
│  service.go, concurrency.go, checkpoint.go          │
│  Trigger, concurrency control, crash recovery       │
├─────────────────────────────────────────────────────┤
│  Layer 3: DAG Scheduling Engine                     │
│  engine.go, dag/                                    │
│  Topo sort, layer-by-layer dispatch, cancel prop    │
├─────────────────────────────────────────────────────┤
│  Layer 4: Step Executor                             │
│  executor.go, node.go                               │
│  4 step types, remote routing, subscribe stdout     │
├─────────────────────────────────────────────────────┤
│  Layer 5: Expression Engine                         │
│  expression.go                                      │
│  ${{ }} substitution, condition eval, thread-safe   │
└─────────────────────────────────────────────────────┘
```

### Layer 1 — Workflow Definition Management

**Responsibility:** Parse, validate, store, and cache workflow definitions.

**Behavior:**

- `parser.LoadWorkflow(path)` parses YAML into `*models.Workflow`, validates name format, step type one-of rule, input key safety, and `workflow_call` ref format.
- The daemon stores each workflow as a disabled App named `workflow-{name}` with metadata `{"type":"workflow","yaml_path":"..."}`. This gives RBAC, ownership, and CRUD for free.
- `scanner.ScanWorkflows` runs every 30 seconds, lists daemon Apps with the `workflow-` prefix, and populates the in-memory `Registry`.
- `Registry` is a thread-safe `map[string]*Workflow` protected by `sync.RWMutex`. The `Get()` method returns the cached definition; the engine deep-copies it per run to avoid shared mutable state.
- `workflow_add` also calls `Registry.Update()` immediately after `AddApp` succeeds, so the workflow is triggerable without waiting for the next scan.
- `workflow_rm` calls `Registry.Remove()` before deleting the daemon App and directory, preventing ghost runs from being triggered during the removal window.

**Interfaces exposed:**
- `Registry.Get(name) *Workflow` — used by Layer 2 to fetch definitions.
- `Registry.Update(name, wf)` / `Registry.Remove(name)` — used by Layer 6 on add/remove.
- `Registry.WatchingApp(app, event) []*Workflow` — used by event listener in Layer 2.

### Layer 2 — Run Lifecycle

**Responsibility:** Manage the full lifecycle of workflow runs: trigger, queue, execute, cancel, recover.

**Behavior:**

- **Trigger:** `triggerRun` creates a unique run ID (`xid`), evaluates the concurrency group (if any), and either starts the run immediately or enqueues it.
- **Concurrency control:** `RunManager` enforces per-group serialization. `TryStart` checks if the group has an active run; if so, either queues the new run or cancels the old one (`cancel-in-progress`). When a run completes, `Complete` dequeues the next pending run if the group is empty. The `Complete` method verifies the run ID was actually in the `running` map before dequeuing — this prevents spurious dequeue when a cancelled run (evicted by `TryStart`) completes its goroutine.
- **Start:** `startRun` writes the checkpoint file first (crash-safe), then the index entry, then launches the goroutine.
- **Launch:** `launchRun` registers `cancelFn` and `ActiveSteps` in a single lock, then spawns the execution goroutine. The goroutine runs `engine.RunWithContext` and handles completion in a `defer` block.
- **Completion (defer):** The defer always fires — even on panic (via `recover`). It writes `MarkComplete` before `UpdateRunInIndex` (durable state before visible state). Then it deletes from maps and calls `Complete` to dequeue the next run. The dequeue path also writes `SaveRunning` before `UpdateRunInIndex`. If the dequeued workflow no longer exists in the registry, the run is marked `"cancelled"` with a log message.
- **Cancel:** `cancelRun` calls `cancel()` first (prevents new step registrations via `OnAppStart`), then `KillAll()` (cleans up already-registered daemon Apps). `CancelByWorkflow` drains the concurrency queue by workflow name before cancelling active runs, preventing dequeue after removal.
- **Recovery:** On startup, `RecoverStale` scans for checkpoint files with `status:"running"`. For each, `resumeRun` writes an atomic checkpoint with both pending and completed jobs (`SaveRunningWithCompleted`), registers in RunManager, and launches the goroutine. Completed jobs are skipped; their step results are restored into the expression context for cross-job references.

**State machine:**

```
               ┌──────────┐
  trigger ───▶ │ pending  │ (queued, waiting for group slot)
               └────┬─────┘
                    │ dequeue
               ┌────▼─────┐
  trigger ───▶ │ running  │ (goroutine active, checkpoint written)
               └──┬───┬───┘
         success  │   │ failure/cancel/panic
            ┌─────▼┐ ┌▼────────┐
            │success│ │failure / │
            └──────┘ │cancelled │
                     └─────────┘
```

**Interfaces exposed:**
- `TriggerManual(name, inputs, token, actor) (runID, status, error)` — used by Layer 6.
- `CancelByRunID(runID)` / `CancelByWorkflow(name)` — used by Layer 6.
- `Checkpoint().GetRunRecord(wf, runID)` — used by Layer 6 for `run_detail`.

### Layer 3 — DAG Scheduling Engine

**Responsibility:** Execute a workflow's job DAG with correct ordering, parallelism, cancellation, and failure propagation.

**Behavior:**

- `RunWithContext` is the entry point. It first deep-copies the workflow (`cloneWorkflow`) so each run has isolated `Job.Status` and `Step.Result` fields — this eliminates data races between concurrent runs of the same workflow.
- `dag.TopoSort` computes execution layers from `needs` dependencies. Each layer is a set of jobs with no inter-dependencies.
- **Single-job layers** run in an anonymous function (so `defer exec.Close()` fires per-iteration, not at function return).
- **Multi-job layers** run as parallel goroutines with `sync.WaitGroup`. Each goroutine has `defer recover()` to prevent one job's panic from crashing the entire run.
- `evaluateNeeds` checks dependency statuses following GitHub Actions semantics: `success` = all deps succeeded; `failure` = at least one dep failed; `skipped` is neutral (blocks success but doesn't trigger failure).
- `runJob` evaluates the `if` condition with `EvalConditionForJobWithStatus`, which supports `always()`, `success()`, `failure()`, and comparison operators.
- `runStep` handles retry with configurable backoff (fixed or exponential, capped at 3600s). Retry sleep is cancel-aware via `time.NewTimer` + `select` on context.
- Cancel propagation: the cancel context is checked at layer boundaries and inside `waitWithContext`. `KillAll` runs remote kills in parallel goroutines to avoid one unreachable node blocking the rest.
- Sub-workflows: `RunSubWorkflow` receives a derived context with timeout (`context.WithTimeout`). The sub-workflow gets its own `ActiveSteps` tracker (not shared with parent) and its own cloned workflow. Outputs are evaluated from the sub-workflow's expression context.

**Interfaces exposed:**
- `RunWithContext(ctx, wf, client, inputs, runID, depth, opts) (exitCode, *Context)` — used by Layer 2.
- `Options.OnJobDone` / `Options.OnStepDone` / `Options.StepLogPathFn` — callbacks to Layer 2 for checkpoint and log persistence.

### Layer 4 — Step Executor

**Responsibility:** Execute individual steps against the App Mesh daemon and collect results.

**Behavior by step type:**

- **command** (`execCommand`): Creates a temporary App (`wf-cmd-*`) with the resolved command/workdir/docker_image and runs it through the shared `runAndWait` path; the temp App is deleted at step end.
- **app** (`execApp`): Runs an existing App by name through the same `runAndWait` path, passing `env`/`sec_env` overrides.
- **runAndWait** (shared by command/app): calls `RunAppAsync`, then waits with the Go SDK's `WaitForAsyncRun`, which subscribes to `STDOUT`+`EXIT`+`REMOVED` events and backfills via `GetAppOutput` any output emitted before the subscription took effect (byte-position dedup bridges backfill and live events). Stdout chunks stream into the step log file as they arrive.
- **message** (`execMessage`): Calls `RunTask` in a goroutine with a buffered channel. A `select` on `ctx.Done()` provides cancel support — if cancelled, the function returns immediately while the goroutine drains to the buffered channel.
- **workflow** (`execWorkflow`): Creates a `context.WithTimeout` from the step's timeout config, passes it to `RunSubWorkflow`. The sub-workflow respects the timeout at DAG layer boundaries.

**Remote execution:** `clientForTarget` creates a forwarding TCP client per job and caches it in `remoteClient`. On TCP disconnect (`appmesh.ErrTransportDisconnected`), the cached client is cleared and API calls on the dead connection are skipped; the next step creates a fresh connection.

**Subscribe failure:** if the subscription cannot be established, `WaitForAsyncRun` returns an error and the step fails — there is no polling fallback.

**stdout collection:** the event handling lives in the Go SDK's `WaitForAsyncRun` (`src/sdk/go/subscribe.go`): it handles `STDOUT`, `EXIT`, `REMOVED`, and `__disconnected__` events, completes exactly once via `sync.Once`, and its `GetAppOutput` backfill is idempotent — if an EXIT event already set the exit code, the backfill result is ignored. The executor's `onOutput` callback guards the stdout buffer and step log file with a mutex and fences late events after the wait returns.

### Layer 5 — Expression Engine

**Responsibility:** Resolve `${{ }}` expressions and evaluate `if` conditions within a thread-safe context.

**Behavior:**

- `Context` holds per-run state: step results (keyed by `jobName.stepName`), job results, job statuses, inputs, env, workflow metadata. All access is protected by `sync.RWMutex`.
- All resolution requires an explicit `jobName` parameter — there is no implicit "current job" field, which eliminates a class of race conditions when parallel jobs share the same context.
- `SubstituteForJob(template, ctx, jobName)` replaces all `${{ expr }}` tokens. `EvalConditionForJob` evaluates boolean conditions with `&&`, `||`, `!`, comparison operators, and status functions (`always()`, `success()`, `failure()`).
- `SnapshotJobSteps` returns a deep copy of a job's step results (including deep-copied `outputs` maps) for `SetJobResult`, ensuring cross-job references are isolated from in-progress writes.
- Supported contexts: `steps.<step>.*` (job-scoped), `jobs.<job>.steps.<step>.*` (cross-job), `job.status`, `workflow.name`, `workflow.run_id`, `inputs.<key>`, `env.<key>`.

### Layer 6 — API Gateway + Observability

**Responsibility:** Expose all workflow operations as RPC actions and manage persistent run data.

**Behavior:**

- `TaskHandler.Run()` is a blocking `FetchTask`/`SendTaskResult` loop. Each request is parsed as JSON, validated (safe ID regex on workflow/run_id/job/step fields), dispatched to one of 12 action handlers, and the response is marshaled back. Marshal errors produce a fixed error JSON to avoid silent drops.
- **CRUD actions** (`workflow_add/get/list/rm/inputs`): Operate on YAML files and daemon Apps. `workflow_add` validates YAML via temp file + parser, preserves old YAML for rollback on `AddApp` failure, and updates the registry immediately. `workflow_rm` removes from registry, drains concurrency queues, cancels active runs, removes daemon App, then removes directory. `workflow_inputs` returns `on.manual.inputs` with fallback to `on.workflow_call.inputs`.
- **Run actions** (`run/cancel/rerun`): Delegate to Layer 2's `TriggerManual`, `CancelByRunID`, etc. `rerun` reads original inputs from `runs.json` with fallback to checkpoint.
- **Observability actions** (`runs/run_detail/log/step_log`): Read from `runs.json` index, checkpoint files, and log files. `runs` returns `[]` (not `null`) when no runs exist. `log` returns distinct errors for not-found vs. read failure.

**workdir layout:**

```
{baseDir}/{workflow}/
├── workflow.yaml
├── runs.json                    (run history index, mutex-protected)
└── runs/{run_id}/
    ├── checkpoint.json          (recovery checkpoint, atomic tmp+rename)
    ├── flow.log                 (structured run log)
    └── steps/{job}.{step}.log   (step stdout, streamed via subscribe)
```

**Retention:** `CleanOldRuns` keeps the 10 most recent runs per workflow. Running and pending runs are protected from deletion.

## Core Concepts

### Workflow Resource

A workflow is represented by:

- A YAML file at `/opt/appmesh/work/workflow/{workflow}/workflow.yaml`.
- A disabled App Mesh App named `workflow-{workflow}` with metadata `{ "type": "workflow", "yaml_path": ... }`.

The pseudo App gives CRUD and RBAC reuse without daemon changes. It is not the execution unit.

### Workflow Run

A Run is represented by files:

- `/opt/appmesh/work/workflow/{workflow}/runs.json` is the run history index.
- `/opt/appmesh/work/workflow/{workflow}/runs/{run_id}/checkpoint.json` is the recovery checkpoint while running.
- `/opt/appmesh/work/workflow/{workflow}/runs/{run_id}/flow.log` is the structured run log.
- `/opt/appmesh/work/workflow/{workflow}/runs/{run_id}/steps/{job}.{step}.log` stores step stdout.

Because all runs execute within the single `workflow` process, `runs.json` access is mutex-protected and race-free.

### Jobs

Jobs form a DAG through `needs`. Jobs in the same DAG layer run in parallel as goroutines. A job starts only after its dependencies finish; by default, skipped dependencies are neutral only when the expression semantics allow it, and failed dependencies skip downstream jobs unless overridden by an explicit condition.

### Steps

Each step has exactly one step type:

- `command`: creates a temporary App Mesh App (`wf-cmd-*`) with a shell command.
- `app`: runs an existing App Mesh App by name through `RunAppAsync`.
- `message`: calls the App Mesh Task API (`RunTask`) on a long-lived App.
- `workflow`: calls another workflow in-process that declares `on.workflow_call`, with max nesting depth 4.

Step names are job-scoped. Cross-job references must use `jobs.<job>.steps.<step>.*`.

## Trigger Model

### Manual

`appm workflow run <name>` sends a Task RPC with action `run` to the `workflow` App. The engine's trigger service starts the run as a goroutine with a unique run ID. Inputs are passed as a JSON map in the Task payload — no shell involved, no injection risk.

### App Event

The trigger service subscribes to daemon app events and triggers matching workflows in goroutines. Supported trigger events are `START`, `EXIT`, `HEALTH`, `STATUS`, and `REMOVED`.

`STDOUT` is intentionally not a workflow trigger event. If stdout-based automation is needed, use a separate log-watcher App that turns log matches into a normal workflow run.

`condition` is intentionally small: only `exit_code` with `==` or `!=`.

### Schedule

`on.schedule` is parsed and documented, but the engine does not dispatch cron internally. Cron should be modeled as an external App Mesh cron App that invokes `appm workflow run <name>`.

This keeps "when to trigger" outside the workflow engine.

### Reusable Workflow

A `workflow` step can call only a target workflow that declares `on.workflow_call`. The parent resolves `with` inputs and calls the engine's `RunSubWorkflow` callback, which executes the sub-workflow in-process (same goroutine). Outputs are evaluated from the sub-workflow's expression context and returned directly to the parent — no files, no subprocess, no temp Apps.

Max nesting depth is 4 levels. The target workflow YAML must be available at the standard workdir path (`/opt/appmesh/work/workflow/{name}/workflow.yaml`).

## Execution Semantics

1. Parse YAML and validate workflow, jobs, steps, step type one-of, safe names, and input key formats.
2. Create run files: `runs.json`, `checkpoint.json`, `flow.log`, and step log paths.
3. Build DAG layers from `jobs[*].needs`.
4. For each job, evaluate dependencies and `if`.
5. For each step, evaluate `if`, merge `env` and `sec_env`, substitute expressions, then dispatch through the executor.
6. Stream stdout by subscribing to `STDOUT`, `EXIT`, and `REMOVED` events after `RunAppAsync`; a `GetAppOutput` backfill covers output emitted before the subscription took effect.
7. Write step result snapshots into the expression context and checkpoint.
8. Run `finally` steps after normal steps. `finally` steps can read `job.status`.
9. Mark run `success`, `failure`, or `cancelled`; then mark checkpoint complete.
10. For `workflow_call`, evaluate declared outputs from the sub-workflow's expression context and return to the parent.

Input defaults and required checks are applied inside the engine.

## Expressions

Supported contexts:

- `steps.<step>.stdout`, `exit_code`, `status`, `response`, `outputs.<key>` for the current job.
- `jobs.<job>.steps.<step>.*` for cross-job references.
- `job.status` for the current job aggregate status.
- `workflow.name` and `workflow.run_id`.
- `inputs.<key>`.
- `env.<key>`.

Supported functions/operators are documented in [WorkflowSchema.md](WorkflowSchema.md). The expression engine is intentionally smaller than GitHub Actions and should not be treated as full GitHub Actions expression compatibility.

## Authentication

The engine authenticates with the local daemon via password-based login. The password is stored as an encrypted `sec_env` on the `workflow` App definition — the daemon decrypts it at spawn time and passes it as a plain environment variable.

**Setup:**

```bash
appm add -a workflow -z APPMESH_PASSWORD=<password>
```

**Runtime flow:**

```
daemon starts workflow App
  → decrypts sec_env → sets APPMESH_PASSWORD env var
  → spawns wf-engine process
     → reads APPMESH_PASSWORD
     → Login(user, password) → obtains JWT token (24h TTL)
     → SDK auto-refresh renews token before expiry
     → each run gets latest token via client.GetToken()
```

**Recovery:** If auto-refresh fails (e.g., daemon restart), the scan loop detects consecutive failures and re-logins with the stored password. If the process itself crashes, `behavior: exit: restart` causes the daemon to respawn it with a fresh login.

**Remote nodes:** Step execution on remote nodes uses `ForwardTo` header — the local daemon proxies the request and handles remote authentication. The engine's own login is used only for the control plane (registry scan, App CRUD, orphan cleanup); step execution uses the per-run identity (see Identity And Security).

## Identity And Security

- Ownership is derived from the authenticated registrant and stored in the `workflow-{name}` pseudo App's metadata; every workflow action authorizes against owner/workflow-admin (`APPMESH_WORKFLOW_ADMINS`), fail-closed (ADR 0006).
- Manually triggered runs execute steps under the triggering caller's token; automatic (event) runs use the workflow's declared `execution_identity` (credentials provisioned via `APPMESH_EXEC_IDENTITIES`) or fail closed. The engine's own identity is never used to run steps (ADR 0006 / ADR 0004).
- The triggering user is recorded as `actor` in the run record for audit.

The unified Run API and a daemon-side act-as/token-exchange model remain future work (see ADR 0004).

## Concurrency

`concurrency.group` follows the GitHub Actions intent:

- same group => only one running at a time.
- `cancel-in-progress: false` => queue the newer run.
- `cancel-in-progress: true` => cancel the active run and start the newer run.

All runs (manual, event-triggered) go through the same `RunManager`, so concurrency is globally enforced. Group names support `${{ }}` expression substitution (e.g., `deploy-${{ inputs.environment }}`).

## Cancel Semantics

Cancel is triggered via the Task API `cancel` action, which calls `CancelByRunID`:

1. Cancel the run's context first — prevents new step registrations via `OnAppStart` and unblocks all waiting goroutines (`waitWithContext`, retry sleep).
2. `ActiveSteps.KillAll()` — snapshots tracked Apps under lock, then deletes them from the daemon. Remote kills run in parallel goroutines to avoid one unreachable node blocking the rest.
3. The goroutine defer fires: writes `MarkComplete("cancelled")` to checkpoint, updates `runs.json`, cleans up maps, and dequeues the next run if applicable.

The ordering (cancel context → KillAll) ensures no step can register after the tracker is cleared but before the context fires.

`CancelByWorkflow` (used by `workflow_rm`) additionally calls `DrainQueueByWorkflow` to remove all pending runs from the concurrency queue before cancelling active runs, preventing dequeue after workflow removal.

## Checkpoint And Recovery

Checkpoint is job-granular with crash-safe write ordering:

- **Write ordering:** Durable state (checkpoint file) is always written before visible state (runs.json index). This applies to both run completion and dequeue paths — a crash at any point leaves the system in a recoverable state.
- **Atomic writes:** Checkpoint files use tmp-file + `os.Rename` for atomic persistence on POSIX.
- Completed job status is persisted with step result snapshots (stdout, exit code, status, response, outputs).
- On startup, `RecoverStale` scans for checkpoint files with `status:"running"`. `resumeRun` writes an atomic checkpoint containing both pending and completed jobs in a single write (`SaveRunningWithCompleted`), then launches the goroutine.
- Completed jobs are skipped during recovery; their step snapshots are restored into the expression context so cross-job expressions work correctly.

Recovery constraints:

- Mid-step crashes cannot resume the partial step; the incomplete job is rerun from its first step.
- Orphan cleanup removes local `wf-cmd-*` Apps on startup before recovery.
- YAML changes between crash and recovery use the current definition — renamed or removed jobs may produce different behavior than the original run.

## Cross-Node Execution

Jobs can target nodes by:

- `node_label`: label selector resolved against configured cluster node addresses.
- `host` key in `node_label` for direct target host specification.

The executor creates a forwarding TCP client (`ForwardTo`) for remote RunAppAsync, Subscribe, RunTask, and cleanup operations.

Resolution order:
1. If `node_label` has a `host` key, use that address directly.
2. Otherwise, check the local node's labels for a match.
3. If no local match, query each `--cluster-nodes` address until a match is found.

Operational assumption: the workflow workdir path is `/opt/appmesh/work/workflow` on all nodes.

## Validation Boundaries

Parser/runtime validation includes:

- workflow/job/step names match `[a-zA-Z0-9_-]+`.
- manual and workflow_call input keys match `[a-zA-Z_][a-zA-Z0-9_]*`.
- step `with` keys use the same safe identifier format.
- each step has exactly one of `command`, `app`, `message`, or `workflow`.
- `workflow` step refs match `[a-zA-Z0-9_-]+` and must target a workflow with `on.workflow_call`.

`workflow add` via the Task API validates the full YAML through the parser before persisting.

## Run Retention

The workdir retains 10 runs per workflow by default. Cleanup runs when a new run starts. Running and pending runs are protected from deletion; old completed run directories may be removed with their logs/checkpoints.

## CLI Commands

| Command | Action |
|---------|--------|
| `add -f <yaml>` | Register workflow (validates YAML, creates pseudo App) |
| `get <name>` | Download workflow YAML |
| `list` | List registered workflows (with last run status) |
| `rm <name>` | Remove workflow |
| `run <name> [-e k=v] [-f]` | Trigger a workflow run; `-f` follows output |
| `runs <name>` | List run history |
| `logs -w <name> <run-id>` | Get flow log |
| `output -w <name> <run-id> -j <job> -s <step>` | Get step stdout |
| `cancel -w <name> <run-id>` | Cancel a run |
| `rerun -w <name> <run-id>` | Re-run with original inputs |
| `detail -w <name> <run-id>` | Show run detail (per-job/step status) |
| `inputs <name>` | Show input parameters for manual trigger |

## Workflow API (Task RPC)

CLI, GUI, and any external system interact with the workflow engine through the App Mesh **Task API** (`run_task`). The `workflow` App runs a FetchTask/SendTaskResult loop to process requests.

### Transport

```
Client (CLI/GUI/SDK)
  │
  │  run_task("workflow", json_payload, timeout)
  │  (any App Mesh SDK: Rust/Python/Go/Java/JavaScript/C++)
  ▼
App Mesh daemon
  │
  │  POST /appmesh/app/workflow/task
  ▼
wf-engine (Go)
  │
  │  FetchTask() → dispatch(action) → SendTaskResult(json_response)
```

### Actions

12 actions covering workflow CRUD, run management, and observability:

| Action | Category | Description |
|--------|----------|-------------|
| `workflow_add` | CRUD | Register a workflow (validates YAML, creates pseudo App) |
| `workflow_get` | CRUD | Retrieve workflow YAML |
| `workflow_list` | CRUD | List all registered workflows |
| `workflow_rm` | CRUD | Remove a workflow and its workdir |
| `workflow_inputs` | CRUD | Get input parameter definitions for a workflow |
| `run` | Run | Trigger a new workflow run |
| `cancel` | Run | Cancel a running workflow by run ID |
| `rerun` | Run | Re-trigger a previous run with same inputs |
| `runs` | Observe | List run history for a workflow |
| `run_detail` | Observe | Get detailed run state (checkpoint or index) |
| `log` | Observe | Get flow log for a run |
| `step_log` | Observe | Get step stdout for a specific job/step |

### Request Format

All requests are JSON payloads sent via `run_task("workflow", payload, timeout_seconds)`.

#### Create Run

```json
{
  "action": "run",
  "workflow": "data-pipeline",
  "inputs": {
    "environment": "prod",
    "version": "2.0"
  }
}
```

Response:
```json
{"status": "ok", "message": "running", "data": {"run_id": "cq1abc2def3g"}}
```

A queued run (concurrency group full) returns `"message": "pending"` instead.

#### Cancel Run

```json
{
  "action": "cancel",
  "workflow": "data-pipeline",
  "run_id": "abc123"
}
```

Response:
```json
{"status": "ok", "message": "cancelled"}
```

#### List Runs

```json
{
  "action": "runs",
  "workflow": "data-pipeline"
}
```

Response:
```json
{
  "status": "ok",
  "data": [
    {"run_id": "abc123", "status": "success", "started_at": "2026-05-24T10:00:00Z", "duration": 30.5},
    {"run_id": "def456", "status": "running", "started_at": "2026-05-24T12:00:00Z"}
  ]
}
```

#### Get Flow Log

```json
{
  "action": "log",
  "workflow": "data-pipeline",
  "run_id": "abc123"
}
```

Response:
```json
{"status": "ok", "data": "[2026-05-24 10:00:01] WORKFLOW data-pipeline RUN abc123 STARTED\n..."}
```

#### Get Step Output

```json
{
  "action": "step_log",
  "workflow": "data-pipeline",
  "run_id": "abc123",
  "job": "build",
  "step": "compile"
}
```

Response:
```json
{"status": "ok", "data": "gcc -o main main.c\n..."}
```

### Error Response

All actions return errors in the same format:
```json
{"status": "error", "message": "workflow 'unknown' not found"}
```

### API Properties

- **Auth:** Inherits daemon RBAC — caller must have permission to call `run_task` on `workflow` App.
- **Cross-node:** Works via `X-Target-Host` forwarding — remote nodes with `workflow` App are reachable.
- **Timeout:** Second parameter of `run_task` controls how long the client waits for a response.
- **Idempotent reads:** `runs`, `run_detail`, `log`, `step_log`, `workflow_get`, `workflow_list`, `workflow_inputs` are read-only and idempotent.
- **Non-idempotent writes:** `run` creates a new run each time. `cancel` is idempotent (cancelling an already-done run returns an error).
- **Concurrency:** The daemon Task API uses a per-App FIFO queue (max 512 pending requests). Multiple clients can call `run_task` concurrently; requests are queued and processed one at a time by the engine's `FetchTask`/`SendTaskResult` loop. All handlers complete in single-digit milliseconds (non-blocking), so queue depth stays near zero under normal use. Event-triggered runs (`on.app_event`) bypass the Task API entirely.

## Known Limitations

| Limitation | Impact | Direction |
|------------|--------|-----------|
| Pending runs cannot be cancelled by run ID | `cancel` only works on running runs; pending (queued) runs must wait or be removed via `workflow_rm` | Add `CancelPendingRun` to remove from queue and mark "cancelled" |
| File-based Run state (`runs.json` + checkpoint) | Not a transactional Run record | Single Run record per run |
| Pseudo-App workflow storage | Reuses daemon App model but is not a first-class workflow resource | First-class Workflow API/resource |
| Owner/permission are not execution identity | Stored metadata does not guarantee step execution as owner | Explicit actor/resource_owner/execution_identity |
| Trigger eligibility not checked | A workflow with only `on.workflow_call` can be started via manual `run` | Validate source against declared triggers |
| `on.schedule` is not dispatched internally | Requires external cron App | External wrapper creates Run |
| Cross-node sub-workflow requires YAML on remote node | Sub-workflow YAML must exist at the same path on execution node | Shared workflow resource |

## ADR Index

| ADR | Decision |
|-----|----------|
| [0001](../../adr/0001-workflow-engine-single-process-goroutines.md) | Single Go binary with goroutines |
| [0002](../../adr/0002-workflow-stored-as-special-app.md) | Workflow stored as special App |
| [0003](../../adr/0003-tcp-transport-for-workflow-engine.md) | TCP transport for daemon communication |
| [0004](../../adr/0004-unified-run-management-model.md) | Unified Run management model target |

## Test Coverage

| Package | Coverage Focus |
|---------|----------------|
| `dag` | Topological sort, cycles, parallel layers |
| `expression` | Substitution, conditions, operators, job scope |
| `parser` | YAML parsing, validation, `on:` key handling |
| `trigger` | Registry, RunManager, events, checkpoint |
| `workdir` | Paths, run index, retention, step logs |
| `e2e` | DAGs, expressions, concurrency, step types, workflow_call parsing |
