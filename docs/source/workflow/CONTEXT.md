# Domain Glossary

Terms used in the App Mesh Workflow Engine feature. Each term has one meaning across code, docs, and conversation.

## Core Concepts (Existing App Mesh)

- **App** — A managed process definition registered with App Mesh. Has a command, owner, env, lifecycle behavior, and resource limits. Persisted as YAML in `/opt/appmesh/work/app/`.
- **Task** — A request-response message sent to a running App via `POST /app/{name}/task`. The client sends a payload, the App fetches it, processes it, and replies. Synchronous from the caller's perspective.
- **Event** — A notification dispatched by App Mesh when an App's state changes. Six types: PROCESS_START, PROCESS_EXIT, STDOUT_OUTPUT, HEALTH_CHANGE, STATUS_CHANGE, APP_REMOVED.
- **Label** — A key-value tag on a node (not an App). Used for node selection and routing in multi-node clusters.
- **App Run** — The act of executing an App via `POST /app/run` (async) or `POST /app/syncrun` (sync). Returns a process_uuid for tracking. Distinct from Workflow Run.

## Workflow Concepts

### Core Model (aligned with GitHub Actions)

- **Workflow** — A YAML-defined pipeline of Jobs. Stored at `/opt/appmesh/work/workflow/{name}/workflow.yaml`. Registered as a special App (label `type=workflow`, name `workflow-{name}`) for CRUD and RBAC. (v2 goal: first-class daemon resource — see ADR 0004.)
- **Job** — A parallel execution unit within a Workflow. Contains an ordered list of Steps. Jobs declare dependencies on other Jobs via `needs`. Independent Jobs run concurrently as goroutines.
- **Step** — A serial execution unit within a Job. Four types:
  - `command` — runs a shell command via `RunAppAsync` (temporary App Mesh process).
  - `app` — triggers an already-registered App via `RunAppAsync` (uses existing App definition).
  - `message` — sends a payload to a running App via the App Mesh Task API and waits for a response. Named "message" (not "task") to avoid confusion with the API-level Task concept.
  - `workflow` — invokes another Workflow via `workflow_call` in-process (max 4 levels deep). Outputs are evaluated from the sub-workflow's expression context and returned directly to the parent.
- **Workflow Run** — A single execution instance of a Workflow. Has a lifecycle: `pending` → `running` → `success`/`failure`/`cancelled`.

### v1 Current Implementation

- **Workflow Engine** — A single Go binary (`wf-engine`) using TCP transport. Runs as a pre-installed daemon App (named `workflow`). All operations (CRUD, run, cancel, observability) go through the Task RPC interface (`run_task`). No separate run mode or temp Apps.
- **Checkpoint** — A JSON file (`checkpoint.json`) in the run directory. Records per-job completion status for crash recovery. On restart, completed jobs are skipped.
- **runs.json** — Per-workflow run history index (separate from checkpoint).
- **Trigger (v1)** — Built into the workflow engine: event listener subscribes to App events, fires workflow runs as goroutines. Cron is NOT built in — `on.schedule` in YAML is parsed but a warning is emitted; use external App Mesh cron apps instead.
- **Cancel** — `cancelRun` cancels the goroutine context AND calls `KillAll()` on tracked active step Apps via `RemoveApp`.
- **Identity** — v1 uses the workflow App's `owner` field as execution identity. No separate actor/execution_identity distinction.

### v2 Target (ADR 0004 — not yet implemented)

- **Unified Run Management** — All trigger sources create a Run Record via a single API. Engine only executes, never decides when to run. Triggers are fully external.
- **Run Record** — Single source of truth replacing checkpoint.json + runs.json. Contains actor, execution_identity, per-job state.
- **Actor** — Who triggered the Run. **Execution Identity** — What credentials steps use. **Resource Owner** — Who owns the workflow. Three distinct roles.
- **First-class Workflow resource** — Daemon-native, not a pseudo-App.

### Data Lifecycle

- **Workflow Workdir** — Per-workflow directory at `/opt/appmesh/work/workflow/{name}/` containing the YAML definition and per-run data.
- **Flow Log** — Per-run structured progress log (`flow.log`).
- **Step Log** — Per-step stdout archive (`{job}.{step}.log`). Streamed via Subscribe events before step completion; fallback to `GetAppOutput` if subscribe is unavailable.
- **Run Retention** — Automatic cleanup of old run directories. Default: keep the 10 most recent runs per workflow.
- **Concurrency Group** — A named mutual-exclusion scope for Workflow Runs. GitHub Actions `concurrency` semantics.

## Expression Context (Workflow YAML)

Step references are scoped to the current Job. Cross-job references use the `jobs.<name>.steps.<step>` path.

- **`${{ steps.<name>.stdout }}`** — Captured stdout of a completed Step (current job scope).
- **`${{ steps.<name>.exit_code }}`** — Integer exit code.
- **`${{ steps.<name>.status }}`** — `success` or `failure`.
- **`${{ steps.<name>.response }}`** — Response body from a message Step.
- **`${{ steps.<name>.outputs.<key> }}`** — Output from a workflow Step's `workflow_call` outputs (evaluated in-process from sub-workflow expression context).
- **`${{ jobs.<name>.status }}`** — Status of a completed Job.
- **`${{ jobs.<name>.steps.<step>.* }}`** — Cross-job step reference.
- **`${{ job.status }}`** — Aggregate status of the current Job.
- **`${{ workflow.name }}`** — Name of the Workflow.
- **`${{ workflow.run_id }}`** — UUID of the current Workflow Run.
- **`${{ inputs.<name> }}`** — Value passed via manual trigger inputs.
- **`${{ env.<name> }}`** — Environment variable value.
- **`success()`** — True if all needs-deps succeeded. Skipped deps = not succeeded.
- **`failure()`** — True if any needs-dep failed. Skipped deps = not failed.
- **`always()`** — Always true; use for unconditional execution.

## Disambiguation

| Ambiguous term | In App Mesh core | In Workflow layer |
|----------------|-----------------|-------------------|
| Task | Request-response message API (`/app/{name}/task`) | Do not use. Use "Step" or "message step" instead. |
| App | A real managed process | In v1, workflow is registered as a special App for CRUD/RBAC. Not a runnable App. |
| Run | `POST /app/run` executes an App (App Run) | `appm workflow run` creates a Workflow Run. Internally each step creates an App Run. |
| Owner | App Mesh user who owns an App | Resource Owner — who owns the workflow definition. v1: no actor/execution_identity split. |
| Trigger | Not a concept in App Mesh core | v1: built-in event listener. v2: external App Mesh cron/event apps. |
