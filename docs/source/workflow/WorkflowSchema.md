# Workflow YAML Schema Reference

Complete schema definition for App Mesh Workflow pipelines.

## Design Status

The YAML shape below is shared by the current prototype and the ADR 0004 target
model. The execution architecture is still being converged: `on.schedule`,
`on.app_event`, `runs.json`, and `checkpoint.json`
describe the v1 prototype path. In the target design, those trigger sources are
external wrappers that create Workflow Runs through one Run API, and each Run
Record is the single lifecycle/logging/checkpoint source of truth.

## Minimal Example

```yaml
name: hello-world
jobs:
  greet:
    steps:
      - name: say-hello
        command: "echo hello"
```

## Full Example

```yaml
name: data-pipeline
permission: 200

on:
  app_event:
    app: "data-collector"
    events: [EXIT]
    condition: "exit_code == 0"
  schedule:
    - cron: "0 2 * * *"
  manual:
    inputs:
      env:
        type: string
        default: "staging"
        description: "Target environment"
  workflow_call:
    inputs:
      region:
        type: string
        required: true
    outputs:
      deploy_url:
        value: "${{ jobs.deploy.steps.verify.stdout }}"

concurrency:
  group: "data-pipeline"
  cancel-in-progress: false

env:
  PIPELINE_VERSION: "2.0"

sec_env:
  DB_PASSWORD: "encrypted-value"

jobs:
  build:
    steps:
      - name: compile
        command: "make build"
        workdir: "/opt/project"
        timeout: 600
        retry:
          max: 3
          backoff: exponential
        env:
          BUILD_TYPE: "release"

  test-unit:
    needs: [build]
    steps:
      - name: run-tests
        command: "make test"
        continue-on-error: true

  test-e2e:
    needs: [build]
    node_label:
      role: "test-server"
    steps:
      - name: run-e2e
        app: "e2e-runner"
        timeout: 300

  deploy:
    needs: [test-unit, test-e2e]
    if: "success()"
    steps:
      - name: deploy-prod
        app: "deployer"
        timeout: 600
        retry:
          max: 2
          backoff: fixed
          interval: 30
        env:
          TARGET: "${{ inputs.env }}"
          VERSION: "${{ jobs.build.steps.compile.stdout }}"

      - name: verify
        command: "curl -f https://prod/health"
        if: "steps.deploy-prod.exit_code == 0"

      - name: rollback
        app: "rollback-service"
        if: "steps.deploy-prod.exit_code != 0"

    finally:
      - name: cleanup
        command: "rm -rf /tmp/workflow/${{ workflow.run_id }}"
        if: "always()"
      - name: notify
        message:
          app: "slack-bot"
          payload: '{"status": "${{ job.status }}", "workflow": "${{ workflow.name }}"}'

  update-docs:
    needs: [deploy]
    steps:
      - name: refresh
        workflow: "doc-refresh"
        with:
          version: "${{ jobs.deploy.steps.verify.stdout }}"
        timeout: 120
```

---

## Top-Level Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | — | Unique workflow identifier. Used as part of the registered App name (`workflow-{name}`). Must match `[a-zA-Z0-9_-]+`. |
| `owner` | string | no | — | **Ignored by the engine** (a YAML-supplied owner would be spoofable). Ownership is always the authenticated user who registers the workflow; only the owner or a workflow admin (`APPMESH_WORKFLOW_ADMINS`) can operate on it. Execution identity is separate — see `execution_identity`. |
| `permission` | integer | no | 0 | Copied onto the registered `workflow-{name}` App's permission field. **Not consulted by the engine's workflow actions** — those check owner/admin only. It affects daemon-side App access (e.g. who sees the pseudo-App), same semantics as App Mesh App permission. |
| `execution_identity` | string | no | — | App Mesh user whose credentials the engine uses to run this workflow's steps (ADR 0004). The engine must hold that identity's credential in `APPMESH_EXEC_IDENTITIES`, and at registration the caller may bind only itself or (as a workflow admin) any configured identity. **When omitted:** manual runs execute under the *triggering caller's* identity; automatic (event) triggers **fail closed** (they have no caller identity, and the engine never runs steps under its own privileged identity). Must match `[a-zA-Z0-9_.@-]+`. |
| `on` | object | no | — | Trigger configuration. Omit to allow only manual/API triggering. |
| `concurrency` | object | no | — | Concurrency control. Omit to allow unlimited parallel runs. |
| `env` | object | no | — | Global environment variables inherited by all Steps. Keys are variable names, values are strings. Supports `${{ }}` expressions. |
| `sec_env` | object | no | — | Global encrypted environment variables. Same as App Mesh `sec_env`. Inherited by all Steps. |
| `jobs` | object | yes | — | Map of job names to Job definitions. At least one job required. |

---

## `on` — Trigger Configuration

Defines when the workflow is automatically triggered. Multiple trigger types can coexist — any match triggers a run.

### `on.app_event` — App Event Trigger

Fires when a registered App emits a matching event.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `app` | string | yes | — | Name of the App to watch. |
| `events` | list[string] | yes | — | Event types to match. Values: `START`, `EXIT`, `HEALTH`, `STATUS`, `REMOVED`. STDOUT is not a valid trigger event — use an external log-watcher App for stdout-based automation. |
| `condition` | string | no | — | Simple expression evaluated against event data. `exit_code` is supported (`return_code` is an accepted alias). Operators: `==`, `!=`. Example: `"exit_code == 0"`. |

```yaml
on:
  app_event:
    app: "data-collector"
    events: [EXIT]
    condition: "exit_code == 0"
```

### `on.schedule` — Cron Trigger (External)

> **Note:** The workflow engine does NOT dispatch cron schedules internally. To schedule a workflow on a cron, register an App Mesh cron App whose command is `appm workflow run <name>`. The `on.schedule` field is parsed for documentation/validation purposes but a warning is emitted at parse time.

Declares the intended cron schedule.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `cron` | string | yes | — | Cron expression (5-field standard or 6-field with seconds). |

```yaml
on:
  schedule:
    - cron: "0 2 * * *"       # daily at 2am
    - cron: "0 */6 * * *"     # every 6 hours
```

### `on.manual` — Manual/API Trigger

Defines input parameters for manual triggering via CLI or API.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `inputs` | object | no | — | Map of input parameter definitions. |

Each input:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `type` | string | yes | — | `string`, `number`, `boolean`. |
| `required` | boolean | no | false | Whether the input must be provided. |
| `default` | any | no | — | Default value if not provided. |
| `description` | string | no | — | Human-readable description. |

```yaml
on:
  manual:
    inputs:
      environment:
        type: string
        default: "staging"
        description: "Target environment"
      dry_run:
        type: boolean
        default: false
```

Trigger via CLI:
```bash
appm workflow run data-pipeline --input environment=prod --input dry_run=false
```

### `on.workflow_call` — Callable by Other Workflows

Declares this workflow as callable from another workflow's `workflow` step type. A workflow with only `on.workflow_call` is intended as a reusable sub-workflow. Note: the engine does not currently enforce trigger eligibility, so such a workflow can still be started via `appm workflow run`.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `inputs` | object | no | — | Input parameter definitions (same schema as `on.manual.inputs`). |
| `outputs` | object | no | — | Values to return to the caller. |

Each output:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `value` | string | yes | — | Expression that resolves to the output value. |

```yaml
on:
  workflow_call:
    inputs:
      region:
        type: string
        required: true
    outputs:
      deploy_url:
        value: "${{ jobs.deploy.steps.get-url.stdout }}"
```

---

## `concurrency` — Concurrency Control

Controls parallel execution of the same workflow. Follows GitHub Actions semantics.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `group` | string | yes | — | Concurrency group name. Runs in the same group are mutually exclusive. Supports `${{ }}` expressions. |
| `cancel-in-progress` | boolean | no | false | `false`: new run queues behind the running one. `true`: running run is cancelled, new run starts immediately. |

```yaml
concurrency:
  group: "deploy-${{ inputs.environment }}"
  cancel-in-progress: true
```

---

## `jobs` — Job Definitions

Map of job name → Job definition. Job names must match `[a-zA-Z0-9_-]+`.

### Job Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `needs` | list[string] | no | — | Job names that must complete before this job starts. Forms the DAG. |
| `if` | string | no | — | Expression. Job runs only if true. Available functions: `success()`, `failure()`, `always()`. Default behavior: job runs only if all `needs` jobs succeeded. |
| `node_label` | object | no | — | Key-value label selector for target node. Step execution is routed to a node matching all labels via `X-Target-Host`. |
| `env` | object | no | — | Job-level environment variables. Merged with global `env` (job wins on conflict). |
| `sec_env` | object | no | — | Job-level encrypted environment variables. Merged with global `sec_env`. |
| `steps` | list[Step] | yes | — | Ordered list of Steps to execute serially. At least one step required. |
| `finally` | list[Step] | no | — | Steps that run after all `steps` complete, regardless of success or failure. Follows same Step schema. |

```yaml
jobs:
  deploy:
    needs: [build, test]
    if: "success()"
    node_label:
      role: "app-server"
      region: "us-east"
    env:
      DEPLOY_MODE: "rolling"
    steps:
      - name: do-deploy
        app: "deployer"
    finally:
      - name: notify
        command: "echo done"
```

---

## Steps — Execution Units

Each Step has a `name` and exactly one of four type keys: `command`, `app`, `message`, or `workflow`. Common fields apply to all types.

### Common Step Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | — | Unique within the Job. Used in `${{ steps.<name>.* }}` references. Must match `[a-zA-Z0-9_-]+`. |
| `if` | string | no | — | Expression. Step runs only if true. Default: runs if all prior steps in the job succeeded. |
| `timeout` | integer | no | 172800 (2 days) for command/app/workflow steps; 300 (5 minutes) for message steps | Maximum execution time in seconds. Step is killed and marked failed if exceeded. `0` falls back to the default — there is no "unlimited" mode. |
| `retry` | object | no | — | Retry policy on failure. |
| `continue-on-error` | bool | no | `false` | `true`: mark step as failed but continue to next step. Default: stop the job on failure. |
| `env` | object | no | — | Step-level environment variables. Merged with job and global `env` (step wins). |
| `sec_env` | object | no | — | Step-level encrypted environment variables. |

### `retry` — Retry Policy

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `max` | integer | yes | — | Maximum number of retry attempts (not counting the initial run). |
| `backoff` | string | no | `"fixed"` | `"fixed"`: wait `interval` seconds between retries. `"exponential"`: wait `interval * 2^attempt` seconds. |
| `interval` | integer | no | 10 | Base wait time in seconds between retries. |

```yaml
retry:
  max: 3
  backoff: exponential
  interval: 10
# Waits: 10s → 20s → 40s
```

---

### Step Type: `command`

Runs a shell command as a temporary App Mesh process.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `command` | string | yes | — | Shell command to execute. |
| `workdir` | string | no | — | Working directory for the command. |
| `shell` | boolean | no | true | Run through shell interpreter. Set false for direct exec. |
| `docker_image` | string | no | — | Run command inside a Docker container. |

```yaml
- name: build
  command: "make build -j$(nproc)"
  workdir: "/opt/project"
  timeout: 600
  env:
    CC: "gcc-12"
```

**Outputs available:**
- `${{ steps.<name>.stdout }}` — captured stdout (trimmed, max 64KB)
- `${{ steps.<name>.exit_code }}` — integer exit code
- `${{ steps.<name>.status }}` — `"success"`, `"failure"`, or `"skipped"`

---

### Step Type: `app`

Triggers an already-registered App Mesh application.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `app` | string | yes | — | Name of the registered App to run. |

The App is executed via `RunAppAsync` over TCP. The engine polls/waits for completion and captures stdout after the step finishes.

Environment variables from `env`/`sec_env` are passed as overrides to the App run.

```yaml
- name: deploy
  app: "deployer"
  timeout: 300
  env:
    TARGET: "prod"
```

**Outputs available:**
- `${{ steps.<name>.stdout }}` — captured stdout
- `${{ steps.<name>.exit_code }}` — integer exit code
- `${{ steps.<name>.status }}` — `"success"`, `"failure"`, or `"skipped"`

---

### Step Type: `message`

Sends a payload to a running long-lived App via the App Mesh Task API (`POST /appmesh/app/{name}/task`) and waits for a response. Called "message" in Workflow terminology to avoid confusion with the core App Mesh Task concept.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `message.app` | string | yes | — | Name of the running App to send the message to. |
| `message.payload` | string | yes | — | Request payload. Supports `${{ }}` expressions. |
| `message.forward_token` | boolean | no | `false` | Inject the run's caller JWT into the JSON payload's `token` field before sending. For a target App that reads the caller token from the payload body. No-op when the payload isn't a JSON object, when an author-set `token` is already present, or for automatic/recovered runs (which carry no caller token). |

```yaml
- name: inference
  message:
    app: "ml-model"
    payload: '{"data": "${{ steps.prepare.stdout }}", "model": "v3"}'
  timeout: 60

# Driving an llm-agent (Scenario A). The daemon authorizes the call via RBAC; llm-agent
# reads no caller token of its own, so forward_token is not needed here. session_send
# get-or-creates the session, so the step need not pre-open one; "${{ workflow.run_id }}"
# gives a fresh per-run session (reuse a stable id to continue a conversation):
- name: ask
  message:
    app: "llm-agent"
    payload: '{"action": "session_send", "session_id": "${{ workflow.run_id }}", "input": "${{ inputs.q }}"}'
```

> **Note:** llm-agent performs no token check of its own, so **automatic triggers
> (event/cron) drive it the same as manual runs** — access is gated by the daemon's RBAC
> on `run_task` (and, for a Scenario B worker, the App's `permission`).

**Outputs available:**
- `${{ steps.<name>.response }}` — response body from the App
- `${{ steps.<name>.exit_code }}` — 0 if response received, non-zero on timeout/error
- `${{ steps.<name>.status }}` — `"success"`, `"failure"`, or `"skipped"`

**App-level errors fail the step.** If the App's response is the platform error envelope
`{"status": "error", "message": "..."}`, the step is marked **failed** (the message
becomes the failure reason) rather than a swallowed success — so `if:`/`needs`,
`continue-on-error`, and retry behave correctly. The full body is still available as
`${{ steps.<name>.response }}`. Responses that are not a JSON object with `status:"error"`
(other JSON, plain text) are unaffected and remain successes on a received reply.

---

### Step Type: `workflow`

Invokes another workflow that declares `on.workflow_call`. Maximum nesting depth: 4 levels.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `workflow` | string | yes | — | Name of the target workflow (must have `on.workflow_call`). |
| `with` | object | no | — | Input values to pass. Keys must match the target's `on.workflow_call.inputs`. |

```yaml
- name: deploy-us
  workflow: "deploy-template"
  with:
    region: "us-east"
    version: "${{ steps.build.stdout }}"
  timeout: 600
```

**Outputs available:**
- `${{ steps.<name>.outputs.<key> }}` — values from the target workflow's `on.workflow_call.outputs`
- `${{ steps.<name>.exit_code }}` — 0 if sub-workflow succeeded, non-zero otherwise
- `${{ steps.<name>.status }}` — `"success"`, `"failure"`, or `"skipped"`

---

## Expression Syntax

Expressions are enclosed in `${{ }}` and evaluated at runtime by the workflow engine.

### Contexts

| Context | Description | Example |
|---------|-------------|---------|
| `steps.<name>.stdout` | Stdout of a completed step (trimmed, max 64KB) | `${{ steps.build.stdout }}` |
| `steps.<name>.exit_code` | Integer exit code | `${{ steps.build.exit_code }}` |
| `steps.<name>.status` | `"success"`, `"failure"`, or `"skipped"` | `${{ steps.build.status }}` |
| `steps.<name>.response` | Response body from a message step | `${{ steps.query.response }}` |
| `steps.<name>.outputs.<key>` | Output from a workflow step | `${{ steps.sub.outputs.url }}` |
| `job.status` | Current job aggregate status | `${{ job.status }}` |
| `jobs.<name>.steps.<name>.*` | Cross-job step reference | `${{ jobs.build.steps.compile.stdout }}` |
| `workflow.name` | Workflow name | `${{ workflow.name }}` |
| `workflow.run_id` | UUID of this run | `${{ workflow.run_id }}` |
| `inputs.<name>` | Manual trigger or workflow_call input | `${{ inputs.environment }}` |
| `env.<name>` | Resolved environment variable | `${{ env.PIPELINE_VERSION }}` |

### Functions

| Function | Description |
|----------|-------------|
| `success()` | True if all preceding steps/needs-jobs succeeded. |
| `failure()` | True if any preceding step/needs-job failed. |
| `always()` | Always true. Use for unconditional execution (e.g., in `finally`). |

### Operators

| Operator | Example |
|----------|---------|
| `==` | `steps.build.exit_code == 0` |
| `!=` | `steps.build.status != "failure"` |
| `>` `<` `>=` `<=` | `steps.build.exit_code > 1` |
| `&&` | `steps.a.status == "success" && steps.b.status == "success"` |
| `\|\|` | `failure() \|\| steps.notify.status == "success"` |
| `!` | `!failure()` |

---

## Variable Precedence

Environment variables are merged with the following precedence (highest wins):

```
step.env  >  job.env  >  global env  >  App defaults
step.sec_env  >  job.sec_env  >  global sec_env  >  App defaults
```

---

## Data Flow Between Steps

### Small data (< 64KB): stdout capture

```yaml
steps:
  - name: get-version
    command: "cat VERSION"
  - name: deploy
    app: "deployer"
    env:
      VERSION: "${{ steps.get-version.stdout }}"
```

### Large data: shared directory

Steps on the same node share the filesystem. Use `workflow.run_id` for isolation:

```yaml
env:
  WORK_DIR: "/tmp/workflow/${{ workflow.run_id }}"

jobs:
  prepare:
    steps:
      - name: download
        command: "curl -o $WORK_DIR/data.csv https://data.internal/export"
  process:
    needs: [prepare]
    steps:
      - name: transform
        command: "/opt/transform.sh $WORK_DIR/data.csv $WORK_DIR/result.csv"
```

---

## Execution Semantics

### Job Scheduling

1. Jobs with no `needs` start immediately in parallel.
2. A job starts when all `needs` jobs have completed.
3. A job with `if` is evaluated after `needs` complete. If false, the job is skipped (status: `skipped`).
4. Default `if`: a job only runs if all `needs` jobs succeeded (implicit `success()`).

### Step Execution

1. Steps within a job execute serially in declaration order.
2. If a step fails (default), remaining steps in the job are skipped. `finally` steps still run.
3. If a step has `continue-on-error: true`, the step is marked failed but the next step proceeds.
4. A step with `if: false` is skipped (status: `skipped`). Skipped steps do not count as failure.
5. Retry attempts happen before evaluating `continue-on-error`. A step that succeeds on retry is marked `success`.

### Finally Block

1. `finally` steps run after all job `steps` complete, regardless of success or failure.
2. `finally` steps execute serially.
3. `finally` step failure does not change the job's status (which is determined by `steps`).
4. `finally` steps have access to all `${{ steps.* }}` and `${{ job.status }}` contexts.

### Workflow Completion

1. Workflow succeeds (exit 0) if all jobs completed successfully or were skipped.
2. Workflow fails (exit non-zero) if any job failed.
3. Structured progress is emitted to stdout throughout execution (see Observability).

---

## Observability

The workflow engine writes structured log lines to a per-run flow log file. View with:

```bash
# List run history
appm workflow runs data-pipeline

# View flow log for a specific run
appm workflow logs -w data-pipeline <run-id>

# View step stdout
appm workflow output -w data-pipeline <run-id> -j build -s compile
```

Log format (in flow.log):

```
[{timestamp}] WORKFLOW {name} RUN {run_id} STARTED
[{timestamp}] JOB {job_name} STARTED
[{timestamp}] STEP {step_name} STARTED
[{timestamp}] STEP {step_name} COMPLETED exit_code={code} duration={seconds}s
[{timestamp}] STEP {step_name} FAILED exit_code={code} duration={seconds}s
[{timestamp}] STEP {step_name} RETRY {attempt}/{max}
[{timestamp}] STEP {step_name} SKIPPED reason="{condition}"
[{timestamp}] JOB {job_name} COMPLETED status={success|failure|skipped}
[{timestamp}] JOB {job_name} FINALLY STARTED
[{timestamp}] JOB {job_name} FINALLY COMPLETED
[{timestamp}] WORKFLOW {name} RUN {run_id} COMPLETED status={success|failure} duration={seconds}s
```

---

## Cross-Node Execution

Jobs can target a specific cluster node via the `node_label` field. Steps in that job execute on the matching remote node via `X-Target-Host` forwarding.

```yaml
jobs:
  backup:
    node_label:
      host: "db-server:6059"      # Direct host specification
    steps:
      - name: dump
        command: "pg_dump -f /backup/db.sql"

  deploy:
    node_label:
      role: "app-server"           # Label-based matching
      region: "us-east"
    steps:
      - name: push
        app: deployer
```

Resolution order:
1. If `node_label` has a `host` key, use that address directly.
2. Otherwise, check the local node's labels for a match.
3. If no local match, query each `--cluster-nodes` address until a match is found.

---

## Checkpoint & Recovery

Each run writes a `checkpoint.json` file that tracks per-job completion status. If the workflow engine crashes mid-run:

1. On restart, the engine scans for `checkpoint.json` files with `status: running`.
2. Jobs marked `success` or `skipped` in the checkpoint are not re-executed.
3. The run resumes from the first incomplete job.

Checkpoint file location: `/opt/appmesh/work/workflow/{name}/runs/{run-id}/checkpoint.json`

---

## Run Retention

Old run data is automatically cleaned up when a new run starts. The retention limit is 10 runs per workflow (hardcoded in v1). When exceeded, the oldest run directories are deleted, including their checkpoint, flow log, and step log files.

---

## Workdir Layout

Each workflow has a dedicated directory on the server:

```
/opt/appmesh/work/workflow/
└── {workflow-name}/
    ├── workflow.yaml               # Workflow definition
    ├── runs.json                   # Run history index
    └── runs/
        └── {run-id}/
            ├── checkpoint.json     # Job-level completion state
            ├── flow.log            # Structured progress log
            └── steps/
                ├── {job}.{step}.log  # Step stdout archive
                └── ...
```

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `appm workflow add -f <yaml>` | Register workflow (validates YAML, creates pseudo App) |
| `appm workflow get <name>` | Download and display workflow YAML definition |
| `appm workflow list` | List all registered workflows (with last run status) |
| `appm workflow rm <name>` | Remove a workflow registration |
| `appm workflow run <name> [-e k=v] [-f]` | Trigger a workflow run; `-f` follows output |
| `appm workflow runs <name>` | List run history (ID, status, time, duration) |
| `appm workflow logs -w <name> <run-id>` | View flow log for a specific run |
| `appm workflow output -w <name> <run-id> -j <job> -s <step>` | View step stdout archive |
| `appm workflow cancel -w <name> <run-id>` | Cancel a running workflow |
| `appm workflow rerun -w <name> <run-id>` | Re-run with original inputs |
| `appm workflow detail -w <name> <run-id>` | Show run detail (per-job/step breakdown) |
| `appm workflow inputs <name>` | Show input parameters for manual trigger |
