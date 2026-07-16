# Workflow

App Mesh Workflow provides GitHub Actions-style CI/CD pipelines that run directly on App Mesh. Define your pipeline as a YAML file, register it, and trigger runs via CLI or events.

Every example below is **copy-paste runnable** against a local App Mesh daemon — commands use `echo`/`sleep`/`true`/`false` so they work without any extra setup.

## Quick Start

### 1. Write a workflow

Save this as `hello.yaml`:

```yaml
name: hello-world
jobs:
  greet:
    steps:
      - name: say-hello
        command: "echo Hello from App Mesh Workflow!"
```

### 2. Register, run, inspect

```bash
# Register
appm workflow add -f hello.yaml

# List registered workflows (owner + last run status)
appm workflow list

# Show a workflow's YAML definition
appm workflow get hello-world

# Show a workflow's declared inputs (name, type, required, default)
appm workflow inputs hello-world

# Trigger a run (note the run_id printed in the message)
appm workflow run hello-world

# Pass inputs declared under on.manual.inputs
appm workflow run hello-world -e env=staging -e dry_run=true

# List runs
appm workflow runs hello-world

# Trigger a new run and tail its log until terminal
appm workflow run hello-world -f

# Read the run's flow log
appm workflow logs -w hello-world <run_id>

# Read a step's stdout
appm workflow output -w hello-world <run_id> -j greet -s say-hello

# Per-job / per-step status, exit codes and timings for one run
appm workflow detail -w hello-world <run_id>

# Cancel a running (or still-queued) run
appm workflow cancel -w hello-world <run_id>

# Re-run a finished run with the same inputs (returns a new run_id)
appm workflow rerun -w hello-world <run_id>

# Clean up
appm workflow rm hello-world
```

## Concepts

A **workflow** contains one or more **jobs**. Jobs run in dependency order (DAG). Each job contains sequential **steps**. Steps execute commands, run existing Apps, send messages, or invoke sub-workflows.

```
Workflow
  ├── Job A
  │     ├── Step 1 (command)
  │     ├── Step 2 (app)
  │     └── finally:
  │           └── Step cleanup
  └── Job B (needs: [A])
        ├── Step 1 (command)
        └── Step 2 (message)
```

## Step Types

### Command Step

Runs a shell command. A temporary App (`wf-cmd-*`) is created and removed after execution.

Save as `command-demo.yaml`:

```yaml
name: command-demo
jobs:
  build:
    steps:
      - name: build
        command: "echo build $BUILD_TYPE && sleep 1 && echo done"
        workdir: "/tmp"
        timeout: 30
        env:
          BUILD_TYPE: release
```

```bash
appm workflow add -f command-demo.yaml
appm workflow run command-demo -f
appm workflow rm command-demo
```

The `command` runs in a shell, so a YAML block scalar (`|`) gives you a full multi-line script — variables, loops, and conditionals all work:

```yaml
name: multiline-demo
jobs:
  build:
    steps:
      - name: script
        command: |
          set -e
          VERSION=2.0.1
          for stage in lint build test; do
            echo "running $stage for $VERSION"
          done
          if [ -d /tmp ]; then echo "tmp exists"; fi
```

```bash
appm workflow add -f multiline-demo.yaml
appm workflow run multiline-demo -f
appm workflow rm multiline-demo
```

> When passing a step's output into another command via `${{ steps.x.stdout }}`, prefer single-line values — a multi-line stdout substituted into a one-line command will have its later lines executed as separate shell commands. Emit a single line (e.g. `echo "$RESULT"`) for values you intend to interpolate.

### App Step

Runs an existing registered App. Useful for long-running services or pre-configured tasks.

```yaml
# app-step-demo.yaml
name: app-step-demo
jobs:
  use-ping:
    steps:
      - name: ping-once
        app: "ping"          # an existing registered App
        timeout: 10
```

```bash
# Make sure the target App exists first (ping is shipped with the daemon)
appm ls | grep ping

appm workflow add -f app-step-demo.yaml
appm workflow run app-step-demo -f
appm workflow rm app-step-demo
```

### Message Step

Sends a JSON payload to another App via the Task API (`run_task`). The target App processes it and returns a response.

```yaml
# message-demo.yaml
name: message-demo
jobs:
  call-pytask:
    steps:
      - name: ask
        message:
          app: "pytask"      # pytask is shipped with the daemon
          payload: 'print("hello from message step")'
        timeout: 30
```

```bash
appm workflow add -f message-demo.yaml
appm workflow run message-demo -f
appm workflow rm message-demo
```

### Sub-workflow Step

Invokes another registered workflow. Inputs are passed via `with`, outputs are returned. Nesting is capped at 4 levels.

Save the callee `deploy-service.yaml`:

```yaml
name: deploy-service
on:
  workflow_call:
    inputs:
      target:
        type: string
        required: true
    outputs:
      deployed_url:
        value: "${{ jobs.deploy.steps.publish.stdout }}"

jobs:
  deploy:
    steps:
      - name: publish
        command: "echo https://${{ inputs.target }}.example.com"
```

Save the caller `release.yaml`:

```yaml
name: release
jobs:
  rollout:
    steps:
      - name: deploy-staging
        workflow: deploy-service
        with:
          target: staging
        timeout: 60

      - name: notify
        command: "echo deployed to ${{ steps.deploy-staging.outputs.deployed_url }}"
```

```bash
appm workflow add -f deploy-service.yaml
appm workflow add -f release.yaml
appm workflow run release -f

appm workflow rm release
appm workflow rm deploy-service
```

## Job Dependencies (DAG)

Use `needs` to define execution order. Jobs without dependencies run in parallel.

```yaml
# dag-demo.yaml
name: dag-demo
jobs:
  build:
    steps:
      - name: compile
        command: "echo building && sleep 1 && echo v1.2.3"

  test:
    needs: [build]
    steps:
      - name: run-tests
        command: "echo testing ${{ jobs.build.steps.compile.stdout }}"

  deploy:
    needs: [test]
    steps:
      - name: deploy
        command: "echo deploying"
```

```bash
appm workflow add -f dag-demo.yaml
appm workflow run dag-demo -f
appm workflow detail -w dag-demo <run_id>   # see per-job status
appm workflow rm dag-demo
```

Execution order: `build` → `test` → `deploy`. If `build` fails, `test` and `deploy` are skipped.

## Conditions

Use `if` on jobs or steps to control execution with expressions.

```yaml
# conditions-demo.yaml
name: conditions-demo
jobs:
  deploy:
    steps:
      - name: check
        command: "echo ready"

      - name: deploy
        command: "false"                            # intentionally fails
        if: "steps.check.stdout == 'ready'"         # step `if` gating on a prior step's output

    finally:
      - name: rollback
        command: "echo rolling back"
        if: "steps.deploy.exit_code != 0"           # failure handling belongs in finally (see note)

  notify:
    needs: [deploy]
    if: "always()"                                  # runs even though deploy failed
    steps:
      - name: send-alert
        command: "echo deploy status was ${{ jobs.deploy.status }}"
```

```bash
appm workflow add -f conditions-demo.yaml
appm workflow run conditions-demo -f
appm workflow rm conditions-demo
```

> **Failure handling must go in `finally`.** A failed step stops the job (see [Error Handling](#error-handling)), so a *later step in the main `steps:` list* — even one with `if: failure()` or `if: "…exit_code != 0"` — is never reached. Put rollback/recovery logic in `finally` (its steps always run and do evaluate `if`), or set `continue-on-error: true` on the step that may fail so the following step's `if` is evaluated.

**Status functions** (evaluated against the current job's steps when used at step/finally level; against dependency jobs when used as a job-level `if`):

| Function | Meaning |
|----------|---------|
| `success()` | All prior steps / dependencies succeeded (default) |
| `failure()` | At least one prior step / dependency failed |
| `always()` | Run regardless of status |

## Expressions

Expressions use `${{ }}` syntax for variable substitution:

| Pattern | Example | Description |
|---------|---------|-------------|
| `inputs.<key>` | `${{ inputs.env }}` | Workflow input value |
| `steps.<name>.stdout` | `${{ steps.build.stdout }}` | Step stdout output (within the same job) |
| `steps.<name>.exit_code` | `${{ steps.build.exit_code }}` | Step exit code |
| `steps.<name>.outputs.<key>` | `${{ steps.deploy.outputs.url }}` | Sub-workflow output (sub-workflow steps only) |
| `job.status` | `${{ job.status }}` | Status of the **current** job — useful in `finally` steps |
| `jobs.<name>.status` | `${{ jobs.test.status }}` | Status of another job (success/failure/skipped) |
| `jobs.<name>.steps.<step>.stdout` | `${{ jobs.build.steps.compile.stdout }}` | Cross-job step output |
| `env.<key>` | `${{ env.VERSION }}` | Environment variable |
| `workflow.name` | `${{ workflow.name }}` | Workflow name |
| `workflow.run_id` | `${{ workflow.run_id }}` | Current run ID |

## Error Handling

### Default: Stop on Failure

By default, a failed step stops the job. Subsequent steps are skipped. `finally` steps still run.

```yaml
# stop-on-fail-demo.yaml
name: stop-on-fail-demo
jobs:
  pipeline:
    steps:
      - name: step-a
        command: "false"             # exit 1

      - name: step-b
        command: "echo never runs"   # skipped
```

```bash
appm workflow add -f stop-on-fail-demo.yaml
appm workflow run stop-on-fail-demo -f
appm workflow detail -w stop-on-fail-demo <run_id>
appm workflow rm stop-on-fail-demo
```

### Continue on Error

Use `continue-on-error: true` to proceed after a failure:

```yaml
# continue-on-error-demo.yaml
name: continue-on-error-demo
jobs:
  pipeline:
    steps:
      - name: lint
        command: "false"
        continue-on-error: true       # failure won't stop the job

      - name: test
        command: "echo lint failed but I still run"
```

```bash
appm workflow add -f continue-on-error-demo.yaml
appm workflow run continue-on-error-demo -f
appm workflow rm continue-on-error-demo
```

### Retry

Retry a step on failure with `fixed` or `exponential` backoff:

```yaml
# retry-demo.yaml
name: retry-demo
jobs:
  flaky:
    steps:
      - name: deploy
        command: "false"               # always fails so we see all retries
        retry:
          max: 3
          backoff: exponential         # or: fixed
          interval: 2                  # seconds (base interval)
```

```bash
appm workflow add -f retry-demo.yaml
appm workflow run retry-demo -f
appm workflow rm retry-demo
```

### Finally

`finally` steps always run after job steps, regardless of success or failure. Use for cleanup.

```yaml
# finally-demo.yaml
name: finally-demo
jobs:
  deploy:
    steps:
      - name: do-work
        command: "false"

    finally:
      - name: cleanup
        command: "echo cleaning tmp files"
      - name: report
        command: "echo job ended with status ${{ job.status }}"
```

```bash
appm workflow add -f finally-demo.yaml
appm workflow run finally-demo -f
appm workflow rm finally-demo
```

## Inputs

Define parameters that users provide when triggering a run:

```yaml
# inputs-demo.yaml
name: inputs-demo
on:
  manual:
    inputs:
      environment:
        type: string
        required: true
        description: "Target environment"
      dry_run:
        type: string
        default: "false"
        description: "Dry run mode"

jobs:
  deploy:
    steps:
      - name: run
        command: "echo env=${{ inputs.environment }} dry_run=${{ inputs.dry_run }}"
```

```bash
appm workflow add -f inputs-demo.yaml

# Show declared inputs
appm workflow inputs inputs-demo

# Required input must be provided
appm workflow run inputs-demo -e environment=production -e dry_run=true -f

appm workflow rm inputs-demo
```

> Input keys must match `[A-Za-z_][A-Za-z0-9_]*` (env-var-safe).

## Concurrency Control

Prevent parallel runs of the same workflow:

```yaml
# concurrency-demo.yaml
name: concurrency-demo
on:
  manual:
    inputs:
      env:
        type: string
        default: "staging"

concurrency:
  group: "deploy-${{ inputs.env }}"
  cancel-in-progress: false           # true = cancel existing run instead of queuing

jobs:
  slow:
    steps:
      - name: work
        command: "echo working on ${{ inputs.env }} && sleep 5"
```

```bash
appm workflow add -f concurrency-demo.yaml

# First run blocks (5s sleep) — follow it in the background
appm workflow run concurrency-demo -e env=prod -f &
sleep 1   # let the first run claim the group slot
# Second run with same group key prints status=pending and queues
appm workflow run concurrency-demo -e env=prod

wait
# Inspect: the queued run started after the first one completed
appm workflow runs concurrency-demo
appm workflow rm concurrency-demo
```

Semantics:

- Same group key → only one active run at a time
- `cancel-in-progress: false` → new run queues behind active run
- `cancel-in-progress: true` → active run is cancelled, new run starts

## Remote Execution

Execute jobs on remote App Mesh nodes using label selectors.

By node label (configure labels on each daemon via `appm label -a -l role=test-server`):

```yaml
# remote-label-demo.yaml
name: remote-label-demo
jobs:
  test:
    node_label:
      role: "test-server"
    steps:
      - name: run-tests
        command: "echo running on $HOSTNAME"
```

By explicit host:

```yaml
# remote-host-demo.yaml
name: remote-host-demo
jobs:
  deploy:
    node_label:
      host: "prod-server-1:6059"
    steps:
      - name: deploy
        command: "echo deploying on $HOSTNAME"
```

```bash
appm workflow add -f remote-label-demo.yaml
appm workflow run remote-label-demo -f
appm workflow rm remote-label-demo
```

## Triggers

### Manual

The default — triggered by `appm workflow run`.

### App Event

Triggered when a registered App emits an event matching the condition.

```yaml
# trigger-on-event.yaml
name: trigger-on-event
on:
  app_event:
    app: "data-collector"            # an existing App you want to listen to
    events: [EXIT]
    condition: "exit_code == 0"

jobs:
  process:
    steps:
      - name: handle
        command: "echo data-collector finished cleanly"
```

```bash
appm workflow add -f trigger-on-event.yaml
# Whenever data-collector emits EXIT with exit_code 0, this workflow runs.
appm workflow runs trigger-on-event           # check accumulated runs
appm workflow rm trigger-on-event
```

> **Automatic triggers require an `execution_identity`.** An event-triggered run has no
> human caller, so it has no identity to run steps under. The engine never falls back to its
> own (privileged) identity — a workflow with `on.app_event` that does not set
> [`execution_identity`](#execution-identity) will **fail closed** at run time. Add one to
> enable automatic triggering.

### Schedule (External)

Cron scheduling is **not** built into the workflow engine. Use App Mesh's native cron support to drive runs:

```bash
# Run hello-world every day at 02:00
appm add -a cron-hello -c "appm workflow run hello-world" -Y -i "0 2 * * *"

# Or, drive on an interval (ISO 8601 duration)
appm add -a tick-hello -c "appm workflow run hello-world" -i PT5M

appm rm -a cron-hello
appm rm -a tick-hello
```

### Workflow Call

Allow the workflow to be invoked as a sub-workflow by another workflow (see [Sub-workflow Step](#sub-workflow-step)):

```yaml
on:
  workflow_call:
    inputs:
      target:
        type: string
        required: true
    outputs:
      deployed_url:
        value: "${{ jobs.deploy.steps.publish.stdout }}"
```

## Execution Identity

Every step runs under an App Mesh identity, and the daemon enforces that identity's RBAC
on everything the step does (running an App, sending a task, creating a command App). The
identity is resolved per run:

| Run | `execution_identity` set | Identity used |
|-----|--------------------------|---------------|
| Manual (`appm workflow run`) | no | the **triggering caller** |
| Manual | yes | the configured **execution_identity** |
| Automatic (`on.app_event`) | no | **none — run fails closed** |
| Automatic | yes | the configured **execution_identity** |

The engine's own (admin) credentials are **never** used to run steps — they serve only the
engine's control plane (registration scan, step-App cleanup). This closes the escalation
where any user who could register an event-triggered workflow would have its steps executed
with admin rights.

### Configuring an execution identity

Because the daemon cannot mint a token for an arbitrary user, the engine authenticates as a
real App Mesh user. An admin provisions the credentials as a secured env var on the engine
App — a JSON map of `username → password`:

```bash
appm add -a workflow -z 'APPMESH_EXEC_IDENTITIES={"svc-pipeline":"<password>"}'
```

Then a workflow references it:

```yaml
name: nightly-pipeline
execution_identity: svc-pipeline    # steps run as svc-pipeline
on:
  app_event:
    app: "data-collector"
    events: [EXIT]
jobs:
  process:
    steps:
      - name: handle
        command: "echo running as the service account"
```

At registration the caller may bind `execution_identity` only to **itself**, or — as a
workflow admin (`APPMESH_WORKFLOW_ADMINS`) — to any configured identity. Binding an identity
the engine has no credential for is rejected. Give the service account the **least privilege**
its steps need.

## Encrypted Environment Variables

Use `sec_env` for sensitive values. They are encrypted at rest by the daemon. `env` is plaintext; `sec_env` is encrypted. Both become plain env vars inside the spawned process. `sec_env` can be set at the workflow, job, or step level (inner level wins on conflict).

```yaml
# secrets-demo.yaml
name: secrets-demo

env:
  API_URL: "https://api.example.com"

sec_env:
  API_KEY: "my-secret-token"

jobs:
  call-api:
    steps:
      - name: request
        command: 'echo "calling $API_URL with key=${API_KEY:0:4}…"'
```

```bash
appm workflow add -f secrets-demo.yaml
appm workflow run secrets-demo -f
appm workflow rm secrets-demo
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `appm workflow add -f <file>` | Register a workflow from YAML (must contain `name:` and `jobs:`) |
| `appm workflow list` | List all registered workflows |
| `appm workflow get <name>` | Print a workflow's YAML |
| `appm workflow rm <name>` | Remove a workflow |
| `appm workflow run <name> [-e key=val] [-f]` | Trigger a run; `-f` follows output until terminal |
| `appm workflow runs <name>` | List run history |
| `appm workflow logs -w <name> <run_id>` | View the run's flow log |
| `appm workflow output -w <name> <run_id> -j <job> -s <step>` | View a step's stdout |
| `appm workflow detail -w <name> <run_id>` | Show run detail (per-job status, steps) |
| `appm workflow cancel -w <name> <run_id>` | Cancel a running workflow |
| `appm workflow rerun -w <name> <run_id>` | Re-run with the same inputs |
| `appm workflow inputs <name>` | Show input parameters defined by the workflow |

## Complete Example

A self-contained pipeline that exercises inputs, env, DAG, retry, continue-on-error, finally, and conditions — runnable as-is.

Save as `ci-cd.yaml`:

```yaml
name: ci-cd
owner: admin

on:
  manual:
    inputs:
      branch:
        type: string
        default: "main"
        description: "Git branch to build"
      environment:
        type: string
        required: true
        description: "Deploy target (staging/production)"

concurrency:
  group: "ci-cd-${{ inputs.environment }}"
  cancel-in-progress: false

env:
  PROJECT: "demo"

jobs:
  build:
    steps:
      - name: checkout
        command: "echo checking out branch ${{ inputs.branch }}"
        timeout: 30

      - name: compile
        command: "echo building $PROJECT && sleep 1 && echo v1.2.3"
        timeout: 60
        retry:
          max: 2
          backoff: fixed
          interval: 2

  test:
    needs: [build]
    steps:
      - name: unit-tests
        command: "echo unit tests passed"

      - name: lint
        command: "false"               # intentionally fails
        continue-on-error: true        # but the job continues

  deploy:
    needs: [test]
    if: "success()"
    steps:
      - name: deploy
        command: "echo deploying to ${{ inputs.environment }}"
        env:
          DEPLOY_ENV: "${{ inputs.environment }}"

      - name: health-check
        command: "echo health OK"
        retry:
          max: 3
          backoff: exponential
          interval: 1

    finally:
      - name: notify
        command: "echo final job status ${{ job.status }}"
```

```bash
# Register
appm workflow add -f ci-cd.yaml

# View declared inputs
appm workflow inputs ci-cd

# Run end-to-end and follow live (note the run_id printed)
appm workflow run ci-cd -e branch=release-v2 -e environment=staging -f

# After completion, inspect details
appm workflow runs ci-cd
appm workflow detail -w ci-cd <run_id>
appm workflow logs -w ci-cd <run_id>
appm workflow output -w ci-cd <run_id> -j deploy -s deploy

# Re-run with same inputs
appm workflow rerun -w ci-cd <run_id>

# Clean up
appm workflow rm ci-cd
```
