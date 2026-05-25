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
appc workflow add -f hello.yaml

# Trigger a run (note the run_id printed in the message)
appc workflow run hello-world

# List runs
appc workflow runs hello-world

# Trigger a new run and tail its log until terminal
appc workflow run hello-world -f

# Read the run's flow log
appc workflow logs -w hello-world <run_id>

# Read a step's stdout
appc workflow output -w hello-world <run_id> -j greet -s say-hello

# Clean up
appc workflow rm hello-world
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
appc workflow add -f command-demo.yaml
appc workflow run command-demo -f
appc workflow rm command-demo
```

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
appc ls | grep ping

appc workflow add -f app-step-demo.yaml
appc workflow run app-step-demo -f
appc workflow rm app-step-demo
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
appc workflow add -f message-demo.yaml
appc workflow run message-demo -f
appc workflow rm message-demo
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
appc workflow add -f deploy-service.yaml
appc workflow add -f release.yaml
appc workflow run release -f

appc workflow rm release
appc workflow rm deploy-service
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
appc workflow add -f dag-demo.yaml
appc workflow run dag-demo -f
appc workflow detail -w dag-demo <run_id>   # see per-job status
appc workflow rm dag-demo
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
      - name: deploy
        command: "false"                            # intentionally fails

      - name: rollback
        command: "echo rolling back"
        if: "steps.deploy.exit_code != 0"           # only on failure

  notify:
    needs: [deploy]
    if: "always()"                                  # runs even if deploy failed
    steps:
      - name: send-alert
        command: "echo deploy status was ${{ jobs.deploy.status }}"
```

```bash
appc workflow add -f conditions-demo.yaml
appc workflow run conditions-demo -f
appc workflow rm conditions-demo
```

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
appc workflow add -f stop-on-fail-demo.yaml
appc workflow run stop-on-fail-demo -f
appc workflow detail -w stop-on-fail-demo <run_id>
appc workflow rm stop-on-fail-demo
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
appc workflow add -f continue-on-error-demo.yaml
appc workflow run continue-on-error-demo -f
appc workflow rm continue-on-error-demo
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
appc workflow add -f retry-demo.yaml
appc workflow run retry-demo -f
appc workflow rm retry-demo
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
appc workflow add -f finally-demo.yaml
appc workflow run finally-demo -f
appc workflow rm finally-demo
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
appc workflow add -f inputs-demo.yaml

# Show declared inputs
appc workflow inputs inputs-demo

# Required input must be provided
appc workflow run inputs-demo -e environment=production -e dry_run=true -f

appc workflow rm inputs-demo
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
appc workflow add -f concurrency-demo.yaml

# First run blocks (5s sleep) — follow it in the background
appc workflow run concurrency-demo -e env=prod -f &
sleep 1   # let the first run claim the group slot
# Second run with same group key prints status=pending and queues
appc workflow run concurrency-demo -e env=prod

wait
# Inspect: the queued run started after the first one completed
appc workflow runs concurrency-demo
appc workflow rm concurrency-demo
```

Semantics:

- Same group key → only one active run at a time
- `cancel-in-progress: false` → new run queues behind active run
- `cancel-in-progress: true` → active run is cancelled, new run starts

## Remote Execution

Execute jobs on remote App Mesh nodes using label selectors.

By node label (configure labels on each daemon via `appc label add -l role=test-server`):

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
appc workflow add -f remote-label-demo.yaml
appc workflow run remote-label-demo -f
appc workflow rm remote-label-demo
```

## Triggers

### Manual

The default — triggered by `appc workflow run`.

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
appc workflow add -f trigger-on-event.yaml
# Whenever data-collector emits EXIT with exit_code 0, this workflow runs.
appc workflow runs trigger-on-event           # check accumulated runs
appc workflow rm trigger-on-event
```

### Schedule (External)

Cron scheduling is **not** built into the workflow engine. Use App Mesh's native cron support to drive runs:

```bash
# Run hello-world every day at 02:00
appc add -a cron-hello -c "appc workflow run hello-world" -Y "0 2 * * *"

# Or, drive on an interval (ISO 8601 duration)
appc add -a tick-hello -c "appc workflow run hello-world" -i PT5M

appc rm -n cron-hello
appc rm -n tick-hello
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
appc workflow add -f secrets-demo.yaml
appc workflow run secrets-demo -f
appc workflow rm secrets-demo
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `appc workflow add -f <file>` | Register a workflow from YAML (must contain `name:` and `jobs:`) |
| `appc workflow list` | List all registered workflows |
| `appc workflow get <name>` | Print a workflow's YAML |
| `appc workflow rm <name>` | Remove a workflow |
| `appc workflow run <name> [-e key=val] [-f]` | Trigger a run; `-f` follows output until terminal |
| `appc workflow runs <name>` | List run history |
| `appc workflow logs -w <name> <run_id>` | View the run's flow log |
| `appc workflow output -w <name> <run_id> -j <job> -s <step>` | View a step's stdout |
| `appc workflow detail -w <name> <run_id>` | Show run detail (per-job status, steps) |
| `appc workflow cancel -w <name> <run_id>` | Cancel a running workflow |
| `appc workflow rerun -w <name> <run_id>` | Re-run with the same inputs |
| `appc workflow inputs <name>` | Show input parameters defined by the workflow |

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
appc workflow add -f ci-cd.yaml

# View declared inputs
appc workflow inputs ci-cd

# Run end-to-end and follow live (note the run_id printed)
appc workflow run ci-cd -e branch=release-v2 -e environment=staging -f

# After completion, inspect details
appc workflow runs ci-cd
appc workflow detail -w ci-cd <run_id>
appc workflow logs -w ci-cd <run_id>
appc workflow output -w ci-cd <run_id> -j deploy -s deploy

# Re-run with same inputs
appc workflow rerun -w ci-cd <run_id>

# Clean up
appc workflow rm ci-cd
```
