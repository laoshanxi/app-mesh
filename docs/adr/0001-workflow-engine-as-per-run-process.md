# ADR 0001 — Workflow Engine as Single Go Binary with Goroutines

## Status

Accepted — this is the implemented design.

ADR 0004 proposes an alternative Run-based model; that redesign is not
implemented, so the engine runs as described here.

## Context

App Mesh needs a workflow/pipeline orchestration capability. The orchestration engine must coordinate multi-step, multi-node job execution using App Mesh's existing APIs.

Three architectural options were considered:

1. **Per-run process (Python)**: Each workflow execution spawns a separate Python process. A separate `wf-engine` process handles events. Simple isolation but high overhead (~30-50MB and ~300ms startup per run) and requires Python runtime on target machines.

2. **Per-run process (Go)**: Same model but with Go binaries. Lower overhead (~5-10MB, ~20ms startup) and zero-dependency deployment, but still spawns OS processes per run.

3. **Single Go process with goroutines**: One long-running `wf-engine serve` process handles event subscriptions and executes each workflow run as a goroutine (~8KB, ~1μs startup). A standalone `wf-engine run` mode exists for CLI ad-hoc execution and testing.

## Decision

**Option 3 — single Go binary, two modes:**

- `wf-engine serve` — long-running mode. Scans for workflow definitions, subscribes to App events, and runs triggered workflows as goroutines within the same process. Registered as an App Mesh App (`behavior.exit: restart`).
- `wf-engine run <workflow.yaml>` — single-shot mode. Executes one workflow and exits. Used by `appm workflow run` for CLI-triggered ad-hoc runs and for testing.

Both modes share the same Go packages (parser, expression, DAG, executor, engine). The `serve` mode additionally includes the trigger subsystem (registry, event listener, concurrency manager).

## Consequences

### Benefits

- **Single binary, zero dependencies**: `go build` produces one `wf-engine` binary. No Python runtime, no pip packages, no virtualenv.
- **Goroutine efficiency**: 100 concurrent workflow runs consume ~1MB total (vs ~3GB with per-process model). Startup is ~1μs per goroutine (vs ~300ms per Python process).
- **Shared TCP connection**: all workflow runs share one persistent TCP connection to the daemon, enabling event subscriptions (EXIT/START) for workflow triggers and reducing connection overhead.
- **One process to manage**: App Mesh registers and monitors a single `wf-engine` App, not N+1 processes.
- **Fault isolation via `recover()`**: each goroutine is wrapped in `defer recover()` to contain panics without crashing other runs.
- **Consistent with Agent**: the Go Agent (`agent`) follows the same single-binary-with-goroutines pattern, keeping architectural consistency.

### Trade-offs

- **Reduced isolation**: a goroutine-level panic is caught by `recover()` but a process-level crash (e.g., OOM) kills all active runs. Acceptable because the engine's work is API calls (low memory), not heavy computation.
- **Per-run log files**: each run writes its flow log to `{workdir}/runs/{run-id}/flow.log` and archives step stdout to `{workdir}/runs/{run-id}/steps/`. Process stdout is used only for operational tee. Run retention (default 10) controls cleanup.
- **No per-run resource limits**: App Mesh cgroup limits apply to the single engine process, not individual runs. Individual step commands still get their own App Mesh process with limits.
