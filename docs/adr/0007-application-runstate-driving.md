# ADR 0007 — Application RunState & Start-Driving Model

## Status

Accepted — implemented. Supersedes the prior poll-driven driving described under "Context".
(Consolidates the former docs/source/AppStartDriving.md analysis and RunStateRefactor.md
change summary, which were internal design notes mislocated in the published docs tree.)
User-visible time ranges, recurring patterns, restart actions, recovery, and Docker scheduling
semantics are specified separately in [ADR 0008](0008-application-scheduling-semantics.md).

## Context

The daemon drives each application's lifecycle: spawn, restart-on-exit, scheduled (periodic/
cron) runs, daily-time-window enforcement, and per-exit-code behavior
(STANDBY / RESTART / KEEPALIVE / REMOVE), plus on-demand `run` (sync/async).

The original design had problems:

- **Torn run-state reads.** Exit detection read several independent atomics
  (`m_pid`/`m_return`/`m_procStartTime`/`m_procExitTime` + the process) — a non-atomic
  composite that could tear across runs.
- **Polled exit detection (`hasExited`)** in the periodic tick, papered over by a magic `+1s`
  buffer for the start-vs-exit write ordering. Because it re-fired every tick, a `REMOVE` app
  with `retention` greater than the tick interval re-armed its self-delete timer forever and
  **was never removed** (headline bug).
- **Overloaded sentinel:** `m_nextLaunchTime == nullptr` meant both "never scheduled" and
  "force-stopped, reschedule me"; periodic first-run *fabricated* a fake previous run.
- **Hand-rolled `ACE_Event` handshake** guarded a register-fires-before-store timer-id race.
- **`LogFileQueue`** had no lock; REST reads raced the spawn writer.

## Decision

- **Consolidate run-state** into private `Runtime::Run`, protected by `Runtime::runMutex` and
  accessed as consistent snapshots. The header exposes neither lifecycle state nor its locks.
- **Single convergence point** `maintainRuntime(now)`: maintain process exit state → stop an
  invalid run → update health → under `Runtime::lifecycleMutex`, plan if needed → consume one
  restart evaluation → consume a due start → call `startRun` after releasing the decision lock.
- **One-shot exit latch** (`Run::restartEvaluationPending`, test-and-clear) replaces the polled
  `hasExited` and its `+1s`; `applyExitPolicy` runs exactly once per genuine natural exit (fixes REMOVE).
- **Two spawn paths, each on its natural thread — never the shared timer thread:**
  - *On-demand `run`* (REST sync/async): `startRun` forks **immediately**, inline on the REST
    worker thread, so the client gets the process/uuid right away.
  - *Scheduled* (first start, restart, periodic, cron): `scheduleStartAt` only **records** the due
    time as `Run::nextLaunch + Armed` (no spawn timer); the scheduler tick's `consumeScheduledStart()`
    revalidates the complete time window and process phase before `startRun`.
- **Explicit schedule intent** `Dormant / NeedsPlan / Armed`, coupled with `nextLaunch` in the
  same run snapshot. A schedule with no future occurrence becomes `Dormant` instead of retrying
  every tick.
- **Natural-vs-deliberate exit:** `AppProcess::Lifecycle::terminating` + `naturalExit`; run-id
  identity allows only the current run's natural exit to request policy evaluation.
- **Recurring retention handoff:** each due interval/cron occurrence becomes the new current run;
  the replaced run is terminated immediately when `retention == 0`, otherwise its own delayed
  termination keeps it alive for the configured buffer without letting its exit drive current policy.
- **Crash-loop backoff** (k8s style): exponential 1→300s, reset after a 60s stable run;
  bypassed for periodic/cron.
- **Recovered processes and attached Docker containers:** they are not reactor-managed children, so
  `maintainRuntime(now)` polls PID identity and synthesizes their exit when necessary. Docker image
  pulls are native children and retain their exact `ProcessManager` exit callback.
- **Exit is claimed in the ProcessManager upcall and finalized once outside its mutex.** Finalization
  drains stdout, records the run result and dispatches callbacks; the tick later evaluates policy.
- **`m_process` uses a non-recursive mutex.** Replacement moves the previous shared pointer out;
  terminate, backend calls, event dispatch and process start never execute while holding that gate.
- **Docker CLI cleanup is non-blocking.** Termination launches a separate `AppProcess` with a short
  timeout and returns; that helper's timer retains its ownership until exit or timeout, so no new
  worker thread or wait on `TimerManager` is required.

## Consequences

- Correctness: REMOVE-with-retention fixed; exactly-once exit handling; no torn reads;
  `LogFileQueue` self-thread-safe; disable/enable invalidates stale start and exit decisions.
- Scheduled-spawn/restart timing is tick-granular: ≤ `ScheduleIntervalSeconds` (default 2s)
  jitter. Negligible for restart/periodic/cron (second/minute-grained); on-demand `run` is
  unaffected (forks immediately on the REST thread).
- **No fork/exec runs on the shared ACE timer-dispatch thread**, so a fork backlog cannot stall
  scheduled termination / removal / stdout-coalesce / health timers. Forks stay serialized by
  construction: on-demand on REST worker threads + scheduled on the single tick thread.
  (Multithreaded fork is acceptable here — glibc `pthread_atfork` covers the pre-existing
  REST/tick fork concurrency; a bare fork→exec from a threaded process is safe.)
- A dedicated single-thread spawn *executor* was prototyped and dropped: tick-poll achieves the
  same "fork off the timer thread" with zero new threads, so the executor was needless complexity.
- Runtime verification is provided by `src/sdk/python/test/test_runstate_e2e.py`,
  `src/sdk/python/test/tools/stress_runstate.py`, and
  `src/sdk/python/test/tools/verify_process_lifecycle.py`; C++ unit execution is optional and
  separate from this design.

### Deferred

- Subscribe **replay-from-position** for STDOUT (today late subscribers get no replay; events
  are live-tail only — short-lived apps need atomic `add_app(subscribe_events=…)`).
- If sub-second restart latency is ever required, signal the scheduler thread (condition
  variable) instead of waiting for the next tick.
- `Application` god-class split; `FromJson`/`AsJson` single-source symmetry; hoist recovery
  `attach()` out of `FromJson`; `AppTimerCron` `offsetSeconds==1` patch (test-first).
