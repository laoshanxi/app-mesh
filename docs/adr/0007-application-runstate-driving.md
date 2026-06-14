# ADR 0007 — Application RunState & Start-Driving Model

## Status

Accepted — implemented. Supersedes the prior poll-driven driving described under "Context".
(Consolidates the former docs/source/AppStartDriving.md analysis and RunStateRefactor.md
change summary, which were internal design notes mislocated in the published docs tree.)

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

- **Consolidate run-state** into one `RunState` struct under one mutex (`m_runMutex`), accessed
  via `updateRunState()` / `loadRunState()` consistent snapshots.
- **Single convergence point** `driveLifecycle()` under `m_lifecycleMutex`, lock order
  `m_lifecycleMutex → m_process → m_runMutex`. Steps: enforce-availability → schedule →
  refresh(health/buffer) → consume-exit→handleError → **spawn-if-due**.
- **One-shot exit latch** (`RunState::exitPending`, test-and-clear) replaces the polled
  `hasExited` and its `+1s`; `handleError` runs exactly once per genuine exit (fixes REMOVE).
- **Two spawn paths, each on its natural thread — never the shared timer thread:**
  - *On-demand `run`* (REST sync/async): `runApp` forks **immediately**, inline on the REST
    worker thread, so the client gets the process/uuid right away.
  - *Scheduled* (first start, restart, periodic, cron): `scheduleSpawnAt` only **records** the due
    time in `RunState.nextLaunch` (no timer); the scheduler tick's `spawnIfDue()` forks when
    `now ≥ nextLaunch`, on the scheduler thread. No spawn timer, no generation token, no
    dedicated executor — the tick is the sole scheduled-spawn driver, serialized by
    `m_lifecycleMutex`.
- **Explicit schedule intent** `m_needsSchedule`, decoupled from the display-only next-launch.
- **Natural-vs-deliberate exit:** `AppProcess::m_terminating` + `naturalExit`; a `reporter`
  identity check latches only the *current* process's natural exit (a buffer process exit
  cannot mint a restart).
- **Crash-loop backoff** (k8s style): exponential 1→300s, reset after a 60s stable run;
  bypassed for periodic/cron.
- **Recovered (attached) processes** (`m_recovered`): not our children, so `refresh()` polls
  and synthesizes their exit.
- **Exit is record-only on the timer thread; the tick drives restart + spawn.** The natural-exit
  upcall (`onTimerAppExit`, on the ACE timer thread) only sets the latch + dispatches the event.
  `driveLifecycle` (lock-holding, multi-step) and the actual fork run on the scheduler-tick
  thread, keeping fork/exec off the shared timer thread. The inline-immediate exit path remains
  behind `onExitUpdate(triggerLifecycle=…)`, disabled.
- **`m_process` stays a recursive mutex** (required): `terminate()` under that lock re-enters
  via `onExitUpdate() → m_process.get()`; a plain mutex self-deadlocks.

## Consequences

- Correctness: REMOVE-with-retention fixed; exactly-once exit handling; no torn reads;
  `LogFileQueue` self-thread-safe; no spurious restart from buffer exits.
- Scheduled-spawn/restart timing is tick-granular: ≤ `ScheduleIntervalSeconds` (default 1s)
  jitter. Negligible for restart/periodic/cron (second/minute-grained); on-demand `run` is
  unaffected (forks immediately on the REST thread).
- **No fork/exec runs on the shared ACE timer-dispatch thread**, so a fork backlog cannot stall
  delayKill / suicide(REMOVE) / stdout-coalesce / health timers. Forks stay serialized by
  construction: on-demand on REST worker threads + scheduled on the single tick thread.
  (Multithreaded fork is acceptable here — glibc `pthread_atfork` covers the pre-existing
  REST/tick fork concurrency; a bare fork→exec from a threaded process is safe.)
- A dedicated single-thread spawn *executor* was prototyped and dropped: tick-poll achieves the
  same "fork off the timer thread" with zero new threads, so the executor was needless complexity.
- Verified by `src/sdk/python/test/{test_runstate_e2e,stress_runstate}.py` and
  `test/application` C++ unit tests.

### Deferred

- Subscribe **replay-from-position** for STDOUT (today late subscribers get no replay; events
  are live-tail only — short-lived apps need atomic `add_app(subscribe_events=…)`).
- If sub-second restart latency is ever required, signal the scheduler thread (condition
  variable) instead of waiting for the next tick.
- `Application` god-class split; `FromJson`/`AsJson` single-source symmetry; hoist recovery
  `attach()` out of `FromJson`; `AppTimerCron` `offsetSeconds==1` patch (test-first).
