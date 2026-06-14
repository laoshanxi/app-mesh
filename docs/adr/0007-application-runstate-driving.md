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
  refresh(health/buffer) → consume-exit → handleError.
- **One-shot exit latch** (`RunState::exitPending`, test-and-clear) replaces the polled
  `hasExited` and its `+1s`; `handleError` runs exactly once per genuine exit (fixes REMOVE).
- **Generation token** (`m_spawnGen`): each arm/cancel bumps it and binds it into
  `onTimerSpawn(gen)`, which runs only if current — removes the timer-id race and any
  `m_lifecycleMutex` coupling. `m_nextStartTimerId` kept for best-effort cancel only.
- **Explicit schedule intent** `m_needsSchedule`, decoupled from the display-only next-launch.
- **Natural-vs-deliberate exit:** `AppProcess::m_terminating` + `naturalExit`; a `reporter`
  identity check latches only the *current* process's natural exit (a buffer process exit
  cannot mint a restart).
- **Crash-loop backoff** (k8s style): exponential 1→300s, reset after a 60s stable run;
  bypassed for periodic/cron.
- **Recovered (attached) processes** (`m_recovered`): not our children, so `refresh()` polls
  and synthesizes their exit.
- **Restart is tick-driven.** The exit upcall records the latch only; the periodic scheduler
  thread (not the single ACE timer-dispatch thread) drives the restart. `driveLifecycle` is
  lock-holding and multi-step and must not run on the timer thread. The inline-immediate path
  is retained behind `onExitUpdate(triggerLifecycle=…)` but disabled.
- **`m_process` stays a recursive mutex** (required): `terminate()` under that lock re-enters
  via `onExitUpdate() → m_process.get()`; a plain mutex self-deadlocks.

## Consequences

- Correctness: REMOVE-with-retention fixed; exactly-once exit handling; no torn reads;
  `LogFileQueue` self-thread-safe; no spurious restart from buffer exits.
- Restart latency ≤ one `ScheduleInterval` (tick-driven) — acceptable; crash cases are
  backoff-dominated anyway.
- The single ACE timer-dispatch thread runs `onTimerSpawn`'s fork/exec, so under extreme fan-out
  (e.g. many apps crash-looping at high frequency) spawn latency is bottlenecked there — verified
  as *slow, not stranded* (the armed spawn always eventually fires). This is a synthetic-load
  ceiling, not a real-workload concern. A dedicated single-thread spawn executor was evaluated and
  **rejected**: it would only isolate other timers, not raise spawn throughput (fork must stay
  serialized on one thread — multithreaded fork is unsafe), so it adds risk without fixing the
  measured number.
- Verified by `src/sdk/python/test/{test_runstate_e2e,stress_runstate}.py` and
  `test/application` C++ unit tests.

### Deferred

- Subscribe **replay-from-position** for STDOUT (today late subscribers get no replay; events
  are live-tail only — short-lived apps need atomic `add_app(subscribe_events=…)`).
- **CV-wake** the scheduler thread to restore *immediate* restart without using the timer thread.
- `Application` god-class split; `FromJson`/`AsJson` single-source symmetry; hoist recovery
  `attach()` out of `FromJson`; `AppTimerCron` `offsetSeconds==1` patch (test-first).
