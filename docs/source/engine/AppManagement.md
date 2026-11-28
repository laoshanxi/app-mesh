# Application Management

This document is the single specification of the managed application model: registration, lifecycle events, scheduling, exit behavior, termination, and recovery. The REST field list lives in [REST API](../interfaces/RESTAPI.md); Docker wiring lives in [Docker Applications](Docker.md); recovery semantics are part of this document.

## 1. Application model

| Kind | Scheduler-managed | Persisted | Start path |
| --- | --- | --- | --- |
| `Managed` | Yes | Yes (`work/apps/<name>.yaml`) | Planned and started by the scheduler |
| `SystemAgent` | Yes | No | Same scheduler path, with agent-specific restart setup |
| `OneShot` | No | No | The `run` API starts it immediately (see [Task Run](TaskRun.md)) |

- An application name matches `[A-Za-z0-9_-]` and is at most 128 characters.
- An application stores `owner_principal_id`. REST input cannot create `system: true` applications or choose an arbitrary process user (see [OS execution user](../security/OSUser.md)).
- `permission` is share bits `<other><group>` (1 deny, 2 read, 3 write; `0` = everyone full access). When omitted, the application is registered owner-only (`11`).
- Re-registering an application with the same name replaces the definition and keeps the output files.

## 2. Lifecycle events

Every accepted run publishes events in the fixed order `START → STDOUT* → EXIT`, including processes that exit immediately after start.

| Event | Payload |
| --- | --- |
| `PROCESS_START` | `pid`, `process_uuid` |
| `STDOUT_OUTPUT` | `output`, `position`, `finished` |
| `PROCESS_EXIT` | `exit_code`, `pid`, `last_error` |

- Output is written to `work/runtime/stdout/appmesh.<name>.out`. `stdout_backup_count` sets how many earlier outputs are kept (default `0`: each start replaces the previous run's output). Docker applications fetch output from the container instead of rotated files.
- The SDK observation surface is: `pid` (running), `status` (enabled), `starts` (accepted starts), `last_error` (start failure reason), `last_exit_time` and `return_code` (exit committed). The daemon does not expose internal scheduling or finalization state.
- See [Event Subscription](../interfaces/EventSubscription.md) for the push channels and the message format.

## 3. Start acceptance and failure

A start either is accepted or is rejected as normal control flow. A rejected start has no process and therefore no `PROCESS_EXIT` event.

An accepted start:

- publishes the PID and the run before it is observable;
- increments `starts` only after acceptance;
- emits `PROCESS_START`;
- for interval/cron applications, pre-arms the next occurrence.

A rejected start records `last_error`, completes any waiting request, and replans:

| Kind | Replan after rejection |
| --- | --- |
| Managed continuous | Through the timer, after crash-loop backoff |
| Managed interval/cron | From one second later; the timer then selects the next legal occurrence |
| On-demand `run` | No replan; the API caller receives the start error |

Retries always pass through the scheduler, so they cannot bypass `start_time`, `end_time`, or the daily window.

## 4. Scheduling

### 4.1 Time model

The allowed time is the intersection of the absolute range and the daily window:

```text
allowed(t) = enabled
          && start_time <= t < end_time
          && daily_window_contains(UTC_time_of_day(t))
```

- `start_time` / `end_time` are Unix epoch seconds. The absolute range is half-open: `start_time` is a valid start instant, `end_time` is not. An omitted `end_time` means no upper bound.
- `daily_limitation.daily_start` / `daily_end` are UTC seconds since midnight. Both endpoints are required together.

| Relationship | Allowed UTC time of day |
| --- | --- |
| `daily_start < daily_end` | `[daily_start, daily_end)` |
| `daily_start > daily_end` | `[daily_start, 24h) ∪ [0, daily_end)` (crosses UTC midnight) |
| `daily_start == daily_end` | Full day |

The server normalizes both endpoints modulo 86,400, so clients may send UTC seconds-of-day or epoch seconds. The daily rule carries no calendar-date meaning; time-zone conversion belongs at the client boundary.

### 4.2 Launch patterns

| Pattern | Selector | Next occurrence |
| --- | --- | --- |
| Continuous | neither field | The earliest allowed time; restart only through exit behavior |
| Interval | `interval` (integer seconds, numeric text, or ISO-8601 duration) | Fixed grid anchored at the configured `start_time`; a late launch does not move the grid, so lateness does not accumulate as drift. A recurring app without `start_time` gets an anchor about one second after registration |
| Cron | `cron_schedule` (six-field expression with seconds, validated at registration) | The expression's next occurrence |

A non-positive parsed interval logs a warning and falls back to seven days. An application whose `end_time` is in the past is rejected at registration.

For compatibility, the daily window is an adjustment rule: the timer first computes an interval or cron occurrence and then advances it to the next daily opening when necessary. The opening itself can be the launch time even when it is not an exact grid or cron occurrence.

### 4.3 Dispatch precision

The scheduler tick (`ScheduleIntervalSeconds`, 1–100 s, default 2 s) consumes due launches. `next_start_time` is a planned time, not a guarantee of exact dispatch. On-demand `run` is unaffected: it starts immediately on its request path.

Early registration plans `start_time` or the next daily opening without waiting for the first periodic pass. A launch is revalidated against the complete time window at consumption: no start happens after `end_time` or inside a closed daily window.

### 4.4 Running-process enforcement

Scheduling governs continuation as well as starting:

- reaching `end_time` stops the run and prevents another start;
- reaching `daily_end` stops the run, keeps the definition, and plans the next opening when one exists before `end_time`;
- disabling stops the current run and cancels the armed launch;
- enabling recomputes the next legal occurrence;
- deletion makes the application unavailable.

## 5. Exit behavior

Only a genuine natural exit of the current run drives exit behavior. Stops caused by disable, range closure, replacement, timeout, or deletion are deliberate exits and never trigger restart policy.

`behavior.exit` selects the default action; `behavior.exit_code_actions` overrides it per exit code.

| Action | Result |
| --- | --- |
| `standby` (default) | No exit-driven plan. Interval/cron keeps the occurrence already armed at start |
| `restart` | Plan the next occurrence through the configured pattern and time ranges |
| `keepalive` | Arm `now + backoff` directly, bypassing the pattern; time ranges still apply |
| `remove` | Cancel any armed recurring start, then delete the application after `stop_grace_period` |

Crash-loop backoff applies only to continuous applications: consecutive runs shorter than 60 seconds delay the next retry by 1, 2, 4, … seconds, capped at 300 seconds; a run of at least 60 seconds resets the backoff.

## 6. Recurring replacement and retention

A due interval or cron occurrence replaces the current run:

- the new run becomes the only current run;
- the replaced run is terminated immediately when `stop_grace_period` is `0`, otherwise it runs for the grace period as the single buffered run;
- each application keeps at most one buffered run; a later replacement stops the preceding buffer first;
- the buffered run's exit never drives the current run's policy.

Explicit disable or deletion bypasses `stop_grace_period` and stops any buffered run immediately.

## 7. Termination

A deliberate stop — terminate, timeout, disable, or delete — terminates the process group and synthesizes exit code `9`. Native and Docker backends share the same convergence: status, PID, and exit time settle once, and a natural exit racing the stop is deduplicated. Docker stopping sends SIGTERM first (the container's `stop_grace_period`, default 10 s) and SIGKILL after the grace; the container is then removed deterministically.

## 8. Recovery

- Application definitions persist under `work/apps/` and reload at daemon start.
- A recovered process the daemon re-attaches to is not a daemon child: the main loop polls its PID identity and reports disappearance. A recovered non-child has no reliable wait status, so its compatible exit code is `0`.
- Attaching to a live recovered process suppresses planning (no duplicate start); attaching to a dead or reused PID requests a new plan.
- Docker running containers are observed by host-PID identity plus the agent's Docker-events subscription. App Mesh is the sole restart controller: containers are created with `AutoRemove=false` and `RestartPolicy=no`.
- A Docker image pull is its own accepted intermediate run: it does not block the start request, and a successful pull with no container yet directly arms the container start.
- On daemon start, labeled containers whose application no longer exists are logged as orphans; set `APPMESH_DOCKER_ORPHAN_SWEEP=delete` in the daemon environment to remove them.

## 9. Related

- [Task Run](TaskRun.md) — on-demand `run` / `syncrun` and the task RPC
- [Docker Applications](Docker.md) — container wiring, images, health, logs
- [Work Directory Specification](../deploy/WorkDir.md) — where applications run and file life time
- [REST API](../interfaces/RESTAPI.md) — endpoints and field reference
