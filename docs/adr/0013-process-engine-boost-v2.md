# ADR 0013: Run the process engine on Boost.Process V2

- Status: Accepted
- Date: 2026-10-09 (implemented 2026-10-09 .. 2026-10-10 on branch `drogon`)
- Related: ADR 0012 removes the ACE transport; this removes the remaining ACE process engine

## Context

The process layer ran on `ACE_Process_Manager` and two reactors: a dedicated process reactor for SIGCHLD, kept separate from the main TP_Reactor to avoid a notification-queue deadlock, and the main reactor for the stdout pumps. The upcall model forced defensive machinery:

- a recursive PM lock held across the fork and kill paths;
- the reference-counted `ExitAdapter` bridge;
- a zero-delay timer hop with a `Finalizing` lifecycle phase, existing only for the hop window;
- `CgroupStartBarrier`, a fork/exec gate so the parent could attach the cgroup right after fork;
- `AttachProcess` and a four-step terminate reap dance;
- a `StdoutPump` with three mutexes and reference counting.

## Decision

Move spawn, exit detection, stdout pumping, and termination onto Boost.Process V2 on one single-threaded asio service, `ProcessService` (io_context + work guard + one thread). Observable behavior — REST API, events, exit codes, stdout positions and ordering — stays the same.

- **Spawn** uses the vfork launcher with `process_start_dir`, `bind_fd` stdio, a full environment merge, and a child-side identity initializer: `setpgid`, the cgroup `procs` join, then `setgid`/`setuid`. The child runs no asio code (a plain fork could deadlock on a service mutex held across it), and an exec failure rejects the start and reaps the child.
- **Exit** arrives through `async_wait`; finalization is one posted task, so exit reports from the wait, from termination, and from attach polling share a single thread. The `Finalizing` phase and the timer hop are gone.
- **Termination** is a process-group SIGKILL with a direct-kill fallback; the pending `async_wait` reaps. `ProcessManager`, `AttachProcess`, and `CgroupStartBarrier` are deleted: the cgroup group is prepared parent-side before the fork, and the child joins the leaf at exec.
- **Stdout** is a `stream_descriptor` read chain plus a 200 ms coalesce timer on the io thread: zero locks and zero atomics. A pipe-pumped stream skips the legacy size-check timer.
- `wait()` takes `std::chrono`; the application layer, the health checks, and the docker backends adapt.

## Consequences

- The two reactor threads are gone; the engine is one service thread plus the timer thread. Four mutexes, one lifecycle phase, and ~600 lines of machinery are removed.
- Exit-code semantics match the ACE adapter: `evaluate_exit_code` reports a signal as its number, so a kill reports 9.
- Boost is pinned at 1.86 for BPv2, shared with the C++17 floor decision in ADR 0012.
- On macOS (no pidfd) each running child may cost one waiter thread; confirmed acceptable in verification.

## Amendment (2026-10-11)

Finalization is now two stages: engine cleanup (pump teardown, resources) on
the `ProcessService` io thread; application callbacks (`recordProcessExit`,
`completeRun`) on a callback thread in `ProcessService`, since they may block
on docker backends and must not stall the engine. Ownerless helpers (docker
CLI, cleanup, health checks) have no callbacks and finalize on the io thread —
their waiters may be the callback thread itself. `dispatchSync` returns false
instead of blocking forever when shutdown drops its task.
