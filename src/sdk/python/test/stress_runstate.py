#!/usr/bin/env python3
"""Concurrent soak/stress harness for the RunState / reconcile refactor.

Runs every e2e scenario CONCURRENTLY and CONTINUOUSLY for a fixed duration, each
scenario driven by several parallel workers, each worker looping over fresh,
uniquely-named apps. The aggregate load (many apps spawning/exiting/restarting/
being read at once) is what exposes concurrency regressions in the refactor:
the per-app reconcile serialization, RunState snapshots, the exit latch, and the
LogFileQueue lock.

Scenarios (see docs/adr/0007):
  restart   §2/§3 exit-driven restart
  remove    §6   REMOVE one-shot latch (retention > schedule interval)
  periodic  §5   periodic loop after simulate-hack removal
  toggle    §4   disable/enable reschedule (m_needsSchedule)
  read      §1/§8 concurrent status reads during rapid restart
  fault     chaos: disable/delete mid restart-loop; disable arm also re-enables and
                   requires a start (R3: disable racing the restart-arm must not strand)

Requires a RUNNING daemon. This is NOT a unittest; run it directly.

Usage:
    cd src/sdk/python/test
    python3 stress_runstate.py
    STRESS_DURATION_SEC=300 STRESS_CONCURRENCY=4 python3 stress_runstate.py
    STRESS_SCENARIOS=restart,remove python3 stress_runstate.py   # subset

Env:
    APPMESH_TEST_URL        daemon base url (default: SDK default https://127.0.0.1:6060)
    APPMESH_TEST_CRED       admin password (default: admin123)
    STRESS_DURATION_SEC     total run time (default: 60)
    STRESS_CONCURRENCY      parallel workers per scenario (default: 3)
    STRESS_RETENTION_SEC    retention for the remove scenario, must be > daemon tick (default: 6)
    STRESS_SCENARIOS        comma list to restrict scenarios (default: all)

Note: timing assertions scale by a load factor (worker count) — the daemon runs all timers on
one thread. Slow stragglers under load are expected; only a 'fail' (stranded) is a real bug.

Exit code: 0 if every iteration passed, 1 if any failed.
"""

import concurrent.futures
import os
import random
import sys
import threading
import time

current_directory = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(current_directory))

from appmesh import AppMeshClient, App

BASE_URL = os.environ.get("APPMESH_TEST_URL")
CRED = os.environ.get("APPMESH_TEST_CRED", "admin123")
DURATION = int(os.environ.get("STRESS_DURATION_SEC", "60"))
CONCURRENCY = int(os.environ.get("STRESS_CONCURRENCY", "3"))
RETENTION_SEC = int(os.environ.get("STRESS_RETENTION_SEC", "6"))
PREFIX = "stress_runstate_"

# Timing assertions scale by this (set in main from worker count): the daemon runs all timers
# on one thread, so multi-event timing (restart/periodic/remove) slows under load; structural
# assertions (toggle/fault/read) don't scale.
SLOW = 1.0


def new_client() -> AppMeshClient:
    c = AppMeshClient(base_url=BASE_URL) if BASE_URL else AppMeshClient()
    c.login("admin", CRED)
    return c


def poll(predicate, timeout: float, interval: float = 0.2) -> bool:
    deadline = time.time() + timeout
    v = predicate()
    while not v and time.time() < deadline:
        time.sleep(interval)
        v = predicate()
    return bool(v)


class Slow(Exception):
    """Met only within the grace window: slow under load, not stranded; reported, not failed."""


def progress(predicate, timeout: float, grace: float) -> str:
    """'ok' (in time), 'slow' (only in grace = progress, not a bug), 'stranded' (never)."""
    if poll(predicate, timeout):
        return "ok"
    if poll(predicate, grace):
        return "slow"
    return "stranded"


def starts(client, name) -> int:
    return int(client.get_app(name).starts or 0)


def pid(client, name) -> int:
    return int(client.get_app(name).pid or 0)


def app_exists(client, name) -> bool:
    return any(a.name == name for a in client.list_apps())


# status: 0=DISABLED 1=ENABLED 2=NOTAVAILABLE. Reads strand (ENABLED+pid=0+no next_start) vs
# slow (pid>0 or next_start armed) on failure.
def app_state(client, name) -> str:
    try:
        a = client.get_app(name)
        return (f"status={a.status} pid={a.pid} starts={a.starts} "
                f"next_start={a.next_start_time} health={a.health} err={a.last_error!r}")
    except Exception as ex:  # noqa: BLE001
        return f"<get_app failed: {ex}>"


# --- scenarios: each creates `name`, asserts, and is cleaned up by the driver ---

def _judge(client, name, kind, r):
    """Turn a progress() verdict into pass (return) / slow (raise Slow) / fail (raise)."""
    if r == "ok":
        return
    detail = f"{name}: {kind}; {app_state(client, name)}"
    if r == "slow":
        raise Slow(detail)  # recovered in grace -> forward progress, not a bug
    raise AssertionError(detail)  # never recovered -> stranded


def scenario_restart(client, name):
    client.add_app(App({"name": name, "command": "sh -c 'sleep 0.5; exit 0'",
                        "shell": True, "behavior": {"exit": "restart"}}))
    base = starts(client, name)
    r = progress(lambda: starts(client, name) >= base + 2, int(14 * SLOW), int(12 * SLOW))
    _judge(client, name, f"no restart on exit (base={base})", r)


def scenario_remove(client, name):
    client.add_app(App({"name": name, "command": "sh -c 'exit 0'", "shell": True,
                        "behavior": {"exit": "remove"}, "retention": str(RETENTION_SEC)}))
    if not app_exists(client, name):
        raise AssertionError(f"{name}: missing right after add")
    r = progress(lambda: not app_exists(client, name), RETENTION_SEC + int(24 * SLOW), int(12 * SLOW))
    _judge(client, name, f"REMOVE app not deleted (retention={RETENTION_SEC}s)", r)


def scenario_periodic(client, name):
    client.add_app(App({"name": name, "command": "echo tick", "shell": True,
                        "start_interval_seconds": "2"}))
    base = starts(client, name)
    # interval=2s -> 2 occurrences need >=4s ideal, plus scheduling latency under load.
    r = progress(lambda: starts(client, name) >= base + 2, int(16 * SLOW), int(12 * SLOW))
    _judge(client, name, f"periodic did not run repeatedly (base={base})", r)


def scenario_toggle(client, name):
    client.add_app(App({"name": name, "command": "sleep 1000"}))
    if not poll(lambda: pid(client, name) > 0, timeout=12):
        raise AssertionError(f"{name}: never started")
    client.disable_app(name)
    if not poll(lambda: pid(client, name) <= 0, timeout=12):
        raise AssertionError(f"{name}: still running after disable")
    client.enable_app(name)
    if not poll(lambda: pid(client, name) > 0, timeout=12):
        raise AssertionError(f"{name}: did not reschedule after enable")


def scenario_read(client, name):
    client.add_app(App({"name": name, "command": "sh -c 'sleep 0.3; exit 1'",
                        "shell": True, "behavior": {"exit": "restart"}}))
    poll(lambda: pid(client, name) > 0, timeout=10)
    end = time.time() + 3
    while time.time() < end:
        # Concurrent read during rapid restart: must not raise/return a torn snapshot
        # (RunState + LogFileQueue::size). None fields between runs are valid.
        client.get_app(name)


def scenario_fault(client, name):
    # Disable/delete an app mid restart-loop: races disable->cancelTimer / delete->destroy
    # against onTimerSpawn and the exit-driven driveLifecycle; must leave consistent state.
    client.add_app(App({"name": name, "command": "sh -c 'sleep 0.2; exit 1'",
                        "shell": True, "behavior": {"exit": "restart"}}))
    if not poll(lambda: pid(client, name) > 0, timeout=10):
        raise AssertionError(f"{name}: never started before fault injection")
    # land the fault at a varied point within the ~0.2-0.8s spawn/exit cycle
    time.sleep(random.uniform(0.0, 0.6))

    if random.random() < 0.5:
        # fault A: disable mid-restart -> must stop & stay stopped & survive; then re-enable
        # must bring it back (R3: disable racing the restart-arm must not strand it forever).
        client.disable_app(name)
        if not poll(lambda: pid(client, name) <= 0, timeout=12):
            raise AssertionError(f"{name}: restart loop did not stop after disable")
        if not app_exists(client, name):
            raise AssertionError(f"{name}: disabled app vanished")
        time.sleep(0.8)
        if pid(client, name) > 0:
            raise AssertionError(f"{name}: disabled app restarted (should stay stopped)")
        base = starts(client, name)
        client.enable_app(name)
        # check starts growth, not pid: the ~0.2s-per-run app makes pid>0 flaky.
        if not poll(lambda: starts(client, name) > base, timeout=15):
            raise AssertionError(f"{name}: stranded after disable-during-restart + enable (R3)")
    else:
        # fault B: delete a restarting app -> must be fully removed
        client.delete_app(name)
        if not poll(lambda: not app_exists(client, name), timeout=12):
            raise AssertionError(f"{name}: running app not removed after delete")


SCENARIOS = {
    "restart": scenario_restart,
    "remove": scenario_remove,
    "periodic": scenario_periodic,
    "toggle": scenario_toggle,
    "read": scenario_read,
    "fault": scenario_fault,
}

# thread-safe counters
_lock = threading.Lock()
_stats = {}  # scenario -> [passed, slow, failed]
_errors = []  # (scenario, message) for hard failures (strands)
_slows = []   # (scenario, message) for slow-but-recovered

_IDX = {"pass": 0, "slow": 1, "fail": 2}


def record(scn, outcome, msg=None):  # outcome: "pass" | "slow" | "fail"
    with _lock:
        _stats.setdefault(scn, [0, 0, 0])
        _stats[scn][_IDX[outcome]] += 1
        if outcome == "fail" and len(_errors) < 50:
            _errors.append((scn, msg))
        elif outcome == "slow" and len(_slows) < 20:
            _slows.append((scn, msg))


def _is_conn_error(ex) -> bool:
    s = str(ex)
    return any(k in s for k in ("Connection", "SSL", "HTTP request failed", "Max retries"))


def worker(scn, fn, widx, deadline):
    client = None
    it = 0
    while time.time() < deadline:
        if client is None:
            # Record connect failures (don't kill the thread) so an unreachable daemon
            # can't report a vacuous "0 failures".
            try:
                client = new_client()
            except Exception as ex:  # noqa: BLE001
                record(scn, "fail", f"connect failed: {ex}")
                time.sleep(1)
                continue
        it += 1
        name = f"{PREFIX}{scn}_{os.getpid()}_{widx}_{it}"
        try:
            fn(client, name)
            record(scn, "pass")
        except Slow as s:
            record(scn, "slow", str(s))  # forward progress under load, not a failure
        except Exception as ex:  # noqa: BLE001
            record(scn, "fail", str(ex))
            if _is_conn_error(ex):
                client = None  # connection lost (e.g. daemon restart): reconnect next iter
        finally:
            if client is not None:
                try:
                    client.delete_app(name)
                except Exception:
                    pass


def reporter(deadline):
    while time.time() < deadline:
        time.sleep(5)
        with _lock:
            # pass/slow/fail per scenario; fail is the only hard signal
            line = " ".join(f"{s}:{p}+{sl}~/{f}x" for s, (p, sl, f) in sorted(_stats.items()))
        remain = int(deadline - time.time())
        print(f"[{remain:>4}s left] pass+slow~/failx  {line}", flush=True)


def main():
    selected = os.environ.get("STRESS_SCENARIOS")
    names = [s.strip() for s in selected.split(",")] if selected else list(SCENARIOS)
    for n in names:
        if n not in SCENARIOS:
            print(f"unknown scenario: {n}; valid: {list(SCENARIOS)}", file=sys.stderr)
            return 2

    global SLOW, CONCURRENCY
    # Positional arg overrides concurrency, e.g. `stress_runstate.py 1` (avoids env-var typos).
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        CONCURRENCY = int(sys.argv[1])
    total_workers = CONCURRENCY * len(names)
    SLOW = min(4.0, max(1.0, total_workers / 8.0))  # scale timing assertions with timer-thread contention

    print(f"soak: {DURATION}s, {CONCURRENCY} workers x {len(names)} scenarios "
          f"({names}), retention={RETENTION_SEC}s, load_factor={SLOW:.2f}", flush=True)
    deadline = time.time() + DURATION
    tasks = [(scn, SCENARIOS[scn], w) for scn in names for w in range(CONCURRENCY)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks) + 1) as pool:
        pool.submit(reporter, deadline)
        futs = [pool.submit(worker, scn, fn, w, deadline) for scn, fn, w in tasks]
        concurrent.futures.wait(futs)

    # best-effort sweep of any leftovers
    try:
        sweeper = new_client()
        for a in sweeper.list_apps():
            if a.name.startswith(PREFIX):
                try:
                    sweeper.delete_app(a.name)
                except Exception:
                    pass
    except Exception:
        pass

    total_pass = sum(p for p, _, _ in _stats.values())
    total_slow = sum(sl for _, sl, _ in _stats.values())
    total_fail = sum(f for _, _, f in _stats.values())
    print("\n==== soak summary ====", flush=True)
    for s in sorted(_stats):
        p, sl, f = _stats[s]
        print(f"  {s:10s} pass={p:<5d} slow={sl:<4d} fail={f}", flush=True)
    if _slows:
        print("  sample slow (recovered under load — not a failure):", flush=True)
        for scn, msg in _slows[:6]:
            print(f"    [{scn}] {msg}", flush=True)
    if _errors:
        print("  sample FAILURES (stranded — investigate):", flush=True)
        for scn, msg in _errors[:10]:
            print(f"    [{scn}] {msg}", flush=True)

    # A run that completed zero iterations is NOT a pass — the daemon was unreachable.
    if total_pass + total_slow + total_fail == 0:
        print("  NO ITERATIONS RAN — daemon unreachable? (vacuous run, not a pass)", flush=True)
        return 2
    print(f"  TOTAL pass={total_pass} slow={total_slow} fail={total_fail}  "
          f"(slow = timer-thread backlog, expected under heavy concurrency; only fail is a bug)", flush=True)
    return 1 if total_fail else 0


if __name__ == "__main__":
    sys.exit(main())
