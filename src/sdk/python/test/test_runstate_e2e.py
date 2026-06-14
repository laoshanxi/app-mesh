"""End-to-end tests for the RunState driving refactor (see docs/adr/0007).

Exercise a RUNNING daemon via the Python SDK:
  test_01 restart-on-exit      test_02 REMOVE deletes (retention > tick: the headline bug)
  test_03 periodic runs        test_04 disable/enable reschedules
  test_05 concurrent reads      test_06 run sync/async
  test_07 crash-loop backoff (bounded restarts)   test_08 spawn-failure retries then recovers
  test_09 attach adopts a live pid & detects its exit (APPMESH_TEST_ATTACH=1, same-host)
  test_10 buffer overlap stays stable
  test_11 agent PSK restart doesn't deadlock the timer thread (APPMESH_TEST_AGENT=1)

Prereqs: a daemon at https://127.0.0.1:6060 (APPMESH_TEST_URL), admin/admin123
(APPMESH_TEST_CRED). test_02 uses retention > the daemon's ScheduleInterval.

Usage:
    cd src/sdk/python/test
    python3 -m unittest --verbose test_runstate_e2e
    APPMESH_TEST_RETENTION_SEC=8 python3 -m unittest test_runstate_e2e.TestRunStateE2E.test_02_remove_behavior_deletes_app
"""

import concurrent.futures
import os
import signal
import subprocess
import sys
import time
import unittest

current_directory = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(current_directory))

from appmesh import AppMeshClient, App

DEFAULT_CRED = os.environ.get("APPMESH_TEST_CRED", "admin123")
BASE_URL = os.environ.get("APPMESH_TEST_URL")  # None -> SDK default (https://127.0.0.1:6060)
# retention used by test_02; MUST exceed the daemon ScheduleIntervalSeconds (default 2s)
# to reproduce the old "REMOVE re-arms every tick and never fires" bug.
RETENTION_SEC = int(os.environ.get("APPMESH_TEST_RETENTION_SEC", "8"))

NAME_PREFIX = "e2e_runstate_"


def _poll(predicate, timeout: float, interval: float = 0.2):
    """Poll predicate() until truthy or timeout; return the last value."""
    deadline = time.time() + timeout
    value = predicate()
    while not value and time.time() < deadline:
        time.sleep(interval)
        value = predicate()
    return value


class TestRunStateE2E(unittest.TestCase):
    def setUp(self):
        self.client = AppMeshClient(base_url=BASE_URL) if BASE_URL else AppMeshClient()
        self.client.login("admin", DEFAULT_CRED)
        self._created = set()

    def tearDown(self):
        for name in list(self._created):
            try:
                self.client.delete_app(name)
            except Exception:
                pass

    # ----- helpers -------------------------------------------------------
    def _name(self, suffix: str) -> str:
        return f"{NAME_PREFIX}{suffix}_{os.getpid()}"

    def _add(self, data: dict) -> App:
        app = self.client.add_app(App(data))
        self._created.add(data["name"])
        return app

    def _app_names(self):
        return {a.name for a in self.client.list_apps()}

    def _starts(self, name: str) -> int:
        return int(self.client.get_app(name).starts or 0)

    def _pid(self, name: str) -> int:
        return int(self.client.get_app(name).pid or 0)

    # ----- §2/§3: exit-driven restart -----------------------------------
    def test_01_restart_on_exit_increments_starts(self):
        name = self._name("restart")
        self._add({
            "name": name,
            "command": "sh -c 'sleep 1; exit 0'",
            "shell": True,
            "behavior": {"exit": "restart"},
        })
        baseline = self._starts(name)
        # Each ~1s run exits and is restarted immediately (not waiting a full tick),
        # so within a short window we should see several spawns.
        grew = _poll(lambda: self._starts(name) >= baseline + 3, timeout=20)
        self.assertTrue(grew, f"app did not restart on exit (starts stuck near {baseline})")

    # ----- §6: REMOVE latch fix (the headline bug) ----------------------
    def test_02_remove_behavior_deletes_app(self):
        name = self._name("remove")
        self._add({
            "name": name,
            "command": "sh -c 'exit 0'",
            "shell": True,
            "behavior": {"exit": "remove"},
            # retention > ScheduleIntervalSeconds: the OLD code re-armed the self-delete
            # timer on every tick and the app was never removed; the new one-shot latch
            # fires handleError exactly once so the app is removed after `retention`.
            "retention": str(RETENTION_SEC),
        })
        self.assertIn(name, self._app_names(), "app should exist right after registration")
        removed = _poll(lambda: name not in self._app_names(), timeout=RETENTION_SEC + 20)
        self.assertTrue(removed, f"REMOVE app was not deleted within {RETENTION_SEC + 20}s")
        if not removed:
            return
        self._created.discard(name)  # already gone

    # ----- §5: periodic still runs after simulate-hack removal ----------
    def test_03_periodic_runs_repeatedly(self):
        name = self._name("periodic")
        self._add({
            "name": name,
            "command": "echo periodic_tick",
            "shell": True,
            "start_interval_seconds": "3",
        })
        baseline = self._starts(name)
        grew = _poll(lambda: self._starts(name) >= baseline + 2, timeout=20)
        self.assertTrue(grew, "periodic app did not run repeatedly")

    # ----- §4: m_needsSchedule reschedules on enable --------------------
    def test_04_disable_enable_reschedules(self):
        name = self._name("toggle")
        self._add({"name": name, "command": "sleep 1000"})
        self.assertTrue(_poll(lambda: self._pid(name) > 0, timeout=15), "app never started")

        self.client.disable_app(name)
        self.assertTrue(_poll(lambda: self._pid(name) <= 0, timeout=15), "disabled app still running")

        self.client.enable_app(name)
        self.assertTrue(_poll(lambda: self._pid(name) > 0, timeout=15),
                        "re-enabled app did not reschedule/start")

    # ----- §1 + §8: concurrent status reads during rapid restart --------
    def test_05_concurrent_status_reads_during_rapid_restart(self):
        name = self._name("race")
        self._add({
            "name": name,
            "command": "sh -c 'sleep 0.3; exit 1'",  # spawns/exits ~every 0.3-0.8s
            "shell": True,
            "behavior": {"exit": "restart"},
        })
        _poll(lambda: self._pid(name) > 0, timeout=10)

        errors = []
        stop_at = time.time() + 6

        def hammer():
            while time.time() < stop_at:
                try:
                    # Must not raise or return a torn/malformed snapshot while the app
                    # rapidly restarts. Field values may be absent (None) between runs.
                    self.client.get_app(name)
                except Exception as ex:  # noqa: BLE001
                    errors.append(repr(ex))
                    return

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(hammer) for _ in range(8)]
            concurrent.futures.wait(futures)

        self.assertEqual(errors, [], f"status reads failed during restart churn: {errors[:3]}")

    # ----- regression smoke: on-demand run path -------------------------
    def test_06_run_sync_and_async_smoke(self):
        rc, _ = self.client.run_app_sync(App({"command": "echo done", "shell": True}), max_time=10)
        self.assertEqual(rc, 0, "synchronous run did not return exit code 0")

        run = self.client.run_app_async(App({"command": "sh -c 'sleep 1; exit 0'", "shell": True}), max_time=10)
        rc = self.client.wait_for_async_run(run, timeout=15)
        self.assertEqual(rc, 0, "asynchronous run did not return exit code 0")

    # ----- step 10: crash-loop backoff throttles restarts ----------------
    def test_07_crash_loop_backoff_throttles_restarts(self):
        name = self._name("backoff")
        self._add({
            "name": name,
            "command": "sh -c 'exit 1'",  # instant crash -> every restart is "short-lived"
            "shell": True,
            "behavior": {"exit": "restart"},
        })
        self.assertTrue(_poll(lambda: self._starts(name) >= 1, timeout=15), "app never started")
        baseline = self._starts(name)
        window = 22  # backoff 1+2+4+8 -> expect ~4-6 more starts; the old 0.5s debounce gave ~30+
        time.sleep(window)
        delta = self._starts(name) - baseline
        self.assertGreaterEqual(delta, 2, f"crash-loop app stopped restarting (delta={delta})")
        self.assertLessEqual(delta, 10, f"backoff not applied: {delta} restarts in {window}s")

    # ----- R4: spawn failure must keep retrying, then recover ------------
    def test_08_spawn_failure_retries_then_recovers(self):
        name = self._name("spawnfail")
        # A '/'-rooted command that does not exist fails in validateCommand BEFORE fork:
        # no process, no exit upcall — the schedule-intent restore is the only retry driver.
        self._add({"name": name, "command": "/nonexistent_e2e_spawnfail_binary"})
        base = self._starts(name)
        retried = _poll(lambda: self._starts(name) >= base + 2 and self._pid(name) <= 0, timeout=20)
        self.assertTrue(retried, "spawn-failure app is not retrying (stranded: no starts growth)")

        # Fix the app via update: it must come up without disable/enable or daemon restart.
        self._add({"name": name, "command": "sleep 1000"})
        self.assertTrue(_poll(lambda: self._pid(name) > 0, timeout=20),
                        "app did not start after the bad command was corrected")

    # ----- R5/R6: attach adopts a live pid; its exit must be detected ----
    # Requires the daemon to SHARE THE PID NAMESPACE with this test (native same-host
    # deployment). A containerized daemon (e.g. Docker on macOS = Linux VM) cannot observe
    # the test's child process — it may even probe an unrelated same-numbered pid inside
    # the container — so this is opt-in.
    @unittest.skipUnless(os.environ.get("APPMESH_TEST_ATTACH") == "1",
                         "needs a native same-host daemon (set APPMESH_TEST_ATTACH=1)")
    @unittest.skipUnless(os.name == "posix", "spawns a local 'sleep' child")
    def test_09_attach_adopts_live_pid_and_detects_its_exit(self):
        name = self._name("attach")
        child = subprocess.Popen(["sleep", "60"])
        try:
            self._add({
                "name": name,
                "command": "sleep 60",
                "pid": child.pid,  # registration-time attach (recovery path)
                "behavior": {"exit": "restart"},
            })
            # Adopted, not killed, not spawned-over: daemon reports OUR pid and keeps it.
            self.assertTrue(_poll(lambda: self._pid(name) == child.pid, timeout=15),
                            f"daemon did not adopt pid {child.pid} (got {self._pid(name)})")
            time.sleep(5)
            self.assertIsNone(child.poll(), "attach killed the live target process")
            self.assertEqual(self._pid(name), child.pid, "daemon spawned over the attached process")

            # Kill it: a recovered process is not the daemon's child (no SIGCHLD), so this
            # exercises the refresh() liveness poll -> synthesized exit -> restart.
            child.kill()
            child.wait()
            restarted = _poll(lambda: self._pid(name) > 0 and self._pid(name) != child.pid, timeout=30)
            self.assertTrue(restarted, "recovered process exit was not detected/restarted")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()

    # ----- R2-adjacent: buffer overlap must not destabilize the app ------
    def test_10_buffer_overlap_stays_stable(self):
        name = self._name("buffer")
        # Each run (3s) outlives the interval (2s): every spawn buffers the previous run
        # (retention=8 -> delayKill later than its natural end), so buffer processes keep
        # exiting naturally next to the current run. No spurious restart may be minted.
        self._add({
            "name": name,
            "command": "sleep 3",
            "start_interval_seconds": "2",
            "retention": "8",
        })
        self.assertTrue(_poll(lambda: self._starts(name) >= 1, timeout=15), "app never started")
        baseline = self._starts(name)
        window = 14
        time.sleep(window)
        delta = self._starts(name) - baseline
        self.assertGreaterEqual(delta, 3, f"periodic+buffer app stalled (delta={delta})")
        self.assertLessEqual(delta, 10, f"buffer exits minted extra restarts: {delta} in {window}s")
        self.assertIn(name, self._app_names(), "app vanished during buffer churn")

    # ----- R1: agent restart must not deadlock the timer thread ----------
    @unittest.skipUnless(os.environ.get("APPMESH_TEST_AGENT") == "1",
                         "disruptive: kills the agent process (set APPMESH_TEST_AGENT=1)")
    def test_11_agent_psk_restart_recovers(self):
        def agent_pid():
            try:
                return int(self.client.get_app("agent").pid or 0)
            except Exception:  # noqa: BLE001 - REST may be down while the agent restarts
                return 0

        old_pid = agent_pid()
        if old_pid <= 0:
            self.skipTest("no 'agent' application on this daemon")
        try:
            os.kill(old_pid, signal.SIGKILL)
        except PermissionError:
            self.skipTest("insufficient permission to signal the agent process")

        # The agent must come back with a working PSK handshake (old bug: the blocking
        # wait froze the single timer thread, the spawn read a deleted SHM -> crash loop).
        recovered = _poll(lambda: agent_pid() > 0 and agent_pid() != old_pid, timeout=40, interval=0.5)
        self.assertTrue(recovered, "agent did not restart after kill")
        stable_pid = agent_pid()
        time.sleep(4)
        self.assertEqual(agent_pid(), stable_pid, "agent is crash-looping (PSK handshake broken)")
        rc, _ = self.client.run_app_sync(App({"command": "echo agent_ok", "shell": True}), max_time=10)
        self.assertEqual(rc, 0, "REST/agent path not functional after agent restart")


if __name__ == "__main__":
    unittest.main(verbosity=2)
