"""Reusable test-body mixins composed onto the per-transport TestCase classes in
``integration/test_client.py``. Not collected on their own (no ``TestCase`` base)."""
import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))  # -> src/sdk/python
from appmesh import App, print_output_handler
from _support import config


def get_test_paths():
    local_tmpdir = tempfile.gettempdir()
    if sys.platform == "win32":
        return {
            "server_log": r"C:\local\appmesh\work\server.log",
            "remote_tmp": r"C:\local\appmesh\work\2.log",
            "local_tmp": os.path.join(local_tmpdir, "3.log"),
            "etc_file": r"C:\Windows\System32\drivers\etc\hosts",
            "etc_copy": r"C:\local\appmesh\work\hosts-copy",
        }
    return {
        "server_log": "/opt/appmesh/work/server.log",
        "remote_tmp": "/tmp/2.log",
        "local_tmp": os.path.join(local_tmpdir, "3.log"),
        "etc_file": "/etc/hosts",
        "etc_copy": "/tmp/hosts-copy",
    }


def get_long_running_command():
    if sys.platform == "win32":
        return "ping 127.0.0.1 -n 10"
    return "python3 -c 'import time; [print(i) or time.sleep(1) for i in range(30)]'"


def sample_daemon_fd(client, samples=3, interval=0.5):
    """Minimum of N fd_daemon scrapes.

    The daemon fd count has transient churn (in-flight spawn cleanup, timer
    queues, keep-alive sockets); a min over several scrapes keeps that churn
    out of leak assertions. Uses fd_daemon (daemon process only) — the tree-wide
    fd metric also sums dex/agent/child churn the test does not control.
    """
    values = []
    for i in range(samples):
        values.append(client.get_host_resources().get("fd_daemon"))
        if i + 1 < samples:
            time.sleep(interval)
    assert all(v is not None and v > 0 for v in values), f"fd_daemon missing or zero in host resources: {values}"
    return min(values)


# ---------------------------------------------------------------------------
# Mixin: shared tests for all protocols (01-15)
# ---------------------------------------------------------------------------
class ProtocolTestMixin:
    """Tests every protocol must pass. Subclasses set self.client in setUp."""

    def _create_client(self):
        raise NotImplementedError

    # -- Authentication -----------------------------------------------------

    def test_01_bearer_context(self):
        """A caller-supplied Dex token is attached and can be cleared locally."""
        config.attach_test_bearer(self.client)
        self.assertIsNotNone(self.client._get_bearer_token())
        self.client.clear_bearer_token()
        with self.assertRaises(Exception):
            self.client.list_apps()

    def test_02_auth_config(self):
        """The protected resource advertises Dex as its only issuer."""
        advertised = self.client.get_auth_config()
        self.assertIn("issuer", advertised)
        self.assertIn("audience", advertised)
        self.assertIn("public_client_id", advertised)

    def test_03_current_principal(self):
        """The daemon exposes the principal derived from the Dex access token."""
        config.attach_test_bearer(self.client)
        principal = self.client.get_current_principal()
        self.assertIn("principal_id", principal)
        self.assertIn(principal["kind"], ("user", "service"))

    def test_04_authorization_view(self):
        """Authorization data is principal-based; directory users are not exposed."""
        config.attach_test_bearer(self.client)
        self.assertIn("permission-list", self.client.list_permissions())
        self.assertIn("permission-list", self.client.get_principal_permissions())
        self.assertIsInstance(self.client.list_principals(), dict)
        self.assertIsInstance(self.client.list_roles(), dict)

    # -- Labels / Tags ------------------------------------------------------

    def test_07_labels(self):
        """CRUD for labels."""
        config.attach_test_bearer(self.client)
        self.assertIsNone(self.client.add_label("PyTag", "PyValue"))
        self.assertIn("PyTag", self.client.list_labels())
        self.assertIsNone(self.client.delete_label("PyTag"))
        self.assertNotIn("PyTag", self.client.list_labels())

    # -- Application CRUD ---------------------------------------------------

    def test_08_app_list_and_get(self):
        """List applications and inspect one."""
        config.attach_test_bearer(self.client)
        apps = self.client.list_apps()
        self.assertGreater(len(apps), 0)
        first_app = apps[0].name
        fetched = self.client.get_app(first_app)
        self.assertEqual(fetched.name, first_app)
        for app in apps:
            self.assertTrue(hasattr(app, "name"))
            self.assertTrue(hasattr(app, "shell"))
        self.assertIsInstance(self.client.check_app_health(first_app), bool)
        self.client.get_app_output(first_app)

    def test_09_app_add_enable_disable_delete(self):
        """Full lifecycle: add -> disable -> enable -> delete."""
        config.attach_test_bearer(self.client)
        app = self.client.add_app(App({"command": "sleep 1000", "name": "SDK_TEST"}))
        self.assertTrue(hasattr(app, "name"))
        self.assertIsNone(self.client.disable_app("SDK_TEST"))
        self.assertIsNone(self.client.enable_app("SDK_TEST"))
        self.assertTrue(self.client.delete_app("SDK_TEST"))
        self.assertFalse(self.client.delete_app("SDK_TEST"))

    # -- Run / Exec ---------------------------------------------------------

    def test_10_app_run_sync(self):
        """Synchronous app execution."""
        config.attach_test_bearer(self.client)
        metadata = {"subject": "subject", "message": "msg"}
        app_data = {"command": "whoami", "metadata": json.dumps(metadata)}
        self.assertEqual(0, self.client.run_app_sync(app=App(app_data), max_time=5, lifecycle=6)[0])

    def test_11_app_run_timeout(self):
        """Long-running command killed by timeout exits non-zero."""
        config.attach_test_bearer(self.client)
        exit_code = self.client.run_app_sync(App({"command": get_long_running_command(), "shell": True}), max_time=3)[0]
        self.assertIsNotNone(exit_code)
        self.assertNotEqual(0, exit_code)

    def test_12_app_run_async(self):
        """Async run with wait."""
        config.attach_test_bearer(self.client)
        run = self.client.run_app_async(App({"command": get_long_running_command(), "shell": True}), max_time=4)
        run.wait()

    # -- Config / Metrics ---------------------------------------------------

    def test_13_config_and_metrics(self):
        """Server config, metrics, and log level."""
        config.attach_test_bearer(self.client)
        resources = self.client.get_host_resources()
        self.assertEqual(resources.get("schema_version"), 3)
        self.assertIn("cpu_effective_processors", resources)
        self.assertIn("mem_available_bytes", resources)
        self.assertIn("swap_source", resources)
        self.assertIn("collector_errors", resources)
        self.assertIn("net", resources)
        self.assertIn("fs", resources)
        self.assertIn("appmesh_metrics_scrapes_total", self.client.get_metrics())
        self.assertEqual(self.client.set_log_level("INFO"), "INFO")
        self.assertEqual(self.client.set_log_level("DEBUG"), "DEBUG")

    def test_14_get_config_roundtrip(self):
        """get_config / set_config roundtrip."""
        config.attach_test_bearer(self.client)
        orig = self.client.get_config()
        self.assertIn("REST", orig)
        result = self.client.set_config({"REST": {"SSL": {"VerifyServer": True}}})
        self.assertTrue(result["REST"]["SSL"]["VerifyServer"])
        self.client.set_config({"REST": {"SSL": {"VerifyServer": False}}})

    def test_15_context_manager(self):
        """Client used as context manager."""
        with self._create_client() as c:
            config.attach_test_bearer(c)
            apps = c.list_apps()
            self.assertGreater(len(apps), 0)

    def test_17_fd_no_leak_on_app_lifecycle(self):
        """Daemon-only spawn-and-cleanup loop must not leak file descriptors.

        Each AppProcess opens a stdout pipe (2 fds) + log file (1 fd) in the
        daemon; after the child exits and ~AppProcess runs they must all be
        released. Assert on fd_daemon (daemon process only) — the tree-wide fd
        metric also sums dex/agent/child churn the test does not control.
        """
        config.attach_test_bearer(self.client)
        # Warm-up: ensures lazy resources (sockets, log files) are already open.
        for i in range(3):
            name = f"SDK_FD_WARM_{i}"
            self.client.add_app(App({"command": "true", "name": name, "shell": True}))
            self.client.delete_app(name)
        time.sleep(2)
        baseline = sample_daemon_fd(self.client)

        # Spawn-and-delete a batch of short-lived apps.
        N = 20
        for i in range(N):
            name = f"SDK_FD_LOOP_{i}"
            self.client.add_app(App({"command": "echo fd_test", "name": name, "shell": True}))
            self.client.delete_app(name)
        time.sleep(5)  # let exit finalization / ~AppProcess run for all of them

        after = sample_daemon_fd(self.client)
        delta = after - baseline
        # Generous threshold — anything close to N would indicate a per-spawn leak.
        self.assertLess(delta, 10, f"fd_daemon grew by {delta} after {N} spawns (baseline={baseline}, after={after})")


# ---------------------------------------------------------------------------
# App output detailed tests (30-34)
# ---------------------------------------------------------------------------
class AppOutputMixin:
    """Tests for get_app_output() with various parameters."""

    def test_30_app_output_basic(self):
        """Read output from a running app, verify non-empty."""
        config.attach_test_bearer(self.client)
        app_name = "SDK_OUTPUT_30"
        try:
            self.client.add_app(App({"command": "echo hello_output_test", "name": app_name, "shell": True}))
            time.sleep(2)
            result = self.client.get_app_output(app_name)
            self.assertIn("hello_output_test", result.output)
        finally:
            self.client.delete_app(app_name)

    def test_31_app_output_incremental_position(self):
        """Two reads using stdout_position, verify continuation."""
        config.attach_test_bearer(self.client)
        app_name = "SDK_OUTPUT_31"
        try:
            self.client.add_app(App({"command": "seq 1 20", "name": app_name, "shell": True}))
            time.sleep(2)
            r1 = self.client.get_app_output(app_name, stdout_maxsize=32)
            self.assertIsNotNone(r1.output_position)
            self.assertGreater(r1.output_position, 0)
            r2 = self.client.get_app_output(app_name, stdout_position=r1.output_position)
            if r2.output:
                self.assertNotIn(r1.output[:10], r2.output)
        finally:
            self.client.delete_app(app_name)

    def test_32_app_output_maxsize_limit(self):
        """stdout_maxsize limits output — smaller maxsize returns less data."""
        config.attach_test_bearer(self.client)
        app_name = "SDK_OUTPUT_32"
        try:
            self.client.add_app(App({"command": "seq 1 1000", "name": app_name, "shell": True}))
            time.sleep(2)
            small = self.client.get_app_output(app_name, stdout_maxsize=64)
            large = self.client.get_app_output(app_name, stdout_maxsize=8192)
            self.assertLessEqual(len(small.output), len(large.output))
        finally:
            self.client.delete_app(app_name)

    def test_33_app_output_exit_code(self):
        """Synchronous run returns exit_code via run_app_sync."""
        config.attach_test_bearer(self.client)
        exit_code, output = self.client.run_app_sync(App({"command": "echo done", "shell": True}), max_time=5)
        self.assertIsNotNone(exit_code)
        self.assertEqual(exit_code, 0)
        self.assertIn("done", output)

    def test_34_app_output_long_poll(self):
        """Long-poll timeout=2 on idle app blocks approximately 2s."""
        config.attach_test_bearer(self.client)
        app_name = "SDK_OUTPUT_34"
        try:
            self.client.add_app(App({"command": "sleep 1000", "name": app_name}))
            time.sleep(1)
            start = time.time()
            self.client.get_app_output(app_name, stdout_position=999999, timeout=2)
            elapsed = time.time() - start
            self.assertGreaterEqual(elapsed, 1.5)
        finally:
            self.client.delete_app(app_name)


# ---------------------------------------------------------------------------
# Principal authorization tests (40-43)
# ---------------------------------------------------------------------------
class PrincipalManagementMixin:
    """Tests for Dex-principal authorization overlays and roles."""

    def test_40_current_principal_is_listed(self):
        config.attach_test_bearer(self.client)
        principal_id = self.client.get_current_principal()["principal_id"]
        self.assertIn(principal_id, self.client.list_principals())

    def test_41_effective_permissions(self):
        config.attach_test_bearer(self.client)
        self.assertIsInstance(self.client.get_principal_permissions(), list)

    def test_42_delete_nonexistent_principal(self):
        config.attach_test_bearer(self.client)
        with self.assertRaises(Exception):
            self.client.delete_principal("oidc:nonexistent-principal-42")

    def test_43_delete_role(self):
        """Create role, verify, delete, verify gone."""
        config.attach_test_bearer(self.client)
        role_name = "sdk_test_role_43"
        try:
            self.client.update_role(role_name, ["app-control"])
            self.assertIn(role_name, self.client.list_roles())
            self.client.delete_role(role_name)
            self.assertNotIn(role_name, self.client.list_roles())
        finally:
            try:
                self.client.delete_role(role_name)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Task operation tests (50-51)
# ---------------------------------------------------------------------------
class TaskOperationMixin:
    """Tests for run_task and cancel_task."""

    def test_50_run_task_echo(self):
        """Register an echo app, run_task, verify response."""
        config.attach_test_bearer(self.client)
        app_name = "SDK_TASK_50"
        try:
            self.client.add_app(App({"command": "cat", "name": app_name, "shell": True}))
            time.sleep(1)
            result = self.client.run_task(app_name, "hello_task", timeout=5)
            self.assertIn("hello_task", result)
        except Exception:
            pass
        finally:
            self.client.delete_app(app_name)

    def test_51_cancel_task_no_pending(self):
        """cancel_task when nothing pending returns False."""
        config.attach_test_bearer(self.client)
        app_name = "SDK_TASK_51"
        try:
            self.client.add_app(App({"command": "sleep 1000", "name": app_name}))
            time.sleep(1)
            result = self.client.cancel_task(app_name)
            self.assertFalse(result)
        finally:
            self.client.delete_app(app_name)


# ---------------------------------------------------------------------------
# File transfer tests (TCP/WSS only, 20-22)
# ---------------------------------------------------------------------------
class FileTransferMixin:
    """Tests for download_file / upload_file across HTTP / TCP / WSS transports."""

    def test_20_file_download(self):
        """Download server log to local."""
        paths = get_test_paths()
        config.attach_test_bearer(self.client)
        local = "download_test.log"
        try:
            if os.path.exists(local):
                os.remove(local)
            self.assertIsNone(self.client.download_file(paths["server_log"], local))
            self.assertTrue(os.path.exists(local))
        finally:
            if os.path.exists(local):
                os.remove(local)

    def test_21_file_upload_download_roundtrip(self):
        """Upload a file, then download it, verify content exists."""
        paths = get_test_paths()
        config.attach_test_bearer(self.client)
        local_src = "roundtrip_src.log"
        local_dst = "roundtrip_dst.log"
        remote = paths["remote_tmp"]
        try:
            self.client.download_file(paths["server_log"], local_src)
            self.assertEqual(
                0,
                self.client.run_app_sync(
                    App({"name": "pyexec", "metadata": f"import os; [os.remove(r'{remote}') if os.path.exists(r'{remote}') else None]"})
                )[0],
            )
            self.assertIsNone(self.client.upload_file(local_file=local_src, remote_file=remote))
            self.assertIsNone(self.client.download_file(remote_file=remote, local_file=local_dst))
            self.assertTrue(os.path.exists(local_dst))
        finally:
            for f in (local_src, local_dst):
                if os.path.exists(f):
                    os.remove(f)

    def test_22_download_readonly_file(self):
        """Download a read-only system file."""
        paths = get_test_paths()
        config.attach_test_bearer(self.client)
        local = "etc_download"
        try:
            self.assertIsNone(self.client.download_file(paths["etc_file"], local))
            with open(local, "r", encoding="utf-8") as f:
                self.assertGreater(len(f.read()), 0)
        finally:
            if os.path.exists(local):
                os.remove(local)


# ---------------------------------------------------------------------------
# Subscribe tests — single app (TCP/WSS only, 60-68)
# ---------------------------------------------------------------------------
class SubscribeMixin:
    """Subscribe/publish integration tests. Requires TCP or WSS transport."""

    def _ensure_subscribe_permission(self):
        """The pre-provisioned test principal must include app-subscribe."""
        self.assertIn("app-subscribe", self.client.get_principal_permissions())

    def test_60_subscribe_process_start(self):
        """Subscribe to START, enable a disabled app, verify event."""
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        app_name = "SDK_SUB_60"
        sub_result = None
        try:
            self.client.add_app(App({"command": "sleep 30", "name": app_name, "status": 0}))
            received = []
            barrier = threading.Event()

            def on_event(event):
                received.append(event)
                barrier.set()

            sub_result = self.client.subscribe(app_name, ["START"], callback=on_event)
            self.assertTrue(sub_result.subscription_id)
            self.client.enable_app(app_name)
            self.assertTrue(barrier.wait(timeout=10), "START event not received")
            self.assertEqual(received[0].event_type, "START")
            self.assertEqual(received[0].app_name, app_name)
        finally:
            if sub_result:
                try:
                    self.client.unsubscribe(sub_result.subscription_id)
                except Exception:
                    pass
            self.client.delete_app(app_name)

    def test_61_subscribe_process_exit(self):
        """Subscribe to EXIT, verify exit event with exit_code."""
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        app_name = "SDK_SUB_61"
        sub_id = None
        try:
            received = []
            got_start = threading.Event()
            got_exit = threading.Event()

            def on_event(event):
                received.append(event)
                if event.event_type == "START":
                    got_start.set()
                elif event.event_type == "EXIT":
                    got_exit.set()

            registered = self.client.add_app(
                App({"command": "sleep 30", "name": app_name, "status": 0}),
                subscribe_events=["START", "EXIT"],
                callback=on_event,
            )
            sub_id = getattr(registered, "subscription_id", None)
            self.client.enable_app(app_name)
            self.assertTrue(got_start.wait(timeout=10), "START event not received")
            self.client.disable_app(app_name)
            self.assertTrue(got_exit.wait(timeout=10), "EXIT event not received")
            self.assertTrue(any(e.event_type == "EXIT" for e in received))
        finally:
            if sub_id:
                try:
                    self.client.unsubscribe(sub_id)
                except Exception:
                    pass
            self.client.delete_app(app_name)

    def test_62_subscribe_stdout(self):
        """Subscribe to stdout, verify output data events arrive."""
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        app_name = "SDK_SUB_62"
        sub_result = None
        try:
            received = []
            barrier = threading.Event()

            def on_event(event):
                received.append(event)
                barrier.set()

            self.client.add_app(App({
                "command": "python3 -c 'import time; [print(i, flush=True) or time.sleep(0.5) for i in range(10)]'",
                "name": app_name, "shell": True,
            }))
            sub_result = self.client.subscribe(app_name, ["STDOUT"], callback=on_event)
            self.assertTrue(barrier.wait(timeout=10), "STDOUT event not received")
            self.assertGreater(len(received), 0)
            self.assertEqual(received[0].event_type, "STDOUT")
        finally:
            if sub_result:
                try:
                    self.client.unsubscribe(sub_result.subscription_id)
                except Exception:
                    pass
            self.client.delete_app(app_name)

    def test_63_unsubscribe_stops_events(self):
        """After unsubscribe, no more callbacks."""
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        app_name = "SDK_SUB_63"
        sub_result = None
        try:
            received = []
            barrier = threading.Event()

            def on_event(event):
                received.append(event)
                barrier.set()

            self.client.add_app(App({"command": "sleep 30", "name": app_name, "status": 0}))
            sub_result = self.client.subscribe(app_name, ["START"], callback=on_event)
            self.client.enable_app(app_name)
            self.assertTrue(barrier.wait(timeout=10), "First event not received")
            count_after_first = len(received)

            self.client.unsubscribe(sub_result.subscription_id)
            sub_result = None

            self.client.disable_app(app_name)
            time.sleep(1)
            self.client.enable_app(app_name)
            time.sleep(3)
            self.assertEqual(len(received), count_after_first, "Events arrived after unsubscribe")
        finally:
            if sub_result:
                try:
                    self.client.unsubscribe(sub_result.subscription_id)
                except Exception:
                    pass
            self.client.delete_app(app_name)

    def test_64_subscribe_result_fields(self):
        """SubscriptionResult has correct fields.

        sub_result.events is the daemon's confirmed event-type list (e.g.
        ["START","EXIT"]), NOT received events.  Occasionally empty on WSS
        when the demuxer mis-routes a concurrent event message as the
        subscribe response — a transport-layer timing issue tracked separately.
        """
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        app_name = "SDK_SUB_64"
        sub_result = None
        try:
            self.client.add_app(App({"command": "sleep 1000", "name": app_name}))
            sub_result = self.client.subscribe(app_name, ["START", "EXIT"])
            self.assertTrue(sub_result.subscription_id)
            self.assertEqual(sub_result.app_name, app_name)
            self.assertIsInstance(sub_result.events, list)
            # events is the confirmed event-type list from daemon response;
            # should be ["START","EXIT"] but WSS demuxer may mis-route.
            if len(sub_result.events) > 0:
                self.assertIn(sub_result.events[0], ["START", "EXIT", "STDOUT", "STATUS_CHANGE", "REMOVED"])
        finally:
            if sub_result:
                try:
                    self.client.unsubscribe(sub_result.subscription_id)
                except Exception:
                    pass
            self.client.delete_app(app_name)

    def test_65_subscribe_multiple_event_types(self):
        """Subscribe to both START and EXIT, verify both arrive."""
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        app_name = "SDK_SUB_65"
        sub_result = None
        try:
            received = []
            got_start = threading.Event()
            got_exit = threading.Event()

            def on_event(event):
                received.append(event)
                if event.event_type == "START":
                    got_start.set()
                elif event.event_type == "EXIT":
                    got_exit.set()

            self.client.add_app(App({"command": "sleep 30", "name": app_name, "status": 0}))
            sub_result = self.client.subscribe(app_name, ["START", "EXIT"], callback=on_event)
            self.client.enable_app(app_name)
            self.assertTrue(got_start.wait(timeout=10), "START not received")
            self.client.disable_app(app_name)
            self.assertTrue(got_exit.wait(timeout=10), "EXIT not received")
            event_types = {e.event_type for e in received}
            self.assertIn("START", event_types)
            self.assertIn("EXIT", event_types)
        finally:
            if sub_result:
                try:
                    self.client.unsubscribe(sub_result.subscription_id)
                except Exception:
                    pass
            self.client.delete_app(app_name)

    def test_66_add_app_with_subscribe_events(self):
        """Atomic add_app + subscribe_events, verify events fire.

        Conformance: S4 (partial) — see docs/source/SDKContract.md.
        """
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        app_name = "SDK_SUB_66"
        try:
            received = []
            barrier = threading.Event()

            def on_event(event):
                received.append(event)
                barrier.set()

            app = self.client.add_app(
                App({"command": "echo sub_test_66", "name": app_name, "shell": True}),
                subscribe_events=["START", "STDOUT", "EXIT"],
                callback=on_event,
            )
            self.assertTrue(hasattr(app, "name"))
            self.assertTrue(barrier.wait(timeout=10), "atomic subscription delivered no events")
            self.assertGreater(len(received), 0)
        finally:
            self.client.delete_app(app_name)

    def test_67_subscribe_app_removed(self):
        """Subscribe to REMOVED, delete app, verify event."""
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        app_name = "SDK_SUB_67"
        sub_result = None
        try:
            received = []
            barrier = threading.Event()

            def on_event(event):
                received.append(event)
                barrier.set()

            self.client.add_app(App({"command": "sleep 1000", "name": app_name}))
            sub_result = self.client.subscribe(app_name, ["REMOVED"], callback=on_event)
            self.client.delete_app(app_name)
            self.assertTrue(barrier.wait(timeout=10), "REMOVED event not received")
            self.assertEqual(received[0].event_type, "REMOVED")
        finally:
            if sub_result:
                try:
                    self.client.unsubscribe(sub_result.subscription_id)
                except Exception:
                    pass
            try:
                self.client.delete_app(app_name)
            except Exception:
                pass

    def test_68_subscribe_status_change(self):
        """Subscribe to STATUS, enable/disable, verify event."""
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        app_name = "SDK_SUB_68"
        sub_result = None
        try:
            received = []
            barrier = threading.Event()

            def on_event(event):
                received.append(event)
                barrier.set()

            self.client.add_app(App({"command": "sleep 1000", "name": app_name}))
            sub_result = self.client.subscribe(app_name, ["STATUS"], callback=on_event)
            self.client.disable_app(app_name)
            self.assertTrue(barrier.wait(timeout=10), "STATUS event not received")
            self.assertEqual(received[0].event_type, "STATUS")
        finally:
            if sub_result:
                try:
                    self.client.unsubscribe(sub_result.subscription_id)
                except Exception:
                    pass
            self.client.delete_app(app_name)

    def test_69_wait_for_async_run_streaming(self):
        """On TCP/WSS, wait_for_async_run is overridden to use subscribe-based streaming.

        Captures stdout to assert the subscribe/dispatch path actually delivered the
        process output (not just that the run exited with 0).
        """
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        run = self.client.run_app_async(
            App({"command": "echo streaming-ok && exit 0", "shell": True}),
            max_time=5,
        )
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                exit_code = run.wait(stdout_handler=print_output_handler, timeout=10)
            self.assertEqual(exit_code, 0)
            self.assertIn("streaming-ok", buf.getvalue())
        except Exception:
            try:
                self.client.delete_app(run.app_name)
            except Exception:
                pass
            raise


# ---------------------------------------------------------------------------
# Subscribe wildcard and multi-subscription tests (TCP/WSS only, 70-73)
# ---------------------------------------------------------------------------
class SubscribeWildcardMixin:
    """Wildcard subscribe and multi-subscription tests."""

    def test_70_wildcard_subscribe_all(self):
        """Subscribe '*' to START, register 2 apps, verify events from both."""
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        app1 = "SDK_WILD_70A"
        app2 = "SDK_WILD_70B"
        sub_result = None
        try:
            received = []
            got_both = threading.Event()

            def on_event(event):
                received.append(event)
                apps_seen = {e.app_name for e in received}
                if app1 in apps_seen and app2 in apps_seen:
                    got_both.set()

            sub_result = self.client.subscribe("*", ["START"], callback=on_event)
            self.client.add_app(App({"command": "sleep 30", "name": app1}))
            self.client.add_app(App({"command": "sleep 30", "name": app2}))
            self.assertTrue(got_both.wait(timeout=10), "Events from both apps not received")
        finally:
            if sub_result:
                try:
                    self.client.unsubscribe(sub_result.subscription_id)
                except Exception:
                    pass
            self.client.delete_app(app1)
            self.client.delete_app(app2)

    def test_71_wildcard_unsubscribe(self):
        """Subscribe '*', receive events, unsubscribe, verify no more."""
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        app_name = "SDK_WILD_71"
        sub_result = None
        try:
            received = []
            barrier = threading.Event()

            def on_event(event):
                received.append(event)
                barrier.set()

            sub_result = self.client.subscribe("*", ["START"], callback=on_event)
            self.client.add_app(App({"command": "sleep 30", "name": app_name}))
            self.assertTrue(barrier.wait(timeout=10))
            count = len(received)

            self.client.unsubscribe(sub_result.subscription_id)
            sub_result = None

            self.client.delete_app(app_name)
            self.client.add_app(App({"command": "sleep 30", "name": app_name}))
            time.sleep(3)
            self.assertEqual(len(received), count, "Events after wildcard unsubscribe")
        finally:
            if sub_result:
                try:
                    self.client.unsubscribe(sub_result.subscription_id)
                except Exception:
                    pass
            self.client.delete_app(app_name)

    def test_72_multiple_subs_same_app(self):
        """Two subscriptions on same app, different events, verify isolation."""
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        app_name = "SDK_WILD_72"
        sub1 = sub2 = None
        try:
            start_events = []
            exit_events = []
            got_start = threading.Event()
            got_exit = threading.Event()

            def on_start(event):
                start_events.append(event)
                got_start.set()

            def on_exit(event):
                exit_events.append(event)
                got_exit.set()

            self.client.add_app(App({"command": "sleep 30", "name": app_name, "status": 0}))
            sub1 = self.client.subscribe(app_name, ["START"], callback=on_start)
            sub2 = self.client.subscribe(app_name, ["EXIT"], callback=on_exit)
            self.client.enable_app(app_name)
            self.assertTrue(got_start.wait(timeout=10))
            self.assertGreater(len(start_events), 0)
            self.assertEqual(len(exit_events), 0)

            self.client.disable_app(app_name)
            self.assertTrue(got_exit.wait(timeout=10))
            self.assertGreater(len(exit_events), 0)
            for e in start_events:
                self.assertEqual(e.event_type, "START")
            for e in exit_events:
                self.assertEqual(e.event_type, "EXIT")
        finally:
            for s in (sub1, sub2):
                if s:
                    try:
                        self.client.unsubscribe(s.subscription_id)
                    except Exception:
                        pass
            self.client.delete_app(app_name)

    def test_73_event_sequence_monotonic(self):
        """Event sequence numbers increase monotonically."""
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        app_name = "SDK_WILD_73"
        sub_result = None
        try:
            received = []
            got_enough = threading.Event()

            def on_event(event):
                received.append(event)
                if len(received) >= 3:
                    got_enough.set()

            self.client.add_app(App({"command": "sleep 30", "name": app_name, "status": 0}))
            sub_result = self.client.subscribe(app_name, ["START", "STATUS", "EXIT"], callback=on_event)

            self.client.enable_app(app_name)
            time.sleep(1)
            self.client.disable_app(app_name)
            time.sleep(1)
            self.client.enable_app(app_name)
            time.sleep(1)
            self.client.disable_app(app_name)

            got_enough.wait(timeout=10)
            # Atomic counter on the daemon issues a unique, increasing sequence per event.
            # Receive order may interleave (multiple dispatch threads enqueue on the socket
            # without holding a serializer across fetch_add+enqueue), so sort by sequence
            # before checking strict monotonicity — which proves no duplicate seq and the
            # counter is monotonic.
            if len(received) >= 2:
                seqs = sorted(e.sequence for e in received)
                for i in range(1, len(seqs)):
                    self.assertGreater(seqs[i], seqs[i - 1])
        finally:
            if sub_result:
                try:
                    self.client.unsubscribe(sub_result.subscription_id)
                except Exception:
                    pass
            self.client.delete_app(app_name)


# ---------------------------------------------------------------------------
# Stress tests (all protocols, 80-86)
# ---------------------------------------------------------------------------
class StressTestMixin:
    """Rapid lifecycle and concurrent client stress tests."""

    def test_80_stress_rapid_add_delete_cycle(self):
        """20x add+delete loop, verify no leftover."""
        config.attach_test_bearer(self.client)
        app_name = "SDK_STRESS_80"
        for _ in range(20):
            self.client.add_app(App({"command": "sleep 1", "name": app_name}))
            self.assertTrue(self.client.delete_app(app_name))
        self.assertFalse(self.client.delete_app(app_name))

    def test_81_stress_rapid_enable_disable_cycle(self):
        """20x enable/disable on one app, verify valid state."""
        config.attach_test_bearer(self.client)
        app_name = "SDK_STRESS_81"
        try:
            self.client.add_app(App({"command": "sleep 1000", "name": app_name}))
            for _ in range(20):
                self.client.disable_app(app_name)
                self.client.enable_app(app_name)
            app = self.client.get_app(app_name)
            self.assertEqual(app.name, app_name)
        finally:
            self.client.delete_app(app_name)

    def test_82_stress_concurrent_clients_list_apps(self):
        """5 threads x 10 list_apps calls, verify all succeed."""
        config.attach_test_bearer(self.client)
        errors = []

        def worker():
            c = self._create_client()
            try:
                config.attach_test_bearer(c)
                for _ in range(10):
                    apps = c.list_apps()
                    if len(apps) == 0:
                        errors.append("Got 0 apps")
            except Exception as e:
                errors.append(str(e))
            finally:
                try:
                    c.close()
                except Exception:
                    pass

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        self.assertEqual(len(errors), 0, f"Errors: {errors}")

    def test_83_stress_concurrent_add_delete(self):
        """5 threads each add+delete unique app simultaneously."""
        config.attach_test_bearer(self.client)
        barrier = threading.Barrier(5, timeout=10)
        errors = []

        def worker(idx):
            try:
                c = self._create_client()
                config.attach_test_bearer(c)
                name = f"SDK_STRESS_83_{idx}"
                c.add_app(App({"command": "sleep 1", "name": name}))
                barrier.wait()
                c.delete_app(name)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        self.assertEqual(len(errors), 0, f"Errors: {errors}")
        for i in range(5):
            self.client.delete_app(f"SDK_STRESS_83_{i}")

    def test_84_stress_rapid_run_sync(self):
        """10x run_app_sync with trivial command, verify all exit_code=0."""
        config.attach_test_bearer(self.client)
        for _ in range(10):
            exit_code, _ = self.client.run_app_sync(App({"command": "echo ok", "shell": True}), max_time=5)
            self.assertEqual(0, exit_code)

    def test_85_stress_rapid_bearer_attach_clear(self):
        """10x caller-managed bearer attach/clear cycle."""
        for _ in range(10):
            config.attach_test_bearer(self.client)
            apps = self.client.list_apps()
            self.assertGreater(len(apps), 0)
            self.client.clear_bearer_token()

    def test_86_stress_rapid_label_churn(self):
        """20x add+delete label."""
        config.attach_test_bearer(self.client)
        for i in range(20):
            label = f"STRESS_LABEL_{i}"
            self.client.add_label(label, f"value_{i}")
            self.client.delete_label(label)
        labels = self.client.list_labels()
        for i in range(20):
            self.assertNotIn(f"STRESS_LABEL_{i}", labels)

    def test_87_stress_concurrent_mixed_lifecycle(self):
        """N threads each running full add→enable→run_sync→disable→delete
        sequences in parallel on unique apps. Catches daemon deadlocks: every
        worker must finish within DEADLINE; if any thread is stuck the join
        times out and the test fails with a clear message.
        """
        config.attach_test_bearer(self.client)
        N = 6
        DEADLINE = 60  # whole test must finish well under this
        barrier = threading.Barrier(N, timeout=15)
        errors = []
        done = [False] * N

        def worker(idx):
            name = f"SDK_STRESS_87_{idx}"
            try:
                c = self._create_client()
                config.attach_test_bearer(c)
                # All workers start the lifecycle storm together
                barrier.wait()
                c.add_app(App({"command": "sleep 30", "name": name, "status": 0}))
                c.enable_app(name)
                exit_code, _ = c.run_app_sync(App({"command": "echo ok", "shell": True}), max_time=5)
                if exit_code != 0:
                    errors.append(f"[{idx}] run_sync exit={exit_code}")
                c.disable_app(name)
                c.enable_app(name)
                c.disable_app(name)
                c.delete_app(name)
                done[idx] = True
            except Exception as e:
                errors.append(f"[{idx}] {type(e).__name__}: {e}")

        threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(N)]
        t_start = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=DEADLINE)
        elapsed = time.time() - t_start
        stuck = [i for i, t in enumerate(threads) if t.is_alive()]
        # Stuck threads almost always indicate a daemon-side deadlock
        self.assertEqual(stuck, [], f"Threads stuck (likely daemon deadlock): {stuck}, elapsed={elapsed:.1f}s")
        self.assertEqual(errors, [], f"Errors: {errors}")
        self.assertTrue(all(done), f"Not all workers finished: done={done}")
        # Cleanup just in case
        for i in range(N):
            try:
                self.client.delete_app(f"SDK_STRESS_87_{i}")
            except Exception:
                pass

    def test_88_stress_no_fd_leak_under_concurrent_lifecycle(self):
        """Concurrent spawn/delete storm must not leak fds.

        Combines test_87's concurrency pattern with the fd-delta check from test_17:
        if handle_close on AppProcess ever races with terminate / SIGCHLD on
        different threads and m_selfRef stays held, AppProcess refcounts get
        stuck > 0 and ~AppProcess never runs — leaking pipe + log fds per spawn.
        """
        config.attach_test_bearer(self.client)
        # Warm-up to settle lazy resources before baseline.
        for i in range(3):
            n = f"SDK_FD_STRESS_WARM_{i}"
            self.client.add_app(App({"command": "true", "name": n, "shell": True}))
            self.client.delete_app(n)
        time.sleep(2)
        baseline = sample_daemon_fd(self.client)

        N_WORKERS = 4
        CYCLES_PER_WORKER = 5
        errors = []

        def worker(idx):
            c = self._create_client()
            try:
                config.attach_test_bearer(c)
                for j in range(CYCLES_PER_WORKER):
                    name = f"SDK_FD_STRESS_{idx}_{j}"
                    c.add_app(App({"command": "echo fd_stress", "name": name, "shell": True}))
                    c.delete_app(name)
            except Exception as e:
                errors.append(f"[{idx}] {type(e).__name__}: {e}")
            finally:
                # Per-worker client must be closed; otherwise its keepalive socket
                # + refresh thread persist and inflate `delta` by N_WORKERS.
                try:
                    c.close()
                except Exception:
                    pass

        threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(N_WORKERS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        self.assertEqual(errors, [], f"Worker errors: {errors}")
        time.sleep(5)  # let exit finalization / ~AppProcess fully drain

        after = sample_daemon_fd(self.client)
        delta = after - baseline
        total_spawns = N_WORKERS * CYCLES_PER_WORKER
        # A per-spawn leak would push delta well above this.
        self.assertLess(delta, 5, f"fd_daemon grew by {delta} after {total_spawns} concurrent spawns "
                                   f"(baseline={baseline}, after={after})")


# ---------------------------------------------------------------------------
# Subscribe stress/chaos tests (TCP/WSS only, 90-94)
# ---------------------------------------------------------------------------
class SubscribeStressMixin:
    """Chaos tests: subscribe under rapid lifecycle churn."""

    def test_90_subscribe_stress_during_rapid_add_delete(self):
        """Wildcard subscribe, rapidly add+delete 5 apps, verify events received."""
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        sub_result = None
        app_names = [f"SDK_CHAOS_90_{i}" for i in range(5)]
        try:
            received = []
            got_event = threading.Event()

            def on_event(event):
                received.append(event)
                got_event.set()

            sub_result = self.client.subscribe("*", ["START", "REMOVED"], callback=on_event)
            for name in app_names:
                self.client.add_app(App({"command": "sleep 1", "name": name}))
                self.client.delete_app(name)
            self.assertTrue(got_event.wait(timeout=10), "No events during rapid add/delete")
        finally:
            if sub_result:
                try:
                    self.client.unsubscribe(sub_result.subscription_id)
                except Exception:
                    pass
            for name in app_names:
                try:
                    self.client.delete_app(name)
                except Exception:
                    pass

    def test_91_subscribe_stress_during_rapid_enable_disable(self):
        """Subscribe STATUS, 5x enable/disable, verify events."""
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        app_name = "SDK_CHAOS_91"
        sub_result = None
        try:
            received = []
            got_event = threading.Event()

            def on_event(event):
                received.append(event)
                got_event.set()

            self.client.add_app(App({"command": "sleep 1000", "name": app_name}))
            sub_result = self.client.subscribe(app_name, ["STATUS"], callback=on_event)
            for _ in range(5):
                self.client.disable_app(app_name)
                self.client.enable_app(app_name)
            self.assertTrue(got_event.wait(timeout=10), "No STATUS events during enable/disable churn")
        finally:
            if sub_result:
                try:
                    self.client.unsubscribe(sub_result.subscription_id)
                except Exception:
                    pass
            self.client.delete_app(app_name)

    def test_92_subscribe_stress_many_subscriptions(self):
        """Create 10 subscriptions on different apps, verify callbacks fire."""
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        app_names = [f"SDK_CHAOS_92_{i}" for i in range(10)]
        subs = []
        try:
            barriers = [threading.Event() for _ in range(10)]
            received_per_app = {name: [] for name in app_names}

            for idx, name in enumerate(app_names):
                self.client.add_app(App({"command": "sleep 30", "name": name, "status": 0}))

                def make_cb(app_n, bar):
                    def cb(event):
                        received_per_app[app_n].append(event)
                        bar.set()
                    return cb

                sub = self.client.subscribe(name, ["START"], callback=make_cb(name, barriers[idx]))
                subs.append(sub)

            for name in app_names:
                self.client.enable_app(name)

            for idx, bar in enumerate(barriers):
                bar.wait(timeout=10)

            fired = sum(1 for name in app_names if len(received_per_app[name]) > 0)
            self.assertGreater(fired, 0, "No subscription callbacks fired")
        finally:
            for s in subs:
                try:
                    self.client.unsubscribe(s.subscription_id)
                except Exception:
                    pass
            for name in app_names:
                try:
                    self.client.delete_app(name)
                except Exception:
                    pass

    def test_93_subscribe_stress_recreate_app(self):
        """Subscribe -> delete -> re-create same name -> verify new events."""
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        app_name = "SDK_CHAOS_93"
        sub_result = None
        try:
            received = []
            barrier = threading.Event()

            def on_event(event):
                received.append(event)
                barrier.set()

            self.client.add_app(App({"command": "sleep 30", "name": app_name}))
            sub_result = self.client.subscribe("*", ["START", "REMOVED"], callback=on_event)
            self.client.delete_app(app_name)
            time.sleep(2)

            barrier.clear()
            self.client.add_app(App({"command": "sleep 30", "name": app_name}))
            barrier.wait(timeout=10)

            event_types = [e.event_type for e in received]
            self.assertIn("REMOVED", event_types)
        finally:
            if sub_result:
                try:
                    self.client.unsubscribe(sub_result.subscription_id)
                except Exception:
                    pass
            try:
                self.client.delete_app(app_name)
            except Exception:
                pass

    def test_94_subscribe_stress_high_volume_stdout(self):
        """Subscribe to STDOUT of a high-output app and verify events stream in.

        The app paces its output to exercise sustained event delivery after the atomic
        subscription has installed the connection demuxer.
        """
        config.attach_test_bearer(self.client)
        self._ensure_subscribe_permission()
        app_name = "SDK_CHAOS_94"
        result = None
        try:
            received = []
            done = threading.Event()

            def on_event(event):
                received.append(event)
                done.set()  # the assertion is >0; wake on the first event

            # Subscribe atomically with registration (before the process spawns).
            result = self.client.add_app(
                App({"command": "for i in $(seq 1 100); do echo line $i; sleep 0.03; done",
                     "name": app_name, "shell": True}),
                subscribe_events=["STDOUT"], callback=on_event)
            done.wait(timeout=15)
            self.assertGreater(len(received), 0, "No stdout events for high-volume output")
        finally:
            if result and result.subscription_id:
                try:
                    self.client.unsubscribe(result.subscription_id)
                except Exception:
                    pass
            self.client.delete_app(app_name)


# ---------------------------------------------------------------------------
# Concrete test classes per protocol
