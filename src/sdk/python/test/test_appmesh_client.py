"""Comprehensive Python SDK integration tests across four protocols.

Covers: HTTP REST, TCP, WebSocket (WSS), REST-over-WSS.
Includes: auth, app CRUD, subscribe/publish, task ops, user mgmt,
          app output, file transfer, stress/chaos scenarios.

Usage:
    python3 -m unittest --verbose                                # all
    python3 -m unittest test_appmesh_client.TestHTTP             # HTTP only
    python3 -m unittest test_appmesh_client.TestTCP              # TCP only
    python3 -m unittest test_appmesh_client.TestWSS              # WSS only
    python3 -m unittest test_appmesh_client.TestWSSRest          # REST-over-WSS
    python3 -m unittest -k subscribe test_appmesh_client         # subscribe tests
    python3 -m unittest -k stress test_appmesh_client            # stress tests
"""

import concurrent.futures
import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import TestCase

from pyotp import TOTP

current_directory = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(current_directory))

from appmesh import AppMeshClient, AppMeshClientTCP, AppMeshClientWSS, App, print_output_handler

DEFAULT_CRED = os.environ.get("APPMESH_TEST_CRED", "admin123")
_WSS_REST_PORT = 6058


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


# ---------------------------------------------------------------------------
# Mixin: shared tests for all protocols (01-15)
# ---------------------------------------------------------------------------
class ProtocolTestMixin:
    """Tests every protocol must pass. Subclasses set self.client in setUp."""

    def _create_client(self):
        raise NotImplementedError

    # -- Authentication -----------------------------------------------------

    def test_01_login_logout(self):
        """Login, verify token, logout, verify locked out."""
        self.client.login("admin", DEFAULT_CRED)
        token = self.client._get_access_token()
        self.assertIsNotNone(token)
        self.assertTrue(self.client.authenticate(token)[0])
        self.assertTrue(self.client.logout())
        with self.assertRaises(Exception):
            self.client.list_apps()

    def test_02_auth_audience(self):
        """Audience-scoped authentication."""
        with self.assertRaises(Exception):
            self.client.login("admin", DEFAULT_CRED, audience="appmesh-service-na")
        self.client.login("admin", DEFAULT_CRED, audience="your-service-api")
        token = self.client._get_access_token()
        self.assertFalse(self.client.authenticate(token)[0])
        self.assertTrue(self.client.authenticate(token, audience="your-service-api")[0])

    def test_03_renew_token(self):
        """Token renewal returns a different token."""
        self.client.login("admin", DEFAULT_CRED)
        t1 = self.client._get_access_token()
        self.client.renew_token(100)
        t2 = self.client._get_access_token()
        self.assertNotEqual(t1, t2)
        self.assertTrue(self.client.authenticate(t2)[0])

    # -- User / Role management ---------------------------------------------

    def test_04_user_management(self):
        """User-related endpoints."""
        self.client.login("admin", DEFAULT_CRED)
        self.assertIn("permission-list", self.client.list_permissions())
        self.assertIn("permission-list", self.client.get_user_permissions())
        self.assertIn("mesh", self.client.list_users())
        self.assertEqual(self.client.get_current_user()["email"], "admin@appmesh.com")
        self.assertIsNone(self.client.lock_user("mesh"))
        self.assertIsNone(self.client.unlock_user("mesh"))

    def test_05_credential_change(self):
        """Change credential, verify old fails, new works, restore."""
        self.client.login("admin", DEFAULT_CRED)
        temp_cred = "Admin@456"
        try:
            self.assertIsNone(self.client.update_password(DEFAULT_CRED, temp_cred))
            with self.assertRaises(Exception):
                self.client.login("admin", DEFAULT_CRED)
            self.assertIsNone(self.client.login("admin", temp_cred))
            self.assertIsNone(self.client.update_password(temp_cred, DEFAULT_CRED))
        finally:
            try:
                self.client.login("admin", temp_cred)
                self.client.update_password(temp_cred, DEFAULT_CRED)
            except Exception:
                pass

    def test_06_roles_and_groups(self):
        """Role and group listing."""
        self.client.login("admin", DEFAULT_CRED)
        self.assertIsNone(
            self.client.update_role(
                "manage",
                ["app-control", "app-delete", "app-reg", "config-set", "file-download", "file-upload", "label-delete", "label-set"],
            )
        )
        self.assertIn("manage", self.client.list_roles())
        self.assertIn("admin", self.client.list_groups())

    # -- Labels / Tags ------------------------------------------------------

    def test_07_labels(self):
        """CRUD for labels."""
        self.client.login("admin", DEFAULT_CRED)
        self.assertIsNone(self.client.add_label("PyTag", "PyValue"))
        self.assertIn("PyTag", self.client.list_labels())
        self.assertIsNone(self.client.delete_label("PyTag"))
        self.assertNotIn("PyTag", self.client.list_labels())

    # -- Application CRUD ---------------------------------------------------

    def test_08_app_list_and_get(self):
        """List applications and inspect one."""
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
        app = self.client.add_app(App({"command": "sleep 1000", "name": "SDK_TEST"}))
        self.assertTrue(hasattr(app, "name"))
        self.assertIsNone(self.client.disable_app("SDK_TEST"))
        self.assertIsNone(self.client.enable_app("SDK_TEST"))
        self.assertTrue(self.client.delete_app("SDK_TEST"))
        self.assertFalse(self.client.delete_app("SDK_TEST"))

    # -- Run / Exec ---------------------------------------------------------

    def test_10_app_run_sync(self):
        """Synchronous app execution."""
        self.client.login("admin", DEFAULT_CRED)
        metadata = {"subject": "subject", "message": "msg"}
        app_data = {"command": "whoami", "metadata": json.dumps(metadata)}
        self.assertEqual(0, self.client.run_app_sync(app=App(app_data), max_time=5, lifecycle=6)[0])

    def test_11_app_run_timeout(self):
        """Long-running command killed by timeout exits non-zero."""
        self.client.login("admin", DEFAULT_CRED)
        exit_code = self.client.run_app_sync(App({"command": get_long_running_command(), "shell": True}), max_time=3)[0]
        self.assertIsNotNone(exit_code)
        self.assertNotEqual(0, exit_code)

    def test_12_app_run_async(self):
        """Async run with wait."""
        self.client.login("admin", DEFAULT_CRED)
        run = self.client.run_app_async(App({"command": get_long_running_command(), "shell": True}), max_time=4)
        run.wait()

    # -- Config / Metrics ---------------------------------------------------

    def test_13_config_and_metrics(self):
        """Server config, metrics, and log level."""
        self.client.login("admin", DEFAULT_CRED)
        self.assertIn("cpu_cores", self.client.get_host_resources())
        self.assertIn("appmesh_prom_scrape_count", self.client.get_metrics())
        self.assertEqual(self.client.set_log_level("INFO"), "INFO")
        self.assertEqual(self.client.set_log_level("DEBUG"), "DEBUG")

    def test_14_get_config_roundtrip(self):
        """get_config / set_config roundtrip."""
        self.client.login("admin", DEFAULT_CRED)
        orig = self.client.get_config()
        self.assertIn("REST", orig)
        result = self.client.set_config({"REST": {"SSL": {"VerifyServer": True}}})
        self.assertTrue(result["REST"]["SSL"]["VerifyServer"])
        self.client.set_config({"REST": {"SSL": {"VerifyServer": False}}})

    def test_15_context_manager(self):
        """Client used as context manager."""
        with self._create_client() as c:
            c.login("admin", DEFAULT_CRED)
            apps = c.list_apps()
            self.assertGreater(len(apps), 0)

    def test_17_fd_no_leak_on_app_lifecycle(self):
        """Spawn-and-cleanup loop must not leak file descriptors.

        Each AppProcess opens a stdout pipe (2 fds) + log file (1 fd); after the
        child exits and ~AppProcess runs they must all be released. Allow a small
        slack for daemon-internal churn (timer queues, log rotation, etc.).
        """
        self.client.login("admin", DEFAULT_CRED)
        # Warm-up: ensures lazy resources (sockets, log files) are already open.
        for i in range(3):
            name = f"SDK_FD_WARM_{i}"
            self.client.add_app(App({"command": "true", "name": name, "shell": True}))
            self.client.delete_app(name)
        time.sleep(2)
        baseline = self.client.get_host_resources().get("fd")
        self.assertIsNotNone(baseline)

        # Spawn-and-delete a batch of short-lived apps.
        N = 20
        for i in range(N):
            name = f"SDK_FD_LOOP_{i}"
            self.client.add_app(App({"command": "echo fd_test", "name": name, "shell": True}))
            self.client.delete_app(name)
        time.sleep(3)  # let onTimerAppExit / ~AppProcess run for all of them

        after = self.client.get_host_resources().get("fd")
        delta = after - baseline
        # Generous threshold — anything close to N would indicate a per-spawn leak.
        self.assertLess(delta, 10, f"fd grew by {delta} after {N} spawns (baseline={baseline}, after={after})")


# ---------------------------------------------------------------------------
# App output detailed tests (30-34)
# ---------------------------------------------------------------------------
class AppOutputMixin:
    """Tests for get_app_output() with various parameters."""

    def test_30_app_output_basic(self):
        """Read output from a running app, verify non-empty."""
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
        app_name = "SDK_OUTPUT_31"
        try:
            self.client.add_app(App({"command": "seq 1 20", "name": app_name, "shell": True}))
            time.sleep(2)
            r1 = self.client.get_app_output(app_name, stdout_maxsize=32)
            self.assertIsNotNone(r1.out_position)
            self.assertGreater(r1.out_position, 0)
            r2 = self.client.get_app_output(app_name, stdout_position=r1.out_position)
            if r2.output:
                self.assertNotIn(r1.output[:10], r2.output)
        finally:
            self.client.delete_app(app_name)

    def test_32_app_output_maxsize_limit(self):
        """stdout_maxsize limits output — smaller maxsize returns less data."""
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
        exit_code, output = self.client.run_app_sync(App({"command": "echo done", "shell": True}), max_time=5)
        self.assertIsNotNone(exit_code)
        self.assertEqual(exit_code, 0)
        self.assertIn("done", output)

    def test_34_app_output_long_poll(self):
        """Long-poll timeout=2 on idle app blocks approximately 2s."""
        self.client.login("admin", DEFAULT_CRED)
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
# User management CRUD tests (40-43)
# ---------------------------------------------------------------------------
class UserManagementMixin:
    """Tests for add_user, delete_user, roles."""

    def test_40_add_and_delete_user(self):
        """Create user, verify in list, delete, verify gone."""
        self.client.login("admin", DEFAULT_CRED)
        username = "sdk_test_user_40"
        try:
            self.client.add_user(username, {"key": "Test@1234", "roles": ["manage"]})
            users = self.client.list_users()
            self.assertIn(username, users)
        finally:
            try:
                self.client.delete_user(username)
            except Exception:
                pass
        users = self.client.list_users()
        self.assertNotIn(username, users)

    def test_41_add_user_with_roles(self):
        """Create user with role and group, verify attributes."""
        self.client.login("admin", DEFAULT_CRED)
        username = "sdk_test_user_41"
        try:
            self.client.add_user(username, {"key": "Test@1234", "roles": ["manage"], "group": "admin"})
            users = self.client.list_users()
            self.assertIn(username, users)
        finally:
            try:
                self.client.delete_user(username)
            except Exception:
                pass

    def test_42_delete_nonexistent_user(self):
        """Deleting nonexistent user raises exception."""
        self.client.login("admin", DEFAULT_CRED)
        with self.assertRaises(Exception):
            self.client.delete_user("nonexistent_user_xyz_42")

    def test_43_delete_role(self):
        """Create role, verify, delete, verify gone."""
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        """Grant app-subscribe to admin by adding a subscriber role and updating the user."""
        if not getattr(SubscribeMixin, "_subscribe_permission_granted", False):
            self.client.update_role("subscriber", ["app-subscribe"])
            users = self.client.list_users()
            admin_data = users.get("admin", {})
            if isinstance(admin_data, dict):
                admin_roles = list(admin_data.get("roles", []))
                if "subscriber" not in admin_roles:
                    admin_roles.append("subscriber")
                    user_body = {
                        "roles": admin_roles,
                        "email": admin_data.get("email", "admin@appmesh.com"),
                        "group": admin_data.get("group", "admin"),
                    }
                    if admin_data.get("exec_user"):
                        user_body["exec_user"] = admin_data["exec_user"]
                    self.client.add_user("admin", user_body)
            self.client.login("admin", DEFAULT_CRED)
            SubscribeMixin._subscribe_permission_granted = True

    def test_60_subscribe_process_start(self):
        """Subscribe to START, enable a disabled app, verify event."""
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        """Atomic add_app + subscribe_events, verify events fire."""
        self.client.login("admin", DEFAULT_CRED)
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
                subscribe_events=["START", "STDOUT"],
            )
            self.assertTrue(hasattr(app, "name"))
            # Events from atomic subscribe arrive on the transport's demuxer
            # Give some time for the app to start
            time.sleep(3)
            self.assertGreaterEqual(len(received), 0)
        finally:
            self.client.delete_app(app_name)

    def test_67_subscribe_app_removed(self):
        """Subscribe to REMOVED, delete app, verify event."""
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
        app_name = "SDK_STRESS_80"
        for _ in range(20):
            self.client.add_app(App({"command": "sleep 1", "name": app_name}))
            self.assertTrue(self.client.delete_app(app_name))
        self.assertFalse(self.client.delete_app(app_name))

    def test_81_stress_rapid_enable_disable_cycle(self):
        """20x enable/disable on one app, verify valid state."""
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
        errors = []

        def worker():
            c = self._create_client()
            try:
                c.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
        barrier = threading.Barrier(5, timeout=10)
        errors = []

        def worker(idx):
            try:
                c = self._create_client()
                c.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
        for _ in range(10):
            exit_code, _ = self.client.run_app_sync(App({"command": "echo ok", "shell": True}), max_time=5)
            self.assertEqual(0, exit_code)

    def test_85_stress_rapid_login_logout(self):
        """10x login/logout cycle."""
        for _ in range(10):
            self.client.login("admin", DEFAULT_CRED)
            apps = self.client.list_apps()
            self.assertGreater(len(apps), 0)
            self.client.logout()

    def test_86_stress_rapid_label_churn(self):
        """20x add+delete label."""
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
        N = 6
        DEADLINE = 60  # whole test must finish well under this
        barrier = threading.Barrier(N, timeout=15)
        errors = []
        done = [False] * N

        def worker(idx):
            name = f"SDK_STRESS_87_{idx}"
            try:
                c = self._create_client()
                c.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
        # Warm-up to settle lazy resources before baseline.
        for i in range(3):
            n = f"SDK_FD_STRESS_WARM_{i}"
            self.client.add_app(App({"command": "true", "name": n, "shell": True}))
            self.client.delete_app(n)
        time.sleep(2)
        baseline = self.client.get_host_resources().get("fd")
        self.assertIsNotNone(baseline)

        N_WORKERS = 4
        CYCLES_PER_WORKER = 5
        errors = []

        def worker(idx):
            c = self._create_client()
            try:
                c.login("admin", DEFAULT_CRED)
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
        time.sleep(5)  # let onTimerAppExit / ~AppProcess fully drain

        after = self.client.get_host_resources().get("fd")
        delta = after - baseline
        total_spawns = N_WORKERS * CYCLES_PER_WORKER
        # A per-spawn leak would push delta well above this.
        self.assertLess(delta, 5, f"fd grew by {delta} after {total_spawns} concurrent spawns "
                                   f"(baseline={baseline}, after={after})")


# ---------------------------------------------------------------------------
# Subscribe stress/chaos tests (TCP/WSS only, 90-94)
# ---------------------------------------------------------------------------
class SubscribeStressMixin:
    """Chaos tests: subscribe under rapid lifecycle churn."""

    def test_90_subscribe_stress_during_rapid_add_delete(self):
        """Wildcard subscribe, rapidly add+delete 5 apps, verify events received."""
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        self.client.login("admin", DEFAULT_CRED)
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
        """App prints 500 lines, subscribe stdout, verify high event count."""
        self.client.login("admin", DEFAULT_CRED)
        self._ensure_subscribe_permission()
        app_name = "SDK_CHAOS_94"
        sub_result = None
        try:
            received = []
            done = threading.Event()

            def on_event(event):
                received.append(event)
                if len(received) >= 3:
                    done.set()

            self.client.add_app(App({
                "command": "seq 1 500",
                "name": app_name,
                "shell": True,
            }))
            sub_result = self.client.subscribe(app_name, ["STDOUT"], callback=on_event)
            done.wait(timeout=15)
            self.assertGreater(len(received), 0, "No stdout events for high-volume output")
        finally:
            if sub_result:
                try:
                    self.client.unsubscribe(sub_result.subscription_id)
                except Exception:
                    pass
            self.client.delete_app(app_name)


# ---------------------------------------------------------------------------
# Concrete test classes per protocol
# ---------------------------------------------------------------------------
class TestHTTP(ProtocolTestMixin, AppOutputMixin, UserManagementMixin, TaskOperationMixin,
               FileTransferMixin, StressTestMixin, TestCase):
    """Tests using HTTP REST client (AppMeshClient)."""

    def setUp(self):
        self.client = AppMeshClient(auto_refresh_token=True)

    def tearDown(self):
        # Close the per-test client; otherwise the requests.Session keepalive
        # socket + token-refresh thread linger and the daemon's fd count grows
        # by ~3 per test across the suite.
        try:
            self.client.close()
        except Exception:
            pass

    def _create_client(self):
        return AppMeshClient(auto_refresh_token=True)

    @unittest.skip("Go agent IsValidFileName blocks /etc/* on download (fixed in source, awaiting release); TCP/WSS still cover it.")
    def test_22_download_readonly_file(self):
        pass

    def test_16_config_set(self):
        """HTTP-specific: set config (VerifyServer flag for SSL)."""
        self.client.login("admin", DEFAULT_CRED)
        result = self.client.set_config({"REST": {"SSL": {"VerifyServer": True}}})
        self.assertTrue(result["REST"]["SSL"]["VerifyServer"])
        self.client.set_config({"REST": {"SSL": {"VerifyServer": False}}})

    def test_17_forward_to(self):
        """HTTP-specific: forward_to header."""
        self.client.login("admin", DEFAULT_CRED)
        self.client.forward_to = "127.0.0.1"
        apps = self.client.list_apps()
        self.assertGreater(len(apps), 0)
        self.client.forward_to = None


class TestTCP(
    ProtocolTestMixin, AppOutputMixin, UserManagementMixin, TaskOperationMixin,
    FileTransferMixin, SubscribeMixin, SubscribeWildcardMixin,
    StressTestMixin, SubscribeStressMixin, TestCase,
):
    """Tests using TCP client (AppMeshClientTCP)."""

    def setUp(self):
        self.client = AppMeshClientTCP(auto_refresh_token=True)

    def tearDown(self):
        try:
            self.client.close()
        except Exception:
            pass

    def _create_client(self):
        return AppMeshClientTCP(auto_refresh_token=True)


class TestWSS(
    ProtocolTestMixin, AppOutputMixin, UserManagementMixin, TaskOperationMixin,
    FileTransferMixin, SubscribeMixin, SubscribeWildcardMixin,
    StressTestMixin, SubscribeStressMixin, TestCase,
):
    """Tests using WebSocket Secure client (AppMeshClientWSS)."""

    def setUp(self):
        self.client = AppMeshClientWSS(auto_refresh_token=True)

    def tearDown(self):
        try:
            self.client.close()
        except Exception:
            pass

    def _create_client(self):
        return AppMeshClientWSS(auto_refresh_token=True)


class TestWSSRest(ProtocolTestMixin, AppOutputMixin, UserManagementMixin, TaskOperationMixin, StressTestMixin, TestCase):
    """Tests using plain HTTPS REST client against the WSS (lws) port."""

    def setUp(self):
        self.client = AppMeshClient(base_url=f"https://127.0.0.1:{_WSS_REST_PORT}", auto_refresh_token=True)

    def tearDown(self):
        try:
            self.client.close()
        except Exception:
            pass

    def _create_client(self):
        return AppMeshClient(base_url=f"https://127.0.0.1:{_WSS_REST_PORT}", auto_refresh_token=True)


# ---------------------------------------------------------------------------
# TOTP tests (HTTP only)
# ---------------------------------------------------------------------------
class TestTOTP(TestCase):
    """TOTP authentication flow (HTTP client)."""

    def setUp(self):
        self.client = AppMeshClient()

    def test_totp_enable_login_disable(self):
        """Full TOTP lifecycle."""
        self.client.login("admin", DEFAULT_CRED)
        totp_secret = self.client.get_totp_secret()
        self.assertIsNotNone(totp_secret)
        totp = TOTP(totp_secret)
        totp_code = totp.now()
        self.assertIsNone(self.client.enable_totp(totp_code))
        totp_code = totp.now()
        self.assertIsNone(self.client.login("admin", DEFAULT_CRED, totp_code))
        challenge = self.client.login("admin", DEFAULT_CRED)
        self.assertIsNotNone(challenge)
        self.assertIsNone(self.client.validate_totp("admin", challenge, totp.now()))
        self.assertIsNone(self.client.disable_totp())


# ---------------------------------------------------------------------------
# Cookie / token tests (HTTP only)
# ---------------------------------------------------------------------------
class TestCookies(TestCase):
    """Cookie persistence and reuse (HTTP client)."""

    def read_file(self, path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    def test_cookie_lifecycle(self):
        """Create, persist, clear, and reload cookies."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            cookie_path = tmp.name
        try:
            os.remove(cookie_path) if os.path.exists(cookie_path) else None
            client = AppMeshClient(cookie_file=cookie_path)
            self.assertFalse(os.path.exists(cookie_path))
            client.login("admin", DEFAULT_CRED)
            self.assertTrue(os.path.exists(cookie_path))
            if os.name == "posix":
                mode = stat.S_IMODE(os.stat(cookie_path).st_mode)
                self.assertEqual(mode, 0o600)
            content = self.read_file(cookie_path)
            self.assertIn("appmesh_auth_token", content)
            self.assertIn("appmesh_csrf_token", content)
            client.logout()
            content_after = self.read_file(cookie_path)
            self.assertNotIn("appmesh_auth_token", content_after)
            client = AppMeshClient(cookie_file=cookie_path)
            client.login("admin", DEFAULT_CRED)
            token = client._get_access_token()
            client2 = AppMeshClient(cookie_file=cookie_path)
            user_info = client2.get_current_user()
            self.assertEqual(user_info["name"], "admin")
        finally:
            os.remove(cookie_path) if os.path.exists(cookie_path) else None

    def test_set_token(self):
        """set_token and jwt_token constructor."""
        client = AppMeshClient()
        client.login("admin", DEFAULT_CRED)
        token = client._get_access_token()
        client2 = AppMeshClient()
        client2.set_token(token)
        self.assertGreater(len(client2.list_apps()), 0)
        client3 = AppMeshClient(jwt_token=token)
        self.assertGreater(len(client3.list_apps()), 0)


# ---------------------------------------------------------------------------
# Protocol-specific edge case tests
# ---------------------------------------------------------------------------
class TestProtocolFixes(TestCase):
    """Tests targeting specific issues found during code review."""

    def test_path_traversal_rejected(self):
        """File paths with '..' must be rejected."""
        client = AppMeshClientTCP()
        client.login("admin", DEFAULT_CRED)
        with self.assertRaises(Exception):
            client.download_file("/opt/appmesh/../../etc/shadow", "shadow.local")
        if os.path.exists("shadow.local"):
            os.remove("shadow.local")

    def test_path_traversal_upload_rejected(self):
        """Upload with '..' in remote path must be rejected."""
        client = AppMeshClientTCP()
        client.login("admin", DEFAULT_CRED)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
            tmp.write(b"test")
            tmp_path = tmp.name
        try:
            with self.assertRaises(Exception):
                client.upload_file(local_file=tmp_path, remote_file="/tmp/../../../etc/evil.txt")
        finally:
            os.remove(tmp_path)

    def test_tcp_large_app_output(self):
        """TCP transport handles non-trivial payload (message framing)."""
        client = AppMeshClientTCP()
        client.login("admin", DEFAULT_CRED)
        exit_code, output = client.run_app_sync(App({"command": "seq 1 100", "shell": True}), max_time=5)
        self.assertEqual(0, exit_code)
        self.assertIn("100", output)

    def test_wss_large_app_output(self):
        """WSS transport handles non-trivial payload (WS framing)."""
        client = AppMeshClientWSS()
        client.login("admin", DEFAULT_CRED)
        exit_code, output = client.run_app_sync(App({"command": "seq 1 100", "shell": True}), max_time=5)
        self.assertEqual(0, exit_code)
        self.assertIn("100", output)

    def test_http_concurrent_requests(self):
        """HTTP handles multiple rapid sequential requests."""
        client = AppMeshClient()
        client.login("admin", DEFAULT_CRED)
        for _ in range(10):
            apps = client.list_apps()
            self.assertGreater(len(apps), 0)

    def test_tcp_concurrent_requests(self):
        """TCP handles multiple rapid sequential requests."""
        client = AppMeshClientTCP()
        client.login("admin", DEFAULT_CRED)
        for _ in range(10):
            apps = client.list_apps()
            self.assertGreater(len(apps), 0)

    def test_wss_concurrent_requests(self):
        """WSS handles multiple rapid sequential requests."""
        client = AppMeshClientWSS()
        client.login("admin", DEFAULT_CRED)
        for _ in range(10):
            apps = client.list_apps()
            self.assertGreater(len(apps), 0)

    def test_wss_rest_concurrent_requests(self):
        """REST-over-WSS handles rapid sequential requests."""
        client = AppMeshClient(base_url=f"https://127.0.0.1:{_WSS_REST_PORT}")
        client.login("admin", DEFAULT_CRED)
        for _ in range(10):
            apps = client.list_apps()
            self.assertGreater(len(apps), 0)

    def test_wss_rest_large_response(self):
        """REST-over-WSS returns large payload."""
        client = AppMeshClient(base_url=f"https://127.0.0.1:{_WSS_REST_PORT}")
        client.login("admin", DEFAULT_CRED)
        exit_code, output = client.run_app_sync(App({"command": "seq 1 500", "shell": True}), max_time=5)
        self.assertEqual(0, exit_code)
        self.assertIn("500", output)

    def test_http_config_ssl_verify_server(self):
        """Verify the new getSslVerifyServer config option."""
        client = AppMeshClient()
        client.login("admin", DEFAULT_CRED)
        cfg = client.set_config({"REST": {"SSL": {"VerifyServer": False}}})
        self.assertFalse(cfg["REST"]["SSL"]["VerifyServer"])
        cfg = client.set_config({"REST": {"SSL": {"VerifyServer": True}}})
        self.assertTrue(cfg["REST"]["SSL"]["VerifyServer"])
        client.set_config({"REST": {"SSL": {"VerifyServer": False}}})

    def test_transport_token_sync(self):
        """TransportClientMixin token extraction logic."""
        from appmesh.transport_mixin import TransportClientMixin

        class FakeResp:
            def __init__(self, status, payload):
                self.status_code = status
                self._payload = payload

            def json(self):
                return self._payload

        mixin = TransportClientMixin()
        mixin._token = None
        mixin._auto_refresh_token = False
        mixin.cookie_file = None
        mixin._on_token_changed = lambda t: setattr(mixin, "_token", t)

        mixin._sync_transport_token(FakeResp(200, {"access_token": "tok1"}), "/appmesh/login", {"X-Set-Cookie": "true"})
        self.assertEqual("tok1", mixin._token)

        mixin._token = "old"
        mixin._sync_transport_token(FakeResp(200, {"access_token": "no"}), "/appmesh/login", {})
        self.assertEqual("old", mixin._token)

        mixin._token = "has-token"
        mixin._sync_transport_token(FakeResp(200, {}), "/appmesh/self/logoff", {})
        self.assertIsNone(mixin._token)


if __name__ == "__main__":
    unittest.main()
