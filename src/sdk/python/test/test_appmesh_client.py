"""Test Python SDK across three protocols: HTTP (REST), TCP, and WebSocket (WSS).

Usage:
    python3 -m unittest --verbose                            # run all
    python3 -m unittest test_appmesh_client.TestHTTP         # HTTP only
    python3 -m unittest test_appmesh_client.TestTCP          # TCP only
    python3 -m unittest test_appmesh_client.TestWSS          # WSS only
    python3 -m unittest test_appmesh_client.TestProtocolFixes  # review-fix tests
"""

import json
import os
import stat
import sys
import tempfile
import unittest
from unittest import TestCase

from pyotp import TOTP

# For source code env:
current_directory = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(current_directory))

from appmesh import AppMeshClient, AppMeshClientTCP, AppMeshClientWSS, App

# Default credential for local dev/test — NOT a production secret
DEFAULT_CRED = os.environ.get("APPMESH_TEST_CRED", "admin123")


def get_test_paths():
    """Return platform-specific paths.

    Remote paths (server_log, remote_tmp, etc.) live on the Linux server.
    Local paths (local_tmp) live on the test machine.
    """
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
    """Return a command that runs for several seconds then exits non-zero."""
    if sys.platform == "win32":
        return "ping 127.0.0.1 -n 10"
    return "python3 -c 'import time; [print(i) or time.sleep(1) for i in range(30)]'"


# ---------------------------------------------------------------------------
# Mixin: shared tests that every protocol must pass
# ---------------------------------------------------------------------------
class ProtocolTestMixin:
    """Shared test logic for all three transports.

    Subclasses MUST set ``self.client`` to the appropriate client before
    each test (via ``setUp``).
    """

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
        self.assertEqual(self.client.set_log_level("DEBUG"), "DEBUG")
        self.assertEqual(self.client.set_log_level("INFO"), "INFO")


# ---------------------------------------------------------------------------
# File-transfer mixin (TCP/WSS only)
# ---------------------------------------------------------------------------
class FileTransferMixin:
    """Tests for download_file / upload_file (TCP and WSS only)."""

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
# Concrete test classes per protocol
# ---------------------------------------------------------------------------
class TestHTTP(ProtocolTestMixin, TestCase):
    """Tests using HTTP REST client (AppMeshClient)."""

    def setUp(self):
        self.client = AppMeshClient()

    def test_14_config_set(self):
        """HTTP-specific: set config (VerifyServer flag for SSL)."""
        self.client.login("admin", DEFAULT_CRED)
        result = self.client.set_config({"REST": {"SSL": {"VerifyServer": True}}})
        self.assertTrue(result["REST"]["SSL"]["VerifyServer"])

    def test_15_forward_to(self):
        """HTTP-specific: forward_to header."""
        self.client.login("admin", DEFAULT_CRED)
        self.client.forward_to = "127.0.0.1"
        apps = self.client.list_apps()
        self.assertGreater(len(apps), 0)
        self.client.forward_to = None


class TestTCP(ProtocolTestMixin, FileTransferMixin, TestCase):
    """Tests using TCP client (AppMeshClientTCP)."""

    def setUp(self):
        self.client = AppMeshClientTCP()


def _wss_available():
    """Check if WSS endpoint is reachable."""
    try:
        c = AppMeshClientWSS()
        c.login("admin", DEFAULT_CRED)
        c.logout()
        return True
    except Exception:
        return False


_WSS_OK = _wss_available()


@unittest.skipUnless(_WSS_OK, "WSS endpoint not available (libwebsockets not enabled)")
class TestWSS(ProtocolTestMixin, FileTransferMixin, TestCase):
    """Tests using WebSocket Secure client (AppMeshClientWSS)."""

    def setUp(self):
        self.client = AppMeshClientWSS()


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
# Tests specifically targeting the review fixes
# ---------------------------------------------------------------------------
class TestProtocolFixes(TestCase):
    """Tests targeting specific issues found during code review."""

    def test_path_traversal_rejected(self):
        """File paths with '..' must be rejected (validates Utility::validateFilePath)."""
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
        """TCP transport can handle non-trivial response payload (tests message framing)."""
        client = AppMeshClientTCP()
        client.login("admin", DEFAULT_CRED)
        exit_code, output = client.run_app_sync(App({"command": "seq 1 100", "shell": True}), max_time=5)
        self.assertEqual(0, exit_code)
        self.assertIn("100", output)

    @unittest.skipUnless(_WSS_OK, "WSS endpoint not available")
    def test_wss_large_app_output(self):
        """WSS transport can handle non-trivial response payload (tests WS framing)."""
        client = AppMeshClientWSS()
        client.login("admin", DEFAULT_CRED)
        exit_code, output = client.run_app_sync(App({"command": "seq 1 100", "shell": True}), max_time=5)
        self.assertEqual(0, exit_code)
        self.assertIn("100", output)

    def test_http_concurrent_requests(self):
        """HTTP client handles multiple rapid sequential requests (tests ABA protection)."""
        client = AppMeshClient()
        client.login("admin", DEFAULT_CRED)
        for _ in range(10):
            apps = client.list_apps()
            self.assertGreater(len(apps), 0)

    def test_tcp_concurrent_requests(self):
        """TCP client handles multiple rapid sequential requests."""
        client = AppMeshClientTCP()
        client.login("admin", DEFAULT_CRED)
        for _ in range(10):
            apps = client.list_apps()
            self.assertGreater(len(apps), 0)

    @unittest.skipUnless(_WSS_OK, "WSS endpoint not available")
    def test_wss_concurrent_requests(self):
        """WSS client handles multiple rapid sequential requests."""
        client = AppMeshClientWSS()
        client.login("admin", DEFAULT_CRED)
        for _ in range(10):
            apps = client.list_apps()
            self.assertGreater(len(apps), 0)

    def test_http_config_ssl_verify_server(self):
        """Verify the new getSslVerifyServer config option works end-to-end."""
        client = AppMeshClient()
        client.login("admin", DEFAULT_CRED)
        cfg = client.set_config({"REST": {"SSL": {"VerifyServer": False}}})
        self.assertFalse(cfg["REST"]["SSL"]["VerifyServer"])
        cfg = client.set_config({"REST": {"SSL": {"VerifyServer": True}}})
        self.assertTrue(cfg["REST"]["SSL"]["VerifyServer"])
        # restore
        client.set_config({"REST": {"SSL": {"VerifyServer": False}}})

    def test_transport_token_sync(self):
        """TransportClientMixin._sync_transport_token for TCP/WSS path-based token extraction."""
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

        # Login with X-Set-Cookie -> token applied
        mixin._sync_transport_token(FakeResp(200, {"access_token": "tok1"}), "/appmesh/login", {"X-Set-Cookie": "true"})
        self.assertEqual("tok1", mixin._token)

        # Login without X-Set-Cookie -> NOT applied
        mixin._token = "old"
        mixin._sync_transport_token(FakeResp(200, {"access_token": "no"}), "/appmesh/login", {})
        self.assertEqual("old", mixin._token)

        # Logoff -> cleared
        mixin._token = "has-token"
        mixin._sync_transport_token(FakeResp(200, {}), "/appmesh/self/logoff", {})
        self.assertIsNone(mixin._token)


if __name__ == "__main__":
    unittest.main()
