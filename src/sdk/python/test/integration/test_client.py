"""App Mesh client integration tests across four transports (HTTP/TCP/WSS/REST-over-WSS).

Requires a running daemon. The shared test bodies live in
``_support/client_mixins.py``; this module composes them onto concrete
per-transport TestCase classes plus the HTTP-only TOTP/cookie/protocol-fix tests.

Usage:
    python3 -m unittest integration.test_client                 # all
    python3 -m unittest integration.test_client.TestHTTP        # HTTP only
    python3 -m unittest integration.test_client.TestTCP         # TCP only
    python3 -m unittest integration.test_client.TestWSS         # WSS only
    python3 -m unittest integration.test_client.TestWSSRest     # REST-over-WSS
"""
import os
import stat
import sys
import tempfile
import unittest
from unittest import TestCase

from pyotp import TOTP

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..")))        # test/  -> _support package
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "..")))  # src/sdk/python -> appmesh
from appmesh import AppMeshClient, AppMeshClientTCP, AppMeshClientWSS, App
from _support import ssl_shim  # noqa: F401  # APPMESH_TEST_SSL_VERIFY override for self-signed daemons
from _support import config
from _support.client_mixins import (
    ProtocolTestMixin,
    AppOutputMixin,
    UserManagementMixin,
    TaskOperationMixin,
    FileTransferMixin,
    SubscribeMixin,
    SubscribeWildcardMixin,
    StressTestMixin,
    SubscribeStressMixin,
)

USER = config.USER
DEFAULT_CRED = config.CRED
_WSS_REST_PORT = config.WSS_REST_PORT


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
        self.client.login(USER, DEFAULT_CRED)
        result = self.client.set_config({"REST": {"SSL": {"VerifyServer": True}}})
        self.assertTrue(result["REST"]["SSL"]["VerifyServer"])
        self.client.set_config({"REST": {"SSL": {"VerifyServer": False}}})

    def test_17_forward_to(self):
        """HTTP-specific: forward_to header."""
        self.client.login(USER, DEFAULT_CRED)
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
        self.client.login(USER, DEFAULT_CRED)
        totp_secret = self.client.get_totp_secret()
        self.assertIsNotNone(totp_secret)
        totp = TOTP(totp_secret)
        totp_code = totp.now()
        self.assertIsNone(self.client.enable_totp(totp_code))
        totp_code = totp.now()
        self.assertIsNone(self.client.login(USER, DEFAULT_CRED, totp_code))
        challenge = self.client.login(USER, DEFAULT_CRED)
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
            client.login(USER, DEFAULT_CRED)
            self.assertTrue(os.path.exists(cookie_path))
            if os.name == "posix":
                mode = stat.S_IMODE(os.stat(cookie_path).st_mode)
                self.assertEqual(mode, 0o600)
            content = self.read_file(cookie_path)
            self.assertIn("appmesh_auth_token", content)
            client.logout()
            content_after = self.read_file(cookie_path)
            self.assertNotIn("appmesh_auth_token", content_after)
            client = AppMeshClient(cookie_file=cookie_path)
            client.login(USER, DEFAULT_CRED)
            client2 = AppMeshClient(cookie_file=cookie_path)
            user_info = client2.get_current_user()
            self.assertEqual(user_info["name"], "admin")
        finally:
            os.remove(cookie_path) if os.path.exists(cookie_path) else None

    def test_set_token(self):
        """set_token and jwt_token constructor."""
        client = AppMeshClient()
        client.login(USER, DEFAULT_CRED)
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
        client.login(USER, DEFAULT_CRED)
        with self.assertRaises(Exception):
            client.download_file("/opt/appmesh/../../etc/shadow", "shadow.local")
        if os.path.exists("shadow.local"):
            os.remove("shadow.local")

    def test_path_traversal_upload_rejected(self):
        """Upload with '..' in remote path must be rejected."""
        client = AppMeshClientTCP()
        client.login(USER, DEFAULT_CRED)
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
        client.login(USER, DEFAULT_CRED)
        exit_code, output = client.run_app_sync(App({"command": "seq 1 100", "shell": True}), max_time=5)
        self.assertEqual(0, exit_code)
        self.assertIn("100", output)

    def test_wss_large_app_output(self):
        """WSS transport handles non-trivial payload (WS framing)."""
        client = AppMeshClientWSS()
        client.login(USER, DEFAULT_CRED)
        exit_code, output = client.run_app_sync(App({"command": "seq 1 100", "shell": True}), max_time=5)
        self.assertEqual(0, exit_code)
        self.assertIn("100", output)

    def test_http_concurrent_requests(self):
        """HTTP handles multiple rapid sequential requests."""
        client = AppMeshClient()
        client.login(USER, DEFAULT_CRED)
        for _ in range(10):
            apps = client.list_apps()
            self.assertGreater(len(apps), 0)

    def test_tcp_concurrent_requests(self):
        """TCP handles multiple rapid sequential requests."""
        client = AppMeshClientTCP()
        client.login(USER, DEFAULT_CRED)
        for _ in range(10):
            apps = client.list_apps()
            self.assertGreater(len(apps), 0)

    def test_wss_concurrent_requests(self):
        """WSS handles multiple rapid sequential requests."""
        client = AppMeshClientWSS()
        client.login(USER, DEFAULT_CRED)
        for _ in range(10):
            apps = client.list_apps()
            self.assertGreater(len(apps), 0)

    def test_wss_rest_concurrent_requests(self):
        """REST-over-WSS handles rapid sequential requests."""
        client = AppMeshClient(base_url=f"https://127.0.0.1:{_WSS_REST_PORT}")
        client.login(USER, DEFAULT_CRED)
        for _ in range(10):
            apps = client.list_apps()
            self.assertGreater(len(apps), 0)

    def test_wss_rest_large_response(self):
        """REST-over-WSS returns large payload."""
        client = AppMeshClient(base_url=f"https://127.0.0.1:{_WSS_REST_PORT}")
        client.login(USER, DEFAULT_CRED)
        exit_code, output = client.run_app_sync(App({"command": "seq 1 500", "shell": True}), max_time=5)
        self.assertEqual(0, exit_code)
        self.assertIn("500", output)

    def test_http_config_ssl_verify_server(self):
        """Verify the new getSslVerifyServer config option."""
        client = AppMeshClient()
        client.login(USER, DEFAULT_CRED)
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
