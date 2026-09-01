"""App Mesh client integration tests across four transports (HTTP/TCP/WSS/REST-over-WSS).

Requires a running daemon. The shared test bodies live in
``_support/client_mixins.py``; this module composes them onto concrete
per-transport TestCase classes plus protocol-specific edge-case tests.

Usage:
    python3 -m unittest integration.test_client                 # all
    python3 -m unittest integration.test_client.TestHTTP        # HTTP only
    python3 -m unittest integration.test_client.TestTCP         # TCP only
    python3 -m unittest integration.test_client.TestWSS         # WSS only
    python3 -m unittest integration.test_client.TestWSSRest     # REST-over-WSS
"""
import os
import sys
import tempfile
import unittest
from unittest import TestCase

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..")))        # test/  -> _support package
sys.path.insert(0, os.path.abspath(os.path.join(_HERE, "..", "..")))  # src/sdk/python -> appmesh
from appmesh import AppMeshClient, AppMeshClientTCP, AppMeshClientWSS, App
from _support import ssl_shim  # noqa: F401  # APPMESH_TEST_SSL_VERIFY override for self-signed daemons
from _support import config
from _support.client_mixins import (
    ProtocolTestMixin,
    AppOutputMixin,
    PrincipalManagementMixin,
    TaskOperationMixin,
    FileTransferMixin,
    SubscribeMixin,
    SubscribeWildcardMixin,
    StressTestMixin,
    SubscribeStressMixin,
)

_WSS_REST_PORT = config.WSS_REST_PORT


# ---------------------------------------------------------------------------
class TestHTTP(ProtocolTestMixin, AppOutputMixin, PrincipalManagementMixin, TaskOperationMixin,
               FileTransferMixin, StressTestMixin, TestCase):
    """Tests using HTTP REST client (AppMeshClient)."""

    def setUp(self):
        self.client = AppMeshClient()

    def tearDown(self):
        # Close the per-test client; otherwise the requests.Session keepalive
        # socket + token-refresh thread linger and the daemon's fd count grows
        # by ~3 per test across the suite.
        try:
            self.client.close()
        except Exception:
            pass

    def _create_client(self):
        return AppMeshClient()

    @unittest.skip("Go agent IsValidFileName blocks /etc/* on download (fixed in source, awaiting release); TCP/WSS still cover it.")
    def test_22_download_readonly_file(self):
        pass

    def test_16_config_set(self):
        """HTTP-specific: set config (VerifyServer flag for SSL)."""
        config.attach_test_bearer(self.client)
        result = self.client.set_config({"REST": {"SSL": {"VerifyServer": True}}})
        self.assertTrue(result["REST"]["SSL"]["VerifyServer"])
        self.client.set_config({"REST": {"SSL": {"VerifyServer": False}}})

    def test_17_forward_to(self):
        """HTTP-specific: forward_to header."""
        config.attach_test_bearer(self.client)
        self.client.forward_to = "127.0.0.1"
        apps = self.client.list_apps()
        self.assertGreater(len(apps), 0)
        self.client.forward_to = None


class TestTCP(
    ProtocolTestMixin, AppOutputMixin, PrincipalManagementMixin, TaskOperationMixin,
    FileTransferMixin, SubscribeMixin, SubscribeWildcardMixin,
    StressTestMixin, SubscribeStressMixin, TestCase,
):
    """Tests using TCP client (AppMeshClientTCP)."""

    def setUp(self):
        self.client = AppMeshClientTCP()

    def tearDown(self):
        try:
            self.client.close()
        except Exception:
            pass

    def _create_client(self):
        return AppMeshClientTCP()


class TestWSS(
    ProtocolTestMixin, AppOutputMixin, PrincipalManagementMixin, TaskOperationMixin,
    FileTransferMixin, SubscribeMixin, SubscribeWildcardMixin,
    StressTestMixin, SubscribeStressMixin, TestCase,
):
    """Tests using WebSocket Secure client (AppMeshClientWSS)."""

    def setUp(self):
        self.client = AppMeshClientWSS()

    def tearDown(self):
        try:
            self.client.close()
        except Exception:
            pass

    def _create_client(self):
        return AppMeshClientWSS()


class TestWSSRest(ProtocolTestMixin, AppOutputMixin, PrincipalManagementMixin, TaskOperationMixin, StressTestMixin, TestCase):
    """Tests using plain HTTPS REST client against the WSS (lws) port."""

    def setUp(self):
        self.client = AppMeshClient(base_url=f"https://127.0.0.1:{_WSS_REST_PORT}")

    def tearDown(self):
        try:
            self.client.close()
        except Exception:
            pass

    def _create_client(self):
        return AppMeshClient(base_url=f"https://127.0.0.1:{_WSS_REST_PORT}")


# ---------------------------------------------------------------------------
# Protocol-specific edge case tests
# ---------------------------------------------------------------------------
class TestProtocolFixes(TestCase):
    """Tests targeting specific issues found during code review."""

    def test_path_traversal_rejected(self):
        """File paths with '..' must be rejected."""
        client = AppMeshClientTCP()
        config.attach_test_bearer(client)
        with self.assertRaises(Exception):
            client.download_file("/opt/appmesh/../../etc/shadow", "shadow.local")
        if os.path.exists("shadow.local"):
            os.remove("shadow.local")

    def test_path_traversal_upload_rejected(self):
        """Upload with '..' in remote path must be rejected."""
        client = AppMeshClientTCP()
        config.attach_test_bearer(client)
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
        config.attach_test_bearer(client)
        exit_code, output = client.run_app_sync(App({"command": "seq 1 100", "shell": True}), max_time=5)
        self.assertEqual(0, exit_code)
        self.assertIn("100", output)

    def test_wss_large_app_output(self):
        """WSS transport handles non-trivial payload (WS framing)."""
        client = AppMeshClientWSS()
        config.attach_test_bearer(client)
        exit_code, output = client.run_app_sync(App({"command": "seq 1 100", "shell": True}), max_time=5)
        self.assertEqual(0, exit_code)
        self.assertIn("100", output)

    def test_http_concurrent_requests(self):
        """HTTP handles multiple rapid sequential requests."""
        client = AppMeshClient()
        config.attach_test_bearer(client)
        for _ in range(10):
            apps = client.list_apps()
            self.assertGreater(len(apps), 0)

    def test_tcp_concurrent_requests(self):
        """TCP handles multiple rapid sequential requests."""
        client = AppMeshClientTCP()
        config.attach_test_bearer(client)
        for _ in range(10):
            apps = client.list_apps()
            self.assertGreater(len(apps), 0)

    def test_wss_concurrent_requests(self):
        """WSS handles multiple rapid sequential requests."""
        client = AppMeshClientWSS()
        config.attach_test_bearer(client)
        for _ in range(10):
            apps = client.list_apps()
            self.assertGreater(len(apps), 0)

    def test_wss_rest_concurrent_requests(self):
        """REST-over-WSS handles rapid sequential requests."""
        client = AppMeshClient(base_url=f"https://127.0.0.1:{_WSS_REST_PORT}")
        config.attach_test_bearer(client)
        for _ in range(10):
            apps = client.list_apps()
            self.assertGreater(len(apps), 0)

    def test_wss_rest_large_response(self):
        """REST-over-WSS returns large payload."""
        client = AppMeshClient(base_url=f"https://127.0.0.1:{_WSS_REST_PORT}")
        config.attach_test_bearer(client)
        exit_code, output = client.run_app_sync(App({"command": "seq 1 500", "shell": True}), max_time=5)
        self.assertEqual(0, exit_code)
        self.assertIn("500", output)

    def test_http_config_ssl_verify_server(self):
        """Verify the new getSslVerifyServer config option."""
        client = AppMeshClient()
        config.attach_test_bearer(client)
        cfg = client.set_config({"REST": {"SSL": {"VerifyServer": False}}})
        self.assertFalse(cfg["REST"]["SSL"]["VerifyServer"])
        cfg = client.set_config({"REST": {"SSL": {"VerifyServer": True}}})
        self.assertTrue(cfg["REST"]["SSL"]["VerifyServer"])
        client.set_config({"REST": {"SSL": {"VerifyServer": False}}})

if __name__ == "__main__":
    unittest.main()
