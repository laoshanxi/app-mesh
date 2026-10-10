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
import threading
import time
import unittest
from unittest import TestCase

import requests
from urllib.parse import urlsplit

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

    def test_17_forward_to(self):
        """A forwarded request reaches the peer over the daemon's own transport.

        The client speaks WSS to this daemon; the daemon's forwarding hop to
        the peer is TCP (msgpack over TLS), and a bare host resolves to the
        peer's TCP API port.
        """
        config.attach_test_bearer(self.client)
        try:
            self.client.forward_to = "127.0.0.1"
            apps = self.client.list_apps()
            self.assertGreater(len(apps), 0)
        finally:
            self.client.forward_to = None

    def test_19_forwarded_subscription(self):
        """A subscription registered through a forwarded hop receives its events.

        The peer pushes events back on the same connection the request arrived
        on, so this pins the reverse route, not just request/response.
        """
        config.attach_test_bearer(self.client)
        self.assertIn("app-subscribe", self.client.get_principal_permissions())
        app_name = "SDK_FWD_19"
        sub_result = None
        try:
            self.client.add_app(App({"command": "sleep 30", "name": app_name, "enabled": 0}))
            received = []
            barrier = threading.Event()

            def on_event(event):
                received.append(event)
                barrier.set()

            self.client.forward_to = "127.0.0.1"
            sub_result = self.client.subscribe(app_name, ["START"], callback=on_event)
            self.assertTrue(sub_result.subscription_id)
            self.client.enable_app(app_name)
            self.assertTrue(barrier.wait(timeout=15), "forwarded START event not received")
            self.assertEqual(received[0].app_name, app_name)
        finally:
            if sub_result:
                try:
                    self.client.unsubscribe(sub_result.subscription_id)
                except Exception:
                    pass
            # The app and the subscription live behind the hop: keep the target
            # set until both are cleaned up.
            self.client.delete_app(app_name)
            self.client.forward_to = None

    def test_20_forwarded_hop_survives_idle(self):
        """An idle forwarded hop stays pooled long enough to deliver an event.

        The forwarding hop is a pooled TCP connection that carries no traffic
        while a subscription waits; if an idle hop were dropped or left
        unusable, a forwarded subscription would be silently lost.
        """
        config.attach_test_bearer(self.client)
        self.assertIn("app-subscribe", self.client.get_principal_permissions())
        app_name = "SDK_FWD_20"
        sub_result = None
        idle_seconds = 90
        try:
            self.client.add_app(App({"command": "sleep 30", "name": app_name, "enabled": 0}))
            received = []
            barrier = threading.Event()

            def on_event(event):
                received.append(event)
                barrier.set()

            self.client.forward_to = "127.0.0.1"
            sub_result = self.client.subscribe(app_name, ["START"], callback=on_event)
            self.assertTrue(sub_result.subscription_id)

            time.sleep(idle_seconds)

            self.client.enable_app(app_name)
            self.assertTrue(barrier.wait(timeout=15),
                            "event lost after {}s of idle on the forwarded hop".format(idle_seconds))
            self.assertEqual(received[0].app_name, app_name)
        finally:
            if sub_result:
                try:
                    self.client.unsubscribe(sub_result.subscription_id)
                except Exception:
                    pass
            self.client.delete_app(app_name)
            self.client.forward_to = None


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

# ---------------------------------------------------------------------------
# The unauthenticated surface must not disclose the running release
# ---------------------------------------------------------------------------
class TestUnauthenticatedSurface(TestCase):
    """Public responses must not reveal version information.

    A version string lets an unauthenticated client match a deployment against
    known CVEs, so the routes served without a bearer (public pages, discovery,
    the API document, the error paths and the metrics endpoints) must stay free
    of the product version and of the HTTP framework banner, in both headers
    and bodies.
    """

    _PUBLIC_REQUESTS = (
        ("GET", "/"),
        ("GET", "/index.html"),
        ("GET", "/swagger/"),
        ("GET", "/openapi.yaml"),
        ("GET", "/appmesh/logo.svg"),
        ("GET", "/appmesh/favicon.png"),
        ("GET", "/oauth/callback"),
        ("GET", "/appmesh/auth/config"),
        ("GET", "/.well-known/oauth-protected-resource"),
        ("GET", "/appmesh/metrics"),
        ("GET", "/metrics"),
        ("GET", "/no-such-route"),
        ("GET", "/appmesh/applications"),
        ("OPTIONS", "/appmesh/applications"),
        ("FOO", "/appmesh/applications"),
    )

    def setUp(self):
        self.client = AppMeshClient()
        config.attach_test_bearer(self.client)

    def tearDown(self):
        try:
            self.client.close()
        except Exception:
            pass

    def _product_version(self):
        """Version part of the release build tag: <project>_<version>_<build date>."""
        build_tag = self.client.get_config()["Version"]
        self.assertTrue(build_tag.startswith("appmesh_"), build_tag)
        return build_tag[len("appmesh_"):].rsplit("_", 1)[0]

    def _entries(self):
        """Client entry (agent) plus the daemon listener behind it."""
        parsed = urlsplit(self.client.base_url)
        direct = "{}://{}:{}".format(parsed.scheme, parsed.hostname, _WSS_REST_PORT)
        return sorted({self.client.base_url, direct})

    def _request(self, method, entry, path):
        """Send one request with no Authorization header."""
        return requests.request(
            method, entry + path, timeout=10, allow_redirects=False,
            verify=AppMeshClient._resolve_ssl_verify(None))

    @staticmethod
    def _surface(response):
        """Everything the client sees: response headers plus body."""
        headers = "\n".join("{}: {}".format(k, v) for k, v in response.headers.items())
        return headers + "\n" + response.text

    def test_public_surface_hides_versions(self):
        version = self._product_version()
        for entry in self._entries():
            for method, path in self._PUBLIC_REQUESTS:
                response = self._request(method, entry, path)
                where = "{} {} -> {}".format(method, entry + path, response.status_code)
                surface = self._surface(response)
                self.assertNotIn("server", [name.lower() for name in response.headers],
                                 "framework banner header on " + where)
                for framework in ("drogon", "libwebsockets"):
                    self.assertNotIn(framework, surface.lower(), framework + " name on " + where)
                self.assertNotIn(version, surface, "product version on " + where)

    def test_metrics_need_no_token(self):
        """A standard exporter scrape: /metrics answers without a bearer."""
        for entry in self._entries():
            for path in ("/metrics", "/appmesh/metrics"):
                response = self._request("GET", entry, path)
                self.assertEqual(
                    200, response.status_code,
                    "{} without a token -> {}".format(entry + path, response.status_code))


if __name__ == "__main__":
    unittest.main()
