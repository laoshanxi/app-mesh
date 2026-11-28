"""Unit coverage for node forwarding on the streaming (SSE) side channel."""

import unittest
from unittest import mock

import requests
from requests.structures import CaseInsensitiveDict

from appmesh.client_http import AppMeshClient
from appmesh.client_tcp import AppMeshClientTCP
from appmesh.client_wss import AppMeshClientWSS
from appmesh.exceptions import AppMeshRequestError

TASK_STREAM = "/appmesh/app/worker/task/stream"
OUTPUT_STREAM = "/appmesh/app/worker/output/stream"


def _sse_response() -> requests.Response:
    """A complete task stream: one final frame and the terminal end frame."""
    resp = requests.Response()
    resp.status_code = 200
    resp.headers = CaseInsensitiveDict({"Content-Type": "text/event-stream"})
    resp._content = b'event: final\ndata: {"result": "node-b"}\n\nevent: end\ndata: {"reason": "final"}\n\n'
    resp._content_consumed = True
    return resp


def _collect(generator):
    """Drain a generator and return its StopIteration value (list() would drop it)."""
    while True:
        try:
            next(generator)
        except StopIteration as stop:
            return stop.value


class TestFramedStreamForwarding(unittest.TestCase):
    """TCP/WSS clients send framed requests with X-Target-Host but stream over a
    direct HTTPS side channel. A forwarded stream must dial the agent REST listener
    with the same target: dialing the engine listener without it ran the task on
    the local node while the caller believed it ran on the target."""

    def _client(self, cls, **kwargs):
        client = cls(**kwargs)
        client._get_bearer_token = mock.Mock(return_value="token")
        return client

    def test_tcp_forwarded_task_stream_dials_agent_port(self):
        client = self._client(AppMeshClientTCP, tcp_address=("gateway.local", 6062), ssl_verify=False)
        client.forward_to = "appmesh_slave1"
        with mock.patch.object(client.session, "post", return_value=_sse_response()) as post:
            end = _collect(client.run_task_stream("worker", "payload"))
        self.assertEqual(end.result, "node-b")
        self.assertEqual(post.call_args.kwargs["url"], f"https://gateway.local:6060{TASK_STREAM}")
        self.assertEqual(post.call_args.kwargs["params"], {"timeout": "300"})
        self.assertEqual(post.call_args.kwargs["headers"]["X-Target-Host"], "appmesh_slave1")
        self.assertEqual(post.call_args.kwargs["headers"]["Authorization"], "Bearer token")

    def test_wss_forwarded_output_stream_dials_agent_port(self):
        client = self._client(AppMeshClientWSS, wss_address=("gateway.local", 6063), ssl_verify=False)
        client.forward_to = "appmesh_slave1"
        with mock.patch.object(client.session, "get", return_value=_sse_response()) as get:
            _collect(client.follow_output("worker", follow=False))
        self.assertEqual(get.call_args.kwargs["url"], f"https://gateway.local:6060{OUTPUT_STREAM}")
        self.assertEqual(get.call_args.kwargs["params"]["follow"], "false")
        self.assertEqual(get.call_args.kwargs["headers"]["X-Target-Host"], "appmesh_slave1")

    def test_local_stream_keeps_engine_listener_and_sends_no_target(self):
        for cls, kwargs, method, path in (
            (AppMeshClientTCP, {"tcp_address": ("gateway.local", 6062)}, "post", TASK_STREAM),
            (AppMeshClientWSS, {"wss_address": ("gateway.local", 6063)}, "get", OUTPUT_STREAM),
        ):
            with self.subTest(cls=cls.__name__):
                client = self._client(cls, ssl_verify=False, **kwargs)
                with mock.patch.object(client.session, method, return_value=_sse_response()) as call:
                    if method == "post":
                        _collect(client.run_task_stream("worker", "payload"))
                    else:
                        _collect(client.follow_output("worker", follow=False))
                self.assertEqual(call.call_args.kwargs["url"], f"https://gateway.local:6063{path}")
                self.assertNotIn("X-Target-Host", call.call_args.kwargs["headers"])

    def test_agent_port_is_configurable(self):
        client = self._client(AppMeshClientTCP, tcp_address=("gateway.local", 6062), ssl_verify=False, agent_port=7060)
        client.forward_to = "appmesh_slave1"
        with mock.patch.object(client.session, "post", return_value=_sse_response()) as post:
            _collect(client.run_task_stream("worker", "payload"))
        self.assertEqual(post.call_args.kwargs["url"], f"https://gateway.local:7060{TASK_STREAM}")

    def test_unreachable_target_fails_the_stream(self):
        """The agent answers 502 for a target it cannot reach; never a local result."""
        client = self._client(AppMeshClientTCP, tcp_address=("gateway.local", 6062), ssl_verify=False)
        client.forward_to = "appmesh_nosuch"
        failed = requests.Response()
        failed.status_code = 502
        failed.reason = "Bad Gateway"
        failed._content = b"failed to forward request"
        with mock.patch.object(client.session, "post", return_value=failed):
            with self.assertRaises(AppMeshRequestError) as ctx:
                _collect(client.run_task_stream("worker", "payload"))
        self.assertEqual(ctx.exception.status_code, 502)

    def test_port_suffixed_target_gets_a_hint_on_404(self):
        """The agent forwards host:port to that port; the target's TCP listener has no stream
        route, so the 404 must say what to change."""
        client = self._client(AppMeshClientTCP, tcp_address=("gateway.local", 6062), ssl_verify=False)
        client.forward_to = "appmesh_slave1:6062"
        failed = requests.Response()
        failed.status_code = 404
        failed.reason = "Not Found"
        failed._content = b'{"message":"Path not found"}'
        with mock.patch.object(client.session, "post", return_value=failed):
            with self.assertRaises(AppMeshRequestError) as ctx:
                _collect(client.run_task_stream("worker", "payload"))
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertIn("'appmesh_slave1:6062'", str(ctx.exception))
        self.assertIn("bare host", str(ctx.exception))

    def test_forwarded_stream_is_signed(self):
        client = self._client(AppMeshClientTCP, tcp_address=("gateway.local", 6062), ssl_verify=False,
                              api_key="key-id", api_secret="key-secret")
        client.forward_to = "appmesh_slave1"
        with mock.patch.object(client.session, "post", return_value=_sse_response()) as post:
            _collect(client.run_task_stream("worker", "payload"))
        headers = post.call_args.kwargs["headers"]
        for name in ("X-Request-Key", "X-Timestamp", "X-Nonce", "X-Signature"):
            self.assertIn(name, headers)
        self.assertEqual(headers["X-Request-Key"], "key-id")
        self.assertEqual(headers["X-Target-Host"], "appmesh_slave1")


class TestHTTPStreamForwarding(unittest.TestCase):
    def test_engine_listener_base_url_reports_the_limitation(self):
        """A base_url on the engine listener answers 400 to a forwarded stream; the
        SDK must explain it rather than leave a bare 400."""
        client = AppMeshClient(base_url="https://gateway.local:6063", ssl_verify=False, bearer_token="token")
        client.forward_to = "appmesh_slave1"
        failed = requests.Response()
        failed.status_code = 400
        failed.reason = "Bad Request"
        failed._content = b'{"message":"Streaming is not supported through node forwarding"}'
        with mock.patch.object(client.session, "post", return_value=failed):
            with self.assertRaises(AppMeshRequestError) as ctx:
                _collect(client.run_task_stream("worker", "payload"))
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("agent REST listener", str(ctx.exception))
        self.assertIn("6060", str(ctx.exception))

    def test_engine_listener_base_url_without_target_keeps_plain_error(self):
        client = AppMeshClient(base_url="https://gateway.local:6063", ssl_verify=False, bearer_token="token")
        failed = requests.Response()
        failed.status_code = 400
        failed._content = b'{"message":"bad request"}'
        with mock.patch.object(client.session, "post", return_value=failed):
            with self.assertRaises(AppMeshRequestError) as ctx:
                _collect(client.run_task_stream("worker", "payload"))
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertNotIn("agent REST listener", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
