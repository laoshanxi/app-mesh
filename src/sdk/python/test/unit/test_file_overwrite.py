"""Unit coverage for the file-upload overwrite flag on every transport.

The engine refuses an existing destination with 409 unless the upload carries
X-File-Overwrite: true. The SDK default stays no-overwrite, so the header must
be absent unless the caller asks for it.
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import requests
from requests.structures import CaseInsensitiveDict

from appmesh.client_http import AppMeshClient
from appmesh.client_tcp import AppMeshClientTCP
from appmesh.client_wss import AppMeshClientWSS

OVERWRITE_HEADER = "X-File-Overwrite"


def _octet_stream_response(body: bytes = b"") -> requests.Response:
    """Build the streamed response the requests library delivers for file bytes."""
    resp = requests.Response()
    resp.status_code = 200
    resp.headers = CaseInsensitiveDict({"Content-Type": "application/octet-stream"})
    resp._content = body
    resp._content_consumed = True  # iter_content() then slices _content instead of reading raw
    return resp


def _precheck_response(*args, **kwargs) -> requests.Response:
    """Answer the TCP upload precheck with the socket-transfer handshake."""
    resp = _octet_stream_response()
    resp.headers["X-Send-File-Socket"] = "true"
    return resp


class _UploadHeaderCase(unittest.TestCase):
    """Shared assertion helpers for the per-transport header checks."""

    def _scratch_file(self, tmp: str) -> Path:
        src = Path(tmp) / "put.txt"
        src.write_bytes(b"payload")
        return src


class TestHttpUploadOverwrite(_UploadHeaderCase):
    """Plain-HTTP transport: the flag maps to the X-File-Overwrite header."""

    def _client(self) -> AppMeshClient:
        client = AppMeshClient("https://127.0.0.1:6060", ssl_verify=False, bearer_token="token")
        return client

    def test_overwrite_sends_header(self):
        client = self._client()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            client, "_request_http", return_value=_octet_stream_response()
        ) as req:
            client.upload_file(str(self._scratch_file(tmp)), "/tmp/remote-put.txt", overwrite=True)
        self.assertEqual(req.call_args[1]["header"][OVERWRITE_HEADER], "true")

    def test_default_sends_no_header(self):
        client = self._client()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            client, "_request_http", return_value=_octet_stream_response()
        ) as req:
            client.upload_file(str(self._scratch_file(tmp)), "/tmp/remote-put.txt")
        self.assertNotIn(OVERWRITE_HEADER, req.call_args[1]["header"])


class TestWssUploadOverwrite(_UploadHeaderCase):
    """WSS transport: both the precheck and the data channel carry the flag."""

    def test_overwrite_sends_header_on_both_hops(self):
        client = AppMeshClientWSS(("gateway.local", 6063), ssl_verify=False, bearer_token="token")
        client.forward_to = None
        client._request_http = mock.Mock()  # control-channel precheck answers 200
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            client.session, "post", return_value=_octet_stream_response()
        ) as post:
            client.upload_file(str(self._scratch_file(tmp)), "/tmp/remote-put.txt", overwrite=True)
        self.assertEqual(client._request_http.call_args[1]["header"][OVERWRITE_HEADER], "true")
        self.assertEqual(post.call_args[1]["headers"][OVERWRITE_HEADER], "true")

    def test_default_sends_no_header(self):
        client = AppMeshClientWSS(("gateway.local", 6063), ssl_verify=False, bearer_token="token")
        client.forward_to = None
        client._request_http = mock.Mock()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            client.session, "post", return_value=_octet_stream_response()
        ) as post:
            client.upload_file(str(self._scratch_file(tmp)), "/tmp/remote-put.txt")
        self.assertNotIn(OVERWRITE_HEADER, client._request_http.call_args[1]["header"])
        self.assertNotIn(OVERWRITE_HEADER, post.call_args[1]["headers"])


class TestTcpUploadOverwrite(_UploadHeaderCase):
    """TCP transport: the upload precheck request carries the flag."""

    def test_overwrite_sends_header(self):
        client = AppMeshClientTCP(("127.0.0.1", 6062), ssl_verify=False, bearer_token="token")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            client, "_request_http", return_value=_precheck_response()
        ) as req, mock.patch.object(client.tcp_transport, "send_message"):
            client.upload_file(str(self._scratch_file(tmp)), "/tmp/remote-put.txt", overwrite=True)
            header = req.call_args[1]["header"]
        self.assertEqual(header[OVERWRITE_HEADER], "true")

    def test_default_sends_no_header(self):
        client = AppMeshClientTCP(("127.0.0.1", 6062), ssl_verify=False, bearer_token="token")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            client, "_request_http", return_value=_precheck_response()
        ) as req, mock.patch.object(client.tcp_transport, "send_message"):
            client.upload_file(str(self._scratch_file(tmp)), "/tmp/remote-put.txt")
            header = req.call_args[1]["header"]
        self.assertNotIn(OVERWRITE_HEADER, header)


if __name__ == "__main__":
    unittest.main()
