"""Unit coverage for the forwarding header on the WSS file data channel."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import requests
from requests.structures import CaseInsensitiveDict

from appmesh.client_wss import AppMeshClientWSS


def _octet_stream_response(body: bytes = b"") -> requests.Response:
    """Build the streamed response the requests library delivers for file bytes."""
    resp = requests.Response()
    resp.status_code = 200
    resp.headers = CaseInsensitiveDict({"Content-Type": "application/octet-stream"})
    resp._content = body
    resp._content_consumed = True  # iter_content() then slices _content instead of reading raw
    return resp


class TestWSSFileDataChannelForwarding(unittest.TestCase):
    """A WSS file transfer is two hops: the control request over the WebSocket and
    the data request over HTTPS. The data request must carry the same X-Target-Host
    as the control request, otherwise the gateway stores or serves the file itself
    while reporting success."""

    def _client(self, forward_to) -> AppMeshClientWSS:
        client = AppMeshClientWSS(("gateway.local", 6058), ssl_verify=False, bearer_token="token")
        client.forward_to = forward_to
        client._request_http = mock.Mock()  # the control-channel precheck answers 200
        return client

    def test_download_data_request_carries_forward_target(self):
        client = self._client("appmesh_slave1")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            client.session, "get", return_value=_octet_stream_response(b"file-bytes")
        ) as get:
            local = Path(tmp) / "got.txt"
            client.download_file("/tmp/remote.txt", str(local))
            self.assertEqual(local.read_bytes(), b"file-bytes")
        self.assertEqual(get.call_args.kwargs["headers"]["X-Target-Host"], "appmesh_slave1")

    def test_upload_data_request_carries_forward_target(self):
        client = self._client("appmesh_slave1")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            client.session, "post", return_value=_octet_stream_response()
        ) as post:
            src = Path(tmp) / "put.txt"
            src.write_bytes(b"payload")
            client.upload_file(str(src), "/tmp/remote-put.txt")
        self.assertEqual(post.call_args.kwargs["headers"]["X-Target-Host"], "appmesh_slave1")

    def test_no_forward_target_sends_no_header(self):
        client = self._client(None)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            client.session, "get", return_value=_octet_stream_response(b"x")
        ) as get:
            client.download_file("/tmp/remote.txt", str(Path(tmp) / "got.txt"))
        self.assertNotIn("X-Target-Host", get.call_args.kwargs["headers"])


if __name__ == "__main__":
    unittest.main()
