"""Unit coverage for UTF-8 response passthrough (ADR 0010 C2)."""

import unittest
from unittest import mock

import requests
from requests.structures import CaseInsensitiveDict

from appmesh.client_http import AppMeshClient


def _utf8_text_response(body: str) -> requests.Response:
    """Build the response the requests library delivers for a
    ``text/plain; charset=utf-8`` body (encoding inferred from the header)."""
    resp = requests.Response()
    resp.status_code = 200
    resp.headers = CaseInsensitiveDict({"Content-Type": "text/plain; charset=utf-8"})
    resp.encoding = "utf-8"
    resp._content = body.encode("utf-8")
    return resp


class TestUtf8ResponsePassthrough(unittest.TestCase):
    """SDK transports must return response text exactly as delivered (UTF-8 on
    every platform), never re-encoded through the local Windows code page.
    Re-encoding replaces characters outside the local code page with '?' and
    corrupts data for callers that process the text."""

    def test_ok_text_plain_response_is_returned_unwrapped(self):
        client = AppMeshClient(ssl_verify=True)
        raw = _utf8_text_response("Hello, 世界!")
        with mock.patch.object(client.session, "get", return_value=raw):
            resp = client._request_http(AppMeshClient._Method.GET, path="/appmesh/app/dummy/output")
        # The response is the object requests delivered: no wrapper subclass,
        # no code page round-trip.
        self.assertIs(type(resp), requests.Response)
        self.assertEqual(resp.text, "Hello, 世界!")


if __name__ == "__main__":
    unittest.main()
