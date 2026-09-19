"""Unit coverage for strict JSON body serialization (no NaN/Infinity on the wire)."""

import json
import unittest

from appmesh.app import App
from appmesh.client_http import AppMeshClient
from appmesh.transport_mixin import TransportClientMixin


class TestStrictJsonBodies(unittest.TestCase):
    """NaN/Infinity are not valid JSON. The daemon (nlohmann) rejects such a
    body with an opaque 400, so every transport must fail at the sender with
    ValueError instead of emitting an invalid request."""

    def test_http_body_with_nan_raises(self):
        client = AppMeshClient(ssl_verify=True)
        with self.assertRaises(ValueError):
            client._request_http("POST", "/appmesh/app/test", body={"health": float("nan")})

    def test_tcp_wss_body_with_nan_raises(self):
        transport = TransportClientMixin()
        with self.assertRaises(ValueError):
            transport._convert_bytes({"health": float("nan")})

    def test_app_str_with_nan_still_prints(self):
        # __str__ is a display path: printing an app with a NaN metric must not
        # crash diagnostics. Wire serialization raises at the sender instead
        # (see the two tests above).
        app = App({"name": "nan-app"})
        app.metadata = {"score": float("nan")}
        self.assertIn("nan-app", str(app))

    def test_finite_floats_still_serialize(self):
        transport = TransportClientMixin()
        data = json.loads(transport._convert_bytes({"health": 0.5, "count": 3}))
        self.assertEqual(data, {"health": 0.5, "count": 3})


if __name__ == "__main__":
    unittest.main()
