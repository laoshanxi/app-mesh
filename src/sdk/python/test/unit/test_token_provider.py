"""Unit coverage for the Python Dex TokenProvider boundary."""

import json
import unittest
from unittest.mock import patch

import requests

from appmesh.client_http import AppMeshClient
from appmesh.dex_oauth import DexOAuthClient, DexOAuthError
from appmesh.token_provider import TokenProvider


def _response(status, payload):
    response = requests.Response()
    response.status_code = status
    response.reason = "test"
    response._content = json.dumps(payload).encode("utf-8")
    # Content is materialized directly; without this flag requests' close()
    # would dereference the unset ``raw`` connection.
    response._content_consumed = True
    response.headers["Content-Type"] = "application/json"
    return response


class _RefreshingProvider(TokenProvider):
    def __init__(self):
        self.token = "old-token"
        self.refreshes = 0

    def get_access_token(self):
        return self.token

    @property
    def can_refresh(self):
        return True

    def refresh_access_token(self, rejected_token=None):
        if rejected_token == self.token:
            self.refreshes += 1
            self.token = "new-token"
        return self.token


class _EngineSession:
    def __init__(self):
        self.authorization = []

    def get(self, **kwargs):
        self.authorization.append(kwargs["headers"].get("Authorization"))
        return _response(401 if len(self.authorization) == 1 else 200, {"ok": True})

    def close(self):
        pass


class _DexSession:
    ISSUER = "https://auth.example/dex"

    def __init__(self):
        self.posted_forms = []
        # patch("appmesh.dex_oauth.requests.Session") patches the shared requests
        # module, so AppMeshClient constructed inside the patched scope also gets
        # this fake; give it the jar surface the Engine client configures.
        self.cookies = requests.cookies.RequestsCookieJar()

    def get(self, url, **kwargs):
        del url, kwargs
        return _response(
            200,
            {
                "issuer": self.ISSUER,
                "authorization_endpoint": self.ISSUER + "/auth",
                "token_endpoint": self.ISSUER + "/token",
                "device_authorization_endpoint": self.ISSUER + "/device/code",
            },
        )

    def post(self, url, **kwargs):
        self.posted_forms.append(dict(kwargs.get("data") or {}))
        if url.endswith("/device/code"):
            return _response(
                200,
                {
                    "device_code": "device-code",
                    "verification_uri": self.ISSUER + "/device",
                    "verification_uri_complete": self.ISSUER + "/device?user_code=ABCD",
                    "expires_in": 600,
                    "interval": 5,
                },
            )
        return _response(200, {"access_token": "access-token", "token_type": "Bearer", "expires_in": 300})

    def close(self):
        pass


class TokenProviderTests(unittest.TestCase):
    def test_shared_installation_mtls_identity_is_not_implicit(self):
        client = AppMeshClient(ssl_verify=True)

        self.assertIsNone(client.ssl_client_cert)

    def test_engine_session_rejects_response_cookies(self):
        client = AppMeshClient(ssl_verify=True)
        request = requests.Request("GET", "https://engine.example/appmesh/resources").prepare()
        cookie = requests.cookies.create_cookie("appmesh_session", "must-not-stick")

        client.session.cookies.set_cookie_if_ok(cookie, request)

        self.assertEqual([], list(client.session.cookies))

    def test_http_retries_one_401_with_refreshed_bearer(self):
        provider = _RefreshingProvider()
        client = AppMeshClient(ssl_verify=True, token_provider=provider)
        client.session = _EngineSession()

        response = client._request_http(AppMeshClient._Method.GET, "/appmesh/resources")

        self.assertEqual(200, response.status_code)
        self.assertEqual(1, provider.refreshes)
        self.assertEqual(["Bearer old-token", "Bearer new-token"], client.session.authorization)

    @patch("appmesh.dex_oauth.requests.Session", return_value=_DexSession())
    def test_front_channel_urls_remain_canonical(self, _session):
        engine = AppMeshClient(ssl_verify=True)
        oauth = DexOAuthClient(
            appmesh_client=engine,
            issuer=_DexSession.ISSUER,
            dex_access_url="http://127.0.0.1:6062/dex",
            client_id="appmesh-cli",
        )

        request = oauth.authorization_request("http://127.0.0.1:49152/callback")
        device = oauth.device_authorization()

        self.assertTrue(request["authorization_url"].startswith(_DexSession.ISSUER + "/auth?"))
        self.assertEqual(_DexSession.ISSUER + "/device", device["verification_uri"])
        self.assertEqual(_DexSession.ISSUER + "/device?user_code=ABCD", device["verification_uri_complete"])

    @patch("appmesh.dex_oauth.requests.Session", return_value=_DexSession())
    def test_callback_rejects_unknown_state_before_code_exchange(self, _session):
        engine = AppMeshClient(ssl_verify=True)
        oauth = DexOAuthClient(
            appmesh_client=engine,
            issuer=_DexSession.ISSUER,
            dex_access_url="http://127.0.0.1:6062/dex",
            client_id="appmesh-cli",
        )
        oauth.authorization_request("http://127.0.0.1:49152/callback")

        with self.assertRaises(DexOAuthError):
            oauth.complete_authorization_callback(
                "http://127.0.0.1:49152/callback?code=code&state=attacker-state"
            )

    @patch("appmesh.dex_oauth.requests.Session", return_value=_DexSession())
    def test_nonce_request_requires_id_token_validator(self, _session):
        engine = AppMeshClient(ssl_verify=True)
        oauth = DexOAuthClient(
            appmesh_client=engine,
            issuer=_DexSession.ISSUER,
            dex_access_url="http://127.0.0.1:6062/dex",
            client_id="appmesh-cli",
        )
        request = oauth.authorization_request(
            "http://127.0.0.1:49152/callback",
            nonce="expected-nonce",
        )

        with self.assertRaises(DexOAuthError):
            oauth.complete_authorization_callback(
                "http://127.0.0.1:49152/callback?code=code&state=" + request["state"]
            )

    @patch("appmesh.dex_oauth.requests.Session", return_value=_DexSession())
    def test_revoke_without_endpoint_still_clears_engine_bearer(self, _session):
        engine = AppMeshClient(ssl_verify=True)
        oauth = DexOAuthClient(
            appmesh_client=engine,
            issuer=_DexSession.ISSUER,
            dex_access_url="http://127.0.0.1:6062/dex",
            client_id="appmesh-cli",
        )
        oauth._install({"access_token": "access-token", "token_type": "Bearer", "expires_in": 300})

        self.assertFalse(oauth.revoke())
        self.assertIsNone(engine.token_provider)

if __name__ == "__main__":
    unittest.main()


class PlainHttpIssuerPolicy(unittest.TestCase):
    """Plain-HTTP issuers stay fail-closed unless the caller opts in."""

    def test_plain_http_issuer_requires_opt_in(self):
        url = "http://appmesh_master:6062/auth"
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            DexOAuthClient._normalize_base_url(url, "issuer")
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            DexOAuthClient._normalize_base_url(url, "access_url")
        self.assertEqual(DexOAuthClient._normalize_base_url(url, "issuer", True), url)
        self.assertEqual(DexOAuthClient._normalize_base_url(url, "access_url", True), url)
