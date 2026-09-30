"""Unit coverage for the Python OAuth TokenProvider boundary."""

import json
import unittest
from unittest.mock import patch
from urllib import parse

import requests

from appmesh.client_http import AppMeshClient
from appmesh.exceptions import AppMeshRequestError
from appmesh.oauth import OAuthClient, OAuthError
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


class _OAuthSession:
    ISSUER = "https://auth.example/dex"

    def __init__(self):
        self.posted_forms = []
        # patch("appmesh.oauth.requests.Session") patches the shared requests
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


class _TokenOnlySession:
    """Token endpoint fake for from_token_set; any GET (discovery) fails the test."""

    def __init__(self, responses=()):
        self.posted_forms = []
        self.queue = list(responses)
        self.cookies = requests.cookies.RequestsCookieJar()

    def get(self, url, **kwargs):
        raise AssertionError("from_token_set must not perform discovery")

    def post(self, url, **kwargs):
        self.posted_forms.append((url, dict(kwargs.get("data") or {})))
        if self.queue:
            item = self.queue.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        return _response(200, {"access_token": "refreshed-token", "token_type": "Bearer", "expires_in": 300})

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

    @patch("appmesh.oauth.requests.Session", return_value=_OAuthSession())
    def test_front_channel_urls_remain_canonical(self, _session):
        engine = AppMeshClient(ssl_verify=True)
        oauth = OAuthClient(
            appmesh_client=engine,
            issuer=_OAuthSession.ISSUER,
            access_url="http://127.0.0.1:6062/dex",
            client_id="appmesh-cli",
        )

        request = oauth.authorization_request("http://127.0.0.1:49152/callback")
        device = oauth.device_authorization()

        self.assertTrue(request["authorization_url"].startswith(_OAuthSession.ISSUER + "/auth?"))
        self.assertEqual(_OAuthSession.ISSUER + "/device", device["verification_uri"])
        self.assertEqual(_OAuthSession.ISSUER + "/device?user_code=ABCD", device["verification_uri_complete"])

    @patch("appmesh.oauth.requests.Session", return_value=_OAuthSession())
    def test_callback_rejects_unknown_state_before_code_exchange(self, _session):
        engine = AppMeshClient(ssl_verify=True)
        oauth = OAuthClient(
            appmesh_client=engine,
            issuer=_OAuthSession.ISSUER,
            access_url="http://127.0.0.1:6062/dex",
            client_id="appmesh-cli",
        )
        oauth.authorization_request("http://127.0.0.1:49152/callback")

        with self.assertRaises(OAuthError):
            oauth.complete_authorization_callback(
                "http://127.0.0.1:49152/callback?code=code&state=attacker-state"
            )

    @patch("appmesh.oauth.requests.Session", return_value=_OAuthSession())
    def test_nonce_request_requires_id_token_validator(self, _session):
        engine = AppMeshClient(ssl_verify=True)
        oauth = OAuthClient(
            appmesh_client=engine,
            issuer=_OAuthSession.ISSUER,
            access_url="http://127.0.0.1:6062/dex",
            client_id="appmesh-cli",
        )
        request = oauth.authorization_request(
            "http://127.0.0.1:49152/callback",
            nonce="expected-nonce",
        )

        with self.assertRaises(OAuthError):
            oauth.complete_authorization_callback(
                "http://127.0.0.1:49152/callback?code=code&state=" + request["state"]
            )

    @patch("appmesh.oauth.requests.Session", return_value=_OAuthSession())
    def test_refresh_token_default_keeps_offline_access(self, _session):
        engine = AppMeshClient(ssl_verify=True)
        config = {
            "issuer": _OAuthSession.ISSUER,
            "public_client_id": "appmesh-cli",
        }
        with patch.object(engine, "get_auth_config", return_value=config):
            oauth = OAuthClient.from_appmesh(engine, access_url="http://127.0.0.1:6062/dex")

        request = oauth.authorization_request("http://127.0.0.1:49152/callback")
        scope = parse.parse_qs(parse.urlsplit(request["authorization_url"]).query)["scope"][0]

        self.assertIn("offline_access", scope.split())

    @patch("appmesh.oauth.requests.Session", return_value=_OAuthSession())
    def test_refresh_token_disabled_omits_offline_access(self, _session):
        engine = AppMeshClient(ssl_verify=True)
        caller_scopes = ["openid", "profile", "offline_access"]
        config = {
            "issuer": _OAuthSession.ISSUER,
            "public_client_id": "appmesh-cli",
            "refresh_token": False,
        }
        with patch.object(engine, "get_auth_config", return_value=config):
            oauth = OAuthClient.from_appmesh(
                engine, access_url="http://127.0.0.1:6062/dex", scopes=caller_scopes
            )

        request = oauth.authorization_request("http://127.0.0.1:49152/callback")
        scope = parse.parse_qs(parse.urlsplit(request["authorization_url"]).query)["scope"][0]
        self.assertNotIn("offline_access", scope.split())

        oauth.device_authorization()
        device_scope = _session.return_value.posted_forms[-1]["scope"]
        self.assertNotIn("offline_access", device_scope.split())

        # Caller-supplied scopes are stripped only in the effective request.
        self.assertEqual(["openid", "profile", "offline_access"], caller_scopes)

        # Without an issued refresh token there is nothing to refresh with.
        oauth._install({"access_token": "access-token", "token_type": "Bearer", "expires_in": 300})
        self.assertFalse(oauth.can_refresh)

    @patch("appmesh.oauth.requests.Session", return_value=_OAuthSession())
    def test_revoke_without_endpoint_still_clears_engine_bearer(self, _session):
        engine = AppMeshClient(ssl_verify=True)
        oauth = OAuthClient(
            appmesh_client=engine,
            issuer=_OAuthSession.ISSUER,
            access_url="http://127.0.0.1:6062/dex",
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
            OAuthClient._normalize_base_url(url, "issuer")
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            OAuthClient._normalize_base_url(url, "access_url")
        self.assertEqual(OAuthClient._normalize_base_url(url, "issuer", True), url)
        self.assertEqual(OAuthClient._normalize_base_url(url, "access_url", True), url)


class FromTokenSetTests(unittest.TestCase):
    """OAuthClient.from_token_set: explicit token endpoint, no discovery."""

    TOKEN_URL = "https://auth.example:6060/auth/token"

    def _client(self, session, **kwargs):
        kwargs.setdefault("token_url", self.TOKEN_URL)
        kwargs.setdefault("access_token", "access-1")
        kwargs.setdefault("refresh_token", "refresh-1")
        with patch("appmesh.oauth.requests.Session", return_value=session):
            return OAuthClient.from_token_set(**kwargs)

    def test_constructs_without_discovery(self):
        session = _TokenOnlySession()
        oauth = self._client(session, expires_in=300)

        self.assertIsInstance(oauth, TokenProvider)
        self.assertTrue(oauth.can_refresh)
        # Not yet near expiry: the stored token is returned, nothing is posted.
        self.assertEqual("access-1", oauth.get_access_token())
        self.assertEqual([], session.posted_forms)

    def test_installs_provider_on_engine_client(self):
        engine = AppMeshClient(ssl_verify=True)
        session = _TokenOnlySession()

        oauth = self._client(session, appmesh_client=engine)

        self.assertIs(oauth, engine.token_provider)

    def test_refreshes_proactively_near_expiry(self):
        session = _TokenOnlySession()
        # Lifetime 20s: refresh margin max(30s, 10%) puts refresh_at in the past.
        oauth = self._client(session, expires_in=20)

        self.assertEqual("refreshed-token", oauth.get_access_token())

        url, form = session.posted_forms[0]
        self.assertEqual(self.TOKEN_URL, url)
        self.assertEqual(
            {"grant_type": "refresh_token", "client_id": "appmesh-cli", "refresh_token": "refresh-1"},
            form,
        )

    def test_refresh_access_token_coalesces_with_rejected_token(self):
        session = _TokenOnlySession()
        oauth = self._client(session)  # unknown expiry: refresh on 401 only

        # A concurrent request already refreshed: the rejected token is no longer
        # current, so the current token is returned without a second refresh.
        self.assertEqual("access-1", oauth.refresh_access_token(rejected_token="superseded-token"))
        self.assertEqual([], session.posted_forms)

        # The current token itself was rejected by the Engine: refresh once.
        self.assertEqual("refreshed-token", oauth.refresh_access_token(rejected_token="access-1"))
        self.assertEqual(1, len(session.posted_forms))

    def test_refresh_token_rotation_and_retention(self):
        session = _TokenOnlySession(
            responses=[
                # No refresh_token in the response: the old one stays valid.
                _response(200, {"access_token": "access-2", "token_type": "Bearer", "expires_in": 300}),
                # Rotated refresh token replaces the stored one.
                _response(
                    200,
                    {
                        "access_token": "access-3",
                        "token_type": "Bearer",
                        "expires_in": 300,
                        "refresh_token": "refresh-2",
                    },
                ),
                _response(200, {"access_token": "access-4", "token_type": "Bearer", "expires_in": 300}),
            ]
        )
        oauth = self._client(session)

        oauth.refresh_access_token()
        oauth.refresh_access_token()
        oauth.refresh_access_token()

        used = [form["refresh_token"] for _url, form in session.posted_forms]
        self.assertEqual(["refresh-1", "refresh-1", "refresh-2"], used)

    def test_invalid_grant_clears_token_state(self):
        session = _TokenOnlySession(
            responses=[_response(400, {"error": "invalid_grant", "error_description": "refresh token expired"})]
        )
        oauth = self._client(session)

        with self.assertRaises(OAuthError):
            oauth.refresh_access_token(rejected_token="access-1")

        self.assertFalse(oauth.can_refresh)
        self.assertIsNone(oauth.get_access_token())
        self.assertEqual({}, oauth.tokens)

    def test_transport_error_keeps_token_state(self):
        session = _TokenOnlySession(responses=[requests.ConnectionError("connection refused")])
        oauth = self._client(session)

        with self.assertRaises(AppMeshRequestError):
            oauth.refresh_access_token(rejected_token="access-1")

        self.assertTrue(oauth.can_refresh)
        self.assertEqual("access-1", oauth.get_access_token())

    def test_token_url_requires_https_or_loopback(self):
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            OAuthClient.from_token_set(
                token_url="http://auth.example:6060/auth/token",
                access_token="access-1",
                refresh_token="refresh-1",
            )

        for url in (
            "http://127.0.0.1:6060/auth/token",
            "http://localhost:6060/auth/token",
            "http://[::1]:6060/auth/token",
            "https://auth.example:6060/auth/token",
        ):
            session = _TokenOnlySession()
            with patch("appmesh.oauth.requests.Session", return_value=session):
                oauth = OAuthClient.from_token_set(token_url=url, access_token="access-1", refresh_token="refresh-1")
            self.assertTrue(oauth.can_refresh)
