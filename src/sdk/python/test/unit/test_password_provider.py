"""Unit coverage for the password-grant TokenProvider."""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

import requests

from appmesh.client_http import AppMeshClient
from appmesh.exceptions import AppMeshRequestError
from appmesh.oauth import OAuthError
from appmesh.password_provider import PasswordGrantProvider
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


class _TokenSession:
    """Token endpoint fake; any GET (discovery) fails the test."""

    def __init__(self, responses=()):
        self.posts = []
        self.queue = list(responses)
        self.cookies = requests.cookies.RequestsCookieJar()

    def get(self, url, **kwargs):
        raise AssertionError("password grant must not perform discovery")

    def post(self, url, **kwargs):
        self.posts.append((url, dict(kwargs.get("data") or {}), kwargs.get("auth")))
        if self.queue:
            item = self.queue.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        return _response(200, {"access_token": "minted-token", "token_type": "Bearer", "expires_in": 300})

    def close(self):
        pass


class PasswordGrantProviderTests(unittest.TestCase):
    TOKEN_URL = "https://auth.example:6060/auth/token"

    def _provider(self, session, **kwargs):
        kwargs.setdefault("token_url", self.TOKEN_URL)
        kwargs.setdefault("username", "admin@appmesh.local")
        kwargs.setdefault("password", "secret")
        with patch("appmesh.oauth.requests.Session", return_value=session):
            return PasswordGrantProvider(**kwargs)

    def test_first_call_mints_token_with_password_grant(self):
        session = _TokenSession()
        provider = self._provider(session)

        self.assertIsInstance(provider, TokenProvider)
        self.assertTrue(provider.can_refresh)
        self.assertEqual("minted-token", provider.get_access_token())

        url, form, auth = session.posts[0]
        self.assertEqual(self.TOKEN_URL, url)
        self.assertEqual(("appmesh-cli", ""), auth)
        self.assertEqual(
            {
                "grant_type": "password",
                "username": "admin@appmesh.local",
                "password": "secret",
                "scope": "openid audience:server:client_id:appmesh-api",
            },
            form,
        )

    def test_fresh_token_is_not_reminted(self):
        session = _TokenSession()
        provider = self._provider(session)

        provider.get_access_token()
        provider.get_access_token()

        self.assertEqual(1, len(session.posts))

    def test_remints_proactively_near_expiry(self):
        session = _TokenSession(
            responses=[
                # Lifetime 20s: refresh margin max(30s, 10%) puts refresh_at in the past.
                _response(200, {"access_token": "short-lived", "token_type": "Bearer", "expires_in": 20}),
            ]
        )
        provider = self._provider(session)

        self.assertEqual("short-lived", provider.get_access_token())
        self.assertEqual("minted-token", provider.get_access_token())
        self.assertEqual(2, len(session.posts))

    def test_refresh_access_token_coalesces_with_rejected_token(self):
        session = _TokenSession()
        provider = self._provider(session)
        provider.get_access_token()

        # A concurrent request already re-minted: the rejected token is no
        # longer current, so no second grant runs.
        self.assertEqual("minted-token", provider.refresh_access_token(rejected_token="superseded-token"))
        self.assertEqual(1, len(session.posts))

        # The current token itself was rejected by the Engine: mint once.
        self.assertEqual("minted-token", provider.refresh_access_token(rejected_token="minted-token"))
        self.assertEqual(2, len(session.posts))

    def test_dead_credentials_kill_provider(self):
        # The bundled Dex answers access_denied; RFC 6749 issuers answer
        # invalid_grant. Both mean the password can never be exchanged.
        for status, code in ((401, "access_denied"), (400, "invalid_grant")):
            with self.subTest(code=code):
                session = _TokenSession(
                    responses=[_response(status, {"error": code, "error_description": "bad credentials"})]
                )
                provider = self._provider(session)

                with self.assertRaises(OAuthError):
                    provider.get_access_token()

                self.assertFalse(provider.can_refresh)
                self.assertIsNone(provider.get_access_token())
                self.assertEqual({}, provider.tokens)

    def test_transient_oauth_error_keeps_provider_alive(self):
        session = _TokenSession(
            responses=[
                _response(400, {"error": "temporarily_unavailable", "error_description": "try later"}),
            ]
        )
        provider = self._provider(session)

        with self.assertRaises(OAuthError):
            provider.get_access_token()

        self.assertTrue(provider.can_refresh)
        # The next call re-runs the grant and can succeed.
        self.assertEqual("minted-token", provider.get_access_token())

    def test_transport_error_keeps_token_state(self):
        session = _TokenSession(
            responses=[
                _response(200, {"access_token": "old-token", "token_type": "Bearer", "expires_in": 300}),
                requests.ConnectionError("connection refused"),
            ]
        )
        provider = self._provider(session)
        provider.get_access_token()

        with self.assertRaises(AppMeshRequestError):
            provider.refresh_access_token(rejected_token="old-token")

        self.assertTrue(provider.can_refresh)
        self.assertEqual("old-token", provider.tokens.get("access_token"))

    def test_installs_provider_on_engine_client(self):
        engine = AppMeshClient(ssl_verify=True)
        session = _TokenSession()

        provider = self._provider(session, appmesh_client=engine)
        provider.get_access_token()

        self.assertIs(provider, engine.token_provider)

    def test_token_response_without_access_token_fails(self):
        session = _TokenSession(responses=[_response(200, {"token_type": "Bearer", "expires_in": 300})])
        provider = self._provider(session)

        with self.assertRaises(OAuthError):
            provider.get_access_token()

    def test_token_url_requires_https_or_loopback(self):
        with self.assertRaisesRegex(ValueError, "must use HTTPS"):
            self._provider(_TokenSession(), token_url="http://auth.example:6060/auth/token")

        for url in (
            "http://127.0.0.1:6060/auth/token",
            "http://localhost:6060/auth/token",
            "https://auth.example:6060/auth/token",
        ):
            self._provider(_TokenSession(), token_url=url)

    def test_credential_source_validation(self):
        session = _TokenSession()
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self._provider(session, password=None)
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self._provider(session, password_file="/tmp/x")
        with self.assertRaisesRegex(ValueError, "non-empty"):
            self._provider(session, password="")
        with self.assertRaisesRegex(ValueError, "username is required"):
            self._provider(session, username=" ")
        with self.assertRaisesRegex(ValueError, "not readable"):
            self._provider(session, password=None, password_file="/nonexistent/agent-password")

    def test_password_file_is_reread_on_each_grant(self):
        session = _TokenSession(
            responses=[
                _response(200, {"access_token": "first", "token_type": "Bearer", "expires_in": 20}),
            ]
        )
        with tempfile.NamedTemporaryFile("w", suffix="-password", delete=False) as handle:
            password_path = handle.name
            handle.write("old-password\n")
        try:
            provider = self._provider(session, password=None, password_file=password_path)
            self.assertEqual("first", provider.get_access_token())

            # Rotate the password on disk; the next grant must use it without
            # a process restart.
            with open(password_path, "w", encoding="utf-8") as handle:
                handle.write("rotated-password\n")
            self.assertEqual("minted-token", provider.get_access_token())

            passwords = [form["password"] for _url, form, _auth in session.posts]
            self.assertEqual(["old-password", "rotated-password"], passwords)
        finally:
            os.unlink(password_path)


if __name__ == "__main__":
    unittest.main()
