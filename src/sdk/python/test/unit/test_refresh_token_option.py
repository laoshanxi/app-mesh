"""Caller control over being issued a refresh token.

Pure unit tests: the HTTP layer is stubbed, no daemon involved. The invariant under test
is that the ``X-Refresh-Token-Request`` opt-in is sent only when the caller asked for a
refresh token — a one-shot client must not be handed a multi-day credential it never
stores or revokes.
"""

import os
import sys
import unittest
from http import HTTPStatus
from unittest import TestCase

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))  # -> src/sdk/python

from appmesh.client_http import AppMeshClient  # noqa: E402  pylint: disable=wrong-import-position

_HEADER = AppMeshClient._HTTP_HEADER_JWT_WANT_REFRESH_TOKEN  # pylint: disable=protected-access
_PATHS = ("/appmesh/login", "/appmesh/totp/validate", "/appmesh/token/renew")


class _FakeResponse:
    """Just enough of requests.Response for the auth paths."""

    status_code = HTTPStatus.OK
    text = ""

    @staticmethod
    def json():
        return {}


class _Recorder:
    """Stands in for _request_http, keeping the headers sent per path."""

    def __init__(self):
        self.headers = {}

    def __call__(self, method, path, query=None, header=None, body=None, raise_on_fail=True):
        self.headers[path] = dict(header or {})
        return _FakeResponse()


def _headers_per_path(auto_refresh, use_refresh):
    client = AppMeshClient(auto_refresh_token=auto_refresh, use_refresh_token=use_refresh)
    recorder = _Recorder()
    client._request_http = recorder  # pylint: disable=protected-access
    client._get_access_token = lambda: "access-token"  # renewal needs a credential  # pylint: disable=protected-access
    try:
        client.login("user", "password")
        client.validate_totp("user", "challenge", "123456")
        client.renew_token()
    finally:
        client.close()
    return recorder.headers


class TestRefreshTokenOptOut(TestCase):
    def _assert_header(self, auto_refresh, use_refresh, expected):
        headers = _headers_per_path(auto_refresh, use_refresh)
        for path in _PATHS:
            with self.subTest(path=path):
                self.assertEqual(_HEADER in headers[path], expected)
                if expected:
                    self.assertEqual(headers[path][_HEADER], "true")

    def test_unset_follows_auto_refresh_on(self):
        # A long-lived client keeps the credential, so it may as well hold one.
        self._assert_header(auto_refresh=True, use_refresh=None, expected=True)

    def test_unset_follows_auto_refresh_off(self):
        # The one-shot default: no background loop, so no long-lived credential either.
        self._assert_header(auto_refresh=False, use_refresh=None, expected=False)

    def test_explicit_false_overrides_auto_refresh(self):
        # Auto-refresh without a refresh token: a missed window costs a re-login, not a leak.
        self._assert_header(auto_refresh=True, use_refresh=False, expected=False)

    def test_explicit_true_without_auto_refresh(self):
        # Manual renewal: the caller wants the credential but not the background loop.
        self._assert_header(auto_refresh=False, use_refresh=True, expected=True)

    def test_declined_omits_the_header_entirely(self):
        # "false" is not the same as absent for a daemon that only checks presence.
        headers = _headers_per_path(auto_refresh=False, use_refresh=False)
        for path in _PATHS:
            self.assertNotIn(_HEADER, headers[path])


if __name__ == "__main__":
    unittest.main()
