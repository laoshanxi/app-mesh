"""Token auto-refresh pacing.

Pure unit tests: they never touch a daemon. The invariant under test is that the
refresh loop renews once per token lifetime fraction, not once per poll interval.
"""

import base64
import json
import os
import sys
import time
import unittest
from unittest import TestCase

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))  # -> src/sdk/python

from appmesh.client_http import AppMeshClient  # noqa: E402  pylint: disable=wrong-import-position


def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def make_jwt(iat, exp):
    """Build an unsigned JWT carrying iat/exp, all the pacing logic reads.

    PyJWT parses the header even with signature verification off, so it has to be
    a real one.
    """
    claims = {"exp": exp}
    if iat:
        claims["iat"] = iat
    return _b64({"alg": "HS256", "typ": "JWT"}) + "." + _b64(claims) + ".sig"


class _PlanClient:
    """Minimal stand-in exposing only what _compute_refresh_plan touches."""

    _TOKEN_REFRESH_INTERVAL = AppMeshClient._TOKEN_REFRESH_INTERVAL
    _TOKEN_REFRESH_OFFSET = AppMeshClient._TOKEN_REFRESH_OFFSET
    _TOKEN_REFRESH_LIFETIME_RATIO = AppMeshClient._TOKEN_REFRESH_LIFETIME_RATIO
    _TOKEN_REFRESH_JITTER_RATIO = AppMeshClient._TOKEN_REFRESH_JITTER_RATIO
    _refresh_margin = AppMeshClient._refresh_margin
    _compute_refresh_plan = AppMeshClient._compute_refresh_plan

    def __init__(self, token, refresh_token=None):
        self.token = token
        self._refresh_token = refresh_token

    def _get_access_token(self):
        return self.token


class TestRefreshMargin(TestCase):
    """The margin is a fraction of the token's lifetime, floored and jittered."""

    def test_margin_scales_with_lifetime(self):
        now = time.time()
        for lifetime, low, high in (
            (1800, 648, 792),  # 30 min -> 40% ±10%
            (604800, 217728, 266112),  # 7 days
            (60, 27, 33),  # 1 min -> floored at the 30s offset
        ):
            with self.subTest(lifetime=lifetime):
                exp = now + lifetime
                margin = AppMeshClient._refresh_margin(make_jwt(now, exp), exp, now)
                self.assertGreaterEqual(margin, low)
                self.assertLessEqual(margin, high)

    def test_jitter_is_deterministic_per_token(self):
        now = time.time()
        exp = now + 3600
        token = make_jwt(now, exp)
        margins = {AppMeshClient._refresh_margin(token, exp, now) for _ in range(10)}
        self.assertEqual(len(margins), 1, "the refresh point must not wobble between polls")

    def test_jitter_spreads_across_tokens(self):
        now = time.time()
        exp = now + 3600
        margins = {AppMeshClient._refresh_margin(make_jwt(now, exp) + str(i), exp, now) for i in range(20)}
        self.assertGreater(len(margins), 5, "clients sharing an identity must not renew in lockstep")


class TestRefreshPlan(TestCase):
    """(sleep, due) decisions of the refresh loop."""

    def test_long_lived_token_polls_without_renewing(self):
        # The regression this change exists for: a 30-minute token used to renew
        # every 5 minutes because the poll cap was applied as a renew interval.
        now = time.time()
        delay, due = _PlanClient(make_jwt(now, now + 1800))._compute_refresh_plan()
        self.assertFalse(due)
        self.assertEqual(delay, AppMeshClient._TOKEN_REFRESH_INTERVAL)

    def test_token_past_refresh_point_is_due(self):
        now = time.time()
        # 30 min lifetime, 25 min old: past the ~18 min refresh point.
        delay, due = _PlanClient(make_jwt(now - 1500, now + 300))._compute_refresh_plan()
        self.assertTrue(due)
        self.assertLessEqual(delay, 1)

    def test_no_credential_at_all_only_polls(self):
        delay, due = _PlanClient(None)._compute_refresh_plan()
        self.assertFalse(due)
        self.assertEqual(delay, AppMeshClient._TOKEN_REFRESH_INTERVAL)

    def test_refresh_token_alone_is_due(self):
        # An access token lost to an expired cookie is recoverable from the refresh
        # token — but only if the loop actually attempts a renewal.
        delay, due = _PlanClient(None, refresh_token="rt")._compute_refresh_plan()
        self.assertTrue(due)
        self.assertLessEqual(delay, 1)

    def test_short_lived_token_does_not_spin(self):
        # A 30s token must not renew every second: the margin is capped at half the
        # lifetime so the refresh point stays inside the token's life.
        now = time.time()
        margin = AppMeshClient._refresh_margin(make_jwt(now, now + 30), now + 30, now)
        self.assertLessEqual(margin, 15)

    def test_undecodable_token_keeps_legacy_cadence(self):
        delay, due = _PlanClient("not-a-jwt")._compute_refresh_plan()
        self.assertTrue(due)
        self.assertEqual(delay, AppMeshClient._TOKEN_REFRESH_INTERVAL)


class TestRetryBackoff(TestCase):
    def test_backoff_is_exponential_and_bounded(self):
        got = [AppMeshClient._refresh_retry_delay(n) for n in range(1, 8)]
        self.assertEqual(got, [5, 10, 20, 40, 60, 60, 60])


if __name__ == "__main__":
    unittest.main()
