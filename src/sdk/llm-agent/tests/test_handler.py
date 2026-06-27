"""Handler dispatch: auth routing and robustness to malformed client input.

The malformed-limits test guards a real regression: per-turn limit fields come straight
from an untrusted client payload, so a non-numeric value must degrade to "unset" and
return a clean result — never raise out of the turn and crash the serving App.
"""
import base64
import json
import tempfile
import unittest

from llm_agent.budget import Ledger
from llm_agent.handler import Handler, _as_int, jwt_username
from llm_agent.llm import FakeLLM
from llm_agent.session import Store
from llm_agent.types import Completion, Message, ROLE_ASSISTANT, ToolCall, TurnLimits, Usage


class FakeClient:
    def list_apps(self):
        return []

    def run_task(self, name, args, timeout):
        return "{}"


def make_handler(tmp):
    return Handler(
        store=Store(f"{tmp}/sessions", 0),
        ledger=Ledger(f"{tmp}/ledger", {}),
        ceiling=TurnLimits(max_iterations=8, max_tokens=0),
        llm_name="fake", server_uri="127.0.0.1:6059", tenant="default",
        workspace=f"{tmp}/ws", tool_timeout=30, admins=["admin"],
        client_factory=lambda token: FakeClient(),
        auth_fn=lambda token: "alice",   # bypass real daemon validation
        llm=FakeLLM(),
    )


class HandlerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.h = make_handler(self.tmp)

    def _send(self, **fields):
        import json
        return self.h.dispatch(json.dumps(dict(token="t", **fields)))

    def test_malformed_max_iterations_does_not_crash(self):
        sid = self._send(action="session_open")["data"]["session_id"]
        # A non-numeric limit must not raise; it degrades to unset → normal answer.
        r = self._send(action="session_send", session_id=sid, input="hi", max_iterations="abc")
        self.assertEqual(r["status"], "ok")
        self.assertTrue(r["data"]["answer"].startswith("stub:"))

    def test_null_input_does_not_corrupt_session(self):
        # Regression: {"input": null} must coerce to "" and answer cleanly, not append a
        # None-content message that poisons the session for every later turn.
        sid = self._send(action="session_open")["data"]["session_id"]
        r = self._send(action="session_send", session_id=sid, input=None)
        self.assertEqual(r["status"], "ok")
        r2 = self._send(action="session_send", session_id=sid, input="follow up")
        self.assertEqual(r2["status"], "ok")  # session still usable

    def test_unknown_action_is_clean_error(self):
        r = self._send(action="nope")
        self.assertEqual(r["status"], "error")

    def test_invalid_json_is_clean_error(self):
        r = self.h.dispatch("not json{")
        self.assertEqual(r["status"], "error")

    def test_send_requires_session_id(self):
        r = self._send(action="session_send", input="hi")
        self.assertEqual(r["status"], "error")

    def test_send_auto_creates_unknown_session(self):
        # A caller (e.g. a workflow step using ${{ workflow.run_id }}) need not pre-open:
        # session_send to an unknown id creates it on first use and is reusable across turns,
        # so the workflow author never has to manage a session_id.
        r = self._send(action="session_send", session_id="run-123", input="hi")
        self.assertEqual(r["status"], "ok")
        self.assertTrue(r["data"]["answer"].startswith("stub:"))
        r2 = self._send(action="session_send", session_id="run-123", input="again")
        self.assertEqual(r2["status"], "ok")


def _jwt(claims):
    """Build an unsigned JWT-shaped string with the given claims payload."""
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64({'alg': 'none'})}.{b64(claims)}.sig"


class JwtUsernameTest(unittest.TestCase):
    def test_claim_priority_preferred_username_first(self):
        tok = _jwt({"preferred_username": "alice", "username": "a2", "sub": "a3"})
        self.assertEqual(jwt_username(tok), "alice")

    def test_falls_back_username_then_sub(self):
        self.assertEqual(jwt_username(_jwt({"username": "bob", "sub": "b2"})), "bob")
        self.assertEqual(jwt_username(_jwt({"sub": "carol"})), "carol")

    def test_malformed_token_returns_empty(self):
        self.assertEqual(jwt_username("not-a-jwt"), "")
        self.assertEqual(jwt_username(""), "")
        self.assertEqual(jwt_username("a.b"), "")  # b not valid base64 json


class _FailingLLM:
    """Spends tokens on the first call (a tool turn), then raises on the second —
    exercising the generic-exception path mid-turn after partial spend."""
    def __init__(self):
        self._calls = 0

    def name(self):
        return "failing"

    def complete(self, messages, tools, stream):
        self._calls += 1
        if self._calls == 1:
            return Completion(
                message=Message(role=ROLE_ASSISTANT, tool_calls=[ToolCall("c1", "echo", "{}")]),
                usage=Usage(input_tokens=10, output_tokens=5))
        raise RuntimeError("provider blew up mid-turn")


class PartialSpendTest(unittest.TestCase):
    def test_generic_exception_still_records_partial_spend(self):
        # Regression: tokens spent before a non-budget exception must still hit the ledger
        # (previously only the BudgetExceeded path recorded spend).
        tmp = tempfile.mkdtemp()
        ledger = Ledger(f"{tmp}/ledger", {})

        class ToolClient:
            def list_apps(self):
                return []  # no tools advertised; the tool call will error, but that's fine

            def run_task(self, name, args, timeout):
                return "{}"

        h = Handler(store=Store(f"{tmp}/s", 0), ledger=ledger,
                    ceiling=TurnLimits(max_iterations=8, max_tokens=0),
                    llm_name="fake", server_uri="127.0.0.1:6059", tenant="acme",
                    workspace=f"{tmp}/w", tool_timeout=30, admins=[],
                    client_factory=lambda token: ToolClient(),
                    auth_fn=lambda token: "alice", llm=_FailingLLM())
        sid = h.dispatch(json.dumps({"action": "session_open", "token": "t"}))["data"]["session_id"]
        r = h.dispatch(json.dumps({"action": "session_send", "session_id": sid, "token": "t", "input": "go"}))
        self.assertEqual(r["status"], "error")
        self.assertEqual(ledger.used("acme"), 15)  # 10 input + 5 output from the first call


class AsIntTest(unittest.TestCase):
    def test_coercion(self):
        self.assertEqual(_as_int("5"), 5)
        self.assertEqual(_as_int(5), 5)
        self.assertEqual(_as_int("abc"), 0)
        self.assertEqual(_as_int(None), 0)
        self.assertEqual(_as_int(-3), 0)      # negative → unset
        self.assertEqual(_as_int(0), 0)


if __name__ == "__main__":
    unittest.main()
