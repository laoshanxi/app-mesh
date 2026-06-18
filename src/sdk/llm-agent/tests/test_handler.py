"""Handler dispatch — turn routing to an injected fake engine (no SDK / network).

Guards the App-Mesh-facing contract: continue_conversation continuity keyed by the
session's cwd (first turn fresh, later turns continue), worker scoping, the shared-App
streaming refusal, close dropping the workdir, and robustness to a malformed payload.
"""
import json
import os
import tempfile
import unittest

from llm_agent import session
from llm_agent.claude_sdk import Result
from llm_agent.handler import Handler


class FakeEngine:
    def __init__(self, raise_first=False):
        self.calls = []
        self._raise_first = raise_first

    def __call__(self, user_input, *, cwd, continue_conversation, max_iterations, stream):
        self.calls.append({"input": user_input, "cwd": cwd, "continue": continue_conversation,
                           "max_iterations": max_iterations, "streamed": stream is not None})
        if self._raise_first and len(self.calls) == 1:
            raise RuntimeError("boom")
        if stream:
            stream(user_input)
        return Result(answer="stub: " + user_input, turn_tokens=42, iterations=1)


def _handler(worker_session_id="", max_iterations=0, raise_first=False):
    ws = tempfile.mkdtemp()
    eng = FakeEngine(raise_first=raise_first)
    h = Handler(workspace=ws, max_iterations=max_iterations,
                worker_session_id=worker_session_id, engine=eng)
    return h, eng, ws


def _send(h, **fields):
    return h.dispatch(json.dumps({"action": "session_send", **fields}))


class HandlerTest(unittest.TestCase):
    def test_session_open_is_gone(self):
        h, _, _ = _handler()
        self.assertEqual(h.dispatch(json.dumps({"action": "session_open"}))["status"], "error")

    def test_send_runs_engine_and_returns_answer(self):
        h, eng, _ = _handler()
        r = _send(h, session_id="s1", input="hi")
        self.assertEqual(r["data"]["answer"], "stub: hi")
        self.assertEqual(r["data"]["turn_tokens"], 42)
        self.assertTrue(eng.calls[0]["cwd"])  # a per-session workdir was passed as cwd

    def test_first_turn_fresh_then_continues(self):
        # The cwd's existence is the continuity signal: created on the first send, so the
        # second send must continue the conversation rather than start over.
        h, eng, _ = _handler()
        _send(h, session_id="s1", input="one")
        _send(h, session_id="s1", input="two")
        self.assertFalse(eng.calls[0]["continue"])
        self.assertTrue(eng.calls[1]["continue"])

    def test_close_removes_the_workdir(self):
        h, _, ws = _handler()
        _send(h, session_id="s1", input="hi")
        self.assertTrue(os.path.isdir(session.workdir(ws, "s1")))
        h.dispatch(json.dumps({"action": "session_close", "session_id": "s1"}))
        self.assertFalse(os.path.isdir(session.workdir(ws, "s1")))

    def test_malformed_max_iterations_does_not_crash(self):
        h, eng, _ = _handler()
        r = _send(h, session_id="s1", input="hi", max_iterations="not-a-number")
        self.assertEqual(r["status"], "ok")
        self.assertEqual(eng.calls[0]["max_iterations"], 0)

    def test_request_may_only_tighten_iteration_ceiling(self):
        h, eng, _ = _handler(max_iterations=5)
        _send(h, session_id="s1", input="hi", max_iterations=3)   # tighter → applies
        _send(h, session_id="s2", input="hi", max_iterations=9)   # looser → clamped to 5
        self.assertEqual(eng.calls[0]["max_iterations"], 3)
        self.assertEqual(eng.calls[1]["max_iterations"], 5)

    def test_streaming_refused_on_shared_app(self):
        h, eng, _ = _handler()
        r = _send(h, session_id="s1", input="hi", stream=True)
        self.assertEqual(r["status"], "error")
        self.assertFalse(eng.calls)  # never reached the engine

    def test_worker_streams_and_scopes_to_its_session(self):
        h, eng, _ = _handler(worker_session_id="W")
        ok = _send(h, session_id="W", input="hi", stream=True)
        self.assertEqual(ok["status"], "ok")
        self.assertTrue(eng.calls[0]["streamed"])
        wrong = _send(h, session_id="other", input="hi")
        self.assertEqual(wrong["status"], "error")

    def test_close_on_worker_requests_exit(self):
        h, _, _ = _handler(worker_session_id="W")
        h.dispatch(json.dumps({"action": "session_close", "session_id": "W"}))
        self.assertTrue(h.exit_requested)

    def test_worker_close_rejects_other_session(self):
        # A worker's close must be scoped to its own session — it must not delete a
        # sibling session's workdir or exit on someone else's close.
        h, _, ws = _handler(worker_session_id="W")
        other = session.workdir(ws, "other")
        os.makedirs(other)
        r = h.dispatch(json.dumps({"action": "session_close", "session_id": "other"}))
        self.assertEqual(r["status"], "error")
        self.assertFalse(h.exit_requested)
        self.assertTrue(os.path.isdir(other))  # sibling workdir untouched

    def test_failed_first_turn_does_not_poison_resume(self):
        # First turn errors → cwd exists but no conversation was persisted; the retry must
        # start FRESH (continue=False), not resume into an empty cwd.
        h, eng, _ = _handler(raise_first=True)
        self.assertEqual(_send(h, session_id="s1", input="one")["status"], "error")
        self.assertEqual(_send(h, session_id="s1", input="two")["status"], "ok")
        self.assertFalse(eng.calls[0]["continue"])
        self.assertFalse(eng.calls[1]["continue"])  # not poisoned by the dir existing


if __name__ == "__main__":
    unittest.main()
