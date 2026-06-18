"""Agent loop behaviour with the deterministic fake LLM and a stub catalog.

These encode the loop's *contract*, not just its mechanics (Rule 9): a tool directive
must drive exactly one tool round then a final answer; the per-turn token ceiling must
stop a runaway turn and surface the partial result; tool output must be fed back as a
ROLE_TOOL message keyed to the originating call.
"""
import unittest

from llm_agent.agent import run_turn
from llm_agent.llm import FakeLLM
from llm_agent.session import Session
from llm_agent.types import BudgetExceeded, ROLE_TOOL, ToolSpec, TurnLimits


class StubCatalog:
    """A catalog exposing one named tool that echoes the call back."""

    def __init__(self, tool_name="echo"):
        self._tool_name = tool_name
        self.invocations = []

    def specs(self):
        return [ToolSpec(name=self._tool_name, description="echo", parameters={"type": "object"})]

    def invoke(self, call):
        self.invocations.append(call)
        return '{"ok": true}'


def _session():
    return Session(id="s1", owner="alice", tenant="default")


class AgentLoopTest(unittest.TestCase):
    def test_plain_answer_no_tools(self):
        res = run_turn(FakeLLM(), _session(), StubCatalog(), TurnLimits(), None, "hello")
        self.assertEqual(res.answer, "stub: hello")
        self.assertEqual(res.iterations, 1)
        self.assertGreater(res.turn_tokens, 0)

    def test_tool_directive_runs_exactly_one_round_then_answers(self):
        # run_turn is always handed a finite ceiling (the handler clamps every request
        # against LLMAGENT_MAX_ITERATIONS, default 8); a bare TurnLimits() floors to a
        # single iteration, leaving no room for the post-tool answer turn.
        sess, cat = _session(), StubCatalog("echo")
        res = run_turn(FakeLLM(), sess, cat, TurnLimits(max_iterations=8), None, "use tool echo {}")
        # One tool round, then a final answer turn — iterations == 2.
        self.assertEqual(res.iterations, 2)
        self.assertEqual(len(cat.invocations), 1)
        self.assertTrue(res.answer.startswith("stub:"))
        # The tool result was fed back, keyed to the call that produced it.
        tool_msgs = [m for m in sess.messages if m.role == ROLE_TOOL]
        self.assertEqual(len(tool_msgs), 1)
        self.assertEqual(tool_msgs[0].tool_call_id, cat.invocations[0].id)
        self.assertEqual(tool_msgs[0].name, "echo")

    def test_directive_for_unknown_tool_is_just_text(self):
        # Tool not in catalog → no tool round; the directive becomes a normal answer.
        sess, cat = _session(), StubCatalog("echo")
        res = run_turn(FakeLLM(), sess, cat, TurnLimits(), None, "use tool missing {}")
        self.assertEqual(res.iterations, 1)
        self.assertEqual(cat.invocations, [])

    def test_token_ceiling_stops_turn_and_carries_partial_result(self):
        # A tiny max_tokens trips on the first model call; the breach must expose how
        # far the turn got rather than silently truncating (Rule 12).
        with self.assertRaises(BudgetExceeded) as ctx:
            run_turn(FakeLLM(), _session(), StubCatalog(), TurnLimits(max_tokens=1), None, "hello there")
        self.assertIsNotNone(ctx.exception.result)
        self.assertGreaterEqual(ctx.exception.result.iterations, 1)

    def test_token_breach_leaves_no_dangling_tool_use_in_history(self):
        # A token breach on a tool-emitting turn must not persist the assistant tool_use
        # turn (a stranded tool_use with no tool_result would make the next provider
        # call invalid). History should hold no assistant message with tool_calls.
        sess, cat = _session(), StubCatalog("echo")
        with self.assertRaises(BudgetExceeded):
            run_turn(FakeLLM(), sess, cat, TurnLimits(max_iterations=8, max_tokens=1), None, "use tool echo {}")
        dangling = [m for m in sess.messages if m.role != ROLE_TOOL and m.tool_calls]
        self.assertEqual(dangling, [])
        self.assertEqual(cat.invocations, [])  # tool never ran either

    def test_invalid_tool_args_become_structured_error(self):
        # If the model emits truncated/garbled JSON args, the tool isn't invoked; a
        # structured error is fed back instead of crashing the turn.
        from llm_agent.agent import _dispatch
        from llm_agent.types import ToolCall
        cat = StubCatalog("echo")
        msgs = _dispatch(cat, [ToolCall("c1", "echo", '{"truncated":')])
        self.assertIn("invalid tool arguments", msgs[0].content)
        self.assertEqual(cat.invocations, [])

    def test_iteration_ceiling_breaches_before_answer(self):
        # max_iterations bounds the reason→act→observe loop. With a budget of 1, the
        # single iteration spends itself emitting+dispatching the tool call and the
        # loop exhausts before the answer turn can run → breach, not a silent stop.
        sess, cat = _session(), StubCatalog("echo")
        with self.assertRaises(BudgetExceeded) as ctx:
            run_turn(FakeLLM(), sess, cat, TurnLimits(max_iterations=1), None, "use tool echo {}")
        self.assertEqual(ctx.exception.result.iterations, 1)
        self.assertEqual(len(cat.invocations), 1)


if __name__ == "__main__":
    unittest.main()
