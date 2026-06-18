"""Provider message-conversion correctness — exercised without any network.

These guard the shapes the real Anthropic/OpenAI APIs are strict about: Anthropic
rejects an empty content array and requires alternating user/assistant turns; OpenAI
needs content=None on a tool-call assistant turn. The dangerous histories (empty
assistant turn, consecutive user turns after a budget breach, tool_result followed by
a user message) only arise at runtime, so unit-testing the converters directly is the
only cheap way to cover them before a real provider call.
"""
import unittest

from llm_agent.llm import _to_anthropic, _to_openai
from llm_agent.types import (
    Message, ROLE_ASSISTANT, ROLE_SYSTEM, ROLE_TOOL, ROLE_USER, ToolCall,
)


class ToAnthropicTest(unittest.TestCase):
    def test_system_extracted_not_in_messages(self):
        system, msgs = _to_anthropic([
            Message(role=ROLE_SYSTEM, content="be terse"),
            Message(role=ROLE_USER, content="hi"),
        ])
        self.assertEqual(system, "be terse")
        self.assertEqual([m["role"] for m in msgs], ["user"])

    def test_empty_assistant_turn_is_dropped(self):
        # An empty assistant message must not become {"content": []} (Anthropic 400).
        _, msgs = _to_anthropic([
            Message(role=ROLE_USER, content="hi"),
            Message(role=ROLE_ASSISTANT, content="", tool_calls=[]),
            Message(role=ROLE_USER, content="still there?"),
        ])
        self.assertTrue(all(m["content"] for m in msgs), "no empty content arrays")
        # the two user turns around the dropped assistant must coalesce into one
        self.assertEqual([m["role"] for m in msgs], ["user"])
        self.assertEqual(len(msgs[0]["content"]), 2)

    def test_consecutive_user_turns_coalesce(self):
        # Arises after a budget breach: a tool_result (user-role) turn followed by the
        # next user input — Anthropic requires alternation, so they must merge.
        _, msgs = _to_anthropic([
            Message(role=ROLE_USER, content="q1"),
            Message(role=ROLE_ASSISTANT, content="", tool_calls=[ToolCall("c1", "echo", "{}")]),
            Message(role=ROLE_TOOL, tool_call_id="c1", name="echo", content="result"),
            Message(role=ROLE_USER, content="q2"),
        ])
        roles = [m["role"] for m in msgs]
        self.assertEqual(roles, ["user", "assistant", "user"])  # alternating
        # the trailing user turn holds both the tool_result and the new text
        last = msgs[-1]["content"]
        self.assertEqual(last[0]["type"], "tool_result")
        self.assertEqual(last[1]["type"], "text")

    def test_assistant_text_and_tool_use_both_kept(self):
        _, msgs = _to_anthropic([
            Message(role=ROLE_USER, content="go"),
            Message(role=ROLE_ASSISTANT, content="thinking", tool_calls=[ToolCall("c1", "echo", '{"a":1}')]),
            Message(role=ROLE_TOOL, tool_call_id="c1", name="echo", content="ok"),
        ])
        asst = msgs[1]["content"]
        self.assertEqual(asst[0], {"type": "text", "text": "thinking"})
        self.assertEqual(asst[1], {"type": "tool_use", "id": "c1", "name": "echo", "input": {"a": 1}})


class ToOpenAITest(unittest.TestCase):
    def test_assistant_tool_call_has_null_content(self):
        out = _to_openai([
            Message(role=ROLE_ASSISTANT, content="", tool_calls=[ToolCall("c1", "echo", "{}")]),
        ])
        self.assertIsNone(out[0]["content"])
        self.assertEqual(out[0]["tool_calls"][0]["id"], "c1")

    def test_tool_and_system_roles_passthrough(self):
        out = _to_openai([
            Message(role=ROLE_SYSTEM, content="sys"),
            Message(role=ROLE_TOOL, tool_call_id="c1", name="echo", content="r"),
        ])
        self.assertEqual(out[0], {"role": "system", "content": "sys"})
        self.assertEqual(out[1], {"role": "tool", "tool_call_id": "c1", "content": "r"})


if __name__ == "__main__":
    unittest.main()
