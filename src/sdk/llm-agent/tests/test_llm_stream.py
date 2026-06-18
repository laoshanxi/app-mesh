"""OpenAI streaming accumulation (_openai_stream) — tested with synthetic chunks, no
network. Guards the stateful delta-merge (content + tool-call id/name/args across
chunks), out-of-order tool-call indices, and usage extraction from the final chunk.
"""
import unittest
from types import SimpleNamespace as NS

from llm_agent.llm import _openai_stream


def _tc(index, id=None, name=None, args=None):
    return NS(index=index, id=id, function=NS(name=name, arguments=args))


def _chunk(content=None, tool_calls=None, usage=None):
    delta = NS(content=content, tool_calls=tool_calls)
    return NS(usage=usage, choices=[NS(delta=delta)] if usage is None else [])


def _client(chunks):
    return NS(chat=NS(completions=NS(create=lambda **kw: iter(chunks))))


class OpenAIStreamTest(unittest.TestCase):
    def test_text_and_single_tool_call_accumulate(self):
        chunks = [
            _chunk(content="Hel"),
            _chunk(content="lo"),
            _chunk(tool_calls=[_tc(0, id="c1", name="echo", args="")]),
            _chunk(tool_calls=[_tc(0, args='{"a":')]),
            _chunk(tool_calls=[_tc(0, args="1}")]),
            _chunk(usage=NS(prompt_tokens=3, completion_tokens=4)),
        ]
        streamed = []
        comp = _openai_stream(_client(chunks), {}, lambda c: streamed.append(c))
        self.assertEqual("".join(streamed), "Hello")
        self.assertEqual(comp.message.content, "Hello")
        self.assertEqual(len(comp.message.tool_calls), 1)
        tc = comp.message.tool_calls[0]
        self.assertEqual((tc.id, tc.name, tc.arguments), ("c1", "echo", '{"a":1}'))
        self.assertEqual(comp.usage.total, 7)

    def test_out_of_order_tool_call_indices_sorted(self):
        chunks = [
            _chunk(tool_calls=[_tc(1, id="c2", name="b", args="{}")]),
            _chunk(tool_calls=[_tc(0, id="c1", name="a", args="{}")]),
        ]
        comp = _openai_stream(_client(chunks), {}, lambda c: None)
        self.assertEqual([t.name for t in comp.message.tool_calls], ["a", "b"])  # by index

    def test_empty_args_default_to_object(self):
        chunks = [_chunk(tool_calls=[_tc(0, id="c1", name="noarg", args="")])]
        comp = _openai_stream(_client(chunks), {}, lambda c: None)
        self.assertEqual(comp.message.tool_calls[0].arguments, "{}")


if __name__ == "__main__":
    unittest.main()
