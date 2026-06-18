"""The agent loop: reason → act → observe, bounded by hard per-turn limits.

Provider details live in the LLM backend; tool execution lives in the catalog. This
loop only orchestrates: call the model, dispatch any tool calls (concurrently), feed
results back, repeat until a final answer or a budget breach.
"""
from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import List

from .types import BudgetExceeded, Message, ROLE_TOOL, StreamFn, ToolCall, TurnLimits

log = logging.getLogger("llm_agent.agent")


@dataclass
class Result:
    answer: str = ""
    iterations: int = 0
    turn_tokens: int = 0


def run_turn(llm, session, catalog, limits: TurnLimits, stream: StreamFn, user_input: str) -> Result:
    session.messages.append(Message(role="user", content=user_input))
    specs = catalog.specs()
    res = Result()

    for i in range(max(limits.max_iterations, 1)):
        res.iterations = i + 1
        comp = llm.complete(session.messages, specs, stream)
        res.turn_tokens += comp.usage.total
        session.cost_tokens += comp.usage.total

        # Check before appending: never leave an over-budget assistant turn in history.
        # If it carried tool_calls, persisting it would strand a tool_use with no
        # tool_result and make the next provider call invalid; the session stays at a
        # clean, resumable boundary instead.
        if limits.max_tokens and res.turn_tokens > limits.max_tokens:
            raise BudgetExceeded("budget_exceeded", res)
        session.messages.append(comp.message)

        if not comp.message.tool_calls:
            if not comp.message.content:
                log.warning("model returned neither text nor tool calls; answer is empty")
            res.answer = comp.message.content
            return res

        session.messages.extend(_dispatch(catalog, comp.message.tool_calls))

    raise BudgetExceeded("budget_exceeded", res)


def _dispatch(catalog, calls: List[ToolCall]) -> List[Message]:
    """Run a turn's tool calls concurrently, returning results in call order. A
    failed call becomes a structured error the model can react to."""
    def one(call: ToolCall) -> Message:
        try:
            json.loads(call.arguments or "{}")  # reject truncated/garbled model args early
        except ValueError:
            out = json.dumps({"error": "invalid tool arguments: not valid JSON"})
            return Message(role=ROLE_TOOL, tool_call_id=call.id, name=call.name, content=out)
        try:
            out = catalog.invoke(call) or ""  # never let a None result into history as content
        except Exception as e:
            out = json.dumps({"error": str(e)})
        return Message(role=ROLE_TOOL, tool_call_id=call.id, name=call.name, content=out)

    if len(calls) == 1:
        return [one(calls[0])]
    with ThreadPoolExecutor(max_workers=min(8, len(calls))) as ex:
        return list(ex.map(one, calls))
