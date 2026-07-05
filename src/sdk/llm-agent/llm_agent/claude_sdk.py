"""The agent loop, delegated to the official Claude Agent SDK (Claude Code-based).

One turn = one ``query()`` call in the session's stable ``cwd``. The SDK owns the
conversation history (persisted by the Claude Code CLI under
``~/.claude/projects/<encoded-cwd>/*.jsonl``, keyed by ``cwd``), so we keep nothing
ourselves: ``continue_conversation=True`` resumes that cwd's conversation, and the
caller's session id simply maps to a fixed cwd. We never store messages or session ids.

Runtime: the ``claude-agent-sdk`` wheel bundles the Claude Code CLI it drives as a
subprocess (no Node.js needed). The Claude API key comes from ``ANTHROPIC_API_KEY`` in
the App's secured env (Bedrock/Vertex via the usual ``CLAUDE_CODE_USE_*`` env).

Tools are Claude Code's full built-in tool set (Bash included) running in the session
``cwd``; ``permission_mode`` defaults to ``bypassPermissions`` so an unattended worker
never blocks on a prompt. Override via ``LLMAGENT_ALLOWED_TOOLS`` / ``LLMAGENT_PERMISSION_MODE``.
"""
from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass

from .types import StreamFn

log = logging.getLogger("llm_agent.claude_sdk")


@dataclass
class Result:
    answer: str = ""
    turn_tokens: int = 0   # input + output tokens for this turn
    iterations: int = 0    # assistant turns the SDK took


def _options(cwd: str, continue_conversation: bool, max_iterations: int):
    """ClaudeAgentOptions for one turn. Imported lazily so the module loads (and tests
    inject a fake engine) without the SDK / Node CLI present."""
    from claude_agent_sdk import ClaudeAgentOptions
    kw = {"permission_mode": os.environ.get("LLMAGENT_PERMISSION_MODE") or "bypassPermissions"}
    if cwd:
        kw["cwd"] = cwd
    if continue_conversation:
        kw["continue_conversation"] = True  # resume the prior conversation in this cwd
    if os.environ.get("LLMAGENT_MODEL"):
        kw["model"] = os.environ["LLMAGENT_MODEL"]
    if os.environ.get("LLMAGENT_SYSTEM_PROMPT"):
        kw["system_prompt"] = os.environ["LLMAGENT_SYSTEM_PROMPT"]
    if os.environ.get("LLMAGENT_ALLOWED_TOOLS"):  # default: unset → SDK's full tool set
        kw["allowed_tools"] = [t.strip() for t in os.environ["LLMAGENT_ALLOWED_TOOLS"].split(",") if t.strip()]
    if max_iterations > 0:
        kw["max_turns"] = max_iterations
    return ClaudeAgentOptions(**kw)


async def _run(prompt: str, options, stream: StreamFn) -> Result:
    from claude_agent_sdk import query, AssistantMessage, TextBlock, ResultMessage
    text, res = [], Result()
    async for msg in query(prompt=prompt, options=options):
        if isinstance(msg, AssistantMessage):
            res.iterations += 1
            for block in msg.content:
                if isinstance(block, TextBlock) and block.text:
                    text.append(block.text)
                    if stream:
                        # A dead stream sink (e.g. broken pipe) must not abort an otherwise-good turn.
                        try:
                            stream(block.text)
                        except Exception:
                            log.warning("stream callback failed; continuing without streaming", exc_info=True)
        elif isinstance(msg, ResultMessage):
            usage = getattr(msg, "usage", None) or {}
            res.turn_tokens = int(usage.get("input_tokens") or 0) + int(usage.get("output_tokens") or 0)
    res.answer = "".join(text)
    if res.turn_tokens == 0:
        log.warning("claude-agent-sdk reported no usage tokens for this turn (no ResultMessage?)")
    return res


def run_turn(user_input: str, *, cwd: str, continue_conversation: bool,
             max_iterations: int, stream: StreamFn) -> Result:
    """Run one turn through the Claude Agent SDK. ``continue_conversation`` resumes the
    prior conversation in ``cwd`` (False on the first turn — a fresh conversation)."""
    return asyncio.run(_run(user_input, _options(cwd, continue_conversation, max_iterations), stream))
