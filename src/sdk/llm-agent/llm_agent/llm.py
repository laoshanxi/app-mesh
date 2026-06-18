"""LLM backends behind one tiny interface.

The agent loop calls ``LLM.complete(messages, tools, stream)`` and gets back the
next assistant turn. Each backend delegates the actual provider HTTP / streaming /
tool-calling format to the official SDK rather than hand-rolling it. ``fake`` is
deterministic and network-free for tests.

Select with LLMAGENT_BACKEND (default: fake). Credentials/endpoints come from the
environment, never hardcoded.
"""
from __future__ import annotations

import json
import logging
import os
from typing import List, Protocol

log = logging.getLogger("llm_agent.llm")

from .types import (
    ROLE_ASSISTANT, ROLE_SYSTEM, ROLE_TOOL, ROLE_USER,
    Completion, Message, StreamFn, ToolCall, ToolSpec, Usage,
)


class LLM(Protocol):
    def name(self) -> str: ...
    def complete(self, messages: List[Message], tools: List[ToolSpec], stream: StreamFn) -> Completion: ...


def make_llm(name: str) -> LLM:
    name = name or "fake"
    if name == "fake":
        return FakeLLM()
    if name == "anthropic":
        return AnthropicLLM()
    if name == "openai":
        return OpenAILLM()
    raise ValueError(f"unknown LLMAGENT_BACKEND {name!r} (fake, anthropic, openai)")


def _max_output_tokens(default: int = 4096) -> int:
    v = os.environ.get("LLMAGENT_MAX_OUTPUT_TOKENS")
    if v and v.isdigit() and int(v) > 0:
        return int(v)
    return default


def _provider_timeout(default: float = 120.0) -> float:
    """Per-request provider timeout (s). Bounds a hung API call so it can't wedge a
    worker (or the shared App's serial loop) indefinitely. LLMAGENT_PROVIDER_TIMEOUT."""
    v = os.environ.get("LLMAGENT_PROVIDER_TIMEOUT")
    try:
        return float(v) if v else default
    except ValueError:
        return default


def _last_user(messages: List[Message]) -> str:
    for m in reversed(messages):
        if m.role == ROLE_USER:
            return m.content
    return ""


# --------------------------------------------------------------------------------
# fake — deterministic, no network. Mirrors a real agent's shape for tests/dev.
# --------------------------------------------------------------------------------
class FakeLLM:
    def name(self) -> str:
        return "fake"

    def complete(self, messages: List[Message], tools: List[ToolSpec], stream: StreamFn) -> Completion:
        last = _last_user(messages)
        # Emit one tool call per turn: only on the turn's first model call (latest
        # message is the user directive, not yet a tool result), if the named tool
        # exists. After the tool runs, fall through to a final answer (turn ends).
        if not (messages and messages[-1].role == ROLE_TOOL):
            name, args = _parse_tool_directive(last)
            if name and any(t.name == name for t in tools):
                return Completion(
                    message=Message(role=ROLE_ASSISTANT, tool_calls=[ToolCall("call_1", name, args)]),
                    usage=Usage(input_tokens=len(last), output_tokens=len(name) + len(args)),
                )
        answer = "stub: " + last
        if stream:
            for tok in answer.split(" "):
                stream(tok + " ")
        return Completion(
            message=Message(role=ROLE_ASSISTANT, content=answer),
            usage=Usage(input_tokens=len(last), output_tokens=len(answer)),
        )


def _parse_tool_directive(s: str):
    """Parse 'use tool <name> <json>' → (name, args-json) or ('', '{}')."""
    marker = "use tool "
    i = s.find(marker)
    if i < 0:
        return "", "{}"
    rest = s[i + len(marker):].strip()
    parts = rest.split(" ", 1)
    name = parts[0]
    args = parts[1].strip() if len(parts) > 1 else "{}"
    try:
        json.loads(args)
    except Exception:
        args = "{}"
    return name, args


# --------------------------------------------------------------------------------
# anthropic — official `anthropic` SDK does all HTTP/streaming/tool-format work.
# --------------------------------------------------------------------------------
class AnthropicLLM:
    def __init__(self):
        import anthropic  # lazy: only needed for this backend
        # A standard sk-ant-api key authenticates via x-api-key (the SDK default). An
        # sk-ant-oat OAuth access token (Claude Code / Console OAuth) must instead use
        # Authorization: Bearer + the oauth beta header, and must NOT also send x-api-key.
        key = os.environ.get("ANTHROPIC_API_KEY", "") or os.environ.get("ANTHROPIC_AUTH_TOKEN", "")
        opts = {"timeout": _provider_timeout()}  # also reads ANTHROPIC_BASE_URL from env
        if key.startswith("sk-ant-oat"):
            os.environ.pop("ANTHROPIC_API_KEY", None)  # else the SDK sends both creds → 401
            opts["auth_token"] = key
            opts["default_headers"] = {"anthropic-beta": "oauth-2025-04-20"}
        self._client = anthropic.Anthropic(**opts)
        self._model = os.environ.get("LLMAGENT_MODEL", "claude-opus-4-8")
        self._max_tokens = _max_output_tokens()

    def name(self) -> str:
        return "anthropic:" + self._model

    def complete(self, messages: List[Message], tools: List[ToolSpec], stream: StreamFn) -> Completion:
        system, msgs = _to_anthropic(messages)
        kwargs = dict(model=self._model, max_tokens=self._max_tokens, messages=msgs)
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = [
                {"name": t.name, "description": t.description, "input_schema": t.parameters or {"type": "object", "properties": {}}}
                for t in tools
            ]
        if stream:
            return _anthropic_stream(self._client, kwargs, stream)
        resp = self._client.messages.create(**kwargs)
        return _anthropic_completion(resp)


def _push_anthropic(msgs, role, blocks):
    """Append a turn, coalescing into the previous turn of the same role and dropping
    empties. Anthropic requires alternating user/assistant turns and rejects an empty
    content array — both can otherwise arise from a budget breach (tool_result turn
    immediately followed by the next user input) or an empty assistant turn."""
    if not blocks:
        return
    if msgs and msgs[-1]["role"] == role:
        msgs[-1]["content"].extend(blocks)
    else:
        msgs.append({"role": role, "content": list(blocks)})


def _to_anthropic(messages: List[Message]):
    system_parts, msgs, tool_run = [], [], []

    def flush():
        if tool_run:
            _push_anthropic(msgs, "user", list(tool_run))  # tool_result is a user-role turn
            tool_run.clear()

    for m in messages:
        if m.role == ROLE_TOOL:
            tool_run.append({"type": "tool_result", "tool_use_id": m.tool_call_id, "content": m.content})
            continue
        flush()
        if m.role == ROLE_SYSTEM:
            system_parts.append(m.content)
        elif m.role == ROLE_USER:
            _push_anthropic(msgs, "user", [{"type": "text", "text": m.content}] if m.content else [])
        elif m.role == ROLE_ASSISTANT:
            blocks = []
            if m.content:
                blocks.append({"type": "text", "text": m.content})
            for tc in m.tool_calls:
                blocks.append({"type": "tool_use", "id": tc.id, "name": tc.name, "input": json.loads(tc.arguments or "{}")})
            _push_anthropic(msgs, "assistant", blocks)
    flush()
    return "\n\n".join(p for p in system_parts if p), msgs


def _anthropic_completion(resp) -> Completion:
    text, calls = [], []
    for b in resp.content:
        if b.type == "text":
            text.append(b.text)
        elif b.type == "tool_use":
            calls.append(ToolCall(b.id, b.name, json.dumps(b.input)))
    return Completion(
        message=Message(role=ROLE_ASSISTANT, content="".join(text), tool_calls=calls),
        usage=Usage(resp.usage.input_tokens, resp.usage.output_tokens),
    )


def _anthropic_stream(client, kwargs, stream: StreamFn) -> Completion:
    with client.messages.stream(**kwargs) as s:
        for text in s.text_stream:
            stream(text)
        return _anthropic_completion(s.get_final_message())


# --------------------------------------------------------------------------------
# openai — official `openai` SDK (Chat Completions). Covers OpenAI + any
# OpenAI-compatible endpoint (vLLM/Ollama/TGI/...) via OPENAI_BASE_URL.
# --------------------------------------------------------------------------------
class OpenAILLM:
    def __init__(self):
        import openai  # lazy
        self._client = openai.OpenAI(timeout=_provider_timeout())  # reads OPENAI_API_KEY (+ OPENAI_BASE_URL)
        self._model = os.environ.get("LLMAGENT_MODEL", "gpt-4o")
        self._max_tokens = _max_output_tokens()

    def name(self) -> str:
        return "openai:" + self._model

    def complete(self, messages: List[Message], tools: List[ToolSpec], stream: StreamFn) -> Completion:
        kwargs = dict(model=self._model, max_tokens=self._max_tokens, messages=_to_openai(messages))
        if tools:
            kwargs["tools"] = [
                {"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.parameters or {"type": "object", "properties": {}}}}
                for t in tools
            ]
        if stream:
            kwargs["stream"] = True
            kwargs["stream_options"] = {"include_usage": True}
            return _openai_stream(self._client, kwargs, stream)
        resp = self._client.chat.completions.create(**kwargs)
        return _openai_completion(resp)


def _to_openai(messages: List[Message]):
    out = []
    for m in messages:
        if m.role == ROLE_TOOL:
            out.append({"role": "tool", "tool_call_id": m.tool_call_id, "content": m.content})
        elif m.role == ROLE_ASSISTANT and m.tool_calls:
            out.append({
                "role": "assistant",
                "content": m.content or None,
                "tool_calls": [{"id": tc.id, "type": "function", "function": {"name": tc.name, "arguments": tc.arguments}} for tc in m.tool_calls],
            })
        else:
            out.append({"role": m.role, "content": m.content})
    return out


def _openai_completion(resp) -> Completion:
    choice = resp.choices[0].message
    calls = [ToolCall(tc.id, tc.function.name, tc.function.arguments or "{}") for tc in (choice.tool_calls or [])]
    u = resp.usage
    return Completion(
        message=Message(role=ROLE_ASSISTANT, content=choice.content or "", tool_calls=calls),
        usage=Usage(getattr(u, "prompt_tokens", 0) or 0, getattr(u, "completion_tokens", 0) or 0),
    )


def _openai_stream(client, kwargs, stream: StreamFn) -> Completion:
    text = []
    calls = {}  # index -> {id,name,args}
    usage = Usage()
    for chunk in client.chat.completions.create(**kwargs):
        if chunk.usage:
            usage = Usage(chunk.usage.prompt_tokens or 0, chunk.usage.completion_tokens or 0)
        if not chunk.choices:
            continue
        delta = chunk.choices[0].delta
        if delta.content:
            text.append(delta.content)
            stream(delta.content)
        for tc in (delta.tool_calls or []):
            c = calls.setdefault(tc.index, {"id": "", "name": "", "args": ""})
            if tc.id:
                c["id"] = tc.id
            if tc.function and tc.function.name:
                c["name"] = tc.function.name
            if tc.function and tc.function.arguments:
                c["args"] += tc.function.arguments
    tool_calls = [ToolCall(c["id"], c["name"], c["args"] or "{}") for _, c in sorted(calls.items())]
    if usage.total == 0:
        # Many OpenAI-compatible servers (vLLM/Ollama/TGI) ignore stream_options and emit
        # no usage chunk. With zero tokens, the per-turn and per-tenant budgets can't count
        # this call — warn loudly rather than silently disable cost enforcement.
        log.warning("streaming completion reported zero usage tokens; token budgets "
                    "cannot account for this turn (backend may not support stream usage)")
    return Completion(message=Message(role=ROLE_ASSISTANT, content="".join(text), tool_calls=tool_calls), usage=usage)
