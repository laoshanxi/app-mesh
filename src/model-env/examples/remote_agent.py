#!/usr/bin/env python3
"""Reference reasoning service for the model-env `remote` backend.

The Go model-env App keeps the platform layer (ReAct loop, tools, budgets,
sessions, RBAC, transport) and forwards a single model call here. This service
is a *stateless completion provider*: given the conversation history and tool
specs, return the next assistant turn (text or tool calls) and token usage. It
does NOT run the agent loop or invoke tools — the Go host does that.

This lets the LLM-interaction layer live in Python (Anthropic/OpenAI SDKs, the
wider agent ecosystem) while everything else stays in Go. The seam is exactly
the HTTP contract below.

Protocol (POST /complete):
    request : {"messages":[Message...], "tools":[ToolSpec...], "stream":bool}
    response (stream=false): {"message":{...}, "usage":{...}}
    response (stream=true) : text/event-stream of
        data: {"type":"text","text":"<chunk>"}                      (optional)
        data: {"type":"completion","message":{...},"usage":{...}}   (final)
        data: {"type":"error","error":"<message>"}

Message = {role, content, tool_calls:[{id,name,arguments}], tool_call_id, name}
ToolSpec = {name, description, parameters(JSON Schema)}

Run:
    pip install anthropic
    ANTHROPIC_API_KEY=... MODELENV_REMOTE_MODEL=claude-opus-4-8 python remote_agent.py
Then point the Go App at it:
    MODELENV_BACKEND=remote MODELENV_REMOTE_URL=http://127.0.0.1:9100
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import anthropic

MODEL = os.environ.get("MODELENV_REMOTE_MODEL", "claude-opus-4-8")
MAX_TOKENS = int(os.environ.get("MODELENV_REMOTE_MAX_TOKENS", "8192"))
client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY


def to_anthropic(messages):
    """Convert the neutral history into Anthropic system + messages.

    System messages hoist into `system`; runs of tool results merge into one
    user message (the API requires alternating roles and all tool_results for an
    assistant turn in the following user turn) — the Python twin of the Go
    anthropic backend's buildRequest.
    """
    system_parts, msgs, tool_run = [], [], []

    def flush():
        if tool_run:
            msgs.append({"role": "user", "content": list(tool_run)})
            tool_run.clear()

    for m in messages:
        role = m.get("role")
        if role == "tool":
            tool_run.append({
                "type": "tool_result",
                "tool_use_id": m.get("tool_call_id", ""),
                "content": m.get("content", ""),
            })
            continue
        flush()
        if role == "system":
            system_parts.append(m.get("content", ""))
        elif role == "user":
            msgs.append({"role": "user",
                         "content": [{"type": "text", "text": m.get("content", "")}]})
        elif role == "assistant":
            blocks = []
            if m.get("content"):
                blocks.append({"type": "text", "text": m["content"]})
            for tc in m.get("tool_calls") or []:
                blocks.append({
                    "type": "tool_use",
                    "id": tc["id"],
                    "name": tc["name"],
                    "input": json.loads(tc.get("arguments") or "{}"),
                })
            msgs.append({"role": "assistant", "content": blocks})
    flush()
    return "\n\n".join(p for p in system_parts if p), msgs


def complete(messages, tools):
    system, msgs = to_anthropic(messages)
    ant_tools = [{
        "name": t["name"],
        "description": t.get("description", ""),
        "input_schema": t.get("parameters") or {"type": "object", "properties": {}},
    } for t in (tools or [])]

    kwargs = {"model": MODEL, "max_tokens": MAX_TOKENS, "messages": msgs}
    if system:
        kwargs["system"] = system
    if ant_tools:
        kwargs["tools"] = ant_tools

    resp = client.messages.create(**kwargs)

    text, tool_calls = [], []
    for block in resp.content:
        if block.type == "text":
            text.append(block.text)
        elif block.type == "tool_use":
            tool_calls.append({
                "id": block.id,
                "name": block.name,
                "arguments": json.dumps(block.input),
            })
    return {
        "message": {"role": "assistant", "content": "".join(text), "tool_calls": tool_calls},
        "usage": {"input_tokens": resp.usage.input_tokens,
                  "output_tokens": resp.usage.output_tokens},
    }


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path.rstrip("/") != "/complete":
            self.send_error(404)
            return
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        stream = bool(body.get("stream"))
        try:
            result = complete(body.get("messages") or [], body.get("tools") or [])
        except Exception as exc:  # surface as a protocol error
            if stream:
                self._sse([{"type": "error", "error": str(exc)}])
            else:
                self.send_error(500, str(exc))
            return

        if stream:
            # This reference does not stream tokens incrementally; it emits the
            # final completion as one SSE event. To stream, use the SDK's
            # streaming API and emit {"type":"text",...} per chunk first.
            self._sse([{"type": "completion", **result}])
        else:
            self._json(result)

    def _json(self, obj):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _sse(self, events):
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        for ev in events:
            self.wfile.write(b"data: " + json.dumps(ev).encode() + b"\n\n")
            self.wfile.flush()

    def log_message(self, *_):  # quiet
        pass


if __name__ == "__main__":
    port = int(os.environ.get("MODELENV_REMOTE_PORT", "9100"))
    print(f"reasoning service on :{port} (model={MODEL})")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
