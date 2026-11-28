# streaming.py
"""Server-sent-events (SSE) primitives shared by the streaming client APIs.

The daemon answers ``GET /appmesh/app/{name}/output/stream`` and
``POST /appmesh/app/{name}/task/stream`` with ``text/event-stream`` frames:

    event: stdout   data: {"position": <int>, "raw_size"?: <int>, "output": "<text>"}
    event: partial  data: {"data": "<text>"}
    event: final    data: {"result": "<payload>"}
    event: end      data: {"reason": "exit|removed|timeout|eof|final|disconnected|error", ...}

Exactly one terminal ``end`` frame closes every stream; ``: ping`` comment
lines are heartbeats.
"""

import json
from dataclasses import dataclass
from typing import Iterator, Optional, Tuple

import requests

from .exceptions import AppMeshConnectionError, AppMeshError, AppMeshRequestError, AppMeshTimeoutError


@dataclass
class SseEnd:
    """Terminal marker of an SSE stream (the generator's return value)."""

    reason: str
    """exit | removed | timeout | eof | final | disconnected | error | closed (peer cut the stream)"""
    exit_code: Optional[int] = None
    """output streams: process exit code when reason is 'exit'"""
    position: Optional[int] = None
    """output streams: final stdout byte cursor"""
    status: Optional[int] = None
    """task streams: HTTP status carried by an error end frame"""
    message: Optional[str] = None
    """task streams: error message"""
    result: Optional[str] = None
    """task streams: the final result payload (same string run_task would return)"""


def iter_sse_events(resp: requests.Response) -> Iterator[Tuple[str, dict]]:
    """Yields ``(event, payload)`` from a streamed ``text/event-stream`` response.

    Invalid JSON in a frame raises AppMeshRequestError. A connection dropped or a
    read timeout before the terminal event raises AppMeshConnectionError (or
    AppMeshTimeoutError), not a raw ``requests`` exception, so the streaming
    generators surface one exception hierarchy.
    """
    resp.encoding = "utf-8"
    event_name = "message"
    data_lines = []
    try:
        for line in resp.iter_lines(decode_unicode=True):
            if line is None:
                continue
            if line == "":
                if event_name != "message" or data_lines:
                    data = "\n".join(data_lines)
                    if data:
                        try:
                            payload = json.loads(data)
                        except ValueError as exc:
                            raise AppMeshRequestError(f"malformed SSE frame ({event_name}): {exc}") from exc
                    else:
                        payload = {}
                    yield event_name, payload
                event_name, data_lines = "message", []
                continue
            if line.startswith(":"):
                continue  # heartbeat comment
            if line.startswith("event:"):
                event_name = line[len("event:"):].strip()
            elif line.startswith("data:"):
                data_lines.append(line[len("data:"):].lstrip())
    except requests.exceptions.Timeout as exc:
        raise AppMeshTimeoutError(f"stream interrupted by a read timeout before the terminal event: {exc}") from exc
    except requests.exceptions.RequestException as exc:
        raise AppMeshConnectionError(f"stream interrupted before the terminal event: {exc}") from exc


def end_from_payload(payload: dict, **extra) -> SseEnd:
    """Builds the terminal marker from an ``end`` frame payload."""
    end = SseEnd(
        reason=str(payload.get("reason", "closed")),
        exit_code=payload.get("exit_code"),
        position=payload.get("position"),
        status=payload.get("status"),
        message=payload.get("message"),
    )
    for key, value in extra.items():
        setattr(end, key, value)
    return end


def raise_on_error_end(end: SseEnd) -> None:
    """Turns an error/timeout terminal frame into the matching exception."""
    if end.reason == "error":
        raise AppMeshRequestError(end.message or "stream failed with an error")
    if end.reason == "timeout":
        raise AppMeshTimeoutError(end.message or "stream timed out")
    if end.reason not in ("exit", "removed", "eof", "final", "disconnected", "closed"):
        raise AppMeshError(f"stream ended with unknown reason: {end.reason}")


def route_hint(status: int) -> str:
    """Pointer appended to SSE 404/405 errors: the engine serves streaming routes
    on its native listener (default wss/https 6063), and the agent REST listener
    (the client's default port 6060) relays them for local and forwarded requests."""
    if status in (404, 405):
        return (" Streaming is served by the engine's native listener (default wss/https port"
                " 6063) and relayed by the agent REST listener (default port 6060), which also"
                " forwards streams when X-Target-Host is set.")
    return ""
