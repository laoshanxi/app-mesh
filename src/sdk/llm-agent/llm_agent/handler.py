"""Task RPC handler: dispatches session_send / session_close, delegating each turn to
the Claude Agent SDK. Runs in two roles — the shared App (many sessions, one stable cwd
each) and a per-session worker (one session, streams to its own stdout, exits on
close/reap).

No auth, quota, owner, tenant, session store, or per-session lock: the daemon authorizes
``run_task`` (RBAC + the worker App's owner-permission), the serve loop is serial, and
the SDK owns the conversation (by cwd). A session is just its workdir.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from typing import Optional

from . import claude_sdk, session

log = logging.getLogger("llm_agent.handler")


def _ok(data=None):
    return {"status": "ok", "data": data} if data is not None else {"status": "ok"}


def _err(message):
    return {"status": "error", "message": message}


def _as_int(v) -> int:
    """Coerce an untrusted request field to a non-negative int; bad input → 0 (unset)."""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return 0
    return n if n > 0 else 0


class Handler:
    def __init__(self, *, workspace: str, max_iterations: int = 0,
                 worker_session_id: str = "", engine=None):
        self.workspace = workspace
        self.max_iterations = max_iterations  # 0 = no ceiling (SDK default)
        self.worker_session_id = worker_session_id
        self._engine = engine or claude_sdk.run_turn  # seam: tests inject a fake
        # worker lifecycle
        self._mu = threading.Lock()
        self._inflight = 0
        self._created = time.time()
        self._last_active = time.time()
        self.exit_requested = False

    # ----- dispatch -----
    def dispatch(self, payload: str) -> dict:
        try:
            req = json.loads(payload)
        except Exception as e:
            return _err("invalid request JSON: %s" % e)
        action = req.get("action")
        if action == "session_send":
            return self._send(req)
        if action == "session_close":
            return self._close(req)
        return _err("unknown action: %s" % action)

    def _send(self, req) -> dict:
        sid = req.get("session_id", "")
        if not sid:
            return _err("session_id required")
        if self.worker_session_id and sid != self.worker_session_id:
            return _err("this worker serves a different session")
        stream_requested = bool(req.get("stream"))
        if stream_requested and not self.worker_session_id:
            return _err("streaming is only available on a session worker App; the shared App does not stream")

        cwd = session.workdir(self.workspace, sid)
        resume = session.started(cwd)  # a prior turn COMPLETED here → continue it (not mere dir existence)
        if cwd:
            try:
                os.makedirs(cwd, exist_ok=True)
                os.utime(cwd, None)  # touch: marks activity for idle reaping
            except OSError as e:
                log.warning("session workdir %s: %s (running without a fixed cwd)", cwd, e)
                cwd, resume = "", False

        stream = (lambda c: (sys.stdout.write(c), sys.stdout.flush())) if (stream_requested and self.worker_session_id) else None
        user_input = req.get("input") or ""
        try:
            res = self._engine(user_input, cwd=cwd, continue_conversation=resume,
                               max_iterations=self._effective_max_iterations(req), stream=stream)
        except Exception as e:
            return _err(str(e))
        session.mark_started(cwd)  # only after a successful turn, so a failed first turn won't poison resume
        return _ok({"answer": res.answer, "iterations": res.iterations, "turn_tokens": res.turn_tokens})

    def _close(self, req) -> dict:
        sid = req.get("session_id", "")
        if not sid:
            return _err("session_id required")
        if self.worker_session_id and sid != self.worker_session_id:
            return _err("this worker serves a different session")
        session.remove(self.workspace, sid)
        if self.worker_session_id:
            self.cleanup_and_exit_after_ack()
        return _ok()

    def _effective_max_iterations(self, req) -> int:
        """A request may only tighten the operator ceiling (0 = no ceiling on either side)."""
        req_n = _as_int(req.get("max_iterations"))
        ceil = self.max_iterations
        if req_n and (ceil <= 0 or req_n < ceil):
            return req_n
        return ceil

    # ----- worker lifecycle -----
    def begin_request(self):
        with self._mu:
            self._inflight += 1
            self._last_active = time.time()

    def end_request(self):
        with self._mu:
            self._inflight -= 1
            self._last_active = time.time()

    def cleanup_and_exit_after_ack(self):
        with self._mu:
            self.exit_requested = True

    def reap_due(self, idle_ttl: float, max_life: float) -> Optional[str]:
        with self._mu:
            if self._inflight > 0:
                return None
            now = time.time()
            if idle_ttl > 0 and now - self._last_active > idle_ttl:
                return "idle"
            if max_life > 0 and now - self._created > max_life:
                return "max-lifetime"
        return None
