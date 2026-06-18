"""Task RPC handler: dispatches session_open / session_send / session_close.

The same handler runs in two admin-provisioned Apps (it registers nothing itself):
the shared per-tenant App (Scenario A, in-process sessions) and a per-session worker
App (Scenario B, ``worker_session_id`` set, streams to its own stdout, exits on
close/reap). It holds NO daemon credentials: the task RPC is authenticated by the
daemon-injected APP_MESH_PROCESS_KEY, and every other daemon call runs under the
caller's token from the request payload.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import sys
import threading
import time
from typing import Optional

from . import agent
from .budget import Ledger
from .llm import make_llm
from .session import Store
from .tools import ToolCatalog
from .types import AuthError, BudgetExceeded, Forbidden, NotFound, TurnLimits

log = logging.getLogger("llm_agent.handler")


def _ok(data=None):
    return {"status": "ok", "data": data} if data is not None else {"status": "ok"}


def _err(message, data=None):
    r = {"status": "error", "message": message}
    if data is not None:
        r["data"] = data
    return r


def _as_int(v) -> int:
    """Coerce an untrusted request field to a non-negative int; bad input → 0
    (treated as unset). Keeps a malformed client payload from crashing the turn."""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return 0
    return n if n > 0 else 0


def jwt_username(token: str) -> str:
    """Username from a JWT (validated elsewhere): preferred_username → username → sub,
    matching the daemon's claim priority across security backends."""
    parts = token.split(".")
    if len(parts) < 2:
        return ""
    try:
        pad = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(pad))
    except Exception:
        return ""
    return claims.get("preferred_username") or claims.get("username") or claims.get("sub") or ""


class Handler:
    def __init__(self, *, store: Store, ledger: Ledger, ceiling: TurnLimits, llm_name: str,
                 server_uri: str, tenant: str, workspace: str, tool_timeout: int,
                 admins, worker_session_id: str = "", max_input_chars: int = 0,
                 client_factory=None, auth_fn=None, llm=None):
        self.store = store
        self.ledger = ledger
        self.ceiling = ceiling
        self.llm = llm if llm is not None else make_llm(llm_name)
        self.server_uri = server_uri
        self.tenant = tenant
        self.workspace = workspace
        self.tool_timeout = tool_timeout
        self.admins = set(admins or [])
        self.worker_session_id = worker_session_id
        self.max_input_chars = max_input_chars  # 0 = unbounded
        self._client_factory = client_factory or self._default_client
        self._auth_fn = auth_fn or self._authenticate
        # worker lifecycle
        self._mu = threading.Lock()
        self._inflight = 0
        self._created = time.time()
        self._last_active = time.time()
        self.exit_requested = False

    # ----- daemon clients (caller-scoped; no service credentials) -----
    def _default_client(self, token: str):
        from appmesh import AppMeshClientTCP
        host, _, port = self.server_uri.partition(":")
        c = AppMeshClientTCP(tcp_address=(host or "127.0.0.1", int(port or 6059)), ssl_verify=False)
        c.set_token(token)
        return c

    def _authenticate(self, token: str) -> str:
        if not token:
            raise AuthError("token required")
        c = self._client_factory(token)
        try:
            c.get_current_user()  # validates: succeeds only for an authentic, unexpired token
        except Exception as e:
            log.warning("token validation failed: %s", e)  # detail to the log, not the caller
            raise AuthError("invalid or expired token")
        user = jwt_username(token)
        if not user:
            raise AuthError("token has no subject")
        return user

    def _is_admin(self, caller: str) -> bool:
        return caller in self.admins

    # ----- dispatch -----
    def dispatch(self, payload: str) -> dict:
        try:
            req = json.loads(payload)
        except Exception as e:
            return _err("invalid request JSON: %s" % e)
        token = req.get("token", "")
        try:
            caller = self._auth_fn(token)
        except AuthError as e:
            return _err("authentication failed: %s" % e)
        action = req.get("action")
        if action == "session_open":
            return self._open(caller)
        if action == "session_send":
            return self._send(req, caller, token)
        if action == "session_close":
            return self._close(req, caller)
        return _err("unknown action: %s" % action)

    def _open(self, caller: str) -> dict:
        if self.worker_session_id:
            return _err("session worker serves its single pre-assigned session; send to it directly")
        try:
            s = self.store.open(caller, self.tenant)
        except Exception as e:
            return _err("open session: %s" % e)
        return _ok({"session_id": s.id})

    def _close(self, req, caller: str) -> dict:
        sid = req.get("session_id", "")
        if not sid:
            return _err("session_id required")
        try:
            self.store.close(sid, caller, self._is_admin(caller), self.tenant)
        except NotFound:
            return _err("session not found")
        except Forbidden as e:
            return _err(str(e))
        if self.worker_session_id:
            self.cleanup_and_exit_after_ack()
        return _ok()

    def _send(self, req, caller: str, token: str) -> dict:
        sid = req.get("session_id", "")
        if not sid:
            return _err("session_id required")
        if self.worker_session_id and sid != self.worker_session_id:
            return _err("session not found")
        stream_requested = bool(req.get("stream"))
        if stream_requested and not self.worker_session_id:
            return _err("streaming is only available on a session worker App; the shared App does not stream")
        try:
            s = self.store.get(sid, caller, self._is_admin(caller), self.tenant)
        except NotFound:
            return _err("session not found")
        except Forbidden as e:
            return _err(str(e))

        try:
            self.ledger.check(self.tenant)
        except BudgetExceeded:
            return _err("budget_exceeded", {"reason": "tenant_quota", "tenant_used": self.ledger.used(self.tenant)})

        catalog = ToolCatalog(self._client_factory(token), self.tool_timeout, sid, self._session_workdir(sid))
        limits = self.ceiling.clamp(TurnLimits(_as_int(req.get("max_iterations")), _as_int(req.get("max_tokens"))))
        stream = (lambda c: (sys.stdout.write(c), sys.stdout.flush())) if (stream_requested and self.worker_session_id) else None

        user_input = req.get("input") or ""  # coerce null/missing → "" (never into history as None)
        if self.max_input_chars and len(user_input) > self.max_input_chars:
            return _err("input too large: %d chars (limit %d)" % (len(user_input), self.max_input_chars))
        with s.lock:
            before = s.cost_tokens  # run_turn grows cost_tokens as it spends; the delta is
            #                         this turn's spend even on a partial (exception) turn.
            try:
                res = agent.run_turn(self.llm, s, catalog, limits, stream, user_input)
            except BudgetExceeded as e:
                self.store.persist(s)  # partial history must survive
                self.ledger.add(self.tenant, s.cost_tokens - before)
                return _err("budget_exceeded", {
                    "reason": "turn_limit",
                    "iterations": e.result.iterations if e.result else 0,
                    "turn_tokens": e.result.turn_tokens if e.result else 0,
                    "max_tokens": limits.max_tokens,
                    "max_iterations": limits.max_iterations,
                })
            except Exception as e:
                self.store.persist(s)
                self.ledger.add(self.tenant, s.cost_tokens - before)  # record partial spend
                return _err(str(e))
            self.store.persist(s)
            self.ledger.add(self.tenant, s.cost_tokens - before)
        return _ok({"answer": res.answer, "iterations": res.iterations,
                    "turn_tokens": res.turn_tokens, "cost_tokens": s.cost_tokens})

    def _session_workdir(self, sid: str) -> str:
        if not self.workspace:
            return ""
        from .session import _safe
        d = os.path.join(self.workspace, _safe(self.tenant), _safe(sid))
        try:
            os.makedirs(d, exist_ok=True)
        except OSError as e:
            log.warning("session workdir %s: %s (tools run without an injected workdir)", d, e)
            return ""
        return d

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
