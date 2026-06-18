"""Cross-run session store: disk-persisted, per-tenant namespaced, owner-checked.

A session holds the conversation history. Persisted as one JSON file per session
under <dir>/<tenant>/<id>.json so a restart can resume it. Reclaimed by idle TTL.
Each session has its own lock so a turn and the reaper don't race.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from dataclasses import asdict
from typing import Dict, List, Optional

from .types import Forbidden, Message, NotFound, ToolCall


class Session:
    def __init__(self, id: str, owner: str, tenant: str):
        self.id = id
        self.owner = owner
        self.tenant = tenant
        self.messages: List[Message] = []
        self.cost_tokens = 0
        self.updated_at = time.time()
        self.lock = threading.Lock()
        self.closed = False  # set under lock on close/delete/reap; persist() then no-ops

    def to_json(self) -> dict:
        return {
            "id": self.id, "owner": self.owner, "tenant": self.tenant,
            "cost_tokens": self.cost_tokens, "updated_at": self.updated_at,
            "messages": [asdict(m) for m in self.messages],
        }

    @classmethod
    def from_json(cls, d: dict) -> "Session":
        s = cls(d["id"], d["owner"], d["tenant"])
        s.cost_tokens = d.get("cost_tokens", 0)
        s.updated_at = d.get("updated_at", time.time())
        # asdict() flattened nested ToolCall dataclasses to dicts on the way out;
        # rebuild them so a resumed session's assistant tool-call turns stay typed
        # (otherwise the next turn's provider conversion hits dicts and AttributeErrors).
        s.messages = [
            Message(**{**m, "tool_calls": [ToolCall(**tc) for tc in m.get("tool_calls", [])]})
            for m in d.get("messages", [])
        ]
        return s


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "-", s) or "default"


class Store:
    def __init__(self, directory: str, ttl_seconds: float):
        self._dir = directory
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._sessions: Dict[str, Session] = {}
        os.makedirs(directory, exist_ok=True)
        self._load()

    def _path(self, tenant: str, sid: str) -> str:
        d = os.path.join(self._dir, _safe(tenant))
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, _safe(sid) + ".json")

    def _load(self) -> None:
        for root, _, files in os.walk(self._dir):
            for fn in files:
                if not fn.endswith(".json"):
                    continue
                try:
                    with open(os.path.join(root, fn)) as f:
                        s = Session.from_json(json.load(f))
                    self._sessions[s.id] = s
                except Exception:
                    continue

    def open(self, owner: str, tenant: str) -> Session:
        return self.create(uuid.uuid4().hex, owner, tenant)

    def create(self, sid: str, owner: str, tenant: str) -> Session:
        with self._lock:
            if sid in self._sessions:
                return self._sessions[sid]
            s = Session(sid, owner, tenant)
            self._sessions[sid] = s
        self.persist(s)
        return s

    def get(self, sid: str, caller: str, is_admin: bool, tenant: str = None) -> Session:
        with self._lock:
            s = self._sessions.get(sid)
        # tenant guard: _load() flattens every tenant's sessions into one map, so a
        # shared session dir could otherwise expose another tenant's session by id.
        # A tenant mismatch is reported as not-found (don't leak its existence).
        if s is None or (tenant is not None and s.tenant != tenant):
            raise NotFound("session not found")
        if not is_admin and s.owner != caller:
            raise Forbidden("permission denied: not the session owner")
        return s

    def persist(self, s: Session) -> None:
        if s.closed:  # closed/reaped concurrently — don't resurrect the file
            return
        s.updated_at = time.time()
        path = self._path(s.tenant, s.id)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(s.to_json(), f)
            f.flush()
            os.fsync(f.fileno())  # durable before the rename, so a resume can't read a torn/rolled-back file
        os.replace(tmp, path)

    def close(self, sid: str, caller: str, is_admin: bool, tenant: str = None) -> None:
        s = self.get(sid, caller, is_admin, tenant)
        with s.lock:                      # serialize with an in-flight turn; flag blocks its persist
            s.closed = True
            with self._lock:
                self._sessions.pop(sid, None)
            try:
                os.remove(self._path(s.tenant, s.id))
            except FileNotFoundError:
                pass

    def delete(self, sid: str) -> None:
        """Unconditionally drop a session and its on-disk history (used by a worker's
        reaper before it exits, so a reaped session leaves no conversation data)."""
        with self._lock:
            s = self._sessions.get(sid)
        if s is None:
            return
        # Mirror close()'s lock order (s.lock → _lock): set `closed` under s.lock so a
        # concurrent in-flight turn's persist() can't resurrect the file after removal.
        with s.lock:
            s.closed = True
            with self._lock:
                self._sessions.pop(sid, None)
            try:
                os.remove(self._path(s.tenant, s.id))
            except FileNotFoundError:
                pass

    def reap(self) -> int:
        if self._ttl <= 0:
            return 0
        cutoff = time.time() - self._ttl
        stale = []
        with self._lock:
            for s in self._sessions.values():
                # Skip a session mid-turn (its lock is held) — busy is not idle.
                if s.lock.acquire(blocking=False):
                    try:
                        if s.updated_at < cutoff:
                            s.closed = True  # under s.lock: a later turn's persist will no-op
                            stale.append(s)
                    finally:
                        s.lock.release()
            for s in stale:
                self._sessions.pop(s.id, None)
        for s in stale:
            try:
                os.remove(self._path(s.tenant, s.id))
            except FileNotFoundError:
                pass
        return len(stale)
