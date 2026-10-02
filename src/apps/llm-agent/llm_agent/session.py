"""A session is just a stable working directory under the workspace, named by the
caller's session id. The Claude Agent SDK owns the conversation history on disk (keyed
by this cwd), so there is no session record to store — the directory IS the state.

No owner, tenant, message history, or persisted session map: access control is the
daemon's (RBAC + the worker App's permission), and continuity is the SDK's (by cwd).
"""
from __future__ import annotations

import os
import re
import shutil
import time


_STARTED = ".llmagent-started"


def _safe(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "-", s) or "default"


def started(cwd: str) -> bool:
    """True once a turn has COMPLETED in this cwd (a sentinel file). The next turn then
    resumes the SDK conversation. Mere directory existence is not enough — a first turn
    that errored leaves the dir but no resumable history, so we must not resume into it."""
    return bool(cwd) and os.path.exists(os.path.join(cwd, _STARTED))


def mark_started(cwd: str) -> None:
    """Record that a turn completed in this cwd (so the next turn resumes)."""
    if cwd:
        try:
            open(os.path.join(cwd, _STARTED), "a").close()
        except OSError:
            pass


def workdir(workspace: str, sid: str) -> str:
    """Absolute, stable cwd for a session — the key the SDK uses to separate each
    conversation's history. Empty workspace → "" (the SDK uses its own default cwd)."""
    return os.path.join(workspace, _safe(sid)) if workspace else ""


def remove(workspace: str, sid: str) -> None:
    """Drop a session's workdir (used on session_close and worker reap)."""
    d = workdir(workspace, sid)
    if d:
        shutil.rmtree(d, ignore_errors=True)


def reap_workdirs(workspace: str, ttl_seconds: float) -> int:
    """Delete session workdirs untouched for longer than ttl (the handler touches a
    session's dir on each turn). Stateless idle cleanup; ttl<=0 disables it."""
    if ttl_seconds <= 0 or not workspace or not os.path.isdir(workspace):
        return 0
    cutoff = time.time() - ttl_seconds
    n = 0
    for name in os.listdir(workspace):
        p = os.path.join(workspace, name)
        if not os.path.isdir(p):
            continue
        try:
            if os.path.getmtime(p) < cutoff:
                shutil.rmtree(p, ignore_errors=True)
                n += 1
        except OSError:
            pass
    return n
