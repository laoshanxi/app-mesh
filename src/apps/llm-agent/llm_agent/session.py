"""A session is just a stable working directory under the workspace, named by the
caller's session id. The Claude Agent SDK owns the conversation history on disk (keyed
by this cwd), so there is no session record to store — the directory IS the state.

No owner, tenant, message history, or persisted session map: access control is the
daemon's (RBAC + the worker App's permission), and continuity is the SDK's (by cwd).
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import time


_STARTED = ".llmagent-started"
# Subdirectories of the workspace that belong to the runtime, never to a session:
# the Claude Code config dir lives here by default (see __main__), so the idle reaper
# must never treat it as an abandoned session workdir.
_RESERVED = {".claude", ".llmagent"}


def _safe(s: str) -> str:
    """Map a session id to one directory name.

    Distinct ids must not collide: the raw sanitization folds many characters to "-",
    which would silently merge two callers' conversations. An id that already fits the
    safe alphabet is used as-is (stable across upgrades); anything else gets a short
    digest suffix so different ids keep different directories.
    """
    clean = re.sub(r"[^A-Za-z0-9_-]", "-", s)
    if not clean:
        return "default"
    if clean == s:
        return s
    digest = hashlib.sha1(s.encode("utf-8", "replace")).hexdigest()[:8]
    return clean + "-" + digest


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


def remove(workspace: str, sid: str, history_root: str = "") -> None:
    """Drop a session's workdir (used on session_close and worker reap).

    history_root is the CLI projects dir (typically <workspace>/.claude/projects).
    When given, also remove the session's on-disk conversation transcript (best
    effort: the CLI encodes the cwd path as its directory name)."""
    d = workdir(workspace, sid)
    if d:
        shutil.rmtree(d, ignore_errors=True)
        if history_root:
            _remove_history(history_root, d)


def _remove_history(history_root: str, cwd: str) -> None:
    """The Claude Code CLI stores a session's transcript under
    <CLAUDE_CONFIG_DIR>/projects/<encoded-cwd>/ where <encoded-cwd> replaces every
    character outside [A-Za-z0-9] with '-' (verified against the live projects dir).
    Best effort: if the encoding ever differs, the transcript stays and the operator
    clears projects/ manually."""
    p = os.path.join(history_root, re.sub(r"[^A-Za-z0-9]", "-", cwd))
    try:
        if os.path.isdir(p):
            shutil.rmtree(p, ignore_errors=True)
    except OSError:
        pass


def reap_workdirs(workspace: str, ttl_seconds: float) -> int:
    """Delete session workdirs untouched for longer than ttl (the handler touches a
    session's dir on each turn). Runtime directories (.claude config, agent log) are
    never session state and are excluded. Stateless idle cleanup; ttl<=0 disables it."""
    if ttl_seconds <= 0 or not workspace or not os.path.isdir(workspace):
        return 0
    cutoff = time.time() - ttl_seconds
    n = 0
    for name in os.listdir(workspace):
        if name in _RESERVED:
            continue
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
