"""Per-tenant cumulative token quota, shared on disk across processes.

Scenario B runs each session in its own worker process, plus the Scenario A shared
App — so an in-memory counter can't enforce a true per-tenant ceiling. They all
point at the same directory; the counter file <dir>/<tenant>.ledger.json is updated
under an flock-guarded read-modify-write. Same tenant + same dir → one quota.

The lock is advisory (flock, Unix); the kernel releases it on process exit, so a
crashed worker never leaves a stale lock. On a non-Unix platform or an I/O error the
check fails open and logs — the per-turn budget still caps any single turn.
"""
from __future__ import annotations

import json
import logging
import os
import re
from contextlib import contextmanager
from typing import Dict

try:
    import fcntl  # Unix
except ImportError:  # pragma: no cover - non-Unix
    fcntl = None

log = logging.getLogger("llm_agent.budget")


class Ledger:
    def __init__(self, directory: str, quota: Dict[str, int]):
        os.makedirs(directory, exist_ok=True)
        self._dir = directory
        self._quota = dict(quota or {})

    def _path(self, tenant: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9_-]", "-", tenant) or "default"
        return os.path.join(self._dir, safe + ".ledger.json")

    @contextmanager
    def _locked(self, tenant: str):
        f = open(self._path(tenant), "a+")
        try:
            if fcntl:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            yield f
        finally:
            try:
                if fcntl:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            finally:
                f.close()

    @staticmethod
    def _read(f) -> int:
        f.seek(0)
        data = f.read()
        if not data:
            return 0
        try:
            return int(json.loads(data).get("used", 0))
        except Exception:
            return 0

    def check(self, tenant: str) -> None:
        """Raise BudgetExceeded if the tenant is at/over quota."""
        from .types import BudgetExceeded
        q = self._quota.get(tenant, 0)
        if q <= 0:
            return
        try:
            with self._locked(tenant) as f:
                used = self._read(f)
        except Exception as e:
            log.warning("tenant %s ledger read failed, allowing turn: %s", tenant, e)
            return
        if used >= q:
            raise BudgetExceeded("budget_exceeded")

    def add(self, tenant: str, tokens: int) -> int:
        """Record spend; return the new cumulative total."""
        try:
            with self._locked(tenant) as f:
                total = self._read(f) + tokens
                f.seek(0)
                f.truncate()
                f.write(json.dumps({"used": total}))
                f.flush()
                os.fsync(f.fileno())
                return total
        except Exception as e:
            log.warning("tenant %s ledger write failed: %s", tenant, e)
            return 0

    def used(self, tenant: str) -> int:
        try:
            with self._locked(tenant) as f:
                return self._read(f)
        except Exception:
            return 0
