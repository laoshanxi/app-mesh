"""Tools are registered App Mesh Apps that carry a ``metadata.tool`` schema.

The catalog lists Apps the caller's token can see, advertises those with a tool
schema, and invokes one by run_task-ing the App (structured JSON in/out) under the
caller's identity — so the tool set is automatically RBAC-scoped to what the caller
could already run, with no separate allowlist.

The calling session's ``session_id`` and a per-session ``workdir`` are injected into
each call so a file-writing tool can scope its side effects (the model's own value
wins). Tools run as separate Apps, so this injection — not any process cwd — is what
isolates their files.
"""
from __future__ import annotations

import json
from typing import List

from .types import ToolCall, ToolSpec


class ToolCatalog:
    def __init__(self, client, timeout: int, session_id: str = "", workdir: str = ""):
        self._client = client  # appmesh client carrying the caller's token
        self._timeout = timeout if timeout > 0 else 300
        self._inject = {}
        if session_id:
            self._inject["session_id"] = session_id
        if workdir:
            self._inject["workdir"] = workdir
        self._allowed = None  # set by specs(); enforced by invoke()

    def specs(self) -> List[ToolSpec]:
        out = []
        allowed = set()
        for app in self._client.list_apps():
            meta = getattr(app, "metadata", None)
            tool = meta.get("tool") if isinstance(meta, dict) else None
            if not isinstance(tool, dict):
                continue
            out.append(ToolSpec(
                name=app.name,
                description=tool.get("description") or (getattr(app, "description", "") or ""),
                parameters=tool.get("parameters") or {"type": "object", "properties": {}},
            ))
            allowed.add(app.name)
        self._allowed = allowed
        return out

    def invoke(self, call: ToolCall) -> str:
        # Only Apps advertised by specs() may be invoked: a prompt-injected model must
        # not be able to run_task an arbitrary App that merely happens to be in the
        # caller's RBAC scope but was never offered as a tool.
        if self._allowed is not None and call.name not in self._allowed:
            raise ValueError("tool %r is not in the advertised catalog" % call.name)
        args = _with_injected(call.arguments, self._inject)
        return self._client.run_task(call.name, args, timeout=self._timeout)


def _with_injected(raw: str, inject: dict) -> str:
    """Add each inject key to the args JSON when it is an object lacking it (the
    model's explicit value wins). Non-object payloads pass through unchanged."""
    s = raw or "{}"
    if not inject:
        return s
    try:
        obj = json.loads(s)
    except Exception:
        return s
    if not isinstance(obj, dict):
        return s
    changed = False
    for k, v in inject.items():
        if v and k not in obj:
            obj[k] = v
            changed = True
    return json.dumps(obj) if changed else s
