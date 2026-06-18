#!/usr/bin/env python3
"""Example model-env agent tool: 'echo'.

A model-env tool is just a registered App that (1) carries a `metadata.tool` schema
(see config/echo-tool.yaml) and (2) runs a task loop taking JSON arguments and
returning JSON. model-env discovers it (the caller's token can see it), advertises
it to the model, and invokes it via run_task — injecting the calling session's
`session_id` into the arguments so a tool can scope per-session side effects.

This echo tool simply returns what it received, which makes the whole tool path —
including the injected session_id — visible end to end. Use it with the stub
backend: a user message like "use tool echo {}" makes the stub emit an `echo`
tool call.

Run as an App Mesh task App (see config/echo-tool.yaml), or standalone for a smoke
check: it will block on task_fetch waiting for the daemon.
"""

import json

from appmesh import AppMeshServerTCP


def handle(payload: str) -> str:
    """Echo the JSON arguments back as a JSON object."""
    try:
        args = json.loads(payload) if payload and payload.strip() else {}
    except json.JSONDecodeError:
        args = {"_raw": payload}
    return json.dumps({
        "echo": args,
        "session_id": args.get("session_id", "") if isinstance(args, dict) else "",
    })


def main():
    ctx = AppMeshServerTCP()
    while True:
        payload = ctx.task_fetch()  # block until the agent invokes this tool
        ctx.task_return(handle(payload))


if __name__ == "__main__":
    main()
