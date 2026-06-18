#!/usr/bin/env python3
"""Example llm-agent tool App: 'echo'.

A tool is a registered App that (1) carries a metadata.tool schema (see
config/echo-tool.yaml) and (2) runs a task loop taking JSON arguments and returning
JSON. llm-agent invokes it via run_task — injecting the calling session's session_id
and a per-session workdir into the arguments. This echo returns what it received so
the whole tool path (including the injected fields) is visible end to end.

Run it as an App Mesh task App (see config/echo-tool.yaml).
"""
import json

from appmesh import AppMeshServerTCP


def handle(payload: str) -> str:
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
        payload = ctx.task_fetch()
        ctx.task_return(handle(payload))


if __name__ == "__main__":
    main()
