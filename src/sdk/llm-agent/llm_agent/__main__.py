"""Entry point — runs the task_fetch/task_return loop in one of two roles.

Both roles are ordinary, admin-provisioned App Mesh Apps (this binary registers
nothing itself):

  - default: the shared per-tenant App, serving Scenario A (batch/DAG) sessions.
  - --session-worker --session-id=X: a per-session worker App serving one Scenario B
    (interactive, streaming) session; exits on close / idle / max-lifetime so the
    daemon (behavior: exit: remove) removes it.

No daemon credentials: the task RPC authenticates with the daemon-injected
APP_MESH_PROCESS_KEY; every other daemon call uses the caller's token from the
request payload.

Env (defaults in parens):
  APPMESH_TENANT(default) APPMESH_SESSION_OWNER(worker) APPMESH_WORKFLOW_ADMINS(admin)
  LLMAGENT_BACKEND(fake) LLMAGENT_MODEL LLMAGENT_MAX_OUTPUT_TOKENS(4096)
  LLMAGENT_SESSION_DIR(./llm-agent-sessions) LLMAGENT_LEDGER_DIR(=SESSION_DIR)
  LLMAGENT_WORKSPACE_DIR(./llm-agent-workspace)
  LLMAGENT_SESSION_TTL_HOURS(168) LLMAGENT_SESSION_IDLE_MINUTES(30) LLMAGENT_SESSION_MAX_HOURS(8)
  LLMAGENT_MAX_ITERATIONS(8) LLMAGENT_MAX_TOKENS(0) LLMAGENT_TOOL_TIMEOUT(300) LLMAGENT_TENANT_QUOTA(0)
  LLMAGENT_MAX_INPUT_CHARS(0) LLMAGENT_PROVIDER_TIMEOUT(120)
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
import time

from .budget import Ledger
from .handler import Handler
from .session import Store
from .types import TurnLimits

log = logging.getLogger("llm_agent")


def _env(key, default=""):
    return os.environ.get(key) or default


def _env_int(key, default):
    try:
        return int(os.environ[key])
    except (KeyError, ValueError):
        return default


def _abs(path):
    return os.path.abspath(path)


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    p = argparse.ArgumentParser(prog="llm-agent")
    p.add_argument("--server", default="127.0.0.1:6059", help="App Mesh TCP server host:port")
    p.add_argument("--session-worker", action="store_true", help="run as a single-session worker (Scenario B)")
    p.add_argument("--session-id", default="", help="worker: the session id this worker serves")
    p.add_argument("--version", action="store_true")
    args = p.parse_args(argv)
    if args.version:
        from . import __version__
        print("llm-agent", __version__)
        return 0

    tenant = _env("APPMESH_TENANT", "default")
    workspace = _abs(_env("LLMAGENT_WORKSPACE_DIR", "./llm-agent-workspace"))
    ledger_dir = _abs(_env("LLMAGENT_LEDGER_DIR", _env("LLMAGENT_SESSION_DIR", "./llm-agent-sessions")))
    quota = {}
    q = _env_int("LLMAGENT_TENANT_QUOTA", 0)
    if q > 0:
        quota[tenant] = q
    ledger = Ledger(ledger_dir, quota)
    ceiling = TurnLimits(_env_int("LLMAGENT_MAX_ITERATIONS", 8), _env_int("LLMAGENT_MAX_TOKENS", 0))
    admins = [a.strip() for a in _env("APPMESH_WORKFLOW_ADMINS", "admin").split(",") if a.strip()]

    common = dict(
        ledger=ledger, ceiling=ceiling, llm_name=_env("LLMAGENT_BACKEND", "fake"),
        server_uri=args.server, tenant=tenant, workspace=workspace,
        tool_timeout=_env_int("LLMAGENT_TOOL_TIMEOUT", 300), admins=admins,
        max_input_chars=_env_int("LLMAGENT_MAX_INPUT_CHARS", 0),
    )

    if args.session_worker:
        return _run_worker(args, common)
    return _run_shared(common)


def _run_shared(common):
    ttl = _env_int("LLMAGENT_SESSION_TTL_HOURS", 168) * 3600
    store = Store(_env("LLMAGENT_SESSION_DIR", "./llm-agent-sessions"), ttl)
    handler = Handler(store=store, **common)
    if ttl > 0:
        threading.Thread(target=_reap_loop, args=(store,), daemon=True).start()
    log.info("llm-agent shared App started (backend=%s) — accepting sessions via run_task", handler.llm.name())
    _serve(handler)
    return 0


def _run_worker(args, common):
    if not args.session_id:
        sys.stderr.write("worker mode requires --session-id\n")
        return 1
    owner = _env("APPMESH_SESSION_OWNER")
    if not owner:
        sys.stderr.write("worker mode requires APPMESH_SESSION_OWNER\n")
        return 1
    store = Store(_env("LLMAGENT_SESSION_DIR", "./llm-agent-sessions"), 0)
    store.create(args.session_id, owner, common["tenant"])
    handler = Handler(store=store, worker_session_id=args.session_id, **common)

    idle = _env_int("LLMAGENT_SESSION_IDLE_MINUTES", 30) * 60
    max_life = _env_int("LLMAGENT_SESSION_MAX_HOURS", 8) * 3600
    if idle > 0 or max_life > 0:
        threading.Thread(target=_worker_reaper, args=(handler, store, args.session_id, idle, max_life), daemon=True).start()

    log.info("llm-agent session worker started (backend=%s) — serving session %s", handler.llm.name(), args.session_id)
    _serve(handler)
    return 0


def _serve(handler: Handler):
    """task_fetch → dispatch → task_return loop. The whole request is bracketed
    in-flight so a worker reaper never exits mid-request."""
    import json
    from appmesh import AppMeshServerTCP
    ctx = AppMeshServerTCP()
    backoff = 1.0
    while True:
        try:
            payload = ctx.task_fetch()
        except Exception as e:
            log.warning("task_fetch error: %s; retrying in %.0fs", e, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30.0)
            continue
        backoff = 1.0
        handler.begin_request()
        try:
            resp = handler.dispatch(payload)
            ctx.task_return(json.dumps(resp))
        except Exception as e:
            # dispatch() already converts handled errors to a response; anything escaping
            # here (e.g. a disk error in persist, or task_return failing) must not kill the
            # serve loop — log and keep serving the next request.
            log.error("unhandled error in request cycle: %s", e, exc_info=True)
        finally:
            handler.end_request()
        if handler.exit_requested:
            log.info("session worker closed — exiting")
            return


def _reap_loop(store: Store):
    while True:
        time.sleep(600)
        try:
            store.reap()
        except Exception:
            pass


def _worker_reaper(handler: Handler, store: Store, sid: str, idle: float, max_life: float):
    while True:
        time.sleep(60)
        reason = handler.reap_due(idle, max_life)
        if reason:
            store.delete(sid)  # drop conversation history before exit
            log.info("session worker %s reaping (%s) — exiting; daemon removes the App", sid, reason)
            logging.shutdown()  # flush log buffers before the hard exit
            os._exit(0)


if __name__ == "__main__":
    sys.exit(main())
