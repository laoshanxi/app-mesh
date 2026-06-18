"""Entry point — runs the task_fetch/task_return loop in one of two roles.

Both are ordinary, admin-provisioned App Mesh Apps (this binary registers nothing):

  - default: the shared App, serving Scenario A (batch/DAG) sessions.
  - --session-worker --session-id=X: a per-session worker App serving one Scenario B
    (interactive, streaming) session; exits on close / idle / max-lifetime so the
    daemon (behavior: exit: remove) removes it.

The agent loop is the Claude Agent SDK (Claude Code-based). The model credential comes from
ANTHROPIC_API_KEY in the App's secured env; the task RPC is authenticated by the
daemon-injected APP_MESH_PROCESS_KEY and authorized by the daemon's RBAC.

Env (defaults in parens):
  LLMAGENT_MODEL  LLMAGENT_SYSTEM_PROMPT  LLMAGENT_ALLOWED_TOOLS  LLMAGENT_PERMISSION_MODE(bypassPermissions)
  LLMAGENT_WORKSPACE_DIR(./llm-agent-workspace)  LLMAGENT_MAX_ITERATIONS(0=no ceiling)
  LLMAGENT_SESSION_TTL_HOURS(168, shared)  LLMAGENT_SESSION_IDLE_MINUTES(30, worker)  LLMAGENT_SESSION_MAX_HOURS(8, worker)
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
import time

from . import session
from .handler import Handler

log = logging.getLogger("llm_agent")


def _env(key, default=""):
    return os.environ.get(key) or default


def _env_int(key, default):
    try:
        return int(os.environ[key])
    except (KeyError, ValueError):
        return default


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

    workspace = os.path.abspath(_env("LLMAGENT_WORKSPACE_DIR", "./llm-agent-workspace"))
    # The Claude Code CLI persists session history under $CLAUDE_CONFIG_DIR (default
    # ~/.claude). The daemon does NOT propagate HOME to a spawned App, so an unset HOME
    # would leave the CLI with nowhere writable and break every turn. Default the config
    # dir to a writable path under the workspace unless the operator set one.
    cfg_dir = _env("CLAUDE_CONFIG_DIR") or os.path.join(workspace, ".claude")
    os.environ["CLAUDE_CONFIG_DIR"] = cfg_dir
    try:
        os.makedirs(cfg_dir, exist_ok=True)
    except OSError as e:
        log.warning("CLAUDE_CONFIG_DIR %s not writable: %s — session history may fail", cfg_dir, e)
    common = dict(workspace=workspace, max_iterations=_env_int("LLMAGENT_MAX_ITERATIONS", 0))
    if args.session_worker:
        return _run_worker(args, common)
    return _run_shared(common)


def _run_shared(common):
    handler = Handler(**common)
    ttl = _env_int("LLMAGENT_SESSION_TTL_HOURS", 168) * 3600
    if ttl > 0:
        threading.Thread(target=_reap_loop, args=(common["workspace"], ttl), daemon=True).start()
    log.info("llm-agent shared App started (Claude Agent SDK) — accepting sessions via run_task")
    _serve(handler)
    return 0


def _run_worker(args, common):
    if not args.session_id:
        sys.stderr.write("worker mode requires --session-id\n")
        return 1
    handler = Handler(worker_session_id=args.session_id, **common)
    idle = _env_int("LLMAGENT_SESSION_IDLE_MINUTES", 30) * 60
    max_life = _env_int("LLMAGENT_SESSION_MAX_HOURS", 8) * 3600
    if idle > 0 or max_life > 0:
        threading.Thread(target=_worker_reaper,
                         args=(handler, args.session_id, common["workspace"], idle, max_life),
                         daemon=True).start()
    log.info("llm-agent session worker started (Claude Agent SDK) — serving session %s", args.session_id)
    _serve(handler)
    return 0


def _serve(handler: Handler):
    """task_fetch → dispatch → task_return loop (serial). The request is bracketed
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
            log.error("unhandled error in request cycle: %s", e, exc_info=True)
        finally:
            handler.end_request()
        if handler.exit_requested:
            log.info("session worker closed — exiting")
            return


def _reap_loop(workspace: str, ttl: float):
    while True:
        time.sleep(600)
        try:
            session.reap_workdirs(workspace, ttl)
        except Exception:
            log.warning("workdir reap error", exc_info=True)


def _worker_reaper(handler: Handler, sid: str, workspace: str, idle: float, max_life: float):
    while True:
        time.sleep(60)
        try:
            reason = handler.reap_due(idle, max_life)
        except Exception:
            log.warning("worker reaper error", exc_info=True)
            continue
        if reason:
            session.remove(workspace, sid)  # drop the session's workdir before exit
            log.info("session worker %s reaping (%s) — exiting; daemon removes the App", sid, reason)
            logging.shutdown()
            os._exit(0)


if __name__ == "__main__":
    sys.exit(main())
