#!/usr/bin/env python3
"""How a user uses llm-agent — runnable end-to-end journeys against a live daemon.

Two interaction models (see README "Two scenarios, two Apps"):
  A — batch: talk to the shared App (`llm-agent`), one final answer per turn
      (a_stream shows the same App streaming token by token).
  B — interactive: an admin-provisioned worker App per session; talk to it by
      name with the same streaming channel.

Streaming rides the task RPC itself (``run_task_stream``): each token is a partial on the
same call, the final envelope carries completion metadata; no STDOUT subscription, no races.

Prereqs: a running daemon with the `llm-agent` App enabled and a Claude key set
(ANTHROPIC_API_KEY as a secured env var; the claude-agent-sdk wheel bundles the Claude
Code CLI, so no Node is needed). For B, an admin-provisioned worker
(--worker-app/--worker-session). The caller supplies a bearer whose Engine
principal has app-run-task.

Run:
  python3 user_scenarios.py --list
  python3 user_scenarios.py a_single
  python3 user_scenarios.py a_stream
  python3 user_scenarios.py b_interactive --worker-app llm-agent-sess-S1 --worker-session S1
"""
import argparse
import json
import os
import sys
import time
import uuid

from appmesh import AppMeshClientTCP


class LLMAgent:
    def __init__(self, host, port, app, task_timeout=120, rest_port=6058):
        # run_task_stream() cannot ride the framed TCP transport: the SDK dials the
        # engine's WSS/HTTPS listener directly (6058 unless WebSocketPort changed).
        self.client = AppMeshClientTCP(tcp_address=(host, int(port)), rest_port=rest_port, ssl_verify=False)
        self.app = app
        self.task_timeout = task_timeout

    def with_bearer(self, bearer):
        """Attach a caller-obtained access token. The agent is not an OAuth client."""
        self.client.set_bearer_token(bearer)
        return self

    def _act(self, app, action, **fields):
        payload = {"action": action}
        payload.update(fields)
        resp = json.loads(self.client.run_task(app, json.dumps(payload), timeout=self.task_timeout))
        if resp.get("status") != "ok":
            raise AgentError(resp.get("message", "error"), resp.get("data"))
        return resp.get("data") or {}

    def ask(self, sid, text, **limits):
        return self._act(self.app, "session_send", session_id=sid, input=text, **limits)

    def close(self, sid):
        self._act(self.app, "session_close", session_id=sid)

    def worker_stream(self, worker, sid):
        return WorkerStream(self.client, worker, sid, self.task_timeout)


def new_session_id():
    """A session id is caller-chosen; session_send get-or-creates it (no session_open)."""
    return uuid.uuid4().hex


class WorkerStream:
    """Canonical streaming client: ``run_task_stream`` partials ARE the answer tokens; one
    call per turn — no subscription, no race handling — on the shared App or any worker."""

    def __init__(self, client, app, sid, task_timeout):
        self._client = client
        self._app = app
        self._sid = sid
        self._timeout = task_timeout

    def send(self, text):
        payload = {"action": "session_send", "session_id": self._sid, "input": text, "stream": True}
        answer = []
        gen = self._client.run_task_stream(self._app, json.dumps(payload), timeout=self._timeout)
        while True:
            try:
                chunk = next(gen)
            except StopIteration as stop:  # the generator's return value is the end marker
                end = stop.value
                break
            answer.append(chunk)
            sys.stdout.write(chunk)
            sys.stdout.flush()
        resp = json.loads(end.result) if end.result else {}
        if resp.get("status") != "ok":
            raise AgentError(resp.get("message", "error"), resp.get("data"))
        return "".join(answer), (resp.get("data") or {})

    def close(self):
        try:  # session_close → a worker exits and the daemon removes its App
            self._client.run_task(self._app, json.dumps(
                {"action": "session_close", "session_id": self._sid}), timeout=20)
        except Exception:
            pass


class AgentError(Exception):
    def __init__(self, message, data=None):
        super().__init__(message)
        self.message = message
        self.data = data


def a_single(a, cfg):
    """A1 — batch: ask once, get one answer."""
    print("[A1] one batch turn.")
    sid = new_session_id()
    r = a.ask(sid, "In one sentence: what is App Mesh?")
    print(f"     answer={r['answer']!r}  iterations={r['iterations']}  turn_tokens={r['turn_tokens']}")
    a.close(sid)


def a_stream(a, cfg):
    """A3 — the same shared App, streaming token by token."""
    print("[A3] streaming turn on the shared App (no worker, no subscription).")
    stream = a.worker_stream(a.app, new_session_id())
    try:
        print("     assistant: ", end="", flush=True)
        answer, meta = stream.send("Count slowly from 1 to 5, one number per line.")
        print(f"\n       [done: iterations={meta.get('iterations')} turn_tokens={meta.get('turn_tokens')}]")
    finally:
        stream.close()


def a_multiturn(a, cfg):
    """A2 — batch with memory: turns build context in one session."""
    print("[A2] multi-turn in one session (same session_id continues the conversation).")
    sid = new_session_id()
    for t in ["My name is Dana.", "I work on payments.", "What is my name and area?"]:
        print(f"     you={t!r}  bot={a.ask(sid, t)['answer']!r}")
    a.close(sid)


def _need_worker(cfg):
    if cfg.worker_app and cfg.worker_session:
        return True
    print("     skipped: provision a worker App and pass --worker-app/--worker-session.")
    return False


def b_interactive(a, cfg):
    """B — interactive: one isolated worker App per session, many streaming turns."""
    print("[B] isolated session worker, multiple streaming turns (context stays private).")
    if not _need_worker(cfg):
        return
    stream = a.worker_stream(cfg.worker_app, cfg.worker_session)
    try:
        for msg in ["Hi! Remember the number 7.", "What number did I give you?", "Say goodbye in one word."]:
            print(f"\n     you: {msg}\n     assistant: ", end="", flush=True)
            _answer, meta = stream.send(msg)  # tokens already rendered live by the stream
            print(f"\n       [done: iterations={meta.get('iterations')} turn_tokens={meta.get('turn_tokens')}]")
    finally:
        stream.close()
        print("\n     session closed (worker removed).")


SCENARIOS = {"a_single": a_single, "a_multiturn": a_multiturn, "a_stream": a_stream, "b_interactive": b_interactive}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("scenario", nargs="?", default="all")
    p.add_argument("--list", action="store_true")
    p.add_argument("--host", default=os.environ.get("APPMESH_TCP_HOST", "127.0.0.1"))
    p.add_argument("--port", default=os.environ.get("APPMESH_TCP_PORT", "6059"))
    p.add_argument("--rest-port", type=int, default=int(os.environ.get("APPMESH_REST_PORT", "6058")),
                   help="engine WSS/HTTPS port (the streaming side channel)")
    p.add_argument("--app", default=os.environ.get("LLMAGENT_APP", "llm-agent"))
    p.add_argument("--worker-app", default=os.environ.get("LLMAGENT_WORKER_APP", ""))
    p.add_argument("--worker-session", default=os.environ.get("LLMAGENT_WORKER_SESSION", ""))
    p.add_argument("--task-timeout", type=int, default=int(os.environ.get("LLMAGENT_TASK_TIMEOUT", "120")))
    cfg = p.parse_args()
    if cfg.list or cfg.scenario == "list":
        for n, fn in SCENARIOS.items():
            print(f"  {n:14s} {fn.__doc__.splitlines()[0]}")
        return 0
    names = list(SCENARIOS) if cfg.scenario == "all" else [cfg.scenario]
    if any(n not in SCENARIOS for n in names):
        print("unknown scenario; try --list", file=sys.stderr)
        return 2
    bearer = os.environ.get("APPMESH_BEARER_TOKEN")
    if not bearer:
        p.error("APPMESH_BEARER_TOKEN is required. Obtain it from the authentication service.")
    a = LLMAgent(cfg.host, cfg.port, cfg.app, cfg.task_timeout, rest_port=cfg.rest_port).with_bearer(bearer)
    print(f"connected to {cfg.host}:{cfg.port}, app {cfg.app!r}\n")
    fails = 0
    for n in names:
        print(f"=== {n} ===")
        try:
            SCENARIOS[n](a, cfg)
        except Exception as e:
            fails += 1
            print(f"     SCENARIO FAILED: {type(e).__name__}: {e}")
        print()
        time.sleep(0.2)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
