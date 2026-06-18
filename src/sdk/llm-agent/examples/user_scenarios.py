#!/usr/bin/env python3
"""How a user uses llm-agent — runnable end-to-end journeys against a live daemon.

Two interaction models (see README "Two scenarios, two Apps"):
  A — batch: talk to the shared App (`llm-agent`), one final answer per turn.
  B — interactive: an admin-provisioned worker App per session; talk to it by name and
      stream its STDOUT.

Prereqs: a running daemon with the `llm-agent` App enabled and a Claude key set
(ANTHROPIC_API_KEY as a secured env var; the claude-agent-sdk wheel bundles the Claude
Code CLI, so no Node is needed). For B, an admin-provisioned worker
(--worker-app/--worker-session). The caller logs in (daemon RBAC needs app-run-task, and
app-subscribe for B streaming).

Run:
  python3 user_scenarios.py --list
  python3 user_scenarios.py a_single
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
    def __init__(self, host, port, app, task_timeout=120):
        self.client = AppMeshClientTCP(tcp_address=(host, int(port)), ssl_verify=False)
        self.app = app
        self.task_timeout = task_timeout

    def login(self, user, password):
        # login() attaches the session cookie used to authorize run_task at the daemon.
        self.client.login(user, password)
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
    """Canonical Scenario B client: ONE long-lived STDOUT subscription, many turns.

    The streamed tokens ARE the answer; ``run_task`` only delivers each turn's input and
    returns completion metadata. The subscription stays open for the whole session.
    """

    def __init__(self, client, worker, sid, task_timeout):
        self._client = client
        self._worker = worker
        self._sid = sid
        self._timeout = task_timeout
        self._buf = []
        self._sub = client.subscribe(worker, ["STDOUT"], callback=self._on_event)
        time.sleep(1.0)  # let the subscription go live before the first turn

    def _on_event(self, evt):
        txt = _event_text(evt)
        if txt:
            self._buf.append(txt)
            sys.stdout.write(txt)
            sys.stdout.flush()

    def send(self, text):
        self._buf.clear()
        payload = {"action": "session_send", "session_id": self._sid, "input": text, "stream": True}
        resp = json.loads(self._client.run_task(self._worker, json.dumps(payload), timeout=self._timeout))
        time.sleep(0.3)  # let trailing STDOUT events arrive
        if resp.get("status") != "ok":
            raise AgentError(resp.get("message", "error"), resp.get("data"))
        return "".join(self._buf), (resp.get("data") or {})

    def close(self):
        try:
            self._client.unsubscribe(self._sub.subscription_id)
        except Exception:
            pass
        try:  # session_close → worker exits → daemon removes the App
            self._client.run_task(self._worker, json.dumps(
                {"action": "session_close", "session_id": self._sid}), timeout=20)
        except Exception:
            pass


class AgentError(Exception):
    def __init__(self, message, data=None):
        super().__init__(message)
        self.message = message
        self.data = data


def _event_text(evt):
    data = getattr(evt, "data", None) or {}
    return data.get("output", "") if isinstance(data, dict) else ""


def a_single(a, cfg):
    """A1 — batch: ask once, get one answer."""
    print("[A1] one batch turn.")
    sid = new_session_id()
    r = a.ask(sid, "In one sentence: what is App Mesh?")
    print(f"     answer={r['answer']!r}  iterations={r['iterations']}  turn_tokens={r['turn_tokens']}")
    a.close(sid)


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
    """B — interactive: ONE App, ONE open STDOUT subscription, many streaming turns."""
    print("[B] one subscription, multiple streaming turns on the worker App.")
    if not _need_worker(cfg):
        return
    stream = a.worker_stream(cfg.worker_app, cfg.worker_session)
    try:
        for msg in ["Hi! Remember the number 7.", "What number did I give you?", "Say goodbye in one word."]:
            print(f"\n     you: {msg}\n     assistant: ", end="", flush=True)
            _answer, meta = stream.send(msg)  # tokens already rendered live by the callback
            print(f"\n       [done: iterations={meta.get('iterations')} turn_tokens={meta.get('turn_tokens')}]")
    finally:
        stream.close()
        print("\n     session closed (worker removed).")


SCENARIOS = {"a_single": a_single, "a_multiturn": a_multiturn, "b_interactive": b_interactive}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("scenario", nargs="?", default="all")
    p.add_argument("--list", action="store_true")
    p.add_argument("--host", default=os.environ.get("APPMESH_TCP_HOST", "127.0.0.1"))
    p.add_argument("--port", default=os.environ.get("APPMESH_TCP_PORT", "6059"))
    p.add_argument("--app", default=os.environ.get("LLMAGENT_APP", "llm-agent"))
    p.add_argument("--user", default=os.environ.get("APPMESH_USER", "admin"))
    p.add_argument("--password", default=os.environ.get("APPMESH_PASSWORD", "admin123"))
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
    a = LLMAgent(cfg.host, cfg.port, cfg.app, cfg.task_timeout).login(cfg.user, cfg.password)
    print(f"connected to {cfg.host}:{cfg.port}, app {cfg.app!r} (user {cfg.user!r})\n")
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
