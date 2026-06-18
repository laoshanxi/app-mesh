#!/usr/bin/env python3
"""How a user uses llm-agent — runnable end-to-end journeys against a live daemon.

Two interaction models (see README "Two scenarios, two Apps"):
  A — batch/DAG: talk to the shared per-tenant App (llm-agent-<tenant>).
  B — interactive: an admin-provisioned worker App per session; talk to it by name
      and stream its stdout.

Prereqs: a running daemon; the Scenario A App enabled (LLMAGENT_BACKEND=fake for
deterministic "stub: <input>"); for B, an admin-provisioned worker (--worker-app,
--worker-session); for tools, a registered tool App (--tool-app); for authz, a
second user. The caller logs in, so that daemon user needs app-run-task (and
app-subscribe for B streaming, app-view for tools).

Run:
  python3 user_scenarios.py --list
  python3 user_scenarios.py all --worker-app llm-agent-sess-S1 \
    --worker-session S1 --tool-app echo
"""
import argparse
import json
import os
import sys
import time

from appmesh import AppMeshClientTCP


class LLMAgent:
    def __init__(self, host, port, app, task_timeout=120):
        self.client = AppMeshClientTCP(tcp_address=(host, int(port)), ssl_verify=False)
        self.app = app
        self.task_timeout = task_timeout
        self.token = None

    def login(self, user, password):
        # login() attaches the token (cookie) and returns None; read it back for the
        # payload — llm-agent needs the JWT in each request's `token` field.
        self.client.login(user, password)
        self.token = self.client._get_access_token()
        if not self.token:
            raise RuntimeError("login succeeded but no access token is available")
        return self

    def _act(self, app, action, **fields):
        payload = {"action": action, "token": self.token}
        payload.update(fields)
        resp = json.loads(self.client.run_task(app, json.dumps(payload), timeout=self.task_timeout))
        if resp.get("status") != "ok":
            raise AgentError(resp.get("message", "error"), resp.get("data"))
        return resp.get("data") or {}

    def open(self):
        return self._act(self.app, "session_open")["session_id"]

    def ask(self, sid, text, **limits):
        return self._act(self.app, "session_send", session_id=sid, input=text, **limits)

    def close(self, sid):
        self._act(self.app, "session_close", session_id=sid)

    def worker_stream(self, worker, sid):
        """Open a Scenario B interactive session: one STDOUT subscription reused across
        every streaming turn (see WorkerStream)."""
        return WorkerStream(self.client, worker, sid, self.token, self.task_timeout)


class WorkerStream:
    """Canonical Scenario B client: ONE long-lived STDOUT subscription, many turns.

    The streamed tokens ARE the answer; ``run_task`` is used only to deliver each turn's
    input and to return completion metadata (iterations / tokens / budget). The single
    subscription stays open for the whole session — not re-opened per turn.
    """

    def __init__(self, client, worker, sid, token, task_timeout):
        self._client = client
        self._worker = worker
        self._sid = sid
        self._token = token
        self._timeout = task_timeout
        self._buf = []
        self._sub = client.subscribe(worker, ["STDOUT"], callback=self._on_event)
        time.sleep(1.0)  # let the subscription go live before the first turn

    def _on_event(self, evt):
        txt = _event_text(evt)
        if txt:
            self._buf.append(txt)
            sys.stdout.write(txt)  # render the live stream
            sys.stdout.flush()

    def send(self, text):
        """Run one turn. Returns (streamed_answer, metadata). The answer comes from the
        STDOUT stream; run_task's return carries only completion metadata."""
        self._buf.clear()
        payload = {"action": "session_send", "token": self._token,
                   "session_id": self._sid, "input": text, "stream": True}
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
        # session_close → worker exits → daemon removes the App
        try:
            self._client.run_task(self._worker, json.dumps(
                {"action": "session_close", "token": self._token, "session_id": self._sid}), timeout=20)
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
    print("[A1] open, ask once, close.")
    sid = a.open()
    r = a.ask(sid, "Summarize: App Mesh runs apps like systemd + cron + a REST API.")
    print(f"     answer={r['answer']!r}  iterations={r['iterations']}  cost_tokens={r['cost_tokens']}")
    a.close(sid)


def a_multiturn(a, cfg):
    """A2 — batch with memory: turns build context in one session."""
    print("[A2] multi-turn in one session.")
    sid = a.open()
    for t in ["My name is Dana.", "I work on payments.", "What is my name and area?"]:
        print(f"     you={t!r}  bot={a.ask(sid, t)['answer']!r}")
    a.close(sid)


def a_budget(a, cfg):
    """A3 — bound a turn (max_iterations=1 + a tool) → budget_exceeded."""
    if not cfg.tool_app:
        print("[A3] skipped: set --tool-app so a tool round can exhaust the 1-iteration budget.")
        return
    print("[A3] bounded turn; expect budget_exceeded.")
    sid = a.open()
    try:
        r = a.ask(sid, f"use tool {cfg.tool_app} {{}}", max_iterations=1)
        print(f"     UNEXPECTED no breach (is {cfg.tool_app!r} registered/visible?) answer={r['answer']!r}")
    except AgentError as e:
        print(f"     budget guard fired as expected: {e.message} {e.data}")
    a.close(sid)


def a_tool(a, cfg):
    """A4 — the agent calls a registered tool App."""
    if not cfg.tool_app:
        print("[A4] skipped: set --tool-app (a registered tool App).")
        return
    print(f"[A4] agent uses tool App {cfg.tool_app!r}.")
    sid = a.open()
    r = a.ask(sid, f"use tool {cfg.tool_app} {{}}")
    note = "tool round happened" if r["iterations"] > 1 else f"NO tool round — is {cfg.tool_app!r} registered & visible?"
    print(f"     {note}; iterations={r['iterations']} answer={r['answer']!r}")
    a.close(sid)


def _need_worker(cfg):
    if cfg.worker_app and cfg.worker_session:
        return True
    print("     skipped: provision a worker App and pass --worker-app/--worker-session.")
    return False


def b_interactive(a, cfg):
    """B — interactive: ONE App, ONE open STDOUT subscription, many streaming turns.

    This is the canonical Scenario B client flow: subscribe once, then converse turn
    after turn with live token streaming. The answer is consumed from the stream; the
    run_task return is only completion metadata. Closing ends the session and the
    daemon removes the worker App.
    """
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
        stream.close()  # ends the session; worker exits → daemon removes it
        print("\n     session closed (worker removed).")


def authz(a, cfg):
    """C1 — a second user cannot act on the owner's session."""
    if not (cfg.user2 and cfg.password2):
        print("[C1] skipped: set --user2/--password2.")
        return
    print("[C1] Alice opens; Bob must not use it.")
    sid = a.open()
    bob = LLMAgent(cfg.host, cfg.port, cfg.app, cfg.task_timeout).login(cfg.user2, cfg.password2)
    try:
        bob.ask(sid, "peeking")
        print("     UNEXPECTED: Bob was allowed in (is user2 an admin?)")
    except AgentError as e:
        print(f"     Bob denied at L2 (session owner) as expected: {e.message}")
    except Exception as e:
        print(f"     Bob denied at L1 (daemon RBAC) as expected: {type(e).__name__}")
    finally:
        a.close(sid)


SCENARIOS = {"a_single": a_single, "a_multiturn": a_multiturn, "a_budget": a_budget,
             "a_tool": a_tool, "b_interactive": b_interactive, "authz": authz}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("scenario", nargs="?", default="all")
    p.add_argument("--list", action="store_true")
    p.add_argument("--host", default=os.environ.get("APPMESH_TCP_HOST", "127.0.0.1"))
    p.add_argument("--port", default=os.environ.get("APPMESH_TCP_PORT", "6059"))
    p.add_argument("--tenant", default=os.environ.get("LLMAGENT_TENANT", "default"))
    p.add_argument("--app", default=os.environ.get("LLMAGENT_APP", ""))
    p.add_argument("--user", default=os.environ.get("APPMESH_USER", "admin"))
    p.add_argument("--password", default=os.environ.get("APPMESH_PASSWORD", "admin123"))
    p.add_argument("--user2", default=os.environ.get("APPMESH_USER2", ""))
    p.add_argument("--password2", default=os.environ.get("APPMESH_PASSWORD2", ""))
    p.add_argument("--worker-app", default=os.environ.get("LLMAGENT_WORKER_APP", ""))
    p.add_argument("--worker-session", default=os.environ.get("LLMAGENT_WORKER_SESSION", ""))
    p.add_argument("--tool-app", default=os.environ.get("LLMAGENT_TOOL_APP", ""))
    p.add_argument("--task-timeout", type=int, default=int(os.environ.get("LLMAGENT_TASK_TIMEOUT", "120")))
    cfg = p.parse_args()
    if not cfg.app:
        # default tenant → `llm-agent`; a named tenant → `llm-agent-<tenant>`
        cfg.app = "llm-agent" if cfg.tenant == "default" else f"llm-agent-{cfg.tenant}"
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
