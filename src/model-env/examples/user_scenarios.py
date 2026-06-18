#!/usr/bin/env python3
"""How a user uses model-env — complete, runnable usage scenarios.

Not a unit-test suite: these are end-to-end user journeys you can run against a
live App Mesh daemon to see how a client drives the model-env agent.

Two interaction models (see README "Two scenarios, two Apps"):

  Scenario A — batch / DAG: talk to the shared per-tenant App (model-env-<tenant>).
               Request in, final answer out. No streaming.
  Scenario B — interactive: an admin has provisioned a dedicated worker App for a
               session (model-env --session-worker --session-id=S). The client
               talks to that worker App by name and streams its stdout.

PREREQUISITES (live environment — nothing is mocked):
  - An App Mesh daemon over TCP.
  - The Scenario A App enabled for the tenant (default "model-env-<tenant>"). Use
    MODELENV_BACKEND=stub for deterministic "stub: <input>" answers, no key.
  - For Scenario B cases: an admin-provisioned worker App (see
    config/model-env-worker.yaml); pass --worker-app and --worker-session.
  - For the tool case: a tool App with metadata.tool the caller can run
    (config/echo-tool.yaml); pass --tool-app.
  - For the authz case: a second non-admin user.

Run (Scenario B journeys need --worker-app/--worker-session; tool/budget journeys
A3/A4 need --tool-app; otherwise those journeys print a "skipped" line):
  python3 user_scenarios.py --list
  python3 user_scenarios.py a_single
  python3 user_scenarios.py all --worker-app model-env-default-sess-S1 \
    --worker-session S1 --tool-app echo
"""

import argparse
import json
import os
import sys
import time

from appmesh import AppMeshClientTCP


class ModelEnv:
    """Client-side handle. Holds the daemon connection and the caller's token; every
    action carries that token so model-env acts under the caller's identity."""

    def __init__(self, host, port, app, task_timeout=120):
        self.client = AppMeshClientTCP(tcp_address=(host, int(port)), ssl_verify=False)
        self.app = app  # the Scenario A App
        self.task_timeout = task_timeout
        self.token = None

    def login(self, user, password):
        self.token = self.client.login(user, password)
        return self

    def _act(self, app, action, **fields):
        payload = {"action": action, "token": self.token}
        payload.update(fields)
        raw = self.client.run_task(app, json.dumps(payload), timeout=self.task_timeout)
        resp = json.loads(raw)
        if resp.get("status") != "ok":
            raise ModelEnvError(resp.get("message", "error"), resp.get("data"))
        return resp.get("data") or {}

    # --- Scenario A: shared tenant App --------------------------------------------

    def open(self):
        return self._act(self.app, "session_open")["session_id"]

    def ask(self, sid, text, **limits):
        return self._act(self.app, "session_send", session_id=sid, input=text, **limits)

    def close(self, sid):
        self._act(self.app, "session_close", session_id=sid)

    # --- Scenario B: a worker App addressed by name -------------------------------

    def ask_worker(self, worker, sid, text, **limits):
        return self._act(worker, "session_send", session_id=sid, input=text, **limits)

    def stream_worker(self, worker, sid, text, on_token):
        """Send a turn with streaming, rendering tokens live from the worker's
        stdout, and return the final result. Subscribe before sending."""
        sub = self.client.subscribe(worker, ["STDOUT"], callback=lambda e: on_token(_event_text(e)))
        try:
            return self._act(worker, "session_send", session_id=sid, input=text, stream=True)
        finally:
            try:
                self.client.unsubscribe(sub.subscription_id)
            except Exception:
                pass

    def close_worker(self, worker, sid):
        self._act(worker, "session_close", session_id=sid)


class ModelEnvError(Exception):
    def __init__(self, message, data=None):
        super().__init__(message)
        self.message = message
        self.data = data


def _event_text(evt):
    """STDOUT chunk lives in event.data['output'] (see appmesh.transport_mixin)."""
    data = getattr(evt, "data", None) or {}
    return data.get("output", "") if isinstance(data, dict) else ""


# --- Scenario A -------------------------------------------------------------------


def scenario_a_single(env, cfg):
    """A1 — batch: ask one question, get one answer."""
    print("[A1] open a session, ask once, close.")
    sid = env.open()
    res = env.ask(sid, "Summarize: App Mesh runs apps like systemd + cron + a REST API.")
    print(f"     answer    : {res['answer']!r}")
    print(f"     iterations: {res['iterations']}  cost_tokens: {res['cost_tokens']}")
    env.close(sid)


def scenario_a_multiturn(env, cfg):
    """A2 — batch with memory: several turns build up context in one session."""
    print("[A2] multi-turn in one session.")
    sid = env.open()
    for turn in ["My name is Dana.", "I work on payments.", "What is my name and area?"]:
        res = env.ask(sid, turn)
        print(f"     you: {turn!r}  bot: {res['answer']!r}")
    env.close(sid)


def scenario_a_budget(env, cfg):
    """A3 — cap a turn's tool rounds and handle budget_exceeded."""
    # A caller can only *lower* a finite operator ceiling, and with the stub a
    # tool-free turn answers in one model call (no breach). So a deterministic demo
    # needs a tool: max_iterations=1 lets the tool round happen but leaves no room
    # for a final answer → budget_exceeded. (Alternatively set MODELENV_MAX_TOKENS
    # on the App and lower it per call.)
    if not cfg.tool_app:
        print("[A3] skipped: set --tool-app so a tool round can exhaust the 1-iteration budget.")
        return
    print("[A3] bounded turn (max_iterations=1 + a tool); expect budget_exceeded.")
    sid = env.open()
    try:
        res = env.ask(sid, f"use tool {cfg.tool_app} {{}}", max_iterations=1)
        print(f"     UNEXPECTED: no breach — is {cfg.tool_app!r} registered and visible? "
              f"(no tool round means the 1-iteration budget isn't exhausted) answer={res['answer']!r}")
    except ModelEnvError as e:
        print(f"     budget guard fired as expected: {e.message} {e.data}")
    env.close(sid)


def scenario_a_tool(env, cfg):
    """A4 — the agent calls a registered tool App (if one is configured)."""
    if not cfg.tool_app:
        print("[A4] skipped: set --tool-app (a registered tool App) to run this.")
        return
    print(f"[A4] agent uses tool App {cfg.tool_app!r}.")
    sid = env.open()
    # The stub backend calls the tool NAMED in the prompt, so name the actual App.
    res = env.ask(sid, f"use tool {cfg.tool_app} {{}}")
    if res["iterations"] > 1:
        print(f"     tool round happened (iterations={res['iterations']}); answer: {res['answer']!r}")
    else:
        print(f"     NO tool round (iterations=1) — is {cfg.tool_app!r} registered and visible to this user? answer: {res['answer']!r}")
    env.close(sid)


# --- Scenario B (needs an admin-provisioned worker App) ---------------------------


def _need_worker(cfg):
    if not (cfg.worker_app and cfg.worker_session):
        print("     skipped: provision a worker App and pass --worker-app/--worker-session.")
        return False
    return True


def scenario_b_streaming(env, cfg):
    """B1 — interactive chat with live streaming from the worker's stdout."""
    print("[B1] stream a reply from the worker App.")
    if not _need_worker(cfg):
        return
    print("     assistant (streaming): ", end="", flush=True)
    res = env.stream_worker(cfg.worker_app, cfg.worker_session, "Write a one-sentence hello.",
                            lambda c: (sys.stdout.write(c), sys.stdout.flush()))
    print(f"\n     final result: {res['answer']!r}")


def scenario_b_multiturn(env, cfg):
    """B2 — multi-turn conversation against the worker App."""
    print("[B2] back-and-forth with the worker App.")
    if not _need_worker(cfg):
        return
    for turn in ["Hi!", "Remember the number 7.", "What number did I give you?"]:
        res = env.ask_worker(cfg.worker_app, cfg.worker_session, turn)
        print(f"     you: {turn!r}  bot: {res['answer']!r}")


# --- Authorization ----------------------------------------------------------------


def scenario_authz(env, cfg):
    """C1 — a second user cannot act on the first user's session (L2 ownership)."""
    if not (cfg.user2 and cfg.password2):
        print("[C1] skipped: set --user2/--password2 for the cross-user case.")
        return
    print("[C1] Alice opens a session; Bob must not use it.")
    sid = env.open()
    bob = ModelEnv(cfg.host, cfg.port, cfg.app, cfg.task_timeout).login(cfg.user2, cfg.password2)
    try:
        bob.ask(sid, "peeking at someone else's chat")
        print("     UNEXPECTED: Bob was allowed in (is user2 an admin?)")
    except ModelEnvError as e:
        print(f"     Bob denied at L2 (session owner) as expected: {e.message}")
    except Exception as e:
        # A denial may also come from L1 (the daemon's app-run-task gate) before the
        # request reaches model-env — still "denied", just at a different layer.
        print(f"     Bob denied at L1 (daemon RBAC) as expected: {type(e).__name__}")
    finally:
        env.close(sid)


SCENARIOS = {
    "a_single": scenario_a_single,
    "a_multiturn": scenario_a_multiturn,
    "a_budget": scenario_a_budget,
    "a_tool": scenario_a_tool,
    "b_streaming": scenario_b_streaming,
    "b_multiturn": scenario_b_multiturn,
    "authz": scenario_authz,
}


def parse_args():
    p = argparse.ArgumentParser(description="model-env user usage scenarios")
    p.add_argument("scenario", nargs="?", default="all", help="scenario name, 'all', or 'list'")
    p.add_argument("--list", action="store_true", help="list scenarios and exit")
    p.add_argument("--host", default=os.environ.get("APPMESH_TCP_HOST", "127.0.0.1"))
    p.add_argument("--port", default=os.environ.get("APPMESH_TCP_PORT", "6059"))
    p.add_argument("--tenant", default=os.environ.get("MODELENV_TENANT", "default"))
    p.add_argument("--app", default=os.environ.get("MODELENV_APP", ""))
    p.add_argument("--user", default=os.environ.get("APPMESH_USER", "admin"))
    p.add_argument("--password", default=os.environ.get("APPMESH_PASSWORD", "admin123"))
    p.add_argument("--user2", default=os.environ.get("APPMESH_USER2", ""))
    p.add_argument("--password2", default=os.environ.get("APPMESH_PASSWORD2", ""))
    p.add_argument("--worker-app", default=os.environ.get("MODELENV_WORKER_APP", ""))
    p.add_argument("--worker-session", default=os.environ.get("MODELENV_WORKER_SESSION", ""))
    p.add_argument("--tool-app", default=os.environ.get("MODELENV_TOOL_APP", ""))
    p.add_argument("--task-timeout", type=int, default=int(os.environ.get("MODELENV_TASK_TIMEOUT", "120")))
    cfg = p.parse_args()
    if not cfg.app:
        cfg.app = f"model-env-{cfg.tenant}"
    return cfg


def main():
    cfg = parse_args()
    if cfg.list or cfg.scenario == "list":
        print("Scenarios:")
        for name, fn in SCENARIOS.items():
            print(f"  {name:14s} {fn.__doc__.splitlines()[0]}")
        return 0

    names = list(SCENARIOS) if cfg.scenario == "all" else [cfg.scenario]
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown:
        print(f"unknown scenario(s): {unknown}; try --list", file=sys.stderr)
        return 2

    env = ModelEnv(cfg.host, cfg.port, cfg.app, cfg.task_timeout).login(cfg.user, cfg.password)
    print(f"connected to {cfg.host}:{cfg.port}, app {cfg.app!r} (user {cfg.user!r})\n")
    failures = 0
    for name in names:
        print(f"=== {name} ===")
        try:
            SCENARIOS[name](env, cfg)
        except Exception as e:  # a scenario failing should not abort the rest
            failures += 1
            print(f"     SCENARIO FAILED: {type(e).__name__}: {e}")
        print()
        time.sleep(0.2)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
