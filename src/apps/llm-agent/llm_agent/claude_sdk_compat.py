"""Python 3.6 fallback for the ``claude_agent_sdk`` surface this App uses.

The official Claude Agent SDK requires Python >= 3.10; the legacy line targets
Ubuntu 18.04's system Python 3.6. This module re-implements the narrow surface
``claude_sdk.py`` consumes — ``query``, ``ClaudeAgentOptions`` and the three
message types — by driving the Claude Code CLI directly with the same
``--print --output-format stream-json`` protocol the official SDK uses.

Behaviour differences kept deliberate and small:

- ``system_prompt`` is appended (``--append-system-prompt``); the CLI in this
  mode has no full-replacement flag the SDK maps to.
- ``continue_conversation`` resumes the cwd's most recent conversation with
  ``--continue`` — the same cwd-keyed model the wrapper already uses.
- The ``claude`` executable must be on PATH (the official wheel bundles its
  own copy; here the host provides it).

On hosts with Python >= 3.10 the real SDK is preferred; ``claude_sdk.py``
imports this module only when ``claude_agent_sdk`` is unavailable.
"""
import json
import logging
import os
import shlex
import shutil
import subprocess
import threading

log = logging.getLogger("llm_agent.claude_sdk_compat")


class ClaudeAgentOptions(object):
    """Same keyword surface as the SDK's options dataclass; plain holder."""

    def __init__(self, permission_mode="default", stderr=None, cwd=None,
                 continue_conversation=False, model=None, system_prompt=None,
                 allowed_tools=None, max_turns=None):
        self.permission_mode = permission_mode
        self.stderr = stderr
        self.cwd = cwd
        self.continue_conversation = continue_conversation
        self.model = model
        self.system_prompt = system_prompt
        self.allowed_tools = allowed_tools
        self.max_turns = max_turns


class TextBlock(object):
    def __init__(self, text):
        self.text = text


class AssistantMessage(object):
    def __init__(self, content):
        self.content = content  # list of blocks (TextBlock, ...)


class ResultMessage(object):
    def __init__(self, result, usage, num_turns, subtype, is_error=False):
        self.result = result
        self.usage = usage or {}
        self.num_turns = num_turns
        self.subtype = subtype
        self.is_error = is_error


def _cli_argv():
    cli = os.environ.get("CLAUDE_CODE_CLI") or "claude"
    if os.path.sep not in cli and not shutil.which(cli):
        raise RuntimeError("the Claude Code CLI (%r) is not on PATH; install it "
                           "or point CLAUDE_CODE_CLI at it" % cli)
    return cli


def _build_argv(prompt, options):
    argv = [_cli_argv(), "--print", "--output-format", "stream-json", "--verbose"]
    mode = options.permission_mode or "default"
    if mode == "bypassPermissions":
        argv.append("--dangerously-skip-permissions")
    else:
        argv.extend(["--permission-mode", mode])
    if options.continue_conversation:
        argv.append("--continue")
    if options.model:
        argv.extend(["--model", options.model])
    if options.system_prompt:
        argv.extend(["--append-system-prompt", options.system_prompt])
    if options.allowed_tools:
        argv.extend(["--allowedTools", ",".join(options.allowed_tools)])
    if options.max_turns:
        argv.extend(["--max-turns", str(options.max_turns)])
    argv.append("--")
    argv.append(prompt)
    return argv


def _pump_stderr(stream, callback):
    """Forward the CLI's own stderr to the callback, line by line."""
    for raw in iter(stream.readline, b""):
        line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        try:
            callback(line)
        except Exception:
            pass
    try:
        stream.close()
    except Exception:
        pass


def _parse_event(raw):
    """Map one stream-json line to the SDK message types (None for noise)."""
    try:
        event = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(event, dict):
        return None
    kind = event.get("type")
    if kind == "assistant":
        blocks = []
        for item in ((event.get("message") or {}).get("content") or []):
            if isinstance(item, dict) and item.get("type") == "text" and item.get("text"):
                blocks.append(TextBlock(item["text"]))
        if blocks:
            return AssistantMessage(blocks)
        return None
    if kind == "result":
        return ResultMessage(
            result=event.get("result") or "",
            usage=event.get("usage") or {},
            num_turns=int(event.get("num_turns") or 0),
            subtype=event.get("subtype") or "",
            is_error=bool(event.get("is_error")),
        )
    return None


async def query(prompt, options):
    """Async generator over one turn: spawn the CLI, map events, finish.

    The CLI is a plain subprocess read synchronously, not asyncio.create_subprocess:
    on Python 3.6 the async subprocess needs a SIGCHLD child watcher attached to
    the running loop, which is fragile inside a supervised App, and this loop is
    single-purpose anyway (one turn at a time, a synchronous stream callback).
    The async-generator surface stays the SDK's.
    """
    argv = _build_argv(prompt, options)
    log.debug("claude cli: %s", " ".join(shlex.quote(a) for a in argv))
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=options.cwd or None,
    )
    stderr_thread = None
    if options.stderr:
        # Drain stderr off-thread: a chatty CLI must not stall the turn.
        stderr_thread = threading.Thread(target=_pump_stderr, args=(proc.stderr, options.stderr), daemon=True)
        stderr_thread.start()
    try:
        for raw in iter(proc.stdout.readline, b""):
            message = _parse_event(raw.decode("utf-8", "replace"))
            if message is not None:
                yield message
        proc.stdout.close()
        proc.wait()
    finally:
        if stderr_thread is not None:
            try:
                proc.stderr.close()  # unblocks the pump on an abnormal exit
            except Exception:
                pass
            stderr_thread.join(timeout=5)
        else:
            try:
                proc.stderr.close()
            except Exception:
                pass
        if proc.poll() is None:  # abnormal path: never leave the CLI running
            proc.kill()
            proc.wait()
