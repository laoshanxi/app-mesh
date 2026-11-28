#!/usr/bin/env python3
"""Python remote code string execution for application py-task"""

import sys
import traceback
from io import StringIO
from contextlib import redirect_stdout, redirect_stderr
from typing import Callable, Optional, Union

try:
    from appmesh import AppMeshWorkerTCP
except ImportError:
    sys.exit("py-task needs the appmesh Python SDK: pip3 install appmesh")


class _StreamingOutput(StringIO):
    """Output buffer that forwards every completed line to a streaming caller.

    ``send_partial`` is skipped entirely once it reports no streaming caller
    (or fails), so one-shot ``run_task`` payloads pay no extra round trips.
    """

    def __init__(self, send_partial: Optional[Callable[[str], bool]] = None):
        super().__init__()
        self._send_partial = send_partial
        self._pending = ""
        self._skip_partial = send_partial is None

    def write(self, s: str) -> int:
        if not self._skip_partial and s:
            self._pending += s
            while "\n" in self._pending:
                line, self._pending = self._pending.split("\n", 1)
                self._emit(line + "\n")
        return super().write(s)

    def _emit(self, line: str) -> None:
        # Flag first: the notice below re-enters write() when called under
        # redirect_stdout, and a lost partial must degrade only the stream
        # (losing the worker kills every tenant sharing it).
        self._skip_partial = True
        try:
            if self._send_partial(line):
                self._skip_partial = False
        except Exception as exc:
            print(f"[py-task] send_task_partial failed ({exc}); continuing without partials",
                  file=sys.__stderr__, flush=True)


def exec_with_output(code: Union[str, bytes], exec_globals: Optional[dict] = None,
                     send_partial: Optional[Callable[[str], bool]] = None) -> str:
    """Execute Python code and capture all output, streaming completed lines."""
    output_buffer = _StreamingOutput(send_partial)
    namespace = exec_globals or {}
    if isinstance(code, bytes):
        code = code.decode("utf-8", errors="replace")
    with redirect_stdout(output_buffer), redirect_stderr(output_buffer):
        try:
            exec(code, namespace)
        except Exception:
            traceback.print_exc()

    return output_buffer.getvalue()


def main():
    """Server loop: fetch a payload, execute it, return the output.

    Transient transport failures (the daemon recycles TCP connections) must end
    at most one task: a crashed worker answers "No process running" to every
    application sharing this App until the keepalive restart.
    """
    context = AppMeshWorkerTCP()
    if not hasattr(context, "send_task_partial"):
        sys.exit("py-task requires appmesh SDK >= 3.0.24 with task streaming support "
                 "(send_task_partial); upgrade with: pip3 install -U appmesh")
    while True:
        payload = context.fetch_task()  # Wait and fetch a payload (retries transient failures; 412/400 raise)
        output = exec_with_output(payload, send_partial=context.send_task_partial)
        try:
            context.send_task_result(output)  # Return the output back to the client
        except Exception as exc:
            # The caller's request times out on its own; keep serving new tasks.
            print(f"[py-task] send_task_result failed ({exc})", file=sys.__stderr__, flush=True)


if __name__ == "__main__":
    main()
