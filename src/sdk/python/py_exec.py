"""Python remote code string execution for application pyrun"""

#!/usr/bin/env python

import traceback
from io import StringIO
from contextlib import redirect_stdout, redirect_stderr

from appmesh import AppMeshClient


def exec_with_output(code_string, exec_globals=None):
    """Execute Python code and capture stdout/stderr."""
    output = StringIO()
    # Redirect both stdout and stderr into the same buffer.
    with redirect_stdout(output), redirect_stderr(output):
        try:
            # Execute using the provided globals mapping or a new empty mapping.
            exec(code_string, exec_globals if exec_globals is not None else {})
        except Exception:
            # Print the full traceback into the same buffer.
            traceback.print_exc()
    return output.getvalue()


if __name__ == "__main__":
    # Minimal server loop: fetch a payload, execute it, return the output.
    mesh = AppMeshClient()
    while True:
        # Block fetch invocation payload.
        payload = mesh.task_fetch()
        # Execute with payload and capture prints.
        output = exec_with_output(payload)
        # Return the result to the client
        mesh.task_return(output)
