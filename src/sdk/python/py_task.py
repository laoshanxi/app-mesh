"""Python remote code string execution for application pyexec"""

#!/usr/bin/env python

import traceback
from io import StringIO
from contextlib import redirect_stdout, redirect_stderr
from typing import Optional, Union

from appmesh import AppMeshServerTCP


def exec_with_output(code: Union[str, bytes], exec_globals: Optional[dict] = None) -> str:
    """Execute Python code and capture all output."""
    output_buffer = StringIO()
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
    """Minimal server loop: fetch a payload, execute it, return the output."""
    context = AppMeshServerTCP()
    while True:
        payload = context.task_fetch()  # Wait and fetch a payload
        output = exec_with_output(payload)  # Execute the payload
        context.task_return(output)  # Return the output back to the client


if __name__ == "__main__":
    main()
