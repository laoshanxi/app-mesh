"""Application output information"""

from http import HTTPStatus
from typing import Optional

# pylint: disable=line-too-long


class AppOutput(object):
    """
    Represents the output information returned by the `app_output()` API, including the application's
    stdout content, current read position, status code, and exit code.
    """

    def __init__(self, status_code: HTTPStatus, output: str, out_position: Optional[int], exit_code: Optional[int]) -> None:
        self.status_code = status_code
        """HTTP status code from the `app_output()` API request, indicating the result status."""

        self.output = output
        """Captured stdout content of the application as returned by the `app_output()` API."""

        self.out_position = out_position
        """Current read position in the application's stdout stream, or `None` if not applicable."""

        self.exit_code = exit_code
        """Exit code of the application, or `None` if the process is still running or hasn't exited."""
