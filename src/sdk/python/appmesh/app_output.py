# app_output.py
"""Application output information."""

from dataclasses import dataclass
from http import HTTPStatus
from typing import Optional


@dataclass(frozen=True)
class AppOutput:
    """
    Output information returned by the `get_app_output()` API.

    Includes the application's stdout, current read position,
    HTTP status code, and process exit code.
    """

    status_code: HTTPStatus
    """HTTP status code from the `get_app_output()` API request."""

    output: str
    """Captured stdout content of the application."""

    output_position: Optional[int]
    """Current read position in stdout stream (wire header ``X-Output-Position``), or None if not applicable."""

    exit_code: Optional[int]
    """Exit code of the application, or None if still running."""
