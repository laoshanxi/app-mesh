# app_run.py
"""Application run object for remote application execution."""

from contextlib import contextmanager
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .client_http import AppMeshClient


class AppRun:
    """
    Application run object for monitoring and retrieving results
    of a remote application run initiated by `run_async()`.
    """

    def __init__(self, client: "AppMeshClient", app_name: str, process_id: str):
        self.app_name = app_name
        """Name of the application associated with this run."""

        self.proc_uid = process_id
        """Unique process ID from `run_async()`."""

        self._client = client
        self._forward_to = client.forward_to

    @contextmanager
    def forward_to(self):
        """
        Context manager to temporarily override the client's `forward_to` setting.

        Ensures operations during this run use the correct target server,
        then restores the original setting.
        """
        original_value = self._client.forward_to
        self._client.forward_to = self._forward_to
        try:
            yield
        finally:
            self._client.forward_to = original_value

    def wait(self, stdout_print: bool = True, timeout: int = 0) -> Optional[int]:
        """
        Wait for the asynchronous run to complete.

        Args:
            stdout_print: If True, prints remote stdout to local console.
            timeout: Maximum time to wait in seconds. 0 means wait indefinitely.

        Returns:
            Exit code if the process finishes successfully, or None on timeout.
        """
        with self.forward_to():
            return self._client.wait_for_async_run(self, stdout_print, timeout)
