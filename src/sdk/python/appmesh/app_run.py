# app_run.py
"""Application run object for remote application execution."""

from contextlib import contextmanager
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from .client_http import AppMeshClient

# Type alias for stdout callback: (data, position) -> None
OutputHandler = Callable[[str, int], None]


def print_output_handler(data: str, position: int) -> None:
    """Pre-built OutputHandler that prints data to stdout."""
    print(data, end="", flush=True)


class AppRun:
    """
    Application run object for monitoring and retrieving results
    of a remote application run initiated by `run_app_async()`.
    """

    def __init__(self, client: "AppMeshClient", app_name: str, process_uuid: str):
        self.app_name = app_name
        """Name of the application associated with this run."""

        self.process_uuid = process_uuid
        """Unique process UUID from `run_app_async()` (wire field ``process_uuid``)."""

        self._client = client
        self._forward_to = client.forward_to

    @contextmanager
    def _use_forward_host(self):
        """
        Context manager to temporarily override the client's `forward_to` setting.

        Ensures operations during this run use the correct target server,
        then restores the original setting.

        Warning:
            Mutates the SHARED client's ``forward_to``: concurrent requests on the
            same client from other threads are routed to this run's target host.
        """
        original_value = self._client.forward_to
        self._client.forward_to = self._forward_to
        try:
            yield
        finally:
            self._client.forward_to = original_value

    def wait(self, stdout_handler: Optional[OutputHandler] = None, timeout: int = 0) -> Optional[int]:
        """
        Wait for the asynchronous run to complete with the saved forwarding target restored.

        Args:
            stdout_handler: optional callback ``(data, position) -> None`` invoked with each
                chunk of stdout. Use ``print_output_handler`` for console output.
            timeout: Maximum time to wait in seconds. 0 means wait indefinitely.

        Returns:
            Exit code if the process finished, or ``None`` when ``timeout`` elapsed first.

        Raises:
            AppMeshConnectionError: On polling/transport failure while waiting.
            AppMeshAppRemovedError: If the app was removed before its exit was observed (TCP/WSS).

        Warning:
            While waiting, the SHARED client's ``forward_to`` is temporarily overridden
            (see ``_use_forward_host``); concurrent requests are routed to that host.
        """
        with self._use_forward_host():
            return self._client.wait_for_async_run(self, stdout_handler, timeout)
