"""Application run object"""

from contextlib import contextmanager

# pylint: disable=line-too-long


class AppRun(object):
    """
    Represents an application run object initiated by `run_async()` for monitoring and retrieving
    the result of a remote application run.
    """

    def __init__(self, client, app_name: str, process_id: str):
        self.app_name = app_name
        """Name of the application associated with this run."""

        self.proc_uid = process_id
        """Unique process ID from `run_async()`."""

        self._client = client
        """Instance of `AppMeshClient` used to manage this application run."""

        self._forwarding_host = client.forwarding_host
        """Target server for the application run, used for forwarding."""

    @contextmanager
    def forwarding_host(self):
        """Context manager to override the `forwarding_host` for the duration of the run."""
        original_value = self._client.forwarding_host
        self._client.forwarding_host = self._forwarding_host
        try:
            yield
        finally:
            self._client.forwarding_host = original_value

    def wait(self, stdout_print: bool = True, timeout: int = 0) -> int:
        """Wait for the asynchronous run to complete.

        Args:
            stdout_print (bool, optional): If `True`, prints remote stdout to local. Defaults to `True`.
            timeout (int, optional): Maximum time to wait in seconds. If `0`, waits until completion. Defaults to `0`.

        Returns:
            int: Exit code if the process finishes successfully. Returns `None` on timeout or exception.
        """
        with self.forwarding_host():
            return self._client.run_async_wait(self, stdout_print, timeout)
