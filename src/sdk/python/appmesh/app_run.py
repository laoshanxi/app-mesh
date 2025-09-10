# app_run.py
"""Application run object for remote application execution."""

from contextlib import contextmanager

# pylint: disable=line-too-long


class AppRun:
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

        self._forward_to = client.forward_to
        """Target server for the application run, used for forwarding."""

    @contextmanager
    def forward_to(self):
        """Context manager to temporarily override the client's `forward_to` setting.

        This ensures that operations during this run use the correct target server,
        then restores the original setting when done.

        Yields:
            None: Context for the overridden forward_to setting.
        """
        original_value = self._client.forward_to
        self._client.forward_to = self._forward_to
        try:
            yield
        finally:
            self._client.forward_to = original_value

    def wait(self, stdout_print: bool = True, timeout: int = 0) -> int:
        """Wait for the asynchronous run to complete.

        Args:
            stdout_print: If `True`, prints remote stdout to local console. Defaults to `True`.
            timeout: Maximum time to wait in seconds. If `0`, waits indefinitely until completion.
                    Defaults to `0`.

        Returns:
            Exit code if the process finishes successfully, or `None` on timeout or exception.
        """
        with self.forward_to():
            return self._client.wait_for_async_run(self, stdout_print, timeout)
