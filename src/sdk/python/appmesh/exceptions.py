# exceptions.py
"""App Mesh SDK exception hierarchy."""


class AppMeshError(Exception):
    """Base exception for all App Mesh SDK errors."""


class AppMeshAuthError(AppMeshError):
    """Authentication or authorization error.

    ``status_code`` distinguishes 401 (the credential itself is rejected) from 403
    (the credential is fine but lacks the permission); callers must not treat them
    alike. ``None`` when the error did not come from an HTTP response.
    """

    def __init__(self, message: str, status_code=None):
        super().__init__(message)
        self.status_code = status_code


class AppMeshConnectionError(AppMeshError):
    """Connection or transport error."""


class AppMeshTimeoutError(AppMeshConnectionError):
    """Receive timeout on an otherwise healthy connection (safe to retry/continue)."""


class AppMeshRequestError(AppMeshError):
    """HTTP request failed."""


class AppMeshAppRemovedError(AppMeshError):
    """The application was removed before its process exit was observed."""


class AppMeshProcessSupersededError(AppMeshError):
    """The current process key was superseded by a newer process instance (HTTP 412)."""


class AppMeshWorkerRejectedError(AppMeshError):
    """The daemon permanently rejected a worker task request (HTTP 400)."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code
