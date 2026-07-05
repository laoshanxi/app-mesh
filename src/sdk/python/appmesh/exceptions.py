# exceptions.py
"""App Mesh SDK exception hierarchy."""


class AppMeshError(Exception):
    """Base exception for all App Mesh SDK errors."""


class AppMeshAuthError(AppMeshError):
    """Authentication or authorization error."""


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
