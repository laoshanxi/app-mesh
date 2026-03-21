# exceptions.py
"""App Mesh SDK exception hierarchy."""


class AppMeshError(Exception):
    """Base exception for all App Mesh SDK errors."""


class AppMeshAuthError(AppMeshError):
    """Authentication or authorization error."""


class AppMeshConnectionError(AppMeshError):
    """Connection or transport error."""


class AppMeshRequestError(AppMeshError):
    """HTTP request failed."""
