# __init__.py
"""
App Mesh SDK package initializer.

This module exports the main client classes used to interact with the App Mesh API.

Example:
    from appmesh import AppMeshClient
    client = AppMeshClient()
"""

import sys
from types import ModuleType

__all__ = ["App", "AppMeshClient", "AppMeshClientTCP", "AppMeshClientOAuth", "AppMeshServer", "AppMeshServerTCP"]

_LAZY_IMPORTS = {
    "App": ("app", "App"),  # from .app import App
    "AppMeshClient": ("client_http", "AppMeshClient"),  # from .client_http import AppMeshClient
    "AppMeshClientTCP": ("client_tcp", "AppMeshClientTCP"),  # from .client_tcp import AppMeshClientTCP
    "AppMeshClientOAuth": ("client_http_oauth", "AppMeshClientOAuth"),  # from .client_http_oauth import AppMeshClientOAuth
    "AppMeshServer": ("server_http", "AppMeshServer"),  # from .server_http import AppMeshServer
    "AppMeshServerTCP": ("server_tcp", "AppMeshServerTCP"),  # from .server_tcp import AppMeshServerTCP
}


def _lazy_import(name):
    """Helper function for lazy importing."""
    if name in _LAZY_IMPORTS:
        module_name, attr_name = _LAZY_IMPORTS[name]
        module = __import__(f"{__name__}.{module_name}", fromlist=[attr_name])
        return getattr(module, attr_name)
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


if sys.version_info >= (3, 7):

    def __getattr__(name):
        return _lazy_import(name)

else:
    # Python 3.6 compatibility
    class _LazyModule(ModuleType):
        def __getattr__(self, name):
            return _lazy_import(name)

    sys.modules[__name__] = _LazyModule(__name__)
    sys.modules[__name__].__dict__.update(globals())
