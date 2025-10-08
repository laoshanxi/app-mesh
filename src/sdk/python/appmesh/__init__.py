# __init__.py
"""
App Mesh SDK package initializer with lazy loading support.

Example:
    from appmesh import AppMeshClient
    client = AppMeshClient()
"""

import sys
from types import ModuleType
from typing import TYPE_CHECKING
from importlib import import_module

__all__ = [
    "App",
    "AppMeshClient",
    "AppMeshClientTCP",
    "AppMeshClientOAuth",
    "AppMeshServer",
    "AppMeshServerTCP",
]

# Lazy import configuration
_LAZY_IMPORTS = {
    "App": ("app", "App"),  # from .app import App
    "AppMeshClient": ("client_http", "AppMeshClient"),  # from .client_http import AppMeshClient
    "AppMeshClientTCP": ("client_tcp", "AppMeshClientTCP"),  # from .client_tcp import AppMeshClientTCP
    "AppMeshClientOAuth": ("client_http_oauth", "AppMeshClientOAuth"),  # from .client_http_oauth import AppMeshClientOAuth
    "AppMeshServer": ("server_http", "AppMeshServer"),  # from .server_http import AppMeshServer
    "AppMeshServerTCP": ("server_tcp", "AppMeshServerTCP"),  # from .server_tcp import AppMeshServerTCP
}

if TYPE_CHECKING:
    # Type checking imports (not executed at runtime)
    from .app import App  # noqa: F401
    from .client_http import AppMeshClient  # noqa: F401
    from .client_tcp import AppMeshClientTCP  # noqa: F401
    from .client_http_oauth import AppMeshClientOAuth  # noqa: F401
    from .server_http import AppMeshServer  # noqa: F401
    from .server_tcp import AppMeshServerTCP  # noqa: F401


def _lazy_import(name: str):
    """
    Internal helper for lazy import resolution using PEP 562.
    Only imports modules when accessed, improving startup time.
    """
    if name in _LAZY_IMPORTS:
        module_name, attr_name = _LAZY_IMPORTS[name]
        module = import_module(f".{module_name}", __name__)
        globals()[name] = getattr(module, attr_name)
        return globals()[name]
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


def __dir__():
    """Provide tab-completion support for lazy-loaded attributes."""
    return sorted(__all__ + list(globals().keys()))


if sys.version_info >= (3, 7):
    __getattr__ = _lazy_import
else:
    # Python 3.6 compatibility via module replacement
    class _LazyModule(ModuleType):
        def __getattr__(self, name):
            return _lazy_import(name)

        def __dir__(self):
            return sorted(__all__ + list(globals().keys()))

    sys.modules[__name__] = _LazyModule(__name__)
    sys.modules[__name__].__dict__.update(globals())
