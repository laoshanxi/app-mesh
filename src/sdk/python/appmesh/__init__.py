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
    "AppRun",
    "AppOutput",
    "AppMeshClient",
    "AppMeshClientTCP",
    "AppMeshClientWSS",
    "OAuthClient",
    "OAuthError",
    "TokenProvider",
    "StaticAccessTokenProvider",
    "AppMeshWorker",
    "AppMeshWorkerTCP",
    "AppMeshWorkerWSS",
    "AppMeshError",
    "AppMeshAuthError",
    "AppMeshConnectionError",
    "AppMeshTimeoutError",
    "AppMeshRequestError",
    "AppMeshAppRemovedError",
    "AppMeshProcessSupersededError",
    "AppMeshWorkerRejectedError",
    "AppEvent",
    "SubscriptionResult",
    "OutputHandler",
    "print_output_handler",
]

# Lazy import configuration
_LAZY_IMPORTS = {
    "App": ("app", "App"),  # from .app import App
    "AppRun": ("app_run", "AppRun"),  # from .app_run import AppRun
    "AppOutput": ("app_output", "AppOutput"),  # from .app_output import AppOutput
    "AppMeshClient": ("client_http", "AppMeshClient"),  # from .client_http import AppMeshClient
    "AppMeshClientTCP": ("client_tcp", "AppMeshClientTCP"),  # from .client_tcp import AppMeshClientTCP
    "AppMeshClientWSS": ("client_wss", "AppMeshClientWSS"),  # from .client_wss import AppMeshClientWSS
    "OAuthClient": ("oauth", "OAuthClient"),  # from .oauth import OAuthClient
    "OAuthError": ("oauth", "OAuthError"),  # from .oauth import OAuthError
    # Compatibility aliases are available but are not part of the documented API.
    "DexOAuthClient": ("dex_oauth", "DexOAuthClient"),
    "DexOAuthError": ("dex_oauth", "DexOAuthError"),
    "TokenProvider": ("token_provider", "TokenProvider"),  # from .token_provider import TokenProvider
    "StaticAccessTokenProvider": ("token_provider", "StaticAccessTokenProvider"),  # from .token_provider import StaticAccessTokenProvider
    "AppMeshWorker": ("worker_http", "AppMeshWorker"),  # from .worker_http import AppMeshWorker
    "AppMeshWorkerTCP": ("worker_tcp", "AppMeshWorkerTCP"),  # from .worker_tcp import AppMeshWorkerTCP
    "AppMeshWorkerWSS": ("worker_wss", "AppMeshWorkerWSS"),  # from .worker_wss import AppMeshWorkerWSS
    "AppMeshError": ("exceptions", "AppMeshError"),  # from .exceptions import AppMeshError
    "AppMeshAuthError": ("exceptions", "AppMeshAuthError"),  # from .exceptions import AppMeshAuthError
    "AppMeshConnectionError": ("exceptions", "AppMeshConnectionError"),  # from .exceptions import AppMeshConnectionError
    "AppMeshTimeoutError": ("exceptions", "AppMeshTimeoutError"),  # from .exceptions import AppMeshTimeoutError
    "AppMeshRequestError": ("exceptions", "AppMeshRequestError"),  # from .exceptions import AppMeshRequestError
    "AppMeshAppRemovedError": ("exceptions", "AppMeshAppRemovedError"),  # from .exceptions import AppMeshAppRemovedError
    "AppMeshProcessSupersededError": ("exceptions", "AppMeshProcessSupersededError"),  # from .exceptions import AppMeshProcessSupersededError
    "AppMeshWorkerRejectedError": ("exceptions", "AppMeshWorkerRejectedError"),  # from .exceptions import AppMeshWorkerRejectedError
    "AppEvent": ("subscribe", "AppEvent"),  # from .subscribe import AppEvent
    "SubscriptionResult": ("subscribe", "SubscriptionResult"),  # from .subscribe import SubscriptionResult
    "OutputHandler": ("app_run", "OutputHandler"),  # from .app_run import OutputHandler
    "print_output_handler": ("app_run", "print_output_handler"),  # from .app_run import print_output_handler
}

if TYPE_CHECKING:
    # Type checking imports (not executed at runtime)
    from .app import App  # noqa: F401
    from .app_run import AppRun  # noqa: F401
    from .app_output import AppOutput  # noqa: F401
    from .client_http import AppMeshClient  # noqa: F401
    from .client_tcp import AppMeshClientTCP  # noqa: F401
    from .client_wss import AppMeshClientWSS  # noqa: F401
    from .oauth import OAuthClient, OAuthError  # noqa: F401
    from .token_provider import StaticAccessTokenProvider, TokenProvider  # noqa: F401
    from .worker_http import AppMeshWorker  # noqa: F401
    from .worker_tcp import AppMeshWorkerTCP  # noqa: F401
    from .worker_wss import AppMeshWorkerWSS  # noqa: F401
    from .exceptions import AppMeshError, AppMeshAuthError, AppMeshConnectionError, AppMeshTimeoutError, AppMeshRequestError, AppMeshAppRemovedError, AppMeshProcessSupersededError, AppMeshWorkerRejectedError  # noqa: F401
    from .subscribe import AppEvent, SubscriptionResult  # noqa: F401
    from .app_run import OutputHandler, print_output_handler  # noqa: F401


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
