"""Shared test SSL override for hosts without /opt/appmesh/ssl talking to a self-signed daemon.

Set APPMESH_TEST_SSL_VERIFY to "false"/"true" or a CA bundle path to override the SDK's
auto mode for clients constructed without an explicit ssl_verify. Unset: no effect.
"""
import os
from appmesh import AppMeshClient

_ENV = os.environ.get("APPMESH_TEST_SSL_VERIFY")
if _ENV is not None:
    _VALUE = {"false": False, "0": False, "no": False, "true": True, "1": True, "yes": True}.get(_ENV.lower(), _ENV)
    _ORIG = AppMeshClient._resolve_ssl_verify.__func__

    def _resolve(cls, ssl_verify):
        return _VALUE if ssl_verify is None else _ORIG(cls, ssl_verify)

    AppMeshClient._resolve_ssl_verify = classmethod(_resolve)
