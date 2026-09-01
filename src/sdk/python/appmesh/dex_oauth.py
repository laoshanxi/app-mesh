"""Compatibility imports for SDK 3.0 applications.

New applications import :class:`OAuthClient` and :class:`OAuthError` from
``appmesh`` or ``appmesh.oauth``.
"""

from .oauth import OAuthClient, OAuthError, requests

DexOAuthClient = OAuthClient
DexOAuthError = OAuthError

__all__ = ["DexOAuthClient", "DexOAuthError"]
