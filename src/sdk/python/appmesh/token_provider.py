"""Access-token provider contracts for App Mesh SDK clients.

Providers own token acquisition and refresh.  Engine clients consume only the
resulting access token and never receive passwords, refresh tokens, or OAuth
authorization responses.
"""

from abc import ABCMeta, abstractmethod
from threading import RLock
from typing import Optional


class TokenProvider(metaclass=ABCMeta):
    """Provide a usable access token to an App Mesh Engine client.

    ``get_access_token`` may refresh proactively when the current token is near
    expiry.  ``refresh_access_token`` is called at most once after the Engine
    rejects a provider-managed token with HTTP 401.  Implementations should use
    ``rejected_token`` to avoid duplicate refreshes when requests race.

    Providers keep refresh credentials private; only an access token crosses
    this boundary into the Engine client.
    """

    @abstractmethod
    def get_access_token(self) -> Optional[str]:
        """Return a current access token, refreshing before expiry when possible."""

    @property
    def can_refresh(self) -> bool:
        """Whether this provider can replace a rejected or expiring token."""
        return False

    def refresh_access_token(self, rejected_token: Optional[str] = None) -> Optional[str]:
        """Replace a rejected token and return the new access token."""
        del rejected_token
        return self.get_access_token()

    def clear(self) -> None:
        """Forget provider-owned in-memory token state, if any."""


class StaticAccessTokenProvider(TokenProvider):
    """In-memory provider for a caller-supplied access token."""

    def __init__(self, token: str):
        self._lock = RLock()
        self._token = self._validate(token)

    @staticmethod
    def _validate(token: str) -> str:
        if not isinstance(token, str) or not token.strip():
            raise ValueError("bearer token must be a non-empty string")
        return token.strip()

    def get_access_token(self) -> Optional[str]:
        with self._lock:
            return self._token

    def clear(self) -> None:
        with self._lock:
            self._token = None
