# client_http_oauth.py
# pylint: disable=line-too-long,broad-exception-caught,too-many-lines,import-outside-toplevel,broad-exception-raised
"""AppMesh HTTP client with Keycloak OAuth2 authentication (direct-to-IdP).

Two OAuth2/Keycloak models exist:

* Daemon-proxied (base ``AppMeshClient``): the client talks only to the daemon, which
  brokers Keycloak; the access token lives in the cookie jar.
* Direct-to-IdP (this ``AppMeshClientOAuth``): the client authenticates against Keycloak
  via ``python-keycloak`` and presents the token to the daemon as a Bearer JWT.

Both reuse the base client's background token refresh; this subclass overrides
``renew_token`` / ``_get_access_token`` to drive the Keycloak refresh.

Dependency: ``python -m pip install python-keycloak``
"""

import json
import logging
import time
import warnings
from typing import Any, Callable, Dict, Optional, Tuple, Union

from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakPostError

from .client_http import AppMeshClient
from .exceptions import AppMeshAuthError

logger = logging.getLogger(__name__)


class AppMeshClientOAuth(AppMeshClient):
    """
    AppMeshClient with Keycloak as the identity provider.

    Dependency:
        python -m pip install python-keycloak
    """

    def __init__(
        self,
        oauth2: Dict[str, str],  # Required for Keycloak
        base_url: str = "https://127.0.0.1:6060",
        ssl_verify: Union[bool, str, None] = None,
        ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = None,
        request_timeout: Tuple[float, float] = (60, 300),
        auto_refresh_token: bool = True,  # Default to True for Keycloak
        use_refresh_token: Optional[bool] = None,
    ):
        """Initialize an App Mesh HTTP client with Keycloak support.

        Args:
            oauth2: Keycloak configuration for oauth2 authentication:
                - auth_server_url: Keycloak server URL (e.g. "https://keycloak.example.com/auth/")
                - realm: Keycloak realm
                - client_id: Keycloak client ID
                - client_secret: Keycloak client secret (optional)
        """
        # Initialize base class; token refresh is driven here via the overridden renew_token()
        super().__init__(
            base_url=base_url,
            ssl_verify=ssl_verify,
            ssl_client_cert=ssl_client_cert,
            request_timeout=request_timeout,
            auto_refresh_token=auto_refresh_token,
            use_refresh_token=use_refresh_token,
        )

        # Keycloak integration
        timeout = (int(request_timeout) if isinstance(request_timeout, (int, float)) else int(request_timeout[0])) if request_timeout is not None else None
        keycloak_kwargs = {
            "server_url": oauth2.get("auth_server_url"),
            "client_id": oauth2.get("client_id"),
            "realm_name": oauth2.get("realm"),
            "client_secret_key": oauth2.get("client_secret"),
            "verify": self.ssl_verify,
            **({} if timeout is None else {"timeout": timeout}),
        }
        self._keycloak_openid = KeycloakOpenID(**keycloak_kwargs)

        self._token: Dict[str, Any] = {}

    def _get_access_token(self) -> Optional[str]:
        """Get the current access token."""
        return self._token.get("access_token") if self._token else None

    def login(
        self,
        username: str,
        password: str,
        totp_code: Optional[str] = None,
        token_expire: Union[str, int] = 0,
        audience: Optional[str] = None,
    ) -> None:
        """Login with username and password using Keycloak.

        Args:
            username: The name of the user.
            password: The password of the user.
            totp_code: The TOTP code if enabled for the user.
            token_expire: Token expiration duration (unused in Keycloak flow).
            audience: Token audience (unused in Keycloak flow).
        """
        if token_expire or audience:
            warnings.warn("token_expire and audience are ignored by the Keycloak login flow", UserWarning, stacklevel=2)
        # Keycloak authentication
        self._token = self._keycloak_openid.token(
            username=username,
            password=password,
            # Pass TOTP as-is: int() would strip leading zeros (e.g. "012345" -> 12345)
            totp=totp_code if totp_code else None,
            grant_type="password",  # grant type for token request: "password" / "client_credentials" / "refresh_token"
            scope="openid profile email",  # request identity claims so userinfo returns preferred_username/email
        )
        self._on_token_changed(self._get_access_token())

    def login_device_flow(
        self,
        scope: str = "openid profile email",
        on_prompt: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        """Login via the OAuth 2.0 Device Authorization Grant (RFC 8628).

        For browserless/input-constrained environments: the user opens
        ``verification_uri_complete`` (or ``verification_uri`` + ``user_code``) on another
        device, and this call polls the token endpoint until approval, denial, or expiry.

        Requires "OAuth 2.0 Device Authorization Grant" enabled on the Keycloak client
        (client settings → Capability config).

        Args:
            scope: OAuth2 scopes to request.
            on_prompt: Callback receiving the device authorization response (keys per
                RFC 8628 §3.2: ``user_code``, ``verification_uri``,
                ``verification_uri_complete``, ``expires_in``, ``interval``) to present
                the instructions to the user. Defaults to printing them to stdout.

        Raises:
            AppMeshAuthError: When the user denies the request, the device code expires,
                or the token request fails for any other reason.
        """
        device = self._keycloak_openid.device(scope=scope)

        if on_prompt:
            on_prompt(device)
        else:
            uri = device.get("verification_uri_complete") or device.get("verification_uri")
            print(f"To sign in, open {uri} and enter code: {device.get('user_code')}")

        # RFC 8628 §3.5: poll no faster than "interval", stop once the device code expires
        interval = int(device.get("interval", 5))
        deadline = time.monotonic() + int(device.get("expires_in", 600))

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AppMeshAuthError("Device authorization expired before the user approved the request")
            time.sleep(min(interval, remaining))
            try:
                self._token = self._keycloak_openid.token(
                    grant_type="urn:ietf:params:oauth:grant-type:device_code",
                    device_code=device["device_code"],
                )
            except KeycloakPostError as e:
                error = self._oauth_error_code(e)
                if error == "authorization_pending":
                    continue
                if error == "slow_down":
                    interval += 5  # RFC 8628 §3.5: back off by 5 seconds
                    continue
                raise AppMeshAuthError(f"Device authorization failed: {error or e}") from e
            self._on_token_changed(self._get_access_token())
            return

    @staticmethod
    def _oauth_error_code(e: KeycloakPostError) -> str:
        """Extract the OAuth2 "error" code from a Keycloak error response body."""
        try:
            return json.loads(e.response_body).get("error", "")
        except Exception:
            return ""

    def _revoke_keycloak_session(self, context: str) -> bool:
        """Best-effort Keycloak RP-initiated logout for the current refresh token.

        Returns True when the Keycloak session was revoked or there was nothing to
        revoke; False only when a revocation was attempted and failed.
        """
        if not (self._keycloak_openid and isinstance(self._token, dict)):
            return True
        refresh_token = self._token.get("refresh_token")
        if not refresh_token:
            return True
        try:
            self._keycloak_openid.logout(refresh_token)
            return True
        except Exception as e:
            logger.warning("Failed to logout from Keycloak during %s: %s", context, e)
            return False

    def logout(self) -> bool:
        """Log out. Returns whether the Keycloak session ended; the daemon logoff is
        best-effort and its failure does not affect the return value."""
        keycloak_ok = self._revoke_keycloak_session("logout")
        # Revoke on the daemon before clearing the token, so it can read the access token.
        try:
            if not super().logout():
                logger.warning("Daemon-side logoff did not succeed")
        except Exception as e:
            logger.warning("Daemon-side logoff failed: %s", e)
        self._token = {}
        return keycloak_ok

    def renew_token(self, token_expire: Union[int, str] = 0) -> None:
        """Renew the current Keycloak token."""
        if not self._token or not isinstance(self._token, dict):
            raise AppMeshAuthError("No valid Keycloak token available")

        refresh_token = self._token.get("refresh_token")
        if not refresh_token:
            raise AppMeshAuthError("No Keycloak refresh token available to renew")

        try:
            # Handle Keycloak token (dictionary format)
            new_token = self._keycloak_openid.refresh_token(refresh_token)
            self._token = new_token
            self._on_token_changed(self._get_access_token())
        except Exception as e:
            logger.error("Keycloak token renewal failed: %s", e)
            raise AppMeshAuthError(f"Keycloak token renewal failed: {str(e)}") from e

    def get_oauth_userinfo(self) -> dict:
        """Get Keycloak OIDC userinfo for the current access token, directly from Keycloak.

        Unlike :meth:`get_current_user` (inherited), which asks the App Mesh daemon
        ``/appmesh/user/self``, this queries the Keycloak userinfo endpoint without
        involving the daemon.

        Returns:
            Keycloak userinfo dictionary (OIDC claims such as ``sub``,
            ``preferred_username``, ``email``).
        """
        access_token = self._get_access_token()
        return self._keycloak_openid.userinfo(access_token)

    def close(self) -> None:
        """Close the session and release resources, including Keycloak logout."""
        if getattr(self, "_keycloak_openid", None):
            self._revoke_keycloak_session("close")
            # Always release, even when no refresh token was present.
            self._keycloak_openid = None
            self._token = {}

        # Close the base class session and resources (timers, etc.)
        super().close()
