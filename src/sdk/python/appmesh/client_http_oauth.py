# client_http_oauth.py
# pylint: disable=line-too-long,broad-exception-caught,too-many-lines,import-outside-toplevel,broad-exception-raised
"""AppMesh HTTP client with Keycloak OAuth2 authentication support."""

import logging
from typing import Optional, Union, Tuple, Dict, Any

from keycloak import KeycloakOpenID

from .client_http import AppMeshClient


class AppMeshClientOAuth(AppMeshClient):
    """
    AppMeshClient with Keycloak as the identity provider.

    Dependency:
        python -m pip install python-keycloak
    """

    def __init__(
        self,
        oauth2: Dict[str, str],  # Required for Keycloak
        rest_url: str = "https://127.0.0.1:6060",
        rest_ssl_verify: Union[bool, str] = AppMeshClient._DEFAULT_SSL_CA_CERT_PATH,
        rest_ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = None,
        rest_timeout: Tuple[float, float] = (60, 300),
        auto_refresh_token: bool = True,  # Default to True for Keycloak
    ):
        """Initialize an App Mesh HTTP client with Keycloak support.

        Args:
            oauth2: Keycloak configuration for oauth2 authentication:
                - auth_server_url: Keycloak server URL (e.g. "https://keycloak.example.com/auth/")
                - realm: Keycloak realm
                - client_id: Keycloak client ID
                - client_secret: Keycloak client secret (optional)
        """
        # Initialize base class, disabling its Keycloak and auto-refresh logic
        super().__init__(
            rest_url=rest_url,
            rest_ssl_verify=rest_ssl_verify,
            rest_ssl_client_cert=rest_ssl_client_cert,
            rest_timeout=rest_timeout,
            auto_refresh_token=auto_refresh_token,
        )

        # Keycloak integration
        timeout = (int(rest_timeout) if isinstance(rest_timeout, (int, float)) else int(rest_timeout[0])) if rest_timeout is not None else None
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
        user_name: str,
        user_pwd: str,
        totp_code: Optional[str] = None,
        timeout_seconds: Union[str, int] = 0,
        audience: Optional[str] = None,
    ) -> Optional[str]:
        """Login with user name and password using Keycloak.

        Args:
            user_name: The name of the user.
            user_pwd: The password of the user.
            totp_code: The TOTP code if enabled for the user.
            timeout_seconds: Login timeout (unused in Keycloak flow).
            audience: Token audience (unused in Keycloak flow).
        """
        # Keycloak authentication
        self._token = self._keycloak_openid.token(
            username=user_name,
            password=user_pwd,
            totp=int(totp_code) if totp_code else None,
            grant_type="password",  # grant type for token request: "password" / "client_credentials" / "refresh_token"
            scope="openid",  # what information to include in the token, such as "openid profile email"
        )

    def logoff(self) -> bool:
        """Log out of the current session from Keycloak and clean up."""
        result = False
        if self._keycloak_openid and self._token:
            try:
                refresh_token = self._token.get("refresh_token")
                if refresh_token:
                    self._keycloak_openid.logout(refresh_token)
                    result = True
            except Exception as e:
                logging.warning("Failed to logout from Keycloak: %s", e)
            finally:
                self._token = {}

        # Call super to handle base class cleanup (timers, session)
        super_result = super().logoff()

        return result and super_result

    def renew_token(self, timeout: Union[int, str] = 0) -> None:
        """Renew the current Keycloak token."""
        if not self._token or not isinstance(self._token, dict):
            raise Exception("No valid Keycloak token available")

        refresh_token = self._token.get("refresh_token")
        if not refresh_token:
            raise Exception("No Keycloak refresh token available to renew")

        try:
            # Handle Keycloak token (dictionary format)
            new_token = self._keycloak_openid.refresh_token(refresh_token)
            self._token = new_token
        except Exception as e:
            logging.error("Keycloak token renewal failed: %s", e)
            raise Exception(f"Keycloak token renewal failed: {str(e)}") from e

    def view_self(self) -> dict:
        """Get information about the current user using Keycloak userinfo.

        Returns:
            User information dictionary.
        """
        access_token = self._get_access_token()
        return self._keycloak_openid.userinfo(access_token)

    def close(self) -> None:
        """Close the session and release resources, including Keycloak logout."""
        # Logout from Keycloak if needed
        if hasattr(self, "_keycloak_openid") and self._keycloak_openid and self._token and isinstance(self._token, dict):
            refresh_token = self._token.get("refresh_token")
            if refresh_token:
                try:
                    self._keycloak_openid.logout(refresh_token)
                except Exception as e:
                    logging.warning("Failed to logout from Keycloak during close: %s", e)
                finally:
                    self._keycloak_openid = None
                    self._token = {}

        # Close the base class session and resources (timers, etc.)
        super().close()
