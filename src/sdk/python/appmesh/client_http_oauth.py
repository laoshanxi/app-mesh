# client_http_oauth.py
# pylint: disable=line-too-long,broad-exception-caught,too-many-lines, import-outside-toplevel, protected-access
import logging
from typing import Optional, Union, Tuple
from keycloak import KeycloakOpenID
from .client_http import AppMeshClient


class AppMeshClientOAuth(AppMeshClient):
    """
    AppMeshClient extended with Keycloak authentication support.

    Managing tokens using Keycloak as the identity provider.
    """

    def __init__(
        self,
        oauth2: dict,  # Required for Keycloak
        rest_url: str = "https://127.0.0.1:6060",
        rest_ssl_verify: Union[bool, str] = AppMeshClient._DEFAULT_SSL_CA_CERT_PATH,
        rest_ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = None,
        rest_timeout: Tuple[float, float] = (60, 300),
        jwt_token: Optional[dict] = None,  # Keycloak dict
        auto_refresh_token: bool = True,  # Default to True for Keycloak
    ):
        """Initialize an App Mesh HTTP client with Keycloak support.
        Args:
            oauth2 (Dict[str, str]): Keycloak configuration for oauth2 authentication:
                - auth_server_url: Keycloak server URL (e.g. "https://keycloak.example.com/auth/")
                - realm: Keycloak realm
                - client_id: Keycloak client ID
                - client_secret: Keycloak client secret (optional)
                Using this parameter enables Keycloak integration for authentication. The 'python-keycloak' package
                will be imported on-demand only when this parameter is, make sure package is installed (pip3 install python-keycloak).
        """
        # Initialize base class, disabling its Keycloak and auto-refresh logic
        super().__init__(
            rest_url=rest_url,
            rest_ssl_verify=rest_ssl_verify,
            rest_ssl_client_cert=rest_ssl_client_cert,
            rest_timeout=rest_timeout,
            jwt_token=jwt_token,
            auto_refresh_token=auto_refresh_token,
        )

        # Keycloak integration
        self._keycloak_openid = KeycloakOpenID(
            server_url=oauth2.get("auth_server_url"),
            client_id=oauth2.get("client_id"),
            realm_name=oauth2.get("realm"),
            client_secret_key=oauth2.get("client_secret"),
            verify=self.ssl_verify,
            timeout=rest_timeout,
        )

    # @override, from typing import override avialable from python3.12
    def _get_access_token(self) -> str:
        return self.jwt_token.get("access_token", "") if self.jwt_token else None

    def login(
        self,
        user_name: str,
        user_pwd: str,
        totp_code: Optional[str] = "",
    ) -> dict:
        """Login with user name and password using Keycloak.
        Args:
            user_name (str): the name of the user.
            user_pwd (str): the password of the user.
            totp_code (str, optional): the TOTP code if enabled for the user.
            timeout_seconds (int | str, optional): token expire timeout of seconds. support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P1W').

        Returns:
            dict: Keycloak token.
        """
        # Keycloak authentication
        self.jwt_token = self._keycloak_openid.token(
            username=user_name,
            password=user_pwd,
            totp=totp_code if totp_code else None,
            grant_type="password",  # grant type for token request: "password" / "client_credentials" / "refresh_token"
            scope="openid",  # what information to include in the token, such as "openid profile email"
        )

        return self.jwt_token

    def logoff(self) -> bool:
        """Log out of the current session from Keycloak and clean up."""
        result = False
        if self._keycloak_openid and self.jwt_token:
            try:
                self._keycloak_openid.logout(self.jwt_token.get("refresh_token"))
                result = True
            except Exception as e:
                logging.warning("Failed to logout from Keycloak: %s", str(e))
            finally:
                self.jwt_token = None

        # Call super to handle base class cleanup (timers, session)
        super_result = super().logoff()

        return result and super_result

    def renew_token(self) -> dict:
        """Renew the current Keycloak token."""
        if not self.jwt_token or not isinstance(self.jwt_token, dict) or "refresh_token" not in self.jwt_token:
            raise Exception("No Keycloak refresh token available to renew")

        try:
            # Handle Keycloak token (dictionary format)
            new_token = self._keycloak_openid.refresh_token(self.jwt_token.get("refresh_token"))
            self.jwt_token = new_token
            return self.jwt_token
        except Exception as e:
            logging.error("Keycloak token renewal failed: %s", str(e))
            raise Exception(f"Keycloak token renewal failed: {str(e)}") from e

    def view_self(self) -> dict:
        """Get information about the current user, using Keycloak userinfo if applicable.
        Returns:
            dict: user definition.
        """
        return self._keycloak_openid.userinfo(self._get_access_token())

    def close(self) -> None:
        """Close the session and release resources, including Keycloak logout."""
        # Logout from Keycloak if needed
        if hasattr(self, "_keycloak_openid") and self._keycloak_openid and hasattr(self, "_jwt_token") and self._jwt_token and isinstance(self._jwt_token, dict) and "refresh_token" in self._jwt_token:
            try:
                self._keycloak_openid.logout(self._jwt_token.get("refresh_token"))
            except Exception as e:
                logging.warning("Failed to logout from Keycloak: %s", str(e))
            finally:
                self._keycloak_openid = None
        # Close the base class session and resources (timers, etc.)
        super().close()
