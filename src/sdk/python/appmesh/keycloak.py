# Keycloak authentication client for App Mesh Python SDK

import base64
import json
import time
from typing import Dict, Optional, Tuple, Any
import requests


class KeycloakClient:
    """
    Client for authenticating with Keycloak and obtaining tokens for App Mesh.

    This class handles the OAuth2/OIDC workflow with Keycloak, including:
    - Direct authentication with username/password
    - Token refresh
    - Token validation
    """

    def __init__(
        self,
        auth_server_url: str,
        realm: str,
        client_id: str,
        client_secret: Optional[str] = None,
        ssl_verify: bool = True,
        timeout: Tuple[int, int] = (10, 60),
        token_refresh_threshold: int = 30,
    ):
        """Initialize Keycloak client.

        Args:
            auth_server_url (str): Keycloak server URL (e.g. https://keycloak.example.com/auth)
            realm (str): Keycloak realm name
            client_id (str): Client ID registered in Keycloak
            client_secret (Optional[str], optional): Client secret if using confidential client. Defaults to None.
            ssl_verify (bool, optional): Verify SSL certificates. Defaults to True.
            timeout (Tuple[int, int], optional): Connection and read timeouts. Defaults to (10, 60).
            token_refresh_threshold (int, optional): Seconds before token expiry to trigger refresh. Defaults to 30.
        """
        self.auth_server_url = auth_server_url.rstrip("/")
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.token_refresh_threshold = token_refresh_threshold

        # Token storage
        self.access_token = None
        self.refresh_token = None
        self.token_expires_at = 0

        # Construct the token endpoint URL
        self.token_endpoint = f"{self.auth_server_url}/realms/{self.realm}/protocol/openid-connect/token"
        self.userinfo_endpoint = f"{self.auth_server_url}/realms/{self.realm}/protocol/openid-connect/userinfo"

        # Create a session for connection pooling
        self.session = requests.Session()

    def __enter__(self):
        """Support for context manager protocol."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up resources when exiting context."""
        self.close()

    def __del__(self):
        """Ensure resources are properly released when the object is garbage collected."""
        try:
            self.close()
        except Exception:
            pass  # Avoid exceptions during garbage collection

    def authenticate(self, username: str, password: str) -> str:
        """Authenticate with username and password.

        Args:
            username (str): Username
            password (str): Password

        Returns:
            str: Access token

        Raises:
            Exception: If authentication fails
        """
        data = {
            "client_id": self.client_id,
            "grant_type": "password",
            "username": username,
            "password": password,
        }

        if self.client_secret:
            data["client_secret"] = self.client_secret

        try:
            response = self.session.post(self.token_endpoint, data=data, verify=self.ssl_verify, timeout=self.timeout)

            if response.status_code != 200:
                raise Exception(f"Authentication failed: {response.text}")

            token_data = response.json()
            self._update_token_data(token_data)
            return self.access_token

        except requests.RequestException as e:
            raise Exception(f"Failed to connect to Keycloak: {str(e)}")

    def refresh_tokens(self) -> str:
        """Refresh the access token using the refresh token.

        Returns:
            str: New access token

        Raises:
            Exception: If refresh fails
        """
        if not self.refresh_token:
            raise Exception("No refresh token available")

        data = {
            "client_id": self.client_id,
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
        }

        if self.client_secret:
            data["client_secret"] = self.client_secret

        try:
            response = self.session.post(self.token_endpoint, data=data, verify=self.ssl_verify, timeout=self.timeout)

            if response.status_code != 200:
                raise Exception(f"Token refresh failed: {response.text}")

            token_data = response.json()
            self._update_token_data(token_data)
            return self.access_token

        except requests.RequestException as e:
            raise Exception(f"Failed to connect to Keycloak: {str(e)}")

    def validate_token(self) -> bool:
        """Check if the current token is valid and not expired.

        Returns:
            bool: True if valid, False otherwise
        """
        if not self.access_token:
            return False

        # Check if the token is expired based on our local expiry time
        if time.time() > self.token_expires_at:
            return False

        return True

    def get_active_token(self) -> str:
        """Get a valid access token, refreshing if necessary.

        Returns:
            str: Valid access token

        Raises:
            Exception: If no valid token can be obtained
        """
        if self.validate_token():
            return self.access_token

        if self.refresh_token:
            try:
                return self.refresh_tokens()
            except Exception:
                pass

        raise Exception("No valid token available and unable to refresh")

    def get_user_info(self) -> Dict[str, Any]:
        """Get information about the authenticated user.

        Returns:
            Dict[str, Any]: User information

        Raises:
            Exception: If request fails
        """
        if not self.access_token:
            raise Exception("Not authenticated")

        headers = {"Authorization": f"Bearer {self.access_token}"}

        try:
            response = self.session.get(self.userinfo_endpoint, headers=headers, verify=self.ssl_verify, timeout=self.timeout)

            if response.status_code != 200:
                raise Exception(f"Failed to get user info: {response.text}")

            return response.json()

        except requests.RequestException as e:
            raise Exception(f"Failed to connect to Keycloak: {str(e)}")

    def _update_token_data(self, token_data: Dict[str, Any]) -> None:
        """Update the stored token data.

        Args:
            token_data (Dict[str, Any]): Token data from Keycloak
        """
        self.access_token = token_data["access_token"]
        self.refresh_token = token_data.get("refresh_token")

        # Calculate token expiration time with configurable buffer
        expires_in = token_data.get("expires_in", 300)
        self.token_expires_at = time.time() + expires_in - self.token_refresh_threshold

    def close(self) -> None:
        """Close the session and release resources."""
        if hasattr(self, "session") and self.session:
            self.session.close()
            self.session = None

    @staticmethod
    def decode_token(token: str) -> Dict[str, Any]:
        """Decode a JWT token without verification.

        Args:
            token (str): JWT token

        Returns:
            Dict[str, Any]: Decoded token payload
        """
        parts = token.split(".")
        if len(parts) != 3:
            raise Exception("Invalid token format")

        # Decode the payload (second part)
        payload = parts[1]
        # Add padding if necessary
        payload += "=" * (4 - len(payload) % 4) if len(payload) % 4 else ""

        try:
            decoded = base64.b64decode(payload)
            return json.loads(decoded)
        except Exception as e:
            raise Exception(f"Failed to decode token: {str(e)}")
