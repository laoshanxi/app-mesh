# HTTP-based App Mesh Client
# pylint: disable=broad-exception-raised,line-too-long,broad-exception-caught,too-many-lines, import-outside-toplevel, protected-access
import abc
import base64
import json
import logging
import os
from datetime import datetime
from enum import Enum, unique
from http import HTTPStatus
import threading
from typing import Optional, Tuple, Union
from urllib import parse
import aniso8601
import jwt
import requests
import time
from .app import App
from .app_run import AppRun
from .app_output import AppOutput


class AppMeshClient(metaclass=abc.ABCMeta):
    """
    Client SDK for interacting with the App Mesh service via REST API.

    The `AppMeshClient` class provides a comprehensive interface for managing and monitoring distributed applications
    within the App Mesh ecosystem. It enables communication with the App Mesh REST API for operations such as
    application lifecycle management, monitoring, and configuration.

    This client is designed for direct usage in applications that require access to App Mesh services over HTTP-based REST.

    Usage:
        - Install the App Mesh Python package:
            python3 -m pip install --upgrade appmesh
        - Import the client module:
            from appmesh import appmesh_client

    Example:
        client = appmesh_client.AppMeshClient()
        client.login("your-name", "your-password")
        response = client.app_view(app_name='ping')

    Attributes:
        - TLS (Transport Layer Security): Supports secure connections between the client and App Mesh service,
          ensuring encrypted communication.
        - JWT (JSON Web Token) and RBAC (Role-Based Access Control): Provides secure API access with
          token-based authentication and authorization to enforce fine-grained permissions.

    Methods:
        # Authentication Management
        - login()
        - logoff()
        - authenticate()
        - renew_token()
        - disable_totp()
        - get_totp_secret()
        - setup_totp()

        # Application Management
        - add_app()
        - delete_app()
        - disable_app()
        - enable_app()
        - check_app_health()
        - get_app_output()
        - view_app()
        - view_all_apps()

        # Run Application Operations
        - run_app_async()
        - wait_for_async_run()
        - run_app_sync()

        # System Management
        - forward_to
        - set_config()
        - view_config()
        - set_log_level()
        - view_host_resources()
        - get_metrics()
        - add_tag()
        - delete_tag()
        - view_tags()

        # File Management
        - download_file()
        - upload_file()

        # User and Role Management
        - add_user()
        - delete_user()
        - lock_user()
        - update_user_password()
        - view_self()
        - unlock_user()
        - view_users()
        - view_user_permissions()
        - view_permissions()
        - delete_role()
        - update_role()
        - view_roles()
        - view_groups()
    """

    DURATION_ONE_WEEK_ISO = "P1W"
    DURATION_TWO_DAYS_ISO = "P2D"
    DURATION_TWO_DAYS_HALF_ISO = "P2DT12H"
    TOKEN_REFRESH_INTERVAL = 60

    DEFAULT_SSL_CA_CERT_PATH = "/opt/appmesh/ssl/ca.pem"
    DEFAULT_SSL_CLIENT_CERT_PATH = "/opt/appmesh/ssl/client.pem"
    DEFAULT_SSL_CLIENT_KEY_PATH = "/opt/appmesh/ssl/client-key.pem"

    DEFAULT_JWT_AUDIENCE = "appmesh-service"

    JSON_KEY_MESSAGE = "message"
    HTTP_USER_AGENT = "appmesh/python"
    HTTP_HEADER_KEY_USER_AGENT = "User-Agent"
    HTTP_HEADER_KEY_X_TARGET_HOST = "X-Target-Host"
    HTTP_HEADER_KEY_X_FILE_PATH = "X-File-Path"

    @unique
    class Method(Enum):
        """REST methods"""

        GET = "GET"
        PUT = "PUT"
        POST = "POST"
        DELETE = "DELETE"
        POST_STREAM = "POST_STREAM"

    def __init__(
        self,
        rest_url: str = "https://127.0.0.1:6060",
        rest_ssl_verify=DEFAULT_SSL_CA_CERT_PATH if os.path.exists(DEFAULT_SSL_CA_CERT_PATH) else False,
        rest_ssl_client_cert=(DEFAULT_SSL_CLIENT_CERT_PATH, DEFAULT_SSL_CLIENT_KEY_PATH) if os.path.exists(DEFAULT_SSL_CLIENT_CERT_PATH) else None,
        rest_timeout=(60, 300),
        jwt_token=None,
        oauth2=None,
        auto_refresh_token=False,
    ):
        """Initialize an App Mesh HTTP client for interacting with the App Mesh server via secure HTTPS.

        Args:
            rest_url (str, optional): The server's base URI, including protocol, hostname, and port. Defaults to `"https://127.0.0.1:6060"`.

            rest_ssl_verify (Union[bool, str], optional): Configures SSL certificate verification for HTTPS requests:
                - `True`: Uses system CA certificates to verify the server's identity.
                - `False`: Disables SSL verification (insecure, use cautiously for development).
                - `str`: Path to a custom CA certificate or directory for verification. This option allows custom CA configuration,
                which may be necessary in environments requiring specific CA chains that differ from the default system CAs.
                To use both a custom CA and the system's default CAs, create a combined CA bundle by concatenating them into a single file. (e.g., `cat custom_ca.pem /etc/ssl/certs/ca-certificates.crt > combined_ca.pem`).

            ssl_client_cert (Union[str, Tuple[str, str]], optional): Path to the SSL client certificate and key. Can be:
                - `str`: A path to a single PEM file containing both the client certificate and private key.
                - `tuple`: A pair of paths (`cert_file`, `key_file`), where `cert_file` is the client certificate file path and `key_file` is the private key file path.

            rest_timeout (tuple, optional): HTTP connection timeouts for API requests, as `(connect_timeout, read_timeout)`.
                The default is `(60, 300)`, where `60` seconds is the maximum time to establish a connection and `300` seconds for the maximum read duration.

            jwt_token (str, optional): JWT token for API authentication, used in headers to authorize requests where required.

            oauth2 (Dict[str, Any], optional): Keycloak configuration for oauth2 authentication:
                - server_url: Keycloak server URL (e.g. "https://keycloak.example.com/auth/")
                - realm: Keycloak realm
                - client_id: Keycloak client ID
                - client_secret: Keycloak client secret (optional)
                Using this parameter enables Keycloak integration for authentication. The 'python-keycloak' package
                will be imported on-demand only when this parameter is, make sure package is installed (pip3 install python-keycloak).

            auto_refresh_token (bool, optional): Enable automatic token refresh before expiration.
                When enabled, a background timer will monitor token expiration and attempt to refresh
                the token before it expires. This works with both native App Mesh tokens and Keycloak tokens.
        """
        self._ensure_logging_configured()
        self.session = requests.Session()
        self.auth_server_url = rest_url
        self._jwt_token = jwt_token
        self.ssl_verify = rest_ssl_verify
        self.ssl_client_cert = rest_ssl_client_cert
        self.rest_timeout = rest_timeout
        self._forward_to = None

        # Keycloak integration
        self._keycloak_openid = None
        if oauth2:
            try:
                from keycloak import KeycloakOpenID

                self._keycloak_openid = KeycloakOpenID(
                    server_url=oauth2.get("auth_server_url"),
                    client_id=oauth2.get("client_id"),
                    realm_name=oauth2.get("realm"),
                    client_secret_key=oauth2.get("client_secret"),
                    verify=self.ssl_verify,
                    timeout=rest_timeout,
                )
            except ImportError:
                logging.error("Keycloak package not installed. Install with: pip install python-keycloak")
                raise Exception("Keycloak integration requested but python-keycloak package is not installed")

        # Token auto-refresh
        self._token_refresh_timer = None
        self._auto_refresh_token = auto_refresh_token
        if auto_refresh_token and jwt_token:
            self._schedule_token_refresh()

    @staticmethod
    def _ensure_logging_configured():
        """Ensure logging is configured. If no handlers are configured, add a default console handler."""
        if not logging.root.handlers:
            logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    def _check_and_refresh_token(self):
        """Check and refresh token if needed, then schedule next check.

        This method is triggered by the refresh timer and will:
        1. Check if token needs refresh based on expiration time
        2. Refresh the token if needed
        3. Schedule the next refresh check
        """
        if not self.jwt_token:
            return

        # Check if token needs refresh
        needs_refresh = True
        time_to_expiry = float("inf")

        # Check token expiration directly from JWT
        try:
            decoded_token = jwt.decode(self.jwt_token if isinstance(self.jwt_token, str) else self.jwt_token.get("access_token", ""), options={"verify_signature": False})
            expiry = decoded_token.get("exp", 0)
            current_time = time.time()
            time_to_expiry = expiry - current_time
            # Refresh if token expires within 5 minutes
            needs_refresh = time_to_expiry < 300
        except Exception as e:
            logging.debug("Failed to parse JWT token for expiration check: %s", str(e))

        # Refresh token if needed
        if needs_refresh:
            try:
                self.renew_token()
                logging.info("Token successfully refreshed")
            except Exception as e:
                logging.error("Token refresh failed: %s", str(e))

        # Schedule next check if auto-refresh is still enabled
        if self._auto_refresh_token and self.jwt_token:
            self._schedule_token_refresh(time_to_expiry)

    def _schedule_token_refresh(self, time_to_expiry=None):
        """Schedule next token refresh check.

        Args:
            time_to_expiry (float, optional): Time in seconds until token expiration.
                When provided, helps calculate optimal refresh timing.

        Calculates appropriate check interval:
        - If token expires soon (within 5 minutes), refresh immediately
        - Otherwise schedule refresh for the earlier of:
          1. 5 minutes before expiration
          2. 60 seconds from now
        """
        # Cancel existing timer if any
        if self._token_refresh_timer:
            self._token_refresh_timer.cancel()
            self._token_refresh_timer = None

        try:
            # Default to checking after 60 seconds
            check_interval = self.TOKEN_REFRESH_INTERVAL

            # Calculate more precise check time if expiry is known
            if time_to_expiry is not None:
                if time_to_expiry <= 300:  # Expires within 5 minutes
                    check_interval = 1  # Almost immediate refresh
                else:
                    # Check at earlier of 5 minutes before expiry or regular interval
                    check_interval = min(time_to_expiry - 300, self.TOKEN_REFRESH_INTERVAL)

            # Create timer to execute refresh check
            self._token_refresh_timer = threading.Timer(check_interval, self._check_and_refresh_token)
            self._token_refresh_timer.daemon = True
            self._token_refresh_timer.start()
            logging.debug("Auto-refresh: Next token check scheduled in %.1f seconds", check_interval)
        except Exception as e:
            logging.error("Auto-refresh: Failed to schedule token refresh: %s", str(e))

    def close(self):
        """Close the session and release resources."""
        # Cancel token refresh timer
        if hasattr(self, "_token_refresh_timer") and self._token_refresh_timer:
            self._token_refresh_timer.cancel()
            self._token_refresh_timer = None

        # Close the session
        if hasattr(self, "session") and self.session:
            self.session.close()
            self.session = None

        # Logout from Keycloak if needed
        if hasattr(self, "_keycloak_openid") and self._keycloak_openid and hasattr(self, "_jwt_token") and self._jwt_token and isinstance(self._jwt_token, dict) and "refresh_token" in self._jwt_token:
            try:
                self._keycloak_openid.logout(self._jwt_token.get("refresh_token"))
            except Exception as e:
                logging.warning("Failed to logout from Keycloak: %s", str(e))
            finally:
                self._keycloak_openid = None

    def __enter__(self):
        """Support for context manager protocol."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Support for context manager protocol, ensuring resources are released."""
        self.close()

    def __del__(self):
        """Ensure resources are properly released when the object is garbage collected."""
        try:
            self.close()
        except Exception:
            pass  # Avoid exceptions during garbage collection

    @property
    def jwt_token(self) -> str:
        """Get the current JWT (JSON Web Token) used for authentication.

        This property manages the authentication token used for securing API requests.
        The token is used to authenticate and authorize requests to the service.

        Returns:
            str: The current JWT token string.
                Returns empty string if no token is set.

        Notes:
            - The token typically includes claims for identity and permissions
            - Token format: "header.payload.signature"
            - Tokens are time-sensitive and may expire
        """
        return self._jwt_token

    @jwt_token.setter
    def jwt_token(self, token: str) -> None:
        """Set the JWT token for authentication.

        Configure the JWT token used for authenticating requests. The token should be
        a valid JWT issued by a trusted authority.

        Args:
            token (str): JWT token string in standard JWT format
                (e.g., "eyJhbGci...payload...signature")
                Pass empty string to clear the token.

        Example:
            >>> client.jwt_token = "eyJhbGci..."  # Set new token
            >>> client.jwt_token = ""             # Clear token

        Notes:
            Security best practices:
            - Store tokens securely
            - Never log or expose complete tokens
            - Refresh tokens before expiration
            - Validate token format before setting
        """
        self._jwt_token = token

    @property
    def forward_to(self) -> str:
        """Get the target host address for request forwarding in a cluster setup.

        This property manages the destination host where requests will be forwarded to
        within a cluster configuration. The host can be specified in two formats:
        1. hostname/IP only: will use the current service's port
        2. hostname/IP with port: will use the specified port

        Returns:
            str: The target host address in either format:
                - "hostname" or "IP" (using current service port)
                - "hostname:port" or "IP:port" (using specified port)
                Returns empty string if no forwarding host is set.

        Notes:
            For proper JWT token sharing across the cluster:
            - All nodes must share the same JWT salt configuration
            - All nodes must use identical JWT issuer settings
            - When port is omitted, current service port will be used
        """
        return self._forward_to

    @forward_to.setter
    def forward_to(self, host: str) -> None:
        """Set the target host address for request forwarding.

        Configure the destination host where requests should be forwarded to. This is
        used in cluster setups for request routing and load distribution.

        Args:
            host (str): Target host address in one of two formats:
                1. "hostname" or "IP" - will use current service port
                (e.g., "backend-node" or "192.168.1.100")
                2. "hostname:port" or "IP:port" - will use specified port
                (e.g., "backend-node:6060" or "192.168.1.100:6060")
                Pass empty string to disable forwarding.

        Examples:
            >>> client.forward_to = "backend-node:6060"  # Use specific port
            >>> client.forward_to = "backend-node"       # Use current service port
            >>> client.forward_to = None                 # Disable forwarding
        """

        self._forward_to = host

    ########################################
    # Security
    ########################################
    def login(self, user_name: str, user_pwd: str, totp_code: Optional[str] = "", timeout_seconds: Union[str, int] = DURATION_ONE_WEEK_ISO, audience: Optional[str] = None) -> str:
        """Login with user name and password

        Args:
            user_name (str): the name of the user.
            user_pwd (str): the password of the user.
            totp_code (str, optional): the TOTP code if enabled for the user.
            timeout_seconds (int | str, optional): token expire timeout of seconds. support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P1W').
            audience (str, optional): The audience of the JWT token, should be available by JWT service configuration (default is 'appmesh-service').

        Returns:
            str: JWT token.
        """
        # Keycloak authentication if configured
        if self._keycloak_openid:
            self.jwt_token = self._keycloak_openid.token(
                username=user_name,
                password=user_pwd,
                totp=totp_code if totp_code else None,
                grant_type="password",  # grant type for token request: "password" / "client_credentials" / "refresh_token"
                scope="openid",  # what information to include in the token, such as "openid profile email"
            )

            if self._auto_refresh_token:
                self._schedule_token_refresh()
            return self.jwt_token

        # Standard App Mesh authentication
        self.jwt_token = None
        resp = self._request_http(
            AppMeshClient.Method.POST,
            path="/appmesh/login",
            header={
                "Authorization": "Basic " + base64.b64encode((user_name + ":" + user_pwd).encode()).decode(),
                "X-Expire-Seconds": str(self._parse_duration(timeout_seconds)),
                **({"X-Audience": audience} if audience else {}),
                # **({"X-Totp-Code": totp_code} if totp_code else {}),
            },
        )
        if resp.status_code == HTTPStatus.OK:
            if "access_token" in resp.json():
                self.jwt_token = resp.json()["access_token"]
        elif resp.status_code == HTTPStatus.PRECONDITION_REQUIRED and "totp_challenge" in resp.json():
            challenge = resp.json()["totp_challenge"]
            self.validate_totp(user_name, challenge, totp_code, timeout_seconds)
        else:
            raise Exception(resp.text)

        if self._auto_refresh_token:
            self._schedule_token_refresh()
        return self.jwt_token

    def validate_totp(self, username: str, challenge: str, code: str, timeout: Union[int, str] = DURATION_ONE_WEEK_ISO) -> str:
        """Validate TOTP challenge and obtain a new JWT token.

        Args:
            username (str): Username to validate
            challenge (str): Challenge string from server
            code (str): TOTP code to validate
            timeout (Union[int, str], optional): Token expiry timeout.
                Accepts ISO 8601 duration format (e.g., 'P1Y2M3DT4H5M6S', 'P1W') or seconds.
                Defaults to DURATION_ONE_WEEK_ISO.

        Returns:
            str: New JWT token if validation succeeds

        Raises:
            Exception: If validation fails or server returns error
        """
        resp = self._request_http(
            AppMeshClient.Method.POST,
            path="/appmesh/totp/validate",
            body={
                "user_name": username,
                "totp_code": code,
                "totp_challenge": challenge,
                "expire_seconds": self._parse_duration(timeout),
            },
        )
        if resp.status_code == HTTPStatus.OK and "access_token" in resp.json():
            self.jwt_token = resp.json()["access_token"]
            return self.jwt_token
        raise Exception(resp.text)

    def logoff(self) -> bool:
        """Log out of the current session from the server.

        Returns:
            bool: logoff success or failure.
        """
        result = False
        # Handle Keycloak logout if configured
        if self._keycloak_openid and self.jwt_token and isinstance(self.jwt_token, dict) and "refresh_token" in self.jwt_token:
            refresh_token = self.jwt_token.get("refresh_token")
            self._keycloak_openid.logout(refresh_token)
            self.jwt_token = None
            result = True

        # Standard App Mesh logout
        if self.jwt_token and isinstance(self.jwt_token, str):
            resp = self._request_http(AppMeshClient.Method.POST, path="/appmesh/self/logoff")
            self.jwt_token = None
            result = resp.status_code == HTTPStatus.OK

        # Cancel token refresh timer
        if self._token_refresh_timer:
            self._token_refresh_timer.cancel()
            self._token_refresh_timer = None

        return result

    def authentication(self, token: str, permission: Optional[str] = None, audience: Optional[str] = None) -> bool:
        """Deprecated: Use authenticate() instead."""
        return self.authenticate(token, permission, audience)

    def authenticate(self, token: str, permission: Optional[str] = None, audience: Optional[str] = None) -> bool:
        """Authenticate with a token and verify permission if specified.

        Args:
            token (str): JWT token returned from login().
            permission (str, optional): the permission ID used to verify the token user
                permission ID can be:
                - pre-defined by App Mesh from security.yaml (e.g 'app-view', 'app-delete')
                - defined by input from role_update() or security.yaml
            audience (str, optional):The audience of the JWT token used to verify the target service.

        Returns:
            bool: authentication success or failure.
        """
        old_token = self.jwt_token
        self.jwt_token = token
        headers = {
            **({"X-Audience": audience} if audience else {}),
            **({"X-Permission": permission} if permission else {}),
        }
        resp = self._request_http(AppMeshClient.Method.POST, path="/appmesh/auth", header=headers)
        if resp.status_code != HTTPStatus.OK:
            self.jwt_token = old_token
            raise Exception(resp.text)
        return resp.status_code == HTTPStatus.OK

    def renew_token(self, timeout: Union[int, str] = DURATION_ONE_WEEK_ISO) -> str:
        """Renew the current token.

        Args:
            timeout_seconds (int | str, optional): token expire timeout of seconds. support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P1W').

        Returns:
            str: The new JWT token. The old token will be invalidated.

        Raises:
            Exception: If token renewal fails or no token exists to renew
        """
        # Ensure token exists
        if not self.jwt_token:
            raise Exception("No token to renew")

        try:
            # Handle Keycloak token (dictionary format)
            if self._keycloak_openid and isinstance(self.jwt_token, dict) and "refresh_token" in self.jwt_token:
                new_token = self._keycloak_openid.refresh_token(self.jwt_token.get("refresh_token"))
                self.jwt_token = new_token

            # Handle App Mesh token (string format)
            elif isinstance(self.jwt_token, str):
                resp = self._request_http(
                    AppMeshClient.Method.POST,
                    path="/appmesh/token/renew",
                    header={"X-Expire-Seconds": str(self._parse_duration(timeout))},
                )
                if resp.status_code == HTTPStatus.OK:
                    if "access_token" in resp.json():
                        new_token = resp.json()["access_token"]
                        self.jwt_token = new_token
                    else:
                        raise Exception("Token renewal response missing access_token")
                else:
                    raise Exception(resp.text)
            else:
                raise Exception("Unsupported token format")

            return self.jwt_token

        except Exception as e:
            logging.error("Token renewal failed: %s", str(e))
            raise Exception(f"Token renewal failed: {str(e)}") from e

    def get_totp_secret(self) -> str:
        """Generate TOTP secret for the current user and return MFA URI.

        Returns:
            str: TOTP secret str
        """
        resp = self._request_http(method=AppMeshClient.Method.POST, path="/appmesh/totp/secret")
        if resp.status_code == HTTPStatus.OK:
            totp_uri = base64.b64decode(resp.json()["mfa_uri"]).decode()
            return self._parse_totp_uri(totp_uri).get("secret")
        raise Exception(resp.text)

    def setup_totp(self, totp_code: str) -> str:
        """Set up 2FA for the current user.

        Args:
            totp_code (str): TOTP code

        Returns:
            str: The new JWT token if setup success, the old token will be blocked.
        """
        resp = self._request_http(
            method=AppMeshClient.Method.POST,
            path="/appmesh/totp/setup",
            header={"X-Totp-Code": totp_code},
        )
        if resp.status_code == HTTPStatus.OK:
            if "access_token" in resp.json():
                self.jwt_token = resp.json()["access_token"]
                return self.jwt_token
        else:
            raise Exception(resp.text)

    def disable_totp(self, user: str = "self") -> bool:
        """Disable 2FA for the specified user.

        Args:
            user (str, optional): user name for disable TOTP.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(
            method=AppMeshClient.Method.POST,
            path=f"/appmesh/totp/{user}/disable",
        )
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.status_code == HTTPStatus.OK

    @staticmethod
    def _parse_totp_uri(totp_uri: str) -> dict:
        """Extract TOTP parameters

        Args:
            totp_uri (str): TOTP uri

        Returns:
            dict: eextract parameters
        """
        parsed_info = {}
        parsed_uri = parse.urlparse(totp_uri)

        # Extract label from the path
        parsed_info["label"] = parsed_uri.path[1:]  # Remove the leading slash

        # Extract parameters from the query string
        query_params = parse.parse_qs(parsed_uri.query)
        for key, value in query_params.items():
            parsed_info[key] = value[0]
        return parsed_info

    ########################################
    # Application view
    ########################################
    def view_app(self, app_name: str) -> App:
        """Get information about a specific application.

        Args:
            app_name (str): the application name.

        Returns:
            App: the application object both contain static configuration and runtime information.

        Exception:
            failed request or no such application
        """
        resp = self._request_http(AppMeshClient.Method.GET, path=f"/appmesh/app/{app_name}")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return App(resp.json())

    def view_all_apps(self):
        """Get information about all applications.

        Returns:
            list: the application object both contain static configuration and runtime information, only return applications that the user has permissions.

        Exception:
            failed request or no such application
        """
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/applications")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        apps = []
        for app in resp.json():
            apps.append(App(app))
        return apps

    def get_app_output(self, app_name: str, stdout_position: int = 0, stdout_index: int = 0, stdout_maxsize: int = 10240, process_uuid: str = "", timeout: int = 0) -> AppOutput:
        """Get the stdout/stderr of an application.

        Args:
            app_name (str): the application name
            stdout_position (int, optional): start read position, 0 means start from beginning.
            stdout_index (int, optional): index of history process stdout, 0 means get from current running process,
                the stdout number depends on 'stdout_cache_size' of the application.
            stdout_maxsize (int, optional): max buffer size to read.
            process_uuid (str, optional): used to get the specified process.
            timeout (int, optional): wait for the running process for some time(seconds) to get the output.

        Returns:
            AppOutput object.
        """
        resp = self._request_http(
            AppMeshClient.Method.GET,
            path=f"/appmesh/app/{app_name}/output",
            query={
                "stdout_position": str(stdout_position),
                "stdout_index": str(stdout_index),
                "stdout_maxsize": str(stdout_maxsize),
                "process_uuid": process_uuid,
                "timeout": str(timeout),
            },
        )
        out_position = int(resp.headers["X-Output-Position"]) if "X-Output-Position" in resp.headers else None
        exit_code = int(resp.headers["X-Exit-Code"]) if "X-Exit-Code" in resp.headers else None
        return AppOutput(status_code=resp.status_code, output=resp.text, out_position=out_position, exit_code=exit_code)

    def check_app_health(self, app_name: str) -> bool:
        """Check the health status of an application.

        Args:
            app_name (str): the application name.

        Returns:
            bool: healthy or not
        """
        resp = self._request_http(AppMeshClient.Method.GET, path=f"/appmesh/app/{app_name}/health")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return int(resp.text) == 0

    ########################################
    # Application manage
    ########################################
    def add_app(self, app: App) -> App:
        """Register a new application.

        Args:
            app (App): the application definition.

        Returns:
            App: resigtered application object.

        Exception:
            failed request
        """
        resp = self._request_http(AppMeshClient.Method.PUT, path=f"/appmesh/app/{app.name}", body=app.json())
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return App(resp.json())

    def delete_app(self, app_name: str) -> bool:
        """Remove an application.

        Args:
            app_name (str): the application name.

        Returns:
            bool: True for delete success, Flase for not exist anymore.
        """
        resp = self._request_http(AppMeshClient.Method.DELETE, path=f"/appmesh/app/{app_name}")
        if resp.status_code == HTTPStatus.OK:
            return True
        elif resp.status_code == HTTPStatus.NOT_FOUND:
            return False
        else:
            raise Exception(resp.text)

    def enable_app(self, app_name: str) -> bool:
        """Enable an application.

        Args:
            app_name (str): the application name.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(AppMeshClient.Method.POST, path=f"/appmesh/app/{app_name}/enable")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.status_code == HTTPStatus.OK

    def disable_app(self, app_name: str) -> bool:
        """Disable an application.

        Args:
            app_name (str): the application name.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(AppMeshClient.Method.POST, path=f"/appmesh/app/{app_name}/disable")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.status_code == HTTPStatus.OK

    ########################################
    # Configuration
    ########################################
    def view_host_resources(self) -> dict:
        """Get a report of host resources including CPU, memory, and disk.

        Returns:
            dict: the host resource json.
        """
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/resources")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.json()

    def view_config(self) -> dict:
        """Get the App Mesh configuration in JSON format.

        Returns:
            dict: the configuration json.
        """
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/config")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.json()

    def set_config(self, config_json: dict) -> dict:
        """Update the configuration.

        Args:
            cfg_json (dict): the new configuration json.

        Returns:
            dict: the updated configuration json.
        """
        resp = self._request_http(AppMeshClient.Method.POST, path="/appmesh/config", body=config_json)
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.json()

    def set_log_level(self, level: str = "DEBUG") -> str:
        """Update the log level.

        Args:
            level (str, optional): log level.

        Returns:
            str: the updated log level.
        """
        resp = self._request_http(AppMeshClient.Method.POST, path="/appmesh/config", body={"BaseConfig": {"LogLevel": level}})
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.json()["BaseConfig"]["LogLevel"]

    ########################################
    # User Management
    ########################################
    def update_user_password(self, old_password: str, new_password: str, user_name: str = "self") -> bool:
        """Change the password of a user.

        Args:
            user_name (str): the user name.
            old_password (str): the old password string.
            new_password (str):the new password string.

        Returns:
            bool: success
        """
        resp = self._request_http(
            method=AppMeshClient.Method.POST,
            path=f"/appmesh/user/{user_name}/passwd",
            body={
                "old_password": base64.b64encode(old_password.encode()).decode(),
                "new_password": base64.b64encode(new_password.encode()).decode(),
            },
        )
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return True

    def add_user(self, user_name: str, user_json: dict) -> bool:
        """Add a new user.

        Args:
            user_name (str): the user name.
            user_json (dict): user definition, follow same user format from security.yaml.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(
            method=AppMeshClient.Method.PUT,
            path=f"/appmesh/user/{user_name}",
            body=user_json,
        )
        return resp.status_code == HTTPStatus.OK

    def delete_user(self, user_name: str) -> bool:
        """Delete a user.

        Args:
            user_name (str): the user name.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(
            method=AppMeshClient.Method.DELETE,
            path=f"/appmesh/user/{user_name}",
        )
        return resp.status_code == HTTPStatus.OK

    def lock_user(self, user_name: str) -> bool:
        """Lock a user.

        Args:
            user_name (str): the user name.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(
            method=AppMeshClient.Method.POST,
            path=f"/appmesh/user/{user_name}/lock",
        )
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.status_code == HTTPStatus.OK

    def unlock_user(self, user_name: str) -> bool:
        """Unlock a user.

        Args:
            user_name (str): the user name.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(
            method=AppMeshClient.Method.POST,
            path=f"/appmesh/user/{user_name}/unlock",
        )
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.status_code == HTTPStatus.OK

    def view_users(self) -> dict:
        """Get information about all users.

        Returns:
            dict: all user definition
        """
        resp = self._request_http(method=AppMeshClient.Method.GET, path="/appmesh/users")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.json()

    def view_self(self) -> dict:
        """Get information about the current user.

        Returns:
            dict: user definition.
        """
        if self._keycloak_openid and isinstance(self.jwt_token, dict) and "access_token" in self.jwt_token:
            return self._keycloak_openid.userinfo(self.jwt_token.get("access_token"))

        resp = self._request_http(method=AppMeshClient.Method.GET, path="/appmesh/user/self")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.json()

    def view_groups(self) -> list:
        """Get information about all user groups.

        Returns:
            dict: user group array.
        """
        resp = self._request_http(method=AppMeshClient.Method.GET, path="/appmesh/user/groups")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.json()

    def view_permissions(self) -> list:
        """Get information about all available permissions.

        Returns:
            dict: permission array
        """
        resp = self._request_http(method=AppMeshClient.Method.GET, path="/appmesh/permissions")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.json()

    def view_user_permissions(self) -> list:
        """Get information about the permissions of the current user.

        Returns:
            dict: user permission array.
        """
        resp = self._request_http(method=AppMeshClient.Method.GET, path="/appmesh/user/permissions")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.json()

    def view_roles(self) -> list:
        """Get information about all roles with permission definitions.

        Returns:
            dict: all role definition.
        """
        resp = self._request_http(method=AppMeshClient.Method.GET, path="/appmesh/roles")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.json()

    def update_role(self, role_name: str, role_permission_json: dict) -> bool:
        """Update or add a role with defined permissions.

        Args:
            role_name (str): the role name.
            role_permission_json (dict): role permission definition array, e.g: ["app-control", "app-delete"]

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(method=AppMeshClient.Method.POST, path=f"/appmesh/role/{role_name}", body=role_permission_json)
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.status_code == HTTPStatus.OK

    def delete_role(self, role_name: str) -> bool:
        """Delete a user role.

        Args:
            role_name (str): the role name.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(
            method=AppMeshClient.Method.DELETE,
            path=f"/appmesh/role/{role_name}",
        )
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.status_code == HTTPStatus.OK

    ########################################
    # Tag management
    ########################################
    def add_tag(self, tag_name: str, tag_value: str) -> bool:
        """Add a new label.

        Args:
            tag_name (str): the label name.
            tag_value (str): the label value.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(
            AppMeshClient.Method.PUT,
            query={"value": tag_value},
            path=f"/appmesh/label/{tag_name}",
        )
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.status_code == HTTPStatus.OK

    def delete_tag(self, tag_name: str) -> bool:
        """Delete a label.

        Args:
            tag_name (str): the label name.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(AppMeshClient.Method.DELETE, path=f"/appmesh/label/{tag_name}")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.status_code == HTTPStatus.OK

    def view_tags(self) -> dict:
        """Get information about all labels.

        Returns:
            dict: label data.
        """
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/labels")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.json()

    ########################################
    # Promethus metrics
    ########################################
    def get_metrics(self):
        """Get Prometheus metrics.

        Returns:
            str: prometheus metrics texts
        """
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/metrics")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return resp.text

    ########################################
    # File management
    ########################################
    def download_file(self, remote_file: str, local_file: str, apply_file_attributes: bool = True) -> None:
        """Download a remote file to the local system. Optionally, the local file will have the same permission as the remote file.

        Args:
            remote_file (str): the remote file path.
            local_file (str): the local file path to be downloaded.
            apply_file_attributes (bool): whether to apply file attributes (permissions, owner, group) to the local file.
        """
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/file/download", header={self.HTTP_HEADER_KEY_X_FILE_PATH: remote_file})
        resp.raise_for_status()

        # Write the file content locally
        with open(local_file, "wb") as fp:
            for chunk in resp.iter_content(chunk_size=8 * 1024):  # 8 KB
                if chunk:
                    fp.write(chunk)

        # Apply file attributes (permissions, owner, group) if requested
        if apply_file_attributes:
            if "X-File-Mode" in resp.headers:
                os.chmod(path=local_file, mode=int(resp.headers["X-File-Mode"]))
            if "X-File-User" in resp.headers and "X-File-Group" in resp.headers:
                file_uid = int(resp.headers["X-File-User"])
                file_gid = int(resp.headers["X-File-Group"])
                try:
                    os.chown(path=local_file, uid=file_uid, gid=file_gid)
                except PermissionError:
                    logging.warning(f"Warning: Unable to change owner/group of {local_file}. Operation requires elevated privileges.")

    def upload_file(self, local_file: str, remote_file: str, apply_file_attributes: bool = True) -> None:
        """Upload a local file to the remote server. Optionally, the remote file will have the same permission as the local file.

        Dependency:
            sudo apt install python3-pip
            pip3 install requests_toolbelt

        Args:
            local_file (str): the local file path.
            remote_file (str): the target remote file to be uploaded.
            apply_file_attributes (bool): whether to upload file attributes (permissions, owner, group) along with the file.
        """
        if not os.path.exists(local_file):
            raise FileNotFoundError(f"Local file not found: {local_file}")

        from requests_toolbelt import MultipartEncoder

        with open(file=local_file, mode="rb") as fp:
            encoder = MultipartEncoder(fields={"filename": os.path.basename(remote_file), "file": ("filename", fp, "application/octet-stream")})
            header = {self.HTTP_HEADER_KEY_X_FILE_PATH: parse.quote(remote_file), "Content-Type": encoder.content_type}

            # Include file attributes (permissions, owner, group) if requested
            if apply_file_attributes:
                file_stat = os.stat(local_file)
                header["X-File-Mode"] = str(file_stat.st_mode & 0o777)  # Mask to keep only permission bits
                header["X-File-User"] = str(file_stat.st_uid)
                header["X-File-Group"] = str(file_stat.st_gid)

            # Upload file with or without attributes
            # https://stackoverflow.com/questions/22567306/python-requests-file-upload
            resp = self._request_http(
                AppMeshClient.Method.POST_STREAM,
                path="/appmesh/file/upload",
                header=header,
                body=encoder,
            )
            resp.raise_for_status()

    ########################################
    # Application run
    ########################################
    def _parse_duration(self, timeout) -> int:
        if isinstance(timeout, int):
            return timeout
        elif isinstance(timeout, str):
            return int(aniso8601.parse_duration(timeout).total_seconds())
        else:
            raise TypeError(f"Invalid timeout type: {str(timeout)}")

    def run_app_async(
        self,
        app: Union[App, str],
        max_time_seconds: Union[int, str] = DURATION_TWO_DAYS_ISO,
        life_cycle_seconds: Union[int, str] = DURATION_TWO_DAYS_HALF_ISO,
    ) -> AppRun:
        """Run an application asynchronously on a remote system without blocking the API.

        Args:
            app (Union[App, str]): An `App` instance or a shell command string.
                - If `app` is a string, it is treated as a shell command for the remote run,
                and an `App` instance is created as:
                `App({"command": "<command_string>", "shell": True})`.
                - If `app` is an `App` object, providing only the `name` attribute (without
                a command) will run an existing application; otherwise, it is treated as a new application.
            max_time_seconds (Union[int, str], optional): Maximum runtime for the remote process.
                Accepts ISO 8601 duration format (e.g., 'P1Y2M3DT4H5M6S', 'P5W'). Defaults to `P2D`.
            life_cycle_seconds (Union[int, str], optional): Maximum lifecycle time for the remote process.
                Accepts ISO 8601 duration format. Defaults to `P2DT12H`.

        Returns:
            AppRun: An application run object that can be used to monitor and retrieve the result of the run.
        """
        if isinstance(app, str):
            app = App({"command": app, "shell": True})

        path = "/appmesh/app/run"
        resp = self._request_http(
            AppMeshClient.Method.POST,
            body=app.json(),
            path=path,
            query={
                "timeout": str(self._parse_duration(max_time_seconds)),
                "lifecycle": str(self._parse_duration(life_cycle_seconds)),
            },
        )
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        # Return an AppRun object with the application name and process UUID
        return AppRun(self, resp.json()["name"], resp.json()["process_uuid"])

    def wait_for_async_run(self, run: AppRun, stdout_print: bool = True, timeout: int = 0) -> int:
        """Wait for an asynchronous run to finish.

        Args:
            run (AppRun): asyncrized run result from run_async().
            stdout_print (bool, optional): print remote stdout to local or not.
            timeout (int, optional): wait max timeout seconds and return if not finished, 0 means wait until finished

        Returns:
            int: return exit code if process finished, return None for timeout or exception.
        """
        if run:
            last_output_position = 0
            start = datetime.now()
            interval = 1 if self.__class__.__name__ == "AppMeshClient" else 1000
            while len(run.proc_uid) > 0:
                app_out = self.get_app_output(app_name=run.app_name, stdout_position=last_output_position, stdout_index=0, process_uuid=run.proc_uid, timeout=interval)
                if app_out.output and stdout_print:
                    print(app_out.output, end="", flush=True)
                if app_out.out_position is not None:
                    last_output_position = app_out.out_position
                if app_out.exit_code is not None:
                    # success
                    try:
                        self.delete_app(run.app_name)
                    except Exception:
                        pass
                    return app_out.exit_code
                if app_out.status_code != HTTPStatus.OK:
                    # failed
                    break
                if timeout > 0 and (datetime.now() - start).seconds > timeout:
                    # timeout
                    break
        return None

    def run_app_sync(
        self,
        app: Union[App, str],
        stdout_print: bool = True,
        max_time_seconds: Union[int, str] = DURATION_TWO_DAYS_ISO,
        life_cycle_seconds: Union[int, str] = DURATION_TWO_DAYS_HALF_ISO,
    ) -> Tuple[Union[int, None], str]:
        """Synchronously run an application remotely, blocking until completion, and return the result.

        If 'app' is a string, it is treated as a shell command and converted to an App instance.
        If 'app' is App object, the name attribute is used to run an existing application if specified.

        Args:
            app (Union[App, str]): An App instance or a shell command string.
                If a string, an App instance is created as:
                `appmesh_client.App({"command": "<command_string>", "shell": True})`
            stdout_print (bool, optional): If True, prints the remote stdout locally. Defaults to True.
            max_time_seconds (Union[int, str], optional): Maximum runtime for the remote process.
                Supports ISO 8601 duration format (e.g., 'P1Y2M3DT4H5M6S', 'P5W'). Defaults to DEFAULT_RUN_APP_TIMEOUT_SECONDS.
            life_cycle_seconds (Union[int, str], optional): Maximum lifecycle time for the remote process.
                Supports ISO 8601 duration format. Defaults to DEFAULT_RUN_APP_LIFECYCLE_SECONDS.

        Returns:
            Tuple[Union[int, None], str]: Exit code of the process (None if unavailable) and the stdout text.
        """
        if isinstance(app, str):
            app = App({"command": app, "shell": True})

        path = "/appmesh/app/syncrun"
        resp = self._request_http(
            AppMeshClient.Method.POST,
            body=app.json(),
            path=path,
            query={
                "timeout": str(self._parse_duration(max_time_seconds)),
                "lifecycle": str(self._parse_duration(life_cycle_seconds)),
            },
        )
        exit_code = None
        if resp.status_code == HTTPStatus.OK:
            if stdout_print:
                print(resp.text, end="")
            if "X-Exit-Code" in resp.headers:
                exit_code = int(resp.headers.get("X-Exit-Code"))
        elif stdout_print:
            print(resp.text)

        return exit_code, resp.text

    def _request_http(self, method: Method, path: str, query: dict = None, header: dict = None, body=None) -> requests.Response:
        """Make an HTTP request.

        Args:
            method (Method): AppMeshClient.Method.
            path (str): URI patch str.
            query (dict, optional): HTTP query parameters.
            header (dict, optional): HTTP headers.
            body (_type_, optional): object to send in the body of the :class:`Request`.

        Returns:
            requests.Response: HTTP response
        """
        rest_url = parse.urljoin(self.auth_server_url, path)

        header = {} if header is None else header
        if self.jwt_token:
            token = self.jwt_token["access_token"] if isinstance(self.jwt_token, dict) and "access_token" in self.jwt_token else self.jwt_token
            header["Authorization"] = "Bearer " + token
        if self.forward_to and len(self.forward_to) > 0:
            if ":" in self.forward_to:
                header[self.HTTP_HEADER_KEY_X_TARGET_HOST] = self.forward_to
            else:
                header[self.HTTP_HEADER_KEY_X_TARGET_HOST] = self.forward_to + ":" + str(parse.urlsplit(self.auth_server_url).port)
        header[self.HTTP_HEADER_KEY_USER_AGENT] = self.HTTP_USER_AGENT

        try:
            if method is AppMeshClient.Method.GET:
                return self.session.get(url=rest_url, params=query, headers=header, cert=self.ssl_client_cert, verify=self.ssl_verify, timeout=self.rest_timeout)
            elif method is AppMeshClient.Method.POST:
                return self.session.post(
                    url=rest_url,
                    params=query,
                    headers=header,
                    data=json.dumps(body) if type(body) in (dict, list) else body,
                    cert=self.ssl_client_cert,
                    verify=self.ssl_verify,
                    timeout=self.rest_timeout,
                )
            elif method is AppMeshClient.Method.POST_STREAM:
                return self.session.post(url=rest_url, params=query, headers=header, data=body, cert=self.ssl_client_cert, verify=self.ssl_verify, stream=True, timeout=self.rest_timeout)
            elif method is AppMeshClient.Method.DELETE:
                return self.session.delete(url=rest_url, headers=header, cert=self.ssl_client_cert, verify=self.ssl_verify, timeout=self.rest_timeout)
            elif method is AppMeshClient.Method.PUT:
                return self.session.put(url=rest_url, params=query, headers=header, json=body, cert=self.ssl_client_cert, verify=self.ssl_verify, timeout=self.rest_timeout)
            else:
                raise Exception("Invalid http method", method)
        except requests.exceptions.RequestException as e:
            raise Exception(f"HTTP request failed: {str(e)}")
