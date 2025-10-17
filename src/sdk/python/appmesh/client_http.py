# client_http.py
# pylint: disable=broad-exception-raised,line-too-long,broad-exception-caught,too-many-lines,import-outside-toplevel

"""App Mesh HTTP Client SDK for REST API interactions."""

# Standard library imports
import abc
import base64
import json
import locale
import logging
import os
import sys
import threading
import time
from contextlib import suppress
from datetime import datetime
from enum import Enum, unique
from http import HTTPStatus
from http.cookiejar import CookieJar, MozillaCookieJar
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib import parse

# Third-party imports
import aniso8601
import jwt
import requests
from requests.cookies import RequestsCookieJar

# Local imports
from .app import App
from .app_output import AppOutput
from .app_run import AppRun

logger = logging.getLogger(__name__)


class AppMeshClient(metaclass=abc.ABCMeta):
    """
    Client SDK for interacting with the App Mesh service via REST API.

    The `AppMeshClient` class provides a comprehensive interface for managing and monitoring distributed applications
    within the App Mesh ecosystem. It enables communication with the App Mesh REST API for operations such as
    application lifecycle management, monitoring, and configuration.

    This client is designed for direct usage in applications that require access to App Mesh services over HTTP-based REST.

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
        - run_task()
        - cancel_task()

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
        - update_password()
        - view_self()
        - unlock_user()
        - view_users()
        - view_user_permissions()
        - view_permissions()
        - delete_role()
        - update_role()
        - view_roles()
        - view_groups()

    Example:
        >>> python -m pip install --upgrade appmesh
        >>> from appmesh import AppMeshClient
        >>> client = AppMeshClient()
        >>> client.login("your-name", "your-password")
        >>> response = client.app_view(app_name='ping')
    """

    # Duration constants
    _DURATION_ONE_WEEK_ISO = "P1W"
    _DURATION_TWO_DAYS_ISO = "P2D"
    _DURATION_TWO_DAYS_HALF_ISO = "P2DT12H"
    _TOKEN_REFRESH_INTERVAL = 300  # 5 min to refresh token
    _TOKEN_REFRESH_OFFSET = 30  # 30s before token expire to refresh token

    # Platform-aware default SSL paths
    _DEFAULT_SSL_DIR = Path("c:/local/appmesh/ssl" if os.name == "nt" else "/opt/appmesh/ssl")
    _DEFAULT_SSL_CA_CERT_PATH = str(_DEFAULT_SSL_DIR / "ca.pem")
    _DEFAULT_SSL_CLIENT_CERT_PATH = str(_DEFAULT_SSL_DIR / "client.pem")
    _DEFAULT_SSL_CLIENT_KEY_PATH = str(_DEFAULT_SSL_DIR / "client-key.pem")

    # JWT constants
    _DEFAULT_JWT_AUDIENCE = "appmesh-service"

    # HTTP headers and constants
    _JSON_KEY_MESSAGE = "message"
    _HTTP_USER_AGENT = "appmesh/python"
    _HTTP_HEADER_KEY_AUTH = "Authorization"
    _HTTP_HEADER_KEY_USER_AGENT = "User-Agent"
    _HTTP_HEADER_KEY_X_TARGET_HOST = "X-Target-Host"
    _HTTP_HEADER_KEY_X_FILE_PATH = "X-File-Path"
    _HTTP_HEADER_JWT_SET_COOKIE = "X-Set-Cookie"
    _HTTP_HEADER_NAME_CSRF_TOKEN = "X-CSRF-Token"
    _COOKIE_TOKEN = "appmesh_auth_token"
    _COOKIE_CSRF_TOKEN = "appmesh_csrf_token"

    @unique
    class _Method(Enum):
        """REST methods"""

        GET = "GET"
        PUT = "PUT"
        POST = "POST"
        DELETE = "DELETE"
        POST_STREAM = "POST_STREAM"

    class _EncodingResponse(requests.Response):
        """Response subclass that handles encoding conversion on Windows."""

        def __init__(self, response: requests.Response):
            super().__init__()
            self.__dict__.update(response.__dict__)

            self._converted_text = None
            self._should_convert = False

            # Check if we need to convert encoding on Windows
            if sys.platform == "win32":
                content_type = response.headers.get("Content-Type", "").lower()
                is_ok = response.status_code == HTTPStatus.OK
                is_utf8_text = "text/plain" in content_type and "utf-8" in content_type

                if is_ok and is_utf8_text:
                    try:
                        local_encoding = locale.getpreferredencoding()
                        if local_encoding.lower() not in {"utf-8", "utf8"}:
                            # Ensure response is decoded as UTF-8 first
                            self.encoding = "utf-8"
                            utf8_text = self.text  # This gives us proper Unicode string

                            with suppress(UnicodeEncodeError, LookupError):
                                # Convert Unicode to local encoding, then back to Unicode
                                local_bytes = utf8_text.encode(local_encoding, errors="replace")
                                self._converted_text = local_bytes.decode(local_encoding)
                                self._should_convert = True

                    except (UnicodeError, LookupError):
                        self.encoding = "utf-8"

        @property
        def text(self):
            """Return converted text if needed, otherwise original text."""
            if self._should_convert and self._converted_text is not None:
                return self._converted_text
            return super().text

    def __init__(
        self,
        rest_url: str = "https://127.0.0.1:6060",
        rest_ssl_verify: Union[bool, str] = _DEFAULT_SSL_CA_CERT_PATH,
        rest_ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = (_DEFAULT_SSL_CLIENT_CERT_PATH, _DEFAULT_SSL_CLIENT_KEY_PATH),
        rest_timeout: Tuple[float, float] = (60, 300),
        jwt_token: Optional[str] = None,
        rest_cookie_file: Optional[str] = None,
        auto_refresh_token: bool = False,
    ):
        """Initialize an App Mesh HTTP client for interacting with the App Mesh server via secure HTTPS.

        Args:
            rest_url: The server's base URI. Defaults to "https://127.0.0.1:6060".
            rest_ssl_verify: SSL server verification mode:
              - True: Use system CAs.
              - False: Disable verification (insecure).
              - str: Path to custom CA or directory. To include system CAs, combine them into one file (e.g., cat custom_ca.pem /etc/ssl/certs/ca-certificates.crt > combined_ca.pem).
            rest_ssl_client_cert: SSL client certificate file(s):
              - str: Single PEM file with cert+key
              - tuple: (cert_path, key_path)
            rest_timeout: Timeouts `(connect_timeout, read_timeout)` in seconds.  Default `(60, 300)`.
            jwt_token: (Deprecate) JWT token for API authentication, overrides cookie file if both provided.
            rest_cookie_file: Cookie file path for HTTP clients (set this to enable persistent cookie storage).
            auto_refresh_token: Enable automatic token refresh before expiration (supports App Mesh and Keycloak tokens).
        """
        self._ensure_logging_configured()
        self.auth_server_url = rest_url
        self.ssl_verify = rest_ssl_verify
        self.ssl_client_cert = rest_ssl_client_cert
        self.rest_timeout = rest_timeout
        self._forward_to = None

        # Token auto-refresh
        self._token_refresh_timer = None
        self._auto_refresh_token = auto_refresh_token

        # Session and cookie management
        self._lock = threading.Lock()
        self.session = requests.Session()
        self.cookie_file = rest_cookie_file
        if self._load_cookies(rest_cookie_file):
            self._handle_token_update(self._get_access_token())

        if jwt_token:
            self.authenticate(jwt_token)

    @staticmethod
    def _ensure_logging_configured() -> None:
        """Ensure logging is configured with a default console handler if needed."""
        if not logging.root.handlers:
            logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    # @abc.abstractmethod
    def _get_access_token(self) -> Optional[str]:
        """Get the current access token."""
        return self._get_cookie_value(self.session.cookies, self._COOKIE_TOKEN)

    def _load_cookies(self, cookie_file: Optional[str]) -> bool:
        """ "Load cookies from a Mozilla-format file into the session"""
        if not cookie_file:
            return False

        cookie_path = Path(cookie_file)
        self.session.cookies = MozillaCookieJar(cookie_file)

        if cookie_path.exists():
            self.session.cookies.load(ignore_discard=True, ignore_expires=True)
            return True
        else:
            cookie_path.parent.mkdir(parents=True, exist_ok=True)
            self.session.cookies.save(ignore_discard=True, ignore_expires=True)
            if os.name == "posix":
                cookie_path.chmod(0o600)  # User read/write only

        return False

    @staticmethod
    def _get_cookie_value(cookies: Union[RequestsCookieJar, CookieJar], name: str, check_expiry: bool = True) -> Optional[str]:
        """Get cookie value by name, checking expiry if requested."""
        if not cookies or not name:
            return None

        # Fast path for RequestsCookieJar (default in requests.Session)
        if isinstance(cookies, RequestsCookieJar):
            cookie = cookies.get(name)
            if not cookie:
                return None

            # Some requests versions return a string directly, others a Cookie object
            if hasattr(cookie, "expires"):
                if check_expiry and cookie.expires and cookie.expires < time.time():
                    return None  # expired
                return getattr(cookie, "value", None)

            # Otherwise, assume the cookie is a plain value
            return str(cookie)

        # Generic CookieJar or derived types (MozillaCookieJar)
        for cookie in cookies:
            if cookie.name == name:
                if check_expiry and cookie.expires and cookie.expires < time.time():
                    return None  # expired
                return cookie.value

        return None

    def _check_and_refresh_token(self) -> None:
        """Check and refresh token if needed, then schedule next check."""
        jwt_token = self._get_access_token()
        if not jwt_token:
            return

        needs_refresh = True
        time_to_expiry = float("inf")

        # Check token expiration directly from JWT
        with suppress(Exception):
            decoded_token = jwt.decode(jwt_token, options={"verify_signature": False})
            expiry = decoded_token.get("exp", 0)
            current_time = time.time()
            time_to_expiry = expiry - current_time
            needs_refresh = time_to_expiry < self._TOKEN_REFRESH_OFFSET

        # Refresh token if needed
        if needs_refresh:
            try:
                self.renew_token()
                logger.info("Token successfully refreshed")
            except Exception as e:
                logger.error("Token refresh failed: %s", e)

        # Schedule next check if auto-refresh is still enabled
        if self._auto_refresh_token and jwt_token:
            self._schedule_token_refresh(time_to_expiry)

    def _schedule_token_refresh(self, time_to_expiry: Optional[float] = None) -> None:
        """Schedule next token refresh check."""
        # Cancel existing timer if any
        if self._token_refresh_timer:
            self._token_refresh_timer.cancel()
            self._token_refresh_timer = None

        try:
            # Default to checking after 60 seconds
            check_interval = self._TOKEN_REFRESH_INTERVAL

            # Calculate more precise check time if expiry is known
            if time_to_expiry is not None:
                if time_to_expiry <= self._TOKEN_REFRESH_OFFSET:  # Expires within 5 minutes
                    check_interval = 1  # Almost immediate refresh
                else:
                    # Check at earlier of 5 minutes before expiry or regular interval
                    check_interval = max(1, min(time_to_expiry - self._TOKEN_REFRESH_OFFSET, self._TOKEN_REFRESH_INTERVAL))

            # Create timer to execute refresh check
            self._token_refresh_timer = threading.Timer(check_interval, self._check_and_refresh_token)
            self._token_refresh_timer.daemon = True
            self._token_refresh_timer.start()
            logger.debug("Auto-refresh: Next token check scheduled in %.1f seconds", check_interval)
        except Exception as e:
            logger.error("Auto-refresh: Failed to schedule token refresh: %s", e)

    # @abc.abstractmethod
    def close(self) -> None:
        """Close the session and release resources."""
        # Cancel token refresh timer
        if self._token_refresh_timer:
            self._token_refresh_timer.cancel()
            self._token_refresh_timer = None

        # Close the session
        if self.session:
            self.session.close()
            self.session = None

        # Clean token
        self._jwt_token = None

    def __enter__(self):
        """Support for context manager protocol."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Support for context manager protocol, ensuring resources are released."""
        self.close()

    def _handle_token_update(self, token: Optional[str]) -> None:
        """Handle post action when token updated"""
        # Handle refresh
        if token and self._auto_refresh_token:
            self._schedule_token_refresh()
        elif self._token_refresh_timer:
            self._token_refresh_timer.cancel()
            self._token_refresh_timer = None

        # Handle session persistence
        if self.cookie_file:
            with self._lock:
                self.session.cookies.save(ignore_discard=True, ignore_expires=True)

    @property
    def forward_to(self) -> str:
        """Target host for request forwarding in a cluster.

        Supports:
        - "hostname" or "IP" → uses current service port
        - "hostname:port" or "IP:port" → uses specified port

        Returns:
            str: Target host (e.g., "node" or "node:6060"), or empty string if unset.

        Notes:
            For JWT sharing across the cluster:
            - All nodes must use the same `JWTSalt` and `Issuer` for JWT settings
            - If port is omitted, current service port is used
        """
        return self._forward_to or ""

    @forward_to.setter
    def forward_to(self, host: str) -> None:
        """Set target host for forwarding.

        Examples:
            >>> client.forward_to = "backend-node:6060"  # Use specific port
            >>> client.forward_to = "backend-node"       # Use current service port
            >>> client.forward_to = None                 # Disable forwarding
        """
        self._forward_to = host

    ########################################
    # Security
    ########################################
    def login(
        self,
        user_name: str,
        user_pwd: str,
        totp_code: Optional[str] = None,
        timeout_seconds: Union[str, int] = _DURATION_ONE_WEEK_ISO,
        audience: Optional[str] = None,
    ) -> Optional[str]:
        """Login with user name and password.

        Args:
            user_name: The name of the user.
            user_pwd: The password of the user.
            totp_code: The TOTP code if enabled for the user.
            timeout_seconds: Token expire timeout. Supports ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P1W').
            audience: The audience of the JWT token, should be available by JWT service configuration (default is 'appmesh-service').

        Returns:
            TOTP challenge string if verification is required, otherwise None.
        """
        # Standard App Mesh authentication
        self.session.cookies.clear()

        credentials = f"{user_name}:{user_pwd}".encode()
        headers = {
            self._HTTP_HEADER_KEY_AUTH: f"Basic {base64.b64encode(credentials).decode()}",
            self._HTTP_HEADER_JWT_SET_COOKIE: "true",  # Enable cookie token mode
            "X-Expire-Seconds": str(self._parse_duration(timeout_seconds)),
        }
        if audience:
            headers["X-Audience"] = audience
        if totp_code:
            headers["X-Totp-Code"] = totp_code

        resp = self._request_http(
            AppMeshClient._Method.POST,
            path="/appmesh/login",
            header=headers,
        )

        if resp.status_code == HTTPStatus.OK:
            self._handle_token_update(resp.json()["access_token"])
        elif resp.status_code == HTTPStatus.PRECONDITION_REQUIRED:
            # TOTP required
            if "totp_challenge" in resp.json():
                challenge = resp.json()["totp_challenge"]
                if not totp_code:
                    return challenge
                self.validate_totp(user_name, challenge, totp_code, timeout_seconds)
        else:
            raise Exception(resp.text)

    def validate_totp(self, username: str, challenge: str, code: str, timeout: Union[int, str] = _DURATION_ONE_WEEK_ISO) -> None:
        """Validate TOTP challenge and obtain a new JWT token.

        Args:
            username: Username to validate.
            challenge: Challenge string from server.
            code: TOTP code to validate.
            timeout: Token expiration duration, defaults to `_DURATION_ONE_WEEK_ISO` (1 week).
                Accepts either:
                  - **ISO 8601 duration string** (e.g., `'P1Y2M3DT4H5M6S'`, `'P1W'`)
                  - **Numeric value (seconds)** for simpler cases.
        """
        body = {
            "user_name": username,
            "totp_code": code,
            "totp_challenge": challenge,
            "expire_seconds": self._parse_duration(timeout),
        }

        headers = {self._HTTP_HEADER_JWT_SET_COOKIE: "true"}

        resp = self._request_http(
            AppMeshClient._Method.POST,
            path="/appmesh/totp/validate",
            body=body,
            header=headers,
        )

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        self._handle_token_update(resp.json()["access_token"])

    def logoff(self) -> bool:
        """Log out of the current session from the server."""
        jwt_token = self._get_access_token()
        if not jwt_token or not isinstance(jwt_token, str):
            return False

        resp = self._request_http(AppMeshClient._Method.POST, path="/appmesh/self/logoff")

        if resp.status_code != HTTPStatus.OK:
            logger.warning("Failed to logout from Keycloak: %s", resp.text)
            return False

        self._handle_token_update("")
        return True

    def authentication(self, token: str, permission: Optional[str] = None, audience: Optional[str] = None, apply: bool = True) -> Tuple[bool, str]:
        """Deprecated: Use authenticate() instead."""
        return self.authenticate(token, permission, audience, apply)

    def authenticate(self, token: str, permission: Optional[str] = None, audience: Optional[str] = None, apply: bool = True) -> Tuple[bool, str]:
        """Authenticate a JWT token and optionally apply it to the current session.

        Args:
            token: JWT token returned from `login()`.
            permission: Optional permission ID to verify for the token's user.
                Can be one of:
                - Predefined by App Mesh in security.yaml (e.g., 'app-view', 'app-delete')
                - Defined via `role_update()` or security.yaml.
            audience: Optional audience value to verify against the JWT token.
            apply: If True, update the current session with the token upon success.

        Returns:
            Tuple of (success: bool, message: str), where:
            - success: True if authentication succeeds (HTTP 200 OK).
            - message: Response message from the server (e.g., error details).
        """
        # Header auth token takes priority over cookie token
        headers = {self._HTTP_HEADER_KEY_AUTH: f"Bearer {token}"}

        if audience:
            headers["X-Audience"] = audience
        if permission:
            headers["X-Permission"] = permission
        if apply:
            headers[self._HTTP_HEADER_JWT_SET_COOKIE] = "true"

        resp = self._request_http(AppMeshClient._Method.POST, path="/appmesh/auth", header=headers)

        if resp.status_code == HTTPStatus.OK:
            if apply:
                self._handle_token_update(self._get_access_token())

        return resp.status_code == HTTPStatus.OK, resp.text

    def renew_token(self, timeout: Union[int, str] = _DURATION_ONE_WEEK_ISO) -> None:
        """Renew the current token.

        Args:
            timeout: Token expire timeout.
        """
        jwt_token = self._get_access_token()
        if not jwt_token:
            raise Exception("No token to renew")

        if not isinstance(jwt_token, str):
            raise Exception("Unsupported token format")

        resp = self._request_http(
            AppMeshClient._Method.POST,
            path="/appmesh/token/renew",
            header={"X-Expire-Seconds": str(self._parse_duration(timeout))},
        )

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        self._handle_token_update(resp.json()["access_token"])

    def get_totp_secret(self) -> str:
        """Generate TOTP secret for the current user."""
        resp = self._request_http(method=AppMeshClient._Method.POST, path="/appmesh/totp/secret")

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        totp_uri = base64.b64decode(resp.json()["mfa_uri"]).decode()
        parsed_uri = self._parse_totp_uri(totp_uri)
        secret = parsed_uri.get("secret")
        if secret is None:
            raise Exception("TOTP URI does not contain a 'secret' field")
        return secret

    def setup_totp(self, totp_code: str) -> None:
        """Set up 2FA for the current user.

        Args:
            totp_code: TOTP code.
        """
        resp = self._request_http(
            method=AppMeshClient._Method.POST,
            path="/appmesh/totp/setup",
            header={"X-Totp-Code": totp_code},
        )

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        self._handle_token_update(resp.json()["access_token"])

    def disable_totp(self, user: str = "self") -> None:
        """Disable 2FA for the specified user."""
        resp = self._request_http(
            method=AppMeshClient._Method.POST,
            path=f"/appmesh/totp/{user}/disable",
        )

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

    @staticmethod
    def _parse_totp_uri(totp_uri: str) -> dict:
        """Extract TOTP parameters from URI."""
        parsed_info = {}
        parsed_uri = parse.urlparse(totp_uri)

        # Extract label from the path
        parsed_info["label"] = parsed_uri.path[1:]  # Remove leading slash

        # Extract parameters from the query string
        query_params = parse.parse_qs(parsed_uri.query)
        for key, value in query_params.items():
            parsed_info[key] = value[0]

        return parsed_info

    ########################################
    # Application view
    ########################################
    def view_app(self, app_name: str) -> App:
        """Get information about a specific application."""
        resp = self._request_http(AppMeshClient._Method.GET, path=f"/appmesh/app/{app_name}")

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        return App(resp.json())

    def view_all_apps(self) -> List[App]:
        """Get information about all applications."""
        resp = self._request_http(AppMeshClient._Method.GET, path="/appmesh/applications")

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        return [App(app) for app in resp.json()]

    def get_app_output(self, app_name: str, stdout_position: int = 0, stdout_index: int = 0, stdout_maxsize: int = 10240, process_uuid: str = "", timeout: int = 0) -> AppOutput:
        """Get the stdout/stderr of an application.

        Args:
            app_name: the application name
            stdout_position: start read position, 0 means start from beginning.
            stdout_index: index of history process stdout, 0 means get from current running process,
                the stdout number depends on 'stdout_cache_size' of the application.
            stdout_maxsize: max buffer size to read.
            process_uuid: used to get the specified process.
            timeout: wait for the running process for some time(seconds) to get the output.

        Returns:
            AppOutput object.
        """
        resp = self._request_http(
            AppMeshClient._Method.GET,
            path=f"/appmesh/app/{app_name}/output",
            query={
                **({"stdout_position": str(stdout_position)} if stdout_position != 0 else {}),
                **({"stdout_index": str(stdout_index)} if stdout_index != 0 else {}),
                **({"stdout_maxsize": str(stdout_maxsize)} if stdout_maxsize != 0 else {}),
                **({"process_uuid": process_uuid} if process_uuid != "" else {}),
                **({"timeout": str(timeout)} if timeout != 0 else {}),
            },
        )

        out_position = int(resp.headers["X-Output-Position"]) if "X-Output-Position" in resp.headers else None
        exit_code = int(resp.headers["X-Exit-Code"]) if "X-Exit-Code" in resp.headers else None

        return AppOutput(status_code=resp.status_code, output=resp.text, out_position=out_position, exit_code=exit_code)

    def check_app_health(self, app_name: str) -> bool:
        """Check the health status of an application."""
        resp = self._request_http(AppMeshClient._Method.GET, path=f"/appmesh/app/{app_name}/health")

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        return int(resp.text) == 0

    ########################################
    # Application manage
    ########################################
    def add_app(self, app: App) -> App:
        """Register a new application."""
        resp = self._request_http(AppMeshClient._Method.PUT, path=f"/appmesh/app/{app.name}", body=app.json())

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        return App(resp.json())

    def delete_app(self, app_name: str) -> bool:
        """Remove an application."""
        resp = self._request_http(AppMeshClient._Method.DELETE, path=f"/appmesh/app/{app_name}")

        if resp.status_code == HTTPStatus.OK:
            return True
        if resp.status_code == HTTPStatus.NOT_FOUND:
            return False

        raise Exception(resp.text)

    def enable_app(self, app_name: str) -> None:
        """Enable an application."""
        resp = self._request_http(AppMeshClient._Method.POST, path=f"/appmesh/app/{app_name}/enable")

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

    def disable_app(self, app_name: str) -> None:
        """Disable an application."""
        resp = self._request_http(AppMeshClient._Method.POST, path=f"/appmesh/app/{app_name}/disable")

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

    ########################################
    # Configuration
    ########################################
    def view_host_resources(self) -> Dict[str, Any]:
        """Get a report of host resources including CPU, memory, and disk."""
        resp = self._request_http(AppMeshClient._Method.GET, path="/appmesh/resources")

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        return resp.json()

    def view_config(self) -> Dict[str, Any]:
        """Get the App Mesh configuration in JSON format."""
        resp = self._request_http(AppMeshClient._Method.GET, path="/appmesh/config")

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        return resp.json()

    def set_config(self, config_json: dict) -> Dict[str, Any]:
        """Update the configuration."""
        resp = self._request_http(AppMeshClient._Method.POST, path="/appmesh/config", body=config_json)

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        return resp.json()

    def set_log_level(self, level: str = "DEBUG") -> str:
        """Update the log level."""
        config_dict = self.set_config(config_json={"BaseConfig": {"LogLevel": level}})

        return config_dict["BaseConfig"]["LogLevel"]

    ########################################
    # User Management
    ########################################
    def update_password(self, old_password: str, new_password: str, user_name: str = "self") -> None:
        """Change the password of a user."""
        body = {
            "old_password": base64.b64encode(old_password.encode()).decode(),
            "new_password": base64.b64encode(new_password.encode()).decode(),
        }

        resp = self._request_http(
            method=AppMeshClient._Method.POST,
            path=f"/appmesh/user/{user_name}/passwd",
            body=body,
        )

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

    def add_user(self, user_name: str, user_json: dict) -> None:
        """Add a new user."""
        resp = self._request_http(
            method=AppMeshClient._Method.PUT,
            path=f"/appmesh/user/{user_name}",
            body=user_json,
        )
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

    def delete_user(self, user_name: str) -> None:
        """Delete a user."""
        resp = self._request_http(
            method=AppMeshClient._Method.DELETE,
            path=f"/appmesh/user/{user_name}",
        )
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

    def lock_user(self, user_name: str) -> None:
        """Lock a user."""
        resp = self._request_http(
            method=AppMeshClient._Method.POST,
            path=f"/appmesh/user/{user_name}/lock",
        )

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

    def unlock_user(self, user_name: str) -> None:
        """Unlock a user."""
        resp = self._request_http(
            method=AppMeshClient._Method.POST,
            path=f"/appmesh/user/{user_name}/unlock",
        )

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

    def view_users(self) -> Dict[str, Any]:
        """Get information about all users."""
        resp = self._request_http(method=AppMeshClient._Method.GET, path="/appmesh/users")

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        return resp.json()

    def view_self(self) -> dict:
        """Get information about the current user."""
        resp = self._request_http(method=AppMeshClient._Method.GET, path="/appmesh/user/self")

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        return resp.json()

    def view_groups(self) -> List[str]:
        """Get information about all user groups."""
        resp = self._request_http(method=AppMeshClient._Method.GET, path="/appmesh/user/groups")

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        return resp.json()

    def view_permissions(self) -> List[str]:
        """Get information about all available permissions."""
        resp = self._request_http(method=AppMeshClient._Method.GET, path="/appmesh/permissions")

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        return resp.json()

    def view_user_permissions(self) -> List[str]:
        """Get information about the permissions of the current user."""
        resp = self._request_http(method=AppMeshClient._Method.GET, path="/appmesh/user/permissions")

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        return resp.json()

    def view_roles(self) -> Dict[str, Dict]:
        """Get information about all roles with permission definitions."""
        resp = self._request_http(method=AppMeshClient._Method.GET, path="/appmesh/roles")

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        return resp.json()

    def update_role(self, role_name: str, permission_set: list) -> None:
        """Update or add a role with defined permissions."""
        resp = self._request_http(method=AppMeshClient._Method.POST, path=f"/appmesh/role/{role_name}", body=permission_set)

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

    def delete_role(self, role_name: str) -> None:
        """Delete a user role."""
        resp = self._request_http(
            method=AppMeshClient._Method.DELETE,
            path=f"/appmesh/role/{role_name}",
        )

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

    ########################################
    # Tag management
    ########################################
    def add_tag(self, tag_name: str, tag_value: str) -> None:
        """Add a new label."""
        resp = self._request_http(
            AppMeshClient._Method.PUT,
            query={"value": tag_value},
            path=f"/appmesh/label/{tag_name}",
        )

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

    def delete_tag(self, tag_name: str) -> None:
        """Delete a label."""
        resp = self._request_http(AppMeshClient._Method.DELETE, path=f"/appmesh/label/{tag_name}")

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

    def view_tags(self) -> Dict[str, str]:
        """Get information about all labels."""
        resp = self._request_http(AppMeshClient._Method.GET, path="/appmesh/labels")

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        return resp.json()

    ########################################
    # Prometheus metrics
    ########################################
    def get_metrics(self) -> str:
        """Get Prometheus metrics."""
        resp = self._request_http(AppMeshClient._Method.GET, path="/appmesh/metrics")

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        return resp.text

    ########################################
    # File management
    ########################################
    @staticmethod
    def _apply_file_attributes(local_path: Path, headers: dict) -> None:
        """Apply file attributes from headers to local file."""
        if sys.platform == "win32":
            return

        if "X-File-Mode" in headers:
            file_mode = int(headers["X-File-Mode"])
            with suppress(OSError):
                local_path.chmod(file_mode)

        if "X-File-User" in headers and "X-File-Group" in headers:
            file_uid = int(headers["X-File-User"])
            file_gid = int(headers["X-File-Group"])
            with suppress(OSError):
                os.chown(path=local_path, uid=file_uid, gid=file_gid)

    @staticmethod
    def _get_file_attributes(local_path: Path) -> dict:
        """Get file attributes as header dictionary."""
        if sys.platform == "win32":
            return {}

        with suppress(OSError):
            st = local_path.stat()
            return {
                "X-File-Mode": str(st.st_mode & 0o777),  # Mask to keep only permission bits
                "X-File-User": str(st.st_uid),
                "X-File-Group": str(st.st_gid),
            }

        return {}

    def download_file(self, remote_file: str, local_file: str, preserve_permissions: bool = True) -> None:
        """Download a remote file to the local system."""
        resp = self._request_http(AppMeshClient._Method.GET, path="/appmesh/file/download", header={self._HTTP_HEADER_KEY_X_FILE_PATH: remote_file})
        resp.raise_for_status()

        # Write the file content locally
        local_path = Path(local_file)
        with local_path.open("wb") as fp:
            for chunk in resp.iter_content(chunk_size=8 * 1024):
                if chunk:
                    fp.write(chunk)

        if preserve_permissions:
            self._apply_file_attributes(local_path, resp.headers)

    def upload_file(self, local_file: str, remote_file: str, preserve_permissions: bool = True) -> None:
        """Upload a local file to the remote server."""
        local_path = Path(local_file)
        if not local_path.exists():
            raise FileNotFoundError(f"Local file not found: {local_file}")

        from requests_toolbelt import MultipartEncoder

        with local_path.open("rb") as fp:
            encoder = MultipartEncoder(fields={"filename": os.path.basename(remote_file), "file": ("filename", fp, "application/octet-stream")})

            header = {self._HTTP_HEADER_KEY_X_FILE_PATH: parse.quote(remote_file), "Content-Type": encoder.content_type}

            if preserve_permissions:
                header.update(self._get_file_attributes(local_path))

            # Upload file with or without attributes
            # https://stackoverflow.com/questions/22567306/python-requests-file-upload
            resp = self._request_http(
                AppMeshClient._Method.POST_STREAM,
                path="/appmesh/file/upload",
                header=header,
                body=encoder,
            )
            resp.raise_for_status()

    ########################################
    # Application run
    ########################################
    @staticmethod
    def _parse_duration(timeout: Union[int, str]) -> int:
        """Parse duration from int or ISO 8601 string."""
        if isinstance(timeout, int):
            return timeout
        if isinstance(timeout, str):
            return int(aniso8601.parse_duration(timeout).total_seconds())
        raise TypeError(f"Invalid timeout type: {timeout}")

    def run_task(self, app_name: str, data: str, timeout: int = 300) -> str:
        """Client send an invocation message to a running App Mesh application and wait for result.

        This method posts the provided `data` to the App Mesh service which will
        forward it to the specified running application instance.

        Args:
            app_name: Name of the target application (as registered in App Mesh).
            data: Payload to deliver to the application. Typically a string.
            timeout: Maximum time in seconds to wait for a response from the application. Defaults to 60 seconds.

        Returns:
            str: The HTTP response body returned by the remote application/service.
        """
        resp = self._request_http(
            AppMeshClient._Method.POST,
            path=f"/appmesh/app/{app_name}/task",
            body=data,
            query={"timeout": str(timeout)},
        )

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        return resp.text

    def cancel_task(self, app_name: str) -> bool:
        """Client cancle a running task to a App Mesh application.

        Args:
            app_name: Name of the target application (as registered in App Mesh).

        Returns:
            bool: Task exist and cancled status.
        """
        resp = self._request_http(
            AppMeshClient._Method.DELETE,
            path=f"/appmesh/app/{app_name}/task",
        )
        return resp.status_code == HTTPStatus.OK

    def run_app_async(
        self,
        app: Union[App, str],
        max_time_seconds: Union[int, str] = _DURATION_TWO_DAYS_ISO,
        life_cycle_seconds: Union[int, str] = _DURATION_TWO_DAYS_HALF_ISO,
    ) -> AppRun:
        """Run an application asynchronously on a remote system without blocking the API.

        Args:
            app: An `App` instance or a shell command string.
                - If `app` is a string, it is treated as a shell command for the remote run,
                and an `App` instance is created as:
                `App({"command": "<command_string>", "shell": True})`.
                - If `app` is an `App` object, providing only the `name` attribute (without
                a command) will run an existing application; otherwise, it is treated as a new application.
            max_time_seconds: Maximum runtime for the remote process.
                Accepts ISO 8601 duration format (e.g., 'P1Y2M3DT4H5M6S', 'P5W'). Defaults to `P2D`.
            life_cycle_seconds: Maximum lifecycle time for the remote process.
                Accepts ISO 8601 duration format. Defaults to `P2DT12H`.

        Returns:
            AppRun: An application run object that can be used to monitor and retrieve the result of the run.
        """
        if isinstance(app, str):
            app = App({"command": app, "shell": True})

        resp = self._request_http(
            AppMeshClient._Method.POST,
            body=app.json(),
            path="/appmesh/app/run",
            query={
                "timeout": str(self._parse_duration(max_time_seconds)),
                "lifecycle": str(self._parse_duration(life_cycle_seconds)),
            },
        )

        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)

        response_data = resp.json()
        return AppRun(self, response_data["name"], response_data["process_uuid"])

    def wait_for_async_run(self, run: AppRun, stdout_print: bool = True, timeout: int = 0) -> Optional[int]:
        """Wait for an asynchronous run to finish.

        Args:
            run: asyncrized run result from run_async().
            stdout_print: print remote stdout to local or not.
            timeout : wait max timeout seconds and return if not finished, 0 means wait until finished

        Returns:
            return exit code if process finished, return None for timeout or exception.
        """
        if not run:
            return None

        last_output_position = 0
        start = datetime.now()
        interval = 1 if self.__class__.__name__ == "AppMeshClient" else 1000

        while run.proc_uid:
            app_out = self.get_app_output(app_name=run.app_name, stdout_position=last_output_position, stdout_index=0, process_uuid=run.proc_uid, timeout=interval)

            if app_out.output and stdout_print:
                print(app_out.output, end="", flush=True)

            if app_out.out_position is not None:
                last_output_position = app_out.out_position

            if app_out.exit_code is not None:
                # success
                with suppress(Exception):
                    self.delete_app(run.app_name)
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
        max_time_seconds: Union[int, str] = _DURATION_TWO_DAYS_ISO,
        life_cycle_seconds: Union[int, str] = _DURATION_TWO_DAYS_HALF_ISO,
    ) -> Tuple[Union[int, None], str]:
        """Synchronously run an application remotely, blocking until completion, and return the result.

        If 'app' is a string, it is treated as a shell command and converted to an App instance.
        If 'app' is App object, the name attribute is used to run an existing application if specified.

        Args:
            app: An App instance or a shell command string.
                If a string, an App instance is created as:
                `appmesh.App({"command": "<command_string>", "shell": True})`
            max_time_seconds: Maximum runtime for the remote process.
                Supports ISO 8601 duration format (e.g., 'P1Y2M3DT4H5M6S', 'P5W'). Defaults to DEFAULT_RUN_APP_TIMEOUT_SECONDS.
            life_cycle_seconds: Maximum lifecycle time for the remote process.
                Supports ISO 8601 duration format. Defaults to DEFAULT_RUN_APP_LIFECYCLE_SECONDS.

        Returns:
            Exit code of the process (None if unavailable) and the stdout text.
        """
        if isinstance(app, str):
            app = App({"command": app, "shell": True})

        resp = self._request_http(
            AppMeshClient._Method.POST,
            body=app.json(),
            path="/appmesh/app/syncrun",
            query={
                "timeout": str(self._parse_duration(max_time_seconds)),
                "lifecycle": str(self._parse_duration(life_cycle_seconds)),
            },
        )

        exit_code = None
        if resp.status_code == HTTPStatus.OK:
            if "X-Exit-Code" in resp.headers:
                exit_code = int(resp.headers["X-Exit-Code"])

        return exit_code, resp.text

    def _request_http(self, method: _Method, path: str, query: Optional[dict] = None, header: Optional[dict] = None, body=None) -> requests.Response:
        """Make an HTTP request."""
        rest_url = parse.urljoin(self.auth_server_url, path)

        # Prepare headers
        headers = header.copy() if header else {}

        csrf_token = self._get_cookie_value(self.session.cookies, self._COOKIE_CSRF_TOKEN)
        if csrf_token:
            # appmesh token
            headers[self._HTTP_HEADER_NAME_CSRF_TOKEN] = csrf_token
        else:
            # OAuth token
            access_token = self._get_access_token()
            if access_token:
                headers[self._HTTP_HEADER_KEY_AUTH] = f"Bearer {access_token}"

        if self.forward_to:
            target_host = self.forward_to
            if ":" not in target_host:
                port = parse.urlsplit(self.auth_server_url).port
                target_host = f"{target_host}:{port}"
            headers[self._HTTP_HEADER_KEY_X_TARGET_HOST] = target_host

        headers[self._HTTP_HEADER_KEY_USER_AGENT] = self._HTTP_USER_AGENT

        # Convert body to JSON string if it's a dict or list
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
            headers.setdefault("Content-Type", "application/json")

        try:
            request_kwargs = {
                "url": rest_url,
                "headers": headers,
                "cert": self.ssl_client_cert,
                "verify": self.ssl_verify,
                "timeout": self.rest_timeout,
            }

            if method == AppMeshClient._Method.GET:
                resp = self.session.get(params=query, **request_kwargs)
            elif method == AppMeshClient._Method.POST:
                resp = self.session.post(params=query, data=body, **request_kwargs)
            elif method == AppMeshClient._Method.POST_STREAM:
                resp = self.session.post(params=query, data=body, stream=True, **request_kwargs)
            elif method == AppMeshClient._Method.DELETE:
                resp = self.session.delete(**request_kwargs)
            elif method == AppMeshClient._Method.PUT:
                resp = self.session.put(params=query, data=body, **request_kwargs)
            else:
                raise Exception("Invalid http method", method)

            # Wrap the response for encoding handling
            return AppMeshClient._EncodingResponse(resp)

        except requests.exceptions.RequestException as e:
            raise Exception(f"HTTP request failed: {e}") from e
