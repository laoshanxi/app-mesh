# client_http.py
# pylint: disable=broad-exception-raised,line-too-long,broad-exception-caught,too-many-lines,import-outside-toplevel

"""App Mesh HTTP Client SDK for REST API interactions."""

# Standard library imports
import json
import locale
import logging
import os
import sys
import warnings
from contextlib import suppress
from datetime import datetime
from enum import Enum, unique
from http import HTTPStatus
from http.cookiejar import DefaultCookiePolicy
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib import parse

# Third-party imports
import aniso8601
import requests
from requests.structures import CaseInsensitiveDict

# Local imports
from .app import App
from .app_output import AppOutput
from .app_run import AppRun, OutputHandler
from .exceptions import AppMeshAuthError, AppMeshConnectionError, AppMeshRequestError
from .token_provider import StaticAccessTokenProvider, TokenProvider

logger = logging.getLogger(__name__)


class _RejectAllCookiesPolicy(DefaultCookiePolicy):
    """Prevent Engine responses from creating SDK authentication state."""

    def set_ok(self, cookie, request):
        del cookie, request
        return False

    def return_ok(self, cookie, request):
        del cookie, request
        return False

    def domain_return_ok(self, domain, request):
        del domain, request
        return False

    def path_return_ok(self, path, request):
        del path, request
        return False


class AppMeshClient:
    """
    HTTP (REST) client for the App Mesh service.

    Manages application lifecycle, monitoring, and configuration over HTTPS,
    with TLS transport and bearer-token authentication.

    Methods:
        # Authentication context
        - set_token_provider()
        - set_bearer_token()
        - clear_bearer_token()
        - get_auth_config()
        - get_current_principal()

        # Application Management
        - get_app()
        - list_apps()
        - get_app_output()
        - check_app_health()
        - add_app()
        - delete_app()
        - enable_app()
        - disable_app()

        # Run Application Operations
        - run_app_async()
        - wait_for_async_run()
        - run_app_sync()
        - run_task()
        - cancel_task()

        # Event Subscription (AppMeshClientTCP/AppMeshClientWSS only; see `supports_events`)
        - subscribe()
        - unsubscribe()

        # System & Configuration
        - forward_to
        - set_config()
        - get_config()
        - set_log_level()
        - get_host_resources()
        - get_metrics()
        - add_label()
        - delete_label()
        - list_labels()

        # File Management
        - download_file()
        - upload_file()

        # Authorization Management
        - list_principals()
        - update_principal()
        - delete_principal()
        - get_principal_permissions()
        - list_permissions()
        - list_roles()
        - update_role()
        - delete_role()

        # Client Lifecycle
        - close()

    Example:
        >>> from appmesh import AppMeshClient
        >>> client = AppMeshClient(bearer_token="access-token")
        >>> app = client.get_app(app_name="ping")
    """

    # Polling interval for wait_for_async_run (seconds)
    _POLL_INTERVAL = 1

    # Whether this client can deliver app events (True on TCP/WSS transports only)
    supports_events = False

    _DURATION_TWO_DAYS_ISO = "P2D"
    _DURATION_TWO_DAYS_HALF_ISO = "P2DT12H"

    # Platform-aware App Mesh directory used only for CA discovery. Client
    # identities are never selected implicitly; mTLS must be configured per caller.
    _DEFAULT_SSL_DIR = Path("c:/local/appmesh/ssl" if os.name == "nt" else "/opt/appmesh/ssl")

    # HTTP headers and constants
    _JSON_KEY_MESSAGE = "message"
    _HTTP_USER_AGENT = "appmesh/python"
    _HTTP_HEADER_KEY_AUTH = "Authorization"
    _HTTP_HEADER_KEY_USER_AGENT = "User-Agent"
    _HTTP_HEADER_KEY_X_TARGET_HOST = "X-Target-Host"
    _HTTP_HEADER_KEY_X_FILE_PATH = "X-File-Path"

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

    @classmethod
    def _resolve_ssl_verify(cls, ssl_verify: Union[bool, str, None]) -> Union[bool, str]:
        """Resolve the ``ssl_verify`` value: ``None`` (auto) selects the App Mesh CA bundle when
        installed, otherwise the system CAs. Verification is never disabled implicitly; a
        non-empty CA path that does not exist is a hard error, while the legacy empty-string
        form means explicit disable (like ``False``).
        """
        if ssl_verify is None:
            ca_path = cls._DEFAULT_SSL_DIR / "ca.pem"
            return str(ca_path) if ca_path.exists() else True
        if ssl_verify == "":  # legacy empty-path form: explicit disable
            return False
        if isinstance(ssl_verify, str) and not os.path.exists(ssl_verify):
            raise ValueError(f"ssl_verify path '{ssl_verify}' does not exist")
        return ssl_verify

    def __init__(
        self,
        base_url: str = "https://127.0.0.1:6060",
        ssl_verify: Union[bool, str, None] = None,
        ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = None,
        request_timeout: Tuple[float, float] = (60, 300),
        *,
        bearer_token: Optional[str] = None,
        token_provider: Optional[TokenProvider] = None,
    ):
        """Initialize an App Mesh HTTP client for interacting with the App Mesh server via secure HTTPS.

        Args:
            base_url: The server's base URI. Defaults to "https://127.0.0.1:6060".
            ssl_verify: SSL server verification mode:
              - None (default): Auto — use the App Mesh CA bundle if installed, otherwise system CAs.
              - True: Use system CAs.
              - False: Disable verification (insecure, must be requested explicitly).
              - str: Path to custom CA or directory (must exist). To include system CAs, combine them into one file (e.g., cat custom_ca.pem /etc/ssl/certs/ca-certificates.crt > combined_ca.pem).
            ssl_client_cert: SSL client certificate file(s):
              - str: Single PEM file with cert+key
              - tuple: (cert_path, key_path)
              - None (default): Do not send a client certificate. mTLS is opt-in.
            request_timeout: Timeouts `(connect_timeout, read_timeout)` in seconds.  Default `(60, 300)`.
            bearer_token: Access token to send as an RFC 6750 bearer token. Token acquisition,
              refresh, persistence, and revocation are handled by :class:`OAuthClient`.
            token_provider: Provider that supplies and refreshes access tokens. Mutually
              exclusive with ``bearer_token``. Refresh credentials remain provider-private.
        """
        self._ensure_logging_configured()
        self.base_url = self._normalize_base_url(base_url)
        self.ssl_verify = self._resolve_ssl_verify(ssl_verify)
        self.ssl_client_cert = ssl_client_cert
        self.request_timeout = request_timeout
        self._forward_to = None

        if bearer_token is not None and token_provider is not None:
            raise ValueError("bearer_token and token_provider are mutually exclusive")
        self._token_provider = None
        if token_provider is not None:
            self.set_token_provider(token_provider)
        elif bearer_token is not None:
            self.set_bearer_token(bearer_token)
        self.session = requests.Session()
        # CLI/SDK authentication is bearer-only. Reject Engine/proxy cookies at
        # the jar policy layer so concurrent requests cannot retain or replay them.
        self.session.cookies.set_policy(_RejectAllCookiesPolicy())

    @staticmethod
    def _normalize_base_url(base_url: str) -> str:
        """Require a stable absolute HTTP(S) Engine URL."""
        if not isinstance(base_url, str) or not base_url.strip():
            raise ValueError("base_url is required")
        candidate = base_url.strip().rstrip("/")
        parsed = parse.urlsplit(candidate)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("base_url has an invalid port") from exc
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or port is not None and not 0 < port < 65536
        ):
            raise ValueError("base_url must be an absolute HTTP(S) URL without credentials, query, or fragment")
        return candidate

    @staticmethod
    def _ensure_logging_configured() -> None:
        """Ensure logging is configured with a default console handler if needed."""
        if not logging.root.handlers:
            logging.basicConfig(
                level=logging.INFO,
                format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )

    @property
    def token_provider(self) -> Optional[TokenProvider]:
        """Return the provider currently attached to this Engine client."""
        return self._token_provider

    def _get_bearer_token(
        self,
        force_refresh: bool = False,
        rejected_token: Optional[str] = None,
    ) -> Optional[str]:
        """Return an access token without exposing provider refresh credentials."""
        provider = self._token_provider
        if provider is None:
            return None
        token = (
            provider.refresh_access_token(rejected_token=rejected_token)
            if force_refresh
            else provider.get_access_token()
        )
        if token is None:
            return None
        if not isinstance(token, str) or not token.strip():
            raise AppMeshAuthError("TokenProvider returned an invalid access token")
        return token.strip()

    def set_token_provider(self, provider: TokenProvider) -> None:
        """Attach a refresh-capable provider to this bearer-only Engine client."""
        if not isinstance(provider, TokenProvider):
            raise TypeError("token_provider must implement TokenProvider")
        self._token_provider = provider

    def set_bearer_token(self, token: str) -> None:
        """Attach a caller-owned, non-refreshing access token."""
        self._token_provider = StaticAccessTokenProvider(token)

    def clear_bearer_token(self) -> None:
        """Detach local authentication state without contacting the authentication service."""
        self._token_provider = None

    def close(self) -> None:
        """Close the client and release resources."""
        if self.session:
            self.session.close()
            self.session = None

    def __enter__(self):
        """Support for context manager protocol."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Support for context manager protocol, ensuring resources are released."""
        self.close()

    def __del__(self):
        """Ensure resources are released when the object is garbage collected."""
        try:
            self.close()
        except Exception:  # pylint: disable=broad-exception-caught
            pass  # suppress all exceptions

    @property
    def forward_to(self) -> str:
        """Target host for request forwarding in a cluster.

        Supports:
        - "hostname" or "IP" → uses current service port
        - "hostname:port" or "IP:port" → uses specified port

        Returns:
            str: Target host (e.g., "node" or "node:6060"), or empty string if unset.

        Notes:
            Every target node must trust the same issuer and App Mesh resource audience.
            If port is omitted, the current service port is used.

        Warning:
            Shared, per-client state read by every request; ``AppRun.wait()`` temporarily
            overrides it. Use separate client instances for concurrent multi-host access.
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
    def get_auth_config(self) -> Dict[str, Any]:
        """Return the public OAuth/OIDC configuration advertised by App Mesh."""
        resp = self._request_http(AppMeshClient._Method.GET, path="/appmesh/auth/config")
        return resp.json()

    def get_current_principal(self) -> Dict[str, Any]:
        """Return the verified principal represented by the current bearer token."""
        resp = self._request_http(AppMeshClient._Method.GET, path="/appmesh/principal/self")
        return resp.json()

    ########################################
    # Application view
    ########################################
    def get_app(self, app_name: str) -> App:
        """Get information about a specific application."""
        resp = self._request_http(AppMeshClient._Method.GET, path=f"/appmesh/app/{app_name}")
        return App(resp.json())

    def list_apps(self) -> List[App]:
        """Get information about all applications."""
        resp = self._request_http(AppMeshClient._Method.GET, path="/appmesh/applications")
        return [App(app) for app in resp.json()]

    def get_app_output(
        self,
        app_name: str,
        stdout_position: int = 0,
        stdout_index: int = 0,
        stdout_maxsize: int = 10240,
        process_uuid: str = "",
        timeout: int = 0,
    ) -> AppOutput:
        """Get incremental stdout/stderr output for a running or completed application.

        Args:
            app_name: the application name
            stdout_position: start read position, 0 means start from beginning.
            stdout_index: index of history process stdout, 0 means get from current running process,
                the stdout number depends on 'stdout_cache_size' of the application.
            stdout_maxsize: max buffer size to read.
            process_uuid: used to get the specified process instance instead of the latest one.
            timeout: long-poll wait time in seconds before returning when no new output is available.

        Returns:
            ``AppOutput`` containing response status, payload text, the next read cursor
            (``output_position``), and ``exit_code`` when the process has already finished.
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
            raise_on_fail=False,
        )

        output_position = int(resp.headers["X-Output-Position"]) if "X-Output-Position" in resp.headers else None
        exit_code = int(resp.headers["X-Exit-Code"]) if "X-Exit-Code" in resp.headers else None

        return AppOutput(status_code=resp.status_code, output=resp.text, output_position=output_position, exit_code=exit_code)

    def check_app_health(self, app_name: str) -> bool:
        """Check the health status of an application."""
        resp = self._request_http(AppMeshClient._Method.GET, path=f"/appmesh/app/{app_name}/health")
        return int(resp.text) == 0

    ########################################
    # Application manage
    ########################################
    def add_app(self, app: App, subscribe_events: Optional[List[str]] = None) -> App:
        """Register a new application.

        ``subscribe_events`` only takes effect on a persistent connection (TCP/WSS) and is
        ignored by the HTTP transport (no demuxer to deliver events to; a ``RuntimeWarning``
        is emitted). When the daemon creates a subscription, the returned App carries
        ``subscription_id``.
        """
        if subscribe_events and not self.supports_events:
            warnings.warn("subscribe_events has no effect over HTTP; use AppMeshClientTCP/AppMeshClientWSS to receive events", RuntimeWarning, stacklevel=2)
        query = {"subscribe_events": ",".join(subscribe_events)} if subscribe_events else None
        resp = self._request_http(AppMeshClient._Method.PUT, path=f"/appmesh/app/{app.name}", query=query, body=app.to_dict())
        return App(resp.json())

    def delete_app(self, app_name: str) -> bool:
        """Remove an application.

        Returns:
            bool: ``True`` when the app was deleted, ``False`` when it did not exist (404).
            Any other non-OK status is logged and raised as an HTTP error.
        """
        resp = self._request_http(AppMeshClient._Method.DELETE, path=f"/appmesh/app/{app_name}", raise_on_fail=False)

        if resp.status_code == HTTPStatus.OK:
            return True
        if resp.status_code == HTTPStatus.NOT_FOUND:
            return False

        logger.warning("Failed to delete app: %s", resp.text)
        resp.raise_for_status()
        return False

    def enable_app(self, app_name: str) -> None:
        """Enable an application."""
        self._request_http(AppMeshClient._Method.POST, path=f"/appmesh/app/{app_name}/enable")

    def disable_app(self, app_name: str) -> None:
        """Disable an application."""
        self._request_http(AppMeshClient._Method.POST, path=f"/appmesh/app/{app_name}/disable")

    ########################################
    # Configuration
    ########################################
    def get_host_resources(self) -> Dict[str, Any]:
        """Get a report of host resources including CPU, memory, and disk."""
        resp = self._request_http(AppMeshClient._Method.GET, path="/appmesh/resources")
        return resp.json()

    def get_config(self) -> Dict[str, Any]:
        """Get the App Mesh configuration in JSON format."""
        resp = self._request_http(AppMeshClient._Method.GET, path="/appmesh/config")
        return resp.json()

    def set_config(self, config: dict) -> Dict[str, Any]:
        """Update the configuration."""
        resp = self._request_http(AppMeshClient._Method.POST, path="/appmesh/config", body=config)
        return resp.json()

    def set_log_level(self, level: str = "DEBUG") -> str:
        """Update the log level."""
        config_dict = self.set_config(config={"BaseConfig": {"LogLevel": level}})
        return config_dict["BaseConfig"]["LogLevel"]

    ########################################
    # Principal and authorization management
    ########################################
    def list_principals(self) -> Dict[str, Any]:
        """List App Mesh authorization overlays keyed by immutable principal ID."""
        resp = self._request_http(method=AppMeshClient._Method.GET, path="/appmesh/principals")
        return resp.json()

    def update_principal(self, principal_id: str, principal_data: dict) -> None:
        """Create or update an App Mesh authorization overlay for a principal."""
        principal = parse.quote(principal_id, safe="")
        self._request_http(method=AppMeshClient._Method.POST, path=f"/appmesh/principal/{principal}", body=principal_data)

    def delete_principal(self, principal_id: str) -> None:
        """Delete an App Mesh authorization overlay; this never deletes an identity-provider user."""
        principal = parse.quote(principal_id, safe="")
        self._request_http(method=AppMeshClient._Method.DELETE, path=f"/appmesh/principal/{principal}")

    def list_permissions(self) -> List[str]:
        """Get information about all available permissions."""
        resp = self._request_http(method=AppMeshClient._Method.GET, path="/appmesh/permissions")
        return resp.json()

    def get_principal_permissions(self) -> List[str]:
        """Return effective permissions for the current verified principal."""
        resp = self._request_http(method=AppMeshClient._Method.GET, path="/appmesh/principal/self/permissions")
        return resp.json()

    def list_roles(self) -> Dict[str, Dict]:
        """Get information about all roles with permission definitions."""
        resp = self._request_http(method=AppMeshClient._Method.GET, path="/appmesh/roles")
        return resp.json()

    def update_role(self, role_name: str, permission_set: list) -> None:
        """Update or add a role with defined permissions."""
        self._request_http(method=AppMeshClient._Method.POST, path=f"/appmesh/role/{role_name}", body=permission_set)

    def delete_role(self, role_name: str) -> None:
        """Delete an App Mesh authorization role."""
        self._request_http(method=AppMeshClient._Method.DELETE, path=f"/appmesh/role/{role_name}")

    ########################################
    # Label management
    ########################################
    def add_label(self, label_name: str, label_value: str) -> None:
        """Add a new label."""
        self._request_http(AppMeshClient._Method.PUT, query={"value": label_value}, path=f"/appmesh/label/{label_name}")

    def delete_label(self, label_name: str) -> None:
        """Delete a label."""
        self._request_http(AppMeshClient._Method.DELETE, path=f"/appmesh/label/{label_name}")

    def list_labels(self) -> Dict[str, str]:
        """Get information about all labels."""
        resp = self._request_http(AppMeshClient._Method.GET, path="/appmesh/labels")
        return resp.json()


    ########################################
    # Prometheus metrics
    ########################################
    def get_metrics(self) -> str:
        """Get Prometheus metrics."""
        resp = self._request_http(AppMeshClient._Method.GET, path="/appmesh/metrics")
        return resp.text

    ########################################
    # File management
    ########################################
    @staticmethod
    def _apply_file_attributes(local_path: Path, headers: CaseInsensitiveDict) -> None:
        """
        Apply file attributes from headers to local file.
        Expected headers: X-File-Mode (decimal str), X-File-User (username), X-File-Group (groupname).
        """
        if sys.platform == "win32":
            return

        headers = CaseInsensitiveDict(headers or {})

        # Ownership by name - apply FIRST, as chown clears setuid/setgid bits
        user_header = headers.get("X-File-User")
        group_header = headers.get("X-File-Group")

        if user_header is not None and group_header is not None:
            chown = getattr(os, "chown", None)
            if callable(chown):
                try:
                    import pwd
                    import grp
                    # Try to resolve as username/groupname first
                    try:
                        uid = pwd.getpwnam(user_header).pw_uid
                    except KeyError:
                        # Fall back to numeric UID if name lookup fails
                        try:
                            uid = int(user_header)
                        except ValueError:
                            uid = None

                    try:
                        gid = grp.getgrnam(group_header).gr_gid
                    except KeyError:
                        # Fall back to numeric GID if name lookup fails
                        try:
                            gid = int(group_header)
                        except ValueError:
                            gid = None

                    if uid is not None and gid is not None:
                        with suppress(OSError):
                            chown(str(local_path), uid, gid)
                    else:
                        logger.warning("Could not resolve X-File-User/Group: %s/%s", user_header, group_header)

                except (ValueError, KeyError) as e:
                    logger.warning("Invalid X-File-User/Group values: %s/%s - %s", user_header, group_header, e)

        # Mode - apply AFTER chown to preserve permission bits
        if "X-File-Mode" in headers:
            try:
                file_mode = int(headers["X-File-Mode"])
                # Validate mode is within valid range (0-511 for 0o777)
                if 0 <= file_mode <= 0o777:
                    with suppress(OSError):
                        local_path.chmod(file_mode)
                else:
                    logger.warning("X-File-Mode value out of range: %s", file_mode)
            except ValueError:
                logger.warning("Invalid X-File-Mode value: %s", headers.get("X-File-Mode"))

    @staticmethod
    def _get_file_attributes(local_path: Path) -> dict:
        """Get file attributes as header dictionary."""
        if sys.platform == "win32":
            return {}

        try:
            import pwd
            import grp
            st = local_path.stat()
            result = {
                "X-File-Mode": str(st.st_mode & 0o777),  # Mask to keep only permission bits
            }

            # Get username/groupname for portability
            try:
                result["X-File-User"] = pwd.getpwuid(st.st_uid).pw_name
            except KeyError:
                # User not found, fall back to UID
                result["X-File-User"] = str(st.st_uid)

            try:
                result["X-File-Group"] = grp.getgrgid(st.st_gid).gr_name
            except KeyError:
                # Group not found, fall back to GID
                result["X-File-Group"] = str(st.st_gid)

            return result

        except OSError:
            return {}

    def download_file(self, remote_file: str, local_file: Optional[str] = None, preserve_permissions: bool = False) -> None:
        """Download a remote file to the local filesystem (``local_file`` defaults to the remote basename).

        When ``preserve_permissions`` is ``True``, POSIX mode/owner/group metadata from App Mesh
        response headers is applied best-effort on non-Windows platforms.
        """
        if not local_file:
            local_file = os.path.basename(remote_file)
        resp = self._request_http(
            AppMeshClient._Method.GET,
            path="/appmesh/file/download",
            header={self._HTTP_HEADER_KEY_X_FILE_PATH: remote_file},
        )

        # Write the file content locally
        local_path = Path(local_file)
        with local_path.open("wb") as fp:
            for chunk in resp.iter_content(chunk_size=8 * 1024):
                if chunk:
                    fp.write(chunk)

        if preserve_permissions:
            self._apply_file_attributes(local_path, resp.headers)

    def upload_file(self, local_file: str, remote_file: Optional[str] = None, preserve_permissions: bool = False) -> None:
        """Upload a local file to the remote server (``remote_file`` defaults to the local file's basename).

        When ``preserve_permissions`` is ``True``, the client also sends local POSIX metadata
        in request headers so the server can recreate permissions/ownership when supported.
        """
        if not remote_file:
            remote_file = os.path.basename(local_file)
        local_path = Path(local_file)
        if not local_path.exists():
            raise FileNotFoundError(f"Local file not found: {local_file}")

        from requests_toolbelt import MultipartEncoder

        with local_path.open("rb") as fp:
            encoder = MultipartEncoder(
                fields={"filename": os.path.basename(remote_file), "file": ("filename", fp, "application/octet-stream")}
            )

            header = {self._HTTP_HEADER_KEY_X_FILE_PATH: parse.quote(remote_file), "Content-Type": encoder.content_type}

            if preserve_permissions:
                header.update(self._get_file_attributes(local_path))

            # Upload file with or without attributes
            # https://stackoverflow.com/questions/22567306/python-requests-file-upload
            self._request_http(
                AppMeshClient._Method.POST_STREAM, path="/appmesh/file/upload", header=header, body=encoder
            )

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

        Args:
            app_name: Name of the target application (as registered in App Mesh).
            data: Payload to deliver to the application. Typically a string.
            timeout: Maximum time in seconds to wait for a response from the application. Defaults to 300 seconds.

        Returns:
            str: The HTTP response body returned by the remote application/service.
        """
        if timeout <= 0:
            timeout = 300
        resp = self._request_http(
            AppMeshClient._Method.POST,
            path=f"/appmesh/app/{app_name}/task",
            body=data,
            query={"timeout": str(timeout)},
        )
        return resp.text

    def cancel_task(self, app_name: str) -> bool:
        """Cancel a running task for an App Mesh application.

        Args:
            app_name: Name of the target application (as registered in App Mesh).

        Returns:
            bool: ``True`` if a task existed and was cancelled. ``False`` means no task
            was pending (208), the application was not found (404), or the request failed
            for another reason (e.g. 401/403); unexpected failures are logged as warnings,
            never raised.
        """
        resp = self._request_http(
            AppMeshClient._Method.DELETE, path=f"/appmesh/app/{app_name}/task", raise_on_fail=False
        )
        if resp.status_code not in (
            HTTPStatus.OK,
            HTTPStatus.ALREADY_REPORTED,
            HTTPStatus.NOT_FOUND,
        ):
            logger.warning("Failed to cancel task for app '%s' with status %d: %s", app_name, resp.status_code, resp.text)
        return resp.status_code == HTTPStatus.OK

    def run_app_async(
        self,
        app: Union[App, str],
        max_time: Union[int, str] = _DURATION_TWO_DAYS_ISO,
        lifecycle: Union[int, str] = _DURATION_TWO_DAYS_HALF_ISO,
    ) -> AppRun:
        """Run an application asynchronously on a remote system without blocking the API.

        Args:
            app: An `App` instance or a shell command string.
                - If `app` is a string, it is treated as a shell command for the remote run,
                and an `App` instance is created as:
                `App({"command": "<command_string>", "shell": True})`.
                - If `app` is an `App` object, providing only the `name` attribute (without
                a command) will run an existing application; otherwise, it is treated as a new application.
            max_time: Maximum runtime for the remote process, after which the daemon kills it
                (sent as the wire query parameter ``timeout``).
                Accepts integer seconds or ISO 8601 duration format (e.g., 'P1Y2M3DT4H5M6S', 'P5W'). Defaults to `P2D`.
            lifecycle: Total retention window for the temporary run app, after which the daemon
                purges it (including its cached output); must cover ``max_time`` plus the time
                needed to collect results (sent as the wire query parameter ``lifecycle``).
                Accepts integer seconds or ISO 8601 duration format. Defaults to `P2DT12H`.

        Returns:
            ``AppRun`` handle that captures the current ``forward_to`` target so later polling can
            continue against the same cluster node.
        """
        if isinstance(app, str):
            app = App({"command": app, "shell": True})

        resp = self._request_http(
            AppMeshClient._Method.POST,
            body=app.to_dict(),
            path="/appmesh/app/run",
            query={
                "timeout": str(self._parse_duration(max_time)),
                "lifecycle": str(self._parse_duration(lifecycle)),
            },
        )

        response_data = resp.json()
        return AppRun(self, response_data["name"], response_data["process_uuid"])

    def wait_for_async_run(self, run: AppRun, stdout_handler: Optional[OutputHandler] = None, timeout: int = 0) -> Optional[int]:
        """Wait for an asynchronous run to finish.

        Args:
            run: asynchronous run handle returned by run_app_async().
            stdout_handler: optional callback ``(data, position) -> None`` invoked with each
                chunk of remote stdout (``print_output_handler`` prints to console).
            timeout: wait max timeout seconds and return if not finished, 0 means wait until finished

        Returns:
            Exit code if the process finished, or ``None`` when ``timeout`` elapsed first.
            On success, this method also makes a best-effort attempt to delete the temporary run app.

        Raises:
            AppMeshConnectionError: If polling the app output fails (non-OK response).
        """
        if not run:
            return None

        last_output_position = 0
        start = datetime.now()
        interval = self._POLL_INTERVAL

        while run.process_uuid:
            app_out = self.get_app_output(
                app_name=run.app_name,
                stdout_position=last_output_position,
                stdout_index=0,
                process_uuid=run.process_uuid,
                timeout=interval,
            )

            if app_out.output and stdout_handler is not None:
                stdout_handler(app_out.output, last_output_position)

            if app_out.output_position is not None:
                last_output_position = app_out.output_position

            if app_out.exit_code is not None:
                # success
                with suppress(Exception):
                    self.delete_app(run.app_name)
                return app_out.exit_code

            if app_out.status_code != HTTPStatus.OK:
                raise AppMeshConnectionError(f"wait_for_async_run polling failed for '{run.app_name}' with status {app_out.status_code}: {app_out.output}")

            if timeout > 0 and (datetime.now() - start).total_seconds() > timeout:
                # timeout
                break

        return None

    def run_app_sync(
        self,
        app: Union[App, str],
        max_time: Union[int, str] = _DURATION_TWO_DAYS_ISO,
        lifecycle: Union[int, str] = _DURATION_TWO_DAYS_HALF_ISO,
    ) -> Tuple[Union[int, None], str]:
        """Synchronously run an application remotely, blocking until completion, and return the result.

        If 'app' is a string, it is treated as a shell command and converted to an App instance.
        If 'app' is App object, the name attribute is used to run an existing application if specified.

        Args:
            app: An App instance or a shell command string.
                If a string, an App instance is created as:
                `appmesh.App({"command": "<command_string>", "shell": True})`
            max_time: Maximum runtime for the remote process, after which the daemon kills it
                (sent as the wire query parameter ``timeout``).
                Accepts integer seconds or ISO 8601 duration format (e.g., 'P1Y2M3DT4H5M6S', 'P5W').
            lifecycle: Total retention window for the temporary run app, after which the daemon
                purges it (sent as the wire query parameter ``lifecycle``).
                Accepts integer seconds or ISO 8601 duration format.

        Returns:
            ``(exit_code, stdout_text)``. ``exit_code`` is ``None`` when the server did not return
            an ``X-Exit-Code`` header.
        """
        if isinstance(app, str):
            app = App({"command": app, "shell": True})

        resp = self._request_http(
            AppMeshClient._Method.POST,
            body=app.to_dict(),
            path="/appmesh/app/syncrun",
            query={
                "timeout": str(self._parse_duration(max_time)),
                "lifecycle": str(self._parse_duration(lifecycle)),
            },
            raise_on_fail=False,
        )

        exit_code = None
        if resp.status_code == HTTPStatus.OK:
            if "X-Exit-Code" in resp.headers:
                exit_code = int(resp.headers["X-Exit-Code"])

        return exit_code, resp.text

    def _request_http(
        self,
        method: _Method,
        path: str,
        query: Optional[dict] = None,
        header: Optional[dict] = None,
        body=None,
        raise_on_fail: bool = True,
    ) -> requests.Response:
        """Make an HTTP request."""
        url = parse.urljoin(self.base_url, path)

        base_headers = header.copy() if header else {}
        caller_manages_auth = any(key.lower() == self._HTTP_HEADER_KEY_AUTH.lower() for key in base_headers)
        provider = None if caller_manages_auth else self._token_provider

        if self.forward_to:
            target_host = self.forward_to
            if ":" not in target_host:
                parsed = parse.urlsplit(self.base_url)
                default_port = {"http": 80, "https": 443}.get(parsed.scheme)
                port = parsed.port or default_port
                target_host = f"{target_host}:{port}"
            base_headers[self._HTTP_HEADER_KEY_X_TARGET_HOST] = target_host

        base_headers[self._HTTP_HEADER_KEY_USER_AGENT] = self._HTTP_USER_AGENT

        # Convert body to JSON string if it's a dict or list
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
            base_headers.setdefault("Content-Type", "application/json")

        # Streaming/multipart bodies cannot be assumed replayable after a 401 response.
        replayable = body is None or isinstance(body, (str, bytes, bytearray))
        rejected_token = None

        try:
            for attempt in range(2):
                headers = dict(base_headers)
                bearer_token = None
                if provider is not None:
                    bearer_token = self._get_bearer_token(
                        force_refresh=attempt == 1,
                        rejected_token=rejected_token,
                    )
                    if bearer_token:
                        headers[self._HTTP_HEADER_KEY_AUTH] = f"Bearer {bearer_token}"

                request_kwargs = {
                    "url": url,
                    "headers": headers,
                    "cert": self.ssl_client_cert,
                    "verify": self.ssl_verify,
                    "timeout": self.request_timeout,
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
                    raise AppMeshRequestError(f"Invalid http method: {method}")

                if (
                    resp.status_code == HTTPStatus.UNAUTHORIZED
                    and attempt == 0
                    and replayable
                    and provider is not None
                    and provider.can_refresh
                ):
                    rejected_token = bearer_token
                    resp.close()
                    continue

                if raise_on_fail:
                    if resp.status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN):
                        raise AppMeshAuthError(f"HTTP {resp.status_code}: {resp.reason}", resp.status_code)
                    resp.raise_for_status()

                return AppMeshClient._EncodingResponse(resp)

            raise AppMeshAuthError("TokenProvider failed to replace a rejected access token", HTTPStatus.UNAUTHORIZED)

        except requests.exceptions.RequestException as e:
            raise AppMeshRequestError(f"HTTP request failed: {e}") from e
