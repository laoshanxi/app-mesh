"""
App Mesh MCP Server
===================

Exposes App Mesh daemon operations as MCP tools over **Streamable HTTP**, so MCP
clients (Claude, etc.) can manage applications remotely.

Authentication is delegated entirely to Dex (see ``auth.py``). This process is an
OAuth resource server: it validates the Dex access token and forwards the same token
to the daemon, so it never receives a password and never issues another token.

Designed to run **as an App Mesh App** (see ``appmesh_mcp_app.yaml``) so it can be
enabled / disabled / removed at any time, independently of the daemon.

Transport: Streamable HTTP. Run with::

    APPMESH_MCP_PORT=6071 python3 appmesh_server.py

Environment:
    APPMESH_URL        App Mesh REST base URL the server talks to (default https://127.0.0.1:6060)
    APPMESH_CA         CA file/dir for verifying the daemon (optional)
    APPMESH_SSL_VERIFY set "false" to disable daemon TLS verification (dev only)
    APPMESH_MCP_HOST   bind host (default 0.0.0.0)
    APPMESH_MCP_PORT   bind port (default 6071)
    APPMESH_MCP_PUBLIC_URL  public base URL used in OAuth metadata (default https://<host>:<port>)
    APPMESH_MCP_TLS_CERT / APPMESH_MCP_TLS_KEY  enable HTTPS for the MCP endpoint
    APPMESH_DEX_ISSUER      canonical Dex issuer embedded in tokens (required)
    APPMESH_DEX_ACCESS_URL  network address this process uses to reach Dex (required)
    APPMESH_DEX_CA_PATH     CA file/dir for verifying Dex independently (optional)
    APPMESH_DEX_TLS_VERIFY  set "false" to disable Dex TLS verification (dev only)
    APPMESH_DEX_AUDIENCE    App Mesh resource audience (default appmesh-api)
"""

# pylint: disable=line-too-long,broad-exception-caught

import logging
import os
from typing import Optional

from fastmcp import FastMCP
from fastmcp.dependencies import CurrentAccessToken
from fastmcp.server.auth import AccessToken

from appmesh import App, AppMeshClient

from auth import appmesh_url, make_appmesh_client, make_auth_provider

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("AppMesh-MCP")


# --------------------------------------------------------------------------- #
# Server + OAuth wiring
# --------------------------------------------------------------------------- #
def _public_url() -> str:
    explicit = os.environ.get("APPMESH_MCP_PUBLIC_URL")
    if explicit:
        return explicit.rstrip("/")
    host = os.environ.get("APPMESH_MCP_HOST", "0.0.0.0")
    if host == "0.0.0.0":
        host = "127.0.0.1"
    port = os.environ.get("APPMESH_MCP_PORT", "6071")
    scheme = "https" if os.environ.get("APPMESH_MCP_TLS_CERT") else "http"
    return f"{scheme}://{host}:{port}"


auth_provider = make_auth_provider(base_url=_public_url())
mcp = FastMCP("AppMesh", auth=auth_provider)


def _client(token: AccessToken) -> AppMeshClient:
    """Build an App Mesh client bound to the caller's Dex access token."""
    return make_appmesh_client(bearer_token=token.token)


# --------------------------------------------------------------------------- #
# Application management
# --------------------------------------------------------------------------- #
@mcp.tool(description="List all registered applications.")
def list_apps(token: AccessToken = CurrentAccessToken()) -> list:
    return [a.to_dict() for a in _client(token).list_apps()]


@mcp.tool(description="Get detailed configuration and runtime status of one application by name.")
def get_app(app_name: str, token: AccessToken = CurrentAccessToken()) -> dict:
    return _client(token).get_app(app_name).to_dict()


@mcp.tool(description="Register a new application. 'app' is the application definition (e.g. {\"name\":\"x\",\"command\":\"...\"}).")
def add_app(app: dict, token: AccessToken = CurrentAccessToken()) -> dict:
    return _client(token).add_app(App(app)).to_dict()


@mcp.tool(description="Delete (remove) an application by name.")
def delete_app(app_name: str, token: AccessToken = CurrentAccessToken()) -> dict:
    return {"success": _client(token).delete_app(app_name)}


@mcp.tool(description="Enable an application so it can be scheduled/run.")
def enable_app(app_name: str, token: AccessToken = CurrentAccessToken()) -> dict:
    _client(token).enable_app(app_name)
    return {"success": True}


@mcp.tool(description="Disable an application (stops it and prevents scheduling).")
def disable_app(app_name: str, token: AccessToken = CurrentAccessToken()) -> dict:
    _client(token).disable_app(app_name)
    return {"success": True}


@mcp.tool(description="Check whether an application is healthy. Returns {healthy: bool}.")
def check_app_health(app_name: str, token: AccessToken = CurrentAccessToken()) -> dict:
    return {"healthy": _client(token).check_app_health(app_name)}


@mcp.tool(description="Read incremental stdout/stderr output of an application. Returns output text, next cursor, and exit_code when finished.")
def get_app_output(
    app_name: str,
    stdout_position: int = 0,
    stdout_index: int = 0,
    stdout_maxsize: int = 10240,
    process_uuid: str = "",
    timeout: int = 0,
    token: AccessToken = CurrentAccessToken(),
) -> dict:
    out = _client(token).get_app_output(app_name, stdout_position, stdout_index, stdout_maxsize, process_uuid, timeout)
    return {"status_code": out.status_code, "output": out.output, "output_position": out.output_position, "exit_code": out.exit_code}


@mcp.tool(description="Run a command or application synchronously, blocking until completion. Provide either 'command' (shell command) or 'app' (definition dict). Returns exit_code and stdout.")
def run_app_sync(
    command: Optional[str] = None,
    app: Optional[dict] = None,
    max_time: int = 0,
    token: AccessToken = CurrentAccessToken(),
) -> dict:
    if not command and not app:
        raise ValueError("provide either 'command' or 'app'")
    target = command if command else App(app)
    kwargs = {"max_time": max_time} if max_time else {}
    exit_code, output = _client(token).run_app_sync(target, **kwargs)
    return {"exit_code": exit_code, "output": output}


@mcp.tool(description="Run a command or application asynchronously. Returns app_name and process_uuid to poll with get_app_output. Provide 'command' or 'app'.")
def run_app_async(
    command: Optional[str] = None,
    app: Optional[dict] = None,
    token: AccessToken = CurrentAccessToken(),
) -> dict:
    if not command and not app:
        raise ValueError("provide either 'command' or 'app'")
    definition = App({"command": command, "shell": True}) if command else App(app)
    run = _client(token).run_app_async(definition)
    return {"app_name": run.app_name, "process_uuid": run.process_uuid}


# --------------------------------------------------------------------------- #
# Tasks (long-running app messaging)
# --------------------------------------------------------------------------- #
@mcp.tool(description="Send a task payload to a long-running application and return its response.")
def run_task(app_name: str, data: str, timeout: int = 300, token: AccessToken = CurrentAccessToken()) -> dict:
    return {"result": _client(token).run_task(app_name, data, timeout)}


@mcp.tool(description="Cancel the in-flight task of an application.")
def cancel_task(app_name: str, token: AccessToken = CurrentAccessToken()) -> dict:
    return {"success": _client(token).cancel_task(app_name)}


# --------------------------------------------------------------------------- #
# Host / metrics
# --------------------------------------------------------------------------- #
@mcp.tool(description="Get host resource usage (CPU, memory, disk, network) of the App Mesh host.")
def get_host_resources(token: AccessToken = CurrentAccessToken()) -> dict:
    return _client(token).get_host_resources()


@mcp.tool(description="Get Prometheus-format metrics text from the App Mesh daemon.")
def get_metrics(token: AccessToken = CurrentAccessToken()) -> dict:
    return {"metrics": _client(token).get_metrics()}


# --------------------------------------------------------------------------- #
# Files (the MCP server never touches the bytes — it returns a curl recipe the
# client runs itself, so the transfer streams daemon<->client directly, with no
# file content in MCP memory or the LLM context, and no size limit)
# --------------------------------------------------------------------------- #
def _daemon_public_url() -> str:
    """Daemon URL the CLIENT should hit (may differ from the server-side APPMESH_URL)."""
    return os.environ.get("APPMESH_DAEMON_PUBLIC_URL", appmesh_url()).rstrip("/")


_CURL_TOKEN_NOTE = (
    "Set APPMESH_TOKEN to a Dex access token for the App Mesh API before running. "
    "Add -k if the daemon uses a self-signed certificate."
)


@mcp.tool(description="Return a ready-to-run curl command that downloads a file DIRECTLY from the App Mesh daemon to the client machine. The MCP server never reads the file — bytes stream daemon->client, never entering MCP memory or the LLM context. Works for any size.")
def file_download_command(remote_file: str, local_file: str = "", token: AccessToken = CurrentAccessToken()) -> dict:
    dst = local_file or os.path.basename(remote_file.rstrip("/")) or "download.bin"
    url = _daemon_public_url() + "/appmesh/file/download"
    command = (
        f'curl -fSL -H "Authorization: Bearer $APPMESH_TOKEN" '
        f'-H "X-File-Path: {remote_file}" "{url}" -o "{dst}"'
    )
    return {"command": command, "remote_file": remote_file, "local_file": dst, "note": _CURL_TOKEN_NOTE}


@mcp.tool(description="Return a ready-to-run curl command that uploads a local file DIRECTLY to the App Mesh daemon. The MCP server never reads the file — bytes stream client->daemon, never entering MCP memory. Works for any size.")
def file_upload_command(local_file: str, remote_file: str, token: AccessToken = CurrentAccessToken()) -> dict:
    from urllib.parse import quote

    url = _daemon_public_url() + "/appmesh/file/upload"
    command = (
        f'curl -fSL -X POST -H "Authorization: Bearer $APPMESH_TOKEN" '
        f'-H "X-File-Path: {quote(remote_file)}" -F "file=@{local_file}" "{url}"'
    )
    return {"command": command, "local_file": local_file, "remote_file": remote_file, "note": _CURL_TOKEN_NOTE}


# --------------------------------------------------------------------------- #
# Configuration / labels
# --------------------------------------------------------------------------- #
@mcp.tool(description="Get the App Mesh daemon configuration.")
def get_config(token: AccessToken = CurrentAccessToken()) -> dict:
    return _client(token).get_config()


@mcp.tool(description="Update the App Mesh daemon configuration with the provided partial config dict. Returns the effective config.")
def set_config(config: dict, token: AccessToken = CurrentAccessToken()) -> dict:
    return _client(token).set_config(config)


@mcp.tool(description="Set the daemon log level (e.g. DEBUG, INFO, WARN, ERROR). Returns the effective level.")
def set_log_level(level: str = "DEBUG", token: AccessToken = CurrentAccessToken()) -> dict:
    return {"level": _client(token).set_log_level(level)}


@mcp.tool(description="List all host labels (key/value tags).")
def list_labels(token: AccessToken = CurrentAccessToken()) -> dict:
    return _client(token).list_labels()


@mcp.tool(description="Add or update a host label.")
def add_label(label_name: str, label_value: str, token: AccessToken = CurrentAccessToken()) -> dict:
    _client(token).add_label(label_name, label_value)
    return {"success": True}


@mcp.tool(description="Delete a host label by name.")
def delete_label(label_name: str, token: AccessToken = CurrentAccessToken()) -> dict:
    _client(token).delete_label(label_name)
    return {"success": True}


# --------------------------------------------------------------------------- #
# Principals / RBAC
# --------------------------------------------------------------------------- #
@mcp.tool(description="Get the current Dex principal and its App Mesh authorization overlay.")
def get_current_principal(token: AccessToken = CurrentAccessToken()) -> dict:
    return _client(token).get_current_principal()


@mcp.tool(description="List App Mesh authorization principals. This does not list identity-provider users.")
def list_principals(token: AccessToken = CurrentAccessToken()) -> dict:
    return _client(token).list_principals()


@mcp.tool(description="Create or update roles, status, and execution mapping for a Dex principal.")
def update_principal(principal_id: str, principal_data: dict, token: AccessToken = CurrentAccessToken()) -> dict:
    _client(token).update_principal(principal_id, principal_data)
    return {"success": True}


@mcp.tool(description="Delete an App Mesh principal policy. This never deletes an identity-provider user.")
def delete_principal(principal_id: str, token: AccessToken = CurrentAccessToken()) -> dict:
    _client(token).delete_principal(principal_id)
    return {"success": True}


@mcp.tool(description="List all permission IDs defined in the system.")
def list_permissions(token: AccessToken = CurrentAccessToken()) -> dict:
    return {"permissions": _client(token).list_permissions()}


@mcp.tool(description="List the current principal's effective permissions.")
def get_principal_permissions(token: AccessToken = CurrentAccessToken()) -> dict:
    return {"permissions": _client(token).get_principal_permissions()}


@mcp.tool(description="List all roles and their permission sets.")
def list_roles(token: AccessToken = CurrentAccessToken()) -> dict:
    return _client(token).list_roles()


@mcp.tool(description="Create or update a role with the given permission list.")
def update_role(role_name: str, permission_set: list, token: AccessToken = CurrentAccessToken()) -> dict:
    _client(token).update_role(role_name, permission_set)
    return {"success": True}


@mcp.tool(description="Delete a role by name.")
def delete_role(role_name: str, token: AccessToken = CurrentAccessToken()) -> dict:
    _client(token).delete_role(role_name)
    return {"success": True}


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    host = os.environ.get("APPMESH_MCP_HOST", "0.0.0.0")
    port = int(os.environ.get("APPMESH_MCP_PORT", "6071"))

    run_kwargs = {"transport": "http", "host": host, "port": port}

    # Optional TLS for the MCP endpoint (recommended for remote clients).
    cert = os.environ.get("APPMESH_MCP_TLS_CERT")
    key = os.environ.get("APPMESH_MCP_TLS_KEY")
    if cert and key:
        run_kwargs["uvicorn_config"] = {"ssl_certfile": cert, "ssl_keyfile": key}

    logger.info("Starting App Mesh MCP Server (Streamable HTTP) on %s:%s", host, port)
    mcp.run(**run_kwargs)
