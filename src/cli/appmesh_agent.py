# appmesh_agent.py
#!/usr/bin/env python3
"""
Kubernetes proxy container for launch native application in App Mesh.
Passes user commands to native App Mesh to launch applications outside
the Docker container while maintaining monitoring and lifecycle management.
"""

import os
import socket
import sys
import warnings
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning

import appmesh

# Suppress SSL warnings for internal connections
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

DEFAULT_TOKEN_URL = "https://127.0.0.1:6060/auth/token"
DEFAULT_USERNAME = "admin@appmesh.local"
# Container-side default; mounted from a node-local file via hostPath.
DEFAULT_PASSWORD_FILE = "/run/appmesh/agent-password"


def get_shadow_app_name():
    """
    Get the shadow application name.

    Returns container ID if running in Docker with cidfile,
    otherwise returns hostname.

    # for host mode networking, use cidfile solution to pass container id here
    # docker run --cidfile=/tmp/container.id -v /tmp/container.id:/tmp/container.id ${IMAGE}
    # https://stackoverflow.com/questions/26979038/how-to-get-container-name-from-inside-docker-io
    """
    container_id_file = "/tmp/container.id"
    if Path(container_id_file).exists():
        try:
            with open(container_id_file, "r", encoding="utf-8") as f:
                return f.readline().strip()
        except (IOError, OSError) as e:
            print(f"Warning: Could not read container ID file: {e}", file=sys.stderr)

    return socket.gethostname()


def build_client_and_monitor_env():
    """
    Build an authenticated App Mesh client and the monitor environment.

    Two authentication modes:

    - APPMESH_BEARER_TOKEN is set: use the token as-is until it expires
      (15 minutes). Suitable for short jobs only.
    - Otherwise: password grant against the node-local authentication
      service, with automatic re-authentication on expiry or 401. The
      password is read from APPMESH_AGENT_PASSWORD_FILE (default
      /run/appmesh/agent-password), never from an environment variable, so
      it cannot leak into `docker inspect`, pod specs, or CI logs.

    Returns (appmesh_client, monitor_env) where monitor_env maps names to
    (value, secure) pairs. Only non-secret settings are passed to the
    monitor in password mode: the monitor re-authenticates on the host from
    its own node-local password file when the container exits.
    """
    bearer_token = os.environ.get("APPMESH_BEARER_TOKEN")
    if bearer_token:
        # The daemon spawns the monitor on the host; secret_env passes the
        # bearer without storing the token in plaintext.
        appmesh_client = appmesh.AppMeshClient(ssl_verify=False, bearer_token=bearer_token)
        return appmesh_client, {"APPMESH_BEARER_TOKEN": (bearer_token, True)}

    username = os.environ.get("APPMESH_AGENT_USERNAME", DEFAULT_USERNAME)
    password_file = os.environ.get("APPMESH_AGENT_PASSWORD_FILE", DEFAULT_PASSWORD_FILE)
    token_url = os.environ.get("APPMESH_AGENT_TOKEN_URL", DEFAULT_TOKEN_URL)
    # The container image has no CA bundle and the node agent uses a
    # self-signed cert; the token endpoint is node-local loopback.
    provider = appmesh.PasswordGrantProvider(
        token_url=token_url,
        username=username,
        password_file=password_file,
        ssl_verify=False,
    )
    # Fail fast on unreadable password file or bad credentials before
    # registering any application on the host.
    provider.get_access_token()
    appmesh_client = appmesh.AppMeshClient(ssl_verify=False, token_provider=provider)

    monitor_env = {
        "APPMESH_AGENT_USERNAME": (username, False),
        "APPMESH_AGENT_TOKEN_URL": (token_url, False),
    }
    host_password_file = os.environ.get("APPMESH_AGENT_HOST_PASSWORD_FILE")
    if host_password_file:
        monitor_env["APPMESH_AGENT_PASSWORD_FILE"] = (host_password_file, False)
    return appmesh_client, monitor_env


def create_monitor_app(shadow_app_name, monitor_app_name, monitor_env):
    """Create the monitor application configuration."""
    monitor_app = appmesh.App(
        {
            "name": monitor_app_name,
            "command": f"python3 /opt/appmesh/script/container_monitor.py {shadow_app_name} {monitor_app_name}",
            "behavior": {"exit": "remove"},
        }
    )
    for key, (value, secure) in monitor_env.items():
        monitor_app.set_env(key, value, secure=secure)
    return monitor_app


def create_native_app(name, command):
    """
    Create the shadow application configuration.

    # TODO: pass container mem/cpu limitation to App Mesh
    # TODO: pass container specific Environments to App Mesh
    """
    return appmesh.App(
        {
            "name": name,
            "command": command,
            "shell": True,
        }
    )


def main():
    """Main execution function."""
    if len(sys.argv) < 2:
        print("Usage: script.py <command> [args...]", file=sys.stderr)
        sys.exit(1)

    # Generate unique monitor name and get shadow name
    native_app_name = get_shadow_app_name()
    monitor_app_name = f"{native_app_name}-SIDE-CAR"

    # Prepare command from arguments
    command = " ".join(sys.argv[1:])

    try:
        appmesh_client, monitor_env = build_client_and_monitor_env()

        # Start monitor application
        monitor_app = create_monitor_app(native_app_name, monitor_app_name, monitor_env)
        appmesh_client.run_app_async(app=monitor_app)

        # Start shadow application
        native_app = create_native_app(native_app_name, command)
        run_handle = appmesh_client.run_app_async(app=native_app)

        # Wait shadow application exit, relaying its stdout to container stdout (pod logs)
        exit_code = appmesh_client.wait_for_async_run(run_handle, stdout_handler=appmesh.print_output_handler)
        sys.exit(exit_code)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
