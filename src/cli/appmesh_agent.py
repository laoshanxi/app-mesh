# appmesh_agent.py
#!/usr/bin/env python3
"""
Kubernetes proxy container for launch native application in App Mesh.
Passes user commands to native App Mesh to launch applications outside
the Docker container while maintaining monitoring and lifecycle management.
"""

import socket
import sys
import warnings
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning

import appmesh

# Suppress SSL warnings for internal connections
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Configuration
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin123"


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


def create_monitor_app(shadow_app_name, monitor_app_name):
    """Create the monitor application configuration."""
    return appmesh.App(
        {
            "name": monitor_app_name,
            "command": f"python3 /opt/appmesh/script/container_monitor.py {shadow_app_name} {monitor_app_name}",
            "behavior": {"exit": "remove"},
        }
    )


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
        # Initialize appmesh
        appmesh_client = appmesh.AppMeshClient()
        appmesh_client.login(DEFAULT_USERNAME, DEFAULT_PASSWORD)

        # Start monitor application
        monitor_app = create_monitor_app(native_app_name, monitor_app_name)
        appmesh_client.run_app_async(app=monitor_app)

        # Start shadow application
        native_app = create_native_app(native_app_name, command)
        run_handle = appmesh_client.run_app_async(app=native_app)

        # Wait shadow application exit
        exit_code = appmesh_client.wait_for_async_run(run_handle)
        sys.exit(exit_code)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
