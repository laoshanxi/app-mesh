# container_monitor.py
#!/usr/bin/env python3
"""Monitor a Docker container and clean up the corresponding App Mesh applications when it exits."""

import os
import sys

# python3 -m pip install --upgrade appmesh docker
from appmesh import AppMeshClient
import docker

DEFAULT_TOKEN_URL = "https://127.0.0.1:6060/auth/token"
DEFAULT_USERNAME = "admin@appmesh.local"
# Node-local password file on the host (mode 600, root-owned), provisioned
# per node. The container agent never sends the password itself.
DEFAULT_HOST_PASSWORD_FILE = "/etc/appmesh/agent-password"


def create_appmesh_client():
    """Create an authenticated App Mesh client for cleanup.

    - APPMESH_BEARER_TOKEN is set: use the token as-is (short jobs).
    - Otherwise: the container may outlive the 15-minute token by far, so
      re-authenticate at cleanup time with the password grant against the
      node-local authentication service. The password is read from
      APPMESH_AGENT_PASSWORD_FILE (default /etc/appmesh/agent-password on
      the host), never from an environment variable.
    """
    bearer_token = os.environ.get("APPMESH_BEARER_TOKEN")
    if bearer_token:
        return AppMeshClient(bearer_token=bearer_token)

    username = os.environ.get("APPMESH_AGENT_USERNAME", DEFAULT_USERNAME)
    token_url = os.environ.get("APPMESH_AGENT_TOKEN_URL", DEFAULT_TOKEN_URL)
    password_file = os.environ.get("APPMESH_AGENT_PASSWORD_FILE", DEFAULT_HOST_PASSWORD_FILE)
    with open(password_file, "r", encoding="utf-8") as f:
        password = f.read().rstrip("\r\n")

    appmesh_client = AppMeshClient()
    # Use the client's resolved CA (packaged self-signed CA when present) so
    # the grant trusts the same endpoint as the Engine connection.
    response = appmesh_client.session.post(
        token_url,
        auth=("appmesh-cli", ""),
        data={
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": "openid audience:server:client_id:appmesh-api",
        },
        verify=appmesh_client.ssl_verify,
        timeout=appmesh_client.request_timeout,
    )
    response.raise_for_status()
    appmesh_client.set_bearer_token(response.json()["access_token"])
    return appmesh_client


def main():
    """Main function to monitor container and cleanup applications."""
    # Validate command line arguments
    if len(sys.argv) < 2:
        print("Usage: script.py <container_name> [app_names...]")
        sys.exit(1)

    container_name = sys.argv[1]
    app_names = sys.argv[1:]  # Include container name and any additional app names

    # Initialize Docker client
    docker_client = docker.APIClient(base_url="unix://var/run/docker.sock")

    # Wait for container to finish
    print(f"Monitoring container: {container_name}")
    try:
        # https://docker-py.readthedocs.io/en/stable/containers.html#docker.models.containers.Container.wait
        result = docker_client.wait(container_name)
        print(f"Container exited with status: {result}")
    except Exception as error:
        print(f"Error waiting for container: {error}")

    # Clean up App Mesh applications
    try:
        appmesh_client = create_appmesh_client()

        for app in app_names:
            print(f"Deleting App Mesh application: {app}")
            appmesh_client.delete_app(app_name=app)

    except Exception as error:
        print(f"Error cleaning up App Mesh applications: {error}")
        sys.exit(1)

    print("Cleanup completed successfully")


if __name__ == "__main__":
    main()
