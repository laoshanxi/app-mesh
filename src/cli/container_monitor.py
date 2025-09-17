# container_monitor.py
#!/usr/bin/env python3
"""Monitor a Docker container and clean up the corresponding App Mesh applications when it exits."""

import sys

# python3 -m pip install --upgrade appmesh docker
from appmesh import AppMeshClient
import docker

# Configuration
DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin123"


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
        appmesh_client = AppMeshClient()
        appmesh_client.login(DEFAULT_USERNAME, DEFAULT_PASSWORD)

        for app in app_names:
            print(f"Deleting App Mesh application: {app}")
            appmesh_client.delete_app(app_name=app)

    except Exception as error:
        print(f"Error cleaning up App Mesh applications: {error}")
        sys.exit(1)

    print("Cleanup completed successfully")


if __name__ == "__main__":
    main()
