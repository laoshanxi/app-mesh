#!/usr/bin/python3
# Example for App Mesh Client.
# Install appmesh package: python3 -m pip install --upgrade appmesh

import os
from time import sleep
from appmesh import AppMeshClient, App, OAuthClient

# Engine traffic and authentication traffic are separate routes, even on one node.
engine_url = os.environ.get("APPMESH_ENGINE_URL", "https://127.0.0.1:6060")
auth_access_url = os.environ.get("APPMESH_AUTH_ACCESS_URL", "http://127.0.0.1:6062/auth")
engine_ca = os.environ.get("APPMESH_ENGINE_CA")
auth_ca = os.environ.get("APPMESH_AUTH_CA_PATH")
client = AppMeshClient(
    base_url=engine_url,
    # None retains the SDK's installed App Mesh CA auto-detection.
    ssl_verify=engine_ca or None,
    bearer_token=os.environ.get("APPMESH_BEARER_TOKEN"),
)


def oauth_client():
    """Build OAuth discovery against the selected authentication route."""
    return OAuthClient.from_appmesh(
        client,
        access_url=auth_access_url,
        ssl_verify=auth_ca or True,
    )


def demo_task_execute():
    """Run a simple remote task 10 times, using the previous result as input."""
    count_in_server = "0"
    for i in range(10):
        task_data = f"print({count_in_server} + {i}, end='')"
        count_in_server = client.run_task(app_name="py-task", data=task_data)
        print(count_in_server)


def demo_app_mgmt():
    """Show basic app management: add, view, enable, get output, and delete."""
    myapp = App()
    myapp.name = "myapp"
    myapp.status = 0  # 0 = disabled
    myapp.command = "ping cloudflare.com"

    # Add app
    print("Application added:", client.add_app(myapp))

    # View app details
    print("Application details:", client.get_app(myapp.name))

    # Enable and wait
    client.enable_app(myapp.name)
    sleep(3)

    # Get and print output
    output = client.get_app_output(myapp.name, timeout=3)
    print("Application output:\n", output.output)

    # Clean up
    print("Application deleted:", client.delete_app(myapp.name))


if __name__ == "__main__":
    print("Start sample...")
    demo_app_mgmt()
    demo_task_execute()
    print("Completed sample")
