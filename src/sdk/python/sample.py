#!/usr/bin/python3
# Example for App Mesh Client.
# Install appmesh package: python3 -m pip install --upgrade appmesh

from time import sleep
from appmesh import AppMeshClient, App

client = AppMeshClient()
client.login("admin", "admin123")


def demo_task_execute():
    """Run a simple remote task 10 times, using the previous result as input."""
    count_in_server = "0"
    for i in range(10):
        task_data = f"print({count_in_server} + {i}, end='')"
        count_in_server = client.run_task(app_name="pytask", data=task_data)
        print(count_in_server)


def demo_app_mgmt():
    """Show basic app management: add, view, enable, get output, and delete."""
    myapp = App()
    myapp.name = "myapp"
    myapp.status = 0  # 0 = disabled
    myapp.command = "ping github.com"

    # Add app
    print("Application added:", client.add_app(myapp))

    # View app details
    print("Application details:", client.view_app(myapp.name))

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
