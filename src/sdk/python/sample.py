#!/usr/bin/python3
# Install App Mesh client library if not already installed:
# python3 -m pip install --upgrade appmesh

from time import sleep
from appmesh import appmesh_client


def main():
    # Initialize the App Mesh Client
    client = appmesh_client.AppMeshClient()

    # Authenticate with App Mesh using username and password
    success = client.login("admin", "admin123")
    if success:
        # Define a new application with name, status, and command to execute
        myapp = appmesh_client.App()
        myapp.name = "myapp"
        myapp.status = 0  # Indicates the app is initially disabled
        myapp.command = "ping github.com"

        # Add the application to App Mesh
        print(client.app_add(myapp))

        # View details of the added application
        print(client.app_view(myapp.name))

        print(myapp.json())
        # Enable the application to start running
        client.app_enable(myapp.name)
        sleep(2)  # Wait briefly to allow the app to start

        # Retrieve and print the application output with a 3-second timeout
        out = client.app_output(myapp.name, timeout=3)
        print(out.output)

        # Delete the application after viewing the output
        print(client.app_delete(myapp.name))
    else:
        print("Login failed. Check credentials.")


if __name__ == "__main__":
    main()
