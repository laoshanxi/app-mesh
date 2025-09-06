"""Example for App Mesh Client."""

#!/usr/bin/python3
# Ensure you have the App Mesh client library installed:
# python3 -m pip install --upgrade appmesh

from time import sleep
from appmesh import AppMeshClient, App


def main() -> None:
    """Demonstrate basic usage of the App Mesh Client SDK."""

    # Initialize the App Mesh Client
    client = AppMeshClient()

    # Authenticate with App Mesh using username and password
    if client.login("admin", "admin123"):

        # Demonstrate remote task execution
        count_in_server = "0"
        for i in range(10):
            # task data
            task_data = f"print({count_in_server}+{i}, end='')"
            # remote invoke and get result
            count_in_server = client.run_task(app_name="pytask", data=task_data)
            # print
            print(count_in_server)

        # Define a new application with name, status, and command to execute
        myapp = App()
        myapp.name = "myapp"
        myapp.status = 0  # Indicates the app is initially disabled
        myapp.command = "ping github.com"

        # Add the application to App Mesh
        response = client.add_app(myapp)
        print("Application added:", response)

        # View details of the added application
        app_details = client.view_app(myapp.name)
        print("Application details:", app_details)

        # Enable the application to start running
        client.enable_app(myapp.name)
        sleep(3)  # Wait briefly to allow the app to start

        # Retrieve and print the application output with a 3-second timeout
        output_response = client.get_app_output(myapp.name, timeout=3)
        print("Application output:\n", output_response.output)

        # Delete the application after viewing the output
        delete_response = client.delete_app(myapp.name)
        print("Application deleted:", delete_response)
    else:
        print("Login failed. Check credentials.")


if __name__ == "__main__":
    main()
