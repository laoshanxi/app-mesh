#!/usr/bin/python3
# python3 -m pip install --upgrade appmesh
from appmesh import appmesh_client


def main():
    # Create a App Mesh Client object
    client = appmesh_client.AppMeshClient()
    # Authenticate
    token = client.login("admin", "admin123")
    if token:
        # call SDK to view application 'ping'
        print(client.app_view("ping"))


if __name__ == "__main__":
    main()
