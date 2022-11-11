#!/usr/bin/python3
import json
import sys

"""
install dependencies for SDK
  python -m pip install --exists-action=w --no-cache-dir --requirement /opt/appmesh/sdk/requirements.txt
"""

# import SDK
sys.path.append("/opt/appmesh/sdk/")
import appmesh_client

def main():
    # Create a App Mesh Client object
    client = appmesh_client.AppMeshClient()
    # Authenticate
    token = client.login("admin", "admin123")
    if token:
        # call SDK to view application 'ping'
        print(json.dumps(client.app_view("ping"), indent=2))

if __name__ == "__main__":
    main()
