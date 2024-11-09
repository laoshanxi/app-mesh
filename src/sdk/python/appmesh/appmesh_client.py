# appmesh_client.py

# Legacy Compatibility Layer
# These imports provide backward compatibility for older code that relies on
# AppMeshClient, App, and AppOutput classes. The updated implementation can be found
# in http_client.py, where these classes are now primarily maintained.

from .http_client import AppMeshClient, App, AppOutput
