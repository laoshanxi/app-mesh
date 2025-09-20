# appmesh_client.py

# Legacy Compatibility Layer
# These imports provide backward compatibility for older code that relies on
# AppMeshClient, App, and AppOutput classes. The updated implementation can be found
# in client_http.py, where these classes are now primarily maintained.

from .client_http import AppMeshClient
from .app import App
from .app_output import AppOutput
