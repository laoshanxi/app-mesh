# Secure REST file server
App Mesh provide file download/upload REST APIs, also those APIs can be authenticated by JWT.

## Solution
Use below API to manage file:
Method | URI | Body/Headers | Desc
---|---|---|---
GET | /appmesh/file/download | Header: <br> FilePath=/opt/remote/filename | Download a file from REST server and grant permission
POST| /appmesh/file/upload | Header: <br> FilePath=/opt/remote/filename <br> Body: <br> file steam | Upload a file to REST server and grant permission

* The simple way is use [Python SDK](https://github.com/laoshanxi/app-mesh/blob/main/src/sdk/python/appmesh_client.py)
* Use appmesh cli is also fine: `appc put -l /opt/appmesh/log/appsvc.log -r /tmp/1.log`