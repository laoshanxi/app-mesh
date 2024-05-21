# Standalone JWT server

JWT authentication is a popular authentication method for HTTP service and client, App Mesh implemented a JWT Server with RBAC (role based access control) and this service can be used to build a JWT server for other systems. detail design refer to [JWT Design](https://app-mesh.readthedocs.io/en/latest/JWT.html)

## Solution

### App Mesh can manage bellow concepts

1. Users
2. Roles
3. Groups
4. Permissions

### Bellow APIs for security

Index | Method | URI | Body/Headers | Desc
---|---|---|---|---
1 |POST| /appmesh/login | Authorization=Basic base64(NAME:PASSWD) <br> Optional: <br> Expire-Seconds=600 | JWT authenticate login
2 |POST| /appmesh/auth | curl -X POST -k -H "Authorization:Bearer <JWT_TOKEN>" <https://127.0.0.1:6060/appmesh/auth> <br> Optional: <br> Auth-Permission=permission_id | JWT token and permission authenticate
3 |POST| /appmesh/user/admin/passwd | New-Password=base64(passwd) | Change user password
4 |POST| /appmesh/user/usera/lock | | admin user to lock usera
5 |POST| /appmesh/user/usera/unlock | | admin user to unlock usera
6 |PUT | /appmesh/user/usera | | Add usera to Users
7 |DEL | /appmesh/user/usera | | Delete usera
8 |GET | /appmesh/users | | Get user list
9 |GET | /appmesh/roles | | Get role list
10 |POST| /appmesh/role/roleA | | Update roleA with defined permissions
11 |DELETE| /appmesh/role/roleA | | Delete roleA
12 |GET | /appmesh/user/permissions |  | Get user self permissions, user token is required in header
13 |GET | /appmesh/permissions |  | Get all permissions
14 |GET | /appmesh/user/groups |  | Get all user groups

### Manage

Other system can call the 10th API to define `Roles` and `Permissions`, and call 6th API to define user with corresponding role.

### Authenticate

System login and permission can all forward to App Mesh 1st and 2nd API to do the authentication.

### UI

All those managements API can be operated by [UI](https://github.com/laoshanxi/app-mesh-ui)

### Deploy a JWT server with SSL certificate

`compose.yml`

```yaml
version: "3"

services:

  jwt_appmesh:
    image: laoshanxi/appmesh:latest
    hostname: www.appmesh.com
    restart: always
    volumes:
     - /etc/ssl/ca-bundle.pem:/opt/appmesh/ssl/ca.pem
     - ./server.pem:/opt/appmesh/ssl/server.pem
     - ./server-key.pem:/opt/appmesh/ssl/server-key.pem
     - ./security.yaml:/opt/appmesh/security.yaml:rw
    ports:
     - "6060:6060"
    environment:
     - APPMESH_REST_RestListenAddress=www.appmesh.com


  jwt_appmesh_ui:
    image: laoshanxi/appmesh-ui:latest
    restart: always
    volumes:
     - ./server.pem:/etc/nginx/conf.d/server.crt
     - ./server-key.pem:/etc/nginx/conf.d/server.key
    ports:
     - "8443:443"
    environment:
     - APP_MESH_SERVER_HOST=www.appmesh.com
    links:
      - jwt_appmesh
    depends_on:
      - jwt_appmesh
```
