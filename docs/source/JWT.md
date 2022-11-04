# JWT authentication  ![jwt-logo](https://jwt.io/img/pic_logo.svg)
[JSON Web Tokens](https://jwt.io/)

------

JSON Web Tokens are an open, industry standard RFC 7519 method for representing claims securely between two parties.

![jwt_auth_process](https://cdn2.auth0.com/docs/media/articles/api-auth/client-credentials-grant.png)

What is supported:

> * REST login use JWT standard
> * Support local JSON based user management and LDAP users
> * Provide login and auth API to run as a stand-alone JWT server
> * Support centralized user & role DB server by Consul

What is **not** supported:
> * Redirect authentication to another JWT server is not supported


### GET JWT token

| Method | URI            | Body/Headers                                                                               | Desc                                                  |
| ------ | -------------- | ------------------------------------------------------------------------------------------ | ----------------------------------------------------- |
| POST   | /appmesh/login | Username=base64(uname) <br> Password=base64(passwd) <br> Optional: <br> Expire-Seconds=600 | JWT authenticate login, the max Expire-Seconds is 24h |

```shell
curl -X POST -k -s -H "Username:$(echo -n user | base64)" -H "Password:$(echo -n Password | base64)" -H "Expire-Seconds:2" https://localhost:6060/appmesh/login | python -m json.tool
```
The REST will response bellow json when authentication success:

```json
{
	"Access-Token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MDU5MjA1NjQsImlhdCI6MTYwNTMxNTc2NCwiaXNzIjoiYXBwbWVzaC1hdXRoMCIsIm5hbWUiOiJhZG1pbiJ9.hPOGoU5cl8TexQKyUnKpSi4r9Hy0Vhi03A-mCyQfpXw",
	"expire_seconds": 604800,
	"expire_time": 1605920564,
	"profile": {
		"auth_time": 1605315764,
		"name": "admin"
	},
	"token_type": "Bearer"
}
```

| response     | desc                                                                                       |
| ------------ | ------------------------------------------------------------------------------------------ |
| Access-Token | JWT token content                                                                          |
| expire_time  | UTC time (seconds) the token will expire, is the server time plus the input Expire-Seconds |
| auth_time    | the server UTC time (seconds)                                                              |
| token_type   | JWT standard "Bearer"                                                                      |


### Use JWT token for REST request

| Method | URI           | Body/Headers                                                                                    | Desc                   |
| ------ | ------------- | ----------------------------------------------------------------------------------------------- | ---------------------- |
| POST   | /appmesh/auth | headers: <br> Authorization=Bearer token_str  <br> Optional: <br> Auth-Permission=permission-id | JWT token authenticate |

```shell
curl -s -X POST -k -H "Authorization:Bearer $jwt_token" -H "Auth-Permission:app-view"  https://127.0.0.1:6060/appmesh/auth | python -m json.tool
```
The REST will response bellow json when authentication success:
```json
{
    "permission": "app-view",
    "success": true,
    "user": "mesh"
}
```

### Deploy an JWT server with SSL certificate

```yaml
version: "3"

services:

  jwt_appmesh:
    image: laoshanxi/appmesh:2.1.1
    hostname: www.appmesh.com
    restart: always
    volumes:
     - /etc/ssl/ca-bundle.pem:/opt/appmesh/ssl/ca.pem
     - ./server.pem:/opt/appmesh/ssl/server.pem
     - ./server-key.pem:/opt/appmesh/ssl/server-key.pem
     - ./security.json:/opt/appmesh/security.json:rw
    ports:
     - "7660:6060"
    environment:
     - APPMESH_REST_RestListenAddress=www.appmesh.com


  jwt_appmesh_ui:
    image: laoshanxi/appmesh-ui:2.1.1
    restart: always
    volumes:
     - ./server.pem:/etc/nginx/conf.d/server.crt
     - ./server-key.pem:/etc/nginx/conf.d/server.key
    ports:
     - "7666:443"
    environment:
     - APP_MESH_SERVER_HOST=www.appmesh.com
    links:
      - jwt_appmesh
    depends_on:
      - jwt_appmesh
```
