# JWT authentication  ![jwt-logo](https://jwt.io/img/pic_logo.svg)
[JSON Web Tokens](https://jwt.io/)

------

JSON Web Tokens are an open, industry standard RFC 7519 method for representing claims securely between two parties.

![jwt_auth_process](https://cdn2.auth0.com/docs/media/articles/api-auth/client-credentials-grant.png)

What is supported:

> * REST login use JWT standard
> * Provide login and auth API to run as a stand-alone JWT server
> * Support centerized  user & role DB server by Consul

What is **not** supported:
> * Redirect authentication to another JWT server is not suported
> * LDAP is not supported


### GET JWT token

Method | URI | Body/Headers | Desc
---|---|---|---
POST| /appmgr/login | username=base64(uname) <br> password=base64(passwd) <br> Optional: <br> expire_seconds=600 | JWT authenticate login, the max expire_seconds is 24h

```shell
curl -X POST -k -s -H "username:$(echo -n user | base64)" -H "password:$(echo -n password | base64)" -H "expire_seconds:2" https://localhost:6060/appmgr/login | python -m json.tool
```
The REST will response bellow json when authentication success:

```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1ODg5Mjc1MTgsImlhdCI6MTU4ODkyNzUxNiwiaXNzIjoiYXBwbWdyLWF1dGgwIiwibmFtZSI6InVzZXIifQ.MRK0MH3hBw0ZbcIbSEtynFMkHSca2SYCCziX24VdT0w",
    "expire_time": 1588927516172435071,
    "profile": {
        "auth_time": 1588927516172426859,
        "name": "user"
    },
    "token_type": "Bearer"
}
```

| response   |  desc   | 
| --------   | -----  |
| access_token     | JWT token content |
| expire_time |  UTC time millisecond the token will expire, is the server time add the input expire_seconds| 
| auth_time | the server UTC time millisecond |
| token_type | JWT standard "Bearer" | 


### Use JWT token for REST request

Method | URI | Body/Headers | Desc
---|---|---|---
POST| /appmgr/auth | headers: <br> Authorization=Bearer token_str  <br> Optional: <br> auth_permission=permission-id | JWT token authenticate

```shell
curl -s -X POST -k -H "Authorization:Bearer $jwt_token" -H "auth_permission:app-view"  https://127.0.0.1:6060/appmgr/auth | python -m json.tool
```
The REST will response bellow json when authentication success:
```json
{
    "permission": "app-view",
    "success": true,
    "user": "user"
}
```

