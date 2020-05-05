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
POST| /login | username=base64(uname) <br> password=base64(passwd) <br> Optional: <br> expire_seconds=600 | JWT authenticate login, the max expire_seconds is 24h

The REST will response bellow json when authentication success:

```json
{
	"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NzA3MDc3NzYsImlhdCI6MTU3MDcwNzE3NiwiaXNzIjoiYXBwbWdyLWF1dGgwIiwibmFtZSI6ImFkbWluIn0.CF_jXy4IrGpl0HKvM8Vh_T7LsGTGO-K73OkRxQ-BFF8",
	"expire_time": 1570707176508714400,
	"profile": {
		"auth_time": 1570707176508711100,
		"name": "admin"
	},
	"token_type": "Bearer"
}
```

| response   |  desc   | 
| --------   | -----  |
| access_token     | JWT token content |
| expire_time |  UTC time seconds the token will expire, is the server time  add the input expire_seconds| 
| auth_time | the server UTC time seconds |
| token_type | JWT standard "Bearer" | 


### Use JWT token for REST request

Method | URI | Body/Headers | Desc
---|---|---|---
POST| /auth/$uname | curl -X POST -k -H "Authorization:Bearer \$jwt_token" https://127.0.0.1:6060/auth/admin | JWT token authenticate