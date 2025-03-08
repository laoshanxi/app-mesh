# Security

App Mesh acts as enterprise middleware, implementing security at multiple levels to provide a secure platform.

## Security Concepts

### User

App Mesh has built-in user management. Each user can define a process execution OS user for application execution. Each user has:

* Password
* MFA key
* Roles

```bash
$ appc user
{
  "email": "admin@appmesh.com",
  "exec_user": "root",
  "group": "admin",
  "locked": false,
  "mfa_enabled": false,
  "name": "admin",
  "roles": [
    "manage",
    "shell",
    "usermgr",
    "view"
  ]
}
```

### RBAC

App Mesh implements role-based access control (RBAC). Users are assigned roles, each containing specific permissions. Every API request undergoes user password verification and permission checks.

### Multi-tenant Applications

Applications managed by App Mesh can define access permissions for other users and groups. You can:

* Register an application visible only to yourself.
* Register an application for your user group.

## Security Data Storage

### Local YAML File

App Mesh uses a local YAML file `security.yaml` to persist all user definitions. This file can only be read and written by the root user.

### Consul User/Role

App Mesh supports storing security content in Consul, enabling all App Mesh instances to share centralized user information.

### LDAP

App Mesh supports LDAP integration for user information management.

### OAuth2

App Mesh supports Keycloak OIDC authentication.

## REST

### SSL

SSL is enabled by default for REST services to ensure secure communication. You can configure custom SSL certificate files.

### JWT Authentication

All REST methods require authentication by default. JWT authentication protects APIs, with each user having role-based permissions to access corresponding methods.

#### JWT Sign Algorithm

App Mesh supports two JWT signing algorithms:

* HS256 - Uses JWTSalt as the secret key
* RS256 - Uses public and private PEM key files for signing
* ES256 - Uses public and private PEM key files with ECDSA algrithom


### PSK (Pre-Shared Key)

Non-user client requests are authenticated through PSK verification.

## Encryption

### Encrypt Application Environment

For applications requiring confidential information, encrypted environment variables can be used to store sensitive data.

### Encrypt User Password

Password encryption is supported, allowing storage of encrypted passwords in YAML or Consul.

## Reference

* [User Role](https://app-mesh.readthedocs.io/en/latest/USER_ROLE.html)
* [JWT](https://app-mesh.readthedocs.io/en/latest/JWT.html)
* [MFA](https://app-mesh.readthedocs.io/en/latest/MFA.html)
