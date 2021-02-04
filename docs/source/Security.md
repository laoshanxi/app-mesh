App Mesh act as an enterprise middleware, security is considered in multiple places to provide enterprise secure platform.

## 1. Data Storage
#### Configuration JSON file
App Mesh use a local JSON file to persist all configuration parameters and all application/user definition contents, the JSON file can be only read/write by root user.

#### Consul user/role
App Mesh support use local JSON file for user/role storage, and also support save user/role information in Consul, with this all App Mesh can share a centralized user info.

#### User Password
App Mesh support encrypt user password for persist, you can store encrypted password in JSON or Consul.

## 2. REST
#### SSL
SSL is enabled by default for REST service to provide secure communication, you can also config to use your own SSL cert files.

#### JWT Authentication
All REST Methods require authentication by default, JWT authentication was used to protect APIs, each user can have its own role with permissions to access corresponding methods.

## 3. Multi tenant
#### Multi tenant applications
Applications managed by App Mesh can define access permissions for other user and other groups, you can register an application only visible for yourself, or you can also register an application for your user group.
Refer to command line: appc reg "--perm" parameter

#### Encrypt application information
If application need some confidential information, you can use encrypted environment variables to store those confidential information.
