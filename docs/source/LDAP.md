
# LDAP integration

------

JWT authentication integrate with LDAP, user login provide password to verify from LDAP and then response with JWT token, the follow-up authentication with JWT token do not connect LDAP Server.

LDAP user organization

![phpldapadmin](https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/ldap.png)

Start LDAP service with Docker container

```
docker run --restart=always --name ldap-appmesh --hostname ldap-appmesh -p 389:389 -p 636:636 --detach osixia/openldap

docker run --restart=always --name ldap-appmesh-ui -p 443:443 --hostname ldap-appmesh-ui --link ldap-appmesh:ldap-appmesh --env PHPLDAPADMIN_LDAP_HOSTS=ldap-appmesh --detach osixia/phpldapadmin
```

Open https://<docker-host-name>, login with "cn=admin,dc=example,dc=org":"admin" and choose "import" to init LDAP group and users from file [ldif](https://raw.githubusercontent.com/laoshanxi/app-mesh/main/src/daemon/security/ldapplugin/ldap_export.ldif).
