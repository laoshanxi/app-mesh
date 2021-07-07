
# LDAP integration

------

JWT authentication integrate with LDAP, user login provide password to verify from LDAP and then response with JWT token, the follow-up authentication with JWT token do not connect LDAP Server.

LDAP user organization

![phpldapadmin](https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/ldap.png)

Start LDAP service with Docker container

```
docker run --name ldap-service --hostname ldap-host -p 389:389 -p 636:636 --detach osixia/openldap
docker run --name phpldapadmin-service -p 443:443 --hostname phpldapadmin-service --link ldap-service:ldap-host --env PHPLDAPADMIN_LDAP_HOSTS=ldap-host --detach osixia/phpldapadmin
```


