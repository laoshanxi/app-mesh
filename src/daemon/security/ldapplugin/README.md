

![phpldapadmin](https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/ldap.PNG)

```
docker run --name ldap-service --hostname ldap-host -p 389:389 -p 636:636 --detach osixia/openldap
docker run --name phpldapadmin-service -p 443:443 --hostname phpldapadmin-service --link ldap-service:ldap-host --env PHPLDAPADMIN_LDAP_HOSTS=ldap-host --detach osixia/phpldapadmin
```


