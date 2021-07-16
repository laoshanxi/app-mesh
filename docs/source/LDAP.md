
# LDAP integration

------

LDAP (Lightweight Directory Access Protocol) is a user authentication data base, all users and groups information can be stored in LDAP. AppMesh users are able to integrate with LDAP to provide enterprise level security.

LDAP user authentication is integrated with JWT, user login provide password, AppMesh verify user from LDAP and then response with JWT token, the follow-up authentication with JWT token as usual without connect LDAP Server.

LDAP user organization

![phpldapadmin](https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/ldap.png)

AppMesh can manage user with groups, each group map to a LDAP organization unit (posix group), each group can define related roles:

```json
{
    "Uri": "ldap://127.0.0.1:389",
    "Groups": {
        "admin": {
            "BindDN": "cn={USER},ou=users,dc=example,dc=org",
            "roles": [
                "manage",
                "view",
                "shell",
                "usermgr"
            ]
        },
        "user": {
            "BindDN": "cn={USER},ou=users,dc=example,dc=org",
            "roles": [
                "view",
                "shell"
            ]
        }
    },


    "Roles": {
        "manage": [
            "app-control",
            "app-delete"
        ],
        "usermgr": [
            "user-add",
            "passwd-change"
        ],
        "shell": [
            "app-run-sync"
        ],
        "view": [
            "config-view",
            "app-view-all",
            "cloud-app-view"
        ]
    }
}
```

Start LDAP service with Docker container

```
docker run --restart=always --name ldap-appmesh --hostname ldap-appmesh -p 389:389 -p 636:636 --detach osixia/openldap

docker run --restart=always --name ldap-appmesh-ui -p 443:443 --hostname ldap-appmesh-ui --link ldap-appmesh:ldap-appmesh --env PHPLDAPADMIN_LDAP_HOSTS=ldap-appmesh --detach osixia/phpldapadmin
```

Open https://<docker-host-name>, login with "cn=admin,dc=example,dc=org":"admin" and choose "import" to init LDAP group and users from file [ldif](https://raw.githubusercontent.com/laoshanxi/app-mesh/main/src/daemon/security/ldapplugin/ldap_export.ldif).
