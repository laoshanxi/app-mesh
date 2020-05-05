#!/bin/bash
################################################################################
## Consul watch script
################################################################################

# curl solution
token=`curl -X POST -k -s -H "username:$(echo -n user | base64)" -H "password:$(echo -n password | base64)" https://localhost:6060/appmgr/login | sed 's/,/\n/g' | grep "access_token" | sed 's/:/\n/g' | sed '1d' | sed 's/}//g' | sed 's/"//g'`
curl -X POST -k -H "Authorization:Bearer $token" https://localhost:6060/appmgr/watch/$1

# curl with SSL cert file
#token=`curl -X POST --cacert /opt/appmanager/ssl/ca.pem --cert /opt/appmanager/ssl/client.pem --key /opt/appmanager/ssl/client-key.pem -s -H "username:$(echo -n user | base64)" -H "password:$(echo -n password | base64)" https://localhost:6060/appmgr/login | sed 's/,/\n/g' | grep "access_token" | sed 's/:/\n/g' | sed '1d' | sed 's/}//g' | sed 's/"//g'`
#curl -X POST --cacert /opt/appmanager/ssl/ca.pem --cert /opt/appmanager/ssl/client.pem --key /opt/appmanager/ssl/client-key.pem -H "Authorization:Bearer $token" https://localhost:6060/appmgr/watch/$1

# appc solution
# appc watch -t $1
