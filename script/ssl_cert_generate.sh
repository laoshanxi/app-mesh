#!/bin/bash
################################################################################
## This Script file used to generate self signed ssl cert files
##
## References:
## https://www.bookstack.cn/read/tidb-v2.1/how-to-secure-generate-self-signed-certificates.md
## https://www.cnblogs.com/fanqisoft/p/10765038.html
## https://blog.csdn.net/kozazyh/article/details/79844609
################################################################################

PATH=$PATH:$(pwd)

cat >ca-config.json <<EOF
{
    "signing": {
        "default": {
            "expiry": "438000h"
        },
        "profiles": {
            "client": {
                "expiry": "438000h",
                "usages": [
                    "signing",
                    "key encipherment",
                    "client auth"
                ]
            },
            "server": {
                "expiry": "438000h",
                "usages": [
                    "signing",
                    "key encipherment",
                    "server auth",
                    "client auth"
                ]
            }
        }
    }
}
EOF

cat >ca-csr.json <<EOF
{
    "CN": "App Mesh",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Shaanxi",
            "O": "Dev",
            "ST": "XiAn",
            "OU":"System"
        }
    ]
}
EOF

cfssl gencert -initca ca-csr.json | cfssljson -bare ca -

IPADDRS=$(ifconfig -a | grep inet | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | tr -d "addr:" | paste -d "," -s)
HOSTNAM=$(hostname --fqdn)
HOSTS="$IPADDRS,$HOSTNAM"
echo '{"CN":"App Mesh","hosts":[""],"key":{"algo":"rsa","size":2048}}' | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=server -hostname=$HOSTS - | cfssljson -bare server

echo '{"CN":"App Mesh Client","hosts":[""],"key":{"algo":"rsa","size":2048}}' | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client -hostname="" - | cfssljson -bare client
