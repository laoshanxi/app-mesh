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
    "CN": "AppMesh",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Shaanxi",
            "O": "DevGroup",
            "ST": "Beijing",
            "OU":"System"
        }
    ]
}
EOF

cfssl gencert -initca ca-csr.json | cfssljson -bare ca -

# https://stackoverflow.com/questions/13322485/how-to-get-the-primary-ip-address-of-the-local-machine-on-linux-and-os-x
IPADDR=$(hostname -I | cut -d' ' -f1)
HOSTNAME=$(hostname --fqdn)
HOSTS="$IPADDR,$HOSTNAME,localhost,127.0.0.1"
echo $HOSTS

echo '{"CN":"appmesh-server","hosts":[""],"key":{"algo":"rsa","size":2048}}' | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=server -hostname=$HOSTS - | cfssljson -bare server

echo '{"CN":"appmesh-client","hosts":[""],"key":{"algo":"rsa","size":2048}}' | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client -hostname=$HOSTS - | cfssljson -bare client
