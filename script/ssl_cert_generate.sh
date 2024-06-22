#!/bin/bash
################################################################################
## This Script file used to generate self signed ssl cert files
##
## References:
## https://www.bookstack.cn/read/tidb-v2.1/how-to-secure-generate-self-signed-certificates.md
## https://www.cnblogs.com/fanqisoft/p/10765038.html
## https://blog.csdn.net/kozazyh/article/details/79844609

## https://github.com/cloudflare/cfssl/wiki/Creating-a-new-CSR
## https://github.com/coreos/docs/blob/master/os/generate-self-signed-certificates.md
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
IPADDR=$(hostname -I | tr ' ' ',' | sed 's/,$//')
HOSTNAME_L=$(hostname --fqdn)
HOSTNAME_S=$(hostname)
LOCAL_ADDR="localhost,127.0.0.1"
HOSTS="$IPADDR,$HOSTNAME_S,$HOSTNAME_L,$LOCAL_ADDR"
echo $HOSTS

echo '{"CN":"'"$HOSTNAME"'","hosts":[""],"key":{"algo":"rsa","size":2048}}' | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=server -hostname=$HOSTS - | cfssljson -bare server

echo '{"CN":"appmesh-client","hosts":[""],"key":{"algo":"rsa","size":2048}}' | cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=client -hostname=$HOSTS - | cfssljson -bare client

# Start a TLS server on port 8443, using the server certificate and key, and requiring the client to present a valid certificate signed by the root CA
# openssl s_server -cert server.pem -key server-key.pem -CAfile ca.pem -verify 1 -port 8443

# Start a TLS client, using the client certificate and key, and verifying the server certificate against the root CA.
# openssl s_client -cert client.pem -key client-key.pem -CAfile ca.pem -verify 1 -connect localhost:8443
