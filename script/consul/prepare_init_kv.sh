#!/usr/bin/env bash
set -euo pipefail

SOURCE_FILE="../../src/daemon/security/security.yaml"
OUTPUT_KV_JSON="./initial_kv.json"

if [ ! -f "$SOURCE_FILE" ]; then
    echo "Error: Source file '$SOURCE_FILE' not found!"
    exit 1
fi

# Base64-encode the source file for Consul KV import
CONTENT=$(base64 -w 0 "$SOURCE_FILE")

cat >"$OUTPUT_KV_JSON" <<EOF
[
    {
        "key": "appmesh/security",
        "flags": 0,
        "value": "$CONTENT"
    }
]
EOF

echo "Generated KV initialization file at $OUTPUT_KV_JSON"
