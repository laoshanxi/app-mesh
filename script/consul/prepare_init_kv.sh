#!/bin/bash

# Input JSON file (replace with the path to your existing file)
SOURCE_JSON_FILE="../../src/daemon/security/security.yaml"

# Output JSON file for KV initialization
OUTPUT_KV_JSON="./initial_kv.json"

# Verify the input file exists
if [ ! -f $SOURCE_JSON_FILE ]; then
    echo "Error: Source JSON file '$SOURCE_JSON_FILE' not found!"
    exit 1
fi

# Read the content of the source JSON file
CONTENT=$(base64 -w 0 "$SOURCE_JSON_FILE")

# Create the initial_kv.json file with the desired KV path
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
