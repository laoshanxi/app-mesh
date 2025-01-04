#!/bin/bash
set -euo pipefail

CONSUL_URL="http://localhost:8500"
TIMEOUT=15
START_TIME=$(date +%s)

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

log "kv_loader waiting for consul"
while ! curl -sf "${CONSUL_URL}/v1/status/leader" | grep -q "[0-9]:[0-9]"; do
    current_time=$(date +%s)
    if [ $((current_time - START_TIME)) -ge $TIMEOUT ]; then
        log "kv_loader timeout after ${TIMEOUT} seconds"
        exit 1
    fi
    sleep 1
    log "kv_loader still waiting"
done

log "kv_loader read export(ed) kv json files from ${INIT_CONSUL_KV_DIR}"
cd "${INIT_CONSUL_KV_DIR}" || exit 1

for json_file in *.json; do
    [ -e "$json_file" ] || continue # Handle case when no .json files exist
    log "kv_loader loading from ${json_file}"
    consul kv import "@${json_file}"
done
