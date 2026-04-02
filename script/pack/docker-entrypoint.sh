#!/usr/bin/env bash
################################################################################
# Docker Entrypoint Wrapper
# Handles user privilege dropping before delegating to the main entrypoint.
# - Default: drops to 'appmesh' user via gosu (secure)
# - APPMESH_RUN_AS_ROOT=true: stays as root (for pip/apt/AI execution)
################################################################################

set -eu

ENTRYPOINT="/opt/appmesh/script/entrypoint.sh"

if [ "${APPMESH_RUN_AS_ROOT:-false}" != "true" ] && id -u appmesh >/dev/null 2>&1 && command -v gosu >/dev/null 2>&1; then
    exec gosu appmesh "$ENTRYPOINT" "$@"
fi

exec "$ENTRYPOINT" "$@"
