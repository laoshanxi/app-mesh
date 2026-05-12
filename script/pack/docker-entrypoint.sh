#!/usr/bin/env bash
################################################################################
# Docker Entrypoint Wrapper
# Handles user privilege dropping before delegating to the main entrypoint.
# - Default: drops to 'appmesh' user via setpriv (secure, no Go dependency)
# - APPMESH_RUN_AS_ROOT=true: stays as root (for pip/apt/AI execution)
################################################################################

set -eu

ENTRYPOINT="/opt/appmesh/script/entrypoint.sh"

if [ "${APPMESH_RUN_AS_ROOT:-false}" != "true" ]; then
    if ! id -u appmesh >/dev/null 2>&1; then
        echo "ERROR: 'appmesh' user not found; refusing to start as root" >&2
        exit 1
    fi
    if ! command -v setpriv >/dev/null 2>&1; then
        echo "ERROR: setpriv not found; refusing to start as root" >&2
        exit 1
    fi
    exec setpriv --reuid=appmesh --regid=appmesh --init-groups --no-new-privs "$ENTRYPOINT" "$@"
fi

exec "$ENTRYPOINT" "$@"
