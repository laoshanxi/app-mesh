#!/usr/bin/env bash
################################################################################
# Docker-only initialization; native services execute bin/appmesh directly.
################################################################################

set -eu
umask 077

readonly PROG_HOME="/opt/appmesh"
readonly PROGRAM="${PROG_HOME}/bin/appmesh"
readonly WORK_DIR="${PROG_HOME}/work"
readonly WORKFLOW_TEMPLATE="${PROG_HOME}/config/templates/workflow.yaml"
readonly WORKFLOW_APP="${WORK_DIR}/apps/workflow.yaml"
readonly TLS_DIR="${WORK_DIR}/ssl"
readonly TLS_GENERATOR="${PROG_HOME}/ssl/generate_ssl_cert.sh"

log() {
    printf '[docker-entrypoint] %s\n' "$*" >&2
}

die() {
    log "$*"
    exit 1
}

ensure_private_directory() {
    local directory="$1"
    [ ! -L "$directory" ] || die "Refusing symbolic-link runtime directory: $directory"
    mkdir -p "$directory"
    [ -d "$directory" ] || die "Runtime path is not a directory: $directory"
    chmod 700 "$directory"
}

publish_default_workflow() {
    ensure_private_directory "${WORK_DIR}/apps"
    [ -f "$WORKFLOW_TEMPLATE" ] || die "Workflow template is unavailable: $WORKFLOW_TEMPLATE"
    [ ! -L "$WORKFLOW_APP" ] || die "Refusing symbolic-link Workflow definition: $WORKFLOW_APP"
    if [ -e "$WORKFLOW_APP" ]; then
        [ -f "$WORKFLOW_APP" ] || die "Workflow definition is not a regular file: $WORKFLOW_APP"
        return
    fi

    local temporary
    temporary=$(mktemp "${WORK_DIR}/apps/.workflow.XXXXXX") || die "Cannot create Workflow definition"
    install -m 600 "$WORKFLOW_TEMPLATE" "$temporary"
    if ! ln "$temporary" "$WORKFLOW_APP" 2>/dev/null; then
        [ ! -L "$WORKFLOW_APP" ] && [ -f "$WORKFLOW_APP" ] || {
            rm -f "$temporary"
            die "Cannot publish Workflow definition"
        }
    fi
    rm -f "$temporary"
}

prepare_tls() {
    ensure_private_directory "$TLS_DIR"
    local existing=0
    local path
    for path in \
        "$TLS_DIR/ca.pem" "$TLS_DIR/ca-key.pem" \
        "$TLS_DIR/server.pem" "$TLS_DIR/server-key.pem" \
        "$TLS_DIR/client.pem" "$TLS_DIR/client-key.pem"; do
        [ ! -L "$path" ] || die "Refusing symbolic-link TLS material: $path"
        if [ -e "$path" ]; then
            [ -f "$path" ] || die "TLS material is not a regular file: $path"
            existing=$((existing + 1))
        fi
    done

    if [ "$existing" -eq 0 ]; then
        [ -x "$TLS_GENERATOR" ] || die "TLS generator is unavailable: $TLS_GENERATOR"
        APPMESH_SSL_OUTPUT_DIR="$TLS_DIR" "$TLS_GENERATOR"
    elif [ "$existing" -ne 6 ]; then
        die "TLS state is incomplete; restore all six files or an empty work/ssl directory"
    fi

    chmod 600 "$TLS_DIR/ca-key.pem" "$TLS_DIR/server-key.pem" "$TLS_DIR/client-key.pem"
    chmod 644 "$TLS_DIR/ca.pem" "$TLS_DIR/server.pem" "$TLS_DIR/client.pem"
}

initialize_runtime() {
    case "${APPMESH_AUTH_MODE:-builtin}" in
        builtin|external) ;;
        *) die "APPMESH_AUTH_MODE must be builtin or external" ;;
    esac
    export APPMESH_AUTH_MODE="${APPMESH_AUTH_MODE:-builtin}"
    ensure_private_directory "$WORK_DIR"
    publish_default_workflow
    prepare_tls
}

prepare_start_command() {
    [ "$#" -gt 0 ] || return 0

    if [ "$1" = "appm" ]; then
        shift
        [ "$#" -gt 0 ] || die "A command is required after the appm marker"
        exec "$@"
    fi

    local yaml_file="${PROG_HOME}/work/apps/start_app.yaml"
    mkdir -p "${PROG_HOME}/work/apps"
    {
        printf '%s\n' "name: start_app"
        printf '%s\n' "owner_principal_id: system:appmesh"
        # OTHER_DENY (10): the container operator's startup command is a system
        # definition; other principals must not view or mutate it. The system
        # owner retains full control.
        printf '%s\n' "permission: 10"
        printf '%s\n' "command: |"
        printf '  %s\n' "$*"
    } >"$yaml_file"
    chmod 600 "$yaml_file"
    log "Registered the startup command in $yaml_file"
}

cd "$PROG_HOME" || die "Cannot enter App Mesh home: $PROG_HOME"
initialize_runtime
prepare_start_command "$@"

log "Starting App Mesh as $(id -u):$(id -g)"
exec "$PROGRAM"
