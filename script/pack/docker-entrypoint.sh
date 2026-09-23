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
# Same directory as the native installer, so the packaged ssl/ paths in
# config.yaml stay valid for both daemon and CLI.
readonly TLS_DIR="${PROG_HOME}/ssl"
readonly TLS_GENERATOR="${PROG_HOME}/ssl/generate_ssl_cert.sh"
readonly AUTH_LAUNCHER="${PROG_HOME}/script/appmesh-auth.sh"

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
        die "TLS state is incomplete; restore all six files or an empty ssl directory"
    fi

    chmod 600 "$TLS_DIR/ca-key.pem" "$TLS_DIR/server-key.pem" "$TLS_DIR/client-key.pem"
    chmod 644 "$TLS_DIR/ca.pem" "$TLS_DIR/server.pem" "$TLS_DIR/client.pem"
}

seed_admin_password() {
    # Declarative first-boot password: the operator mounts a secret file and
    # points APPMESH_ADMIN_PASSWORD_FILE at it. The password never travels in
    # an environment variable value, which would leak through docker inspect.
    # Applied only before the first bootstrap creates the credential, so later
    # set-initial-password/rotate changes survive container restarts.
    local password_file="${APPMESH_ADMIN_PASSWORD_FILE:-}"
    [ -n "$password_file" ] || return 0
    local credentials="${WORK_DIR}/auth/secrets/initial-admin-credentials"
    if [ -e "$credentials" ]; then
        log "Administrator credential already exists; ignoring APPMESH_ADMIN_PASSWORD_FILE"
        return 0
    fi
    [ ! -L "$password_file" ] && [ -f "$password_file" ] ||
        die "APPMESH_ADMIN_PASSWORD_FILE is not a regular file: $password_file"
    log "Seeding the initial administrator password from $password_file"
    "$AUTH_LAUNCHER" set-initial-password <"$password_file" ||
        die "Failed to seed the initial administrator password"
}

initialize_runtime() {
    case "${APPMESH_AUTH_MODE:-builtin}" in
        builtin|external) ;;
        *) die "APPMESH_AUTH_MODE must be builtin or external" ;;
    esac
    export APPMESH_AUTH_MODE="${APPMESH_AUTH_MODE:-builtin}"
    ensure_private_directory "$WORK_DIR"
    [ -x "$AUTH_LAUNCHER" ] || die "Authentication bootstrap is unavailable"
    if [ "${APPMESH_AUTH_MODE}" = "builtin" ]; then
        seed_admin_password
    fi
    "$AUTH_LAUNCHER" bootstrap || die "Authentication bootstrap failed"
    configure_admin_ui
    publish_default_workflow
    prepare_tls
}

# The administration UI is a bundled System App. Switching its definition to
# disabled is a hard gate: the daemon will not start it, and the application
# API refuses to re-enable system Apps, so no remote caller can turn it back on.
configure_admin_ui() {
    local definition="${PROG_HOME}/apps/dexuser.yaml"
    local flag="${APPMESH_AUTH_ADMIN_UI:-}"
    [ -n "$flag" ] || return 0
    [ -f "$definition" ] || return 0
    case "$flag" in
        on|ON|true|1|enabled)
            sed -i 's/^enabled:.*/enabled: true/' "$definition" ||
                die "Cannot enable the administration UI definition: $definition"
            log "Administration UI enabled (APPMESH_AUTH_ADMIN_UI=$flag)"
            ;;
        off|OFF|false|0|disabled)
            sed -i 's/^enabled:.*/enabled: false/' "$definition" ||
                die "Cannot disable the administration UI definition: $definition"
            log "Administration UI disabled (APPMESH_AUTH_ADMIN_UI=$flag)"
            ;;
        *) die "APPMESH_AUTH_ADMIN_UI must be on or off" ;;
    esac
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
