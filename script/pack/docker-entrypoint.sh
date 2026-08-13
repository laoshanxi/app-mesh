#!/usr/bin/env bash
################################################################################
# Docker-only initialization; native services execute bin/appmesh directly.
################################################################################

set -eu

readonly PROG_HOME="/opt/appmesh"
readonly PROGRAM="${PROG_HOME}/bin/appmesh"
readonly APPM="${PROG_HOME}/bin/appm"
readonly WORKFLOW_TEMPLATE="${PROG_HOME}/config/templates/workflow.yaml"
readonly WORKFLOW_APP="${PROG_HOME}/work/apps/workflow.yaml"

log() {
    printf '[docker-entrypoint] %s\n' "$*" >&2
}

die() {
    log "$*"
    exit 1
}

disable_incompatible_default_workflow() {
    if [ -f "$WORKFLOW_APP" ] && [ -f "$WORKFLOW_TEMPLATE" ] && cmp -s "$WORKFLOW_APP" "$WORKFLOW_TEMPLATE"; then
        local disabled_app="${WORKFLOW_APP}.disabled"
        [ -e "$disabled_app" ] && disabled_app="${disabled_app}.$(date +%s)"
        mv "$WORKFLOW_APP" "$disabled_app"
        log "Secure installation moved the default workflow App to $disabled_app"
        log "Provision the workflow App sec_env after the daemon starts"
    fi
}

initialize_secure_installation() {
    local flag_file="${PROG_HOME}/work/.appmginit"

    if [ "${APPMESH_SECURE_INSTALLATION:-N}" = "Y" ] && [ ! -f "$flag_file" ]; then
        log "Initializing secure installation"
        "$APPM" appmginit
    fi

    if [ "${APPMESH_SECURE_INSTALLATION:-N}" = "Y" ] || [ -f "$flag_file" ]; then
        disable_incompatible_default_workflow
    fi
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
        printf '%s\n' "command: |"
        printf '  %s\n' "$*"
    } >"$yaml_file"
    chmod 600 "$yaml_file"
    log "Registered the startup command in $yaml_file"
}

cd "$PROG_HOME" || die "Cannot enter App Mesh home: $PROG_HOME"
prepare_start_command "$@"
initialize_secure_installation

log "Starting App Mesh as $(id -u):$(id -g)"
exec "$PROGRAM"
