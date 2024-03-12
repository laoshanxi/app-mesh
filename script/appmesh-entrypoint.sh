#!/bin/bash
################################################################################
## This script is used for init.d service startup appsvc process
## and also can be used for docker image entrypoint
## https://stackoverflow.com/questions/20162678/linux-script-to-check-if-process-is-running-and-act-on-the-result
################################################################################

export PROG_HOME=/opt/appmesh
export PROG=bin/appsvc
export PROGC=bin/appc

log() {
	local timestamp
	timestamp=$(date --rfc-3339=seconds)
	logger "$timestamp: $@"
	echo "$timestamp: $@"
}

cd "${PROG_HOME}" || {
	log "Failed to change directory to ${PROG_HOME}"
	exit 1
}

SCRIPT_PID="$$"
export LD_LIBRARY_PATH=${PROG_HOME}/lib64:${LD_LIBRARY_PATH}

pre_start_app() {
	if [[ $# -gt 0 ]]; then
		if [ "$1" = "appc" ]; then
			# If arguments start with appc, then just run this native command and ignore appc
			shift
			log "Running native command: $*"
			/bin/sh -c 'echo "$*"'
		else
			# If arguments start with command, then register as a long-running application
			cat <<EOF >/opt/appmesh/apps/start_app.json
{
    "name": "start_app",
    "command": "$*"
}
EOF
		fi
	fi
}

pre_start_app "$@"

while true; do
	PID=$(tr -d '\0' </var/run/appmesh.pid)
	PID_EXIST=$(ps aux | awk '{print $2}' | grep -w "$PID")
	CMD_EXIST=$(ps aux | awk '{print $11}' | grep -w "${PROG_HOME}/${PROG}")
	if [[ ! $PID_EXIST ]] && [[ ! $CMD_EXIST ]]; then
		nohup "${PROG_HOME}/${PROG}" &
		log "Starting App Mesh service"
	fi
	sleep 1
done
