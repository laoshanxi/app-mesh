#!/bin/bash
################################################################################
## This script is used for init.d service startup appsvc process
## and also can be used for docker image entrypoint
## https://stackoverflow.com/questions/20162678/linux-script-to-check-if-process-is-running-and-act-on-the-result
################################################################################

export PROG_HOME=/opt/appmesh
export PROG=${PROG_HOME}/bin/appsvc
export LD_LIBRARY_PATH=${PROG_HOME}/lib64:${LD_LIBRARY_PATH}

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

pre_start_app() {
	if [[ $# -gt 0 ]]; then
		if [ "$1" = "appc" ]; then
			# If arguments start with appc, then just run this native command and ignore appc
			shift
			log "Running native command: $*"
			/bin/sh -c 'echo "$*"'
		else
			escaped_command=$(echo "$*" | sed 's/\\/\\\\/g; s/"/\\"/g')
			# If arguments start with command, then register as a long-running application
			cat <<EOF >/opt/appmesh/apps/start_app.json
{
    "name": "start_app",
    "command": "$escaped_command"
}
EOF
		fi
	fi

	echo "APPMESH_SECURE_INSTALLATION=$APPMESH_SECURE_INSTALLATION"
	if [ "$APPMESH_SECURE_INSTALLATION" = "Y" ]; then
		FLAG_FILE="$PROG_HOME/work/.appmginit"
		if [ ! -f "$FLAG_FILE" ]; then
			touch "$FLAG_FILE"
			# gernerate password for secure installation
			/usr/bin/appc appmginit
		fi
	fi
}

pre_start_app "$@"

while true; do
	log "Starting App Mesh service: $PROG"
	$PROG >/dev/null 2>&1
	EXIT_STATUS=$?
	log "App Mesh exit status: $EXIT_STATUS"
	sleep 2
done
