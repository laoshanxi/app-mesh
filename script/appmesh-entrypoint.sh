#!/bin/bash
################################################################################
# App Mesh Entrypoint Script
# Initializes the App Mesh service (appsvc) for init.d or as a Docker entrypoint.
################################################################################

# Environment Variables
export PROG_HOME="/opt/appmesh"
export PROGRAM="${PROG_HOME}/bin/appsvc"
export LD_LIBRARY_PATH="${PROG_HOME}/lib64:${LD_LIBRARY_PATH}"

# Function: Logging Utility
log() {
	local level="$1"
	local message="$2"
	local timestamp
	timestamp=$(date --rfc-3339=seconds)
	echo "$timestamp [$level]: $message"
	logger "$timestamp [$level]: $message"
}

# Function: Change to Program Directory
initialize_directory() {
	cd "${PROG_HOME}" || {
		log "ERROR" "Failed to change directory to ${PROG_HOME}"
		exit 1
	}
}

# Function: Prepare and register the initial app
prepare_app_start() {
	if [ $# -gt 0 ]; then
		# Check if the first argument is "appc"
		if [ "$1" = "appc" ]; then
			shift
			log "INFO" "Executing native command: $*"
			"$@"
		else
			# Register as long-running app with escaped command
			local command="$*"
			local yaml_file="${PROG_HOME}/work/apps/start_app.yaml"
			# Write YAML configuration for the long-running app
			cat <<EOF >"$yaml_file"
name: start_app
command: |
  $command
EOF
			log "INFO" "Registered long-running application command: $escaped_command"
		fi
	fi
}

# Function: Secure Installation Check
secure_installation_check() {
	if [ "${APPMESH_SECURE_INSTALLATION}" = "Y" ]; then
		local flag_file="${PROG_HOME}/work/.appmginit"
		if [ ! -f "$flag_file" ]; then
			touch "$flag_file"
			log "INFO" "Initializing secure installation"
			/usr/bin/appc appmginit
		fi
	fi
}

# Function: Start App Mesh Service in Loop
start_service_loop() {
	trap 'log "INFO" "Received SIGTERM, stopping service"; exit 0' 15

	while true; do
		log "INFO" "Starting App Mesh service: $PROGRAM"
		"$PROGRAM"
		local exit_status=$?
		log "INFO" "App Mesh service exited with status: $exit_status"
		sleep 2
	done
}

################################################################################
# Main Script Execution
################################################################################

initialize_directory
prepare_app_start "$@"
secure_installation_check
start_service_loop
