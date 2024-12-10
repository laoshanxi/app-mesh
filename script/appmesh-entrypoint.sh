#!/usr/bin/env bash
################################################################################
# App Mesh Entrypoint Script
# Initializes the App Mesh service (appsvc) for init.d or as a Docker entrypoint.
################################################################################

set -e # Exit on error
set -u # Exit on undefined variables

# Environment Variables
export PROG_HOME="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/.." && pwd -P)"
export PROGRAM="${PROG_HOME}/bin/appsvc"
export LD_LIBRARY_PATH="${PROG_HOME}/lib64:${LD_LIBRARY_PATH:-}"

# Function: Logging Utility
log() {
	local level="$1"
	local message="$2"
	local timestamp

	# More portable date format that works across distributions
	if command -v date >/dev/null 2>&1; then
		if date -Iseconds >/dev/null 2>&1; then
			timestamp=$(date -Iseconds)
		else
			timestamp=$(date '+%Y-%m-%d %H:%M:%S%z')
		fi
	else
		timestamp=$(printf '%(%Y-%m-%d %H:%M:%S)T')
	fi

	printf '%s [%s]: %s\n' "$timestamp" "$level" "$message"

	# Use logger only if available
	if command -v logger >/dev/null 2>&1; then
		logger -t "appmesh" "$level" "$message"
	fi
}

# Function: Check Required Dependencies
check_dependencies() {
	local missing_deps=0
	local required_commands="touch mkdir chmod"

	for cmd in $required_commands; do
		if ! command -v "$cmd" >/dev/null 2>&1; then
			log "ERROR" "Required command not found: $cmd"
			((missing_deps++))
		fi
	done

	if [ "$missing_deps" -ne 0 ]; then
		log "ERROR" "Missing required dependencies. Please install them first."
		exit 1
	fi
}

# Function: Change to Program Directory
initialize_directory() {
	if [ ! -d "${PROG_HOME}" ]; then
		log "ERROR" "Program directory ${PROG_HOME} does not exist"
		exit 1
	fi

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
			exec "$@"
		else
			# Register as long-running app with escaped command
			local yaml_file="${PROG_HOME}/work/apps/start_app.yaml"
			local command="$*"

			# Ensure work/apps directory exists
			mkdir -p "${PROG_HOME}/work/apps"

			# Create YAML with proper escaping
			{
				echo "name: start_app"
				echo "command: |"
				echo "  $command" | sed 's/^/  /'
			} >"$yaml_file"

			chmod 600 "$yaml_file"
			log "INFO" "Registered long-running application command in $yaml_file"
		fi
	fi
}

# Function: Secure Installation Check
secure_installation_check() {
	if [ "${APPMESH_SECURE_INSTALLATION:-N}" = "Y" ]; then
		local flag_file="${PROG_HOME}/work/.appmginit"

		# Ensure work directory exists
		mkdir -p "${PROG_HOME}/work"

		if [ ! -f "$flag_file" ]; then
			touch "$flag_file"
			chmod 600 "$flag_file"
			log "INFO" "Initializing secure installation"
			"${PROG_HOME}/bin/appc" appmginit
		fi
	fi
}

# Function: Start App Mesh Service in Loop
start_service_loop() {
	# Handle multiple signal types
	trap 'log "INFO" "Received shutdown signal, stopping service"; exit 0' TERM INT QUIT

	while true; do
		if [ ! -x "$PROGRAM" ]; then
			log "ERROR" "Program file not executable: $PROGRAM"
			exit 1
		fi

		log "INFO" "Starting App Mesh service: $PROGRAM"
		"$PROGRAM"
		local exit_status=$?

		log "WARNING" "App Mesh service exited with status: $exit_status"
		sleep 3
	done
}

################################################################################
# Main Script Execution
################################################################################

check_dependencies
initialize_directory
prepare_app_start "$@"
secure_installation_check
start_service_loop
