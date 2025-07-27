#!/usr/bin/env bash
################################################################################
## init.d service definition file
## will be used when systemd is not installed on Linux
## https://gist.github.com/mrowe/8b617a8b12a6248d48b8
################################################################################

### BEGIN INIT INFO
# Provides:          appsvc
# Required-Start:    $local_fs $remote_fs $network $syslog
# Required-Stop:     $local_fs $remote_fs $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: App Mesh Service
# Description:       Controls the App Mesh service and its watchdog
### END INIT INFO

set -e # Exit on error
set -u # Exit on undefined variables

# Environment variables with fallback defaults
export PROG_HOME="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/.." && pwd -P)"
export PROG=${PROG:-"${PROG_HOME}/bin/appsvc"}
export PROG_WATCHDOG=${PROG_WATCHDOG:-"${PROG_HOME}/script/entrypoint.sh"}

# Constants
readonly TIMEOUT_SECONDS=10                    # Desired timeout in seconds
readonly SLEEP_INTERVAL=0.2                    # Check interval in seconds
readonly MAX_ATTEMPTS=$((TIMEOUT_SECONDS * 5)) # 5 attempts per second (1/0.2)
readonly ENV_FILE="$PROG_HOME/appmesh.default"

# Exit codes as per LSB standards
readonly LSB_OK=0
readonly LSB_INVALID_ARGS=2
readonly LSB_NOT_RUNNING=3
readonly LSB_NOT_ROOT=4
readonly LSB_NOT_INSTALLED=5
readonly LSB_NOT_CONFIGURED=6
readonly LSB_NOT_RUNNING_RELOAD=7

# Source LSB functions if available
[ -r /lib/lsb/init-functions ] && . /lib/lsb/init-functions

# Source system configuration
[ -r ENV_FILE ] && . ENV_FILE

log() {
	local level="$1"
	local message="$2"
	local timestamp
	timestamp=$(date -Iseconds 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')

	# Use logger if available, fallback to printf
	if command -v logger >/dev/null 2>&1; then
		logger -t "appmesh" -p "daemon.${level}" "${message}"
	fi
	printf '[%s] [%s] %s\n' "${timestamp}" "${level}" "${message}" >&2
}

check_installation() {
	if [ ! -x "$PROG" ]; then
		log "error" "App Mesh executable not found or not executable: $PROG"
		return $LSB_NOT_INSTALLED
	fi
	if [ ! -x "$PROG_WATCHDOG" ]; then
		log "error" "App Mesh watchdog not found or not executable: $PROG_WATCHDOG"
		return $LSB_NOT_INSTALLED
	fi
	return $LSB_OK
}

get_pid() {
	# Find the PID of the process matching the provided name
	ps aux | grep -w "$1" | grep -v grep | awk '{print $2}'
}

is_running() {
	local pid
	pid=$(get_pid "$1")
	[ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

start_service() {
	check_installation || return $?

	if is_running "$PROG"; then
		log "info" "App Mesh is already running"
		return $LSB_OK
	fi

	log "info" "Starting App Mesh Service..."
	cd "${PROG_HOME}" || {
		log "error" "Failed to change to ${PROG_HOME}"
		return $LSB_NOT_CONFIGURED
	}

	# Start the watchdog process
	nohup "$PROG_WATCHDOG" </dev/null >/dev/null 2>&1 &

	# Wait for process to be detected with timeout
	attempt=0
	sleep 1
	while ! is_running "$PROG" && [ $attempt -lt $MAX_ATTEMPTS ]; do
		sleep $SLEEP_INTERVAL
		attempt=$((attempt + 1))
	done

	if is_running "$PROG"; then
		local pid
		pid=$(get_pid "$PROG")
		log "info" "App Mesh started successfully (PID: $pid)"
		return $LSB_OK
	else
		log "error" "App Mesh failed to start within $TIMEOUT_SECONDS seconds"
		return $LSB_NOT_RUNNING
	fi
}

stop_service() {
	log "info" "Stopping App Mesh Service..."

	local pid
	pid=$(get_pid "$PROG")
	if [ -z "$pid" ]; then
		log "info" "App Mesh is not running"
		return $LSB_OK
	fi

	# Try graceful shutdown
	kill "$pid" || true
	sleep $SLEEP_INTERVAL
	#local attempt=0
	#while is_running "$PROG" && [ $attempt -lt $MAX_ATTEMPTS ]; do
	#	sleep $SLEEP_INTERVAL
	#	attempt=$((attempt + 1))
	#done

	# Force kill if still running
	if is_running "$PROG"; then
		log "info" "Force killing App Mesh process (PID: $pid)"
		kill -9 "$pid" || true
	fi

	log "info" "App Mesh stopped"
	return $LSB_OK
}

service_status() {
	if is_running "$PROG"; then
		local pid
		pid=$(get_pid "$PROG")
		log "info" "App Mesh is running (PID: $pid)"
		return $LSB_OK
	else
		log "info" "App Mesh is not running"
		return $LSB_NOT_RUNNING
	fi
}

# Ensure root privileges
if [ "$(id -u)" != "0" ]; then
	log "error" "This script must be run as root"
	exit $LSB_NOT_ROOT
fi

case "$1" in
start)
	start_service
	;;
stop)
	stop_service
	;;
restart | force-reload)
	stop_service
	sleep 1
	start_service
	;;
reload)
	if is_running "$PROG"; then
		log "info" "Reloading configuration..."
		kill -HUP "$(get_pid "$PROG")" || true
		exit $LSB_OK
	else
		log "error" "Cannot reload: App Mesh is not running"
		exit $LSB_NOT_RUNNING_RELOAD
	fi
	;;
status)
	service_status
	;;
*)
	echo "Usage: $0 {start|stop|restart|force-reload|reload|status}"
	exit $LSB_INVALID_ARGS
	;;
esac

exit $?
