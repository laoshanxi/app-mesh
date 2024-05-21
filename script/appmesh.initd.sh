#!/bin/bash
################################################################################
## init.d service definition file
## will be used when systemd is not installed on Linux
## https://gist.github.com/mrowe/8b617a8b12a6248d48b8
################################################################################

### BEGIN INIT INFO
#
# Provides:          appsvc
# Required-Start:    $local_fs $remote_fs
# Required-Stop:     $local_fs $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: initscript
# Description:       This file should be used to construct scripts to be placed in /etc/init.d.
#
### END INIT INFO

export PROG_HOME=/opt/appmesh
export PROG=${PROG_HOME}/bin/appsvc
export PROG_WATCHDOG=${PROG_HOME}/script/appmesh-entrypoint.sh
export PID_FILE=/var/run/appmesh.pid
export LD_LIBRARY_PATH=${PROG_HOME}/lib64:${LD_LIBRARY_PATH}

# Source environment variables
. ${PROG_HOME}/script/appmesh.environment || true

log() {
	logger "[$(date)] $1"
	echo "$1"
}

start() {
	if [ -f "$PID_FILE" ]; then
		PID=$(cat "$PID_FILE")
		if [ -n "$PID" ] && pgrep -f "$PROG" >/dev/null 2>&1 && ps -p "$PID" >/dev/null 2>&1; then
			log "Error! $PROG is already running!"
			exit 1
		fi
	fi

	log "Starting $PROG_WATCHDOG"
	cd "$PROG_HOME"
	"$PROG_WATCHDOG" &
	# echo $! > $PID_FILE
}

stop() {
	log "Stopping $PROG_WATCHDOG"
	PIDS=$(pgrep -f "$PROG_WATCHDOG")
	if [ -n "$PIDS" ]; then
		kill -9 "$PIDS"
		if [ $? -eq 0 ]; then
			log "$PROG_WATCHDOG killed successfully"
		else
			log "Failed to kill $PROG_WATCHDOG processes"
		fi
	fi

	PIDS=$(pgrep -f "$PROG")
	if [ -n "$PIDS" ]; then
		kill -9 "$PIDS"
		if [ $? -eq 0 ]; then
			log "$PROG killed successfully"
		else
			log "Failed to kill $PROG processes"
		fi
	fi
	rm -f "$PID_FILE"
}

status() {
	if [ -f "$PID_FILE" ]; then
		PID=$(cat "$PID_FILE")
		if [ -n "$PID" ] && pgrep -f "$PROG" >/dev/null 2>&1 && ps -p "$PID" >/dev/null 2>&1; then
			echo "App Mesh is running"
			exit 0
		else
			echo "App Mesh PID is NOT running"
		fi
	else
		echo "App Mesh is NOT running"
	fi
	exit 1
}

# Ensure the script is run as root
if [ "$(id -u)" != "0" ]; then
	log "This script must be run as root"
	exit 1
fi

case "$1" in
start)
	start
	;;
stop)
	stop
	;;
reload | restart | force-reload)
	stop
	start
	;;
status)
	status
	;;
*)
	echo "Usage: $0 {start|stop|reload|restart|status}" 1>&2
	exit 1
	;;
esac
