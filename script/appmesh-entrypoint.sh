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
	logger "$1"
	echo $1
}

cd ${PROG_HOME}

SCRIPT_PID="$$"
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${PROG_HOME}/lib64:/usr/local/lib64:/usr/local/lib/

##################################################################################
# for docker entrypoint, this function can register docker container commands to
# app mesh application, accept parameter as bellow format:
#  1. appc reg xxx
#  2. mysqld (automaticly register to appmesh with long running app)
##################################################################################
pre_reg_app() {
	if [[ $# -gt 0 ]]; then
		# wait for app mesh service ready
		until [ $(curl -sL -k -w "%{http_code}" -o /dev/null https://localhost:6060/) -eq 200 ]; do sleep 0.25; done
		${PROG_HOME}/${PROGC} logon -u admin -x admin123 -o ""
		# remove default ping app for container
		${PROG_HOME}/${PROGC} unreg -n ping -f || true
		if [ $1 = "appc" ]; then
			# if arguments start with appc, then just run this appc command
			/bin/sh -c "$*"
		else
			# if arguments start with command, then reg as long running application
			${PROG_HOME}/${PROGC} reg -n start_app -c "$*" -f
		fi
	fi
}

while true; do
	if [ ! -f /var/run/appmesh.pid ]; then
		nohup ${PROG_HOME}/${PROG} &
	else
		PID=$(tr -d '\0' </var/run/appmesh.pid)
		PID_EXIST=$(ps aux | awk '{print $2}' | grep -w $PID)
		CMD_EXIST=$(ps aux | awk '{print $11}' | grep -w ${PROG_HOME}/${PROG})
		if [[ ! $PID_EXIST ]] && [[ ! $CMD_EXIST ]]; then
			nohup ${PROG_HOME}/${PROG} &
			pre_reg_app $*
			log "$(date --rfc-3339=seconds): Starting App Mesh"
		fi
	fi
	sleep 2
done
