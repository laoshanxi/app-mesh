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
	logger "$(date --rfc-3339=seconds): $@"
	echo "$(date --rfc-3339=seconds): $@"
}

cd ${PROG_HOME}

SCRIPT_PID="$$"
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${PROG_HOME}/lib64:/usr/local/lib64:/usr/local/lib/

##################################################################################
# for docker entrypoint, this function can register docker container commands to
# app mesh application, accept parameter as bellow format:
#  1. run docker container and register an application as long running
#     docker run -d laoshanxi/appmesh ping www.baidu.com
#  2. run docker container and run external cmd
#     docker run -d laoshanxi/appmesh appc ls
##################################################################################
pre_start_app() {
	if [[ $# -gt 0 ]]; then
		log "wait for app mesh service ready"
		until [ $(curl -sL -k -w "%{http_code}" -o /dev/null https://localhost:6060/) -eq 200 ]; do sleep 0.25; done
		${PROG_HOME}/${PROGC} logon -u admin -x admin123 -o ""
		log "remove default ping app for container"
		${PROG_HOME}/${PROGC} unreg -n ping -f || true
		if [ $1 = "appc" ]; then
			# if arguments start with appc, then just run this native command and ignore appc
			shift
			log "run native cmd: $@"
			/bin/sh -c "$@"
		else
			# if arguments start with command, then reg as long running application
			${PROG_HOME}/${PROGC} reg -n start_app -c "$*" -f
			log "appc reg -n start_app -c $* -f"
		fi
	fi
}

FIRST_START="true"
while true; do
	PID=$(tr -d '\0' </var/run/appmesh.pid)
	PID_EXIST=$(ps aux | awk '{print $2}' | grep -w $PID)
	CMD_EXIST=$(ps aux | awk '{print $11}' | grep -w ${PROG_HOME}/${PROG})
	if [[ ! $PID_EXIST ]] && [[ ! $CMD_EXIST ]]; then
		nohup ${PROG_HOME}/${PROG} &
		log "Starting App Mesh service, FIRST_START=$FIRST_START"
		if [ "$FIRST_START" == "true" ]; then
			log "Check pre-start application"
			pre_start_app $*
			FIRST_START="false"
		fi
	fi
	sleep 2
done
