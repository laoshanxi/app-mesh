#!/bin/bash
################################################################################
## This script is used for init.d service startup appsvc process
## and also can be used for docker image entrypoint
## https://stackoverflow.com/questions/20162678/linux-script-to-check-if-process-is-running-and-act-on-the-result
################################################################################

log() {
	logger "[$(date)]""$1"
	echo $1
}

# prepare work dir
if [ ! -d "/opt/appmesh/work" ]; then
	mkdir /opt/appmesh/work
fi
cd /opt/appmesh/work

SCRIPT_PID="$$"
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/opt/appmesh/lib64:/usr/local/lib64:/usr/local/lib/

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
		/opt/appmesh/bin/appc logon -u admin -x Admin123
		if [ $1 = "appc" ]; then
			# if arguments start with appc, then just run this appc command
			/bin/sh -c "$*"
		else
			# if arguments start with command, then reg as long running application
			/opt/appmesh/bin/appc unreg -n ping -f || true
			/opt/appmesh/bin/appc reg -n start_app -c "$*" -f
		fi
	fi
}

while true; do
	case "$(ps aux | grep -w /opt/appmesh/bin/appsvc | grep -v grep | grep -v appsvc.json | wc -w)" in

	0)
		sleep 0.1
		result=$(ps aux | grep -w /opt/appmesh/bin/appsvc | grep -v grep | grep -v appsvc.json | awk '{print $2}')
		if [ -z "$result" ]; then
			nohup /opt/appmesh/bin/appsvc &
			sleep 1
			pre_reg_app $*
			log "Starting App Mesh:     $(date)"
		else
			log "Double check App Mesh is alive: $(date)"
		fi
		sleep 2
		;;
	1) # all ok
		sleep 2
		;;
	*) # Only kill the process that was not started by this script
		for i in $(ps aux | grep -w /opt/appmesh/bin/appsvc | grep -v grep | grep -v appsvc.json | awk '{print $2}'); do
			if [ $(pstree -Ap $SCRIPT_PID | grep $i | wc -w) -eq 0 ]; then
				log "Killed duplicate App Mesh $i: $(date)"
				kill -9 $i
			fi
		done
		sleep 2
		;;
	esac
done
