#!/bin/bash

#####################################################################
# This script is used for init.d service startup appsvc process
# Also can be used for docker entrypoint
#####################################################################

# give short time while system starting up.
sleep 0.5

log(){
	logger "[`date`]""$1"
	echo $1
}

cd /opt/appmanager/

SCRIPT_PID="$$"
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/appmanager/lib64

# support override default listen port frmo env
if [ -z $APPMGR_OVERRIDE_LISTEN_PORT ]; then
	log "APPMGR_OVERRIDE_LISTEN_PORT from env:${APPMGR_OVERRIDE_LISTEN_PORT}"
fi

pre_reg_app() {
	if [[ $# -gt 0 ]]; then
		/opt/appmanager/appc -u admin -x Admin123
		/opt/appmanager/appc unreg -n ping -f
		/opt/appmanager/appc reg -n start_app -c "$*" -f
	fi
}

while true ; do
	case "$(ps aux | grep -w /opt/appmanager/appsvc | grep -v grep | grep -v appsvc.json | wc -w)" in
	
	0)	sleep 0.1
		result=$(ps aux | grep -w /opt/appmanager/appsvc | grep -v grep | grep -v appsvc.json | awk '{print $2}')
		if [ -z "$result" ]; then
			nohup /opt/appmanager/appsvc &
			sleep 1
			pre_reg_app $*
			log "Starting Application Manager:     $(date)"
		else
			log "Double check Application Manager is alive: $(date)"
		fi
		sleep 2
		;;
	1)	# all ok
		sleep 2
		;;
	*)	# Only kill the process that was not started by this script
		for i in $(ps aux | grep -w /opt/appmanager/appsvc | grep -v grep | grep -v appsvc.json | awk '{print $2}')
		  do
			if [ $(pstree -Ap $SCRIPT_PID | grep $i | wc -w) -eq 0 ] ; then
			  log "Killed duplicate Application Manager $i: $(date)"
			  kill -9 $i
			fi
		done
		sleep 2
		;;
	esac
done

# Reference
# https://stackoverflow.com/questions/20162678/linux-script-to-check-if-process-is-running-and-act-on-the-result
