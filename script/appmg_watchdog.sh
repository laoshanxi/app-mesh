#! /bin/bash

# give short time while system starting up.
sleep 1

log(){
	logger "[`date`]""$1"
	echo $1
}

cd /opt/appmanager/
MYID="$$"
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/appmanager/lib64
while true ; do
	case "$(ps aux | grep -w /opt/appmanager/appsvc | grep -v grep | awk '{print $2}' | wc -w)" in
	
	0)	sleep 0.1
		result=$(ps aux | grep -w /opt/appmanager/appsvc | grep -v grep | awk '{print $2}')
		if [ -z "$result" ]; then
			nohup /opt/appmanager/appsvc >/dev/null 2>&1 &
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
		for i in $(ps aux | grep -w /opt/appmanager/appsvc | grep -v grep | awk '{print $2}')
		  do
			if [ $(pstree -Ap $MYID | grep $i | wc -w) -eq 0 ] ; then
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
