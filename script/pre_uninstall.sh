#!/bin/bash
################################################################################
## RPM pre uninstallation script file, will be executed before installation
################################################################################

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/appmanager/lib64

# backup configuration file to avoid overide when next installation
if [ -f "/opt/appmanager/appsvc.json" ];then
	cp -f /opt/appmanager/appsvc.json /opt/appmanager/.appsvc.json
fi
# stop all running applications
#if [ -f "/opt/appmanager/appc" ];then
#	/opt/appmanager/appc view -l | awk '{if (NR>1){cmd="/opt/appmanager/appc disable -n "$2;print(cmd);system(cmd)}}'
#fi
