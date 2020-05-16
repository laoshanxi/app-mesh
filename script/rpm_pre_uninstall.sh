#!/bin/bash
################################################################################
## RPM pre uninstallation script file, will be executed before installation
################################################################################

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/appmesh/lib64

# backup configuration file to avoid overide when next installation
if [ -f "/opt/appmesh/appsvc.json" ];then
	cp -f /opt/appmesh/appsvc.json /opt/appmesh/.appsvc.json
fi
# stop all running applications
#if [ -f "/opt/appmesh/appc" ];then
#	/opt/appmesh/appc view -l | awk '{if (NR>1){cmd="/opt/appmesh/appc disable -n "$2;print(cmd);system(cmd)}}'
#fi
