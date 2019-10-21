#!/bin/bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/appmanager/lib64
if [ -f "/lib/systemd/system/appmanager.service" ];then
	/opt/appmanager/appc view -l | awk '{if (NR>1){cmd="/opt/appmanager/appc stop -n "$2;print(cmd);system(cmd)}}'
fi
