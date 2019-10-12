#!/bin/bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/appmanager/lib64
if [ -f "/usr/lib/systemd/system/appmanager.service" ];then
	appc view -l | awk '{if (NR>1){cmd="appc stop -n "$2;print(cmd);system(cmd)}}'
fi
