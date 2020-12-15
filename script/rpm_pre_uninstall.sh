#!/bin/bash
################################################################################
## RPM pre uninstallation script file, will be executed before installation
################################################################################

INSTALL_DIR=/opt/appmesh
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$INSTALL_DIR/lib64

# backup configuration file to avoid overide when next installation
if [ -f "$INSTALL_DIR/appsvc.json" ]; then
	cp -f $INSTALL_DIR/appsvc.json $INSTALL_DIR/.appsvc.json
fi
# stop all running applications
#if [ -f "$INSTALL_DIR/appc" ];then
#	$INSTALL_DIR/appc view -l | awk '{if (NR>1){cmd="$INSTALL_DIR/appc disable -n "$2;print(cmd);system(cmd)}}'
#fi
