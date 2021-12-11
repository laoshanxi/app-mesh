#!/bin/bash
################################################################################
## RPM pre uninstallation script file, will be executed before installation
################################################################################

INSTALL_DIR=/opt/appmesh
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/opt/appmesh/lib64:/usr/local/lib64:/usr/local/lib/

# backup configuration file to avoid overide when next installation
if [ -f "$INSTALL_DIR/config.json" ]; then
	cp -f $INSTALL_DIR/config.json $INSTALL_DIR/.config.json
fi
if [ -f "$INSTALL_DIR/security.json" ]; then
	cp -f $INSTALL_DIR/security.json $INSTALL_DIR/.security.json
fi
if [ -f "$INSTALL_DIR/ldap.json" ]; then
	cp -f $INSTALL_DIR/ldap.json $INSTALL_DIR/.ldap.json
fi
# stop all running applications
if [ -f "$INSTALL_DIR/appc" ];then
	$INSTALL_DIR/appc view -l | awk '{if (NR>1){cmd="$INSTALL_DIR/appc disable -n "$2;print(cmd);system(cmd)}}'
fi
