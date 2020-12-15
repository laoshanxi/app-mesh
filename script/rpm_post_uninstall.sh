#!/bin/bash
################################################################################
## RPM post uninstallation script file, will be executed when uninstalled
################################################################################
INSTALL_DIR=/opt/appmesh
SYSTEMD_PATH=/etc/systemd/system/appmesh.service
systemctl stop appmesh
systemctl disable appmesh

# remove systemd
if [ -f $SYSTEMD_PATH ]; then
	rm -f $SYSTEMD_PATH
	systemctl daemon-reload
fi

# remove init.d
if [ -f "/etc/init.d/appmesh" ]; then
	rm -f /etc/init.d/appmesh
fi

rm -f /usr/share/bash-completion/completions/appc

rm -rf ~/._appmesh_*
rm -f /usr/bin/appc
rm -f $INSTALL_DIR/apprest
rm -f $INSTALL_DIR/work/appmesh.*
#rm -rf $INSTALL_DIR

# clean user appmesh
id appmesh >&/dev/null
if [ $? -eq 0 ]; then
	userdel -r appmesh || true
fi
