#!/bin/bash
################################################################################
## RPM post uninstallation script file, will be executed when uninstalled
################################################################################

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

# clean user appmesh
userdel -r appmesh -f || true
