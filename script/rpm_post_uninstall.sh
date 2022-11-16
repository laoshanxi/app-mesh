#!/bin/bash
################################################################################
## RPM post uninstallation script file, will be executed when uninstalled
################################################################################

export SYSTEMD_FILE=/etc/systemd/system/appmesh.service
export INITD_FILE=/etc/init.d/appmesh

# remove systemd
if [ -f $SYSTEMD_FILE ]; then
	systemctl stop appmesh
	systemctl disable appmesh
	rm -f $SYSTEMD_FILE
	systemctl daemon-reload
fi

# remove init.d
if [ -f $INITD_FILE ]; then
	service appmesh stop
	rm -f /etc/init.d/appmesh
fi

rm -f /usr/share/bash-completion/completions/appc

rm -rf ~/._appmesh_*
rm -f /usr/bin/appc
