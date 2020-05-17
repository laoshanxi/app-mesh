#!/bin/bash
################################################################################
## RPM post uninstallation script file, will be executed when uninstalled
################################################################################

systemctl stop appmesh
systemctl disable appmesh


# remove systemd
if [ -f "/lib/systemd/system/appmesh.service" ]; then
	rm -f /lib/systemd/system/appmesh.service
	systemctl daemon-reload
fi

# remove init.d
if [ -f "/etc/init.d/appmesh" ]; then
	rm -f /etc/init.d/appmesh
fi

rm -f /usr/share/bash-completion/completions/appc

rm -rf ~/._appmesh_*
rm -f /usr/bin/appc
#rm -rf /opt/appmesh