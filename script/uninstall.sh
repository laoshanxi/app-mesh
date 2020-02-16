#!/bin/bash
################################################################################
## RPM post uninstallation script file, will be executed when uninstalled
################################################################################

systemctl stop appmanager
systemctl disable appmanager


# remove systemd
if [ -f "/lib/systemd/system/appmanager.service" ]; then
	rm -f /lib/systemd/system/appmanager.service
	systemctl daemon-reload
fi

# remove init.d
if [ -f "/etc/init.d/appmanager" ]; then
	rm -f /etc/init.d/appmanager
fi

rm -f /usr/share/bash-completion/completions/appc

rm -rf ~/._appmgr_*
rm -f /usr/bin/appc
#rm -rf /opt/appmanager