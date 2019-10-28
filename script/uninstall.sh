#!/bin/bash

systemctl stop appmanager
systemctl disable appmanager


# remove systemd
if [ -f "/lib/systemd/system/appmanager.service" ]; then
	rm -f /lib/systemd/system/appmanager.service
fi

# remove init.d
if [ -f "/etc/init.d/appmanager" ]; then
	rm -f /etc/init.d/appmanager
fi

systemctl daemon-reload
rm -f /usr/bin/appc
#rm -rf /opt/appmanager