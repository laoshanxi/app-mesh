#!/bin/bash

if [ -f "/usr/lib/systemd/system/appmanager.service" ];then
	systemctl stop appmanager
	systemctl disable appmanager
fi

#rm -rf /opt/appmanager

rm -f /usr/bin/appc
rm -f /usr/lib/systemd/system/appmanager.service
systemctl daemon-reload
