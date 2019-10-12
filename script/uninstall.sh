#!/bin/bash

if [ -f "/lib/systemd/system/appmanager.service" ];then
	systemctl stop appmanager
	systemctl disable appmanager
fi

#rm -rf /opt/appmanager

rm -f /usr/bin/appc
rm -f /lib/systemd/system/appmanager.service
systemctl daemon-reload
