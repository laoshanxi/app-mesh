#!/bin/bash
apppath=/opt/appmanager

if [ -f "/etc/init.d/appmanager" ];then
	systemctl stop appmanager
	systemctl disable appmanager
fi

#rm -rf $apppath

rm -f /usr/bin/appc
rm -f /etc/init.d/appmanager
