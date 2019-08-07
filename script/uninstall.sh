#!/bin/bash
apppath=/opt/appmanager

if [ -f "/etc/init.d/appsvc" ];then
	systemctl stop appsvc
	systemctl disable appsvc
fi

#rm -rf $apppath

rm -f /usr/bin/appc
rm -f /etc/init.d/appsvc
