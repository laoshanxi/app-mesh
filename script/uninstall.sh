#!/bin/bash
apppath=/opt/appmanager

if [ -f "/etc/init.d/appsvc" ];then
	service appsvc stop
	systemctl disable appsvc
fi

#rm -rf $apppath

rm -f /usr/bin/appc
rm -f /etc/init.d/appsvc
