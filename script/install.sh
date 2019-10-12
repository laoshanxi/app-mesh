#!/bin/bash
apppath=/opt/appmanager
if [ ! -d $apppath ];then
	mkdir -p $apppath
elif [ -f "/usr/lib/systemd/system/appmanager.service" ];then
	systemctl stop appmanager
	sleep 2
fi

chmod 644 $apppath/script/appmanager.service
cp -f $apppath/script/appmanager.service /usr/lib/systemd/system/appmanager.service

systemctl daemon-reload
systemctl enable appmanager
systemctl start appmanager

rm -rf /usr/bin/appc
ln -s /opt/appmanager/script/appc.sh /usr/bin/appc
chmod +x /opt/appmanager/script/appc.sh
