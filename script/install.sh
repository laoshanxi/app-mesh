#!/bin/bash
INSTALL_DIR=/opt/appmanager
if [ ! -d $INSTALL_DIR ]; then
	mkdir -p $INSTALL_DIR
elif [[ -f "/lib/systemd/system/appmanager.service" ]] || [[ -f "/etc/init.d/appmanager" ]]; then
	systemctl stop appmanager
	sleep 1
fi

if [ -f "/usr/lib/systemd/systemd" ]; then
	chmod 644 $INSTALL_DIR/script/appmanager.systemd.service
	cp -f $INSTALL_DIR/script/appmanager.systemd.service /lib/systemd/system/appmanager.service
else
	chmod 744 $INSTALL_DIR/script/appmanager.initd.sh
	cp -f $INSTALL_DIR/script/appmanager.initd.sh /etc/init.d/appmanager
fi

rm -rf /usr/bin/appc
ln -s /opt/appmanager/script/appc.sh /usr/bin/appc
chmod +x /opt/appmanager/script/appc.sh

systemctl start appmanager
systemctl enable appmanager
systemctl daemon-reload

