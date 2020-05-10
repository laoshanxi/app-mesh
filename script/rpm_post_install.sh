#!/bin/bash
################################################################################
## RPM post installation script file, will be executed while installation
################################################################################
INSTALL_DIR=/opt/appmanager
if [ ! -d $INSTALL_DIR ]; then
	mkdir -p $INSTALL_DIR
elif [[ -f "/lib/systemd/system/appmanager.service" ]] || [[ -f "/etc/init.d/appmanager" ]]; then
	systemctl stop appmanager
	sleep 1
fi

if [ -f "/usr/lib/systemd/systemd" ]; then
	chmod 644 $INSTALL_DIR/script/appmgr.systemd.service
	cp -f $INSTALL_DIR/script/appmgr.systemd.service /lib/systemd/system/appmanager.service
	systemctl daemon-reload
else
	chmod 744 $INSTALL_DIR/script/appmgr.initd.sh
	cp -f $INSTALL_DIR/script/appmgr.initd.sh /etc/init.d/appmanager
fi

# bash completion
if [ -d "/usr/share/bash-completion/completions" ]; then
	cp -f $INSTALL_DIR/script/bash_completion.sh /usr/share/bash-completion/completions/appc
fi

if [[ "$APPMGR_FRESH_INSTALL" = "Y" ]] || [[ ! -f "/opt/appmanager/ssl/server.pem" ]]; then
	# ssl cert gernerate
	cd /opt/appmanager/ssl/; sh /opt/appmanager/ssl/ssl_cert_generate.sh
fi
if [[ ! "$APPMGR_FRESH_INSTALL" = "Y" ]] && [ -f "/opt/appmanager/.appsvc.json" ]; then
	# restore previous configuration file
	mv /opt/appmanager/.appsvc.json /opt/appmanager/appsvc.json
else
	sed -i "s/MYHOST/$(hostname -f)/g" /opt/appmanager/appsvc.json
fi

# create appc softlink
rm -rf /usr/bin/appc
ln -s /opt/appmanager/script/appc.sh /usr/bin/appc
chmod +x /opt/appmanager/script/appc.sh

# start service directly
systemctl enable appmanager
systemctl start appmanager
