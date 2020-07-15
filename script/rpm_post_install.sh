#!/bin/bash
################################################################################
## RPM post installation script file, will be executed while installation
################################################################################
INSTALL_DIR=/opt/appmesh
SYSTEMD_FILE=/etc/systemd/system/appmesh.service
if [ ! -d $INSTALL_DIR ]; then
	mkdir -p $INSTALL_DIR
elif [[ -f $SYSTEMD_FILE ]] || [[ -f "/etc/init.d/appmesh" ]]; then
	systemctl stop appmesh
	sleep 1
fi

if [ -d "/etc/systemd/system/" ]; then
	chmod 644 $INSTALL_DIR/script/appmesh.systemd.service
	cp -f $INSTALL_DIR/script/appmesh.systemd.service $SYSTEMD_FILE
	systemctl daemon-reload
else
	chmod 744 $INSTALL_DIR/script/appmesh.initd.sh
	cp -f $INSTALL_DIR/script/appmesh.initd.sh /etc/init.d/appmesh
fi

# bash completion
if [ -d "/usr/share/bash-completion/completions" ]; then
	cp -f $INSTALL_DIR/script/bash_completion.sh /usr/share/bash-completion/completions/appc
fi

if [[ "$APPMESH_FRESH_INSTALL" = "Y" ]] || [[ ! -f "/opt/appmesh/ssl/server.pem" ]]; then
	# ssl cert gernerate
	cd /opt/appmesh/ssl/; sh /opt/appmesh/ssl/ssl_cert_generate.sh
fi
if [[ "$APPMESH_FRESH_INSTALL" != "Y" ]] && [ -f "/opt/appmesh/.appsvc.json" ]; then
	# restore previous configuration file
	mv /opt/appmesh/.appsvc.json /opt/appmesh/appsvc.json
else
	sed -i "s/MYHOST/$(hostname -f)/g" /opt/appmesh/appsvc.json
	rm -rf /opt/appmesh/work
fi

# create appc softlink
rm -rf /usr/bin/appc
ln -s /opt/appmesh/script/appc.sh /usr/bin/appc
chmod +x /opt/appmesh/script/appc.sh
if [ ! -d "/opt/appmesh/work" ]; then
    mkdir /opt/appmesh/work
fi

# start service directly
systemctl enable appmesh
systemctl start appmesh

# add user appmesh
id appmesh >& /dev/null
if [ $? -ne 0 ]; then
    useradd appmesh -s /usr/sbin/nologin --no-create-home  || true
fi
