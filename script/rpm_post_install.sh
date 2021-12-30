#!/bin/bash
################################################################################
## RPM post installation script file, will be executed while installation
################################################################################

INSTALL_DIR=/opt/appmesh
SYSTEMD_FILE=/etc/systemd/system/appmesh.service
if [ ! -d ${INSTALL_DIR} ]; then
	mkdir -p ${INSTALL_DIR}
elif [[ -f $SYSTEMD_FILE ]] || [[ -f "/etc/init.d/appmesh" ]]; then
	systemctl stop appmesh
	sleep 1
fi

# systemd environment file: /opt/appmesh/script/appmesh.environment
cat /dev/null >/opt/appmesh/script/appmesh.environment
for e in $(env); do
	key=$(echo $e | awk -F"=" '{print $1}')
	val=$(echo $e | awk -F"=" '{print $2}')
	if [[ $key == APPMESH_* ]]; then
		echo $key"="$val
		echo $e >>/opt/appmesh/script/appmesh.environment
	fi
done

if [ -d "/etc/systemd/system/" ]; then
	chmod 644 ${INSTALL_DIR}/script/appmesh.systemd.service
	cp -f ${INSTALL_DIR}/script/appmesh.systemd.service $SYSTEMD_FILE
	# systemd user
	if [ -n ${APPMESH_DAEMON_EXEC_USER+1} ]; then
		sed -i "s#User=#User=${APPMESH_DAEMON_EXEC_USER}#g" $SYSTEMD_FILE
	fi
	# systemd user group
	if [ -n ${APPMESH_DAEMON_EXEC_USER_GROUP+1} ]; then
		sed -i "s#Group=#Group=${APPMESH_DAEMON_EXEC_USER_GROUP}#g" $SYSTEMD_FILE
	fi
	systemctl daemon-reload
else
	chmod 744 ${INSTALL_DIR}/script/appmesh.initd.sh
	cp -f ${INSTALL_DIR}/script/appmesh.initd.sh /etc/init.d/appmesh
fi

# bash completion
if [ -d "/usr/share/bash-completion/completions" ]; then
	cp -f ${INSTALL_DIR}/script/bash_completion.sh /usr/share/bash-completion/completions/appc
fi

if [[ "$APPMESH_FRESH_INSTALL" = "Y" ]] || [[ ! -f "${INSTALL_DIR}/ssl/server.pem" ]]; then
	# ssl cert gernerate
	cd ${INSTALL_DIR}/ssl/
	sh ${INSTALL_DIR}/ssl/ssl_cert_generate.sh
fi
if [[ "$APPMESH_FRESH_INSTALL" != "Y" ]] && [ -f "${INSTALL_DIR}/.config.json" ]; then
	# restore previous configuration file
	mv ${INSTALL_DIR}/.config.json ${INSTALL_DIR}/config.json
else
	sed -i "s/MYHOST/$(hostname -f)/g" ${INSTALL_DIR}/config.json
	rm -rf ${INSTALL_DIR}/work
fi
if [[ "$APPMESH_FRESH_INSTALL" != "Y" ]] && [ -f "${INSTALL_DIR}/.security.json" ]; then
	# restore previous security file
	mv ${INSTALL_DIR}/.security.json ${INSTALL_DIR}/security.json
fi
if [[ "$APPMESH_FRESH_INSTALL" != "Y" ]] && [ -f "${INSTALL_DIR}/.ldap.json" ]; then
	# restore previous security file
	mv ${INSTALL_DIR}/.ldap.json ${INSTALL_DIR}/ldap.json
fi

# create appc softlink
rm -rf /usr/bin/appc
ln -s ${INSTALL_DIR}/script/appc.sh /usr/bin/appc
chmod +x ${INSTALL_DIR}/script/appc.sh
if [ ! -d "${INSTALL_DIR}/work" ]; then
	mkdir ${INSTALL_DIR}/work
	chmod 777 ${INSTALL_DIR}/work
fi

# only allow root access config json file
# 600 rw-------
chmod 644 ${INSTALL_DIR}/config.json
chmod 600 ${INSTALL_DIR}/security.json
if [ -n ${APPMESH_DAEMON_EXEC_USER+1} ]; then
	chown ${APPMESH_DAEMON_EXEC_USER} ${INSTALL_DIR} ${INSTALL_DIR}/ssl/* ${INSTALL_DIR}/*.json
	if [ -n ${APPMESH_DAEMON_EXEC_USER_GROUP+1} ]; then
		chown ${APPMESH_DAEMON_EXEC_USER}:${APPMESH_DAEMON_EXEC_USER_GROUP} ${INSTALL_DIR} ${INSTALL_DIR}/ssl/* ${INSTALL_DIR}/*.json
	fi
fi

# start service
# systemctl enable appmesh
# systemctl start appmesh
if [[ "$APPMESH_SECURE_INSTALLATION" = "Y" ]]; then
	# gernerate password for secure installation
	/usr/bin/appc appmginit
fi

# add user appmesh
useradd appmesh -s /usr/sbin/nologin --no-create-home --user-group || true
