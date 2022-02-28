#!/bin/bash
################################################################################
## RPM post installation script file, will be executed while installation
################################################################################

export PROG_HOME=/opt/appmesh
export SYSTEMD_FILE=/etc/systemd/system/appmesh.service

if [ ! -d ${PROG_HOME} ]; then
	mkdir -p ${PROG_HOME}
elif [[ -f $SYSTEMD_FILE ]] || [[ -f "/etc/init.d/appmesh" ]]; then
	systemctl stop appmesh
	sleep 1
fi

# systemd environment file: ${PROG_HOME}/script/appmesh.environment
cat /dev/null >${PROG_HOME}/script/appmesh.environment
for e in $(env); do
	key=$(echo $e | awk -F"=" '{print $1}')
	val=$(echo $e | awk -F"=" '{print $2}')
	if [[ $key == APPMESH_* ]]; then
		echo $key"="$val
		echo $e >>${PROG_HOME}/script/appmesh.environment
	fi
done

if [ -d "/etc/systemd/system/" ]; then
	chmod 644 ${PROG_HOME}/script/appmesh.systemd.service
	cp -f ${PROG_HOME}/script/appmesh.systemd.service $SYSTEMD_FILE
	# systemd user
	if [ -z ${APPMESH_DAEMON_EXEC_USER+x} ]; then
		echo "APPMESH_DAEMON_EXEC_USER not set, daemon run as root user"
	else
		sed -i "s#User=#User=${APPMESH_DAEMON_EXEC_USER}#g" $SYSTEMD_FILE
	fi
	# systemd user group
	if [ -z ${APPMESH_DAEMON_EXEC_USER_GROUP+x} ]; then
		echo "APPMESH_DAEMON_EXEC_USER_GROUP not set, daemon run as default user group"
	else
		sed -i "s#Group=#Group=${APPMESH_DAEMON_EXEC_USER_GROUP}#g" $SYSTEMD_FILE
	fi
	systemctl daemon-reload
else
	chmod 744 ${PROG_HOME}/script/appmesh.initd.sh
	cp -f ${PROG_HOME}/script/appmesh.initd.sh /etc/init.d/appmesh
fi

# bash completion
if [ -d "/usr/share/bash-completion/completions" ]; then
	cp -f ${PROG_HOME}/script/bash_completion.sh /usr/share/bash-completion/completions/appc
fi

if [[ "$APPMESH_FRESH_INSTALL" = "Y" ]] || [[ ! -f "${PROG_HOME}/ssl/server.pem" ]]; then
	# ssl cert gernerate
	cd ${PROG_HOME}/ssl/
	sh ${PROG_HOME}/ssl/ssl_cert_generate.sh
fi
if [[ "$APPMESH_FRESH_INSTALL" != "Y" ]] && [ -f "${PROG_HOME}/.config.json" ]; then
	# restore previous configuration file
	mv ${PROG_HOME}/.config.json ${PROG_HOME}/config.json
else
	sed -i "s/MYHOST/$(hostname -f)/g" ${PROG_HOME}/config.json
	rm -rf ${PROG_HOME}/work
fi
if [[ "$APPMESH_FRESH_INSTALL" != "Y" ]] && [ -f "${PROG_HOME}/.security.json" ]; then
	# restore previous security file
	mv ${PROG_HOME}/.security.json ${PROG_HOME}/security.json
fi
if [[ "$APPMESH_FRESH_INSTALL" != "Y" ]] && [ -f "${PROG_HOME}/.ldap.json" ]; then
	# restore previous security file
	mv ${PROG_HOME}/.ldap.json ${PROG_HOME}/ldap.json
fi

# create appc softlink
rm -rf /usr/bin/appc
ln -s ${PROG_HOME}/script/appc.sh /usr/bin/appc
chmod +x ${PROG_HOME}/script/appc.sh

# only allow root access config json file
# 600 rw-------
chmod 644 ${PROG_HOME}/config.json
chmod 600 ${PROG_HOME}/security.json
if [ -z ${APPMESH_DAEMON_EXEC_USER+x} ]; then
	echo "APPMESH_DAEMON_EXEC_USER not set"
else
	echo "APPMESH_DAEMON_EXEC_USER is set to $APPMESH_DAEMON_EXEC_USER"
	chown ${APPMESH_DAEMON_EXEC_USER} ${PROG_HOME} ${PROG_HOME}/ssl/* ${PROG_HOME}/*.json
	if [ -z ${APPMESH_DAEMON_EXEC_USER_GROUP+x} ]; then
		echo "APPMESH_DAEMON_EXEC_USER_GROUP not set"
	else
		echo "APPMESH_DAEMON_EXEC_USER_GROUP is set to $APPMESH_DAEMON_EXEC_USER_GROUP"
		chown ${APPMESH_DAEMON_EXEC_USER}:${APPMESH_DAEMON_EXEC_USER_GROUP} ${PROG_HOME} ${PROG_HOME}/ssl/* ${PROG_HOME}/*.json
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
