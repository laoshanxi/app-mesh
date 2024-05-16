#!/bin/bash
################################################################################
## RPM post installation script file, will be executed while installation
################################################################################

export PROG_HOME=/opt/appmesh
export SYSTEMD_FILE=/etc/systemd/system/appmesh.service
export INITD_FILE=/etc/init.d/appmesh

if [ ! -d ${PROG_HOME} ]; then
	mkdir -p ${PROG_HOME}
elif [ -f $SYSTEMD_FILE ] || [ -f "/etc/init.d/appmesh" ]; then
	systemctl stop appmesh
	sleep 1
fi

chmod +x ${PROG_HOME}/script/*.sh

# systemd environment file: ${PROG_HOME}/script/appmesh.environment
cat /dev/null >${PROG_HOME}/script/appmesh.environment
echo "LD_LIBRARY_PATH=/opt/appmesh/lib64:$LD_LIBRARY_PATH" >>${PROG_HOME}/script/appmesh.environment
echo "LANG=en_US.UTF-8" >>${PROG_HOME}/script/appmesh.environment
echo "LC_ALL=en_US.UTF-8" >>${PROG_HOME}/script/appmesh.environment
for e in $(env); do
	key=$(echo $e | awk -F"=" '{print $1}')
	val=$(echo $e | awk -F"=" '{print $2}')
	if [ $key == APPMESH_* ]; then
		echo $key"="$val
		echo "$e" >>${PROG_HOME}/script/appmesh.environment
	fi
done
# set default execute user to current user
# https://cloud.tencent.com/developer/ask/sof/878838
if [ 0"$APPMESH_DefaultExecUser" = "0" ]; then
	echo "APPMESH_DefaultExecUser=$LOGNAME" >>${PROG_HOME}/script/appmesh.environment
fi
cat ${PROG_HOME}/script/appmesh.environment

# check systemd or initd (systemd --test can not run with root)
# https://unix.stackexchange.com/questions/121654/convenient-way-to-check-if-system-is-using-systemd-or-sysvinit-in-bash
# https://www.linuxquestions.org/questions/linux-newbie-8/checking-if-i-have-systemd-or-init-d-4175639948/
if [ $(ps --no-headers -o comm 1) = "systemd" ]; then
	echo "installing systemd service"
	chmod 644 ${PROG_HOME}/script/appmesh.systemd.service
	cp -f ${PROG_HOME}/script/appmesh.systemd.service $SYSTEMD_FILE
	# systemd user
	if [ -z ${APPMESH_DAEMON_EXEC_USER+x} ]; then
		echo "App Mesh Service run with user: root"
	else
		sed -i "s#User=#User=${APPMESH_DAEMON_EXEC_USER}#g" $SYSTEMD_FILE
		echo "App Mesh Service run with user: ${APPMESH_DAEMON_EXEC_USER}"
	fi
	# systemd user group
	if [ -z ${APPMESH_DAEMON_EXEC_USER_GROUP+x} ]; then
		:
	else
		sed -i "s#Group=#Group=${APPMESH_DAEMON_EXEC_USER_GROUP}#g" $SYSTEMD_FILE
		echo "App Mesh Service run with user group: ${APPMESH_DAEMON_EXEC_USER_GROUP}"
	fi
	systemctl daemon-reload
else
	echo "installing initd service"
	chmod 744 ${PROG_HOME}/script/appmesh.initd.sh
	cp -f ${PROG_HOME}/script/appmesh.initd.sh ${INITD_FILE}
fi

# bash completion
if [ -d "/usr/share/bash-completion/completions" ]; then
	cp -f ${PROG_HOME}/script/bash_completion.sh /usr/share/bash-completion/completions/appc
	chmod 644 /usr/share/bash-completion/completions/appc
fi

if [ "$APPMESH_FRESH_INSTALL" = "Y" ] || [ ! -f "${PROG_HOME}/ssl/server.pem" ]; then
	# ssl cert gernerate
	cd ${PROG_HOME}/ssl/
	sh ${PROG_HOME}/ssl/ssl_cert_generate.sh
	chmod 644 ${PROG_HOME}/ssl/*.pem
fi
if [ "$APPMESH_FRESH_INSTALL" != "Y" ] && [ -f "${PROG_HOME}/.config.yaml" ]; then
	# restore previous configuration file
	mv ${PROG_HOME}/.config.yaml ${PROG_HOME}/config.yaml
else
	sed -i "s/MYHOST/$(hostname -f)/g" ${PROG_HOME}/config.yaml
	rm -rf ${PROG_HOME}/work
fi
if [ "$APPMESH_FRESH_INSTALL" != "Y" ] && [ -f "${PROG_HOME}/.security.yaml" ]; then
	# restore previous security file
	mv ${PROG_HOME}/.security.yaml ${PROG_HOME}/security.yaml
fi
if [ "$APPMESH_FRESH_INSTALL" != "Y" ] && [ -f "${PROG_HOME}/.ldap.yaml" ]; then
	# restore previous security file
	mv ${PROG_HOME}/.ldap.yaml ${PROG_HOME}/ldap.yaml
fi
if [ "$APPMESH_FRESH_INSTALL" != "Y" ] && [ -d "${PROG_HOME}/.apps" ]; then
	# restore apps dir
	rm -rf ${PROG_HOME}/apps
	mv ${PROG_HOME}/.apps ${PROG_HOME}/apps
fi

# create appc softlink
rm -rf /usr/bin/appc
ln -s ${PROG_HOME}/script/appc.sh /usr/bin/appc
chmod +x ${PROG_HOME}/script/appc.sh

# only allow root access config json file
# 600 rw-------
# 644 rw-r--r--
chmod 644 ${PROG_HOME}/config.yaml
chmod 644 ${PROG_HOME}/security.yaml
chmod o+rw ${PROG_HOME}/apps
if [ -z ${APPMESH_DAEMON_EXEC_USER+x} ]; then
	:
else
	echo "APPMESH_DAEMON_EXEC_USER=$APPMESH_DAEMON_EXEC_USER"
	chown ${APPMESH_DAEMON_EXEC_USER} ${PROG_HOME} ${PROG_HOME}/ssl/* ${PROG_HOME}/*.json
	if [ -z ${APPMESH_DAEMON_EXEC_USER_GROUP+x} ]; then
		:
	else
		echo "APPMESH_DAEMON_EXEC_USER_GROUP=$APPMESH_DAEMON_EXEC_USER_GROUP"
		chown ${APPMESH_DAEMON_EXEC_USER}:${APPMESH_DAEMON_EXEC_USER_GROUP} ${PROG_HOME} ${PROG_HOME}/ssl/* ${PROG_HOME}/*.json
	fi
fi

# start service
# systemctl enable appmesh
# systemctl start appmesh
echo "APPMESH_SECURE_INSTALLATION=$APPMESH_SECURE_INSTALLATION"
if [ "$APPMESH_SECURE_INSTALLATION" = "Y" ]; then
	# gernerate password for secure installation
	/usr/bin/appc appmginit
fi
echo "Install App Mesh complete"

