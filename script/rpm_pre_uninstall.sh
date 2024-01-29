#!/bin/bash
################################################################################
## RPM pre uninstallation script file, will be executed before installation
################################################################################

export PROG_HOME=/opt/appmesh
export PROGC=bin/appc
export LD_LIBRARY_PATH=${PROG_HOME}/lib64:${LD_LIBRARY_PATH}

# backup configuration file to avoid overide when next installation
if [ -f "${PROG_HOME}/config.json" ]; then
	cp -f ${PROG_HOME}/config.json ${PROG_HOME}/.config.json
fi
if [ -f "${PROG_HOME}/security.json" ]; then
	cp -f ${PROG_HOME}/security.json ${PROG_HOME}/.security.json
fi
if [ -f "${PROG_HOME}/ldap.json" ]; then
	cp -f ${PROG_HOME}/ldap.json ${PROG_HOME}/.ldap.json
fi
if [ -d "${PROG_HOME}/apps" ]; then
	cp -rf ${PROG_HOME}/apps ${PROG_HOME}/.apps
fi

# stop all running applications
if [ -f "${PROG_HOME}/${PROGC}" ]; then
	${PROG_HOME}/${PROGC} logon -u admin -x admin123 -o "" || true
	${PROG_HOME}/${PROGC} view -l | awk '{if (NR>1){cmd="${PROG_HOME}/bin/appc disable -n "$2;print(cmd);system(cmd)}}'
fi
