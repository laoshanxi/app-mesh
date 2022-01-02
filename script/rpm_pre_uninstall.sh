#!/bin/bash
################################################################################
## RPM pre uninstallation script file, will be executed before installation
################################################################################

PROG_HOME=/opt/appmesh

export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:${PROG_HOME}/lib64:/usr/local/lib64:/usr/local/lib/

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

# stop all running applications
if [ -f "${PROG_HOME}/bin/appc" ]; then
	${PROG_HOME}/bin/appc view -l | awk '{if (NR>1){cmd="${PROG_HOME}/bin/appc disable -n "$2;print(cmd);system(cmd)}}'
fi
