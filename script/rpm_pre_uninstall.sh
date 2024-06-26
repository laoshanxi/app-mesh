#!/bin/bash
################################################################################
## RPM pre uninstallation script file, will be executed before installation
################################################################################

export PROG_HOME=/opt/appmesh
export PROGC=bin/appc
export LD_LIBRARY_PATH=${PROG_HOME}/lib64:${LD_LIBRARY_PATH}

# stop all running applications
if [ -f "${PROG_HOME}/${PROGC}" ]; then
	${PROG_HOME}/${PROGC} logon -u admin -x admin123 || true
	${PROG_HOME}/${PROGC} view -l | awk '{if (NR>1){cmd="${PROG_HOME}/bin/appc disable -n "$2;print(cmd);system(cmd)}}'
fi
