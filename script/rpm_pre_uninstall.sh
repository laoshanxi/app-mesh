#!/bin/bash
################################################################################
## RPM pre uninstallation script file, will be executed before installation
################################################################################

export PROG_HOME=/opt/appmesh
export PROGC=bin/appc
export LD_LIBRARY_PATH=${PROG_HOME}/lib64:${LD_LIBRARY_PATH}

# disable script exit on error
set +e

# stop all running applications
if [ -f "${PROG_HOME}/${PROGC}" ]; then
	APP_DIR=${PROG_HOME}/work/apps
	TMP_DIR=${PROG_HOME}/work/.apps

	if [ -d "$APP_DIR" ] && [ "$(ls -A $APP_DIR)" ]; then
		rm -rf $TMP_DIR
		cp -rf $APP_DIR $TMP_DIR
	fi

	# ${PROG_HOME}/${PROGC} ls -l | awk '{if (NR>1){cmd="${PROG_HOME}/bin/appc disable -n "$2;print(cmd);system(cmd)}}'
	${PROG_HOME}/${PROGC} disable --all

	if [ -d "$TMP_DIR" ] && [ "$(ls -A $TMP_DIR)" ]; then
		rm -f ${APP_DIR}/*
		mv -f ${TMP_DIR}/* ${APP_DIR}/
		rm -rf $TMP_DIR
	fi

fi
