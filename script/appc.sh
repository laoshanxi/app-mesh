#!/bin/bash
################################################################################
## wrapper script for CLI binary appc
## with this script can avoid source environment before execute appc
################################################################################

# dynamic get script path and parent dir path
SCRIPT_ABS=$(readlink -f "$0")
SCRIPT_DIR=$(dirname $SCRIPT_ABS)
PROG_HOME=$(cd "${SCRIPT_DIR}/.."; pwd)

# by default, IFS is space which means space is string spliter
IFS=$'\n'
export LD_LIBRARY_PATH=${PROG_HOME}/lib64:${LD_LIBRARY_PATH}
${PROG_HOME}/bin/appc $@
