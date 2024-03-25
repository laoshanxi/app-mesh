#!/bin/bash
################################################################################
## wrapper script for CLI binary appc
## with this script can avoid source environment before execute appc
################################################################################
export PROG_HOME=/opt/appmesh

# by default, IFS is space which means space is string spliter
IFS=$'\n'
export LD_LIBRARY_PATH=${PROG_HOME}/lib64:${LD_LIBRARY_PATH}
${PROG_HOME}/bin/appc $@
