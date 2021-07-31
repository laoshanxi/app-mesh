#!/bin/bash
################################################################################
## wrapper script for CLI binary appc
## with this script can avoid source environment before execute appc
################################################################################

# by default, IFS is space which means space is string spliter
IFS=$'\n'
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/opt/appmesh/lib64
/opt/appmesh/bin/appc $@
