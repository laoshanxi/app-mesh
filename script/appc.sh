#!/bin/bash
################################################################################
## This Script file a wrapper of CLI binary "appc
################################################################################

# by default, IFS is space which means space is string spliter
IFS=$'\n'
export LD_LIBRARY_PATH=/opt/appmesh/lib64:$LD_LIBRARY_PATH
/opt/appmesh/appc $@
