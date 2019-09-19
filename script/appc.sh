#!/bin/bash
# by default, IFS is space which means space is string spliter
IFS=$'\n'
export LD_LIBRARY_PATH=/opt/appmanager/lib64:$LD_LIBRARY_PATH
/opt/appmanager/appc $@
