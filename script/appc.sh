#!/bin/bash
export LD_LIBRARY_PATH=/opt/appmanager/lib64:$LD_LIBRARY_PATH
/opt/appmanager/appc $@
