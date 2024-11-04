#!/bin/bash
################################################################################
# Wrapper Script for appc CLI
# Executes the appc binary with necessary environment setup.
################################################################################

export PROG_HOME="/opt/appmesh"
export LD_LIBRARY_PATH="${PROG_HOME}/lib64:${LD_LIBRARY_PATH}"

# Modify IFS temporarily to handle arguments with spaces
ORIGINAL_IFS="$IFS"
IFS=$'\n'

# Execute appc with all passed arguments and capture exit status
"${PROG_HOME}/bin/appc" "$@"
exit_status=$?

# Restore the original IFS and exit with the status of appc
IFS="$ORIGINAL_IFS"
exit $exit_status
