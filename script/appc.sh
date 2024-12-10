#!/usr/bin/env bash
################################################################################
# Wrapper Script for appc CLI
# Executes the appc binary with necessary environment setup.
################################################################################

export PROG_HOME="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")/.." && pwd -P)"
export LD_LIBRARY_PATH="${PROG_HOME}/lib64:${LD_LIBRARY_PATH:-}"

# Modify IFS temporarily to handle arguments with spaces
ORIGINAL_IFS="$IFS"
IFS=$'\n'

# Execute appc with all passed arguments and capture exit status
"${PROG_HOME}/bin/appc" "$@"
exit_status=$?

# Restore the original IFS and exit with the status of appc
IFS="$ORIGINAL_IFS"
exit $exit_status
