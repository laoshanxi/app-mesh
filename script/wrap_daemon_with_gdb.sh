#!/usr/bin/env bash
# Replace /opt/appmesh/bin/appsvc with a gdb wrapper that, on any crash, appends a full
# thread backtrace to /cores/gdb-${OS_TAG}.log. The CI failure handler dumps that log to
# the workflow output, so the stack appears inline (no artifact download needed).
#
# Usage: wrap_daemon_with_gdb.sh <os-tag>
set -eu

OS_TAG="${1:?os tag required}"
REAL=/opt/appmesh/bin/appsvc
BACKUP="${REAL}.real"
LOG="/cores/gdb-${OS_TAG}.log"

[ -x "$REAL" ] || { echo "$REAL not found"; exit 1; }
command -v gdb >/dev/null || { echo "gdb not installed"; exit 1; }

[ -e "$BACKUP" ] || mv "$REAL" "$BACKUP"

# Heredoc: unquoted EOF expands ${LOG}/${BACKUP}; \$@ stays literal so the wrapper passes
# its own argv through. \\n becomes \n in the file, which gdb echo prints as a newline.
cat > "$REAL" <<EOF
#!/bin/bash
exec gdb -batch -nx -q \\
    -ex 'set pagination off' \\
    -ex 'set logging file ${LOG}' \\
    -ex 'set logging redirect on' \\
    -ex 'set logging overwrite off' \\
    -ex 'set logging on' \\
    -ex 'handle SIGPIPE nostop noprint pass' \\
    -ex 'handle SIGUSR1 nostop noprint pass' \\
    -ex 'handle SIGUSR2 nostop noprint pass' \\
    -ex 'handle SIGCHLD nostop noprint pass' \\
    -ex 'run' \\
    -ex 'echo \\n=== CRASH STACK ===\\n' \\
    -ex 'info signal' \\
    -ex 'thread apply all bt full' \\
    -ex 'echo === CRASH END ===\\n' \\
    -ex 'quit' \\
    --args "${BACKUP}" "\$@"
EOF
chmod +x "$REAL"
echo "wrapped: $REAL -> gdb --args $BACKUP (log: $LOG)"
