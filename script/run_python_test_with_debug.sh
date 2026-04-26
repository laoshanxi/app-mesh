#!/usr/bin/env bash
# Helper for CI to run the Python integration tests with structured debug context on failure.
#
# Strictly additive wrapper:
#  - Runs the test ONCE (the previous "run twice" pattern existed to work around flakiness
#    that the SDK fixes — auto_refresh_token, atomic add+subscribe, WSS PING/PONG — have
#    eliminated; CI time halved).
#  - Never aborts on its own diagnostic helpers (best-effort log/grep/stat are all guarded).
#  - Pure POSIX-ish bash, works on Ubuntu 18/22/24 (bash 4.4–5.x), CentOS 7 (bash 4.2), macOS (bash 3.2).
#
# Usage: run_python_test_with_debug.sh <python-test-script-path>
# Env knobs:
#   APPMESH_SERVER_LOG  override path to daemon log (default /opt/appmesh/work/server.log)
#   APPMESH_PID_FILE    override path to daemon pid file (default /opt/appmesh/appmesh.pid)

TEST_SCRIPT="${1:-}"
if [ -z "${TEST_SCRIPT}" ]; then
    echo "usage: $0 <test-script-path>" >&2
    exit 2
fi
if [ ! -f "${TEST_SCRIPT}" ]; then
    echo "test script not found: ${TEST_SCRIPT}" >&2
    exit 2
fi

SERVER_LOG="${APPMESH_SERVER_LOG:-/opt/appmesh/work/server.log}"
PID_FILE="${APPMESH_PID_FILE:-/opt/appmesh/appmesh.pid}"
DAEMON_BIN="${APPMESH_DAEMON_BIN:-/opt/appmesh/bin/appsvc}"
SUSPECT_PATTERNS='500 InternalServerError|412 RuntimeError|404 NotFound|apiFileDownload|/etc/hosts|fileStat|file_download|throw|exception|deadlock|aborted|abort|crash|core dumped|signal|backtrace|terminate called|SIGSEGV|SIGABRT|error:'

# GitHub Actions log group helpers (plain text outside GHA)
gha_group()    { printf '::group::%s\n' "$*"; }
gha_endgroup() { printf '::endgroup::\n'; }
gha_notice()   { printf '::notice::%s\n' "$*"; }

snapshot_log_offset() {
    [ -r "${SERVER_LOG}" ] || { echo 0; return; }
    local size
    size=$(wc -c < "${SERVER_LOG}" 2>/dev/null | tr -d ' \t\n')
    case "${size}" in
        ''|*[!0-9]*) echo 0 ;;
        *)           echo "${size}" ;;
    esac
}

dump_log_delta_since() {
    local off="${1:-0}"
    if [ ! -r "${SERVER_LOG}" ]; then
        echo "(server.log not readable at ${SERVER_LOG})"
        return 0
    fi
    local total
    total=$(snapshot_log_offset)
    local skip=$((off > 0 ? off : 0))
    if [ "${total}" -le "${skip}" ]; then
        echo "(no new log entries since previous offset=${skip})"
        return 0
    fi
    # tail -c +N is POSIX (N is 1-based byte offset). Skip first ${skip} bytes -> start at byte skip+1.
    tail -c "+$((skip + 1))" "${SERVER_LOG}" 2>/dev/null || true
}

dump_suspect_entries() {
    if [ -r "${SERVER_LOG}" ]; then
        grep -nE "${SUSPECT_PATTERNS}" "${SERVER_LOG}" | tail -200 || true
    fi
}

dump_environment_snapshot() {
    gha_group "env snapshot"
    echo "----- uname / OS -----"
    uname -a 2>&1 || true
    command -v sw_vers >/dev/null 2>&1 && sw_vers 2>&1 || true
    [ -r /etc/os-release ] && cat /etc/os-release 2>&1 || true
    echo "----- limits -----"
    ulimit -a 2>&1 || true
    echo "----- coredump config -----"
    [ -r /proc/sys/kernel/core_pattern ] && echo "core_pattern: $(cat /proc/sys/kernel/core_pattern)"
    [ -r /proc/sys/fs/suid_dumpable ]    && echo "suid_dumpable: $(cat /proc/sys/fs/suid_dumpable)"
    if [ -r "${PID_FILE}" ]; then
        local pid
        pid=$(cat "${PID_FILE}" 2>/dev/null)
        if [ -n "${pid}" ] && [ -r "/proc/${pid}/limits" ]; then
            echo "daemon ${pid} core limit: $(grep -i 'core file size' /proc/${pid}/limits 2>/dev/null)"
        fi
    fi
    echo "----- /etc/hosts info (test_22 target) -----"
    ls -la /etc/hosts /private/etc/hosts 2>&1 | head -5 || true
    if command -v stat >/dev/null 2>&1; then
        stat -L /etc/hosts 2>&1 || stat /etc/hosts 2>&1 || true
    fi
    head -3 /etc/hosts 2>&1 || true
    echo "----- daemon process -----"
    ps -ef 2>/dev/null | grep -E "appsvc|appmesh\.agent" | grep -v grep || true
    [ -r "${PID_FILE}" ] && echo "appmesh.pid=$(cat "${PID_FILE}" 2>/dev/null)" || true
    echo "----- daemon work dir -----"
    ls -la /opt/appmesh/work/ 2>&1 | head -20 || true
    gha_endgroup
}

find_recent_core() {
    # Print the most recently modified core file path, if any. Search common locations.
    local cores
    cores=$(ls -t /cores/core.* /tmp/core.* /var/lib/systemd/coredump/core.* /var/crash/core.* 2>/dev/null | head -1)
    if [ -n "${cores}" ] && [ -f "${cores}" ]; then
        echo "${cores}"
    fi
}

extract_backtrace_from_core() {
    local core="$1"
    [ -z "${core}" ] && return 1
    [ ! -r "${core}" ] && return 1
    [ ! -x "${DAEMON_BIN}" ] && { echo "(daemon binary ${DAEMON_BIN} missing — cannot resolve backtrace)"; return 1; }
    if command -v gdb >/dev/null 2>&1; then
        echo "----- gdb backtrace from ${core} -----"
        gdb -batch -ex "set pagination off" -ex "thread apply all bt" -ex "quit" "${DAEMON_BIN}" "${core}" 2>&1 | tail -200 || true
    elif command -v lldb >/dev/null 2>&1; then
        echo "----- lldb backtrace from ${core} -----"
        lldb -b -c "${core}" "${DAEMON_BIN}" -o "thread backtrace all" -o "quit" 2>&1 | tail -200 || true
    else
        echo "(neither gdb nor lldb available; core saved at ${core} for offline analysis)"
    fi
}

dump_running_daemon_stack() {
    # Best-effort: if daemon is still up but stuck, attach a debugger and dump all thread stacks.
    local pid=""
    if [ -r "${PID_FILE}" ]; then
        pid=$(cat "${PID_FILE}" 2>/dev/null)
    fi
    if [ -z "${pid}" ] || ! kill -0 "${pid}" 2>/dev/null; then
        echo "(daemon not running — skipping live stack dump)"
        return 0
    fi
    if command -v gdb >/dev/null 2>&1; then
        echo "----- gdb live thread stacks (pid ${pid}) -----"
        gdb -batch -ex "set pagination off" -ex "thread apply all bt" -ex "detach" -ex "quit" -p "${pid}" 2>&1 | tail -200 || true
    elif command -v lldb >/dev/null 2>&1; then
        echo "----- lldb live thread stacks (pid ${pid}) -----"
        # macOS lldb may need sudo + permissions; best-effort only
        sudo -n lldb -b -p "${pid}" -o "thread backtrace all" -o "detach" -o "quit" 2>&1 | tail -200 \
            || lldb -b -p "${pid}" -o "thread backtrace all" -o "detach" -o "quit" 2>&1 | tail -200 \
            || true
    else
        echo "(neither gdb nor lldb available; cannot capture live stacks)"
    fi
}

dump_failure_context() {
    local label="$1"
    local off="$2"
    gha_group "${label} — daemon process state"
    ps -ef 2>/dev/null | grep -E "appsvc|appmesh\.agent" | grep -v grep || echo "(daemon process not found — likely crashed)"
    [ -r "${PID_FILE}" ] && echo "appmesh.pid file present: $(cat "${PID_FILE}" 2>/dev/null)" || echo "(pid file missing)"
    if command -v ss >/dev/null 2>&1; then
        ss -tln 2>/dev/null | grep -E ':(6058|6059|6060) ' || echo "(no daemon listener on 6058/6059/6060)"
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tln 2>/dev/null | grep -E ':(6058|6059|6060) ' || echo "(no daemon listener on 6058/6059/6060)"
    fi
    # Crash detection: if pid recorded but process is gone -> daemon crashed
    if [ -r "${PID_FILE}" ]; then
        local pid
        pid=$(cat "${PID_FILE}" 2>/dev/null)
        if [ -n "${pid}" ] && ! kill -0 "${pid}" 2>/dev/null; then
            echo "::error::Daemon pid=${pid} from pid file is dead — DAEMON CRASHED"
        fi
    fi
    gha_endgroup
    gha_group "${label} — server.log full delta (since test start)"
    dump_log_delta_since "${off}"
    gha_endgroup
    gha_group "${label} — server.log suspect entries (full file)"
    dump_suspect_entries
    gha_endgroup
    gha_group "${label} — server.log tail (last 200 lines, in case delta/grep missed something)"
    [ -r "${SERVER_LOG}" ] && tail -n 200 "${SERVER_LOG}" || echo "(server.log not readable)"
    gha_endgroup
    gha_group "${label} — gdb wrapper backtrace (if daemon was wrapped)"
    local gdb_log
    for gdb_log in /cores/gdb-*.log; do
        if [ -r "${gdb_log}" ]; then
            echo "----- ${gdb_log} -----"
            cat "${gdb_log}" 2>&1 || true
        fi
    done
    gha_endgroup
    gha_group "${label} — crash dump backtrace"
    local core
    core=$(find_recent_core)
    if [ -n "${core}" ]; then
        echo "Most recent core dump: ${core}"
        ls -la "${core}" 2>&1 || true
        extract_backtrace_from_core "${core}"
    else
        echo "(no core dump found in /cores, /tmp, /var/lib/systemd/coredump, /var/crash)"
        if command -v coredumpctl >/dev/null 2>&1; then
            echo "----- coredumpctl recent -----"
            coredumpctl list --no-pager 2>&1 | tail -20 || true
            coredumpctl info appsvc --no-pager 2>&1 | tail -100 || true
        fi
    fi
    gha_endgroup
    gha_group "${label} — live daemon thread stacks (if still running)"
    dump_running_daemon_stack
    gha_endgroup
}

# ----- pre-test snapshot -----
dump_environment_snapshot

# ----- single run (gating) -----
off=$(snapshot_log_offset)
gha_notice "Python test run starts at $(date '+%F %T')"
set +e
python3 "${TEST_SCRIPT}"
rc=$?
set -e
if [ ${rc} -ne 0 ]; then
    dump_failure_context "test failed" "${off}"
    exit ${rc}
fi
exit 0
