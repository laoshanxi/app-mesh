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

DUMP_ONLY=0
DUMP_LABEL=""
if [ "${1:-}" = "--dump-only" ]; then
    DUMP_ONLY=1
    DUMP_LABEL="${2:-external failure}"
elif [ "$#" -lt 1 ]; then
    echo "usage: $0 <test-script-path> [more-test-scripts...]" >&2
    echo "       $0 --dump-only <label>" >&2
    exit 2
else
    for s in "$@"; do
        if [ ! -f "$s" ]; then
            echo "test script not found: $s" >&2
            exit 2
        fi
    done
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

# Run a command with sudo if available and allowed (NOPASSWD), else just run it directly.
# Used so the same script works in docker root containers (no sudo binary) and on macOS
# runners (need sudo to read root-owned core files).
run_maybe_sudo() {
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo -n "$@"
    else
        "$@"
    fi
}

# True if pid is a live process. Tolerates EPERM (cross-user) by preferring `ps -p`
# over `kill -0`, since the daemon runs under sudo and tests under the unprivileged
# runner user — `kill -0 root_pid` returns non-zero even when the process is alive.
daemon_pid_alive() {
    local pid="$1"
    [ -n "${pid}" ] || return 1
    if command -v ps >/dev/null 2>&1; then
        ps -p "${pid}" >/dev/null 2>&1 && return 0
    fi
    kill -0 "${pid}" 2>/dev/null
}

extract_backtrace_from_core() {
    local core="$1"
    if [ -z "${core}" ]; then echo "(no core path supplied)"; return 1; fi
    if [ ! -e "${core}" ]; then echo "(core file ${core} disappeared)"; return 1; fi
    echo "core file: $(ls -la "${core}" 2>&1 || true)"
    # core may be owned by root with mode 400 (typical when daemon was started under sudo
    # on macOS, or when running inside docker as a non-root test stage). Try chmod first
    # so a follow-up gdb/lldb can read it without privilege; harmless if already readable.
    if [ ! -r "${core}" ]; then
        echo "(core ${core} not readable by $(id -un); attempting privilege escalation)"
        run_maybe_sudo chmod +r "${core}" 2>/dev/null || true
    fi
    if [ ! -x "${DAEMON_BIN}" ]; then
        echo "(daemon binary ${DAEMON_BIN} missing — cannot resolve backtrace; raw core kept at ${core})"
        return 1
    fi
    if command -v gdb >/dev/null 2>&1; then
        echo "----- gdb backtrace from ${core} -----"
        run_maybe_sudo gdb -batch -ex "set pagination off" -ex "thread apply all bt full" -ex "quit" "${DAEMON_BIN}" "${core}" 2>&1 | tail -400 || true
    elif command -v lldb >/dev/null 2>&1; then
        echo "----- lldb backtrace from ${core} -----"
        run_maybe_sudo lldb -b -c "${core}" "${DAEMON_BIN}" -o "thread backtrace all" -o "quit" 2>&1 | tail -400 || true
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
    if ! daemon_pid_alive "${pid}"; then
        echo "(daemon not running — skipping live stack dump)"
        return 0
    fi
    if command -v gdb >/dev/null 2>&1; then
        echo "----- gdb live thread stacks (pid ${pid}) -----"
        run_maybe_sudo gdb -batch -ex "set pagination off" -ex "thread apply all bt" -ex "detach" -ex "quit" -p "${pid}" 2>&1 | tail -200 || true
    elif command -v lldb >/dev/null 2>&1; then
        echo "----- lldb live thread stacks (pid ${pid}) -----"
        run_maybe_sudo lldb -b -p "${pid}" -o "thread backtrace all" -o "detach" -o "quit" 2>&1 | tail -200 || true
    else
        echo "(neither gdb nor lldb available; cannot capture live stacks)"
    fi
}

dump_linux_system_log() {
    # Linux-only. When the daemon disappears with no shutdown trail in server.log
    # (e.g., SIGKILL by OOM-killer or container reaper), kernel logs / dmesg are the
    # only place that records WHY. macOS uses dump_macos_system_log instead.
    [ "$(uname -s)" = "Linux" ] || return 0
    echo "----- dmesg tail (kernel oom / signal events) -----"
    if command -v dmesg >/dev/null 2>&1; then
        run_maybe_sudo dmesg --time-format=iso 2>/dev/null | tail -80 \
            || dmesg 2>/dev/null | tail -80 \
            || echo "(dmesg unavailable — typical inside docker without --privileged)"
    fi
    echo "----- recent appsvc/app-mesh hits in dmesg -----"
    run_maybe_sudo dmesg 2>/dev/null | grep -iE "appsvc|app-mesh|killed process|out of memory|oom-killer" | tail -40 \
        || true
    echo "----- /proc/meminfo (last few key lines) -----"
    [ -r /proc/meminfo ] && head -5 /proc/meminfo || true
    echo "----- daemon process tree (if anything left) -----"
    ps -elf 2>/dev/null | grep -E "appsvc|gdb|appmesh" | grep -v grep || echo "(no appsvc/gdb processes alive)"
}

dump_macos_system_log() {
    # macOS-only. When the daemon disappears with no shutdown trail in server.log
    # (typical for SIGKILL / sandbox / OOM / launchd termination), the macOS unified
    # log and DiagnosticReports are the only places that record WHY. Linux containers
    # have neither; this is a no-op there.
    [ "$(uname -s)" = "Darwin" ] || return 0
    if command -v log >/dev/null 2>&1; then
        echo "----- macOS unified log (last 5m, appsvc events) -----"
        # `log show` requires sudo to read system events on recent macOS.
        run_maybe_sudo log show --last 5m --style compact \
            --predicate 'process == "appsvc" OR senderImagePath CONTAINS "appsvc"' 2>&1 | tail -200 \
            || echo "(log show failed)"
    fi
    echo "----- macOS DiagnosticReports for appsvc -----"
    for d in /Library/Logs/DiagnosticReports "$HOME/Library/Logs/DiagnosticReports"; do
        if [ -d "$d" ]; then
            local reports
            reports=$(run_maybe_sudo find "$d" -maxdepth 1 -type f \( -name 'appsvc*' -o -name 'appmesh*' \) -mtime -1 2>/dev/null)
            if [ -n "$reports" ]; then
                echo "$reports" | while read -r r; do
                    echo "--- $r ---"
                    run_maybe_sudo cat "$r" 2>/dev/null | tail -120 || true
                done
            else
                echo "(no recent appsvc/appmesh reports in $d)"
            fi
        fi
    done
}

dump_failure_context() {
    local label="$1"
    local off="$2"
    # One consolidated group: daemon state + crash detection + server.log tail.
    gha_group "${label} — diagnostics"
    echo "----- daemon process state -----"
    ps -ef 2>/dev/null | grep -E "appsvc|appmesh\.agent" | grep -v grep || echo "(daemon process not found — likely crashed)"
    if [ -r "${PID_FILE}" ]; then
        local pid
        pid=$(cat "${PID_FILE}" 2>/dev/null)
        echo "pid file: ${pid}"
        if [ -n "${pid}" ] && ! daemon_pid_alive "${pid}"; then
            echo "::error::Daemon pid=${pid} from pid file is dead — DAEMON CRASHED"
        fi
    else
        echo "(pid file missing)"
    fi
    echo "----- server.log tail (last 200 lines) -----"
    [ -r "${SERVER_LOG}" ] && tail -n 200 "${SERVER_LOG}" || echo "(server.log not readable)"
    # macOS .ips crash reports / Linux dmesg — only printed when the OS produced one.
    dump_macos_system_log
    dump_linux_system_log
    gha_endgroup

    # Second group only if a core file actually exists; skip otherwise to avoid noise.
    local core
    core=$(find_recent_core)
    if [ -n "${core}" ]; then
        gha_group "${label} — crash backtrace (${core})"
        ls -la "${core}" 2>&1 || true
        extract_backtrace_from_core "${core}"
        gha_endgroup
    fi
}

# ----- pre-test snapshot -----
dump_environment_snapshot

# ----- dump-only mode: external caller (e.g. failed go test) just wants the
#       full daemon diagnostic block, not to run any Python test.
if [ "${DUMP_ONLY}" = "1" ]; then
    printf '::error::%s — dumping daemon diagnostics\n' "${DUMP_LABEL}"
    dump_failure_context "${DUMP_LABEL}" "0"
    exit 0
fi

# ----- pre-flight: refuse to run 199 tests against a dead daemon -----
# When the daemon dies before/at startup the whole suite fans out into 199 connection-refused
# tracebacks, drowning the real diagnostics. Detect that up-front, dump backtrace, exit fast.
preflight_daemon_ok() {
    local pid=""
    [ -r "${PID_FILE}" ] && pid=$(cat "${PID_FILE}" 2>/dev/null)
    daemon_pid_alive "${pid}"
}

if ! preflight_daemon_ok; then
    # Make the failure visible WITHOUT relying on the user expanding GHA groups.
    printf '::error::Daemon dead before tests started — skipping suite, dumping backtrace inline\n'
    dump_failure_context "preflight: daemon dead" "0"
    exit 97
fi

# ----- run each script in order, stop + dump on the first failure -----
# Multi-script support is so callers can chain e.g. test_appmesh_client.py + sample.py
# under one wrapper; without this, sample.py crashes lose all daemon diagnostics.
off=$(snapshot_log_offset)
gha_notice "Python test run starts at $(date '+%F %T')"
for script in "$@"; do
    gha_notice "Running ${script}"
    set +e
    python3 -W ignore::ResourceWarning "${script}"
    rc=$?
    set -e
    if [ ${rc} -ne 0 ]; then
        # Surface the headline error outside any group so it's visible without expanding folds.
        crashed_pid=""
        [ -r "${PID_FILE}" ] && crashed_pid=$(cat "${PID_FILE}" 2>/dev/null)
        if [ -n "${crashed_pid}" ] && ! daemon_pid_alive "${crashed_pid}"; then
            printf '::error::Daemon CRASHED during %s — backtrace below in "crash dump backtrace" group\n' "${script}"
        else
            printf '::error::%s failed (rc=%s) — see groups below\n' "${script}" "${rc}"
        fi
        dump_failure_context "test failed: ${script}" "${off}"
        exit ${rc}
    fi
done
exit 0
