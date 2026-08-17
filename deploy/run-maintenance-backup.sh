#!/usr/bin/env bash
set -euo pipefail

umask 077

project_dir="${CAMELLIA_REMOTE_PROJECT_DIR:-/opt/camellia-remote-management}"
env_file="${CAMELLIA_REMOTE_ENV_FILE:-/etc/camellia-remote-management/management.env}"
backup_script="${CAMELLIA_REMOTE_BACKUP_SCRIPT:-$project_dir/backup-postgres.sh}"
backup_dir="${CAMELLIA_REMOTE_BACKUP_DIR:-/var/backups/camellia-remote-management}"
state_dir="${CAMELLIA_REMOTE_MAINTENANCE_STATE_DIR:-/var/lib/camellia-remote-management/maintenance}"
ledger_helper="${CAMELLIA_REMOTE_MAINTENANCE_LEDGER_HELPER:-$project_dir/scripts/maintenance_ledger.py}"
envelope_helper="${CAMELLIA_REMOTE_BACKUP_ENVELOPE_HELPER:-$project_dir/scripts/backup_envelope.py}"
guard_script="${CAMELLIA_REMOTE_MAINTENANCE_GUARD_SCRIPT:-$project_dir/deploy/management-maintenance-guard.sh}"
deadline_seconds="${CAMELLIA_REMOTE_BACKUP_OPERATION_TIMEOUT_SECONDS:-2700}"
heartbeat_seconds="${CAMELLIA_REMOTE_BACKUP_RUN_HEARTBEAT_SECONDS:-30}"
started_clock=$SECONDS
started_at="$(date -u +%Y%m%dT%H%M%SZ)"
operation_id=""
temporary_dir=""
stdout_file=""
stderr_file=""
stdout_fifo=""
stderr_fifo=""
stdout_tee_pid=""
stderr_tee_pid=""
child_pid=""
signal_received=""
termination_reason=""
termination_started=0
ledger_failed=0
scheduled_recorded=0
terminal_recorded=0

kill_process_tree() {
    local pid="$1" signal="$2" child
    [[ "$pid" =~ ^[0-9]+$ ]] || return 0
    if [[ -r "/proc/$pid/task/$pid/children" ]]; then
        local children
        children="$(< "/proc/$pid/task/$pid/children")"
        for child in $children; do
            kill_process_tree "$child" "$signal"
        done
    fi
    kill -"$signal" "$pid" >/dev/null 2>&1 || true
}

elapsed_seconds() {
    printf '%s\n' "$((SECONDS - started_clock))"
}

cleanup_resources() {
    trap - EXIT HUP INT TERM
    if [[ -n "$child_pid" ]] && kill -0 "$child_pid" >/dev/null 2>&1; then
        kill_process_tree "$child_pid" TERM
        wait "$child_pid" >/dev/null 2>&1 || true
    fi
    for pid in "$stdout_tee_pid" "$stderr_tee_pid"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
            kill -TERM "$pid" >/dev/null 2>&1 || true
            wait "$pid" >/dev/null 2>&1 || true
        fi
    done
    if [[ -n "$temporary_dir" ]]; then
        rm -f -- "$stdout_fifo" "$stderr_fifo" "$stdout_file" "$stderr_file"
        rmdir -- "$temporary_dir" >/dev/null 2>&1 || true
    fi
}

ledger_record() {
    local status="$1" reason="$2"
    shift 2
    if ! python3 "$ledger_helper" record \
        --state-dir "$state_dir" \
        --operation-id "$operation_id" \
        --kind backup \
        --status "$status" \
        --reason "$reason" \
        --started-at "$started_at" \
        --deadline-seconds "$deadline_seconds" \
        "$@" >/dev/null; then
        ledger_failed=1
        echo "maintenance backup wrapper error: ledger write failed status=$status reason=$reason" >&2
        return 1
    fi
    [[ "$status" == "scheduled" ]] && scheduled_recorded=1
    if [[ "$status" == "completed" || "$status" == "failed" || "$status" == "skipped" || "$status" == "unknown" ]]; then
        terminal_recorded=1
    fi
}

on_exit() {
    local status=$?
    if (( status != 0 && scheduled_recorded == 1 && terminal_recorded == 0 && ledger_failed == 0 )); then
        ledger_record failed wrapper-exit --duration-seconds "$(elapsed_seconds)" || true
    fi
    cleanup_resources
    exit "$status"
}
trap on_exit EXIT

die() {
    echo "maintenance backup wrapper error: $*" >&2
    exit 1
}

on_signal() {
    signal_received="signal"
}
trap on_signal HUP INT TERM

[[ "$project_dir" = /* && "$env_file" = /* && "$backup_script" = /* && "$backup_dir" = /* ]] || die "paths must be absolute"
[[ "$state_dir" = /* && "$ledger_helper" = /* && "$envelope_helper" = /* && "$guard_script" = /* ]] || die "helper paths must be absolute"
[[ -f "$env_file" && ! -L "$env_file" && -r "$env_file" ]] || die "environment file is missing or unsafe"
[[ -x "$backup_script" && ! -L "$backup_script" ]] || die "backup script is missing or unsafe"
[[ -f "$ledger_helper" && ! -L "$ledger_helper" && -r "$ledger_helper" ]] || die "maintenance ledger helper is missing"
[[ -f "$envelope_helper" && ! -L "$envelope_helper" && -r "$envelope_helper" ]] || die "backup envelope helper is missing"
[[ -x "$guard_script" && ! -L "$guard_script" ]] || die "maintenance guard is missing or unsafe"
[[ "$deadline_seconds" =~ ^[0-9]+$ && "$deadline_seconds" -ge 60 && "$deadline_seconds" -le 3600 ]] ||
    die "backup deadline must be between 60 and 3600 seconds"
[[ "$heartbeat_seconds" =~ ^[0-9]+$ && "$heartbeat_seconds" -ge 10 && "$heartbeat_seconds" -le 60 ]] ||
    die "backup heartbeat must be between 10 and 60 seconds"

operation_id="${INVOCATION_ID:-}"
if [[ -z "$operation_id" ]]; then
    operation_id="$(python3 "$envelope_helper" new-id)" || die "cannot allocate backup operation ID"
fi
[[ "$operation_id" =~ ^[0-9a-f]{32}$ ]] || die "backup operation ID is invalid"
ledger_record scheduled timer-triggered || die "cannot record scheduled backup"

set +e
guard_output="$($guard_script 2>&1)"
guard_status=$?
set -e
if (( guard_status == 1 )); then
    reason="not-running"
    [[ "$guard_output" == *"skipped:maintenance"* ]] && reason="maintenance"
    ledger_record skipped "$reason" --duration-seconds "$(elapsed_seconds)" || die "cannot record skipped backup"
    exit 0
fi
if (( guard_status != 0 )); then
    ledger_record failed guard-failure --duration-seconds "$(elapsed_seconds)" || true
    die "maintenance guard failed"
fi
ledger_record started execution-started || die "cannot record backup start"

temporary_dir="$(mktemp -d -p "$state_dir" ".backup-wrapper-$operation_id.XXXXXX")" || die "cannot create wrapper state directory"
chmod 0700 "$temporary_dir"
stdout_file="$temporary_dir/stdout"
stderr_file="$temporary_dir/stderr"
stdout_fifo="$temporary_dir/stdout.fifo"
stderr_fifo="$temporary_dir/stderr.fifo"
mkfifo -m 0600 "$stdout_fifo" "$stderr_fifo"
tee "$stdout_file" <"$stdout_fifo" &
stdout_tee_pid=$!
tee "$stderr_file" <"$stderr_fifo" >&2 &
stderr_tee_pid=$!

CAMELLIA_REMOTE_BACKUP_OPERATION_ID="$operation_id" \
    "$backup_script" >"$stdout_fifo" 2>"$stderr_fifo" &
child_pid=$!
next_heartbeat=$heartbeat_seconds
while kill -0 "$child_pid" >/dev/null 2>&1; do
    sleep 1 || true
    elapsed="$(elapsed_seconds)"
    if [[ -n "$signal_received" && -z "$termination_reason" ]]; then
        termination_reason=interrupted
        termination_started=$elapsed
        kill_process_tree "$child_pid" TERM
    elif (( elapsed >= deadline_seconds )) && [[ -z "$termination_reason" ]]; then
        termination_reason=deadline
        termination_started=$elapsed
        kill_process_tree "$child_pid" TERM
    fi
    if [[ -n "$termination_reason" ]] && (( elapsed >= termination_started + 15 )); then
        kill_process_tree "$child_pid" KILL
    elif [[ -z "$termination_reason" ]] && (( elapsed >= next_heartbeat )); then
        if ! ledger_record heartbeat backup-running --duration-seconds "$elapsed"; then
            termination_reason=ledger-failure
            termination_started=$elapsed
            kill_process_tree "$child_pid" TERM
        fi
        next_heartbeat=$((next_heartbeat + heartbeat_seconds))
    fi
done

set +e
wait "$child_pid"
child_status=$?
child_pid=""
wait "$stdout_tee_pid"
stdout_status=$?
stdout_tee_pid=""
wait "$stderr_tee_pid"
stderr_status=$?
stderr_tee_pid=""
set -e

elapsed="$(elapsed_seconds)"
if [[ "$termination_reason" == "interrupted" ]]; then
    ledger_record unknown interrupted --duration-seconds "$elapsed" || true
    exit 130
elif [[ "$termination_reason" == "deadline" ]]; then
    ledger_record failed deadline --duration-seconds "$elapsed" || true
    exit 124
elif [[ "$termination_reason" == "ledger-failure" || "$ledger_failed" -eq 1 ]]; then
    exit 1
elif (( stdout_status != 0 || stderr_status != 0 )); then
    ledger_record failed output-capture --duration-seconds "$elapsed" || true
    exit 1
fi

if (( child_status == 75 )) && grep -q 'skipped:active-run' "$stderr_file"; then
    ledger_record skipped active-run --duration-seconds "$elapsed" || true
    exit 75
elif (( child_status != 0 )); then
    ledger_record failed backup-exit --duration-seconds "$elapsed" || true
    exit "$child_status"
fi

result_json="$(tail -n 1 "$stdout_file")" || {
    ledger_record failed result-contract --duration-seconds "$elapsed" || true
    exit 1
}
metadata="$(CAMELLIA_REMOTE_BACKUP_RESULT="$result_json" python3 - "$backup_dir" "$operation_id" <<'PY'
import json
import os
import re
import stat
import sys

backup_dir = os.path.abspath(sys.argv[1])
operation_id = sys.argv[2]


def no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def read_json(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        encoded = os.read(fd, 4097)
    finally:
        os.close(fd)
    if not encoded or len(encoded) > 4096:
        raise ValueError("invalid status size")
    return json.loads(encoded.decode(), object_pairs_hook=no_duplicates)


directory = os.lstat(backup_dir)
if not stat.S_ISDIR(directory.st_mode) or stat.S_ISLNK(directory.st_mode):
    raise SystemExit(1)
result = json.loads(os.environ["CAMELLIA_REMOTE_BACKUP_RESULT"], object_pairs_hook=no_duplicates)
if set(result) != {"backup_id", "manifest", "status"} or result["status"] != "created:verified":
    raise SystemExit(1)
if result["backup_id"] != operation_id or not isinstance(result["manifest"], str):
    raise SystemExit(1)
manifest = os.path.abspath(result["manifest"])
match = re.fullmatch(r"backup-set-([0-9]{8}T[0-9]{6}Z)-([0-9a-f]{32})[.]manifest[.]age", os.path.basename(manifest))
if os.path.dirname(manifest) != backup_dir or match is None or match.group(2) != operation_id:
    raise SystemExit(1)
status_value = read_json(os.path.join(backup_dir, "latest-verified.json"))
required = {"backup_id", "completed_at", "format", "generation", "manifest_filename", "previous_backup_id", "recorded_at", "status"}
if set(status_value) != required or status_value["format"] != "camellia-remote-backup-status-v2":
    raise SystemExit(1)
if status_value["status"] != "verified" or status_value["backup_id"] != operation_id:
    raise SystemExit(1)
if status_value["manifest_filename"] != os.path.basename(manifest):
    raise SystemExit(1)
generation = status_value["generation"]
if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
    raise SystemExit(1)
stem = f"{match.group(1)}-{operation_id}"
paths = [
    os.path.join(backup_dir, f"postgres-{stem}.dump.age"),
    os.path.join(backup_dir, f"recordings-{stem}.bundle.age"),
    manifest,
]
total = 0
for path in paths:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        current = os.fstat(fd)
    finally:
        os.close(fd)
    if not stat.S_ISREG(current.st_mode) or current.st_mode & 0o077 or current.st_size < 1:
        raise SystemExit(1)
    total += current.st_size
print(generation, total)
PY
)" || {
    ledger_record failed result-contract --duration-seconds "$elapsed" || true
    exit 1
}
read -r generation output_bytes <<<"$metadata"
ledger_record completed verified --duration-seconds "$elapsed" \
    --artifact-generation "$generation" --output-bytes "$output_bytes" || exit 1
