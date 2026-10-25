#!/usr/bin/env bash
set -euo pipefail

umask 077

project_dir="/opt/camellia-remote-management"
env_file="/etc/camellia-remote-management/management.env"
runtime_dir="/run/camellia-remote-management"
docker_binary="/usr/bin/docker"
controller=""
health_probe=""
notify_binary="/usr/bin/systemd-notify"
timeout_binary="/usr/bin/timeout"
max_cycles=0
controller_pid=""

die() {
    echo "management supervisor error: $*" >&2
    exit 125
}

usage() {
    echo "usage: $0 [--project-dir ABSOLUTE_PATH] [--env-file ABSOLUTE_PATH] [--runtime-dir ABSOLUTE_PATH] [--docker-binary ABSOLUTE_PATH] [--controller ABSOLUTE_PATH] [--health-probe ABSOLUTE_PATH] [--notify-binary ABSOLUTE_PATH] [--timeout-binary ABSOLUTE_PATH] [--max-cycles N]" >&2
    exit 2
}

require_integer_range() {
    local name="$1" value="$2" minimum="$3" maximum="$4"
    [[ "$value" =~ ^[0-9]+$ ]] || die "$name must be an integer"
    (( value >= minimum && value <= maximum )) || die "$name must be between $minimum and $maximum"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-dir)
            [[ $# -ge 2 ]] || usage
            project_dir="$2"
            shift 2
            ;;
        --env-file)
            [[ $# -ge 2 ]] || usage
            env_file="$2"
            shift 2
            ;;
        --runtime-dir)
            [[ $# -ge 2 ]] || usage
            runtime_dir="$2"
            shift 2
            ;;
        --docker-binary)
            [[ $# -ge 2 ]] || usage
            docker_binary="$2"
            shift 2
            ;;
        --controller)
            [[ $# -ge 2 ]] || usage
            controller="$2"
            shift 2
            ;;
        --health-probe)
            [[ $# -ge 2 ]] || usage
            health_probe="$2"
            shift 2
            ;;
        --notify-binary)
            [[ $# -ge 2 ]] || usage
            notify_binary="$2"
            shift 2
            ;;
        --timeout-binary)
            [[ $# -ge 2 ]] || usage
            timeout_binary="$2"
            shift 2
            ;;
        --max-cycles)
            [[ $# -ge 2 ]] || usage
            max_cycles="$2"
            shift 2
            ;;
        *) usage ;;
    esac
done

[[ -n "$controller" ]] || controller="$project_dir/start-management-stack.sh"
[[ -n "$health_probe" ]] || health_probe="$project_dir/deploy/check-management-health.sh"
for path in "$project_dir" "$env_file" "$runtime_dir" "$docker_binary" "$controller" "$health_probe" "$notify_binary" "$timeout_binary"; do
    [[ "$path" = /* ]] || die "all paths must be absolute"
done
[[ -d "$project_dir" && ! -L "$project_dir" ]] || die "project directory is missing or unsafe"
[[ -f "$env_file" && ! -L "$env_file" && -r "$env_file" ]] || die "environment file is missing or unsafe"
for executable in "$docker_binary" "$controller" "$health_probe" "$notify_binary" "$timeout_binary"; do
    [[ -f "$executable" && ! -L "$executable" && -x "$executable" ]] || die "required executable is missing or unsafe"
done

interval="${CAMELLIA_REMOTE_SUPERVISION_INTERVAL_SECONDS:-10}"
stable_successes="${CAMELLIA_REMOTE_SUPERVISION_STABLE_SUCCESSES:-3}"
recovery_limit="${CAMELLIA_REMOTE_SUPERVISION_RECOVERY_ATTEMPTS:-3}"
recovery_window="${CAMELLIA_REMOTE_SUPERVISION_RECOVERY_WINDOW_SECONDS:-600}"
health_timeout="${CAMELLIA_REMOTE_SUPERVISION_HEALTH_TIMEOUT_SECONDS:-15}"
require_integer_range CAMELLIA_REMOTE_SUPERVISION_INTERVAL_SECONDS "$interval" 1 60
require_integer_range CAMELLIA_REMOTE_SUPERVISION_STABLE_SUCCESSES "$stable_successes" 2 10
require_integer_range CAMELLIA_REMOTE_SUPERVISION_RECOVERY_ATTEMPTS "$recovery_limit" 1 5
require_integer_range CAMELLIA_REMOTE_SUPERVISION_RECOVERY_WINDOW_SECONDS "$recovery_window" 60 3600
require_integer_range CAMELLIA_REMOTE_SUPERVISION_HEALTH_TIMEOUT_SECONDS "$health_timeout" 1 30
require_integer_range max_cycles "$max_cycles" 0 100

if [[ -e "$runtime_dir" || -L "$runtime_dir" ]]; then
    [[ -d "$runtime_dir" && ! -L "$runtime_dir" ]] || die "runtime directory is unsafe"
else
    install -d -m 0700 "$runtime_dir"
fi
runtime_mode="$(stat -c '%a' -- "$runtime_dir")"
runtime_owner="$(stat -c '%u' -- "$runtime_dir")"
runtime_mode_value=$((8#$runtime_mode))
if (( (runtime_mode_value & 077) != 0 )) || [[ "$runtime_owner" -ne "$(id -u)" ]]; then
    die "runtime directory permissions are unsafe"
fi

state_file="$runtime_dir/admission.state"
if [[ -e "$state_file" || -L "$state_file" ]]; then
    [[ -f "$state_file" && ! -L "$state_file" ]] || die "admission state file is unsafe"
    state_mode="$(stat -c '%a' -- "$state_file")"
    state_owner="$(stat -c '%u' -- "$state_file")"
    state_mode_value=$((8#$state_mode))
    if (( (state_mode_value & 077) != 0 )) || [[ "$state_owner" -ne "$(id -u)" ]]; then
        die "admission state file permissions are unsafe"
    fi
fi
declare -a recovery_attempts=()
stable_count=0
notified_ready=false
cycle_count=0

publish_state() {
    local state="$1" reason="$2"
    local temporary="$state_file.tmp.$$"
    printf 'version=1\nstate=%s\nreason=%s\nobserved_at=%s\n' \
        "$state" "$reason" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$temporary"
    chmod 0600 "$temporary"
    mv -f -- "$temporary" "$state_file"
    echo "event=management_supervision state=$state reason=$reason" >&2
}

notify_status() {
    local status="$1"
    "$notify_binary" --status="$status" --watchdog >/dev/null || die "systemd notification failed"
}

stop_supervisor() {
    trap - HUP INT TERM
    if [[ -n "$controller_pid" ]] && kill -0 "$controller_pid" >/dev/null 2>&1; then
        kill -TERM "$controller_pid" >/dev/null 2>&1 || true
        wait "$controller_pid" >/dev/null 2>&1 || true
    fi
    publish_state isolated supervisor_stopping
    exit 0
}
trap stop_supervisor HUP INT TERM

run_controller() {
    local reason="$1" status
    publish_state isolated "$reason"
    "$notify_binary" --status="recovering:$reason" >/dev/null || die "systemd notification failed"
    "$controller" &
    controller_pid=$!
    while kill -0 "$controller_pid" >/dev/null 2>&1; do
        notify_status "recovering:$reason"
        # Poll frequently so a fast controller does not add the full
        # supervision interval to startup/recovery latency.  The watchdog
        # heartbeat remains much shorter than WatchdogSec=45s.
        sleep 1
    done
    set +e
    wait "$controller_pid"
    status=$?
    set -e
    controller_pid=""
    return "$status"
}

sleep_with_heartbeat() {
    local remaining="$1" slice
    while (( remaining > 0 )); do
        slice=$((remaining < 10 ? remaining : 10))
        sleep "$slice"
        remaining=$((remaining - slice))
        notify_status "supervising"
    done
}

if ! run_controller initial_start; then
    publish_state isolated initial_start_failed
    exit 1
fi

while true; do
    set +e
    probe_output="$(
        "$timeout_binary" --foreground --signal=TERM "$health_timeout" \
            "$health_probe" --project-dir "$project_dir" --env-file "$env_file" --docker-binary "$docker_binary"
    )"
    probe_status=$?
    set -e
    read -r classification process_state health_state extra <<<"$probe_output"
    [[ -z "${extra:-}" ]] || die "health probe returned an invalid result"
    now=$SECONDS

    case "$probe_status" in
        0)
            [[ "$classification $process_state $health_state" == "healthy running healthy" ]] ||
                die "health probe success result is invalid"
            stable_count=$((stable_count + 1))
            if (( stable_count >= stable_successes )); then
                publish_state ready stable
                recovery_attempts=()
                if [[ "$notified_ready" == false ]]; then
                    "$notify_binary" --ready --status="ready:stable" >/dev/null || die "systemd notification failed"
                    notified_ready=true
                else
                    notify_status "ready:stable"
                fi
            else
                publish_state isolated stabilizing
                notify_status "isolated:stabilizing success=$stable_count/$stable_successes"
            fi
            ;;
        10)
            stable_count=0
            publish_state isolated container_starting
            notify_status "isolated:container_starting"
            ;;
        20)
            stable_count=0
            publish_state isolated dependency_unhealthy
            notify_status "isolated:dependency_unhealthy"
            ;;
        30)
            stable_count=0
            publish_state isolated process_failure
            retained=()
            for attempted_at in "${recovery_attempts[@]}"; do
                if (( now - attempted_at < recovery_window )); then
                    retained+=("$attempted_at")
                fi
            done
            recovery_attempts=("${retained[@]}")
            if (( ${#recovery_attempts[@]} < recovery_limit )); then
                recovery_attempts+=("$now")
                attempt=${#recovery_attempts[@]}
                if ! run_controller "process_recovery_$attempt"; then
                    publish_state isolated process_recovery_failed
                fi
            else
                notify_status "isolated:recovery_exhausted attempts=${#recovery_attempts[@]}"
            fi
            ;;
        40)
            publish_state isolated control_failure
            exit 125
            ;;
        124)
            publish_state isolated health_probe_timeout
            exit 125
            ;;
        *)
            die "health probe returned an unsupported status"
            ;;
    esac

    cycle_count=$((cycle_count + 1))
    if (( max_cycles > 0 && cycle_count >= max_cycles )); then
        exit 0
    fi
    sleep_with_heartbeat "$interval"
done
