#!/usr/bin/env bash
set -euo pipefail

umask 077

lease_dir="/run/camellia-remote-management"
lease_file="$lease_dir/maintenance.lease"
project_dir="/opt/camellia-remote-management"
env_file="/etc/camellia-remote-management/management.env"
systemctl_binary="/usr/bin/systemctl"
docker_binary="/usr/bin/docker"
deployment_lock="$lease_dir/deployment.lock"
stack_unit="camellia-remote-management-stack.service"
timers=(
    camellia-remote-management-backup.timer
    camellia-remote-management-cleanup.timer
)
operation_units=(
    camellia-remote-management-backup.service
    camellia-remote-management-cleanup.service
)

die() {
    echo "maintenance error: $*" >&2
    exit 1
}

usage() {
    cat >&2 <<'EOF'
usage:
  management-maintenance.sh enter [--reason TEXT]
  management-maintenance.sh status
  management-maintenance.sh leave --confirm-validated
EOF
    exit 2
}

[[ $# -ge 1 ]] || usage
command="$1"
shift
reason="operator-requested"
confirmed=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --reason)
            [[ $# -ge 2 ]] || usage
            reason="$2"
            shift 2
            ;;
        --confirm-validated)
            confirmed=true
            shift
            ;;
        *) usage ;;
    esac
done

[[ "$command" == "enter" || "$command" == "status" || "$command" == "leave" ]] || usage
if [[ "$command" == "leave" && "$confirmed" != true ]]; then
    echo "maintenance error: leave requires --confirm-validated" >&2
    exit 2
fi
if [[ "$command" != "enter" && "$reason" != "operator-requested" ]]; then
    usage
fi
[[ "$(id -u)" -eq 0 ]] || die "must run as root"
[[ ${#reason} -le 160 && "$reason" =~ ^[[:alnum:]_.:@/+\ -]+$ ]] || die "maintenance reason is invalid"
[[ -x "$systemctl_binary" && ! -L "$systemctl_binary" ]] || die "systemctl is unavailable or symlinked"
[[ -x "$docker_binary" && ! -L "$docker_binary" ]] || die "docker is unavailable or symlinked"

validate_lease() {
    [[ -f "$lease_file" && ! -L "$lease_file" ]] || die "maintenance lease is missing or unsafe"
    local mode owner
    mode="$(stat -c '%a' -- "$lease_file")"
    owner="$(stat -c '%u' -- "$lease_file")"
    local mode_value=$((8#$mode))
    (( owner == 0 && (mode_value & 077) == 0 && (mode_value & 0400) != 0 )) ||
        die "maintenance lease has unsafe owner or permissions"
}

stack_state() {
    "$systemctl_binary" show --property=ActiveState --value "$stack_unit"
}

compose() {
    "$docker_binary" compose --env-file "$env_file" -f "$project_dir/docker-compose.yaml" "$@"
}

prepare_runtime_dir() {
    if [[ -e "$lease_dir" || -L "$lease_dir" ]]; then
        [[ -d "$lease_dir" && ! -L "$lease_dir" ]] || die "maintenance runtime path is unsafe"
    else
        install -d -o root -g root -m 0700 "$lease_dir"
    fi
    local mode owner mode_value
    mode="$(stat -c '%a' -- "$lease_dir")"
    owner="$(stat -c '%u' -- "$lease_dir")"
    mode_value=$((8#$mode))
    (( owner == 0 && (mode_value & 077) == 0 )) || die "maintenance runtime directory is unsafe"
}

acquire_deployment_lock() {
    prepare_runtime_dir
    if [[ -e "$deployment_lock" || -L "$deployment_lock" ]]; then
        [[ -f "$deployment_lock" && ! -L "$deployment_lock" ]] || die "deployment lock is unsafe"
    fi
    exec 9>>"$deployment_lock"
    chmod 0600 "$deployment_lock"
    local mode owner mode_value
    mode="$(stat -c '%a' -- "$deployment_lock")"
    owner="$(stat -c '%u' -- "$deployment_lock")"
    mode_value=$((8#$mode))
    (( owner == 0 && (mode_value & 077) == 0 )) || die "deployment lock has unsafe owner or permissions"
    flock -w 600 9 || die "another deployment operation did not finish within 10 minutes"
}

if [[ "$command" == "status" ]]; then
    if [[ -e "$lease_file" || -L "$lease_file" ]]; then
        validate_lease
        echo "maintenance:active"
        sed -n '1,4p' "$lease_file"
    else
        echo "maintenance:inactive"
    fi
    echo "stack:$(stack_state)"
    exit 0
fi

[[ -f "$env_file" && ! -L "$env_file" ]] || die "management environment file is missing or symlinked"
[[ -f "$project_dir/docker-compose.yaml" && ! -L "$project_dir/docker-compose.yaml" ]] ||
    die "docker compose file is missing or symlinked"

if [[ "$command" == "enter" ]]; then
    # Deployment start and maintenance transitions share this lock.  The lease
    # is created only after any in-flight start has reached a terminal state.
    acquire_deployment_lock
    if [[ -e "$lease_file" || -L "$lease_file" ]]; then
        validate_lease
        echo "maintenance:already-active"
        exit 0
    fi
    if ! (set -o noclobber; printf 'version=1\nstarted_at=%s\nreason=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$reason" >"$lease_file"); then
        die "cannot create maintenance lease"
    fi
    chmod 0600 "$lease_file"
    chown root:root "$lease_file"

    # The lease is created before stopping timers, so a concurrently queued
    # operation is skipped by its ExecCondition instead of touching Docker.
    "$systemctl_binary" stop "${timers[@]}"
    "$systemctl_binary" stop "${operation_units[@]}"
    "$systemctl_binary" stop "$stack_unit"
    state="$(stack_state)"
    [[ "$state" == "inactive" || "$state" == "failed" ]] || die "stack did not stop (state=$state); lease remains active"
    if ! remaining_containers="$(compose ps --quiet)"; then
        die "cannot inspect deployment containers; lease remains active"
    fi
    [[ -z "$remaining_containers" ]] || die "deployment containers remain; lease remains active"
    echo "maintenance:entered reason=$reason"
    echo "timers and stack are stopped; the lease remains until an explicitly validated leave"
    exit 0
fi

acquire_deployment_lock
validate_lease
for unit in "${timers[@]}" "${operation_units[@]}" "$stack_unit"; do
    state="$($systemctl_binary show --property=ActiveState --value "$unit")"
    [[ "$state" != "active" && "$state" != "activating" && "$state" != "reloading" && "$state" != "deactivating" ]] ||
        die "$unit must be stopped before leaving maintenance"
done
if ! remaining_containers="$(compose ps --quiet)"; then
    die "cannot inspect deployment containers; lease remains active"
fi
[[ -z "$remaining_containers" ]] || die "deployment containers must be stopped before leaving maintenance"
unlink -- "$lease_file"
echo "maintenance:left"
echo "start the stack, validate readiness, and then explicitly start both timers"
