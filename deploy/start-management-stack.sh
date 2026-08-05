#!/usr/bin/env bash
set -euo pipefail

umask 077

project_dir="/opt/camellia-remote-management"
env_file="/etc/camellia-remote-management/management.env"
runtime_dir="/run/camellia-remote-management"
lease_file="$runtime_dir/maintenance.lease"
docker_binary="/usr/bin/docker"

die() {
    echo "stack start error: $*" >&2
    exit 1
}

usage() {
    echo "usage: $0 [--project-dir ABSOLUTE_PATH] [--env-file ABSOLUTE_PATH] [--runtime-dir ABSOLUTE_PATH] [--lease-file ABSOLUTE_PATH] [--docker-binary ABSOLUTE_PATH]" >&2
    exit 2
}

require_canonical_path() {
    local path="$1"
    local description="$2"
    local resolved
    resolved="$(realpath -e -- "$path" 2>/dev/null)" || die "$description does not exist or cannot be resolved"
    [[ "$resolved" == "$path" ]] || die "$description must be an existing canonical path without symlinks"
}

require_owned_path() {
    local path="$1"
    local description="$2"
    local mode owner mode_value
    mode="$(stat -c '%a' -- "$path" 2>/dev/null)" || die "cannot inspect $description permissions"
    owner="$(stat -c '%u' -- "$path" 2>/dev/null)" || die "cannot inspect $description owner"
    mode_value=$((8#$mode))
    [[ "$owner" -eq "$(id -u)" ]] || die "$description has an unsafe owner"
    (( (mode_value & 022) == 0 )) || die "$description is writable by group or other users"
}

assert_no_maintenance_lease() {
    if [[ -e "$lease_file" || -L "$lease_file" ]]; then
        die "maintenance lease is active; validated leave is required before stack start"
    fi
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
        --lease-file)
            [[ $# -ge 2 ]] || usage
            lease_file="$2"
            shift 2
            ;;
        --docker-binary)
            [[ $# -ge 2 ]] || usage
            docker_binary="$2"
            shift 2
            ;;
        *) usage ;;
    esac
done

[[ "$project_dir" = /* && "$env_file" = /* && "$runtime_dir" = /* && "$lease_file" = /* ]] ||
    die "deployment paths must be absolute"
[[ "$lease_file" == "$runtime_dir/maintenance.lease" ]] ||
    die "maintenance lease must be the protected runtime-directory lease"
assert_no_maintenance_lease
[[ "$docker_binary" = /* && -f "$docker_binary" && ! -L "$docker_binary" && -x "$docker_binary" ]] ||
    die "docker binary is missing, symlinked, or not executable"
[[ -d "$project_dir" && ! -L "$project_dir" ]] || die "project directory is missing or symlinked"
[[ -f "$project_dir/docker-compose.yaml" && ! -L "$project_dir/docker-compose.yaml" ]] ||
    die "docker compose file is missing or symlinked"
[[ -f "$env_file" && ! -L "$env_file" && -r "$env_file" ]] ||
    die "management environment file is missing, symlinked, or unreadable"

require_canonical_path "$docker_binary" "docker binary"
require_canonical_path "$project_dir" "project directory"
require_canonical_path "$project_dir/docker-compose.yaml" "docker compose file"
require_canonical_path "$env_file" "management environment file"
require_owned_path "$docker_binary" "docker binary"
require_owned_path "$project_dir" "project directory"
require_owned_path "$project_dir/docker-compose.yaml" "docker compose file"

env_mode="$(stat -c '%a' -- "$env_file" 2>/dev/null)" || die "cannot inspect management environment permissions"
env_owner="$(stat -c '%u' -- "$env_file" 2>/dev/null)" || die "cannot inspect management environment owner"
env_mode_value=$((8#$env_mode))
expected_owner="$(id -u)"
if (( (env_mode_value & 077) != 0 || (env_mode_value & 0400) == 0 )) ||
    [[ "$env_owner" -ne "$expected_owner" ]]; then
    die "management environment file has unsafe owner or permissions"
fi

runtime_parent="$(dirname -- "$runtime_dir")"
require_canonical_path "$runtime_parent" "runtime parent directory"
if [[ -e "$runtime_dir" || -L "$runtime_dir" ]]; then
    [[ -d "$runtime_dir" && ! -L "$runtime_dir" ]] || die "runtime directory is not a safe directory"
else
    install -d -m 0700 "$runtime_dir"
fi
require_canonical_path "$runtime_dir" "runtime directory"
runtime_mode="$(stat -c '%a' -- "$runtime_dir" 2>/dev/null)" || die "cannot inspect runtime directory permissions"
runtime_owner="$(stat -c '%u' -- "$runtime_dir" 2>/dev/null)" || die "cannot inspect runtime directory owner"
runtime_mode_value=$((8#$runtime_mode))
if (( (runtime_mode_value & 077) != 0 )) || [[ "$runtime_owner" -ne "$expected_owner" ]]; then
    die "runtime directory has unsafe owner or permissions"
fi

lock_file="$runtime_dir/deployment.lock"
if [[ -e "$lock_file" || -L "$lock_file" ]]; then
    [[ -f "$lock_file" && ! -L "$lock_file" ]] || die "deployment lock is not a safe regular file"
fi
exec 9>>"$lock_file"
chmod 0600 "$lock_file"
lock_mode="$(stat -c '%a' -- "$lock_file" 2>/dev/null)" || die "cannot inspect deployment lock permissions"
lock_owner="$(stat -c '%u' -- "$lock_file" 2>/dev/null)" || die "cannot inspect deployment lock owner"
lock_mode_value=$((8#$lock_mode))
if (( (lock_mode_value & 077) != 0 )) || [[ "$lock_owner" -ne "$expected_owner" ]]; then
    die "deployment lock has unsafe owner or permissions"
fi
if ! flock -n 9; then
    echo "another deployment operation is active" >&2
    exit 75
fi
assert_no_maintenance_lease

compose=("$docker_binary" compose --env-file "$env_file" -f "$project_dir/docker-compose.yaml")
"${compose[@]}" config --quiet

# No old application generation may remain online while migration runs.
"${compose[@]}" stop --timeout 45 management
if ! running_services="$("${compose[@]}" ps --status running --services)"; then
    die "cannot inspect running services"
fi
if printf '%s\n' "$running_services" | grep -Fxq management; then
    die "management container remained online after stop"
fi

"${compose[@]}" rm --force --stop migrate
"${compose[@]}" up --detach --wait postgres
"${compose[@]}" run --rm --no-deps migrate
assert_no_maintenance_lease
"${compose[@]}" up --detach --wait --no-deps management

echo "stack-started:migration-verified"
