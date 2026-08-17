#!/usr/bin/env bash
set -euo pipefail

umask 077

project_dir="/opt/camellia-remote-management"
env_file="/etc/camellia-remote-management/management.env"
docker_binary="/usr/bin/docker"
budget_script=""

die() {
    echo "stack stop error: $*" >&2
    exit 1
}

usage() {
    echo "usage: $0 [--project-dir ABSOLUTE_PATH] [--env-file ABSOLUTE_PATH] [--docker-binary ABSOLUTE_PATH] [--budget-script ABSOLUTE_PATH]" >&2
    exit 2
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
        --docker-binary)
            [[ $# -ge 2 ]] || usage
            docker_binary="$2"
            shift 2
            ;;
        --budget-script)
            [[ $# -ge 2 ]] || usage
            budget_script="$2"
            shift 2
            ;;
        *) usage ;;
    esac
done

[[ "$project_dir" = /* && "$env_file" = /* && "$docker_binary" = /* ]] || die "deployment paths must be absolute"
[[ -d "$project_dir" && ! -L "$project_dir" ]] || die "project directory is missing or symlinked"
[[ -f "$project_dir/docker-compose.yaml" && ! -L "$project_dir/docker-compose.yaml" ]] || die "docker compose file is missing or symlinked"
[[ -f "$env_file" && ! -L "$env_file" && -r "$env_file" ]] || die "environment file is missing or unsafe"
[[ -x "$docker_binary" && ! -L "$docker_binary" ]] || die "docker binary is missing or unsafe"

if [[ -z "$budget_script" ]]; then
    budget_script="$project_dir/deploy/shutdown-budget.sh"
fi
[[ "$budget_script" = /* && -f "$budget_script" && ! -L "$budget_script" && -x "$budget_script" ]] ||
    die "shutdown budget script is missing or unsafe"

read -r _graceful docker_stop _systemd < <("$budget_script" --env-file "$env_file" --values) ||
    die "shutdown budget validation failed"
export CAMELLIA_REMOTE_DOCKER_STOP_GRACE_PERIOD_SECONDS="$docker_stop"

"$docker_binary" compose --env-file "$env_file" -f "$project_dir/docker-compose.yaml" \
    down --timeout "$docker_stop" --remove-orphans
