#!/usr/bin/env bash
set -euo pipefail

umask 077

project_dir="${CAMELLIA_REMOTE_PROJECT_DIR:-/opt/camellia-remote-management}"
env_file="${CAMELLIA_REMOTE_ENV_FILE:-/etc/camellia-remote-management/management.env}"
docker_binary="${CAMELLIA_REMOTE_DOCKER_BINARY:-/usr/bin/docker}"
operation_runner="${CAMELLIA_REMOTE_OPERATION_RUNNER:-$project_dir/deploy/run-compose-operation.sh}"
operation_seed="$(date -u +%Y%m%dt%H%M%Sz)-$$"

[[ -x "$operation_runner" && ! -L "$operation_runner" ]] || {
    echo "cleanup error: compose operation runner is missing or unsafe" >&2
    exit 2
}

run_cleanup_operation() {
    local suffix="$1"
    shift
    "$operation_runner" \
        --project-dir "$project_dir" \
        --env-file "$env_file" \
        --docker-binary "$docker_binary" \
        --operation-id "${operation_seed}-${suffix}" \
        --operation-kind cleanup \
        --service management \
        --timeout-seconds 300 \
        --env CAMELLIA_REMOTE_DATABASE_OPERATION_PROFILE=CLEANUP \
        -- "$@"
}

run_cleanup_operation retention python manage.py purge_expired_state
run_cleanup_operation capacity python manage.py check_sequence_capacity --fail-level critical
