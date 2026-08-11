#!/usr/bin/env bash
set -euo pipefail

umask 077

project_dir="${CAMELLIA_REMOTE_PROJECT_DIR:-/opt/camellia-remote-management}"
env_file="${CAMELLIA_REMOTE_ENV_FILE:-/etc/camellia-remote-management/management.env}"
docker_binary="${CAMELLIA_REMOTE_DOCKER_BINARY:-/usr/bin/docker}"
timeout_binary="${CAMELLIA_REMOTE_TIMEOUT_BINARY:-/usr/bin/timeout}"
operation_id=""
operation_kind=""
service=""
timeout_seconds=""
stop_seconds="20"
declare -a container_environment=()

die() {
    echo "compose operation error: $*" >&2
    exit 2
}

usage() {
    cat >&2 <<'EOF'
usage: run-compose-operation.sh \
  --operation-id ID --operation-kind KIND --service SERVICE \
  --timeout-seconds N [--stop-seconds N] [--env NAME=VALUE]... [-- COMMAND [ARG]...]
EOF
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
        --timeout-binary)
            [[ $# -ge 2 ]] || usage
            timeout_binary="$2"
            shift 2
            ;;
        --operation-id)
            [[ $# -ge 2 ]] || usage
            operation_id="$2"
            shift 2
            ;;
        --operation-kind)
            [[ $# -ge 2 ]] || usage
            operation_kind="$2"
            shift 2
            ;;
        --service)
            [[ $# -ge 2 ]] || usage
            service="$2"
            shift 2
            ;;
        --timeout-seconds)
            [[ $# -ge 2 ]] || usage
            timeout_seconds="$2"
            shift 2
            ;;
        --stop-seconds)
            [[ $# -ge 2 ]] || usage
            stop_seconds="$2"
            shift 2
            ;;
        --env)
            [[ $# -ge 2 ]] || usage
            container_environment+=(--env "$2")
            shift 2
            ;;
        --)
            shift
            break
            ;;
        *) usage ;;
    esac
done

[[ "$project_dir" = /* && "$env_file" = /* && "$docker_binary" = /* && "$timeout_binary" = /* ]] ||
    die "paths must be absolute"
[[ -f "$project_dir/docker-compose.yaml" && ! -L "$project_dir/docker-compose.yaml" ]] ||
    die "docker compose file is missing or symlinked"
[[ -f "$env_file" && ! -L "$env_file" && -r "$env_file" ]] || die "environment file is missing or unsafe"
[[ -x "$docker_binary" && ! -L "$docker_binary" ]] || die "docker binary is missing or unsafe"
[[ -x "$timeout_binary" && ! -L "$timeout_binary" ]] || die "timeout binary is missing or unsafe"
[[ "$operation_id" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]] || die "operation ID is invalid"
[[ "$operation_kind" =~ ^[a-z0-9][a-z0-9-]{0,19}$ ]] || die "operation kind is invalid"
[[ "$service" =~ ^[a-z0-9][a-z0-9_-]{0,31}$ ]] || die "service name is invalid"
for value in "$timeout_seconds" "$stop_seconds"; do
    [[ "$value" =~ ^[0-9]+$ ]] || die "timeout values must be positive integers"
done
(( timeout_seconds >= 1 && timeout_seconds <= 3900 )) || die "operation timeout must be between 1 and 3900 seconds"
(( stop_seconds >= 1 && stop_seconds <= 120 )) || die "stop timeout must be between 1 and 120 seconds"
for ((index = 1; index < ${#container_environment[@]}; index += 2)); do
    environment_value="${container_environment[$index]}"
    [[ "$environment_value" != *$'\n'* && "$environment_value" =~ ^[A-Z][A-Z0-9_]{0,63}=.*$ ]] ||
        die "container environment override is invalid"
done

container_name="camellia-remote-${operation_kind}-${operation_id:0:20}"
compose=("$docker_binary" compose --env-file "$env_file" -f "$project_dir/docker-compose.yaml")
client_pid=""

docker_state() {
    "$timeout_binary" --foreground --signal=TERM --kill-after=2s 3s "$docker_binary" "$@"
}

docker_stop() {
    local control_timeout=$((stop_seconds + 5))
    "$timeout_binary" --foreground --signal=TERM --kill-after=2s "${control_timeout}s" "$docker_binary" "$@"
}

# shellcheck disable=SC2317
terminate_client() {
    local attempt
    [[ -n "$client_pid" ]] || return 0
    kill -TERM "$client_pid" >/dev/null 2>&1 || true
    for ((attempt = 0; attempt < 50; attempt += 1)); do
        if ! kill -0 "$client_pid" >/dev/null 2>&1; then
            break
        fi
        sleep 0.1
    done
    kill -KILL "$client_pid" >/dev/null 2>&1 || true
    wait "$client_pid" >/dev/null 2>&1 || true
}

container_operation_id() {
    docker_state container inspect \
        --format '{{ index .Config.Labels "io.camellia.remote.operation-id" }}' \
        "$container_name" 2>/dev/null
}

container_is_absent() {
    local names
    if ! names="$(
        docker_state container ls --all \
            --filter "name=^/${container_name}$" \
            --format '{{.Names}}' 2>/dev/null
    )"; then
        echo "compose operation error: cannot confirm remote container state" >&2
        return 2
    fi
    [[ -z "$names" ]]
}

remove_operation_container() {
    local actual_id
    if ! actual_id="$(container_operation_id)"; then
        if container_is_absent; then
            return 0
        fi
        echo "compose operation error: remote container exists but its identity cannot be verified" >&2
        return 1
    fi
    if [[ "$actual_id" != "$operation_id" ]]; then
        echo "compose operation error: refusing to stop container with mismatched operation identity" >&2
        return 1
    fi
    docker_stop container stop --time "$stop_seconds" "$container_name" >/dev/null 2>&1 || true
    if container_operation_id >/dev/null; then
        docker_state container kill "$container_name" >/dev/null 2>&1 || true
    fi
    if container_operation_id >/dev/null; then
        docker_state container rm --force "$container_name" >/dev/null 2>&1 || true
    fi
    if ! container_is_absent; then
        echo "compose operation error: remote operation container did not terminate" >&2
        return 1
    fi
}

# shellcheck disable=SC2317
cancel_operation() {
    local signal="$1"
    trap - HUP INT TERM
    terminate_client
    if ! remove_operation_container; then
        exit 125
    fi
    echo "operation_cancelled kind=$operation_kind operation_id=$operation_id signal=$signal" >&2
    exit 130
}
trap 'cancel_operation HUP' HUP
trap 'cancel_operation INT' INT
trap 'cancel_operation TERM' TERM

echo "operation_started kind=$operation_kind operation_id=$operation_id timeout_seconds=$timeout_seconds" >&2
set +e
"$timeout_binary" --foreground --signal=TERM --kill-after="${stop_seconds}s" "${timeout_seconds}s" \
    "${compose[@]}" run --rm --no-deps -T \
    --name "$container_name" \
    --label "io.camellia.remote.operation-id=$operation_id" \
    --label "io.camellia.remote.operation-kind=$operation_kind" \
    "${container_environment[@]}" \
    "$service" "$@" <&0 &
client_pid=$!
wait "$client_pid"
status=$?
client_pid=""
set -e

if ! remove_operation_container; then
    exit 125
fi
if (( status == 124 || status == 137 )); then
    echo "operation_timeout kind=$operation_kind operation_id=$operation_id timeout_seconds=$timeout_seconds" >&2
    exit 124
fi
echo "operation_finished kind=$operation_kind operation_id=$operation_id status=$status" >&2
exit "$status"
