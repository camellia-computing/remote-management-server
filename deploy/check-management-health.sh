#!/usr/bin/env bash
set -euo pipefail

project_dir="/opt/camellia-remote-management"
env_file="/etc/camellia-remote-management/management.env"
docker_binary="/usr/bin/docker"

usage() {
    echo "usage: $0 [--project-dir ABSOLUTE_PATH] [--env-file ABSOLUTE_PATH] [--docker-binary ABSOLUTE_PATH]" >&2
    exit 40
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
        *) usage ;;
    esac
done

[[ "$project_dir" = /* && "$env_file" = /* && "$docker_binary" = /* ]] || usage
[[ -d "$project_dir" && ! -L "$project_dir" ]] || usage
[[ -f "$project_dir/docker-compose.yaml" && ! -L "$project_dir/docker-compose.yaml" ]] || usage
[[ -f "$env_file" && ! -L "$env_file" && -r "$env_file" ]] || usage
[[ -x "$docker_binary" && ! -L "$docker_binary" ]] || usage

compose=("$docker_binary" compose --env-file "$env_file" -f "$project_dir/docker-compose.yaml")
if ! container_ids="$("${compose[@]}" ps --all --quiet management 2>/dev/null)"; then
    echo "control_failure unknown unknown"
    exit 40
fi
mapfile -t ids < <(printf '%s\n' "$container_ids" | sed '/^[[:space:]]*$/d')
if (( ${#ids[@]} == 0 )); then
    echo "process_failure absent none"
    exit 30
fi
if (( ${#ids[@]} != 1 )) || [[ ! "${ids[0]}" =~ ^[A-Za-z0-9_.:-]{1,128}$ ]]; then
    echo "control_failure ambiguous unknown"
    exit 40
fi

if ! inspection="$(
    "$docker_binary" container inspect \
        --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' \
        "${ids[0]}" 2>/dev/null
)"; then
    echo "control_failure unknown unknown"
    exit 40
fi
read -r process_state health_state extra <<<"$inspection"
if [[ -n "${extra:-}" || ! "$process_state" =~ ^[a-z]+$ || ! "$health_state" =~ ^[a-z]+$ ]]; then
    echo "control_failure invalid invalid"
    exit 40
fi

if [[ "$process_state" != "running" ]]; then
    echo "process_failure $process_state $health_state"
    exit 30
fi
case "$health_state" in
    healthy)
        echo "healthy running healthy"
        exit 0
        ;;
    starting)
        echo "starting running starting"
        exit 10
        ;;
    unhealthy)
        echo "dependency_unhealthy running unhealthy"
        exit 20
        ;;
    *)
        echo "control_failure running $health_state"
        exit 40
        ;;
esac
