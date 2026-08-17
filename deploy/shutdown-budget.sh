#!/bin/sh
set -eu

# The application graceful timeout is the only tunable input. Docker needs a
# small signal/cleanup margin and systemd is deliberately fixed above the
# largest supported Docker budget. Keeping this arithmetic in one executable
# prevents the three independently edited configuration files from drifting.
DOCKER_MARGIN_SECONDS=15
SYSTEMD_TIMEOUT_SECONDS=660

env_file=
mode=values

usage() {
    echo "usage: $0 [--env-file ABSOLUTE_PATH] [--values|--print]" >&2
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --env-file)
            [ "$#" -ge 2 ] || usage
            env_file=$2
            shift 2
            ;;
        --values)
            mode=values
            shift
            ;;
        --print)
            mode=print
            shift
            ;;
        *)
            usage
            ;;
    esac
done

if [ -n "$env_file" ]; then
    case "$env_file" in
        /*) ;;
        *) echo "shutdown budget error: environment path must be absolute" >&2; exit 2 ;;
    esac
    if [ ! -f "$env_file" ] || [ -L "$env_file" ] || [ ! -r "$env_file" ]; then
        echo "shutdown budget error: environment file is missing or unsafe" >&2
        exit 2
    fi
fi

read_env_value() {
    key=$1
    [ -n "$env_file" ] || return 1
    awk -v key="$key" '
        $0 ~ /^[[:space:]]*#/ { next }
        {
            line = $0
            sub(/\r$/, "", line)
            split(line, parts, "=")
            candidate = parts[1]
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", candidate)
            if (candidate == key) {
                position = index(line, "=")
                print substr(line, position + 1)
                found = 1
                exit
            }
        }
        END { if (!found) exit 1 }
    ' "$env_file"
}

value_or_file() {
    key=$1
    current=$2
    if [ -n "$current" ]; then
        printf '%s\n' "$current"
        return 0
    fi
    read_env_value "$key" 2>/dev/null || true
}

graceful="${CAMELLIA_REMOTE_GUNICORN_GRACEFUL_TIMEOUT_SECONDS-}"
graceful=$(value_or_file CAMELLIA_REMOTE_GUNICORN_GRACEFUL_TIMEOUT_SECONDS "$graceful")
[ -n "$graceful" ] || graceful=30

docker_stop="${CAMELLIA_REMOTE_DOCKER_STOP_GRACE_PERIOD_SECONDS-}"
docker_stop=$(value_or_file CAMELLIA_REMOTE_DOCKER_STOP_GRACE_PERIOD_SECONDS "$docker_stop")

is_integer() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

if ! is_integer "$graceful" || [ "$graceful" -lt 1 ] || [ "$graceful" -gt 600 ]; then
    echo "shutdown budget error: CAMELLIA_REMOTE_GUNICORN_GRACEFUL_TIMEOUT_SECONDS must be between 1 and 600" >&2
    exit 1
fi

expected_docker_stop=$((graceful + DOCKER_MARGIN_SECONDS))
if [ -z "$docker_stop" ]; then
    docker_stop=$expected_docker_stop
fi
if ! is_integer "$docker_stop" || [ "$docker_stop" -lt 1 ] || [ "$docker_stop" -gt 615 ]; then
    echo "shutdown budget error: CAMELLIA_REMOTE_DOCKER_STOP_GRACE_PERIOD_SECONDS must be between 1 and 615" >&2
    exit 1
fi
if [ "$docker_stop" -ne "$expected_docker_stop" ]; then
    echo "shutdown budget error: Docker stop grace must equal Gunicorn graceful timeout plus ${DOCKER_MARGIN_SECONDS}s" >&2
    exit 1
fi
if [ "$docker_stop" -gt $((SYSTEMD_TIMEOUT_SECONDS - 30)) ]; then
    echo "shutdown budget error: systemd stop timeout leaves less than 30s after Docker grace" >&2
    exit 1
fi

if [ "$mode" = values ]; then
    printf '%s %s %s\n' "$graceful" "$docker_stop" "$SYSTEMD_TIMEOUT_SECONDS"
else
    printf 'CAMELLIA_REMOTE_GUNICORN_GRACEFUL_TIMEOUT_SECONDS=%s\n' "$graceful"
    printf 'CAMELLIA_REMOTE_DOCKER_STOP_GRACE_PERIOD_SECONDS=%s\n' "$docker_stop"
    printf 'CAMELLIA_REMOTE_SYSTEMD_STOP_TIMEOUT_SECONDS=%s\n' "$SYSTEMD_TIMEOUT_SECONDS"
fi
