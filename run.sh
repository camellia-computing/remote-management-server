#!/bin/sh
set -eu

APP_DIR="/app"
cd "$APP_DIR"

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

PORT="${CAMELLIA_REMOTE_BIND_PORT:-21114}"
HOST="${CAMELLIA_REMOTE_BIND_HOST:-0.0.0.0}"
WORKERS="${CAMELLIA_REMOTE_GUNICORN_WORKERS:-2}"
THREADS="${CAMELLIA_REMOTE_GUNICORN_THREADS:-2}"
TIMEOUT="${CAMELLIA_REMOTE_GUNICORN_TIMEOUT_SECONDS:-60}"
GRACEFUL_TIMEOUT="${CAMELLIA_REMOTE_GUNICORN_GRACEFUL_TIMEOUT_SECONDS:-30}"
KEEP_ALIVE="${CAMELLIA_REMOTE_GUNICORN_KEEP_ALIVE_SECONDS:-5}"
MAX_REQUESTS="${CAMELLIA_REMOTE_GUNICORN_MAX_REQUESTS:-1000}"
MAX_REQUESTS_JITTER="${CAMELLIA_REMOTE_GUNICORN_MAX_REQUESTS_JITTER:-100}"
FORWARDED_ALLOW_IPS="${CAMELLIA_REMOTE_GUNICORN_FORWARDED_ALLOW_IPS:-127.0.0.1}"
RECORD_DIR="${CAMELLIA_REMOTE_RECORD_UPLOAD_ROOT:-$APP_DIR/records}"

if [ -z "${CAMELLIA_REMOTE_DATABASE_URL:-}" ]; then
    echo "CAMELLIA_REMOTE_DATABASE_URL is required" >&2
    exit 1
fi

if [ ! -d "$RECORD_DIR" ] || [ ! -w "$RECORD_DIR" ]; then
    echo "Recording directory is not writable: $RECORD_DIR" >&2
    exit 1
fi

case "${CAMELLIA_REMOTE_RUN_MIGRATIONS:-false}" in
    1|true|TRUE|yes|YES)
        python manage.py migrate --noinput
        ;;
    0|false|FALSE|no|NO)
        ;;
    *)
        echo "CAMELLIA_REMOTE_RUN_MIGRATIONS must be true or false" >&2
        exit 1
        ;;
esac

python manage.py check

exec gunicorn camellia_remote_management.wsgi:application \
    --bind "$HOST:$PORT" \
    --workers "$WORKERS" \
    --threads "$THREADS" \
    --timeout "$TIMEOUT" \
    --graceful-timeout "$GRACEFUL_TIMEOUT" \
    --keep-alive "$KEEP_ALIVE" \
    --max-requests "$MAX_REQUESTS" \
    --max-requests-jitter "$MAX_REQUESTS_JITTER" \
    --worker-tmp-dir /tmp \
    --forwarded-allow-ips "$FORWARDED_ALLOW_IPS" \
    --access-logfile "-" \
    --error-logfile "-" \
    --capture-output
