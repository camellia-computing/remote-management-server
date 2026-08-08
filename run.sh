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
ACCESS_LOG_FORMAT='method=%(m)s route=%(route)s status=%(s)s bytes=%(B)s duration_us=%(D)s request_id=%(request_id)s trace_id=%(trace_id)s span_id=%(span_id)s event_id=%(event_id)s'

require_integer_range() {
    variable_name="$1"
    variable_value="$2"
    minimum="$3"
    maximum="$4"
    case "$variable_value" in
        ''|*[!0-9]*)
            echo "$variable_name must be an integer" >&2
            exit 1
            ;;
    esac
    if [ "$variable_value" -lt "$minimum" ] || [ "$variable_value" -gt "$maximum" ]; then
        echo "$variable_name must be between $minimum and $maximum" >&2
        exit 1
    fi
}

if [ ! -d "$RECORD_DIR" ] || [ ! -w "$RECORD_DIR" ]; then
    echo "Recording directory is not writable: $RECORD_DIR" >&2
    exit 1
fi

require_integer_range CAMELLIA_REMOTE_BIND_PORT "$PORT" 1 65535
require_integer_range CAMELLIA_REMOTE_GUNICORN_WORKERS "$WORKERS" 1 64
require_integer_range CAMELLIA_REMOTE_GUNICORN_THREADS "$THREADS" 1 64
require_integer_range CAMELLIA_REMOTE_GUNICORN_TIMEOUT_SECONDS "$TIMEOUT" 1 600
require_integer_range CAMELLIA_REMOTE_GUNICORN_GRACEFUL_TIMEOUT_SECONDS "$GRACEFUL_TIMEOUT" 1 600
require_integer_range CAMELLIA_REMOTE_GUNICORN_KEEP_ALIVE_SECONDS "$KEEP_ALIVE" 1 120
require_integer_range CAMELLIA_REMOTE_GUNICORN_MAX_REQUESTS "$MAX_REQUESTS" 1 1000000
require_integer_range CAMELLIA_REMOTE_GUNICORN_MAX_REQUESTS_JITTER "$MAX_REQUESTS_JITTER" 0 1000000

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

python manage.py migrate --check
python manage.py check_username_identity
python manage.py check --deploy

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
    --logger-class camellia_remote_management.access_logging.SafeAccessLogger \
    --access-logformat "$ACCESS_LOG_FORMAT" \
    --access-logfile "-" \
    --error-logfile "-" \
    --capture-output
