#!/bin/sh
set -eu

umask 077

project_dir="/opt/camellia-remote-management"
env_file="/etc/camellia-remote-management/management.env"
backup_dir="/var/backups/camellia-remote-management"
retention_hours="${CAMELLIA_REMOTE_BACKUP_RETENTION_HOURS:-168}"

case "$retention_hours" in
    ''|*[!0-9]*)
        echo "CAMELLIA_REMOTE_BACKUP_RETENTION_HOURS must be a positive integer" >&2
        exit 1
        ;;
esac
if [ "$retention_hours" -lt 24 ]; then
    echo "CAMELLIA_REMOTE_BACKUP_RETENTION_HOURS must be at least 24" >&2
    exit 1
fi

install -d -m 0700 "$backup_dir"
exec 9>"$backup_dir/.backup.lock"
if ! flock -n 9; then
    echo "another backup is already running" >&2
    exit 0
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
temporary="$backup_dir/.postgres-$timestamp.dump.tmp"
destination="$backup_dir/postgres-$timestamp.dump"
trap 'rm -f "$temporary"' EXIT HUP INT TERM

docker compose --env-file "$env_file" -f "$project_dir/docker-compose.yaml" \
    exec -T postgres sh -eu -c \
    'pg_dump --format=custom --compress=9 --no-owner --no-acl --username "$POSTGRES_USER" "$POSTGRES_DB"' \
    >"$temporary"

test -s "$temporary"
docker compose --env-file "$env_file" -f "$project_dir/docker-compose.yaml" \
    exec -T postgres pg_restore --list <"$temporary" >/dev/null
mv "$temporary" "$destination"
trap - EXIT HUP INT TERM

find "$backup_dir" -maxdepth 1 -type f -name 'postgres-*.dump' \
    -mmin "+$((retention_hours * 60))" -delete

printf 'created %s\n' "$destination"
