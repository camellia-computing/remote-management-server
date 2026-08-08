#!/usr/bin/env bash
set -euo pipefail

umask 077

project_dir="${CAMELLIA_REMOTE_PROJECT_DIR:-/opt/camellia-remote-management}"
env_file="${CAMELLIA_REMOTE_ENV_FILE:-/etc/camellia-remote-management/management.env}"
backup_dir="${CAMELLIA_REMOTE_BACKUP_DIR:-/var/backups/camellia-remote-management}"
envelope_helper="${CAMELLIA_REMOTE_BACKUP_ENVELOPE_HELPER:-$project_dir/scripts/backup_envelope.py}"
age_binary="${CAMELLIA_REMOTE_BACKUP_AGE_BINARY:-/usr/bin/age}"
retention_hours="${CAMELLIA_REMOTE_BACKUP_RETENTION_HOURS:-168}"
recipient="${CAMELLIA_REMOTE_BACKUP_AGE_RECIPIENT:-}"
backup_key_id="${CAMELLIA_REMOTE_BACKUP_AGE_KEY_ID:-}"
deployment_id="${CAMELLIA_REMOTE_BACKUP_DEPLOYMENT_ID:-}"
database_name="${CAMELLIA_REMOTE_DATABASE_NAME:-}"

die() {
    echo "backup error: $*" >&2
    exit 1
}

case "$retention_hours" in
    ''|*[!0-9]*) die "CAMELLIA_REMOTE_BACKUP_RETENTION_HOURS must be a positive integer" ;;
esac
if (( retention_hours < 24 )); then
    die "CAMELLIA_REMOTE_BACKUP_RETENTION_HOURS must be at least 24"
fi
[[ "$recipient" =~ ^age1[^[:space:]]{20,255}$ ]] || die "CAMELLIA_REMOTE_BACKUP_AGE_RECIPIENT must be an age1 recipient"
[[ "$backup_key_id" =~ ^[a-z0-9][a-z0-9._-]{0,31}$ ]] || die "CAMELLIA_REMOTE_BACKUP_AGE_KEY_ID is invalid"
[[ "$deployment_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "CAMELLIA_REMOTE_BACKUP_DEPLOYMENT_ID is invalid"
[[ -n "$database_name" && ${#database_name} -le 63 && "$database_name" != *$'\n'* ]] || die "CAMELLIA_REMOTE_DATABASE_NAME is invalid"
[[ "$project_dir" = /* && "$env_file" = /* && "$backup_dir" = /* && "$envelope_helper" = /* ]] || die "backup paths must be absolute"
[[ -x "$age_binary" ]] || die "age binary is missing or not executable: $age_binary"
[[ -f "$envelope_helper" && ! -L "$envelope_helper" ]] || die "backup envelope helper is missing or a symlink"
[[ -f "$env_file" && ! -L "$env_file" && -r "$env_file" ]] || die "management environment file is missing, symlinked, or unreadable: $env_file"
env_mode="$(stat -c '%a' -- "$env_file" 2>/dev/null)" || die "cannot inspect management environment permissions"
env_mode_value=$((8#$env_mode))
(( (env_mode_value & 077) == 0 && (env_mode_value & 0400) != 0 )) ||
    die "management environment file must be owner-readable and inaccessible to group/other users"
env_owner="$(stat -c '%u' -- "$env_file" 2>/dev/null)" || die "cannot inspect management environment owner"
if [[ "$(id -u)" -eq 0 ]]; then
    [[ "$env_owner" -eq 0 ]] || die "management environment file must be owned by root"
else
    [[ "$env_owner" -eq "$(id -u)" ]] || die "management environment file must be owned by the invoking user"
fi
[[ -f "$project_dir/docker-compose.yaml" ]] || die "docker compose file is missing: $project_dir/docker-compose.yaml"

install -d -m 0700 "$backup_dir"
chmod 0700 "$backup_dir"
exec 9>"$backup_dir/.backup.lock"
if ! flock -n 9; then
    echo "another backup is already running" >&2
    exit 75
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_id="$(python3 "$envelope_helper" new-id)"
compose=(docker compose --env-file "$env_file" -f "$project_dir/docker-compose.yaml")
temporary="$backup_dir/.postgres-$timestamp-$backup_id.dump.age.tmp"
destination="$backup_dir/postgres-$timestamp-$backup_id.dump.age"
recording_temporary="$backup_dir/.recordings-$timestamp-$backup_id.bundle.age.tmp"
recording_destination="$backup_dir/recordings-$timestamp-$backup_id.bundle.age"
checkpoint_started=0
checkpoint_json=""

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    rm -f -- "$temporary" "$recording_temporary"
    if (( status != 0 )); then
        rm -f -- "$destination" "$recording_destination"
        if (( checkpoint_started == 1 )); then
            "${compose[@]}" exec -T management python manage.py recording_backup abort \
                --backup-id "$backup_id" --ignore-missing >/dev/null 2>&1 || true
        fi
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

server_version_num="$("${compose[@]}" run --rm --no-deps -T database-backup \
    psql --no-psqlrc --tuples-only --no-align --command 'SHOW server_version_num' \
    | tr -d '[:space:]')"
[[ "$server_version_num" =~ ^[0-9]+$ ]] || die "PostgreSQL server version is invalid"
postgres_major="$((server_version_num / 10000))"
(( postgres_major > 0 )) || die "PostgreSQL major version is invalid"

checkpoint_json="$("${compose[@]}" exec -T management python manage.py recording_backup begin \
    --backup-id "$backup_id" --requested-at "$timestamp")" || die "cannot begin a consistent recording checkpoint"
checkpoint_started=1
"${compose[@]}" exec -T management python manage.py check_username_identity >/dev/null || \
    die "username identity contract is invalid"
checkpoint_values="$(CAMELLIA_REMOTE_CHECKPOINT_JSON="$checkpoint_json" CAMELLIA_REMOTE_BACKUP_ID="$backup_id" python3 -c '
import json, os
value = json.loads(os.environ["CAMELLIA_REMOTE_CHECKPOINT_JSON"])
epoch = value.get("epoch_id", "")
digest = value.get("inventory_digest", "")
if set(value) != {"backup_id", "epoch_id", "inventory_count", "inventory_digest", "manifest_version", "object_count", "requested_at", "state"}:
    raise SystemExit(1)
if value["backup_id"] != os.environ["CAMELLIA_REMOTE_BACKUP_ID"] or value["state"] != "ready":
    raise SystemExit(1)
print(epoch, digest)
')" || die "recording checkpoint metadata is invalid"
read -r recording_epoch_id recording_inventory_digest <<<"$checkpoint_values"
[[ "$recording_epoch_id" =~ ^[0-9a-f-]{36}$ ]] || die "recording checkpoint epoch is invalid"
[[ "$recording_inventory_digest" =~ ^[0-9a-f]{64}$ ]] || die "recording checkpoint digest is invalid"

# pg_dump is never written to disk in plaintext. The metadata frame is also
# encrypted by age, so restore can authenticate deployment/database context
# and the exact frozen recording inventory epoch.
set -o pipefail
"${compose[@]}" run --rm --no-deps -T database-backup \
    pg_dump --format=custom --compress=9 --no-owner --no-acl \
    | python3 "$envelope_helper" pack \
        --backup-id "$backup_id" \
        --created-at "$timestamp" \
        --deployment-id "$deployment_id" \
        --database-name "$database_name" \
        --postgres-major "$postgres_major" \
        --key-id "$backup_key_id" \
        --component database \
        --recording-epoch-id "$recording_epoch_id" \
        --recording-inventory-digest "$recording_inventory_digest" \
    | "$age_binary" --encrypt --recipient "$recipient" --output "$temporary"

"${compose[@]}" exec -T management python manage.py recording_backup export --backup-id "$backup_id" \
    | python3 "$envelope_helper" pack \
        --backup-id "$backup_id" \
        --created-at "$timestamp" \
        --deployment-id "$deployment_id" \
        --database-name "$database_name" \
        --postgres-major "$postgres_major" \
        --key-id "$backup_key_id" \
        --component recordings \
        --recording-epoch-id "$recording_epoch_id" \
        --recording-inventory-digest "$recording_inventory_digest" \
    | "$age_binary" --encrypt --recipient "$recipient" --output "$recording_temporary"
set +o pipefail

test -s "$temporary" || die "encrypted backup is empty"
test -s "$recording_temporary" || die "encrypted recording backup is empty"
mv -- "$recording_temporary" "$recording_destination"
mv -- "$temporary" "$destination"
CAMELLIA_REMOTE_BACKUP_FSYNC_DIR="$backup_dir" python3 -c '
import os
fd = os.open(os.environ["CAMELLIA_REMOTE_BACKUP_FSYNC_DIR"], os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
'
"${compose[@]}" exec -T management python manage.py recording_backup finish --backup-id "$backup_id" >/dev/null
checkpoint_started=0
trap - EXIT HUP INT TERM

while IFS= read -r -d '' expired_database; do
    expired_name="${expired_database##*/}"
    if [[ ! "$expired_name" =~ ^postgres-([0-9]{8}T[0-9]{6}Z)-([0-9a-f]{32})\.dump\.age$ ]]; then
        continue
    fi
    expired_recordings="$backup_dir/recordings-${BASH_REMATCH[1]}-${BASH_REMATCH[2]}.bundle.age"
    [[ -f "$expired_recordings" && ! -L "$expired_recordings" ]] || continue
    if [[ -z "$(find "$expired_recordings" -maxdepth 0 -type f \
        -mmin "+$((retention_hours * 60))" -print -quit)" ]]; then
        continue
    fi
    rm -f -- "$expired_database" "$expired_recordings"
done < <(
    find "$backup_dir" -maxdepth 1 -type f -name 'postgres-*.dump.age' \
        -mmin "+$((retention_hours * 60))" -print0
)

printf 'created %s\n' "$destination"
