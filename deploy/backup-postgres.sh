#!/usr/bin/env bash
set -euo pipefail

umask 077

project_dir="${CAMELLIA_REMOTE_PROJECT_DIR:-/opt/camellia-remote-management}"
env_file="${CAMELLIA_REMOTE_ENV_FILE:-/etc/camellia-remote-management/management.env}"
backup_dir="${CAMELLIA_REMOTE_BACKUP_DIR:-/var/backups/camellia-remote-management}"
envelope_helper="${CAMELLIA_REMOTE_BACKUP_ENVELOPE_HELPER:-$project_dir/scripts/backup_envelope.py}"
age_binary="${CAMELLIA_REMOTE_BACKUP_AGE_BINARY:-/usr/bin/age}"
identity_file="${CAMELLIA_REMOTE_BACKUP_AGE_IDENTITY_FILE:-}"
retention_hours="${CAMELLIA_REMOTE_BACKUP_RETENTION_HOURS:-168}"
retention_minimum_count="${CAMELLIA_REMOTE_BACKUP_RETENTION_MINIMUM_COUNT:-24}"
recipient="${CAMELLIA_REMOTE_BACKUP_AGE_RECIPIENT:-}"
backup_key_id="${CAMELLIA_REMOTE_BACKUP_AGE_KEY_ID:-}"
data_encryption_key_id="${CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY_ID:-}"
deployment_id="${CAMELLIA_REMOTE_BACKUP_DEPLOYMENT_ID:-}"
database_name="${CAMELLIA_REMOTE_DATABASE_NAME:-}"
source_revision="${CAMELLIA_REMOTE_RELEASE_REVISION:-}"
management_image="${CAMELLIA_REMOTE_MANAGEMENT_IMAGE:-}"
operation_runner="${CAMELLIA_REMOTE_OPERATION_RUNNER:-$project_dir/deploy/run-compose-operation.sh}"
docker_binary="${CAMELLIA_REMOTE_DOCKER_BINARY:-$(command -v docker 2>/dev/null || true)}"
backup_timeout_seconds="${CAMELLIA_REMOTE_BACKUP_OPERATION_TIMEOUT_SECONDS:-2700}"
pg_dump_lock_timeout_seconds="${CAMELLIA_REMOTE_BACKUP_PG_DUMP_LOCK_TIMEOUT_SECONDS:-30}"
run_stale_seconds="${CAMELLIA_REMOTE_BACKUP_RUN_STALE_SECONDS:-180}"
run_heartbeat_seconds="${CAMELLIA_REMOTE_BACKUP_RUN_HEARTBEAT_SECONDS:-30}"
backup_started_seconds=$SECONDS

die() {
    echo "backup error: $*" >&2
    exit 1
}

for integer_value in "$retention_hours" "$retention_minimum_count"; do
    [[ "$integer_value" =~ ^[0-9]+$ ]] || die "backup retention values must be positive integers"
done
for timeout_value in "$backup_timeout_seconds" "$pg_dump_lock_timeout_seconds" "$run_stale_seconds" "$run_heartbeat_seconds"; do
    [[ "$timeout_value" =~ ^[0-9]+$ ]] || die "backup timeout values must be positive integers"
done
(( backup_timeout_seconds >= 60 && backup_timeout_seconds <= 3600 )) ||
    die "CAMELLIA_REMOTE_BACKUP_OPERATION_TIMEOUT_SECONDS must be between 60 and 3600"
(( pg_dump_lock_timeout_seconds >= 1 && pg_dump_lock_timeout_seconds <= 300 )) ||
    die "CAMELLIA_REMOTE_BACKUP_PG_DUMP_LOCK_TIMEOUT_SECONDS must be between 1 and 300"
(( pg_dump_lock_timeout_seconds < backup_timeout_seconds )) || die "pg_dump lock timeout must be shorter than backup timeout"
(( run_heartbeat_seconds >= 10 && run_heartbeat_seconds <= 60 )) ||
    die "CAMELLIA_REMOTE_BACKUP_RUN_HEARTBEAT_SECONDS must be between 10 and 60"
(( run_stale_seconds >= run_heartbeat_seconds * 3 && run_stale_seconds <= 3600 )) ||
    die "CAMELLIA_REMOTE_BACKUP_RUN_STALE_SECONDS must be between three heartbeat intervals and 3600"
if (( retention_hours < 24 )); then
    die "CAMELLIA_REMOTE_BACKUP_RETENTION_HOURS must be at least 24"
fi
(( retention_minimum_count >= 2 && retention_minimum_count <= 1000 )) ||
    die "CAMELLIA_REMOTE_BACKUP_RETENTION_MINIMUM_COUNT must be between 2 and 1000"
[[ "$recipient" =~ ^age1[^[:space:]]{20,255}$ ]] || die "CAMELLIA_REMOTE_BACKUP_AGE_RECIPIENT must be an age1 recipient"
[[ "$backup_key_id" =~ ^[a-z0-9][a-z0-9._-]{0,31}$ ]] || die "CAMELLIA_REMOTE_BACKUP_AGE_KEY_ID is invalid"
[[ "$data_encryption_key_id" =~ ^[a-z0-9][a-z0-9._-]{0,31}$ ]] || \
    die "CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY_ID is invalid"
[[ "$deployment_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "CAMELLIA_REMOTE_BACKUP_DEPLOYMENT_ID is invalid"
[[ -n "$database_name" && ${#database_name} -le 63 && "$database_name" != *$'\n'* ]] || die "CAMELLIA_REMOTE_DATABASE_NAME is invalid"
[[ "$source_revision" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || die "CAMELLIA_REMOTE_RELEASE_REVISION must be an exact Git revision"
[[ "$management_image" =~ ^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$ ]] ||
    die "CAMELLIA_REMOTE_MANAGEMENT_IMAGE must be pinned by SHA-256 digest"
[[ "$project_dir" = /* && "$env_file" = /* && "$backup_dir" = /* && "$envelope_helper" = /* ]] || die "backup paths must be absolute"
[[ -x "$age_binary" ]] || die "age binary is missing or not executable: $age_binary"
[[ -x "$docker_binary" && ! -L "$docker_binary" ]] || die "docker binary is missing or unsafe"
[[ -x "$operation_runner" && ! -L "$operation_runner" ]] || die "compose operation runner is missing or unsafe"
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
[[ -n "$identity_file" && "$identity_file" = /* ]] || die "CAMELLIA_REMOTE_BACKUP_AGE_IDENTITY_FILE is required and must be absolute"
[[ -f "$identity_file" && ! -L "$identity_file" && -r "$identity_file" ]] ||
    die "backup verification identity is missing, unreadable, or a symlink"
identity_mode="$(stat -c '%a' -- "$identity_file" 2>/dev/null)" || die "cannot inspect backup identity permissions"
identity_owner="$(stat -c '%u' -- "$identity_file" 2>/dev/null)" || die "cannot inspect backup identity owner"
identity_mode_value=$((8#$identity_mode))
(( (identity_mode_value & 077) == 0 && (identity_mode_value & 0400) != 0 )) ||
    die "backup verification identity must be owner-readable and inaccessible to group/other users"
if [[ "$(id -u)" -eq 0 ]]; then
    [[ "$identity_owner" -eq 0 ]] || die "backup verification identity must be owned by root"
else
    [[ "$identity_owner" -eq "$(id -u)" ]] || die "backup verification identity must be owned by the invoking user"
fi

[[ ! -L "$backup_dir" ]] || die "backup directory must not be a symlink"
install -d -m 0700 "$backup_dir"
[[ -d "$backup_dir" && ! -L "$backup_dir" ]] || die "backup directory is unsafe"
chmod 0700 "$backup_dir"
exec 9>"$backup_dir/.backup.lock"
run_id="$(python3 "$envelope_helper" new-id)"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_state="$backup_dir/.backup-run.json"
if ! flock -n 9; then
    if holder_json="$(python3 "$envelope_helper" run-inspect --path "$run_state" --stale-seconds "$run_stale_seconds")"; then
        printf '%s\n' "$holder_json" >&2
        exit 75
    else
        inspect_status=$?
        printf '%s\n' "$holder_json" >&2
        (( inspect_status == 3 )) && exit 1
        die "active backup holder metadata is invalid"
    fi
fi

if [[ -e "$run_state" || -L "$run_state" ]]; then
    orphan_json="$(python3 "$envelope_helper" run-inspect --path "$run_state" --stale-seconds "$run_stale_seconds" 2>/dev/null || true)"
    printf '{"previous_holder":%s,"status":"recovered:orphan-run-state"}\n' "${orphan_json:-null}" >&2
fi
backup_id="$run_id"
temporary="$backup_dir/.postgres-$timestamp-$backup_id.dump.age.tmp"
destination="$backup_dir/postgres-$timestamp-$backup_id.dump.age"
recording_temporary="$backup_dir/.recordings-$timestamp-$backup_id.bundle.age.tmp"
recording_destination="$backup_dir/recordings-$timestamp-$backup_id.bundle.age"
manifest_temporary="$backup_dir/.backup-set-$timestamp-$backup_id.manifest.age.tmp"
manifest_destination="$backup_dir/backup-set-$timestamp-$backup_id.manifest.age"
status_temporary="$backup_dir/.latest-verified-$backup_id.json.tmp"
status_destination="$backup_dir/latest-verified.json"
retention_catalog=""
checkpoint_started=0
backup_committed=0
checkpoint_json=""
heartbeat_pid=""

remaining_operation_seconds() {
    local elapsed remaining
    elapsed=$((SECONDS - backup_started_seconds))
    remaining=$((backup_timeout_seconds - elapsed))
    (( remaining > 0 )) || die "backup operation deadline exhausted"
    printf '%s\n' "$remaining"
}

run_backup_operation() {
    local suffix="$1"
    local kind="$2"
    local service="$3"
    shift 3
    local remaining
    remaining="$(remaining_operation_seconds)"
    local -a profile_environment=()
    if [[ "$service" == "management" ]]; then
        profile_environment=(--env CAMELLIA_REMOTE_DATABASE_OPERATION_PROFILE=BACKUP)
    fi
    "$operation_runner" \
        --project-dir "$project_dir" \
        --env-file "$env_file" \
        --docker-binary "$docker_binary" \
        --operation-id "${backup_id}-${suffix}" \
        --operation-kind "$kind" \
        --service "$service" \
        --timeout-seconds "$remaining" \
        --env "PGAPPNAME=camellia-backup:${backup_id:0:12}:${suffix}" \
        "${profile_environment[@]}" \
        -- "$@"
}

cleanup() {
    local status="${1:-$?}"
    trap - EXIT HUP INT TERM
    if [[ -n "$heartbeat_pid" ]]; then
        kill "$heartbeat_pid" >/dev/null 2>&1 || true
        wait "$heartbeat_pid" >/dev/null 2>&1 || true
    fi
    rm -f -- "$temporary" "$recording_temporary" "$manifest_temporary" "$status_temporary"
    [[ -z "$retention_catalog" ]] || rm -f -- "$retention_catalog"
    if (( status != 0 && backup_committed == 0 )); then
        rm -f -- "$destination" "$recording_destination" "$manifest_destination"
        if (( checkpoint_started == 1 )); then
            "$operation_runner" \
                --project-dir "$project_dir" \
                --env-file "$env_file" \
                --docker-binary "$docker_binary" \
                --operation-id "${backup_id}-abort" \
                --operation-kind backup-abort \
                --service management \
                --timeout-seconds 30 \
                --env CAMELLIA_REMOTE_DATABASE_OPERATION_PROFILE=BACKUP \
                -- python manage.py recording_backup abort \
                --backup-id "$backup_id" --ignore-missing >/dev/null 2>&1 || true
        fi
    fi
    python3 "$envelope_helper" run-clear --path "$run_state" --run-id "$run_id" >/dev/null 2>&1 || true
    exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 130' HUP INT TERM

python3 "$envelope_helper" run-create --path "$run_state" --run-id "$run_id" \
    --started-at "$timestamp" --pid "$$" --phase starting
(
    heartbeat_sleep_pid=""
    trap '[[ -z "$heartbeat_sleep_pid" ]] || kill "$heartbeat_sleep_pid" >/dev/null 2>&1; exit 0' TERM INT
    while true; do
        sleep "$run_heartbeat_seconds" &
        heartbeat_sleep_pid=$!
        wait "$heartbeat_sleep_pid" || exit 0
        heartbeat_sleep_pid=""
        python3 "$envelope_helper" run-update --path "$run_state" --run-id "$run_id" || exit 1
    done
) &
heartbeat_pid=$!

update_phase() {
    python3 "$envelope_helper" run-update --path "$run_state" --run-id "$run_id" --phase "$1"
}

update_phase metadata
server_version_num="$(run_backup_operation version backup-metadata database-backup \
    psql --no-psqlrc --tuples-only --no-align --command 'SHOW server_version_num' \
    | tr -d '[:space:]')"
[[ "$server_version_num" =~ ^[0-9]+$ ]] || die "PostgreSQL server version is invalid"
postgres_major="$((server_version_num / 10000))"
(( postgres_major > 0 )) || die "PostgreSQL major version is invalid"

checkpoint_json="$(run_backup_operation begin backup-checkpoint management python manage.py recording_backup begin \
    --backup-id "$backup_id" --requested-at "$timestamp")" || die "cannot begin a consistent recording checkpoint"
checkpoint_started=1
run_backup_operation identity backup-checkpoint management python manage.py check_username_identity >/dev/null || \
    die "username identity contract is invalid"
schema_json="$(run_backup_operation schema backup-checkpoint management python manage.py check_release_schema)" || \
    die "release schema contract is invalid"
schema_values="$(CAMELLIA_REMOTE_SCHEMA_JSON="$schema_json" python3 -c '
import json, os
value = json.loads(os.environ["CAMELLIA_REMOTE_SCHEMA_JSON"])
if set(value) != {"migration_count", "schema_generation", "schema_manifest_version"}:
    raise SystemExit(1)
if not isinstance(value["migration_count"], int) or value["migration_count"] <= 0:
    raise SystemExit(1)
if not isinstance(value["schema_manifest_version"], int) or value["schema_manifest_version"] <= 0:
    raise SystemExit(1)
print(value["schema_generation"], value["schema_manifest_version"], value["migration_count"])
')" || die "release schema metadata is invalid"
read -r schema_generation schema_manifest_version migration_count <<<"$schema_values"
[[ "$schema_generation" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]] || die "release schema generation is invalid"
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
update_phase exporting-database
set -o pipefail
run_backup_operation database backup-database database-backup \
    pg_dump --format=custom --compress=9 --no-owner --no-acl \
        --lock-wait-timeout="${pg_dump_lock_timeout_seconds}s" \
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

update_phase exporting-recordings
run_backup_operation recordings backup-recordings management python manage.py recording_backup export \
        --backup-id "$backup_id" \
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
ln -- "$recording_temporary" "$recording_destination" || die "recording backup destination already exists"
rm -f -- "$recording_temporary"
ln -- "$temporary" "$destination" || die "database backup destination already exists"
rm -f -- "$temporary"
CAMELLIA_REMOTE_BACKUP_FSYNC_DIR="$backup_dir" python3 -c '
import os
fd = os.open(os.environ["CAMELLIA_REMOTE_BACKUP_FSYNC_DIR"], os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
'

# Full-read verification deliberately runs before the manifest completion
# marker is published. pg_restore writes SQL to /dev/null, forcing every
# custom-archive data block to be decompressed without touching a database.
update_phase verifying-database
set -o pipefail
"$age_binary" --decrypt --identity "$identity_file" "$destination" \
    | python3 "$envelope_helper" unpack \
        --expect-backup-id "$backup_id" \
        --expect-created-at "$timestamp" \
        --expect-deployment-id "$deployment_id" \
        --expect-database-name "$database_name" \
        --expect-postgres-major "$postgres_major" \
        --expect-key-id "$backup_key_id" \
        --expect-component database \
        --expect-recording-epoch-id "$recording_epoch_id" \
        --expect-recording-inventory-digest "$recording_inventory_digest" \
    | run_backup_operation verify-database backup-verify database-backup \
        pg_restore --format=custom --file=/dev/null --no-owner --no-acl

update_phase verifying-recordings
"$age_binary" --decrypt --identity "$identity_file" "$recording_destination" \
    | python3 "$envelope_helper" unpack \
        --expect-backup-id "$backup_id" \
        --expect-created-at "$timestamp" \
        --expect-deployment-id "$deployment_id" \
        --expect-database-name "$database_name" \
        --expect-postgres-major "$postgres_major" \
        --expect-key-id "$backup_key_id" \
        --expect-component recordings \
        --expect-recording-epoch-id "$recording_epoch_id" \
        --expect-recording-inventory-digest "$recording_inventory_digest" \
    | run_backup_operation verify-recordings backup-verify management python manage.py recording_backup verify \
        --backup-id "$backup_id" \
        --epoch-id "$recording_epoch_id" \
        --inventory-digest "$recording_inventory_digest" >/dev/null
set +o pipefail

verified_at="$(date -u +%Y%m%dT%H%M%SZ)"
completed_at="$(date -u +%Y%m%dT%H%M%SZ)"
update_phase publishing-manifest
set -o pipefail
python3 "$envelope_helper" set-create \
        --backup-id "$backup_id" \
        --created-at "$timestamp" \
        --deployment-id "$deployment_id" \
        --database-name "$database_name" \
        --postgres-major "$postgres_major" \
        --key-id "$backup_key_id" \
        --data-encryption-key-id "$data_encryption_key_id" \
        --source-revision "$source_revision" \
        --management-image "$management_image" \
        --schema-generation "$schema_generation" \
        --schema-manifest-version "$schema_manifest_version" \
        --migration-count "$migration_count" \
        --recording-epoch-id "$recording_epoch_id" \
        --recording-inventory-digest "$recording_inventory_digest" \
        --database-artifact "$destination" \
        --recordings-artifact "$recording_destination" \
        --verified-at "$verified_at" \
        --completed-at "$completed_at" \
    | "$age_binary" --encrypt --recipient "$recipient" --output "$manifest_temporary"
set +o pipefail
test -s "$manifest_temporary" || die "encrypted backup set manifest is empty"
ln -- "$manifest_temporary" "$manifest_destination" || die "backup set manifest destination already exists"
rm -f -- "$manifest_temporary"
CAMELLIA_REMOTE_BACKUP_FSYNC_DIR="$backup_dir" python3 -c '
import os
fd = os.open(os.environ["CAMELLIA_REMOTE_BACKUP_FSYNC_DIR"], os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
'

# Re-open all three final paths. This verifies the manifest AEAD and binds its
# immutable ciphertext sizes/digests to the files retained and copied offsite.
update_phase verifying-manifest
set -o pipefail
"$age_binary" --decrypt --identity "$identity_file" "$manifest_destination" \
    | python3 "$envelope_helper" set-verify \
        --expect-backup-id "$backup_id" \
        --expect-created-at "$timestamp" \
        --expect-deployment-id "$deployment_id" \
        --expect-database-name "$database_name" \
        --expect-postgres-major "$postgres_major" \
        --expect-key-id "$backup_key_id" \
        --expect-data-encryption-key-id "$data_encryption_key_id" \
        --expect-source-revision "$source_revision" \
        --expect-management-image "$management_image" \
        --database-artifact "$destination" \
        --recordings-artifact "$recording_destination" >/dev/null
set +o pipefail

update_phase finalizing
run_backup_operation finish backup-finalize management python manage.py recording_backup finish \
    --backup-id "$backup_id" >/dev/null
checkpoint_started=0
backup_committed=1

recorded_at="$(date -u +%Y%m%dT%H%M%SZ)"
set -o pipefail
"$age_binary" --decrypt --identity "$identity_file" "$manifest_destination" \
    | python3 "$envelope_helper" status \
        --manifest-filename "${manifest_destination##*/}" \
        --recorded-at "$recorded_at" >"$status_temporary"
set +o pipefail
test -s "$status_temporary" || die "verified backup freshness status is empty"
mv -- "$status_temporary" "$status_destination"
CAMELLIA_REMOTE_BACKUP_FSYNC_DIR="$backup_dir" python3 -c '
import os
fd = os.open(os.environ["CAMELLIA_REMOTE_BACKUP_FSYNC_DIR"], os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
'

# Retention accepts only complete, age-authenticated three-file generations.
# It uses the manifest completion time and always protects the newest N sets;
# legacy pairs and malformed/incomplete sets are preserved for investigation.
update_phase retention
retention_catalog="$(mktemp "$backup_dir/.retention-$backup_id.XXXXXX")" || die "cannot create retention catalog"
for retained_manifest in "$backup_dir"/backup-set-*.manifest.age; do
    [[ -e "$retained_manifest" ]] || continue
    retained_name="${retained_manifest##*/}"
    if [[ ! "$retained_name" =~ ^backup-set-([0-9]{8}T[0-9]{6}Z)-([0-9a-f]{32})\.manifest\.age$ ]]; then
        continue
    fi
    retained_timestamp="${BASH_REMATCH[1]}"
    retained_id="${BASH_REMATCH[2]}"
    retained_database="$backup_dir/postgres-$retained_timestamp-$retained_id.dump.age"
    retained_recordings="$backup_dir/recordings-$retained_timestamp-$retained_id.bundle.age"
    if retention_entry="$(
        set -o pipefail
        "$age_binary" --decrypt --identity "$identity_file" "$retained_manifest" \
            | python3 "$envelope_helper" set-entry \
                --manifest-filename "$retained_name" \
                --database-artifact "$retained_database" \
                --recordings-artifact "$retained_recordings"
    )"; then
        printf '%s\n' "$retention_entry" >>"$retention_catalog"
    else
        printf '{"manifest":"%s","status":"retention-preserved:invalid-set"}\n' "$retained_name" >&2
    fi
done
sort -n -k1,1 -k2,2 -o "$retention_catalog" "$retention_catalog"
valid_generation_count="$(wc -l <"$retention_catalog")"
retention_cutoff_epoch="$(date -u -d "-$retention_hours hours" +%s)"
while read -r retained_epoch retained_id retained_database_name retained_recordings_name retained_manifest_name; do
    [[ -n "$retained_epoch" ]] || continue
    (( retained_epoch < retention_cutoff_epoch )) || break
    (( valid_generation_count > retention_minimum_count )) || break
    rm -f -- \
        "$backup_dir/$retained_database_name" \
        "$backup_dir/$retained_recordings_name" \
        "$backup_dir/$retained_manifest_name"
    valid_generation_count=$((valid_generation_count - 1))
done <"$retention_catalog"
CAMELLIA_REMOTE_BACKUP_FSYNC_DIR="$backup_dir" python3 -c '
import os
fd = os.open(os.environ["CAMELLIA_REMOTE_BACKUP_FSYNC_DIR"], os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
'

printf '{"backup_id":"%s","manifest":"%s","status":"created:verified"}\n' \
    "$backup_id" "$manifest_destination"
