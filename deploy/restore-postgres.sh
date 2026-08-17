#!/usr/bin/env bash
set -euo pipefail

umask 077

project_dir="${CAMELLIA_REMOTE_PROJECT_DIR:-/opt/camellia-remote-management}"
env_file="${CAMELLIA_REMOTE_ENV_FILE:-/etc/camellia-remote-management/management.env}"
envelope_helper="${CAMELLIA_REMOTE_BACKUP_ENVELOPE_HELPER:-$project_dir/scripts/backup_envelope.py}"
age_binary="${CAMELLIA_REMOTE_BACKUP_AGE_BINARY:-/usr/bin/age}"
identity_file="${CAMELLIA_REMOTE_BACKUP_AGE_IDENTITY_FILE:-}"
recipient="${CAMELLIA_REMOTE_BACKUP_AGE_RECIPIENT:-}"
deployment_id="${CAMELLIA_REMOTE_BACKUP_DEPLOYMENT_ID:-}"
database_name="${CAMELLIA_REMOTE_DATABASE_NAME:-}"
postgres_major_expected="${CAMELLIA_REMOTE_BACKUP_POSTGRES_MAJOR:-}"
backup_key_id_expected="${CAMELLIA_REMOTE_BACKUP_AGE_KEY_ID:-}"
data_encryption_key_id_expected="${CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY_ID:-}"
source_revision_expected="${CAMELLIA_REMOTE_RELEASE_REVISION:-}"
management_image_expected="${CAMELLIA_REMOTE_MANAGEMENT_IMAGE:-}"
restore_target_id="${CAMELLIA_REMOTE_RESTORE_TARGET_ID:-}"
restore_confirmation="${CAMELLIA_REMOTE_RESTORE_CONFIRM:-}"
restore_evidence_dir="${CAMELLIA_REMOTE_RESTORE_EVIDENCE_DIR:-}"
operation_runner="${CAMELLIA_REMOTE_OPERATION_RUNNER:-$project_dir/deploy/run-compose-operation.sh}"
docker_binary="${CAMELLIA_REMOTE_DOCKER_BINARY:-$(command -v docker 2>/dev/null || true)}"
restore_timeout_seconds="${CAMELLIA_REMOTE_RESTORE_OPERATION_TIMEOUT_SECONDS:-3600}"
restore_started_seconds=$SECONDS
restore_started_at="$(date -u +%Y%m%dT%H%M%SZ)"

die() {
    echo "restore error: $*" >&2
    exit 1
}

usage() {
    echo "usage: $0 BACKUP.dump.age" >&2
    exit 2
}

[[ $# -eq 1 ]] || usage
backup_path="$1"

[[ "$project_dir" = /* && "$env_file" = /* && "$envelope_helper" = /* ]] || die "restore paths must be absolute"
[[ -f "$backup_path" && ! -L "$backup_path" && -r "$backup_path" ]] || die "backup is missing, unreadable, or a symlink"
[[ -x "$age_binary" ]] || die "age binary is missing or not executable: $age_binary"
[[ -x "$docker_binary" && ! -L "$docker_binary" ]] || die "docker binary is missing or unsafe"
[[ -x "$operation_runner" && ! -L "$operation_runner" ]] || die "compose operation runner is missing or unsafe"
[[ "$restore_timeout_seconds" =~ ^[0-9]+$ ]] || die "restore timeout must be a positive integer"
(( restore_timeout_seconds >= 300 && restore_timeout_seconds <= 3900 )) ||
    die "CAMELLIA_REMOTE_RESTORE_OPERATION_TIMEOUT_SECONDS must be between 300 and 3900"
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
bootstrap_script="$project_dir/deploy/bootstrap-postgres-roles.sh"
[[ -f "$bootstrap_script" && ! -L "$bootstrap_script" && -r "$bootstrap_script" ]] ||
    die "database role bootstrap script is missing, unreadable, or a symlink"
bootstrap_resolved="$(realpath -e -- "$bootstrap_script" 2>/dev/null)" || die "cannot resolve database role bootstrap script"
[[ "$bootstrap_resolved" == "$bootstrap_script" ]] || die "database role bootstrap script path must be canonical"
bootstrap_mode="$(stat -c '%a' -- "$bootstrap_script" 2>/dev/null)" || die "cannot inspect database role bootstrap permissions"
bootstrap_owner="$(stat -c '%u' -- "$bootstrap_script" 2>/dev/null)" || die "cannot inspect database role bootstrap owner"
bootstrap_mode_value=$((8#$bootstrap_mode))
(( (bootstrap_mode_value & 022) == 0 )) || die "database role bootstrap script is writable by group or other users"
if [[ "$(id -u)" -eq 0 ]]; then
    [[ "$bootstrap_owner" -eq 0 ]] || die "database role bootstrap script must be owned by root"
else
    [[ "$bootstrap_owner" -eq "$(id -u)" ]] || die "database role bootstrap script has an unsafe owner"
fi
[[ -n "$identity_file" ]] || die "CAMELLIA_REMOTE_BACKUP_AGE_IDENTITY_FILE is required"
[[ "$identity_file" = /* ]] || die "restore identity path must be absolute"
[[ -f "$identity_file" && ! -L "$identity_file" && -r "$identity_file" ]] || die "restore identity is missing, unreadable, or a symlink"

# The identity is a high-value decryption secret.  Refuse group/other access
# and require ownership by root (when running as root) or the invoking user.
identity_mode="$(stat -c '%a' -- "$identity_file" 2>/dev/null)" || die "cannot inspect restore identity permissions"
identity_owner="$(stat -c '%u' -- "$identity_file" 2>/dev/null)" || die "cannot inspect restore identity owner"
identity_mode_value=$((8#$identity_mode))
(( (identity_mode_value & 077) == 0 && (identity_mode_value & 0400) != 0 )) ||
    die "restore identity must be owner-readable and inaccessible to group/other users"
if [[ "$(id -u)" -eq 0 ]]; then
    [[ "$identity_owner" -eq 0 ]] || die "restore identity must be owned by root"
else
    [[ "$identity_owner" -eq "$(id -u)" ]] || die "restore identity must be owned by the invoking user"
fi

base_name="$(basename -- "$backup_path")"
if [[ ! "$base_name" =~ ^postgres-([0-9]{8}T[0-9]{6}Z)-([0-9a-f]{32})\.dump\.age$ ]]; then
    die "backup filename must be postgres-<UTC timestamp>-<backup id>.dump.age"
fi
expected_created_at="${BASH_REMATCH[1]}"
expected_backup_id="${BASH_REMATCH[2]}"
restore_run_id="$(python3 "$envelope_helper" new-id)"
[[ "$backup_path" == "$base_name" || "$backup_path" == */"$base_name" ]] || die "backup path is invalid"
backup_parent="$(dirname -- "$backup_path")"
recording_backup_path="$backup_parent/recordings-$expected_created_at-$expected_backup_id.bundle.age"
set_manifest_path="$backup_parent/backup-set-$expected_created_at-$expected_backup_id.manifest.age"
[[ -f "$recording_backup_path" && ! -L "$recording_backup_path" && -r "$recording_backup_path" ]] || \
    die "the matching encrypted recording backup is missing, unreadable, or a symlink"
[[ -f "$set_manifest_path" && ! -L "$set_manifest_path" && -r "$set_manifest_path" ]] || \
    die "the authenticated backup set manifest is missing, unreadable, or a symlink"

[[ -n "$deployment_id" ]] || die "CAMELLIA_REMOTE_BACKUP_DEPLOYMENT_ID is required"
[[ -n "$database_name" ]] || die "CAMELLIA_REMOTE_DATABASE_NAME is required"
[[ -n "$postgres_major_expected" && "$postgres_major_expected" =~ ^[1-9][0-9]{0,2}$ ]] || \
    die "CAMELLIA_REMOTE_BACKUP_POSTGRES_MAJOR is required and invalid"
[[ -n "$backup_key_id_expected" ]] || die "CAMELLIA_REMOTE_BACKUP_AGE_KEY_ID is required"
[[ "$data_encryption_key_id_expected" =~ ^[a-z0-9][a-z0-9._-]{0,31}$ ]] || \
    die "CAMELLIA_REMOTE_DATA_ENCRYPTION_KEY_ID is required and invalid"
[[ "$source_revision_expected" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || \
    die "CAMELLIA_REMOTE_RELEASE_REVISION must identify the exact restore release"
[[ "$management_image_expected" =~ ^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$ ]] || \
    die "CAMELLIA_REMOTE_MANAGEMENT_IMAGE must be pinned by SHA-256 digest"
[[ "$recipient" =~ ^age1[^[:space:]]{20,255}$ ]] || die "CAMELLIA_REMOTE_BACKUP_AGE_RECIPIENT is invalid"
[[ "$restore_target_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || \
    die "CAMELLIA_REMOTE_RESTORE_TARGET_ID is required and invalid"
expected_confirmation="restore:$expected_backup_id:$restore_target_id"
[[ "$restore_confirmation" == "$expected_confirmation" ]] || \
    die "set CAMELLIA_REMOTE_RESTORE_CONFIRM=$expected_confirmation only for an isolated empty target"
[[ "$restore_evidence_dir" = /* ]] || die "CAMELLIA_REMOTE_RESTORE_EVIDENCE_DIR is required and must be absolute"
[[ ! -L "$restore_evidence_dir" ]] || die "restore evidence directory must not be a symlink"
install -d -m 0700 "$restore_evidence_dir"
[[ -d "$restore_evidence_dir" && ! -L "$restore_evidence_dir" ]] || die "restore evidence directory is unsafe"
chmod 0700 "$restore_evidence_dir"

remaining_operation_seconds() {
    local elapsed remaining
    elapsed=$((SECONDS - restore_started_seconds))
    remaining=$((restore_timeout_seconds - elapsed))
    (( remaining > 0 )) || die "restore operation deadline exhausted"
    printf '%s\n' "$remaining"
}

run_restore_operation() {
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
        --operation-id "${expected_backup_id}-${suffix}" \
        --operation-kind "$kind" \
        --service "$service" \
        --timeout-seconds "$remaining" \
        --env "PGAPPNAME=camellia-restore:${expected_backup_id:0:12}:${suffix}" \
        "${profile_environment[@]}" \
        -- "$@"
}

# age authenticates the complete ciphertext before the envelope helper or
# pg_restore is allowed to run.  This short-lived file is mode 0600 and is
# removed on every exit; it prevents a tampered age stream from reaching
# pg_restore before age has verified its final authentication tag.  The backup
# artifact itself is always encrypted and no identity contents enter argv/logs.
database_envelope_temporary="$(mktemp "${TMPDIR:-/tmp}/camellia-restore-database.XXXXXX")" || \
    die "cannot create secure database restore temporary"
recording_envelope_temporary="$(mktemp "${TMPDIR:-/tmp}/camellia-restore-recordings.XXXXXX")" || \
    { rm -f -- "$database_envelope_temporary"; die "cannot create secure recording restore temporary"; }
set_manifest_temporary="$(mktemp "${TMPDIR:-/tmp}/camellia-restore-set.XXXXXX")" || \
    { rm -f -- "$database_envelope_temporary" "$recording_envelope_temporary"; die "cannot create secure set restore temporary"; }
receipt_temporary="$restore_evidence_dir/.restore-receipt-$restore_run_id.age.tmp"
status_temporary="$restore_evidence_dir/.latest-restore-$expected_backup_id.json.tmp"
chmod 0600 "$database_envelope_temporary" "$recording_envelope_temporary" "$set_manifest_temporary"
cleanup() {
    rm -f -- "$database_envelope_temporary" "$recording_envelope_temporary" "$set_manifest_temporary" \
        "$receipt_temporary" "$status_temporary"
}
cancel_restore() {
    trap - EXIT HUP INT TERM
    cleanup
    exit 130
}
trap cleanup EXIT
trap cancel_restore HUP INT TERM

set -o pipefail
"$age_binary" --decrypt --identity "$identity_file" "$backup_path" >"$database_envelope_temporary"
"$age_binary" --decrypt --identity "$identity_file" "$recording_backup_path" >"$recording_envelope_temporary"
"$age_binary" --decrypt --identity "$identity_file" "$set_manifest_path" >"$set_manifest_temporary"
set_json="$(python3 "$envelope_helper" set-verify \
    --expect-backup-id "$expected_backup_id" \
    --expect-created-at "$expected_created_at" \
    --expect-deployment-id "$deployment_id" \
    --expect-database-name "$database_name" \
    --expect-postgres-major "$postgres_major_expected" \
    --expect-key-id "$backup_key_id_expected" \
    --expect-data-encryption-key-id "$data_encryption_key_id_expected" \
    --expect-source-revision "$source_revision_expected" \
    --expect-management-image "$management_image_expected" \
    --database-artifact "$backup_path" \
    --recordings-artifact "$recording_backup_path" <"$set_manifest_temporary")" || \
    die "backup set manifest or ciphertext digest is invalid"
pair_json="$(python3 "$envelope_helper" pair "$database_envelope_temporary" "$recording_envelope_temporary")" || \
    die "database and recording artifacts do not form one authenticated backup epoch"
pair_values="$(CAMELLIA_REMOTE_BACKUP_PAIR_JSON="$pair_json" \
    CAMELLIA_REMOTE_EXPECTED_BACKUP_ID="$expected_backup_id" \
    CAMELLIA_REMOTE_EXPECTED_CREATED_AT="$expected_created_at" \
    CAMELLIA_REMOTE_EXPECTED_DEPLOYMENT_ID="$deployment_id" \
    CAMELLIA_REMOTE_EXPECTED_DATABASE_NAME="$database_name" \
    CAMELLIA_REMOTE_EXPECTED_POSTGRES_MAJOR="$postgres_major_expected" \
    CAMELLIA_REMOTE_EXPECTED_KEY_ID="$backup_key_id_expected" \
    CAMELLIA_REMOTE_BACKUP_SET_JSON="$set_json" \
    python3 -c '
import json, os
value = json.loads(os.environ["CAMELLIA_REMOTE_BACKUP_PAIR_JSON"])
backup_set = json.loads(os.environ["CAMELLIA_REMOTE_BACKUP_SET_JSON"])
expected = {
    "backup_id": os.environ["CAMELLIA_REMOTE_EXPECTED_BACKUP_ID"],
    "created_at": os.environ["CAMELLIA_REMOTE_EXPECTED_CREATED_AT"],
    "database_name": os.environ["CAMELLIA_REMOTE_EXPECTED_DATABASE_NAME"],
    "deployment_id": os.environ["CAMELLIA_REMOTE_EXPECTED_DEPLOYMENT_ID"],
    "key_id": os.environ["CAMELLIA_REMOTE_EXPECTED_KEY_ID"],
    "postgres_major": os.environ["CAMELLIA_REMOTE_EXPECTED_POSTGRES_MAJOR"],
}
if any(value.get(field) != expected_value for field, expected_value in expected.items()):
    raise SystemExit(1)
for field in (*expected, "recording_epoch_id", "recording_inventory_digest"):
    if value.get(field) != backup_set.get(field):
        raise SystemExit(1)
print(value.get("recording_epoch_id", ""), value.get("recording_inventory_digest", ""))
')" || die "backup epoch metadata is invalid"
read -r recording_epoch_id recording_inventory_digest <<<"$pair_values"
[[ "$recording_epoch_id" =~ ^[0-9a-f-]{36}$ ]] || die "backup recording epoch is invalid"
[[ "$recording_inventory_digest" =~ ^[0-9a-f]{64}$ ]] || die "backup recording inventory digest is invalid"
# The authenticated artifact is restored only through the migration owner.
# Bootstrap runs before and after restore so an old superuser-owned volume and
# newly restored objects both converge to the same least-privilege boundary.
run_restore_operation bootstrap-before restore-bootstrap database-bootstrap
empty_relation_count="$(run_restore_operation empty-target restore-preflight database-restore \
    psql --no-psqlrc --tuples-only --no-align --command \
    "SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')" \
    | tr -d '[:space:]')"
[[ "$empty_relation_count" == "0" ]] || die "restore target database is not empty"
run_restore_operation preflight restore-recordings management python manage.py recording_backup restore-preflight
python3 "$envelope_helper" unpack \
        --expect-backup-id "$expected_backup_id" \
        --expect-created-at "$expected_created_at" \
        --expect-deployment-id "$deployment_id" \
        --expect-database-name "$database_name" \
        --expect-postgres-major "$postgres_major_expected" \
        --expect-key-id "$backup_key_id_expected" \
        --expect-component database \
        --expect-recording-epoch-id "$recording_epoch_id" \
        --expect-recording-inventory-digest "$recording_inventory_digest" \
    <"$database_envelope_temporary" \
    | run_restore_operation database restore-database database-restore \
        pg_restore --single-transaction --exit-on-error --format=custom --no-owner --no-acl
set +o pipefail
run_restore_operation bootstrap-restored restore-bootstrap database-bootstrap
run_restore_operation migration restore-migration migrate
run_restore_operation bootstrap-migrated restore-bootstrap database-bootstrap
run_restore_operation schema restore-validate management python manage.py check_release_schema >/dev/null || \
    die "restored schema does not match this release"
run_restore_operation identity restore-validate management python manage.py check_username_identity >/dev/null || \
    die "restored username identity contract is invalid"
run_restore_operation keys restore-validate management python manage.py rotate_data_encryption --dry-run >/dev/null || \
    die "restored encrypted-field and key inventory is invalid"
set -o pipefail
python3 "$envelope_helper" unpack \
        --expect-backup-id "$expected_backup_id" \
        --expect-created-at "$expected_created_at" \
        --expect-deployment-id "$deployment_id" \
        --expect-database-name "$database_name" \
        --expect-postgres-major "$postgres_major_expected" \
        --expect-key-id "$backup_key_id_expected" \
        --expect-component recordings \
        --expect-recording-epoch-id "$recording_epoch_id" \
        --expect-recording-inventory-digest "$recording_inventory_digest" \
    <"$recording_envelope_temporary" \
    | run_restore_operation recordings restore-recordings management python manage.py recording_backup restore \
        --backup-id "$expected_backup_id" \
        --epoch-id "$recording_epoch_id" \
        --inventory-digest "$recording_inventory_digest"
set +o pipefail
run_restore_operation probe restore-validate database-probe

restore_completed_at="$(date -u +%Y%m%dT%H%M%SZ)"
restore_rto_seconds=$((SECONDS - restore_started_seconds))
receipt_name="restore-receipt-$restore_completed_at-$expected_backup_id-$restore_target_id-$restore_run_id.json.age"
receipt_destination="$restore_evidence_dir/$receipt_name"
status_destination="$restore_evidence_dir/latest-restore-verified.json"

set -o pipefail
python3 "$envelope_helper" restore-receipt \
        --manifest-filename "${set_manifest_path##*/}" \
        --manifest-artifact "$set_manifest_path" \
        --restore-run-id "$restore_run_id" \
        --target-id "$restore_target_id" \
        --restore-started-at "$restore_started_at" \
        --completed-at "$restore_completed_at" \
        --rto-seconds "$restore_rto_seconds" \
        <"$set_manifest_temporary" \
    | "$age_binary" --encrypt --recipient "$recipient" --output "$receipt_temporary"
set +o pipefail
test -s "$receipt_temporary" || die "encrypted restore receipt is empty"
python3 "$envelope_helper" restore-receipt \
        --manifest-filename "${set_manifest_path##*/}" \
        --manifest-artifact "$set_manifest_path" \
        --restore-run-id "$restore_run_id" \
        --target-id "$restore_target_id" \
        --restore-started-at "$restore_started_at" \
        --completed-at "$restore_completed_at" \
        --rto-seconds "$restore_rto_seconds" \
        <"$set_manifest_temporary" >"$status_temporary"
test -s "$status_temporary" || die "restore freshness status is empty"
ln -- "$receipt_temporary" "$receipt_destination" || die "restore receipt destination already exists"
rm -f -- "$receipt_temporary"
mv -- "$status_temporary" "$status_destination"
CAMELLIA_REMOTE_RESTORE_FSYNC_DIR="$restore_evidence_dir" python3 -c '
import os
fd = os.open(os.environ["CAMELLIA_REMOTE_RESTORE_FSYNC_DIR"], os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
'

printf '{"backup":"%s","receipt":"%s","rto_seconds":%s,"status":"restored:verified"}\n' \
    "$backup_path" "$receipt_destination" "$restore_rto_seconds"
