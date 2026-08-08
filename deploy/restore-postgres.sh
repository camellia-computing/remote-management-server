#!/usr/bin/env bash
set -euo pipefail

umask 077

project_dir="${CAMELLIA_REMOTE_PROJECT_DIR:-/opt/camellia-remote-management}"
env_file="${CAMELLIA_REMOTE_ENV_FILE:-/etc/camellia-remote-management/management.env}"
envelope_helper="${CAMELLIA_REMOTE_BACKUP_ENVELOPE_HELPER:-$project_dir/scripts/backup_envelope.py}"
age_binary="${CAMELLIA_REMOTE_BACKUP_AGE_BINARY:-/usr/bin/age}"
identity_file="${CAMELLIA_REMOTE_BACKUP_AGE_IDENTITY_FILE:-}"
deployment_id="${CAMELLIA_REMOTE_BACKUP_DEPLOYMENT_ID:-}"
database_name="${CAMELLIA_REMOTE_DATABASE_NAME:-}"
postgres_major_expected="${CAMELLIA_REMOTE_BACKUP_POSTGRES_MAJOR:-}"
backup_key_id_expected="${CAMELLIA_REMOTE_BACKUP_AGE_KEY_ID:-}"

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
[[ "$backup_path" == "$base_name" || "$backup_path" == */"$base_name" ]] || die "backup path is invalid"
backup_parent="$(dirname -- "$backup_path")"
recording_backup_path="$backup_parent/recordings-$expected_created_at-$expected_backup_id.bundle.age"
[[ -f "$recording_backup_path" && ! -L "$recording_backup_path" && -r "$recording_backup_path" ]] || \
    die "the matching encrypted recording backup is missing, unreadable, or a symlink"

[[ -n "$deployment_id" ]] || die "CAMELLIA_REMOTE_BACKUP_DEPLOYMENT_ID is required"
[[ -n "$database_name" ]] || die "CAMELLIA_REMOTE_DATABASE_NAME is required"
[[ -n "$postgres_major_expected" && "$postgres_major_expected" =~ ^[1-9][0-9]{0,2}$ ]] || \
    die "CAMELLIA_REMOTE_BACKUP_POSTGRES_MAJOR is required and invalid"
[[ -n "$backup_key_id_expected" ]] || die "CAMELLIA_REMOTE_BACKUP_AGE_KEY_ID is required"

compose=(docker compose --env-file "$env_file" -f "$project_dir/docker-compose.yaml")

# age authenticates the complete ciphertext before the envelope helper or
# pg_restore is allowed to run.  This short-lived file is mode 0600 and is
# removed on every exit; it prevents a tampered age stream from reaching
# pg_restore before age has verified its final authentication tag.  The backup
# artifact itself is always encrypted and no identity contents enter argv/logs.
database_envelope_temporary="$(mktemp "${TMPDIR:-/tmp}/camellia-restore-database.XXXXXX")" || \
    die "cannot create secure database restore temporary"
recording_envelope_temporary="$(mktemp "${TMPDIR:-/tmp}/camellia-restore-recordings.XXXXXX")" || \
    { rm -f -- "$database_envelope_temporary"; die "cannot create secure recording restore temporary"; }
chmod 0600 "$database_envelope_temporary" "$recording_envelope_temporary"
cleanup() {
    rm -f -- "$database_envelope_temporary" "$recording_envelope_temporary"
}
trap cleanup EXIT HUP INT TERM

set -o pipefail
"$age_binary" --decrypt --identity "$identity_file" "$backup_path" >"$database_envelope_temporary"
"$age_binary" --decrypt --identity "$identity_file" "$recording_backup_path" >"$recording_envelope_temporary"
pair_json="$(python3 "$envelope_helper" pair "$database_envelope_temporary" "$recording_envelope_temporary")" || \
    die "database and recording artifacts do not form one authenticated backup epoch"
pair_values="$(CAMELLIA_REMOTE_BACKUP_PAIR_JSON="$pair_json" \
    CAMELLIA_REMOTE_EXPECTED_BACKUP_ID="$expected_backup_id" \
    CAMELLIA_REMOTE_EXPECTED_CREATED_AT="$expected_created_at" \
    CAMELLIA_REMOTE_EXPECTED_DEPLOYMENT_ID="$deployment_id" \
    CAMELLIA_REMOTE_EXPECTED_DATABASE_NAME="$database_name" \
    CAMELLIA_REMOTE_EXPECTED_POSTGRES_MAJOR="$postgres_major_expected" \
    CAMELLIA_REMOTE_EXPECTED_KEY_ID="$backup_key_id_expected" \
    python3 -c '
import json, os
value = json.loads(os.environ["CAMELLIA_REMOTE_BACKUP_PAIR_JSON"])
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
print(value.get("recording_epoch_id", ""), value.get("recording_inventory_digest", ""))
')" || die "backup epoch metadata is invalid"
read -r recording_epoch_id recording_inventory_digest <<<"$pair_values"
[[ "$recording_epoch_id" =~ ^[0-9a-f-]{36}$ ]] || die "backup recording epoch is invalid"
[[ "$recording_inventory_digest" =~ ^[0-9a-f]{64}$ ]] || die "backup recording inventory digest is invalid"
# The authenticated artifact is restored only through the migration owner.
# Bootstrap runs before and after restore so an old superuser-owned volume and
# newly restored objects both converge to the same least-privilege boundary.
"${compose[@]}" run --rm --no-deps -T database-bootstrap
"${compose[@]}" run --rm --no-deps -T management python manage.py recording_backup restore-preflight
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
    | "${compose[@]}" run --rm --no-deps -T database-restore \
        pg_restore --single-transaction --exit-on-error --format=custom --no-owner --no-acl
set +o pipefail
"${compose[@]}" run --rm --no-deps -T database-bootstrap
"${compose[@]}" run --rm --no-deps -T management python manage.py check_username_identity >/dev/null || \
    die "restored username identity contract is invalid"
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
    | "${compose[@]}" run --rm --no-deps -T management python manage.py recording_backup restore \
        --backup-id "$expected_backup_id" \
        --epoch-id "$recording_epoch_id" \
        --inventory-digest "$recording_inventory_digest"
set +o pipefail
"${compose[@]}" run --rm --no-deps -T database-probe

printf 'restored %s\n' "$backup_path"
