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
plaintext_temporary="$(mktemp "${TMPDIR:-/tmp}/camellia-restore.XXXXXX")" || die "cannot create secure restore temporary"
chmod 0600 "$plaintext_temporary"
cleanup() {
    rm -f -- "$plaintext_temporary"
}
trap cleanup EXIT HUP INT TERM

set -o pipefail
"$age_binary" --decrypt --identity "$identity_file" "$backup_path" >"$plaintext_temporary"
# The authenticated artifact is restored only through the migration owner.
# Bootstrap runs before and after restore so an old superuser-owned volume and
# newly restored objects both converge to the same least-privilege boundary.
"${compose[@]}" run --rm --no-deps -T database-bootstrap
python3 "$envelope_helper" unpack \
        --expect-backup-id "$expected_backup_id" \
        --expect-created-at "$expected_created_at" \
        --expect-deployment-id "$deployment_id" \
        --expect-database-name "$database_name" \
        --expect-postgres-major "$postgres_major_expected" \
        --expect-key-id "$backup_key_id_expected" \
    <"$plaintext_temporary" \
    | "${compose[@]}" run --rm --no-deps -T database-restore \
        pg_restore --single-transaction --exit-on-error --format=custom --no-owner --no-acl
set +o pipefail
"${compose[@]}" run --rm --no-deps -T database-bootstrap
"${compose[@]}" run --rm --no-deps -T database-probe

printf 'restored %s\n' "$backup_path"
