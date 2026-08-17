#!/usr/bin/env bash
set -euo pipefail

umask 077

project_dir="${CAMELLIA_REMOTE_PROJECT_DIR:-/opt/camellia-remote-management}"
env_file="${CAMELLIA_REMOTE_ENV_FILE:-/etc/camellia-remote-management/management.env}"
docker_binary="${CAMELLIA_REMOTE_DOCKER_BINARY:-/usr/bin/docker}"
operation_runner="${CAMELLIA_REMOTE_OPERATION_RUNNER:-$project_dir/deploy/run-compose-operation.sh}"
operation_seed="${CAMELLIA_REMOTE_MAINTENANCE_OPERATION_ID:-$(date -u +%Y%m%dt%H%M%Sz)-$$}"

[[ -x "$operation_runner" && ! -L "$operation_runner" ]] || {
    echo "cleanup error: compose operation runner is missing or unsafe" >&2
    exit 2
}

run_cleanup_operation() {
    local suffix="$1"
    shift
    "$operation_runner" \
        --project-dir "$project_dir" \
        --env-file "$env_file" \
        --docker-binary "$docker_binary" \
        --operation-id "${operation_seed}-${suffix}" \
        --operation-kind cleanup \
        --service management \
        --timeout-seconds 300 \
        --env CAMELLIA_REMOTE_DATABASE_OPERATION_PROFILE=CLEANUP \
        -- "$@"
}

retention_result="$(run_cleanup_operation retention python manage.py purge_expired_state)"
printf '%s\n' "$retention_result"
capacity_result="$(run_cleanup_operation capacity python manage.py check_sequence_capacity --fail-level critical)"
printf '%s\n' "$capacity_result"
CAMELLIA_REMOTE_CLEANUP_RETENTION="$retention_result" CAMELLIA_REMOTE_CLEANUP_CAPACITY="$capacity_result" python3 - <<'PY'
import json
import os

retention = json.loads(os.environ["CAMELLIA_REMOTE_CLEANUP_RETENTION"])
capacity = json.loads(os.environ["CAMELLIA_REMOTE_CLEANUP_CAPACITY"])
if not isinstance(retention, dict) or not isinstance(capacity, dict):
    raise SystemExit(1)
if any(not isinstance(key, str) or not isinstance(value, (int, bool)) for key, value in retention.items()):
    raise SystemExit(1)
if capacity.get("status") not in {"ok", "warning"}:
    raise SystemExit(1)
base_effects = {
    "expired_access_tokens",
    "expired_oidc_sessions",
    "expired_device_proof_challenges",
    "expired_device_recovery_approvals",
    "expired_share_links_marked",
    "login_attempts",
    "login_admission_locks",
    "retained_share_links",
    "request_rate_buckets",
    "request_rate_leases",
}
bounded_effects = {
    "recording_active_expired",
    "recording_finalized_purged",
    "recording_aborted_purged",
    "recording_orphans_quarantined",
    "recording_quarantine_purged",
    "audit_connections_expired",
    "audit_connections_purged",
    "legacy_file_audits_purged",
    "legacy_alarm_audits_purged",
}
required = base_effects | bounded_effects | {
    "expired_management_batch_operations",
    "management_batch_operations_purged",
    "management_batch_operations_remaining",
    "dry_run",
}
if not required.issubset(retention) or retention["dry_run"] is not False:
    raise SystemExit(1)
for key in required - {"dry_run"}:
    value = retention[key]
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SystemExit(1)
if retention["management_batch_operations_purged"] + retention["management_batch_operations_remaining"] != retention[
    "expired_management_batch_operations"
]:
    raise SystemExit(1)
input_count = sum(retention[key] for key in base_effects | bounded_effects) + retention[
    "expired_management_batch_operations"
]
output_count = sum(retention[key] for key in base_effects | bounded_effects) + retention[
    "management_batch_operations_purged"
]
print(
    json.dumps(
        {
            "capacity_status": capacity.get("status"),
            "format": "camellia-remote-cleanup-result-v1",
            "input_count": input_count,
            "output_count": output_count,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
)
PY
