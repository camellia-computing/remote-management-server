#!/usr/bin/env bash
set -euo pipefail

umask 077

project_dir="${CAMELLIA_REMOTE_PROJECT_DIR:-/opt/camellia-remote-management}"
state_dir="${CAMELLIA_REMOTE_MAINTENANCE_STATE_DIR:-/var/lib/camellia-remote-management/maintenance}"
ledger_helper="${CAMELLIA_REMOTE_MAINTENANCE_LEDGER_HELPER:-$project_dir/scripts/maintenance_ledger.py}"
systemctl_binary="${CAMELLIA_REMOTE_SYSTEMCTL_BINARY:-/usr/bin/systemctl}"
unit="${1:-}"

die() {
    echo "maintenance failure notifier error: $*" >&2
    exit 1
}

case "$unit" in
    camellia-remote-management-backup.service) kind=backup ;;
    camellia-remote-management-cleanup.service) kind=cleanup ;;
    *) die "unit is not an approved maintenance service" ;;
esac
[[ "$project_dir" = /* && "$state_dir" = /* && "$ledger_helper" = /* && "$systemctl_binary" = /* ]] || die "paths must be absolute"
[[ -f "$ledger_helper" && ! -L "$ledger_helper" && -r "$ledger_helper" ]] || die "ledger helper is missing or unsafe"
[[ -x "$systemctl_binary" && ! -L "$systemctl_binary" ]] || die "systemctl binary is missing or unsafe"

invocation_id="$($systemctl_binary show --property=InvocationID --value "$unit")" || die "cannot read maintenance invocation ID"
[[ "$invocation_id" =~ ^[0-9a-f]{32}$ ]] || die "maintenance invocation ID is invalid"
python3 "$ledger_helper" notify-failure \
    --state-dir "$state_dir" \
    --kind "$kind" \
    --notification-id "$invocation_id" >/dev/null
