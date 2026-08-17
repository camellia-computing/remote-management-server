#!/usr/bin/env bash
set -euo pipefail

umask 077

project_dir="${CAMELLIA_REMOTE_PROJECT_DIR:-/opt/camellia-remote-management}"
state_dir="${CAMELLIA_REMOTE_MAINTENANCE_STATE_DIR:-/var/lib/camellia-remote-management/maintenance}"
ledger_helper="${CAMELLIA_REMOTE_MAINTENANCE_LEDGER_HELPER:-$project_dir/scripts/maintenance_ledger.py}"
backup_age="${CAMELLIA_REMOTE_BACKUP_FRESHNESS_SECONDS:-5400}"
cleanup_age="${CAMELLIA_REMOTE_CLEANUP_FRESHNESS_SECONDS:-900}"
clock_skew="${CAMELLIA_REMOTE_MAINTENANCE_CLOCK_SKEW_SECONDS:-300}"
kind="${1:-all}"

die() {
    echo "maintenance freshness error: $*" >&2
    exit 1
}

[[ "$project_dir" = /* && "$state_dir" = /* && "$ledger_helper" = /* ]] || die "paths must be absolute"
[[ -f "$ledger_helper" && ! -L "$ledger_helper" && -r "$ledger_helper" ]] || die "ledger helper is missing or unsafe"
for value in "$backup_age" "$cleanup_age"; do
    [[ "$value" =~ ^[0-9]+$ && "$value" -ge 60 && "$value" -le 604800 ]] || die "freshness budgets are invalid"
done
[[ "$clock_skew" =~ ^[0-9]+$ && "$clock_skew" -le 3600 ]] || die "clock skew budget is invalid"
[[ "$kind" == "all" || "$kind" == "backup" || "$kind" == "cleanup" ]] || die "usage: check-maintenance-freshness.sh [all|backup|cleanup]"

check_one() {
    local target="$1" maximum_age="$2"
    python3 "$ledger_helper" check \
        --state-dir "$state_dir" \
        --kind "$target" \
        --maximum-age-seconds "$maximum_age" \
        --clock-skew-seconds "$clock_skew"
}

if [[ "$kind" == "backup" ]]; then
    check_one backup "$backup_age"
elif [[ "$kind" == "cleanup" ]]; then
    check_one cleanup "$cleanup_age"
else
    status=0
    check_one backup "$backup_age" || status=$?
    cleanup_status=0
    check_one cleanup "$cleanup_age" || cleanup_status=$?
    (( cleanup_status <= status )) || status=$cleanup_status
    exit "$status"
fi
