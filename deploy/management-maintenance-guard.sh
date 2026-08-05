#!/usr/bin/env bash
set -euo pipefail

lease_file="/run/camellia-remote-management/maintenance.lease"
stack_unit="camellia-remote-management-stack.service"
systemctl_binary="/usr/bin/systemctl"

die() {
    echo "maintenance guard error: $*" >&2
    exit 255
}

usage() {
    echo "usage: $0 [--lease-file ABSOLUTE_PATH] [--stack-unit UNIT.service] [--systemctl-binary ABSOLUTE_PATH]" >&2
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --lease-file)
            [[ $# -ge 2 ]] || usage
            lease_file="$2"
            shift 2
            ;;
        --stack-unit)
            [[ $# -ge 2 ]] || usage
            stack_unit="$2"
            shift 2
            ;;
        --systemctl-binary)
            [[ $# -ge 2 ]] || usage
            systemctl_binary="$2"
            shift 2
            ;;
        *) usage ;;
    esac
done

[[ "$lease_file" = /* ]] || die "maintenance lease path must be absolute"
[[ "$systemctl_binary" = /* && -f "$systemctl_binary" && ! -L "$systemctl_binary" && -x "$systemctl_binary" ]] ||
    die "systemctl binary is missing, symlinked, or not executable"
[[ "$stack_unit" =~ ^[A-Za-z0-9_.@:-]+\.service$ ]] || die "stack unit name is invalid"

if [[ -e "$lease_file" || -L "$lease_file" ]]; then
    [[ -f "$lease_file" && ! -L "$lease_file" ]] || die "unsafe maintenance lease type"
    lease_mode="$(stat -c '%a' -- "$lease_file" 2>/dev/null)" || die "cannot inspect maintenance lease permissions"
    lease_owner="$(stat -c '%u' -- "$lease_file" 2>/dev/null)" || die "cannot inspect maintenance lease owner"
    lease_mode_value=$((8#$lease_mode))
    expected_owner=0
    if [[ "$(id -u)" -ne 0 ]]; then
        expected_owner="$(id -u)"
    fi
    if (( (lease_mode_value & 077) != 0 || (lease_mode_value & 0400) == 0 )) ||
        [[ "$lease_owner" -ne "$expected_owner" ]]; then
        die "unsafe maintenance lease owner or permissions"
    fi
    echo "skipped:maintenance"
    exit 1
fi

if ! active_state="$("$systemctl_binary" show --property=ActiveState --value "$stack_unit")"; then
    die "cannot query stack state"
fi
if [[ "$active_state" != "active" ]]; then
    echo "skipped:not-running state=$active_state"
    exit 1
fi
