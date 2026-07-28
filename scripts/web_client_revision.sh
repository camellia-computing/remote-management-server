#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
LOCK_FILE="${SCRIPT_DIR}/../web-client.lock"

if [[ ! -f "$LOCK_FILE" ]]; then
  echo "Missing Web client revision lock: $LOCK_FILE" >&2
  exit 1
fi

mapfile -t lock_lines < "$LOCK_FILE"
if [[ ${#lock_lines[@]} -ne 1 || ! "${lock_lines[0]}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "web-client.lock must contain exactly one full 40-character lowercase Git commit" >&2
  exit 1
fi

printf '%s\n' "${lock_lines[0]}"
