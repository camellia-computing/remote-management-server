#!/usr/bin/env bash
set -euo pipefail

source_root=${1:?Usage: web_client_toolchains.sh SOURCE_ROOT}
workflow="$source_root/.github/workflows/ci.yml"
[[ -f "$workflow" && ! -L "$workflow" ]] || {
  echo 'The verified client source must declare its build toolchains' >&2
  exit 1
}

read_version() {
  local key=$1 value
  value=$(awk -F ': ' -v key="$key" '$1 == "  " key { gsub(/"/, "", $2); print $2 }' "$workflow")
  [[ "$value" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
    echo "The verified client source must declare one exact $key" >&2
    return 1
  }
  printf '%s' "$value"
}

flutter_version=$(read_version FLUTTER_VERSION)
node_version=$(read_version NODE_VERSION)
printf 'flutter-version=%s\nnode-version=%s\n' "$flutter_version" "$node_version"
