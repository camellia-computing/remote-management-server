#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
resolver="$script_directory/../resolve-container-registries.sh"
test_root="$(mktemp -d)"
trap 'find "$test_root" -maxdepth 1 -type f -delete; rmdir "$test_root"' EXIT

resolve() {
  local map="$1"
  GITHUB_OUTPUT="$test_root/output" \
  GITHUB_REPOSITORY_OWNER=Example-Organization \
  LOGICAL_REPOSITORY_ID=remote-management \
  CONTAINER_REGISTRY_MAP="$map" \
    bash "$resolver"
}

resolve '{"remote-management":{"dockerhub":null,"ghcr":"management"},"remote-server":{"dockerhub":null,"ghcr":"server"}}'
grep -Fxq 'ghcr=ghcr.io/example-organization/management' "$test_root/output"
grep -Fxq 'dockerhub=' "$test_root/output"
grep -Fxq 'primary=ghcr.io/example-organization/management' "$test_root/output"

: > "$test_root/output"
resolve '{"remote-management":{"dockerhub":"example/management","ghcr":null}}'
grep -Fxq 'ghcr=' "$test_root/output"
grep -Fxq 'dockerhub=docker.io/example/management' "$test_root/output"
grep -Fxq 'primary=docker.io/example/management' "$test_root/output"

for invalid in \
  '{}' \
  '{"remote-management":{"dockerhub":null,"ghcr":null}}' \
  '{"remote-management":{"dockerhub":"UPPER/name","ghcr":null}}' \
  '{"remote-management":{"dockerhub":null,"ghcr":"owner/name"}}' \
  '{"remote-management":{"dockerhub":null,"ghcr":"valid","extra":"invalid"}}'
do
  : > "$test_root/output"
  if resolve "$invalid" >/dev/null 2>&1; then
    echo "Invalid registry map was accepted: $invalid" >&2
    exit 1
  fi
done

echo "Container registry map tests passed"
