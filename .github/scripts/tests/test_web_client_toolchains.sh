#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd -P)
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/.github/workflows"
workflow="$fixture/.github/workflows/ci.yml"
printf 'env:\n  FLUTTER_VERSION: "3.47.7"\n  NODE_VERSION: "24.22.1"\n' > "$workflow"
actual=$(bash "$root/scripts/web_client_toolchains.sh" "$fixture")
[[ "$actual" == $'flutter-version=3.47.7\nnode-version=24.22.1' ]]

for invalid in 'stable' '3.47.7-extra' '3.47.7 # comment' '3.47.7:unexpected'; do
  printf 'env:\n  FLUTTER_VERSION: "%s"\n  NODE_VERSION: "24.22.1"\n' "$invalid" > "$workflow"
  if bash "$root/scripts/web_client_toolchains.sh" "$fixture" >/dev/null 2>&1; then
    echo 'An invalid source toolchain was accepted' >&2
    exit 1
  fi
done

printf 'env:\n  FLUTTER_VERSION: "3.47.7"\n  NODE_VERSION: "24.22.1"\n  NODE_VERSION: "24.22.2"\n' > "$workflow"
if bash "$root/scripts/web_client_toolchains.sh" "$fixture" >/dev/null 2>&1; then
  echo 'Duplicate source toolchain declarations were accepted' >&2
  exit 1
fi

printf 'env:\n  NODE_VERSION: "24.22.1"\n' > "$workflow"
if bash "$root/scripts/web_client_toolchains.sh" "$fixture" >/dev/null 2>&1; then
  echo 'A missing source toolchain declaration was accepted' >&2
  exit 1
fi
echo 'Pinned source toolchain tests passed'
