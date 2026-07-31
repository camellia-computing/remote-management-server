#!/usr/bin/env bash
set -euo pipefail

: "${LATEST_DIGEST:?LATEST_DIGEST is required}"
: "${OWNS_LATEST:?OWNS_LATEST is required}"

ghcr_image="${GHCR_IMAGE:-}"
dockerhub_image="${DOCKERHUB_IMAGE:-}"

[[ "$LATEST_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  { echo "LATEST_DIGEST must be a canonical OCI digest" >&2; exit 1; }
[[ "$OWNS_LATEST" == true || "$OWNS_LATEST" == false ]] ||
  { echo "OWNS_LATEST must be true or false" >&2; exit 1; }

if [[ "$OWNS_LATEST" == false ]]; then
  echo "A newer completed stable release owns latest; registry aliases are unchanged"
  exit 0
fi

for image in "$dockerhub_image" "$ghcr_image"; do
  [[ -n "$image" ]] || continue
  oras copy --recursive "$image@$LATEST_DIGEST" "$image:latest"
  current="$(oras manifest fetch --descriptor "$image:latest" | jq -er '.digest')"
  [[ "$current" == "$LATEST_DIGEST" ]] || {
    echo "$image:latest does not resolve to $LATEST_DIGEST" >&2
    exit 1
  }
done
echo "Registry latest aliases resolve to $LATEST_DIGEST"
