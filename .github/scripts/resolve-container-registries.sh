#!/usr/bin/env bash
set -euo pipefail

: "${CONTAINER_REGISTRY_MAP:?CONTAINER_REGISTRY_MAP is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${GITHUB_REPOSITORY_OWNER:?GITHUB_REPOSITORY_OWNER is required}"
: "${LOGICAL_REPOSITORY_ID:?LOGICAL_REPOSITORY_ID is required}"

[[ "$LOGICAL_REPOSITORY_ID" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] || {
  echo "Invalid logical repository ID" >&2
  exit 1
}
owner="${GITHUB_REPOSITORY_OWNER,,}"
[[ "$owner" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] || {
  echo "Repository owner cannot form a canonical GHCR namespace" >&2
  exit 1
}

entry="$(
  jq -ce --arg id "$LOGICAL_REPOSITORY_ID" '
    if type != "object" then error("registry map must be an object")
    elif has($id) | not then error("logical repository is absent")
    elif .[$id] | type != "object" then error("registry entry must be an object")
    elif (.[$id] | keys) != ["dockerhub", "ghcr"] then
      error("registry entry must contain exactly dockerhub and ghcr")
    else .[$id] end
  ' <<< "$CONTAINER_REGISTRY_MAP"
)" || {
  echo "CONTAINER_REGISTRY_MAP does not contain a valid reviewed entry for $LOGICAL_REPOSITORY_ID" >&2
  exit 1
}

ghcr_name="$(jq -r '.ghcr // empty' <<< "$entry")"
dockerhub_name="$(jq -r '.dockerhub // empty' <<< "$entry")"
if [[ -n "$ghcr_name" &&
      ! "$ghcr_name" =~ ^[a-z0-9]+([._-][a-z0-9]+)*$ ]]; then
  echo "Reviewed GHCR image name is invalid" >&2
  exit 1
fi
if [[ -n "$dockerhub_name" &&
      ! "$dockerhub_name" =~ ^[a-z0-9]+([._-][a-z0-9]+)*/[a-z0-9]+([._-][a-z0-9]+)*$ ]]; then
  echo "Reviewed Docker Hub repository is invalid" >&2
  exit 1
fi
[[ -n "$ghcr_name" || -n "$dockerhub_name" ]] || {
  echo "A formal image release requires at least one configured registry" >&2
  exit 1
}

ghcr=""
dockerhub=""
[[ -z "$ghcr_name" ]] || ghcr="ghcr.io/$owner/$ghcr_name"
[[ -z "$dockerhub_name" ]] || dockerhub="docker.io/$dockerhub_name"
primary="${ghcr:-$dockerhub}"
{
  echo "dockerhub=$dockerhub"
  echo "ghcr=$ghcr"
  echo "primary=$primary"
} >> "$GITHUB_OUTPUT"
