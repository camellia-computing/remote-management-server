#!/usr/bin/env bash
set -euo pipefail

reference="${1:?image@digest is required}"
version="${2:?stable version is required}"
revision="${3:?source revision is required}"
web_revision="$(tr -d '\r\n' < web-client.lock)"

[[ "$reference" =~ @sha256:[0-9a-f]{64}$ ]]
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
[[ "$revision" =~ ^[0-9a-f]{40}$ ]]
[[ "$web_revision" =~ ^[0-9a-f]{40}$ ]]

docker buildx imagetools inspect --raw "$reference" |
  jq -e '
    [
      .manifests[]? |
      select(.platform.os == "linux") |
      .platform.architecture
    ] | sort | unique == ["amd64", "arm64"]
  ' >/dev/null

for architecture in amd64 arm64; do
  docker pull --platform "linux/$architecture" "$reference"
  image_id="$(docker image inspect --format '{{.Id}}' "$reference")"
  local_tag="remote-management-release-verify:$architecture"
  docker tag "$image_id" "$local_tag"
  docker run --rm --platform "linux/$architecture" \
    --entrypoint python "$local_tag" -c \
    'import django, camellia_remote_management; assert django.VERSION >= (6, 0)'
  image_version="$(docker image inspect \
    --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' \
    "$local_tag")"
  image_revision="$(docker image inspect \
    --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
    "$local_tag")"
  image_source="$(docker image inspect \
    --format '{{ index .Config.Labels "org.opencontainers.image.source" }}' \
    "$local_tag")"
  image_web_revision="$(docker image inspect \
    --format '{{ index .Config.Labels "io.camellia.remote.web.revision" }}' \
    "$local_tag")"
  [[ "$image_version" == "$version" ]]
  [[ "$image_revision" == "$revision" ]]
  [[ "$image_source" == "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY" ]]
  [[ "$image_web_revision" == "$web_revision" ]]
  [[ "$(docker image inspect --format '{{.Config.User}}' "$local_tag")" == "appuser" ]]
done
