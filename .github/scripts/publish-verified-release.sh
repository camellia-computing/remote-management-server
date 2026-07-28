#!/usr/bin/env bash
set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${RELEASE_APP_LOGIN:?RELEASE_APP_LOGIN is required}"
: "${RELEASE_COMMIT:?RELEASE_COMMIT is required}"
: "${RELEASE_TAG:?RELEASE_TAG is required}"
: "${RELEASE_TITLE:?RELEASE_TITLE is required}"
: "${RELEASE_ASSET_DIRECTORY:?RELEASE_ASSET_DIRECTORY is required}"
: "${RELEASE_NOTES_FILE:?RELEASE_NOTES_FILE is required}"
: "${RELEASE_CHECKSUM_FILE:?RELEASE_CHECKSUM_FILE is required}"
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
[[ "$RELEASE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'RELEASE_COMMIT must be a full commit SHA' >&2
  exit 2
}
[[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo 'RELEASE_TAG must be a stable vX.Y.Z tag' >&2
  exit 2
}
[[ -d "$RELEASE_ASSET_DIRECTORY" && ! -L "$RELEASE_ASSET_DIRECTORY" ]] || {
  echo 'RELEASE_ASSET_DIRECTORY must be a real directory' >&2
  exit 2
}
for path in "$RELEASE_NOTES_FILE" "$RELEASE_CHECKSUM_FILE"; do
  [[ -f "$path" && ! -L "$path" ]] || {
    echo "Release verification file is unavailable or is a symlink: $path" >&2
    exit 2
  }
done
checksum_name="$(basename "$RELEASE_CHECKSUM_FILE")"

mapfile -t expected_assets < <(
  find "$RELEASE_ASSET_DIRECTORY" -maxdepth 1 -type f -printf '%f\n' | sort
)
((${#expected_assets[@]} > 0)) || {
  echo 'No release assets were provided' >&2
  exit 1
}
unexpected_entry="$(
  find "$RELEASE_ASSET_DIRECTORY" -mindepth 1 -maxdepth 1 ! -type f -print -quit
)"
[[ -z "$unexpected_entry" ]] || {
  echo "Release asset directory contains a non-regular entry: $unexpected_entry" >&2
  exit 2
}

upload_assets=()
notes_present=false
checksums_present=false
for asset in "${expected_assets[@]}"; do
  [[ "$asset" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] || {
    echo "Release asset name is not portable and safe: $asset" >&2
    exit 2
  }
  upload_assets+=("$RELEASE_ASSET_DIRECTORY/$asset")
  [[ "$asset" == "$(basename "$RELEASE_NOTES_FILE")" ]] && notes_present=true
  [[ "$asset" == "$checksum_name" ]] && checksums_present=true
done
[[ "$notes_present" == true && "$checksums_present" == true ]] || {
  echo 'Release notes and checksum manifest must both be published assets' >&2
  exit 2
}

releases_json="$(
  gh api -X GET "repos/$GITHUB_REPOSITORY/releases" -f per_page=100
)"
compatible_count="$(
  jq -r --arg tag "$RELEASE_TAG" \
    '[.[] | select(.tag_name == $tag)] | length' <<< "$releases_json"
)"
[[ "$compatible_count" == 0 || "$compatible_count" == 1 ]] || {
  echo "Multiple Releases unexpectedly use $RELEASE_TAG" >&2
  exit 1
}
if [[ "$compatible_count" == 1 ]]; then
  jq -e \
    --arg app "$RELEASE_APP_LOGIN" \
    --arg sha "$RELEASE_COMMIT" \
    --arg tag "$RELEASE_TAG" \
    --arg title "$RELEASE_TITLE" '
      .[] |
      select(.tag_name == $tag) |
      .draft == true and
      .immutable == false and
      .target_commitish == $sha and
      .author.login == $app and
      .name == $title
    ' <<< "$releases_json" >/dev/null || {
    echo "Existing Release $RELEASE_TAG is not a compatible App-authored draft" >&2
    exit 1
  }
fi

if [[ "$compatible_count" == 0 ]]; then
  gh release create "$RELEASE_TAG" "${upload_assets[@]}" \
    --draft \
    --notes-file "$RELEASE_NOTES_FILE" \
    --repo "$GITHUB_REPOSITORY" \
    --target "$RELEASE_COMMIT" \
    --title "$RELEASE_TITLE"
else
  gh release upload "$RELEASE_TAG" "${upload_assets[@]}" \
    --clobber \
    --repo "$GITHUB_REPOSITORY"
fi

verify_release() {
  local expected_draft="$1" expected_immutable="$2" destination release_json
  release_json="$(gh api "repos/$GITHUB_REPOSITORY/releases/tags/$RELEASE_TAG")"
  jq -e \
    --arg app "$RELEASE_APP_LOGIN" \
    --arg sha "$RELEASE_COMMIT" \
    --arg tag "$RELEASE_TAG" \
    --arg title "$RELEASE_TITLE" \
    --argjson draft "$expected_draft" \
    --argjson immutable "$expected_immutable" '
      .tag_name == $tag and
      .target_commitish == $sha and
      .author.login == $app and
      .name == $title and
      .prerelease == false and
      .draft == $draft and
      .immutable == $immutable and
      ([.assets[].name] | length == (unique | length)) and
      ([.assets[] | select(.uploader.login != $app)] | length == 0)
    ' <<< "$release_json" >/dev/null || return 1

  destination="$(mktemp -d "$RUNNER_TEMP/camellia-release-readback.XXXXXX")"
  printf '%s\n' "${expected_assets[@]}" > "$destination/expected-assets"
  jq -r '.assets[].name' <<< "$release_json" | sort > "$destination/actual-assets"
  cmp "$destination/expected-assets" "$destination/actual-assets" || {
    echo "Release asset set differs for $RELEASE_TAG" >&2
    return 1
  }
  jq -j '.body // ""' <<< "$release_json" > "$destination/release-notes"
  cmp "$RELEASE_NOTES_FILE" "$destination/release-notes" || {
    echo "Release notes differ for $RELEASE_TAG" >&2
    return 1
  }

  gh release download "$RELEASE_TAG" \
    --dir "$destination" \
    --repo "$GITHUB_REPOSITORY"
  for asset in "${expected_assets[@]}"; do
    cmp "$RELEASE_ASSET_DIRECTORY/$asset" "$destination/$asset" || {
      echo "Downloaded Release asset differs: $asset" >&2
      return 1
    }
  done
  (
    cd "$destination"
    sha256sum --check "$checksum_name"
  )
}

verify_release true false
gh release edit "$RELEASE_TAG" --draft=false --repo "$GITHUB_REPOSITORY"

for attempt in {1..15}; do
  if verify_release false true; then
    echo "Published and verified immutable Release $RELEASE_TAG"
    exit 0
  fi
  if ((attempt < 15)); then
    sleep 2
  fi
done
echo "Published Release $RELEASE_TAG did not converge to verified immutable state" >&2
exit 1
