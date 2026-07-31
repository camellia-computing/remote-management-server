#!/usr/bin/env bash
set -euo pipefail

: "${ACTIONS_TOKEN:?ACTIONS_TOKEN is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${RELEASE_SHA:?RELEASE_SHA is required}"
: "${RELEASE_SIGNING_IDENTITY:?RELEASE_SIGNING_IDENTITY is required}"
: "${RELEASE_TAG:?RELEASE_TAG is required}"
: "${VERSION:?VERSION is required}"
: "${RELEASE_ID:?RELEASE_ID is required}"
: "${RELEASE_APP_LOGIN:?RELEASE_APP_LOGIN is required}"
: "${RELEASE_PR_NUMBER:?RELEASE_PR_NUMBER is required}"
: "${LOGICAL_REPOSITORY_ID:?LOGICAL_REPOSITORY_ID is required}"
: "${LOGICAL_IMAGE_ID:?LOGICAL_IMAGE_ID is required}"
: "${RELEASE_TITLE:?RELEASE_TITLE is required}"
: "${RUNTIME_VERIFY_SCRIPT:?RUNTIME_VERIFY_SCRIPT is required}"

assets_directory="${ASSETS_DIRECTORY:-release-assets}"
oci_archive="${OCI_ARCHIVE:-release-image.oci.tar}"
verify_published_only="${VERIFY_PUBLISHED_ONLY:-false}"
recorded_digest="${RECORDED_DIGEST:-}"
ghcr_image="${GHCR_IMAGE:-}"
dockerhub_image="${DOCKERHUB_IMAGE:-}"
primary_image="${PRIMARY_IMAGE:-}"
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
tag="v$VERSION"
issuer="https://token.actions.githubusercontent.com"
tag_identity="https://github.com/$GITHUB_REPOSITORY/.github/workflows/publish-release.yml@refs/tags/$tag"
main_identity="https://github.com/$GITHUB_REPOSITORY/.github/workflows/publish-release.yml@refs/heads/main"
work_directory="$(mktemp -d "${RUNNER_TEMP:-/tmp}/container-release.XXXXXX")"
trap 'rm -rf "$work_directory"' EXIT

[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
  { echo "VERSION must be stable SemVer" >&2; exit 1; }
[[ "$RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]] ||
  { echo "RELEASE_SHA must be a full lowercase commit" >&2; exit 1; }
[[ "$RELEASE_TAG" == "$tag" ]] ||
  { echo "Release tag does not match v$VERSION" >&2; exit 1; }
[[ "$LOGICAL_REPOSITORY_ID" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ &&
  "$LOGICAL_IMAGE_ID" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] ||
  { echo "Release evidence IDs must be logical IDs" >&2; exit 1; }
[[ "$RELEASE_SIGNING_IDENTITY" == "$tag_identity" ||
  "$RELEASE_SIGNING_IDENTITY" == "$main_identity" ]] || {
  echo "Release signing identity is not an authorized publication workflow" >&2
  exit 1
}
[[ "$verify_published_only" == true || "$verify_published_only" == false ]] ||
  { echo "VERIFY_PUBLISHED_ONLY must be true or false" >&2; exit 1; }
[[ -n "$ghcr_image" || -n "$dockerhub_image" ]] ||
  { echo "At least one reviewed registry target is required" >&2; exit 1; }
[[ -n "$primary_image" &&
  ("$primary_image" == "$ghcr_image" || "$primary_image" == "$dockerhub_image") ]] || {
  echo "PRIMARY_IMAGE must identify one configured registry target" >&2
  exit 1
}
[[ -f "$RUNTIME_VERIFY_SCRIPT" && ! -L "$RUNTIME_VERIFY_SCRIPT" ]] ||
  { echo "Runtime verification script is unavailable" >&2; exit 1; }

release_json="$work_directory/release.json"
assets_json="$work_directory/assets.json"
remote_names="$work_directory/remote-assets"
expected_raw_names="$work_directory/expected-raw-assets"
expected_names="$work_directory/expected-assets"

refresh_release() {
  local body draft immutable
  GH_TOKEN="$GH_TOKEN" gh api --paginate --slurp \
    "repos/$GITHUB_REPOSITORY/releases?per_page=100" |
    jq -ce --arg tag "$tag" --argjson id "$RELEASE_ID" '
      [.[][] | select(.tag_name == $tag)] as $matches |
      if ($matches | length) == 1 and $matches[0].id == $id then $matches[0]
      elif ($matches | length) == 0 then error("managed release not found")
      elif ($matches | length) > 1 then error("multiple releases use the same tag")
      else error("managed release identity changed") end
    ' > "$release_json"
  [[ "$(jq -r '.target_commitish // empty' "$release_json")" == "$RELEASE_SHA" ]] ||
    { echo "Release target changed" >&2; return 1; }
  [[ "$(jq -r '.name // empty' "$release_json")" == "$RELEASE_TITLE $VERSION" ]] ||
    { echo "Release title changed" >&2; return 1; }
  [[ "$(jq -r '.author.login // empty' "$release_json")" == "$RELEASE_APP_LOGIN" ]] ||
    { echo "Release author changed" >&2; return 1; }
  draft="$(jq -r '.draft | if . == true then "true" elif . == false then "false" else empty end' "$release_json")"
  immutable="$(jq -r '.immutable | if . == true then "true" elif . == false then "false" else empty end' "$release_json")"
  [[ -n "$draft" && -n "$immutable" && ("$draft" == true || "$immutable" == true) ]] ||
    { echo "Release state metadata is invalid" >&2; return 1; }
  body="$(jq -r '.body // ""' "$release_json")"
  [[ "$(grep -Fxc "<!-- release-commit:$RELEASE_SHA -->" <<< "$body" || true)" == 1 ]] ||
    { echo "Managed commit marker changed" >&2; return 1; }
  [[ "$(grep -Fxc "<!-- release-pr:$RELEASE_PR_NUMBER -->" <<< "$body" || true)" == 1 ]] ||
    { echo "Managed PR marker changed" >&2; return 1; }
  jq -ce '.assets | if type == "array" then . else error("release assets unavailable") end' \
    "$release_json" > "$assets_json"
  jq -r '.[].name' "$assets_json" | LC_ALL=C sort > "$remote_names"
  [[ "$(uniq -d "$remote_names")" == "" ]] ||
    { echo "Release contains duplicate asset names" >&2; return 1; }
}

download_asset() {
  local name="$1" destination="$2" asset_id
  asset_id="$(jq -r --arg name "$name" '.[] | select(.name == $name) | .id' "$assets_json")"
  [[ "$asset_id" =~ ^[1-9][0-9]*$ ]] ||
    { echo "Unable to resolve remote asset $name" >&2; return 1; }
  GH_TOKEN="$GH_TOKEN" gh api -H "Accept: application/octet-stream" \
    "repos/$GITHUB_REPOSITORY/releases/assets/$asset_id" > "$destination"
}

delete_asset() {
  local name="$1" asset_id
  asset_id="$(jq -r --arg name "$name" '.[] | select(.name == $name) | .id' "$assets_json")"
  [[ "$asset_id" =~ ^[1-9][0-9]*$ ]] ||
    { echo "Unable to resolve draft asset $name" >&2; return 1; }
  GH_TOKEN="$GH_TOKEN" gh api -X DELETE \
    "repos/$GITHUB_REPOSITORY/releases/assets/$asset_id" >/dev/null
}

verify_blob_bundle() {
  local subject="$1" bundle="$2" identity
  local -a identities=("$tag_identity")
  [[ "$RELEASE_SIGNING_IDENTITY" == "$tag_identity" ]] ||
    identities+=("$RELEASE_SIGNING_IDENTITY")
  for identity in "${identities[@]}"; do
    if cosign verify-blob "$subject" \
      --bundle "$bundle" \
      --certificate-identity "$identity" \
      --certificate-oidc-issuer "$issuer" >/dev/null 2>&1; then
      return 0
    fi
  done
  echo "Blob signature is not bound to the managed publication workflow: $(basename "$bundle")" >&2
  return 1
}

verify_image_signature() {
  local image="$1" digest="$2" output="${3:-}" identity result
  local -a identities=("$tag_identity")
  [[ "$RELEASE_SIGNING_IDENTITY" == "$tag_identity" ]] ||
    identities+=("$RELEASE_SIGNING_IDENTITY")
  for identity in "${identities[@]}"; do
    if result="$(cosign verify "$image@$digest" \
      --certificate-identity "$identity" \
      --certificate-oidc-issuer "$issuer" \
      --output json 2>/dev/null)"; then
      [[ -z "$output" ]] || printf '%s\n' "$result" > "$output"
      printf '%s\n' "$identity"
      return 0
    fi
  done
  echo "Image signature is not bound to the managed publication workflow: $image@$digest" >&2
  return 1
}

descriptor_digest() {
  local reference="$1" output digest
  if ! output="$(oras manifest fetch --descriptor "$reference" 2>&1)"; then
    if grep -Eqi "manifest unknown|name unknown|not found|404" <<< "$output"; then
      return 0
    fi
    echo "Unable to query $reference: $output" >&2
    return 1
  fi
  digest="$(jq -er '.digest' <<< "$output")" || return 1
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    { echo "Registry returned an invalid digest for $reference" >&2; return 1; }
  printf '%s\n' "$digest"
}

verify_registry_aliases() {
  local image="$1" digest="$2" alias
  for alias in "$VERSION" "sha-$RELEASE_SHA"; do
    [[ "$(descriptor_digest "$image:$alias")" == "$digest" ]] || {
      echo "$image:$alias does not resolve to $digest" >&2
      return 1
    }
  done
  [[ "$(descriptor_digest "$image@$digest")" == "$digest" ]]
}

verify_registry_evidence() {
  local directory="$1" digest="$2"
  jq -e \
    --arg commit "$RELEASE_SHA" \
    --arg digest "$digest" \
    --arg dockerhub "$dockerhub_image" \
    --arg ghcr "$ghcr_image" \
    --arg version "$VERSION" '
      def expected($name; $repository):
        if $repository == "" then
          .name == $name and .status == "skipped" and
          .reason == "not-configured" and
          (keys | sort) == ["name", "reason", "status"]
        else
          .name == $name and .status == "published" and
          .repository == $repository and .digest == $digest and
          .aliases == [$version, ("sha-" + $commit)] and
          .readback == "verified" and
          .signature.mechanism == "keyless-cosign" and
          .signature.verification == "verified" and
          .signature.issuer == "https://token.actions.githubusercontent.com" and
          .signature.evidence == [($name + "-cosign-verification.json")]
        end;
      length == 2 and
      (.[0] | expected("dockerhub"; $dockerhub)) and
      (.[1] | expected("ghcr"; $ghcr))
    ' "$directory/registry-results.json" >/dev/null || {
    echo "Registry results do not match the reviewed registry map" >&2
    return 1
  }
}

configure_local_assets() {
  find "$assets_directory" -maxdepth 1 -type f ! -name "*.sigstore.json" \
    -printf "%f\n" | LC_ALL=C sort > "$expected_raw_names"
  {
    cat "$expected_raw_names"
    sed "s/$/.sigstore.json/" "$expected_raw_names"
  } | LC_ALL=C sort > "$expected_names"
}

configure_remote_assets() {
  local bootstrap="$work_directory/checksum-bootstrap"
  local bootstrap_bundle="$bootstrap.sigstore.json"
  grep -Fxq SHA256SUMS "$remote_names" ||
    { echo "Published Release has no checksum inventory" >&2; return 1; }
  grep -Fxq SHA256SUMS.sigstore.json "$remote_names" ||
    { echo "Published Release has no signed checksum inventory" >&2; return 1; }
  download_asset SHA256SUMS "$bootstrap"
  download_asset SHA256SUMS.sigstore.json "$bootstrap_bundle"
  verify_blob_bundle "$bootstrap" "$bootstrap_bundle"
  python3 - "$bootstrap" "$expected_raw_names" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
entries = []
for line in source.read_text(encoding="utf-8").splitlines():
    match = re.fullmatch(r"[0-9a-f]{64}  ([A-Za-z0-9][A-Za-z0-9._-]*)", line)
    if not match:
        raise ValueError("SHA256SUMS contains an unsafe or malformed entry")
    name = match.group(1)
    if name == "SHA256SUMS" or name.endswith(".sigstore.json"):
        raise ValueError("SHA256SUMS contains a recursive or signature entry")
    entries.append(name)
if entries != sorted(set(entries)):
    raise ValueError("SHA256SUMS entries must be sorted and unique")
names = sorted(["SHA256SUMS", *entries])
destination.write_text("\n".join(names) + "\n", encoding="utf-8")
PY
  {
    cat "$expected_raw_names"
    sed "s/$/.sigstore.json/" "$expected_raw_names"
  } | LC_ALL=C sort > "$expected_names"
}

verify_asset_directory() {
  local directory="$1" digest="$2" bundle subject evidence_name
  (
    cd "$directory"
    sha256sum --check SHA256SUMS
  )
  python3 "$script_directory/validate-release-evidence.py" \
    "$directory/release-evidence.json" >/dev/null
  jq -e \
    --arg commit "$RELEASE_SHA" \
    --arg digest "$digest" \
    --arg image "$LOGICAL_IMAGE_ID" \
    --arg repository "$LOGICAL_REPOSITORY_ID" \
    --arg version "$VERSION" '
      .repository == $repository and
      .version == $version and
      .release_kind == "formal" and
      .source.commit == $commit and
      .source.ref == ("refs/tags/v" + $version) and
      .files == [] and
      (.images | length) == 1 and
      .images[0].name == $image and
      .images[0].digest == $digest
    ' "$directory/release-evidence.json" >/dev/null || {
    echo "Release evidence does not identify the managed service image" >&2
    return 1
  }
  verify_registry_evidence "$directory" "$digest"
  while IFS= read -r evidence_name; do
    [[ "$evidence_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ &&
      -f "$directory/$evidence_name" && ! -L "$directory/$evidence_name" ]] || {
      echo "Dependency evidence is unavailable or unsafe: $evidence_name" >&2
      return 1
    }
  done < <(jq -r '.dependencies[].evidence' "$directory/release-evidence.json")
  while IFS= read -r -d '' bundle; do
    subject="${bundle%.sigstore.json}"
    [[ -f "$subject" && ! -L "$subject" ]] ||
      { echo "Signature bundle has no safe subject" >&2; return 1; }
    verify_blob_bundle "$subject" "$bundle"
  done < <(find "$directory" -maxdepth 1 -type f -name "*.sigstore.json" -print0 | sort -z)
}

verify_remote_release() {
  local destination="$1" digest="$2" name
  diff -u "$expected_names" "$remote_names"
  mkdir "$destination"
  while IFS= read -r name; do
    download_asset "$name" "$destination/$name"
  done < "$expected_names"
  verify_asset_directory "$destination" "$digest"
}

verify_attestations() {
  local digest="$1"
  GH_TOKEN="$ACTIONS_TOKEN" gh attestation verify \
    "oci://$primary_image@$digest" --repo "$GITHUB_REPOSITORY" >/dev/null
  GH_TOKEN="$ACTIONS_TOKEN" gh attestation verify \
    "oci://$primary_image@$digest" --repo "$GITHUB_REPOSITORY" \
    --predicate-type "https://spdx.dev/Document/v2.3" >/dev/null
}

refresh_release
if [[ "$verify_published_only" == true || "$(jq -r '.draft' "$release_json")" == false ]]; then
  [[ "$(jq -r '.draft' "$release_json")" == false ]] ||
    { echo "Verification-only mode requires a published Release" >&2; exit 1; }
  [[ "$recorded_digest" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    { echo "Published recovery requires its recorded digest" >&2; exit 1; }
  configure_remote_assets
  for image in "$dockerhub_image" "$ghcr_image"; do
    [[ -n "$image" ]] || continue
    verify_registry_aliases "$image" "$recorded_digest"
    verify_image_signature "$image" "$recorded_digest" >/dev/null
  done
  verify_remote_release "$work_directory/published-existing" "$recorded_digest"
  verify_attestations "$recorded_digest"
  echo "Verified existing immutable $tag and all configured registries"
  exit 0
fi

[[ -d "$assets_directory" && ! -L "$assets_directory" ]] ||
  { echo "Release evidence directory is unavailable" >&2; exit 1; }
[[ -f "$oci_archive" && ! -L "$oci_archive" ]] ||
  { echo "Frozen OCI archive is unavailable" >&2; exit 1; }
digest="$(jq -r '.digest // empty' "$assets_directory/frozen-release-evidence.json")"
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  { echo "Frozen evidence contains no valid OCI digest" >&2; exit 1; }
[[ -z "$recorded_digest" ]] ||
  { echo "Draft Release cannot contain a recorded digest" >&2; exit 1; }
jq -e \
  --arg commit "$RELEASE_SHA" \
  --arg digest "$digest" \
  --arg image "$LOGICAL_IMAGE_ID" \
  --arg repository "$LOGICAL_REPOSITORY_ID" \
  --arg version "$VERSION" '
    .repository == $repository and .image == $image and
    .version == $version and .source.commit == $commit and
    .source.ref == ("refs/tags/v" + $version) and .digest == $digest
  ' "$assets_directory/frozen-release-evidence.json" >/dev/null

oci_layout="$work_directory/oci-layout"
python3 - "$oci_archive" "$oci_layout" <<'PY'
import pathlib
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
destination.mkdir()
with tarfile.open(archive, "r:*") as source:
    for member in source.getmembers():
        if not (member.isdir() or member.isfile()):
            raise ValueError(f"unsafe OCI archive member: {member.name}")
    source.extractall(destination, filter="data")
PY
[[ "$(jq -r '.imageLayoutVersion // empty' "$oci_layout/oci-layout")" == "1.0.0" ]]
mapfile -t layout_digests < <(jq -r '.manifests[].digest' "$oci_layout/index.json" | sort -u)
[[ "${#layout_digests[@]}" == 1 && "${layout_digests[0]}" == "$digest" ]] || {
  echo "OCI archive descriptor does not match frozen digest" >&2
  exit 1
}

registry_fragments=()
publish_registry() {
  local name="$1" image="$2" alias current signature_file identity fragment
  fragment="$work_directory/$name-result.json"
  registry_fragments+=("$fragment")
  if [[ -z "$image" ]]; then
    jq -n --arg name "$name" \
      '{name:$name,status:"skipped",reason:"not-configured"}' > "$fragment"
    return
  fi
  for alias in "$VERSION" "sha-$RELEASE_SHA"; do
    current="$(descriptor_digest "$image:$alias")"
    if [[ -z "$current" ]]; then
      oras copy --recursive --from-oci-layout "$oci_layout@$digest" "$image:$alias"
      current="$(descriptor_digest "$image:$alias")"
    fi
    [[ "$current" == "$digest" ]] || {
      echo "Immutable alias conflict: $image:$alias resolves to $current" >&2
      return 1
    }
  done
  cosign sign --yes "$image@$digest"
  signature_file="$assets_directory/$name-cosign-verification.json"
  identity="$(verify_image_signature "$image" "$digest" "$signature_file")"
  verify_registry_aliases "$image" "$digest"
  jq -n \
    --arg name "$name" --arg repository "$image" --arg digest "$digest" \
    --arg version "$VERSION" --arg commit "$RELEASE_SHA" \
    --arg identity "$identity" --arg evidence "$name-cosign-verification.json" '{
      name: $name,
      status: "published",
      repository: $repository,
      digest: $digest,
      aliases: [$version, ("sha-" + $commit)],
      signature: {
        mechanism: "keyless-cosign",
        verification: "verified",
        identity: $identity,
        issuer: "https://token.actions.githubusercontent.com",
        evidence: [$evidence]
      },
      readback: "verified"
    }' > "$fragment"
}

publish_registry dockerhub "$dockerhub_image"
publish_registry ghcr "$ghcr_image"
jq -s 'sort_by(.name)' "${registry_fragments[@]}" > "$assets_directory/registry-results.json"
verify_registry_evidence "$assets_directory" "$digest"
bash "$RUNTIME_VERIFY_SCRIPT" "$primary_image@$digest" "$VERSION" "$RELEASE_SHA"

python3 "$script_directory/build-container-release-evidence.py" finalize \
  --frozen "$assets_directory/frozen-release-evidence.json" \
  --registries "$assets_directory/registry-results.json" \
  --output "$assets_directory/release-evidence.json"
python3 "$script_directory/validate-release-evidence.py" \
  "$assets_directory/release-evidence.json" >/dev/null
(
  cd "$assets_directory"
  find . -maxdepth 1 -type f ! -name "*.sigstore.json" ! -name SHA256SUMS \
    -printf "%f\0" |
    LC_ALL=C sort -z |
    xargs -0 sha256sum > "$work_directory/release-checksums"
  mv "$work_directory/release-checksums" SHA256SUMS
  sha256sum --check SHA256SUMS
)
configure_local_assets
mapfile -d "" subjects < <(
  find "$assets_directory" -maxdepth 1 -type f ! -name "*.sigstore.json" -print0 |
    sort -z
)
for subject in "${subjects[@]}"; do
  cosign sign-blob --yes --bundle "$subject.sigstore.json" "$subject" >/dev/null
  verify_blob_bundle "$subject" "$subject.sigstore.json"
done
configure_local_assets
find "$assets_directory" -maxdepth 1 -type f -printf "%f\n" |
  LC_ALL=C sort > "$work_directory/local-assets"
diff -u "$expected_names" "$work_directory/local-assets"
verify_asset_directory "$assets_directory" "$digest"
verify_attestations "$digest"

refresh_release
[[ "$(jq -r '.draft' "$release_json")" == true ]] || {
  configure_remote_assets
  verify_remote_release "$work_directory/published-concurrently" "$digest"
  exit 0
}
LC_ALL=C comm -13 "$expected_names" "$remote_names" > "$work_directory/unexpected-assets"
[[ ! -s "$work_directory/unexpected-assets" ]] || {
  echo "Draft Release contains unexpected assets" >&2
  sed "s/^/  /" "$work_directory/unexpected-assets" >&2
  exit 1
}
while IFS= read -r name; do
  local_path="$assets_directory/$name"
  if grep -Fxq "$name" "$remote_names"; then
    remote_path="$work_directory/existing-$name"
    download_asset "$name" "$remote_path"
    if ! cmp -s "$local_path" "$remote_path"; then
      delete_asset "$name"
      GH_TOKEN="$GH_TOKEN" gh release upload "$tag" "$local_path" \
        --repo "$GITHUB_REPOSITORY"
    fi
  else
    GH_TOKEN="$GH_TOKEN" gh release upload "$tag" "$local_path" \
      --repo "$GITHUB_REPOSITORY"
  fi
done < "$expected_names"

refresh_release
verify_remote_release "$work_directory/verified-draft" "$digest"
ACTIONS_TOKEN="$ACTIONS_TOKEN" GH_TOKEN="$GH_TOKEN" \
  python3 "$script_directory/manage-release.py" authorize \
    --version "$VERSION" --sha "$RELEASE_SHA" --tag "$tag" >/dev/null
refresh_release
if [[ "$(jq -r '.draft' "$release_json")" == true ]]; then
  body="$(jq -r '.body // ""' "$release_json")"
  marker="<!-- container-digest:$digest -->"
  existing="$(grep -E '^<!-- container-digest:sha256:[0-9a-f]{64} -->$' <<< "$body" || true)"
  [[ -z "$existing" || "$existing" == "$marker" ]] ||
    { echo "Release notes contain a conflicting digest" >&2; exit 1; }
  if [[ -z "$existing" ]]; then
    notes="$work_directory/release-notes.md"
    {
      printf "%s\n\n## Container image\n\n" "$body"
      for image in "$dockerhub_image" "$ghcr_image"; do
        [[ -n "$image" ]] || continue
        printf -- "- \`%s@%s\`\n" "$image" "$digest"
      done
      printf "\nImmutable aliases: \`%s\`, \`sha-%s\`.\n\n%s\n" \
        "$VERSION" "$RELEASE_SHA" "$marker"
    } > "$notes"
    GH_TOKEN="$GH_TOKEN" gh release edit "$tag" --repo "$GITHUB_REPOSITORY" \
      --notes-file "$notes"
  fi
  GH_TOKEN="$GH_TOKEN" gh release edit "$tag" --repo "$GITHUB_REPOSITORY" \
    --draft=false
fi

refresh_release
[[ "$(jq -r '.draft' "$release_json")" == false &&
  "$(jq -r '.immutable' "$release_json")" == true ]] ||
  { echo "Release did not become immutable" >&2; exit 1; }
body="$(jq -r '.body // ""' "$release_json")"
[[ "$(grep -Fxc "<!-- container-digest:$digest -->" <<< "$body" || true)" == 1 ]]
verify_remote_release "$work_directory/published" "$digest"
for image in "$dockerhub_image" "$ghcr_image"; do
  [[ -n "$image" ]] || continue
  verify_registry_aliases "$image" "$digest"
  verify_image_signature "$image" "$digest" >/dev/null
done
echo "Published and independently re-read $tag at $digest"
