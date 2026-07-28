#!/usr/bin/env bash
set -euo pipefail

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
assets="$root/assets"
fake_bin="$root/bin"
remote="$root/remote"
runner="$root/runner"
state="$root/release-state"
mkdir -p "$assets" "$fake_bin" "$remote" "$runner"

printf 'verified payload\n' > "$assets/camellia-remote-1.2.3.tar.gz"
printf '# Verified release\n' > "$assets/RELEASE-NOTES.md"
(
  cd "$assets"
  sha256sum RELEASE-NOTES.md camellia-remote-1.2.3.tar.gz > SHA256SUMS
)

cat > "$fake_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

release_json() {
  local assets_json draft immutable
  [[ -f "$FAKE_STATE" ]] || return 1
  draft=true
  immutable=false
  if [[ "$(cat "$FAKE_STATE")" == published ]]; then
    draft=false
    immutable=true
  fi
  assets_json="$(
    find "$FAKE_REMOTE" -maxdepth 1 -type f -printf '%f\n' |
      LC_ALL=C sort |
      jq -Rsc --arg uploader "$FAKE_UPLOADER" '
        split("\n")[:-1] |
        map({name: ., uploader: {login: $uploader}})
      '
  )"
  jq -nc \
    --arg app "$FAKE_APP" \
    --arg sha "$FAKE_SHA" \
    --arg tag "$FAKE_TAG" \
    --arg title "$FAKE_TITLE" \
    --rawfile body "$FAKE_STATE.notes" \
    --argjson assets "$assets_json" \
    --argjson draft "$draft" \
    --argjson immutable "$immutable" '{
      tag_name: $tag,
      target_commitish: $sha,
      author: {login: $app},
      name: $title,
      body: $body,
      prerelease: false,
      draft: $draft,
      immutable: $immutable,
      assets: $assets
    }'
}

[[ "${GH_TOKEN:-}" == test-token ]] || {
  echo 'Mock gh received an unexpected token' >&2
  exit 1
}

case "$1" in
  api)
    shift
    method=GET
    route=
    while (($#)); do
      case "$1" in
        -X)
          method="$2"
          shift 2
          ;;
        -f|-H)
          shift 2
          ;;
        *)
          route="$1"
          shift
          ;;
      esac
    done
    [[ "$method" == GET ]] || exit 1
    case "$route" in
      repos/test/repository)
        jq -nc '{
          allow_auto_merge: false,
          allow_squash_merge: true,
          allow_merge_commit: false,
          allow_rebase_merge: false,
          delete_branch_on_merge: true,
          squash_merge_commit_title: "PR_TITLE",
          squash_merge_commit_message: "BLANK"
        }'
        ;;
      repos/test/repository/immutable-releases)
        jq -nc --argjson enabled "$FAKE_IMMUTABLE" '{enabled: $enabled}'
        ;;
      repos/test/repository/releases)
        if [[ -f "$FAKE_STATE" ]]; then
          release_json | jq -sc '.'
        else
          printf '[]\n'
        fi
        ;;
      repos/test/repository/releases/tags/v1.2.3)
        release_json
        ;;
      *)
        echo "Unexpected mock API route: $route" >&2
        exit 1
        ;;
    esac
    ;;
  release)
    operation="$2"
    tag="$3"
    shift 3
    [[ "$tag" == "$FAKE_TAG" ]] || exit 1
    case "$operation" in
      create)
        [[ ! -f "$FAKE_STATE" ]] || exit 1
        while (($#)) && [[ "$1" != --* ]]; do
          cp "$1" "$FAKE_REMOTE/$(basename "$1")"
          shift
        done
        notes=
        target=
        title=
        while (($#)); do
          case "$1" in
            --draft)
              shift
              ;;
            --notes-file)
              notes="$2"
              shift 2
              ;;
            --repo)
              shift 2
              ;;
            --target)
              target="$2"
              shift 2
              ;;
            --title)
              title="$2"
              shift 2
              ;;
            *)
              exit 1
              ;;
          esac
        done
        [[ "$target" == "$FAKE_SHA" && "$title" == "$FAKE_TITLE" && -f "$notes" ]]
        cp "$notes" "$FAKE_STATE.notes"
        printf 'draft\n' > "$FAKE_STATE"
        ;;
      upload)
        [[ -f "$FAKE_STATE" && "$(cat "$FAKE_STATE")" == draft ]]
        while (($#)) && [[ "$1" != --* ]]; do
          cp "$1" "$FAKE_REMOTE/$(basename "$1")"
          shift
        done
        [[ "$1" == --clobber && "$2" == --repo && "$3" == test/repository ]]
        ;;
      download)
        destination=
        while (($#)); do
          case "$1" in
            --dir)
              destination="$2"
              shift 2
              ;;
            --repo)
              shift 2
              ;;
            *)
              exit 1
              ;;
          esac
        done
        [[ -d "$destination" ]]
        cp "$FAKE_REMOTE"/* "$destination/"
        ;;
      edit)
        [[ "$1" == --draft=false && "$2" == --repo && "$3" == test/repository ]]
        printf 'published\n' > "$FAKE_STATE"
        ;;
      *)
        exit 1
        ;;
    esac
    ;;
  *)
    echo "Unexpected mock gh call: $*" >&2
    exit 1
    ;;
esac
EOF
chmod +x "$fake_bin/gh"

export FAKE_APP='release-manager[bot]'
export FAKE_IMMUTABLE=true
export FAKE_REMOTE="$remote"
export FAKE_SHA=0123456789abcdef0123456789abcdef01234567
export FAKE_STATE="$state"
export FAKE_TAG=v1.2.3
export FAKE_TITLE='Camellia Remote 1.2.3'
export FAKE_UPLOADER="$FAKE_APP"

run_policy() {
  PATH="$fake_bin:$PATH" \
  GH_TOKEN=test-token \
  GITHUB_REPOSITORY=test/repository \
  RELEASE_APP_LOGIN="$FAKE_APP" \
  RELEASE_APP_SLUG=release-manager \
    bash .github/scripts/validate-github-release-policy.sh
}

run_publisher() {
  PATH="$fake_bin:$PATH" \
  GH_TOKEN=test-token \
  GITHUB_REPOSITORY=test/repository \
  RELEASE_APP_LOGIN="$FAKE_APP" \
  RELEASE_ASSET_DIRECTORY="$assets" \
  RELEASE_CHECKSUM_FILE="$assets/SHA256SUMS" \
  RELEASE_COMMIT="$FAKE_SHA" \
  RELEASE_NOTES_FILE="$assets/RELEASE-NOTES.md" \
  RELEASE_TAG="$FAKE_TAG" \
  RELEASE_TITLE="$FAKE_TITLE" \
  RUNNER_TEMP="$runner" \
    bash .github/scripts/publish-verified-release.sh
}

run_policy >/dev/null
run_publisher >/dev/null
[[ "$(cat "$state")" == published ]]
cmp "$assets/camellia-remote-1.2.3.tar.gz" "$remote/camellia-remote-1.2.3.tar.gz"

printf 'interrupted upload\n' > "$remote/camellia-remote-1.2.3.tar.gz"
printf 'draft\n' > "$state"
run_publisher >/dev/null
cmp "$assets/camellia-remote-1.2.3.tar.gz" "$remote/camellia-remote-1.2.3.tar.gz"

rm -f "$state" "$state.notes" "$remote"/*
FAKE_UPLOADER='unexpected-user'
export FAKE_UPLOADER
if run_publisher >/dev/null 2>&1; then
  echo 'Publication accepted an asset uploaded by another identity' >&2
  exit 1
fi
[[ "$(cat "$state")" == draft ]]

rm -f "$state" "$state.notes" "$remote"/*
FAKE_UPLOADER="$FAKE_APP"
export FAKE_UPLOADER
printf 'unsafe\n' > "$assets/unsafe asset"
if run_publisher >/dev/null 2>&1; then
  echo 'Publication accepted a non-portable asset name' >&2
  exit 1
fi
[[ ! -f "$state" ]]
rm "$assets/unsafe asset"

FAKE_IMMUTABLE=false
export FAKE_IMMUTABLE
if run_policy >/dev/null 2>&1; then
  echo 'Repository policy accepted disabled immutable Releases' >&2
  exit 1
fi

echo 'Release publication policy and recovery tests passed'
