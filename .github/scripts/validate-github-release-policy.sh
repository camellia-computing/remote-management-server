#!/usr/bin/env bash
set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${RELEASE_APP_LOGIN:?RELEASE_APP_LOGIN is required}"
: "${RELEASE_APP_SLUG:?RELEASE_APP_SLUG is required}"

[[ "$RELEASE_APP_SLUG" =~ ^[a-z0-9][a-z0-9-]*$ &&
   "$RELEASE_APP_LOGIN" == "${RELEASE_APP_SLUG}[bot]" ]] || {
  echo 'Release policy token identity does not match RELEASE_APP_LOGIN' >&2
  exit 1
}

repository_json="$(gh api "repos/$GITHUB_REPOSITORY")" || {
  echo 'Unable to read repository release policy' >&2
  exit 1
}
jq -e '
  .allow_auto_merge == false and
  .allow_squash_merge == true and
  .allow_merge_commit == false and
  .allow_rebase_merge == false and
  .delete_branch_on_merge == true and
  .squash_merge_commit_title == "PR_TITLE" and
  .squash_merge_commit_message == "BLANK"
' <<< "$repository_json" >/dev/null || {
  echo 'Repository must disable auto-merge and use squash-only PR-title merges with blank messages and automatic branch deletion' >&2
  exit 1
}

immutable_json="$(gh api "repos/$GITHUB_REPOSITORY/immutable-releases")" || {
  echo 'Unable to read immutable Release settings' >&2
  exit 1
}
jq -e '.enabled == true' <<< "$immutable_json" >/dev/null || {
  echo 'Repository must enable immutable Releases' >&2
  exit 1
}

echo "Validated release policy for $GITHUB_REPOSITORY as $RELEASE_APP_LOGIN"
