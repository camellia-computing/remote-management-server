#!/usr/bin/env bash
# Classify a candidate from immutable Git objects.  This is deliberately kept
# as a small, reviewable script: changing the classifier itself is a runtime
# change and is therefore covered by the production suite.
set -euo pipefail

: "${EVENT_NAME:?EVENT_NAME is required}"
: "${GITHUB_OUTPUT:=}"
: "${GITHUB_STEP_SUMMARY:=}"

runtime=false
automation=false
dependencies=false

if [[ "$EVENT_NAME" == "workflow_dispatch" ]]; then
  runtime=true
  automation=true
else
  if [[ "$EVENT_NAME" == "pull_request" ]]; then
    : "${PR_BASE_SHA:?PR_BASE_SHA is required}"
    : "${PR_HEAD_SHA:?PR_HEAD_SHA is required}"
    base="$PR_BASE_SHA"
    head="$PR_HEAD_SHA"
  else
    : "${PUSH_BASE_SHA:?PUSH_BASE_SHA is required}"
    : "${PUSH_HEAD_SHA:?PUSH_HEAD_SHA is required}"
    base="$PUSH_BASE_SHA"
    head="$PUSH_HEAD_SHA"
  fi
  [[ "$base" =~ ^[0-9a-f]{40}$|^0+$ ]]
  [[ "$head" =~ ^[0-9a-f]{40}$ ]]
  if [[ "$base" =~ ^0+$ ]]; then
    base="$(git hash-object -t tree /dev/null)"
  fi

  changed_paths="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/camellia-remote-changed-paths"
  umask 077
  git diff --name-only -z "$base" "$head" > "$changed_paths"
  while IFS= read -r -d '' path; do
    # Documentation-only changes can use the cheap metadata gate.  Workflow,
    # reusable-action, and CI policy changes are explicitly runtime changes.
    case "$path" in
      README.md|README_EN.md|docs/*|LICENSE|LICENSE.*|.github/ISSUE_TEMPLATE/*|.github/dependabot.yml|scripts/release_metadata.py|scripts/test_release_metadata.py)
        ;;
      .github/workflows/*|.github/actions/*|.github/scripts/ci_*)
        runtime=true
        ;;
      *)
        runtime=true
        ;;
    esac
    case "$path" in
      .github/*|scripts/*|deploy/*|docker-compose*.yml|docker-compose*.yaml|run.sh|sync_web_client.sh)
        automation=true
        ;;
    esac
    case "$path" in
      pyproject.toml|uv.lock|Dockerfile|docker-compose*.yml|docker-compose*.yaml|.github/dependabot.yml|.github/actions/*|.github/workflows/*)
        dependencies=true
        ;;
    esac
  done < "$changed_paths"
  rm -f -- "$changed_paths"
fi

if [[ -n "$GITHUB_OUTPUT" ]]; then
  {
    echo "runtime=$runtime"
    echo "automation=$automation"
    echo "dependencies=$dependencies"
  } >> "$GITHUB_OUTPUT"
fi
if [[ -n "$GITHUB_STEP_SUMMARY" ]]; then
  {
    echo "### Change classification"
    echo
    echo "- Runtime validation: \`$runtime\`"
    echo "- Automation validation: \`$automation\`"
    echo "- Dependency review: \`$dependencies\`"
  } >> "$GITHUB_STEP_SUMMARY"
else
  printf 'runtime=%s\nautomation=%s\ndependencies=%s\n' "$runtime" "$automation" "$dependencies"
fi
