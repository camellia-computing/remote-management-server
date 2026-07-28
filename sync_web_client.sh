#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SRC_INPUT=""
CLIENT_REPO_INPUT=""
LOCKED_REVISION="$("${SCRIPT_DIR}/scripts/web_client_revision.sh")"

usage() {
  cat <<'EOF'
Usage:
  sync_web_client.sh --build-from CLIENT_REPOSITORY
  sync_web_client.sh --source COMPILED_WEB_DIRECTORY

Exactly one input mode is required. --build-from runs the client's canonical
release build first; --source only synchronizes an already compiled, clean and
revision-stamped build. Both modes require the source revision pinned by
web-client.lock.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build-from)
      if [[ $# -lt 2 ]]; then
        echo "--build-from requires a client repository" >&2
        exit 2
      fi
      CLIENT_REPO_INPUT="$2"
      shift 2
      ;;
    --source)
      if [[ $# -lt 2 ]]; then
        echo "--source requires a compiled web directory" >&2
        exit 2
      fi
      SRC_INPUT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -n "$SRC_INPUT" && -n "$CLIENT_REPO_INPUT" ]]; then
  echo "--source and --build-from are mutually exclusive" >&2
  exit 2
fi
if [[ -z "$SRC_INPUT" && -z "$CLIENT_REPO_INPUT" ]]; then
  usage >&2
  exit 2
fi

EXPECTED_REVISION=""
if [[ -n "$CLIENT_REPO_INPUT" ]]; then
  if [[ ! -d "$CLIENT_REPO_INPUT" ]]; then
    echo "Client repository not found: $CLIENT_REPO_INPUT" >&2
    exit 1
  fi
  CLIENT_REPO="$(cd "$CLIENT_REPO_INPUT" && pwd -P)"
  BUILD_SCRIPT="${CLIENT_REPO}/flutter/web/tools/build_web.sh"
  if [[ ! -f "$BUILD_SCRIPT" ]] || ! git -C "$CLIENT_REPO" rev-parse --show-toplevel >/dev/null 2>&1; then
    echo "Invalid client repository: $CLIENT_REPO" >&2
    exit 1
  fi
  if [[ -n "$(git -C "$CLIENT_REPO" status --porcelain --untracked-files=no)" ]]; then
    echo "Client repository has tracked changes; commit them before producing a synchronized runtime." >&2
    exit 1
  fi
  EXPECTED_REVISION="$(git -C "$CLIENT_REPO" rev-parse HEAD)"
  if [[ "$EXPECTED_REVISION" != "$LOCKED_REVISION" ]]; then
    echo "Client repository revision does not match web-client.lock: expected $LOCKED_REVISION, got $EXPECTED_REVISION" >&2
    exit 1
  fi

  (cd "$CLIENT_REPO" && bash "$BUILD_SCRIPT" --mode release)

  if [[ -n "$(git -C "$CLIENT_REPO" status --porcelain --untracked-files=no)" ]]; then
    echo "Client build modified tracked source files; refusing to synchronize ambiguous output." >&2
    exit 1
  fi
  SRC_INPUT="${CLIENT_REPO}/flutter/build/web"
fi

if [[ ! -d "$SRC_INPUT" ]]; then
  echo "Source web build not found: $SRC_INPUT" >&2
  exit 1
fi

SRC="$(cd "$SRC_INPUT" && pwd -P)"
DST="${SCRIPT_DIR}/static/web_client"
STATIC_DIR="${SCRIPT_DIR}/static"

if [[ "$SRC" == "/" || "$SRC" == "$DST" ]]; then
  echo "Refusing unsafe web client source: $SRC" >&2
  exit 1
fi
if [[ -n "$(find "$SRC" -type l -print -quit)" ]]; then
  echo "Web client build must not contain symbolic links" >&2
  exit 1
fi

SOURCE_REVISION_FILE="${SRC}/.source_revision"
if [[ ! -f "$SOURCE_REVISION_FILE" ]]; then
  echo "Web client build is missing source provenance: $SOURCE_REVISION_FILE" >&2
  exit 1
fi
SOURCE_REVISION_RECORD="$(tr -d '\r\n' < "$SOURCE_REVISION_FILE")"
if [[ ! "$SOURCE_REVISION_RECORD" =~ ^([0-9a-f]{40,64})[[:space:]]clean$ ]]; then
  echo "Web client build does not come from a clean, revision-stamped source tree" >&2
  exit 1
fi
SOURCE_REVISION="${BASH_REMATCH[1]}"
if [[ "$SOURCE_REVISION" != "$LOCKED_REVISION" ]]; then
  echo "Web client revision does not match web-client.lock: expected $LOCKED_REVISION, got $SOURCE_REVISION" >&2
  exit 1
fi
if [[ -n "$EXPECTED_REVISION" && "$SOURCE_REVISION" != "$EXPECTED_REVISION" ]]; then
  echo "Web client provenance mismatch: expected $EXPECTED_REVISION, got $SOURCE_REVISION" >&2
  exit 1
fi

STAGING="$(mktemp -d "${STATIC_DIR}/.web-client-stage.XXXXXX")"
BACKUP=""

cleanup() {
  if [[ -n "$STAGING" && -d "$STAGING" ]]; then
    rm -rf -- "$STAGING"
  fi
  if [[ -n "$BACKUP" && -d "$BACKUP" ]]; then
    if [[ ! -e "$DST" ]]; then
      mv -- "$BACKUP" "$DST"
    else
      rm -rf -- "$BACKUP"
    fi
  fi
}
trap cleanup EXIT

cp -a -- "$SRC"/. "$STAGING"/

# Flutter copies everything under flutter/web into build/web. Only the compiled
# bridge belongs in a deployable artifact; source, package managers and build
# scripts needlessly expose internals and inflate the production image.
rm -rf -- \
  "$STAGING/README.md" \
  "$STAGING/tools" \
  "$STAGING/js/README.md" \
  "$STAGING/js/node_modules" \
  "$STAGING/js/src" \
  "$STAGING/js/tools" \
  "$STAGING/js/package.json" \
  "$STAGING/js/package-lock.json" \
  "$STAGING/js/tsconfig.json" \
  "$STAGING/js/vite.config.ts"

if [[ -f "$STAGING/assets/NOTICES" ]]; then
  sed -i 's/[[:blank:]]\+$//' "$STAGING/assets/NOTICES"
fi

# Flutter embeds flutter.js into the bootstrap but leaves a source-map comment
# even when release builds do not publish the map. WhiteNoise treats the
# dangling comment as a required static dependency, so remove it from both
# emitted copies.
for generated_js in flutter.js flutter_bootstrap.js; do
  if [[ -f "$STAGING/$generated_js" ]]; then
    sed -i '/^[[:blank:]]*\/\/[#@][[:blank:]]*sourceMappingURL=.*$/d' \
      "$STAGING/$generated_js"
  fi
done

required_files=(
  ".source_revision"
  "flutter_bootstrap.js"
  "main.dart.js"
  "manifest.json"
  "canvaskit/canvaskit.wasm"
  "js/dist/web_bridge.js"
)
for required_file in "${required_files[@]}"; do
  if [[ ! -f "$STAGING/$required_file" ]]; then
    echo "Incomplete web client build; missing $required_file" >&2
    exit 1
  fi
done

if [[ -d "$DST" ]]; then
  BACKUP="$(mktemp -d "${STATIC_DIR}/.web-client-backup.XXXXXX")"
  rmdir -- "$BACKUP"
  mv -- "$DST" "$BACKUP"
fi
mv -- "$STAGING" "$DST"
STAGING=""
if [[ -n "$BACKUP" ]]; then
  rm -rf -- "$BACKUP"
  BACKUP=""
fi

echo "Synced web client revision $SOURCE_REVISION to: $DST"
