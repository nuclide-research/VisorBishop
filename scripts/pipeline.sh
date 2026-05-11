#!/bin/bash
# VisorBishop pipeline: raw sweep JSON → cross-platform corpus → VisorLog
# ledger → refreshed dashboard JSON.
#
# Each stage of the pipeline is a separate script in this directory.
# This wrapper orchestrates them with the right env vars.
#
# Usage:
#   ./pipeline.sh                  # rebuild corpus + ingest + refresh
#   ./pipeline.sh --rebuild        # + run a downstream `build` command
#   ./pipeline.sh --rebuild --push # + commit + push (caller-defined)
#
# Configuration (env vars; all have sensible defaults for an operator
# who set up VisorBishop alongside VisorLog in the same parent dir):
#   VB_CORPUS_FILE       — corpus config JSON                (default: ./corpus.json)
#   VB_OUTPUT_PATH       — cross-platform JSON destination   (default: ./cross-platform.json)
#   VB_PUBLIC_PATH       — optional second copy              (default: unset)
#   VB_VISORLOG_BIN      — visorlog binary                   (default: visorlog on PATH)
#   VB_VISORLOG_DB       — VisorLog SQLite DB                (default: ./visorlog.db)
#   VB_BUILD_CMD         — command to run when --rebuild     (default: unset; e.g. "npm run build")
#   VB_BUILD_DIR         — directory to run VB_BUILD_CMD in  (default: cwd)
#   VB_PUSH_CMD          — command to run when --push        (default: "git push origin main")
#
# Idempotent: running twice in a row produces no changes
# (VisorLog ingest --dedup is keyed on (source, notes), which contains
# the platform + target URL).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Defaults
: "${VB_CORPUS_FILE:=$SCRIPT_DIR/corpus.json}"
: "${VB_OUTPUT_PATH:=$(pwd)/cross-platform.json}"
: "${VB_VISORLOG_BIN:=visorlog}"
: "${VB_VISORLOG_DB:=$(pwd)/visorlog.db}"
: "${VB_PUSH_CMD:=git push origin main}"

export VB_CORPUS_FILE VB_OUTPUT_PATH VB_VISORLOG_BIN VB_VISORLOG_DB

REBUILD=0
PUSH=0
for arg in "$@"; do
  case "$arg" in
    --rebuild) REBUILD=1 ;;
    --push) PUSH=1 ;;
    -h|--help)
      sed -n '2,/^set/p' "$0" | sed 's/^# \{0,1\}//' | head -n -1
      exit 0
      ;;
    *) echo "unknown flag: $arg" >&2; exit 1 ;;
  esac
done

echo "=== [1/3] Build cross-platform corpus ==="
python3 "$SCRIPT_DIR/build_cross_platform_corpus.py"

echo ""
echo "=== [2/3] Ingest into VisorLog (dedup mode) ==="
VB_CORPUS_OUTPUT="$VB_OUTPUT_PATH" python3 "$SCRIPT_DIR/visorbishop_to_visorlog.py" 2>/dev/null \
  | "$VB_VISORLOG_BIN" --db "$VB_VISORLOG_DB" ingest --dedup

echo ""
echo "=== [3/3] Refresh dashboard JSON from VisorLog ledger ==="
python3 "$SCRIPT_DIR/refresh_dashboard_from_visorlog.py"

if [[ "$REBUILD" -eq 1 ]]; then
  if [[ -z "${VB_BUILD_CMD:-}" ]]; then
    echo ""
    echo "(skipped: --rebuild requested but VB_BUILD_CMD is not set)"
  else
    echo ""
    echo "=== Build: $VB_BUILD_CMD ==="
    if [[ -n "${VB_BUILD_DIR:-}" ]]; then
      ( cd "$VB_BUILD_DIR" && eval "$VB_BUILD_CMD" )
    else
      eval "$VB_BUILD_CMD"
    fi
  fi
fi

if [[ "$PUSH" -eq 1 ]]; then
  echo ""
  echo "=== Push: $VB_PUSH_CMD ==="
  eval "$VB_PUSH_CMD"
fi

echo ""
echo "=== Pipeline complete ==="
