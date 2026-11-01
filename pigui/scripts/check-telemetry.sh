#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/dev-env.sh"

cargo build -q -p pigui-cli
CLI="./target/debug/pigui-cli"

"$CLI" status

echo
echo "extractor file: $PIGUI_EXTRACTOR_JSON"
if [ -f "$PIGUI_EXTRACTOR_JSON" ]; then
  wc -c "$PIGUI_EXTRACTOR_JSON"
  wc -l "$PIGUI_EXTRACTOR_JSON"
else
  echo "missing"
fi

echo
"$CLI" dns --limit 10
echo
"$CLI" domains --limit 10
