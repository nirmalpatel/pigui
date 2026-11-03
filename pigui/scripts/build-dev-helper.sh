#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIGUI_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${PIGUI_DEV_HELPER_DIR:-$PIGUI_ROOT/target/debug}"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "dev helper is only available on macOS" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

xcrun swiftc \
  -O \
  -parse-as-library \
  -swift-version 5 \
  -target arm64-apple-macos14.0 \
  -framework Foundation \
  -framework Security \
  -framework SystemConfiguration \
  -o "$OUT_DIR/pigui-helper" \
  "$PIGUI_ROOT/packaging/macos/helper/PiguiHelper.swift"

xcrun swiftc \
  -O \
  -parse-as-library \
  -swift-version 5 \
  -target arm64-apple-macos14.0 \
  -framework Foundation \
  -o "$OUT_DIR/pigui-helperctl" \
  "$PIGUI_ROOT/packaging/macos/helper/PiguiHelperCtl.swift"

chmod 0755 "$OUT_DIR/pigui-helper" "$OUT_DIR/pigui-helperctl"
echo "dev helper ready: $OUT_DIR/pigui-helper"
