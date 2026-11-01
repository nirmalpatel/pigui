#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${1:?usage: build-helper.sh <PIGUI.app>}"

if [ "$(uname -m)" != "arm64" ]; then
  echo "this packaging target is arm64-only" >&2
  exit 1
fi

mkdir -p "$APP_DIR/Contents/MacOS"

xcrun swiftc \
  -O \
  -parse-as-library \
  -swift-version 5 \
  -target arm64-apple-macos14.0 \
  -framework Foundation \
  -framework Security \
  -framework SystemConfiguration \
  -o "$APP_DIR/Contents/MacOS/pigui-helper" \
  "$SCRIPT_DIR/helper/PiguiHelper.swift"

chmod 0755 "$APP_DIR/Contents/MacOS/pigui-helper"
