#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIGUI_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

BUILD_DIR="${PIGUI_BUILD_DIR:-$PIGUI_ROOT/target/macos}"
APP_DIR="$BUILD_DIR/PIGUI.app"
VERSION="$(awk -F'"' '/^version = / { print $2; exit }' "$PIGUI_ROOT/Cargo.toml")"
TEAM_ID="${PIGUI_TEAM_ID:-}"

resolve_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s\n' "$PIGUI_ROOT/$1" ;;
  esac
}

SNORT_BIN="$(resolve_path "${PIGUI_SNORT_BIN:-../build/src/snort}")"
SNORT_LUA="$(resolve_path "${PIGUI_SNORT_LUA_PATH:-../lua}")"
PIGUI_SNORT_CONFIG="$PIGUI_ROOT/config/snort/pigui.lua"

if [ ! -x "$SNORT_BIN" ]; then
  echo "Snort binary not found: $SNORT_BIN" >&2
  exit 1
fi
if [ ! -d "$SNORT_LUA" ]; then
  echo "Snort Lua tree not found: $SNORT_LUA" >&2
  exit 1
fi

echo "building PIGUI Rust binaries"
cargo build --release -p pigui-daemon -p pigui-cli --manifest-path "$PIGUI_ROOT/Cargo.toml"

TAURI_APP="$PIGUI_ROOT/apps/pigui-gui/src-tauri/target/release/bundle/macos/PIGUI.app"
if [ "${PIGUI_SKIP_GUI:-0}" = "1" ]; then
  if [ ! -d "$TAURI_APP" ]; then
    echo "PIGUI_SKIP_GUI=1 but no Tauri app exists at $TAURI_APP" >&2
    exit 1
  fi
else
  echo "building PIGUI Tauri app"
  (
    cd "$PIGUI_ROOT/apps/pigui-gui"
    npm run tauri build -- --bundles app
  )
fi

rm -rf "$APP_DIR"
mkdir -p "$BUILD_DIR"
cp -R "$TAURI_APP" "$APP_DIR"

echo "assembling app binaries"
install -m 0755 "$PIGUI_ROOT/target/release/pigui-daemon" "$APP_DIR/Contents/MacOS/pigui-daemon"
install -m 0755 "$PIGUI_ROOT/target/release/pigui-cli" "$APP_DIR/Contents/MacOS/pigui-cli"
"$SCRIPT_DIR/build-helper.sh" "$APP_DIR"
xcrun swiftc \
  -O \
  -parse-as-library \
  -swift-version 5 \
  -target arm64-apple-macos14.0 \
  -framework Foundation \
  -framework ServiceManagement \
  -o "$APP_DIR/Contents/MacOS/pigui-servicectl" \
  "$SCRIPT_DIR/service/PiguiServiceCtl.swift"
chmod 0755 "$APP_DIR/Contents/MacOS/pigui-servicectl"
xcrun swiftc \
  -O \
  -parse-as-library \
  -swift-version 5 \
  -target arm64-apple-macos14.0 \
  -framework Foundation \
  -o "$APP_DIR/Contents/MacOS/pigui-helperctl" \
  "$SCRIPT_DIR/helper/PiguiHelperCtl.swift"
chmod 0755 "$APP_DIR/Contents/MacOS/pigui-helperctl"

echo "bundling Snort and dependencies"
python3 "$SCRIPT_DIR/bundle_snort.py" \
  "$SNORT_BIN" \
  "$SNORT_LUA" \
  "$PIGUI_SNORT_CONFIG" \
  "$APP_DIR"

mkdir -p "$APP_DIR/Contents/Library/LaunchAgents" "$APP_DIR/Contents/Library/LaunchDaemons"
install -m 0644 "$SCRIPT_DIR/launchd/com.pigui.daemon.plist" \
  "$APP_DIR/Contents/Library/LaunchAgents/com.pigui.daemon.plist"
install -m 0644 "$SCRIPT_DIR/launchd/com.pigui.helper.plist" \
  "$APP_DIR/Contents/Library/LaunchDaemons/com.pigui.helper.plist"

INFO="$APP_DIR/Contents/Info.plist"
plist_set_string() {
  /usr/libexec/PlistBuddy -c "Set :$1 $2" "$INFO" 2>/dev/null \
    || /usr/libexec/PlistBuddy -c "Add :$1 string $2" "$INFO"
}
plist_set_bool() {
  /usr/libexec/PlistBuddy -c "Set :$1 $2" "$INFO" 2>/dev/null \
    || /usr/libexec/PlistBuddy -c "Add :$1 bool $2" "$INFO"
}

plist_set_string "LSMinimumSystemVersion" "14.0"
plist_set_string "CFBundleDisplayName" "PIGUI"
plist_set_string "CFBundleShortVersionString" "$VERSION"
plist_set_string "CFBundleVersion" "$VERSION"
plist_set_bool "NSHighResolutionCapable" "true"

if [ -n "$TEAM_ID" ]; then
  plist_set_string "PIGUIAppRequirement" \
    "anchor apple generic and certificate leaf[subject.OU] = \"$TEAM_ID\" and identifier \"com.pigui.app\""
  plist_set_string "PIGUIHelperClientRequirement" \
    "anchor apple generic and certificate leaf[subject.OU] = \"$TEAM_ID\" and (identifier \"com.pigui.daemon\" or identifier \"com.pigui.helperctl\")"
  plist_set_string "PIGUIHelperRequirement" \
    "anchor apple generic and certificate leaf[subject.OU] = \"$TEAM_ID\" and identifier \"com.pigui.helper\""
else
  plist_set_string "PIGUIAppRequirement" "identifier \"com.pigui.app\""
  plist_set_string "PIGUIHelperClientRequirement" \
    "identifier \"com.pigui.daemon\" or identifier \"com.pigui.helperctl\""
  plist_set_string "PIGUIHelperRequirement" "identifier \"com.pigui.helper\""
fi

if [ -z "${PIGUI_SIGN_IDENTITY:-}" ]; then
  echo "ad-hoc signing for local verification"
  find "$APP_DIR/Contents/Frameworks" -type f -name '*.dylib' -print0 2>/dev/null |
    while IFS= read -r -d '' library; do
      codesign --force --sign - "$library" >/dev/null 2>&1 || true
    done
  GUI_EXECUTABLE="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP_DIR/Contents/Info.plist")"
  codesign --force --sign - --identifier "com.pigui.app" "$APP_DIR/Contents/MacOS/$GUI_EXECUTABLE" >/dev/null 2>&1 || true
  codesign --force --sign - --identifier "com.pigui.daemon" "$APP_DIR/Contents/MacOS/pigui-daemon" >/dev/null 2>&1 || true
  codesign --force --sign - --identifier "com.pigui.cli" "$APP_DIR/Contents/MacOS/pigui-cli" >/dev/null 2>&1 || true
  codesign --force --sign - --identifier "com.pigui.helper" "$APP_DIR/Contents/MacOS/pigui-helper" >/dev/null 2>&1 || true
  codesign --force --sign - --identifier "com.pigui.servicectl" "$APP_DIR/Contents/MacOS/pigui-servicectl" >/dev/null 2>&1 || true
  codesign --force --sign - --identifier "com.pigui.helperctl" "$APP_DIR/Contents/MacOS/pigui-helperctl" >/dev/null 2>&1 || true
  codesign --force --sign - --identifier "com.pigui.snort" "$APP_DIR/Contents/MacOS/snort" >/dev/null 2>&1 || true
  codesign --force --sign - --identifier "com.pigui.app" "$APP_DIR" >/dev/null 2>&1 || true
  "$SCRIPT_DIR/verify-bundle.sh" "$APP_DIR"
else
  PIGUI_SIGN_IDENTITY="$PIGUI_SIGN_IDENTITY" \
  PIGUI_TEAM_ID="$TEAM_ID" \
  PIGUI_NOTARY_PROFILE="${PIGUI_NOTARY_PROFILE:-}" \
  PIGUI_NOTARIZE="${PIGUI_NOTARIZE:-0}" \
    "$SCRIPT_DIR/sign-and-notarize.sh" "$APP_DIR" "$VERSION"
  "$SCRIPT_DIR/verify-bundle.sh" "$APP_DIR"
fi

echo "app ready: $APP_DIR"
