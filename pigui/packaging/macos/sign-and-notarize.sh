#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${1:?usage: sign-and-notarize.sh <PIGUI.app> [version]}"
VERSION="${2:-0.1.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IDENTITY="${PIGUI_SIGN_IDENTITY:?PIGUI_SIGN_IDENTITY is required}"
TEAM_ID="${PIGUI_TEAM_ID:-}"
NOTARY_PROFILE="${PIGUI_NOTARY_PROFILE:-}"
NOTARIZE="${PIGUI_NOTARIZE:-0}"
CONTENTS="$APP_DIR/Contents"
DMG="${APP_DIR%/*}/PIGUI-$VERSION.dmg"
ZIP="${APP_DIR%/*}/PIGUI-$VERSION.zip"

sign() {
  local path="$1"
  shift
  codesign --force --options runtime --timestamp --sign "$IDENTITY" "$@" "$path"
}

echo "signing bundled dylibs"
find "$CONTENTS/Frameworks" -type f -name '*.dylib' -print0 2>/dev/null |
  while IFS= read -r -d '' library; do
    sign "$library"
  done

GUI_EXECUTABLE="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$CONTENTS/Info.plist")"

echo "signing executables"
sign "$CONTENTS/MacOS/$GUI_EXECUTABLE" --identifier "com.pigui.app"
sign "$CONTENTS/MacOS/snort" \
  --identifier "com.pigui.snort" \
  --entitlements "$SCRIPT_DIR/entitlements/snort.entitlements"
sign "$CONTENTS/MacOS/pigui-daemon" --identifier "com.pigui.daemon"
sign "$CONTENTS/MacOS/pigui-cli" --identifier "com.pigui.cli"
sign "$CONTENTS/MacOS/pigui-servicectl" --identifier "com.pigui.servicectl"
sign "$CONTENTS/MacOS/pigui-helperctl" --identifier "com.pigui.helperctl"
sign "$CONTENTS/MacOS/pigui-helper" --identifier "com.pigui.helper"

echo "signing app"
sign "$APP_DIR" \
  --identifier "com.pigui.app" \
  --entitlements "$SCRIPT_DIR/entitlements/main.entitlements"

codesign --verify --deep --strict --verbose=2 "$APP_DIR"

notarize_and_staple() {
  local submit_path="$1"
  local staple_path="$2"
  local label="$3"

  echo "submitting $label for notarization"
  xcrun notarytool submit "$submit_path" --keychain-profile "$NOTARY_PROFILE" --wait

  echo "stapling $label"
  for attempt in 1 2 3; do
    if xcrun stapler staple "$staple_path"; then
      break
    fi
    if [ "$attempt" = "3" ]; then
      echo "stapler failed after 3 attempts for $label" >&2
      exit 1
    fi
    echo "stapler failed for $label; retrying in 10s" >&2
    sleep 10
  done
  xcrun stapler validate "$staple_path"
}

if [ "$NOTARIZE" = "1" ]; then
  if [ -z "$NOTARY_PROFILE" ]; then
    echo "PIGUI_NOTARY_PROFILE is required for notarization" >&2
    exit 1
  fi

  # The LaunchDaemon helper requires the app itself to be notarized and
  # stapled, not only the enclosing DMG. Submit an app archive first, then
  # staple the app bundle before building the DMG.
  rm -f "$ZIP"
  ditto -c -k --keepParent "$APP_DIR" "$ZIP"
  notarize_and_staple "$ZIP" "$APP_DIR" "app"
  spctl -a -vvv -t exec "$APP_DIR"
fi

echo "creating DMG"
rm -f "$DMG"
hdiutil create -volname "PIGUI" -srcfolder "$APP_DIR" -ov -format UDZO "$DMG" >/dev/null
codesign --force --timestamp --sign "$IDENTITY" "$DMG"

if [ "$NOTARIZE" = "1" ]; then
  notarize_and_staple "$DMG" "$DMG" "DMG"
  spctl -a -vvv -t install "$DMG"
fi

if [ -n "$TEAM_ID" ]; then
  echo "signed with team $TEAM_ID"
fi
echo "release artifact: $DMG"
