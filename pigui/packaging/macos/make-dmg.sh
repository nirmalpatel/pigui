#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIGUI_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

APP_DIR="${1:?usage: make-dmg.sh <PIGUI.app> [version]}"
APP_DIR="$(cd "$(dirname "$APP_DIR")" && pwd)/$(basename "$APP_DIR")"
VERSION="${2:-$(awk -F'"' '/^version = / { print $2; exit }' "$PIGUI_ROOT/Cargo.toml")}"
ARCH="${PIGUI_TARGET_ARCH:-$(uname -m)}"
BUILD_DIR="${PIGUI_BUILD_DIR:-$PIGUI_ROOT/target/macos}"
DMG="${PIGUI_DMG_PATH:-$BUILD_DIR/PIGUI-$VERSION-macos-$ARCH.dmg}"
VOLUME_NAME="${PIGUI_DMG_VOLNAME:-PIGUI}"
IDENTITY="${PIGUI_SIGN_IDENTITY:-}"
NOTARY_PROFILE="${PIGUI_NOTARY_PROFILE:-}"
NOTARIZE="${PIGUI_NOTARIZE:-0}"

if [ ! -d "$APP_DIR" ]; then
  echo "app bundle not found: $APP_DIR" >&2
  exit 1
fi
if [ ! -f "$APP_DIR/Contents/Info.plist" ]; then
  echo "not an app bundle: $APP_DIR" >&2
  exit 1
fi
if [ "$NOTARIZE" = "1" ] && [ -z "$NOTARY_PROFILE" ]; then
  echo "PIGUI_NOTARY_PROFILE is required for notarization" >&2
  exit 1
fi

if [ -n "$IDENTITY" ]; then
  SIGN_ARGS=(--force --timestamp --sign "$IDENTITY")
else
  echo "warning: PIGUI_SIGN_IDENTITY is not set; ad-hoc signing the DMG" >&2
  SIGN_ARGS=(--force --sign -)
fi

mkdir -p "$BUILD_DIR"
STAGE="$(mktemp -d "$BUILD_DIR/dmg.XXXXXX")"
cleanup() {
  rm -rf "$STAGE"
}
trap cleanup EXIT

echo "staging DMG contents"
ditto "$APP_DIR" "$STAGE/PIGUI.app"
ln -s /Applications "$STAGE/Applications"

if [ -f "$APP_DIR/Contents/Resources/icon.icns" ] && command -v SetFile >/dev/null 2>&1; then
  cp "$APP_DIR/Contents/Resources/icon.icns" "$STAGE/.VolumeIcon.icns"
  SetFile -a C "$STAGE" || true
fi

echo "creating $DMG"
rm -f "$DMG"
hdiutil create -volname "$VOLUME_NAME" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
codesign "${SIGN_ARGS[@]}" "$DMG"

if [ "$NOTARIZE" = "1" ]; then
  echo "submitting DMG for notarization"
  xcrun notarytool submit "$DMG" --keychain-profile "$NOTARY_PROFILE" --wait

  echo "stapling DMG"
  for attempt in 1 2 3; do
    if xcrun stapler staple "$DMG"; then
      break
    fi
    if [ "$attempt" = "3" ]; then
      echo "stapler failed after 3 attempts for $DMG" >&2
      exit 1
    fi
    echo "stapler failed; retrying in 10s" >&2
    sleep 10
  done
  xcrun stapler validate "$DMG"
  spctl -a -vvv -t install "$DMG"
fi

echo "DMG ready: $DMG"
shasum -a 256 "$DMG"
