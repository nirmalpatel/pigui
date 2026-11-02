#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIGUI_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="${1:-$(awk -F'"' '/^version = / { print $2; exit }' "$PIGUI_ROOT/Cargo.toml")}"
ARCH="${PIGUI_TARGET_ARCH:-$(uname -m)}"
RELEASE_DIR="${PIGUI_RELEASE_DIR:-$PIGUI_ROOT/packaging/releases/v$VERSION}"
APP_DIR="${PIGUI_APP_DIR:-$PIGUI_ROOT/target/macos/PIGUI.app}"
DMG="${PIGUI_DMG_PATH:-$PIGUI_ROOT/target/macos/PIGUI-$VERSION-macos-$ARCH.dmg}"
CHECKSUMS="$RELEASE_DIR/SHA256SUMS"
MANIFEST="$RELEASE_DIR/manifest.json"

fail() {
  echo "check-release: $*" >&2
  exit 1
}

echo "checking version consistency"
cargo_version="$(awk -F'"' '/^version = / { print $2; exit }' "$PIGUI_ROOT/Cargo.toml")"
tauri_version="$(awk -F'"' '/"version"/ { print $4; exit }' "$PIGUI_ROOT/apps/pigui-gui/src-tauri/tauri.conf.json")"
package_version="$(awk -F'"' '/"version"/ { print $4; exit }' "$PIGUI_ROOT/apps/pigui-gui/package.json")"
gui_cargo_version="$(awk -F'"' '/^version = / { print $2; exit }' "$PIGUI_ROOT/apps/pigui-gui/src-tauri/Cargo.toml")"

for name_value in \
  "Cargo.toml:$cargo_version" \
  "tauri.conf.json:$tauri_version" \
  "package.json:$package_version" \
  "pigui-gui Cargo.toml:$gui_cargo_version"
do
  name="${name_value%%:*}"
  value="${name_value#*:}"
  [ "$value" = "$VERSION" ] || fail "$name is $value, expected $VERSION"
done
echo "  $VERSION"

echo "checking release files"
for path in "$APP_DIR" "$DMG" "$CHECKSUMS" "$MANIFEST" "$RELEASE_DIR/notes.md"; do
  [ -e "$path" ] || fail "missing $path"
done

echo "checking DMG checksum"
expected_sha="$(awk -v file="$(basename "$DMG")" '$2 == file { print $1; exit }' "$CHECKSUMS")"
[ -n "$expected_sha" ] || fail "$CHECKSUMS has no entry for $(basename "$DMG")"
actual_sha="$(shasum -a 256 "$DMG" | awk '{ print $1 }')"
[ "$actual_sha" = "$expected_sha" ] || fail "DMG checksum mismatch"
manifest_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["artifacts"][0]["sha256"])' "$MANIFEST")"
[ "$manifest_sha" = "$actual_sha" ] || fail "manifest checksum mismatch"
echo "  $actual_sha"

echo "checking app bundle"
"$SCRIPT_DIR/macos/verify-bundle.sh" "$APP_DIR"

echo "checking notarization and Gatekeeper"
xcrun stapler validate "$APP_DIR"
xcrun stapler validate "$DMG"
spctl -a -vvv -t exec "$APP_DIR"
spctl -a -vvv -t install "$DMG"

echo "checking DMG layout"
MOUNT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pigui-mount.XXXXXX")"
cleanup() {
  hdiutil detach "$MOUNT_DIR" >/dev/null 2>&1 || true
  rmdir "$MOUNT_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT
hdiutil attach -readonly -nobrowse -mountpoint "$MOUNT_DIR" "$DMG" >/dev/null
[ -d "$MOUNT_DIR/PIGUI.app" ] || fail "DMG is missing PIGUI.app"
[ -L "$MOUNT_DIR/Applications" ] || fail "DMG is missing the Applications shortcut"
[ "$(readlink "$MOUNT_DIR/Applications")" = "/Applications" ] || fail "Applications shortcut has the wrong target"

echo "release check passed: $VERSION ($ARCH)"
