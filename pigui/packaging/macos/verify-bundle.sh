#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${1:?usage: verify-bundle.sh <PIGUI.app>}"
CONTENTS="$APP_DIR/Contents"

fail() {
  echo "verify-bundle: $*" >&2
  exit 1
}

GUI_EXECUTABLE="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$CONTENTS/Info.plist")"
if [ -z "$GUI_EXECUTABLE" ]; then
  fail "Info.plist has no CFBundleExecutable"
fi

for path in \
  "$CONTENTS/MacOS/$GUI_EXECUTABLE" \
  "$CONTENTS/MacOS/pigui-daemon" \
  "$CONTENTS/MacOS/pigui-cli" \
  "$CONTENTS/MacOS/pigui-helper" \
  "$CONTENTS/MacOS/pigui-servicectl" \
  "$CONTENTS/MacOS/pigui-helperctl" \
  "$CONTENTS/MacOS/snort" \
  "$CONTENTS/Resources/snort/etc/snort.lua" \
  "$CONTENTS/Resources/snort/payload-id.txt" \
  "$CONTENTS/Library/LaunchAgents/com.pigui.daemon.plist" \
  "$CONTENTS/Library/LaunchDaemons/com.pigui.helper.plist"
do
  [ -e "$path" ] || fail "missing $path"
done

echo "checking helper version"
BUNDLE_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$CONTENTS/Info.plist")"
HELPER_VERSION="$("$CONTENTS/MacOS/pigui-helper" --version)"
[ "$HELPER_VERSION" = "$BUNDLE_VERSION" ] \
  || fail "helper reports version $HELPER_VERSION, expected $BUNDLE_VERSION"

echo "checking Mach-O dependencies"
while IFS= read -r -d '' binary; do
  while IFS= read -r dependency; do
    case "$dependency" in
      /System/Library/*|/usr/lib/*|/Library/Apple/*|@rpath/*)
        ;;
      *)
        fail "$binary references non-bundled dependency: $dependency"
        ;;
    esac
  done < <(otool -L "$binary" | tail -n +2 | sed 's/^[[:space:]]*//' | sed 's/ (compatibility version.*//')
done < <(find "$CONTENTS/MacOS" "$CONTENTS/Frameworks" -type f -print0 2>/dev/null)

echo "checking bundled Snort"
grep -q "PIGUI Snort overrides" "$CONTENTS/Resources/snort/etc/snort.lua" \
  || fail "Snort config is missing PIGUI overrides"
"$CONTENTS/MacOS/snort" -V >/dev/null
"$CONTENTS/MacOS/snort" -c "$CONTENTS/Resources/snort/etc/snort.lua" -T >/dev/null

if codesign -dv "$APP_DIR" >/dev/null 2>&1; then
  echo "checking app signature"
  codesign --verify --deep --strict --verbose=2 "$APP_DIR"
else
  echo "app is not signed yet"
fi

echo "bundle verification passed"
