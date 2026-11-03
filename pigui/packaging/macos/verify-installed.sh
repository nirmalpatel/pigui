#!/usr/bin/env bash
set -u

APP="${1:-/Applications/PIGUI.app}"
CONTENTS="$APP/Contents"
STATE="$HOME/Library/Application Support/PIGUI"

if [ ! -d "$APP" ]; then
  echo "PIGUI.app not found at $APP" >&2
  exit 1
fi

echo "== App =="
echo "path: $APP"
APP_VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$CONTENTS/Info.plist" 2>/dev/null)"
echo "version: ${APP_VERSION:-unknown}"

echo
echo "== Helper =="
HELPER_JSON="$("$CONTENTS/MacOS/pigui-helperctl" version 2>&1 || true)"
HELPER_VERSION="$(printf '%s' "$HELPER_JSON" \
  | python3 -c 'import json,sys; print((json.load(sys.stdin).get("data") or {}).get("version", ""))' 2>/dev/null || true)"
if [ -z "$HELPER_VERSION" ]; then
  echo "version: unavailable"
  echo "helper may not be registered; run pigui-servicectl status"
elif [ "$HELPER_VERSION" = "$APP_VERSION" ]; then
  echo "version: $HELPER_VERSION (matches app)"
else
  echo "version: $HELPER_VERSION (MISMATCH: app is $APP_VERSION)"
  echo "Re-register the helper so launchd loads the installed version."
  exit 1
fi

echo
echo "== Code signature =="
codesign --verify --deep --strict --verbose=2 "$APP" 2>&1 | tail -n 5
codesign -dv --verbose=4 "$APP" 2>&1 \
  | grep -E 'Identifier|Authority|TeamIdentifier|Runtime|Sealed' \
  | sed -n '1,12p'

echo
echo "== Notarization ticket =="
xcrun stapler validate "$APP" 2>&1 | sed -n '1,6p'
spctl -a -vvv -t exec "$APP" 2>&1 | sed -n '1,6p'

echo
echo "== SMAppService =="
"$CONTENTS/MacOS/pigui-servicectl" status 2>&1

echo
echo "== launchd helper =="
launchctl print system/com.pigui.helper 2>&1 | sed -n '1,45p'

echo
echo "== launchd agent =="
launchctl print "gui/$(id -u)/com.pigui.daemon" 2>&1 | sed -n '1,25p'

echo
echo "== Processes =="
pgrep -fl 'PIGUI.app/Contents/MacOS|pigui-helper|snort' || true

echo
echo "== Daemon log =="
tail -n 20 "$STATE/var/log/daemon.log" 2>/dev/null || echo "no daemon log"

echo
echo "== Audit log =="
if [ -r /Library/Logs/PIGUI/audit.log ]; then
  tail -n 20 /Library/Logs/PIGUI/audit.log
else
  echo "not readable without root: /Library/Logs/PIGUI/audit.log"
fi
