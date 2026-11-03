#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIGUI_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
APP="${1:-/Applications/PIGUI.app}"
ACTION="${2:-status}"

if [ ! -d "$APP" ]; then
  echo "PIGUI.app not found at $APP" >&2
  exit 1
fi

echo "== Installed bundle checks =="
"$PIGUI_ROOT/packaging/macos/verify-installed.sh" "$APP"

echo
echo "== SMAppService registration =="
"$APP/Contents/MacOS/pigui-servicectl" status

if [ "$ACTION" = "capture" ]; then
  IFACE="${PIGUI_SNORT_INTERFACE:-en0}"
  echo
  echo "== Starting capture through packaged helper on $IFACE =="
  "$APP/Contents/MacOS/pigui-helperctl" enable-capture "$IFACE"
elif [ "$ACTION" = "stop-capture" ]; then
  echo
  echo "== Stopping capture through packaged helper =="
  "$APP/Contents/MacOS/pigui-helperctl" disable-capture
elif [ "$ACTION" != "status" ]; then
  echo "usage: $0 [PIGUI.app] [status|capture|stop-capture]" >&2
  exit 2
fi

echo
echo "== Runtime parity =="
PIGUI_HOME="$HOME/Library/Application Support/PIGUI" \
PIGUI_SOCKET="$HOME/Library/Application Support/PIGUI/var/run/pigui-daemon.sock" \
  "$SCRIPT_DIR/parity-check.sh"
