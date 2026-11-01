#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/dev-env.sh"

ALERTS_FILE="${PIGUI_FIXTURE_ALERT_JSON:-./tests/fixtures/alert_json/valid.jsonl}"

cargo build -p pigui-daemon
./target/debug/pigui-daemon --alerts-file "$ALERTS_FILE" &
DAEMON_PID=$!

cleanup() {
  kill -TERM "$DAEMON_PID" 2>/dev/null || true
  wait "$DAEMON_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for _ in $(seq 1 100); do
  [ -S "$PIGUI_SOCKET" ] && break
  sleep 0.1
done

if [ ! -S "$PIGUI_SOCKET" ]; then
  echo "pigui-daemon socket did not appear at $PIGUI_SOCKET" >&2
  exit 1
fi

echo "pigui-daemon ready at $PIGUI_SOCKET"
(
  cd apps/pigui-gui
  npm install --silent
  npm run tauri dev
)
