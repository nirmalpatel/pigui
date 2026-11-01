#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/dev-env.sh"

export PIGUI_MODE=live
export PIGUI_DB_PATH="${PIGUI_LIVE_DB_PATH:-./var/lib/pigui-live.db}"
export PIGUI_ALERT_JSON="${PIGUI_SNORT_LOG_DIR:-./var/log/snort}/alert_json.txt"
export PIGUI_EXTRACTOR_JSON="${PIGUI_SNORT_LOG_DIR:-./var/log/snort}/file_connector_pigui_transmit"

if [ -S "$PIGUI_SOCKET" ]; then
  echo "stopping existing pigui-daemon on $PIGUI_SOCKET"
  "$SCRIPT_DIR/stop-live.sh" || true
  sleep 0.5
fi

echo "requesting sudo credentials for live capture..."
sudo -v

"$SCRIPT_DIR/snort-live.sh" &
SNORT_WRAPPER_PID=$!
SNORT_PID=""
DAEMON_PID=""

read_snort_pid() {
  cat "$PIGUI_SNORT_PIDFILE" 2>/dev/null \
    || sudo cat "$PIGUI_SNORT_PIDFILE" 2>/dev/null \
    || true
}

cleanup() {
  if [ -n "$DAEMON_PID" ]; then
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  if [ -f "$PIGUI_SNORT_PIDFILE" ]; then
    SNORT_PID="$(read_snort_pid)"
    if [ -n "$SNORT_PID" ]; then
      sudo kill "$SNORT_PID" 2>/dev/null || true
    fi
  fi
  kill -TERM "$SNORT_WRAPPER_PID" 2>/dev/null || true
  wait "$SNORT_WRAPPER_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for _ in $(seq 1 100); do
  [ -f "$PIGUI_SNORT_PIDFILE" ] && break
  sleep 0.1
done
if [ ! -f "$PIGUI_SNORT_PIDFILE" ]; then
  echo "Snort PID file did not appear at $PIGUI_SNORT_PIDFILE" >&2
  exit 1
fi

# Snort creates the PID file before dropping privileges, so it can be
# root-owned even when capture runs as the current user.
sudo chown "$(id -u):$(id -g)" "$PIGUI_SNORT_PIDFILE" 2>/dev/null || true
sudo chmod 0644 "$PIGUI_SNORT_PIDFILE" 2>/dev/null || true
sudo find "$PIGUI_SNORT_LOG_DIR" -maxdepth 1 -type f -exec chmod a+r {} + 2>/dev/null || true

SNORT_PID="$(read_snort_pid)"
if [ -z "$SNORT_PID" ] || ! sudo kill -0 "$SNORT_PID" 2>/dev/null; then
  echo "Snort failed to start; check $PIGUI_SNORT_LOG_DIR" >&2
  exit 1
fi

cargo build -p pigui-daemon
./target/debug/pigui-daemon > var/log/live-daemon.log 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 100); do
  [ -S "$PIGUI_SOCKET" ] && break
  sleep 0.1
done
if [ ! -S "$PIGUI_SOCKET" ]; then
  echo "pigui-daemon socket did not appear at $PIGUI_SOCKET" >&2
  exit 1
fi

echo "live capture ready: snort=$SNORT_PID daemon=$DAEMON_PID"
(
  cd apps/pigui-gui
  npm install --silent
  npm run tauri dev
)
