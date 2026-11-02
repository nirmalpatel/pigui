#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/dev-env.sh"

# The dev app always consumes live Snort output.
export PIGUI_ALERT_JSON="$PIGUI_SNORT_LOG_DIR/alert_json.txt"
export PIGUI_EXTRACTOR_JSON="$PIGUI_SNORT_LOG_DIR/file_connector_pigui_transmit"

SNORT_WRAPPER_PID=""
DAEMON_PID=""

read_snort_pid() {
  cat "$PIGUI_SNORT_PIDFILE" 2>/dev/null \
    || sudo cat "$PIGUI_SNORT_PIDFILE" 2>/dev/null \
    || true
}

stop_daemon() {
  if [ -S "$PIGUI_SOCKET" ]; then
    echo "stopping pigui-daemon"
    python3 - "$PIGUI_SOCKET" <<'PY' || true
import json
import socket
import sys

path = sys.argv[1]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(path)
sock.sendall(json.dumps({"id": 1, "method": "shutdown", "params": {}}).encode() + b"\n")
sock.recv(4096)
sock.close()
PY
  fi
  rm -f "$PIGUI_SOCKET" 2>/dev/null || true
}

stop_snort() {
  if [ -f "$PIGUI_SNORT_PIDFILE" ]; then
    SNORT_PID="$(read_snort_pid)"
    if [ -n "$SNORT_PID" ]; then
      echo "stopping Snort pid $SNORT_PID"
      sudo kill "$SNORT_PID" 2>/dev/null || true
    fi
    sudo rm -f "$PIGUI_SNORT_PIDFILE" 2>/dev/null || rm -f "$PIGUI_SNORT_PIDFILE" 2>/dev/null || true
  fi
}

stop_all() {
  stop_daemon
  stop_snort
}

cleanup() {
  trap - EXIT
  set +e
  if [ -n "$DAEMON_PID" ]; then
    kill -TERM "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
  fi
  stop_snort
  if [ -n "$SNORT_WRAPPER_PID" ]; then
    kill -TERM "$SNORT_WRAPPER_PID" 2>/dev/null
    wait "$SNORT_WRAPPER_PID" 2>/dev/null
  fi
}

case "${1:-}" in
  --stop)
    stop_all
    exit 0
    ;;
  "")
    ;;
  *)
    echo "usage: $0 [--stop]" >&2
    exit 2
    ;;
esac

stop_all

echo "requesting sudo credentials for live capture..."
sudo -v

IFACE="${PIGUI_SNORT_INTERFACE:-}"
if [ -z "$IFACE" ]; then
  IFACE="$(route -n get default 2>/dev/null | sed -n 's/^ *interface: *//p' | head -1)"
fi
if [ -z "$IFACE" ]; then
  echo "could not determine capture interface; set PIGUI_SNORT_INTERFACE" >&2
  exit 1
fi
export PIGUI_SNORT_INTERFACE="$IFACE"

SNORT_BIN="${PIGUI_SNORT_BIN:-../build/src/snort}"
case "$SNORT_BIN" in
  /*) ;;
  *) SNORT_BIN="$PIGUI_ROOT/$SNORT_BIN" ;;
esac

mkdir -p "$PIGUI_SNORT_LOG_DIR" "$PIGUI_SNORT_CONFIG_DIR" "$(dirname "$PIGUI_SNORT_CONTROL_SOCKET")"

echo "generating Snort configuration..."
cargo run -q -p pigui-cli -- snort generate-config >/dev/null

echo "starting Snort on $IFACE (log dir $PIGUI_SNORT_LOG_DIR)"
PID_NAME="$(basename "$PIGUI_SNORT_PIDFILE")"
SNORT_ARGS=(
  -c "$PIGUI_SNORT_CONFIG_DIR/snort.lua"
  -i "$IFACE"
  -l "$PIGUI_SNORT_LOG_DIR"
  --create-pidfile "$PID_NAME"
  -q
)

CURRENT_USER="$(id -un)"
CURRENT_GROUP="$(id -gn)"

trap cleanup EXIT
trap 'exit 130' INT TERM

(
  if ! sudo "$SNORT_BIN" "${SNORT_ARGS[@]}" -u "$CURRENT_USER" -g "$CURRENT_GROUP"; then
    echo "privilege-dropped Snort failed; retrying as root" >&2
    sudo "$SNORT_BIN" "${SNORT_ARGS[@]}"
  fi
) >"$PIGUI_SNORT_LOG_DIR/snort.log" 2>&1 &
SNORT_WRAPPER_PID=$!

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
  echo "Snort failed to start; check $PIGUI_SNORT_LOG_DIR/snort.log" >&2
  exit 1
fi

cargo build -p pigui-daemon
./target/debug/pigui-daemon > var/log/dev-daemon.log 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 100); do
  [ -S "$PIGUI_SOCKET" ] && break
  sleep 0.1
done
if [ ! -S "$PIGUI_SOCKET" ]; then
  echo "pigui-daemon socket did not appear at $PIGUI_SOCKET" >&2
  exit 1
fi

echo "dev app ready: snort=$SNORT_PID daemon=$DAEMON_PID"
(
  cd apps/pigui-gui
  npm install --silent
  npm run tauri dev
)
