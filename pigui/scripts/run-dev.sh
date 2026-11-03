#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/dev-env.sh"

export PIGUI_ALERT_JSON="$PIGUI_SNORT_LOG_DIR/alert_json.txt"
export PIGUI_EXTRACTOR_JSON="$PIGUI_SNORT_LOG_DIR/file_connector_pigui_transmit"

HELPER_LABEL="com.pigui.helper.dev"
DAEMON_PID=""

abs_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s\n' "$PIGUI_ROOT/$1" ;;
  esac
}

HELPER_PLIST="$(abs_path "$PIGUI_RUN_DIR")/$HELPER_LABEL.plist"
HELPER_STATE_DIR="$(abs_path "$PIGUI_RUN_DIR")/helper"

read_snort_pid() {
  cat "$PIGUI_SNORT_PIDFILE" 2>/dev/null \
    || sudo cat "$PIGUI_SNORT_PIDFILE" 2>/dev/null \
    || true
}

rpc_call() {
  local method="$1"
  local params="${2:-{}}"
  python3 - "$PIGUI_SOCKET" "$method" "$params" <<'PY'
import json
import socket
import sys

path, method, raw = sys.argv[1], sys.argv[2], sys.argv[3]
params = json.loads(raw) if raw else {}
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(15)
sock.connect(path)
sock.sendall(json.dumps({"id": 1, "method": method, "params": params}).encode() + b"\n")
data = b""
while not data.endswith(b"\n"):
    chunk = sock.recv(65536)
    if not chunk:
        break
    data += chunk
sock.close()
response = json.loads(data)
if not response.get("ok"):
    raise SystemExit(response.get("error") or "rpc failed")
if response.get("data") is not None:
    print(json.dumps(response["data"]))
PY
}

stop_capture() {
  if [ -S "$PIGUI_SOCKET" ]; then
    rpc_call capture.stop '{}' >/dev/null 2>&1 || true
  fi
}

stop_daemon() {
  if [ -S "$PIGUI_SOCKET" ]; then
    echo "stopping pigui-daemon"
    rpc_call shutdown '{}' >/dev/null 2>&1 || true
  fi
  rm -f "$PIGUI_SOCKET" 2>/dev/null || true
}

stop_helper() {
  sudo launchctl bootout "system/$HELPER_LABEL" 2>/dev/null || true
  sudo rm -f "$HELPER_PLIST" 2>/dev/null || true
  sudo rm -rf "$HELPER_STATE_DIR" 2>/dev/null || true
}

stop_snort() {
  if [ -f "$PIGUI_SNORT_PIDFILE" ]; then
    SNORT_PID="$(read_snort_pid)"
    if [ -n "$SNORT_PID" ]; then
      echo "stopping leftover Snort pid $SNORT_PID"
      sudo kill "$SNORT_PID" 2>/dev/null || true
    fi
    sudo rm -f "$PIGUI_SNORT_PIDFILE" 2>/dev/null || rm -f "$PIGUI_SNORT_PIDFILE" 2>/dev/null || true
  fi
}

stop_all() {
  stop_capture
  stop_daemon
  stop_helper
  stop_snort
}

cleanup() {
  trap - EXIT
  set +e
  if [ -n "$DAEMON_PID" ]; then
    stop_capture
    kill -TERM "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
  fi
  stop_helper
  stop_snort
}

write_helper_plist() {
  local snort_bin snort_config snort_log run_dir log_dir extra_env
  snort_bin="$(abs_path "$SNORT_BIN")"
  snort_config="$(abs_path "$PIGUI_SNORT_CONFIG_DIR")/snort.lua"
  snort_log="$(abs_path "$PIGUI_SNORT_LOG_DIR")"
  run_dir="$(abs_path "$PIGUI_RUN_DIR")"
  log_dir="$(abs_path "$PIGUI_LOG_DIR")"
  extra_env=""
  if [ -n "${DYLD_LIBRARY_PATH:-}" ]; then
    extra_env="$extra_env<key>DYLD_LIBRARY_PATH</key><string>$DYLD_LIBRARY_PATH</string>"
  fi
  if [ -n "${DYLD_FALLBACK_LIBRARY_PATH:-}" ]; then
    extra_env="$extra_env<key>DYLD_FALLBACK_LIBRARY_PATH</key><string>$DYLD_FALLBACK_LIBRARY_PATH</string>"
  fi
  mkdir -p "$run_dir" "$log_dir" "$HELPER_STATE_DIR"

  cat >"$HELPER_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$HELPER_LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PIGUI_ROOT/target/debug/pigui-helper</string>
        <string>--dev</string>
        <string>--service</string>
        <string>$HELPER_LABEL</string>
    </array>
    <key>MachServices</key>
    <dict>
        <key>$HELPER_LABEL</key>
        <true/>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PIGUI_HELPER_DEV</key>
        <string>1</string>
        <key>PIGUI_HELPER_SERVICE</key>
        <string>$HELPER_LABEL</string>
        <key>PIGUI_HELPER_STATE_ROOT</key>
        <string>$HELPER_STATE_DIR</string>
        <key>PIGUI_HELPER_AUDIT</key>
        <string>$log_dir/helper-audit.log</string>
        <key>PIGUI_DEV_SNORT_BIN</key>
        <string>$snort_bin</string>
        <key>PIGUI_DEV_SNORT_CONFIG</key>
        <string>$snort_config</string>
        <key>PIGUI_DEV_SNORT_LOG_DIR</key>
        <string>$snort_log</string>
        $extra_env
    </dict>
    <key>StandardOutPath</key>
    <string>$log_dir/helper.log</string>
    <key>StandardErrorPath</key>
    <string>$log_dir/helper.log</string>
</dict>
</plist>
PLIST
  sudo chown root:wheel "$HELPER_PLIST"
  sudo chmod 0644 "$HELPER_PLIST"
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

echo "requesting sudo credentials for dev capture helper..."
sudo -v

stop_all

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

mkdir -p "$PIGUI_SNORT_LOG_DIR" "$PIGUI_SNORT_CONFIG_DIR" "$PIGUI_RUN_DIR" "$HELPER_STATE_DIR"

echo "generating Snort configuration..."
cargo run -q -p pigui-cli -- snort generate-config >/dev/null

echo "building dev daemon and capture helper..."
cargo build -p pigui-daemon
"$SCRIPT_DIR/build-dev-helper.sh"

echo "starting dev capture helper ($HELPER_LABEL)"
write_helper_plist
trap cleanup EXIT
trap 'exit 130' INT TERM
sudo launchctl bootstrap system "$HELPER_PLIST"
for _ in $(seq 1 50); do
  if sudo launchctl print "system/$HELPER_LABEL" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
if ! sudo launchctl print "system/$HELPER_LABEL" >/dev/null 2>&1; then
  echo "dev helper failed to load; see $(abs_path "$PIGUI_LOG_DIR")/helper.log" >&2
  exit 1
fi

echo "starting pigui-daemon"
PIGUI_HELPER_DEV=1 \
PIGUI_HELPER_SERVICE="$HELPER_LABEL" \
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

echo "starting capture on $IFACE through daemon -> dev helper"
if ! rpc_call capture.start "{\"interface\":\"$IFACE\"}" >/dev/null; then
  echo "capture could not be started through the dev helper" >&2
  echo "daemon log: $(abs_path "$PIGUI_LOG_DIR")/dev-daemon.log" >&2
  echo "helper log: $(abs_path "$PIGUI_LOG_DIR")/helper.log" >&2
  exit 1
fi

echo "dev app ready: interface=$IFACE daemon=$DAEMON_PID helper=$HELPER_LABEL"
(
  cd apps/pigui-gui
  npm install --silent
  npm run tauri dev
)
