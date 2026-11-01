#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/dev-env.sh"

if [ -f "$PIGUI_SNORT_PIDFILE" ]; then
  PID="$(cat "$PIGUI_SNORT_PIDFILE" 2>/dev/null || sudo cat "$PIGUI_SNORT_PIDFILE" 2>/dev/null || true)"
  if [ -n "$PID" ]; then
    echo "stopping Snort pid $PID"
    sudo kill "$PID" 2>/dev/null || true
  fi
  sudo rm -f "$PIGUI_SNORT_PIDFILE" 2>/dev/null || rm -f "$PIGUI_SNORT_PIDFILE" 2>/dev/null || true
else
  echo "no Snort PID file at $PIGUI_SNORT_PIDFILE"
fi

if [ -S "$PIGUI_SOCKET" ]; then
  echo "stopping pigui-daemon"
  python3 - "$PIGUI_SOCKET" <<'PY'
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
