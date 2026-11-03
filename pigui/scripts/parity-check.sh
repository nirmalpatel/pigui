#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/dev-env.sh"

SOCKET="${PIGUI_SOCKET:-$PIGUI_RUN_DIR/pigui-daemon.sock}"

python3 - "$SOCKET" <<'PY'
import json
import socket
import sys

path = sys.argv[1]

def call(method, params=None):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(path)
    sock.sendall(json.dumps({"id": 1, "method": method, "params": params or {}}).encode() + b"\n")
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    sock.close()
    response = json.loads(data)
    if not response.get("ok"):
        raise RuntimeError(response.get("error") or "rpc failed")
    return response.get("data")

status = call("status")
print("== PIGUI runtime ==")
print(f"environment:          {status.get('environment')}")
print(f"database:             {status.get('db_path')}")
print(f"socket:               {status.get('socket_path')}")
print(f"snort running:        {status.get('snort_running')}")
print(f"snort interface:      {status.get('snort_interface')}")
print(f"capture running:      {status.get('capture_running')}")
print(f"capture interface:    {status.get('capture_interface')}")
print(f"capture mode:         {status.get('capture_mode')}")
print(f"snort config hash:    {status.get('snort_config_hash')}")
print(f"extractor file:       {status.get('extractor_file')}")
print(f"extractor rows:       {status.get('extractor_ingested')}")
print(f"alerts:               {status.get('alert_count')}")
print(f"dns/tls/http/quic:    {status.get('dns_count')}/{status.get('tls_count')}/{status.get('http_count')}/{status.get('quic_count')}")
print(f"domains:              {status.get('domain_count')}")

try:
    capture = call("capture.status")
    helper = capture.get("helper") or {}
    data = helper.get("data") if isinstance(helper, dict) else None
    print()
    print("== Capture helper ==")
    print(f"capture state:        {capture.get('capture')}")
    if isinstance(data, dict):
        print(f"helper version:       {data.get('version')}")
        print(f"helper uid:           {data.get('uid')}")
        print(f"helper capture:       {data.get('capture_running')}")
        print(f"helper snort pid:     {data.get('snort_pid')}")
        print(f"helper interface:     {data.get('interface')}")
        print(f"helper payload root:  {data.get('state_root')}")
        print(f"helper audit log:     {data.get('audit_log')}")
    else:
        print(f"helper response:      {helper}")
except Exception as error:
    print()
    print(f"capture helper unavailable: {error}")

try:
    stats = call("maintenance.stats")
    print()
    print("== Maintenance ==")
    print(f"db bytes:             {stats.get('db_bytes')}")
    print(f"last run:             {stats.get('last_run')}")
    print(f"last deleted:         {stats.get('last_deleted')}")
    for entry in stats.get("table_counts") or []:
        print(f"  {entry['name']}: {entry['rows']}")
except Exception as error:
    print(f"maintenance stats unavailable: {error}")
PY
