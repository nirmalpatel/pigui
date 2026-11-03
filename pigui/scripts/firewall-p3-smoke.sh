#!/usr/bin/env bash
set -euo pipefail

# P3 smoke test for the daemon firewall RPC surface.
#
# Run this after scripts/run-dev.sh has started the daemon and helper. It
# creates one temporary rule through the daemon, applies it, exercises dynamic
# blocks, counters, and events, then removes its rule and restores the previous
# enabled state.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIGUI_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PIGUI_ROOT"

CLI="$PIGUI_ROOT/target/debug/pigui-cli"
if [ ! -x "$CLI" ]; then
  echo "build the CLI first: cargo build -p pigui-cli" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pigui-p3-smoke.XXXXXX")"
RULE_FILE="$TMP_DIR/rule.json"
RULE_ID=""
WAS_ENABLED=""

cleanup() {
  set +e
  if [ -n "$RULE_ID" ]; then
    "$CLI" firewall rule-delete "$RULE_ID" >/dev/null 2>&1
  fi
  if [ "$WAS_ENABLED" = "0" ]; then
    "$CLI" firewall enable false >/dev/null 2>&1
    "$CLI" firewall apply >/dev/null 2>&1
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

cat >"$RULE_FILE" <<'JSON'
{
  "name": "p3 smoke udp 9",
  "enabled": true,
  "action": "block",
  "direction": "out",
  "protocol": "udp",
  "remote_port": "9",
  "log": true
}
JSON

status_json="$("$CLI" firewall status)"
WAS_ENABLED="$(python3 -c '
import json, sys
data = json.load(sys.stdin)
print(int(bool(data.get("state", {}).get("enabled"))))
' <<<"$status_json")"

echo "firewall enabled before: $WAS_ENABLED"
if [ "$WAS_ENABLED" = "0" ]; then
  "$CLI" firewall enable true >/dev/null
fi

echo
echo "creating temporary rule"
created="$("$CLI" firewall rule-add --file "$RULE_FILE")"
echo "$created"
RULE_ID="$(python3 -c '
import json, sys
print(json.load(sys.stdin)["id"])
' <<<"$created")"

echo
echo "applying firewall"
"$CLI" firewall apply

echo
echo "adding dynamic block 192.0.2.10"
"$CLI" firewall block 192.0.2.10 --direction both --ttl 60

echo
echo "sending one loopback UDP packet to port 9"
sleep 0.2
python3 - <<'PY'
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b"pigui-p3\n", ("127.0.0.1", 9))
sock.close()
PY
sleep 0.2

echo
echo "counters"
"$CLI" firewall counters

echo
echo "events"
"$CLI" firewall events --limit 20

echo
echo "active blocks"
"$CLI" firewall blocks

echo
echo "removing dynamic block"
"$CLI" firewall unblock 192.0.2.10 --direction both

echo
echo "deleting temporary rule"
"$CLI" firewall rule-delete "$RULE_ID"
RULE_ID=""

if [ "$WAS_ENABLED" = "0" ]; then
  echo
  echo "restoring disabled firewall state"
  "$CLI" firewall enable false
  "$CLI" firewall apply
else
  echo
  echo "reapplying remaining rules"
  "$CLI" firewall apply
fi

echo
echo "final status"
"$CLI" firewall status
echo
echo "P3 smoke test complete"
