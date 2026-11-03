#!/usr/bin/env bash
set -euo pipefail

# P2 smoke test for the PIGUI PF helper backend.
#
# Run this after `scripts/run-dev.sh` has started the dev daemon and root helper.
# It applies a temporary PIGUI rule, adds a dynamic block, captures one blocked
# loopback packet, prints counters/events, then restores the previous PF state.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIGUI_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PIGUI_ROOT"

export PIGUI_HELPER_DEV="${PIGUI_HELPER_DEV:-1}"
export PIGUI_HELPER_SERVICE="${PIGUI_HELPER_SERVICE:-com.pigui.helper.dev}"

CLI="$PIGUI_ROOT/target/debug/pigui-cli"
HELPERCTL="$PIGUI_ROOT/target/debug/pigui-helperctl"

if [ ! -x "$CLI" ] || [ ! -x "$HELPERCTL" ]; then
  echo "build the dev helper and CLI first:" >&2
  echo "  ./scripts/build-dev-helper.sh && cargo build -p pigui-cli" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pigui-p2-smoke.XXXXXX")"
BLOCK_RULES="$TMP_DIR/block.pf"
ALLOW_RULES="$TMP_DIR/allow.pf"
APPLIED=0

cleanup() {
  set +e
  if [ "$APPLIED" -eq 1 ]; then
    if [ "${PF_ENABLED_BEFORE:-1}" -eq 0 ]; then
      "$CLI" helper firewall-flush --disable-pf >/dev/null 2>&1
    else
      "$CLI" helper firewall-flush >/dev/null 2>&1
    fi
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

status_json="$("$CLI" helper firewall-status)"
parsed="$(python3 -c '
import json, sys
data = json.load(sys.stdin)["data"]
print(int(bool(data.get("pf_enabled"))), int(bool(data.get("pf_enabled_by_pigui"))))
' <<<"$status_json")"
PF_ENABLED_BEFORE="${parsed% *}"
PIGUI_OWNED_BEFORE="${parsed#* }"

echo "PF before: enabled=$PF_ENABLED_BEFORE pigui_owned=$PIGUI_OWNED_BEFORE"

cat >"$BLOCK_RULES" <<'PF'
# PIGUI managed block rules. Do not edit.
table <pigui_block4_in> persist
table <pigui_block4_out> persist
table <pigui_block6_in> persist
table <pigui_block6_out> persist
block drop in log (to pflog1) quick inet from <pigui_block4_in> to any label "pigui-dynamic4-in-src"
block drop in log (to pflog1) quick inet from any to <pigui_block4_in> label "pigui-dynamic4-in-dst"
block drop out log (to pflog1) quick inet from <pigui_block4_out> to any label "pigui-dynamic4-out-src"
block drop out log (to pflog1) quick inet from any to <pigui_block4_out> label "pigui-dynamic4-out-dst"
block drop in log (to pflog1) quick inet6 from <pigui_block6_in> to any label "pigui-dynamic6-in-src"
block drop in log (to pflog1) quick inet6 from any to <pigui_block6_in> label "pigui-dynamic6-in-dst"
block drop out log (to pflog1) quick inet6 from <pigui_block6_out> to any label "pigui-dynamic6-out-src"
block drop out log (to pflog1) quick inet6 from any to <pigui_block6_out> label "pigui-dynamic6-out-dst"
block drop out log (to pflog1) quick proto udp from any to any port 9 label "pigui-rule-1"
PF

cat >"$ALLOW_RULES" <<'PF'
# PIGUI managed allow rules. Do not edit.
PF

echo
echo "applying temporary PIGUI rules"
APPLIED=1
if [ "$PF_ENABLED_BEFORE" -eq 0 ]; then
  "$CLI" helper firewall-apply "$BLOCK_RULES" "$ALLOW_RULES" --generation 1 --enable-pf
else
  "$CLI" helper firewall-apply "$BLOCK_RULES" "$ALLOW_RULES" --generation 1
fi

echo
echo "adding dynamic block 192.0.2.10"
"$CLI" helper firewall-block 192.0.2.10 --direction both --ttl 60

echo
echo "sending one loopback UDP packet to port 9"
sleep 0.2
python3 - <<'PY'
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b"pigui-p2\n", ("127.0.0.1", 9))
sock.close()
PY
sleep 0.2

echo
echo "rule counters"
"$CLI" helper firewall-counters

echo
echo "recent pflog events"
"$CLI" helper firewall-events --limit 20

echo
echo "removing dynamic block 192.0.2.10"
"$CLI" helper firewall-unblock 192.0.2.10 --direction both

echo
echo "flushing PIGUI rules"
if [ "$PF_ENABLED_BEFORE" -eq 0 ]; then
  "$CLI" helper firewall-flush --disable-pf
else
  "$CLI" helper firewall-flush
fi
APPLIED=0

echo
echo "P2 smoke test complete"
