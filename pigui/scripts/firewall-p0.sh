#!/usr/bin/env bash
set -euo pipefail

# P0 feasibility probe for macOS PF integration.
#
# Default mode is read-only. It inspects the live PF ruleset and the macOS
# Application Firewall without reading or modifying /etc.
#
# Test mode loads one harmless rule into a throwaway anchor and sends a single
# loopback UDP packet to see whether PF evaluates anchors under com.apple/*.
# The anchor is flushed on exit. If PF is disabled, test mode refuses to enable
# it unless --enable-pf is also given.

PFCTL="/sbin/pfctl"
TCPDUMP="/usr/sbin/tcpdump"
SOCKETFILTERFW="/usr/libexec/ApplicationFirewall/socketfilterfw"
ANCHOR="com.apple/pigui.p0test"
LABEL="pigui-p0"
ORDER_A="com.apple/000.pigui.p0a"
ORDER_Z="com.apple/999.pigui.p0z"
LABEL_A="pigui-p0-a"
LABEL_Z="pigui-p0-z"
TEST_PORT=9

MODE="inspect"
ENABLE_PF=0

usage() {
  cat <<'EOF'
usage: firewall-p0.sh [--test-anchor|--test-order] [--enable-pf]

  --test-anchor  Load a harmless throwaway PF anchor under com.apple/*,
                 send one loopback UDP packet, print label counters/pflog, then flush.
  --test-order   Load a 000.* pass-quick anchor after a 999.* block-quick anchor
                 to determine whether com.apple child anchors run by name order
                 or load order. Flushes both anchors on exit.
  --enable-pf    Allow test mode to run `pfctl -E` when PF is currently disabled.
                 PF is disabled again on exit only if this script enabled it.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --test-anchor)
      MODE="test"
      ;;
    --test-order)
      MODE="order"
      ;;
    --enable-pf)
      ENABLE_PF=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [ "$(uname -s)" != "Darwin" ]; then
  echo "firewall-p0.sh only runs on macOS" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "PF inspection requires root. Run:" >&2
  echo "  sudo $0 $*" >&2
  exit 1
fi

section() {
  printf '\n=== %s ===\n' "$1"
}

run() {
  printf '\n$ %s\n' "$*"
  "$@" 2>&1 || true
}

section "System"
run sw_vers
run uname -m
run ls -l "$PFCTL" "$TCPDUMP" "$SOCKETFILTERFW"

section "Application Firewall"
run "$SOCKETFILTERFW" --getglobalstate
run "$SOCKETFILTERFW" --getblockall
run "$SOCKETFILTERFW" --getstealthmode
run "$SOCKETFILTERFW" --listapps

section "PF status"
PF_INFO="$("$PFCTL" -s info 2>&1 || true)"
printf '%s\n' "$PF_INFO"
PF_WAS_ENABLED=0
if printf '%s\n' "$PF_INFO" | grep -qi '^Status: Enabled'; then
  PF_WAS_ENABLED=1
fi
printf 'pf_was_enabled=%s\n' "$PF_WAS_ENABLED"

section "Live PF anchors"
run "$PFCTL" -s Anchors
run "$PFCTL" -s Anchors -vv

section "Live PF references"
run "$PFCTL" -s References

section "Live PF filter rules"
run "$PFCTL" -s rules

section "Live PF NAT rules"
run "$PFCTL" -s nat

section "Live PF tables"
run "$PFCTL" -s Tables

section "Apple anchor rules"
run "$PFCTL" -a com.apple -sr

section "pflog"
run ifconfig pflog0

section "PIGUI anchor feasibility"
if "$PFCTL" -s rules 2>/dev/null | grep -q 'anchor "com.apple/\*"'; then
  echo "result: com.apple/* wildcard anchor is referenced by the active ruleset"
else
  echo "result: com.apple/* wildcard anchor was not found in the active ruleset"
  echo "note: PF may be disabled or the system ruleset may not be loaded yet"
fi

if [ "$MODE" = "inspect" ]; then
  echo
  echo "inspect-only complete; no state was changed"
  exit 0
fi

TMP_ENABLED=0
PF_TOKEN=""
PFLOG_CREATED=0
TMP_RULE="$(mktemp "${TMPDIR:-/tmp}/pigui-p0-rule.XXXXXX")"
TMP_RULE_A="$(mktemp "${TMPDIR:-/tmp}/pigui-p0-rule-a.XXXXXX")"
TMP_RULE_Z="$(mktemp "${TMPDIR:-/tmp}/pigui-p0-rule-z.XXXXXX")"
TMP_LOG="$(mktemp "${TMPDIR:-/tmp}/pigui-p0-log.XXXXXX")"
TCPDUMP_PID=""
trap 'cleanup' EXIT INT TERM

flush_anchor() {
  "$PFCTL" -a "$1" -F all >/dev/null 2>&1
  "$PFCTL" -a "$1" -f /dev/null >/dev/null 2>&1
}

cleanup() {
  set +e
  if [ -n "$TCPDUMP_PID" ]; then
    kill "$TCPDUMP_PID" >/dev/null 2>&1
    wait "$TCPDUMP_PID" >/dev/null 2>&1
  fi
  for anchor in "$ANCHOR" "$ORDER_A" "$ORDER_Z"; do
    flush_anchor "$anchor"
  done
  rm -f "$TMP_RULE" "$TMP_RULE_A" "$TMP_RULE_Z" "$TMP_LOG"
  if [ "$PFLOG_CREATED" -eq 1 ]; then
    ifconfig pflog0 destroy >/dev/null 2>&1
    echo "destroyed pflog0 created by the test" >&2
  fi
  if [ "$TMP_ENABLED" -eq 1 ]; then
    if [ -n "$PF_TOKEN" ]; then
      "$PFCTL" -X "$PF_TOKEN" >/dev/null 2>&1
    else
      "$PFCTL" -X >/dev/null 2>&1
    fi
    echo "released pf enable token${PF_TOKEN:+ $PF_TOKEN}" >&2
  fi
}

send_test_packet() {
  echo
  echo "sending one loopback UDP packet to 127.0.0.1:$TEST_PORT"
  python3 - "$TEST_PORT" <<'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b"pigui-p0\n", ("127.0.0.1", port))
sock.close()
PY
  sleep 1
}

start_pflog_capture() {
  section "Test pflog"
  if ! ifconfig pflog0 >/dev/null 2>&1; then
    echo "creating pflog0"
    if ifconfig pflog0 create; then
      PFLOG_CREATED=1
    else
      echo "could not create pflog0; logging capture will be skipped"
    fi
  fi
  run ifconfig pflog0
  "$TCPDUMP" -n -e -ttt -i pflog0 -c 1 >"$TMP_LOG" 2>&1 &
  TCPDUMP_PID=$!
}

stop_pflog_capture() {
  if [ -n "$TCPDUMP_PID" ]; then
    kill "$TCPDUMP_PID" >/dev/null 2>&1 || true
    wait "$TCPDUMP_PID" >/dev/null 2>&1 || true
    TCPDUMP_PID=""
  fi
}

show_pflog_capture() {
  section "pflog capture"
  if [ -s "$TMP_LOG" ]; then
    cat "$TMP_LOG"
  else
    echo "no pflog records captured"
  fi
}

section "Test setup"
if [ "$PF_WAS_ENABLED" -eq 0 ]; then
  if [ "$ENABLE_PF" -ne 1 ]; then
    echo "PF is disabled. Re-run with --enable-pf to allow a temporary enable." >&2
    exit 1
  fi
  echo "PF is disabled; enabling temporarily with pfctl -E"
  ENABLE_OUTPUT="$("$PFCTL" -E 2>&1)"
  printf '%s\n' "$ENABLE_OUTPUT"
  PF_TOKEN="$(printf '%s\n' "$ENABLE_OUTPUT" | awk '/Token *:/ {print $3; exit}')"
  TMP_ENABLED=1
fi

if [ "$MODE" = "test" ]; then
  cat >"$TMP_RULE" <<EOF
block drop log quick proto udp from any to any port $TEST_PORT label "$LABEL"
EOF

  echo
  echo "loading test rule into $ANCHOR"
  "$PFCTL" -a "$ANCHOR" -f "$TMP_RULE"
  run "$PFCTL" -a "$ANCHOR" -sr

  start_pflog_capture
  send_test_packet
  stop_pflog_capture

  section "Test anchor counters"
  run "$PFCTL" -a "$ANCHOR" -vs labels
  run "$PFCTL" -a "$ANCHOR" -vs rules
  show_pflog_capture

  echo
  echo "interpretation:"
  echo "  nonzero label counters => the com.apple/* anchor is evaluated"
  echo "  zero label counters     => the anchor was loaded but not evaluated,"
  echo "                             or the packet never reached PF"
  echo
  echo "test complete; flushing $ANCHOR"
  exit 0
fi

# Order test: load 999.* first, then 000.*. If 000.* is still evaluated first,
# PF orders com.apple children by name; if 999.* wins, it orders by load order.
cat >"$TMP_RULE_Z" <<EOF
block drop log quick proto udp from any to any port $TEST_PORT label "$LABEL_Z"
EOF
cat >"$TMP_RULE_A" <<EOF
pass quick proto udp from any to any port $TEST_PORT label "$LABEL_A"
EOF

echo
echo "loading $ORDER_Z ($LABEL_Z) first"
"$PFCTL" -a "$ORDER_Z" -f "$TMP_RULE_Z"
echo "loading $ORDER_A ($LABEL_A) second"
"$PFCTL" -a "$ORDER_A" -f "$TMP_RULE_A"

run "$PFCTL" -a "$ORDER_Z" -sr
run "$PFCTL" -a "$ORDER_A" -sr

send_test_packet

section "Order test counters"
run "$PFCTL" -a "$ORDER_Z" -vs labels
run "$PFCTL" -a "$ORDER_A" -vs labels

echo
echo "interpretation:"
echo "  $LABEL_A increments => 000.* ran before 999.* (name-based order)"
echo "  $LABEL_Z increments => 999.* ran before 000.* (load order or reverse name)"
echo "  both increment      => quick did not stop sibling anchor evaluation"
echo
echo "test complete; flushing $ORDER_A and $ORDER_Z"
