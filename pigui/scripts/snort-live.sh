#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/dev-env.sh"

export PIGUI_MODE=live

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

# The control socket is enabled by a later phase. It is created before Snort
# drops privileges, so wiring it now would leave a root-owned socket that the
# unprivileged daemon cannot use.

CURRENT_USER="$(id -un)"
CURRENT_GROUP="$(id -gn)"

if sudo "$SNORT_BIN" "${SNORT_ARGS[@]}" -u "$CURRENT_USER" -g "$CURRENT_GROUP" "$@"; then
  exit 0
fi

echo "privilege-dropped Snort failed; retrying as root" >&2
sudo "$SNORT_BIN" "${SNORT_ARGS[@]}" "$@"
