#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIGUI_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PIGUI_ROOT"

if [ -n "${PIGUI_MCP_BIN:-}" ]; then
  exec "$PIGUI_MCP_BIN" "$@"
fi

if [ ! -x target/debug/pigui-mcp ] || \
   [ -n "$(find crates/pigui-mcp crates/pigui-core -newer target/debug/pigui-mcp -name '*.rs' -print -quit 2>/dev/null)" ]; then
  cargo build -q -p pigui-mcp 1>&2
fi

exec ./target/debug/pigui-mcp "$@"
