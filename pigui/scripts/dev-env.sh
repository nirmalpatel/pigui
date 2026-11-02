#!/usr/bin/env bash
# Source this file to load development defaults. Relative paths in .env are
# interpreted relative to the pigui/ directory.

PIGUI_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PIGUI_ROOT" || return 1

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
else
  set -a
  # shellcheck disable=SC1091
  . ./.env.example
  set +a
fi

export PIGUI_HOME="${PIGUI_HOME:-$PIGUI_ROOT}"

# Defaults keep older .env files and partial environments working.
export PIGUI_DB_PATH="${PIGUI_DB_PATH:-./var/lib/pigui.db}"
export PIGUI_SNORT_BIN="${PIGUI_SNORT_BIN:-../build/src/snort}"
export PIGUI_SNORT_CONFIG="${PIGUI_SNORT_CONFIG:-../lua/snort.lua}"
export PIGUI_SNORT_LUA_PATH="${PIGUI_SNORT_LUA_PATH:-../lua}"
export PIGUI_SNORT_LOG_DIR="${PIGUI_SNORT_LOG_DIR:-./var/log/snort}"
export PIGUI_SNORT_CONFIG_DIR="${PIGUI_SNORT_CONFIG_DIR:-./var/snort}"
export PIGUI_SNORT_PIDFILE="${PIGUI_SNORT_PIDFILE:-./var/log/snort/snort.pid}"
export PIGUI_SNORT_CONTROL_SOCKET="${PIGUI_SNORT_CONTROL_SOCKET:-./var/run/snort.sock}"
export PIGUI_EXTRACTOR_JSON="${PIGUI_EXTRACTOR_JSON:-./var/log/snort/file_connector_pigui_transmit}"
export PIGUI_PROCESS_POLL_MS="${PIGUI_PROCESS_POLL_MS:-1000}"

mkdir -p var/run var/log var/lib var/log/snort var/snort
