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
export PIGUI_FIXTURE_ALERT_JSON="${PIGUI_FIXTURE_ALERT_JSON:-./tests/fixtures/alert_json/valid.jsonl}"

mkdir -p var/run var/log var/lib
