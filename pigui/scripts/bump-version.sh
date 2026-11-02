#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:?usage: bump-version.sh <version>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIGUI_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

python3 - "$PIGUI_ROOT" "$VERSION" <<'PY'
import re
import sys

root, version = sys.argv[1], sys.argv[2]

files = [
    (f"{root}/Cargo.toml", r'^version = "[^"]+"'),
    (f"{root}/apps/pigui-gui/src-tauri/Cargo.toml", r'^version = "[^"]+"'),
    (f"{root}/apps/pigui-gui/src-tauri/tauri.conf.json", r'"version": "[^"]+"'),
    (f"{root}/apps/pigui-gui/package.json", r'"version": "[^"]+"'),
]

for path, pattern in files:
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    if path.endswith(".json"):
        replacement = f'"version": "{version}"'
    else:
        replacement = f'version = "{version}"'
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise SystemExit(f"could not update version in {path}")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(updated)
    print(f"updated {path}")
PY

cargo metadata --format-version 1 --manifest-path "$PIGUI_ROOT/Cargo.toml" >/dev/null

echo "version set to $VERSION"
