#!/usr/bin/env python3
"""Copy Snort and its non-system dylibs into a PIGUI.app bundle."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

SYSTEM_PREFIXES = (
    "/System/Library/",
    "/usr/lib/",
    "/usr/lib/system/",
    "/Library/Apple/",
)

NON_SYSTEM_PREFIXES = (
    "/opt/homebrew/",
    "/usr/local/",
    "/opt/local/",
)


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True)


def dependencies(path: Path) -> list[str]:
    output = run("otool", "-L", str(path))
    result: list[str] = []
    for line in output.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        dep = line.split(" (compatibility version", 1)[0].strip()
        if dep:
            result.append(dep)
    return result


def is_system(path: str) -> bool:
    return path.startswith(SYSTEM_PREFIXES)


def is_non_system(path: str) -> bool:
    return path.startswith(NON_SYSTEM_PREFIXES)


def candidate(path: str, relative_to: Path) -> Path | None:
    if path.startswith("@rpath/"):
        path = str(relative_to / path[len("@rpath/"):])
    elif path.startswith("@loader_path/"):
        path = str(relative_to / path[len("@loader_path/"):])
    elif path.startswith("@executable_path/"):
        return None
    result = Path(path)
    return result if result.is_file() else None


def main() -> int:
    if len(sys.argv) != 5:
        print(
            "usage: bundle_snort.py <snort> <lua-dir> <pigui-config> <PIGUI.app>",
            file=sys.stderr,
        )
        return 2

    snort = Path(sys.argv[1]).resolve()
    lua_dir = Path(sys.argv[2]).resolve()
    pigui_config = Path(sys.argv[3]).resolve()
    app = Path(sys.argv[4]).resolve()

    if not snort.is_file():
        print(f"snort binary not found: {snort}", file=sys.stderr)
        return 1
    if not lua_dir.is_dir():
        print(f"snort lua tree not found: {lua_dir}", file=sys.stderr)
        return 1

    contents = app / "Contents"
    macos = contents / "MacOS"
    frameworks = contents / "Frameworks"
    resources = contents / "Resources" / "snort"
    for directory in (macos, frameworks, resources / "etc", resources / "lua", resources / "rules"):
        directory.mkdir(parents=True, exist_ok=True)

    target_snort = macos / "snort"
    shutil.copy2(snort, target_snort)
    os.chmod(target_snort, 0o755)

    # Map basename -> chosen source path. Prefer a non-system build when the
    # same library is linked from both Homebrew and /usr/lib.
    chosen: dict[str, Path] = {}
    pending = [target_snort]
    visited: set[Path] = set()

    while pending:
        current = pending.pop()
        if current in visited or not current.is_file():
            continue
        visited.add(current)
        for dep in dependencies(current):
            name = Path(dep).name
            if name in chosen:
                continue
            source = candidate(dep, current.parent)
            if source is not None and is_non_system(dep):
                chosen[name] = source
                pending.append(source)
            elif source is not None and not is_system(dep):
                print(f"unsupported dependency: {dep}", file=sys.stderr)
                return 1

    # A library that only appears as a system path can still be shadowed by a
    # bundled library with the same basename. Rewrite those references too.
    for name, source in list(chosen.items()):
        destination = frameworks / name
        if not destination.exists():
            shutil.copy2(source, destination)
            os.chmod(destination, 0o644)

    all_binaries = [target_snort, *[frameworks / name for name in chosen]]
    for destination in all_binaries:
        if destination.parent == frameworks:
            subprocess.run(
                ["install_name_tool", "-id", f"@rpath/{destination.name}", str(destination)],
                check=True,
            )

    for binary in all_binaries:
        for dep in dependencies(binary):
            name = Path(dep).name
            if name in chosen:
                subprocess.run(
                    ["install_name_tool", "-change", dep, f"@rpath/{name}", str(binary)],
                    check=True,
                )

    # The executable resolves @rpath against its own location. Staged payloads
    # use the same Contents-like layout: bin/snort and Frameworks.
    run("install_name_tool", "-add_rpath", "@executable_path/../Frameworks", str(target_snort))

    # Config layout: etc/snort.lua plus a sibling lua tree and rules.
    shutil.copytree(lua_dir, resources / "lua", dirs_exist_ok=True)
    shutil.copy2(lua_dir / "snort.lua", resources / "etc" / "snort.lua")
    with (resources / "etc" / "snort.lua").open("a", encoding="utf-8") as handle:
        handle.write("\n")
        handle.write(pigui_config.read_text(encoding="utf-8"))
    shutil.copy2(lua_dir / "snort_defaults.lua", resources / "etc" / "snort_defaults.lua")
    for rule in lua_dir.glob("*.rules"):
        shutil.copy2(rule, resources / "etc" / rule.name)
        shutil.copy2(rule, resources / "rules" / rule.name)

    payload = hashlib.sha256()
    for path in sorted(resources.rglob("*")):
        if path.is_file():
            payload.update(path.relative_to(resources).as_posix().encode())
            payload.update(path.read_bytes())
    payload.update(target_snort.read_bytes())
    for name in sorted(chosen):
        payload.update((frameworks / name).read_bytes())
    # arm64 requires a valid code signature before a modified Mach-O can run.
    # Release signing replaces this ad-hoc signature later.
    for binary in all_binaries:
        subprocess.run(["codesign", "--force", "--sign", "-", str(binary)], check=True)

    payload_id = payload.hexdigest()[:24]
    (resources / "payload-id.txt").write_text(payload_id + "\n", encoding="utf-8")

    print(f"bundled {len(chosen)} dylibs; payload id {payload_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
