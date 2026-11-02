# PIGUI

PIGUI is a cross-platform network security application built alongside Snort 3.
macOS is currently supported; Linux and Windows support is in progress. It runs
Snort as an external passive sensor and adds OS process attribution, a local
manager daemon, a narrow privileged firewall helper, and an Activity
Monitor-style GUI.

> This repository is a fork of [snort3/snort3](https://github.com/snort3/snort3).
> PIGUI lives on the `pigui` branch, which is this fork's default branch. The
> `master` branch mirrors upstream Snort 3.

- Project directory: [`pigui/`](pigui/)
- Project README: [`pigui/README.md`](pigui/README.md)
- Architecture and design: [`pigui/docs/README.md`](pigui/docs/README.md)
- Short summary: [`PIGUI.md`](PIGUI.md)

## Status

Early implementation. Fixture ingestion, live alert/extractor ingestion, nettop
process attribution, the daemon RPC API, the CLI, the Tauri shell, macOS app
packaging, the SMAppService/XPC helper, and a signed/notarized DMG workflow
exist. PF enforcement and rule bundles are still planned.

## Download

Signed and notarized macOS releases are published on the
[GitHub releases page](https://github.com/nirmalpatel/pigui/releases).

```text
Latest macOS release:  pigui-v0.1.0
Artifact:              PIGUI-0.1.0-macos-arm64.dmg
Requirements:          macOS 14 or newer, Apple silicon
Verification:          SHA256SUMS, notarized and stapled DMG
```

Open the DMG, drag PIGUI to `Applications`, then register the privileged helper
from the Capture tab. See the release notes for the approval steps.

## Quick start

```bash
cd pigui
cp .env.example .env        # optional; scripts fall back to .env.example
./scripts/probe-snort.sh    # resolve Snort and print capabilities
./scripts/run-dev.sh        # fixture daemon, then the Tauri window
```

For live capture see [`pigui/docs/01-quickstart.md`](pigui/docs/01-quickstart.md).
Packaging and signing are documented in
[`pigui/packaging/macos/README.md`](pigui/packaging/macos/README.md).

## Relationship to Snort

PIGUI consumes Snort as an external process. It does not link against Snort C++
internals, is not part of the top-level Snort CMake build, and does not modify
Snort C++ source. The upstream Snort 3 README remains available on the
[`master` branch](https://github.com/nirmalpatel/pigui/blob/master/README.md)
and at [snort3/snort3](https://github.com/snort3/snort3).

## License

PIGUI is GPL-2.0-only, matching the Snort 3 repository it lives in.
