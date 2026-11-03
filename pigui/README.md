# PIGUI

PIGUI is a cross-platform network security application built alongside Snort 3.
It consumes Snort as an external passive sensor and adds OS process
attribution, a local manager daemon, a narrow privileged helper, and an
Activity Monitor-style GUI.

Status: early implementation. Fixture ingestion, live alert/extractor
ingestion, nettop process attribution, the daemon RPC API, the CLI, the Tauri
shell, macOS app packaging, a minimal SMAppService/XPC helper, and a
signed/notarized DMG workflow exist. PF enforcement and rule bundles are still
planned.

PIGUI lives inside the Snort 3 repository on the `pigui` branch, but it is not
part of the Snort core build. PIGUI does not link against Snort C++ internals
or modify Snort source. The parent Snort tree is treated as a dependency and
reference.

## Documentation

Full documentation lives in [`docs/`](docs/README.md).

| Document | Contents |
|---|---|
| [Overview](docs/00-abridged-docs.md) | Core concepts, boundaries, and links |
| [Quick start](docs/01-quickstart.md) | Dev app, live capture, tests, diagnostics |
| [Architecture](docs/02-architecture.md) | Components, crates, layout, paths |
| [Data](docs/03-data.md) | Sources, reconciliation, SQLite schema |
| [Daemon](docs/04-daemon.md) | Lifecycle, tasks, privileges, storage |
| [Snort build](docs/05-snort-compile.md) | Verified macOS build and platform notes |
| [RPC API](docs/06-rpc-api.md) | Unix-socket method reference |
| [Security](docs/07-security.md) | Trust boundaries, IPC, audit, enforcement |
| [Development](docs/08-development.md) | Build, test, env vars, troubleshooting |
| [Roadmap](docs/09-roadmap.md) | Milestones, risks, decisions |

## Quick start

```bash
cd pigui
cp .env.example .env        # optional; scripts fall back to .env.example

./scripts/probe-snort.sh    # resolve Snort and print capabilities
./scripts/run-dev.sh        # Snort + daemon + Tauri dev
```

Package the macOS app (unsigned by default):

```bash
./packaging/macos/build-app.sh
```

See [packaging/macos/README.md](packaging/macos/README.md) for signing,
notarization, and the SMAppService helper model. Release records live in
[`packaging/releases/`](packaging/releases/README.md); the current macOS record
is [v0.1.0](packaging/releases/v0.1.0/macos-arm64.md).

Signed and notarized macOS builds are published on the
[GitHub releases page](https://github.com/nirmalpatel/pigui/releases). The
current release is `pigui-v0.1.0`; download
`PIGUI-0.1.0-macos-arm64.dmg` and its `SHA256SUMS`.

Development uses a temporary root LaunchDaemon to run the same Swift helper in
`--dev` mode; capture flows through GUI -> daemon -> helper -> Snort. The
packaged app uses the SMAppService helper with a root-owned staged Snort payload.
Neither the daemon nor the GUI runs as root, and PIGUI never asks for a
password. See [docs/01-quickstart.md](docs/01-quickstart.md).

## Platform

PIGUI is designed to be cross-platform. macOS is the current supported platform;
Linux and Windows support is in progress. See
[docs/09-roadmap.md](docs/09-roadmap.md).

## License

PIGUI is intended to be GPLv2-compatible while it lives inside the Snort 3
repository. Confirm the final licensing and distribution model before any
closed-source distribution or separate commercial packaging.
