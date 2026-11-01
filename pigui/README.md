# PIGUI

PIGUI is a macOS-first network security application built alongside Snort 3.
It consumes Snort as an external passive sensor and adds OS process
attribution, a local manager daemon, a privileged firewall helper (planned),
and an Activity Monitor-style GUI.

Status: early implementation. Fixture ingestion, live alert/extractor
ingestion, nettop process attribution, the daemon RPC API, the CLI, and the
Tauri shell exist. PF enforcement, rule bundles, the helper, and release
packaging are planned.

PIGUI lives inside the Snort 3 repository on the `pigui` branch, but it is not
part of the Snort core build. PIGUI does not link against Snort C++ internals
or modify Snort source. The parent Snort tree is treated as a dependency and
reference.

## Documentation

Full documentation lives in [`docs/`](docs/README.md).

| Document | Contents |
|---|---|
| [Overview](docs/00-abridged-docs.md) | Core concepts, boundaries, and links |
| [Quick start](docs/01-quickstart.md) | Fixture mode, live capture, CLI checks |
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
./scripts/run-dev.sh        # fixture daemon, then the Tauri window
```

For live capture see [docs/01-quickstart.md](docs/01-quickstart.md). Snort must
run with `sudo` for BPF access; the daemon does not run as root.

## Platform

macOS is the first and only supported platform for the first release. Linux and
Windows are planned as later adapters. See
[docs/09-roadmap.md](docs/09-roadmap.md).

## License

PIGUI is intended to be GPLv2-compatible while it lives inside the Snort 3
repository. Confirm the final licensing and distribution model before any
closed-source distribution or separate commercial packaging.
