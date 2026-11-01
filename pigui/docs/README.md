# PIGUI documentation

PIGUI is a macOS-first network security application built alongside Snort 3.
It consumes Snort as an external passive sensor and adds OS process
attribution, a manager daemon, a narrow privileged helper, and an
Activity Monitor-style GUI.

- Status: early implementation. Fixture ingestion, live alert/extractor
  ingestion, nettop process attribution, the daemon RPC API, the CLI, the Tauri
  shell, macOS app packaging, a narrow SMAppService/XPC helper, and a
  signed/notarized DMG workflow exist. PF enforcement and rule bundles are
  planned.
- Target platform: macOS first. Linux and Windows are later adapters.
- Project directory: `pigui/`
- Parent Snort tree: not modified by PIGUI and not part of PIGUI's build.

## Documents

| Document | Contents |
|---|---|
| [00-abridged-docs.md](00-abridged-docs.md) | Core concepts, project boundaries, and links to everything else |
| [01-quickstart.md](01-quickstart.md) | Run the fixture app, run live capture, and verify the install |
| [02-architecture.md](02-architecture.md) | Components, crate boundaries, repository layout, runtime paths |
| [03-data.md](03-data.md) | Snort and OS data sources, reconciliation, SQLite schema |
| [04-daemon.md](04-daemon.md) | Daemon lifecycle, tasks, privilege model, storage, degraded modes |
| [05-snort-compile.md](05-snort-compile.md) | Verified Snort build and cross-platform build guidance |
| [06-rpc-api.md](06-rpc-api.md) | Unix-socket JSON-RPC reference used by the CLI and GUI |
| [07-security.md](07-security.md) | Trust boundaries, IPC, audit, rules, and firewall safety |
| [08-development.md](08-development.md) | Build, test, fixtures, environment reference, troubleshooting |
| [09-roadmap.md](09-roadmap.md) | Milestones, risks, decisions, platform status, license |

## Status legend

Docs use three labels:

- **Implemented**: present and exercised by the current code.
- **Partial**: present but limited, or missing pieces.
- **Planned**: designed but not implemented. Never assume it exists.

## Reading order

Start with [00-abridged-docs.md](00-abridged-docs.md), then
[01-quickstart.md](01-quickstart.md). Contributors should also read
[02-architecture.md](02-architecture.md), [03-data.md](03-data.md), and
[08-development.md](08-development.md).

## License

PIGUI is GPLv2-compatible while it lives inside the Snort 3 repository. Confirm
the final licensing and distribution model before closed-source distribution or
separate commercial packaging.
