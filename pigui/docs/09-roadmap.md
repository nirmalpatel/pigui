# Roadmap and status

PIGUI is at an early implementation stage. This page separates what exists from
what is planned.

## Milestones

| Milestone | Deliverable | Status |
|---|---|---|
| M0 | Branch, docs, architecture, repository guardrails | Complete |
| M1 | Rust workspace and Tauri scaffold | Complete |
| M2 | Core models, config, SQLite schema, fixture parsers | Partial: alerts, extractor, domains, and schema complete |
| M3 | Snort discovery, config generation, control adapter, log ingestion | Partial: discovery, config generation, alert/extractor ingestion complete; control adapter missing |
| M4 | macOS process/socket collector and correlation | Partial: `nettop` collector and 5-tuple joins complete; Network Extension later |
| M5 | Rule bundle manager and validation pipeline | Planned |
| M6 | PF helper in dry-run mode | Partial: SMAppService/XPC helper and dry-run actions implemented; PF execution pending |
| M7 | Daemon API and GUI MVP | Partial: live processes/connections/destinations/alerts/domains/DNS API and tabs complete |
| M8 | launchd packaging and macOS system integration | Partial: signed/notarized/stapled app and DMG implemented; installed helper launch verification pending |
| M9 | Hardening, retention, audit, tests, documentation | Partial: retention, tests, and docs exist; audit and hardening pending |
| M10 | Linux/ufw/nftables and Windows support | In progress |

## Implemented

- Rust workspace with core, Snort adapter, collector, firewall types, daemon,
  CLI, and Tauri GUI, plus a packaged Swift/XPC helper.
- Snort discovery and capability probe.
- Generated live Snort configuration with validation.
- Alert JSONL ingestion with dedupe.
- Extractor ingestion for `conn`, `dns`, `ssl`, `http`, and `quic`.
- `nettop` and `ps` process/socket collection.
- Live flows, completed connections, processes, destinations, domains, DNS,
  TLS, HTTP, and QUIC storage.
- Domain normalization, registrable-domain trust, review flags, PTR lookups,
  and watched domains.
- Unix-socket daemon API.
- CLI for headless inspection and diagnostics.
- Tauri 2 + Svelte GUI shell.
- Signed, notarized, stapled macOS DMG with bundled Snort and dylibs.

## Partial or missing

- Snort control socket: Snort can be built with it, but PIGUI has no client and
  live scripts do not wire it.
- Signal-based Snort management.
- Firewall: types and a dry-run backend exist; PF execution is a placeholder.
- Helper: XPC service, payload staging, Snort lifecycle, audit, dry-run
  firewall actions, dev-mode launchd/XPC capture, and capture-state recovery
  exist; PF execution and fuller GUI onboarding remain.
- Rule bundles and policy engine.
- Log rotation (database retention is implemented).
- Sensor stats and firewall action history; helper privileged-action audit exists.
- `/Applications` helper registration/approval verification and full production onboarding.
- Linux and Windows adapters.
- Windows-compatible IPC and file/process APIs.

## Platform support

| Platform | Snort mode | Enforcement | Process attribution | Status |
|---|---|---|---|---|
| macOS 14+ | Passive pcap/BPF | PF (planned) | `nettop`/`ps` | Supported |
| Linux | Passive first, inline optional | ufw/nftables (planned) | `ss`/`/proc`/eBPF (planned) | In progress |
| Windows | Native support uncertain | Defender Firewall/WFP (planned) | `GetExtendedTcpTable`/ETW (planned) | In progress |

macOS is the currently supported platform. Linux and Windows support is in
progress.

## Risks

- Snort on macOS is passive; PIGUI detects, PF enforces.
- Polling-based process attribution is imperfect, especially for short flows
  and UDP.
- Domains are ambiguous for shared/CDN IPs and hidden DNS.
- Snort control-socket commands are not a stable public ABI.
- Log volume can grow quickly; retention and rotation are required.
- The privileged helper is the highest-risk component and must remain narrow.
- Native Windows Snort support is uncertain.
- Living inside the Snort 3 repository has GPLv2 implications.
- Tauri does not provide native AppKit controls; a SwiftUI shell may be added
  later without changing the daemon protocol.

## Decisions

Resolved:

- GUI stack: Rust + Tauri 2 with a Svelte frontend.
- Storage: SQLite first; GUI preferences use a separate GUI-local SQLite file.
- Cross-platform design; macOS is the current platform, with Linux and Windows
  in progress.
- PIGUI consumes Snort as an external process, not a linked library.
- Snort control socket is preferred for management, with signal/file fallback.
- Enforcement is firewall-based and off by default.
- PIGUI is GPLv2-compatible while it lives in the Snort 3 tree.

Still open:

- Minimum macOS version. Current proposal: macOS 14+.
- Whether process-aware blocking is a later Network Extension effort.
- Whether the ruleset is native Snort syntax or a custom DSL requiring a
  compiler.
- Windows native sensor versus WSL2/container/remote Linux sensor.
- Distribution and notarization workflow. Packaging scripts exist; signing,
  notarization, and release credentials still need to be set.

## License

PIGUI is intended to be GPLv2-compatible while it lives inside the Snort 3
repository. Confirm the final licensing and distribution model before any
closed-source distribution or separate commercial packaging.
