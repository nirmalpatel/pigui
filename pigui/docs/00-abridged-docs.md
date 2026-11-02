# PIGUI overview

PIGUI is a local network security application that puts a usable operator
surface over Snort 3. Snort remains the packet inspection and detection engine.
PIGUI adds process attribution, normalization, history, policy, enforcement
tooling, and a GUI.

It answers three questions:

1. What is happening on this machine right now?
2. Which process is responsible for a connection or destination?
3. What should be done about it, safely and with an audit trail?

## Relationship to Snort 3

PIGUI lives inside the Snort 3 repository on the `pigui` branch, but it is not
part of the Snort core build.

- PIGUI consumes Snort as an external process.
- PIGUI does not link against Snort C++ internals.
- PIGUI does not modify Snort source.
- PIGUI is not added to the top-level Snort CMake build.
- Snort binaries and configuration are resolved from the parent repository or a
  configured installation path.
- The parent `lua/` tree is read as a source of defaults; generated
  configuration is written under `pigui/var/snort/`.

Keeping this boundary explicit lets PIGUI evolve independently while remaining
compatible with upstream Snort changes.

## Components

| Component | Privilege | Responsibility | Status |
|---|---|---|---|
| `pigui-gui` | User | Tauri 2 + Svelte presentation shell | Implemented |
| `pigui-daemon` | Unprivileged | Ingestion, correlation, SQLite, policy, local RPC | Implemented |
| Snort 3 | Root | Passive packet inspection and telemetry | Implemented |
| OS collectors | Daemon thread | Process/socket attribution via `nettop` and `ps` | Partial: macOS collector implemented |
| `pigui-helper` | Root | Narrow capture lifecycle and dry-run firewall actions | Partial: SMAppService/XPC helper implemented |
| `pigui-cli` | User | Headless management and diagnostics | Implemented |
| `pigui-firewall` | Library | Firewall backend trait and dry-run/PF placeholders | Partial |

The GUI never calls `pfctl` or Snort's control socket directly. The daemon owns
normalization and policy. The packaged helper owns privileged actions.

See [02-architecture.md](02-architecture.md) for the full component diagram and
crate boundaries.

## Data model in one paragraph

Snort emits alerts and protocol records. PIGUI tails those files, normalizes
them into SQLite, and joins them to OS snapshots by 5-tuple and time. Alert
destination IPs, Snort `conn`/`dns`/`ssl`/`http`/`quic` extractor records, and
`nettop` connection rows all feed the same endpoint, flow, connection, and
domain tables. Domains come from DNS answers, TLS/QUIC SNI, HTTP Host, optional
PTR lookups, and watched-domain resolution. Process attribution is best-effort
because Snort sees flows, not processes.

See [03-data.md](03-data.md) for sources, joins, precedence, and the actual
schema.

## Current working slice

Implemented today:

- Snort binary discovery and capability probing.
- Generated live Snort configuration with `alert_json`, extractor, and DNS
  response publishing.
- Alert and extractor JSONL ingestion into SQLite.
- `nettop` process/socket snapshots and 5-tuple joins.
- Destination/domain observations, trust state, PTR, and watched domains.
- Daemon Unix-socket RPC, CLI, and Tauri GUI tabs.
- Self-contained macOS app packaging with bundled Snort and dylibs.
- SMAppService/XPC helper, root-owned Snort payload staging, capture UI, and
  signed/notarized DMG workflow.

Not implemented today:

- Snort control-socket commands (build support exists; PIGUI client does not).
- Rule bundle management and policy evaluation.
- PF enforcement.
- Retention/rotation jobs and sensor stats.
- `/Applications` helper registration/approval verification.
- Linux and Windows adapters.

See [09-roadmap.md](09-roadmap.md) for milestone status.

## Platform reality

PIGUI is designed to be cross-platform. The constraints below describe the
current macOS implementation; Linux and Windows adapters are in progress.

These constraints are architectural requirements:

- Snort on macOS uses pcap/BPF passively. It detects and logs; it cannot drop
  packets inline.
- Enforcement on macOS is planned through PF, not Snort.
- Snort sees packets and flows, not processes. Attribution must come from the
  OS: `nettop`, `lsof`, `netstat`, or later a Network Extension.
- Snort's control socket exists only when built with `--enable-shell`.
- Domains are derived, not universal. A single IP can map to many domains and
  shared/CDN IPs are ambiguous.
- `app_id` is an application label, not a domain.
- Process attribution is best-effort for short-lived flows, UDP, and
  connections that close between polls.
- Native Windows Snort support is not a first-class build target. Assume WSL2,
  a container, or a remote Linux sensor until proven otherwise.

## Design decisions

Resolved:

- GUI: Rust + Tauri 2 with a Svelte frontend.
- Storage: SQLite first; GUI preferences use a separate GUI-local SQLite file.
- Cross-platform design; macOS is the current platform, with Linux and Windows
  in progress.
- PIGUI consumes Snort as an external process, not a linked library.
- Enforcement is firewall-based and off by default.
- PIGUI is GPLv2-compatible while it lives in the Snort 3 tree.

Open items are tracked in [09-roadmap.md](09-roadmap.md).

## Where to go next

- New user: [01-quickstart.md](01-quickstart.md)
- Contributor: [02-architecture.md](02-architecture.md),
  [03-data.md](03-data.md), [08-development.md](08-development.md)
- Snort build: [05-snort-compile.md](05-snort-compile.md)
- API consumer: [06-rpc-api.md](06-rpc-api.md)
- Security review: [07-security.md](07-security.md)
