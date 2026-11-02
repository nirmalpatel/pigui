# Architecture

PIGUI is a Rust workspace plus a Tauri GUI. It consumes Snort as an external
process. Snort, the daemon, the GUI, and the planned helper are separate trust
domains.

## Process and privilege model

| Process | Privilege | Responsibility | Status |
|---|---|---|---|
| `PIGUI.app` | User | Presentation, search, drill-down, confirmations | Implemented |
| `pigui-daemon` | Unprivileged | Ingestion, storage, policy, local API | Implemented |
| `pigui-helper` | Root | Capture lifecycle, staged Snort payload, audit, dry-run firewall actions | Partial: SMAppService/XPC helper implemented |
| Snort 3 | Root | Packet inspection, alerts, flow/domain telemetry | Implemented |
| OS collectors | Daemon thread | Process/socket attribution | Partial: macOS collector implemented |

The GUI never calls `pfctl`, Snort, or the helper directly. The daemon owns
normalization and policy. The helper owns privileged actions. The daemon itself
is unprivileged. Development scripts use `sudo` to launch Snort; the packaged
app uses SMAppService and XPC instead and never asks PIGUI for a password.

```text
┌─────────────────────────────────────────────────────────────┐
│ PIGUI.app                                                   │
│ Tauri 2 + Svelte, unprivileged user session                 │
└────────────────────────────┬────────────────────────────────┘
                             │ Unix-socket JSON-RPC
┌────────────────────────────▼────────────────────────────────┐
│ pigui-daemon                                                │
│ tailers, collector, SQLite, RPC API, policy (planned)       │
│ Unprivileged                                                │
└──────────┬──────────────────────────────┬───────────────────┘
           │ planned RPC                  │ files / logs
┌──────────▼──────────────┐   ┌───────────▼──────────────────┐
│ pigui-helper (planned)  │   │ Snort 3                      │
│ Root. PF/ufw only.      │   │ Root. Passive IDS.           │
└──────────┬──────────────┘   └───────────┬──────────────────┘
           │                              │ alert_json, extractor
   PF anchor/table (planned)              │ perf/flow dumps (planned)
                                          │
┌─────────────────────────────────────────▼───────────────────┐
│ OS collectors: nettop, ps (current); lsof/netstat/future    │
│ Network Extension, eBPF, ETW                                │
└─────────────────────────────────────────────────────────────┘
```

## Crate boundaries

| Crate or app | Responsibility |
|---|---|
| `pigui-core` | Shared models, configuration, bundle/release paths, RPC types, domain normalization, GUI settings types, Unix socket client, helper and service bridges |
| `pigui-snort` | Snort discovery, capability probe, config generation, process status, file tailer |
| `pigui-collector` | Collector trait, macOS `nettop` collector and parser, `ps` metadata enrichment |
| `pigui-firewall` | Firewall traits and block request/outcome types; dry-run backend; PF placeholder |
| `pigui-daemon` | Ingestion, correlation, SQLite store, RPC server, background tasks |
| `pigui-helper` | Placeholder crate; the packaged helper is Swift under `packaging/macos/helper` |
| `pigui-cli` | Headless management, diagnostics, test fixture ingestion |
| `pigui-gui` | Tauri Rust commands and Svelte frontend |

Dependency direction is one-way: `pigui-core` is the base, `pigui-snort` and
`pigui-collector` depend on it, `pigui-daemon` composes them, and the CLI and
GUI consume the daemon over RPC. `pigui-gui` also links `pigui-core` for the
client and settings types.

## Current repository layout

```text
pigui/
├── README.md
├── .env.example
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── rustfmt.toml
├── apps/
│   └── pigui-gui/
│       ├── index.html
│       ├── package.json
│       ├── src/                 # Svelte frontend
│       ├── src-tauri/           # Tauri Rust backend
│       └── dist/                # generated frontend build
├── config/
│   └── snort/
│       └── pigui.lua            # documented telemetry overrides
├── crates/
│   ├── pigui-core/
│   ├── pigui-snort/
│   ├── pigui-collector/
│   ├── pigui-firewall/
│   ├── pigui-daemon/
│   ├── pigui-helper/
│   └── pigui-cli/
├── docs/
├── packaging/
│   └── macos/                  # app bundle, Snort bundling, helper, signing
│       └── releases/           # signed release records and checksums
├── scripts/
│   ├── check-telemetry.sh
│   ├── dev-env.sh
│   ├── probe-snort.sh
│   └── run-dev.sh
├── tests/
│   └── fixtures/
│       ├── alert_json/
│       └── extractor/
└── var/                         # runtime state, ignored by git
```

`packaging/macos` now exists and builds `PIGUI.app`, bundles Snort and its
dylibs, and installs the helper and daemon plists. Linux/Windows packaging, a
rule bundle directory, and a checked-in Snort build script are still planned.

## Runtime paths

Development uses paths under `pigui/var/` and reads Snort from the parent tree:

```text
../build/src/snort                 # default Snort binary
../lua/snort.lua                   # source config
var/run/pigui-daemon.sock          # daemon RPC socket
var/lib/pigui.db                   # dev and prod database
var/lib/pigui-gui.db               # GUI preferences
var/snort/snort.lua                # generated Snort config
var/snort/snort_defaults.lua       # copied defaults
var/log/snort/                     # alert/extractor/pid/log output
var/log/snort/file_connector_pigui_transmit
```

macOS production paths:

```text
/Applications/PIGUI.app
PIGUI.app/Contents/Library/LaunchAgents/com.pigui.daemon.plist
PIGUI.app/Contents/Library/LaunchDaemons/com.pigui.helper.plist
~/Library/Application Support/PIGUI/
/Library/Application Support/PIGUI/payload/<payload-id>/
/Library/Logs/PIGUI/audit.log
```

The helper and daemon are registered with `SMAppService`; no privileged helper
is installed under `/Library/PrivilegedHelperTools`.

Development must not write into the parent Snort source tree.

## Data flow

Current implemented flow:

1. The daemon probes Snort and reports capabilities.
2. `snort generate-config` copies the parent `lua/snort.lua` and
   `snort_defaults.lua`, appends PIGUI extractor/logging overrides, copies rule
   files, and validates the result with `snort -T`.
3. Snort writes `alert_json.txt` and the extractor JSONL file under PIGUI's
   state directory.
4. The daemon tails both files, parses records, and writes to SQLite.
5. A background thread polls `nettop`, enriches processes with `ps`, and
   writes live flows and process rows.
6. Another background thread performs PTR lookups and watched-domain
   resolution.
7. The daemon serves normalized state over a Unix socket.
8. The GUI and CLI query the daemon.

Planned flow additions:

1. Rule bundle creation, validation, atomic activation, and rollback.
2. Policy evaluation producing alert, block, quarantine, or manual decisions.
3. Privileged helper calls to apply PF/ufw/nftables changes.
4. Audit log, retention jobs, and sensor statistics.

The current code does not invoke the helper, apply firewall rules, evaluate
policy, or manage rule bundles.

## Boundaries to preserve

- PIGUI must remain independent of Snort C++ internals.
- The GUI must not execute shell commands or arbitrary Lua.
- The daemon must not require root.
- The helper must expose a fixed, allowlisted action surface.
- Generated files belong under PIGUI's state directory, never upstream source
  directories.
- Platform adapters stay behind traits so macOS, Linux, and Windows can differ
  without changing the RPC model.
