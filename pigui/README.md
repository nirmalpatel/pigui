# PIGUI

PIGUI is a system-level network security application built alongside Snort 3.
It combines Snort's detection telemetry with operating-system process
attribution, a local manager daemon, a privileged firewall helper, and a GUI
inspired by Activity Monitor.

Status: early implementation. Phase 1 (fixture ingestion) and Phase 2 (live
capture + process attribution) are implemented: the Rust workspace, Snort
discovery/capability probe, generated live Snort config, `alert_json` and
extractor ingestion into SQLite, nettop-based process/connection collection, a
local daemon API, the CLI, and a Tauri 2 + Svelte shell. PF enforcement, rule
bundles, and launchd packaging remain planned.

Target platform: macOS first. Linux and Windows are planned as later platform
adapters, not first-release requirements.

Current development environment:

- Snort 3.12.4.0 source tree
- macOS 15.5, arm64
- Rust 1.97 and Cargo
- Node.js 22
- Xcode 16.3 / Swift 6.1 available
- Tauri 2 chosen for the GUI
- SQLite intended for local storage

Verified parent Snort build on macOS 15.5 arm64:

- Binary: `../build/src/snort`
- Version: `3.12.4.0`
- Shell/control support: enabled (`--control-socket` is present)
- DAQ modules: `bpf`, `divert`, `dump`, `fst`, `pcap`, `savefile`, `trace`
- Hyperscan, Jemalloc, LZMA, OpenSSL 3, PCRE2, and LuaJIT enabled
- Configuration validation passes with `snort -c ../lua/snort.lua -T`
- Development uses this in-tree binary directly; no system-wide Snort
  installation is performed for now

## Relationship to Snort 3

PIGUI lives inside the Snort 3 repository on the `pigui` branch, but it is not
part of the Snort core build.

- PIGUI consumes Snort as an external service and process.
- PIGUI does not link against Snort C++ internals.
- PIGUI does not modify Snort source in its first working version.
- PIGUI is not added to the top-level Snort CMake build initially.
- Snort binaries and configuration are resolved from the parent repository or
  from a configured installation path.

Keeping this boundary explicit lets PIGUI evolve independently while remaining
compatible with upstream Snort changes.

## Vision

PIGUI should answer three operational questions quickly:

1. What is happening on this machine right now?
2. Which process is responsible for a connection or destination?
3. What should be done about it, safely and with an audit trail?

The primary GUI concept is an Activity Monitor-style process table joined with
Snort alerts, connection metadata, destination history, DNS/TLS/HTTP hostname
observations, and firewall state.

PIGUI is not a replacement for Snort. Snort remains the packet inspection and
detection engine. PIGUI is the management, correlation, presentation, and
enforcement layer.

## Goals

- Run Snort continuously as a managed system service.
- Ingest Snort alerts, connection records, domain observations, and stats.
- Correlate Snort flows and alerts with OS process and socket ownership.
- Present process-, connection-, destination-, and alert-oriented views.
- Manage versioned Snort rule bundles and policy metadata.
- Validate and activate rule changes safely with rollback.
- Integrate with PF on macOS for IP/port enforcement.
- Provide a privileged helper with a narrow, auditable action surface.
- Store historical events and aggregates locally.
- Provide a CLI for automation and headless diagnostics.
- Keep the architecture portable enough for Linux and Windows adapters later.

## Non-goals

- Inline packet dropping on macOS. Snort runs passively there.
- A kernel extension or full EndpointSecurity product in the first version.
- Replacing Snort's detection engine or rule language.
- Full packet capture as the primary UI.
- Cloud management or multi-device fleet control.
- Native Windows Snort support as a first-release deliverable.
- Process-aware network blocking in the first release.

## Platform Reality

These constraints are architectural requirements, not implementation details.

- Snort on macOS uses the pcap/BPF DAQ in passive mode. It can detect and log,
  but it cannot drop packets inline.
- Enforcement on macOS is performed by PF, not by Snort.
- Snort sees packets and flows, not processes. Process attribution must come
  from the OS: `nettop`, `lsof`, `netstat`, or later a Network Extension.
- Snort's control socket exists only when Snort is built with `--enable-shell`.
  Homebrew's Snort build does not enable it by default.
- Without the control socket, PIGUI falls back to signals, log files, and
  process supervision.
- Domains are not present in all Snort records. They must be derived from DNS
  responses, TLS SNI, HTTP Host, QUIC SNI, or external enrichment.
- `app_id` is an application label, not a domain name.
- Native Windows support in the Snort 3 tree is not a first-class build target.
  Windows plans should assume WSL2, a container, or a remote Linux sensor until
  proven otherwise.
- Linux can support inline Snort, but PIGUI defaults to passive Snort plus a
  firewall backend for cross-platform consistency.

## System Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│ PIGUI.app                                                   │
│ GUI, menu bar item, notifications, drill-down               │
│ Unprivileged, user session                                  │
└────────────────────────────┬────────────────────────────────┘
                             │ local RPC
┌────────────────────────────▼────────────────────────────────┐
│ pigui-daemon                                                 │
│ Ingestion, normalization, SQLite, policy engine, local API  │
│ Unprivileged system service                                  │
└───────────────┬───────────────────────────────┬─────────────┘
                │ local RPC                     │ files, control socket
┌───────────────▼──────────────┐   ┌────────────▼─────────────┐
│ pigui-helper                 │   │ Snort 3                  │
│ Root. PF/ufw actions only.   │   │ Root. Passive IDS.       │
│ No packet processing.        │   │ launchd-managed.         │
└───────────────┬──────────────┘   └────────────┬─────────────┘
                │                               │
        PF anchor/table                 alert_json, extractor,
                                        perf_monitor, flow dumps,
                                        control socket

┌─────────────────────────────────────────────────────────────┐
│ OS collectors                                                │
│ nettop, lsof, netstat, later Network Extension/eBPF/ETW     │
└─────────────────────────────────────────────────────────────┘
```

### Process and privilege model

| Process | Privilege | Responsibility |
|---|---|---|
| `PIGUI.app` | User | Presentation, search, drill-down, confirmations |
| `pigui-daemon` | Unprivileged system user | Ingestion, storage, policy, local API |
| `pigui-helper` | Root | Firewall operations and privileged service actions |
| Snort | Root | Packet inspection, alerts, flow/domain telemetry |
| OS collectors | Daemon worker or helper | Process/socket attribution |

The GUI never calls `pfctl` or Snort's control socket directly. The daemon owns
normalization and policy. The helper owns privileged actions.

## Planned Components

Rust workspace:

| Crate or app | Responsibility |
|---|---|
| `pigui-core` | Shared models, config, parsers, policy types, RPC types |
| `pigui-snort` | Snort discovery, config generation, control client, log tailers |
| `pigui-collector` | Process, socket, and destination attribution |
| `pigui-firewall` | Firewall backend traits and platform implementations |
| `pigui-daemon` | Ingestion, correlation, storage, API, policy engine |
| `pigui-helper` | Minimal privileged firewall and service-control helper |
| `pigui-cli` | Headless management, diagnostics, automation |
| `pigui-gui` | Tauri 2 GUI and Tauri Rust backend |

The exact crate split may change during scaffolding, but the boundaries should
remain: core data types, Snort adapter, collectors, storage/policy, privileged
helper, and GUI.

## Data Sources

PIGUI consumes multiple Snort outputs. Each has a different purpose and
freshness model.

| Source | Content | Use |
|---|---|---|
| `alert_json` | Alert events with signature, priority, IPs, ports, protocol, action, app_id, service | Incidents and triage |
| `extractor` `conn` | Connection records with originator/responder IPs and ports, duration, bytes, packets, state | Destination and flow history |
| `extractor` `dns` | DNS query, query type, response code, answers, TTLs | IP-to-domain mapping |
| `extractor` `ssl` | TLS SNI, version, certificate metadata, validation status | HTTPS hostname attribution |
| `extractor` `http` | Host, URI, method, user agent, status | HTTP destination context |
| `extractor` `quic` | QUIC SNI and client protocol | HTTP/3 attribution |
| `stream.dump_flows()` | Live flow-table snapshot with client/server IP and port, bytes, packets, TCP state, idle/uptime | Live connection detail |
| `perf_monitor` | Base, CPU, flow, and flow_ip aggregates | Trends, top talkers, host-pair analysis |
| `host_cache` / RNA | Host services, client information, OS awareness | Asset and host context |
| Control socket | Stats, reload, pause/resume, flow dumps | Management |
| Signals | Reload, stats dump, rotate, shutdown | Fallback for builds without shell |
| OS collectors | PID, process name, user, socket ownership, bytes | Process attribution |
| Firewall helper | Blocks, allowlists, TTLs, audit | Enforcement state |

### Destination visibility

Destination IP, port, and protocol are directly available from:

- `alert_json` for alerts
- `extractor` connection records
- `stream.dump_flows()`
- `perf_monitor` flow_ip
- packet logging, if enabled

Alerts alone are not enough to see all outgoing traffic. To see every tracked
connection, PIGUI must enable `extractor` connection events or poll flow dumps.

### Domain visibility

Domains are derived, not universally present:

- DNS responses provide query-to-answer mappings.
- TLS SNI provides the requested hostname for HTTPS.
- HTTP Host provides the hostname for plaintext HTTP.
- QUIC SNI provides the requested hostname for HTTP/3.
- Reverse DNS is a fallback and is often misleading for CDN and shared IPs.

Snort's DNS extractor requires `publish_response = true` in the `dns` module.
PIGUI should maintain its own DNS and hostname observation store because a
single IP can map to many domains and mappings change over time.

Planned Snort extractor shape:

```lua
dns = { publish_response = true }

extractor =
{
    formatting = 'json',
    connector = 'pigui_extractor',
    time = 'unix',
    protocols =
    {
        { service = 'conn', on_events = 'eof',
          fields = 'ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service conn_state duration orig_pkts resp_pkts orig_bytes resp_bytes' },
        { service = 'dns', on_events = 'response',
          fields = 'ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto query qtype_name rcode_name answers TTLs' },
        { service = 'ssl', on_events = 'tls_metadata_event',
          fields = 'ts uid id.orig_h id.orig_p id.resp_h id.resp_p server_name version validation_status subject issuer' },
        { service = 'http', on_events = 'eot',
          fields = 'ts uid id.orig_h id.orig_p id.resp_h id.resp_p method host uri user_agent status_code' },
        { service = 'quic', on_events = 'handshake',
          fields = 'ts uid id.orig_h id.orig_p id.resp_h id.resp_p server_name client_protocol' }
    }
}
```

The connector, file paths, and generated configuration are owned by PIGUI. The
parent Snort `lua/` directory is used as a source of defaults and templates,
not edited in place.

### Process attribution

The OS collector produces snapshots of process and socket ownership. PIGUI
joins those snapshots to Snort flows and alerts by 5-tuple and time.

macOS sources:

- `nettop` for process summaries and connection-level byte counters
- `lsof -nP -i` for current socket ownership
- `netstat -anv` for TCP/UDP connections with PID and byte counters

Attribution is best-effort for:

- short-lived flows
- UDP
- connections that close between polls
- traffic from other users when collection lacks privilege

A future macOS Network Extension could provide stronger attribution, but it is
not part of the first release.

## Data Flow

1. PIGUI daemon generates a Snort configuration and rule bundle under PIGUI's
   own state directory.
2. PIGUI validates the configuration with `snort -T`.
3. PIGUI activates the bundle atomically and asks Snort to reload through the
   control socket, a signal, or the service manager.
4. Snort writes alerts, extractor records, and perf files to PIGUI-owned paths.
5. PIGUI tails and parses the records into normalized local storage.
6. PIGUI collects process/socket snapshots and correlates them with flows and
   alerts.
7. PIGUI evaluates policy and records would-block or block decisions.
8. PIGUI asks the privileged helper to apply firewall changes when policy
   permits enforcement.
9. The GUI reads normalized state from the daemon API.

## Data Model

Initial SQLite schema, subject to change during scaffolding:

```text
processes
  pid, start_time, name, path, user, signing_id,
  bytes_in, bytes_out, risk_score, first_seen, last_seen

connections
  id, flow_id, pid, proto, client_ip, client_port,
  server_ip, server_port, state, bytes_ab, bytes_ba,
  packets_ab, packets_ba, start_time, last_seen,
  app_id, service, hostname, alert_count, block_state

flows
  flow_id, proto, client_ip, client_port, server_ip, server_port,
  tcp_state, bytes_ab, bytes_ba, packets_ab, packets_ba,
  idle_time, up_time, first_seen, last_seen

endpoints
  ip, hostname, asn, geo, first_seen, last_seen,
  bytes_in, bytes_out, connection_count, process_count,
  alert_count, reputation, blocked

alerts
  event_id, ts, gid, sid, rev, priority, class, msg,
  src_ip, src_port, dst_ip, dst_port, proto, action,
  app_id, service, pid, connection_id, rule, block_state

dns_observations
  ts, client_ip, query, qtype, rcode, answers, ttl

tls_observations
  ts, client_ip, server_ip, server_port, server_name,
  version, validation_status, subject, issuer

http_observations
  ts, client_ip, server_ip, server_port, method, host, uri,
  user_agent, status_code

firewall_actions
  id, ts, ip, direction, reason, rule, ttl, expires, actor, result

rule_bundles
  id, created_at, source, hash, active, validated, notes

sensor_stats
  ts, packets, drops, flows, cpu, memory, latency, daq_stats

audit_log
  id, ts, actor, action, target, details, result
```

Retention defaults:

- Raw alerts: 30 days
- Connection/flow detail: 7 days
- Aggregates: 90 days
- Audit log: at least 1 year
- Optional pcap ring buffer: size-bounded, disabled by default

SQLite with WAL is the first storage choice. If analytics volume grows, a
separate analytical store can be evaluated later.

## Rules and Policy

PIGUI owns the rule bundle lifecycle. Snort remains the rule execution engine.

Proposed bundle layout:

```text
rules/
├── bundles/
│   └── <bundle-id>/
│       ├── snort.rules
│       ├── policy.toml
│       └── manifest.toml
└── active -> bundles/<bundle-id>
```

Requirements:

- Bundles are versioned and content-hashed.
- `snort.rules` uses native Snort rule syntax.
- `policy.toml` maps rule IDs to PIGUI actions.
- `manifest.toml` records source, creation time, and validation status.
- Every candidate bundle is validated with `snort -T` before activation.
- Activation is atomic.
- A failed reload restores the last known good bundle.
- Every rule change is audited.
- The first release defaults to alert-only and dry-run enforcement.
- If the ruleset is authored in a custom DSL, a compilation step to Snort
  rules must be added before activation.

Policy actions:

| Action | Meaning |
|---|---|
| `ignore` | Store or drop the event without surfacing it |
| `alert` | Surface the event, no enforcement |
| `block_src` | Block the source IP for a TTL |
| `block_dst` | Block the destination IP for a TTL |
| `quarantine` | Apply a stronger temporary block policy |
| `manual` | Require operator confirmation |

## Firewall Integration

PIGUI enforces with platform firewalls, not by making Snort inline.

macOS:

- Own PF anchor and table.
- Do not rewrite the system-wide `pf.conf`.
- Prefer table-based IP blocking for fast updates.
- Apply TTLs and maximum table sizes.
- Record every action in the audit log.

Ubuntu and Linux later:

- Start with `ufw` for a simple backend.
- Add `nftables` or `ipset` for high-rate dynamic blocking.
- Keep the same firewall trait and action model.

Windows later:

- Use Windows Defender Firewall or WFP.
- Treat native Windows Snort as a separate research track.

Important distinction:

- PF, ufw, and nftables block IP/port traffic.
- They do not natively block a process.
- Process-aware blocking requires a different backend: a macOS Network
  Extension, Linux cgroups/eBPF, or Windows WFP/program rules.

PIGUI must state clearly in the UI whether an action blocks a destination or a
process.

Safety requirements:

- Alert-only by default.
- Dry-run mode for all enforcement.
- Allowlist loopback, gateway, DNS/DHCP, management, SSH/RDP, and update hosts.
- TTL-based blocks with automatic expiry.
- Maximum block count and rate.
- Rollback and flush operations.
- Confirmation for destructive actions.
- Audit actor, rule, reason, and result.

## GUI

The GUI is a Tauri 2 application with a Rust backend and a Svelte frontend.
The shell uses a responsive, full-width flex layout: headers and status bars
stay fixed while content panels and tables grow to fill the window, with
breakpoints for smaller windows. The theme switch supports System, Light, and
Dark; the selection is persisted in a GUI-local SQLite database
(`var/lib/pigui-gui.db` in development, the Tauri app-data directory in release)
and cached in `localStorage` so the correct theme is applied before mount.

Primary views:

| View | Purpose |
|---|---|
| Overview | Health, throughput, drops, alerts, top processes, top destinations |
| Processes | Activity Monitor-style process list with traffic and risk |
| Connections | Live connection/flow table with process attribution |
| Destinations | Remote endpoints, domains, bytes, processes, alerts, block state |
| Alerts | Triage, severity, rule, process, destination, actions |
| Rules | Bundles, validation, activation, hit counts, rollback |
| Firewall | Blocks, TTLs, allowlist, dry-run state, audit |
| Timeline | Alerts, new flows, new destinations, blocks, reloads |
| Health | Snort, daemon, helper, collectors, storage, log rotation |

Key interactions:

- Sort and filter like Activity Monitor.
- Expand a process to see its connections and destinations.
- Drill from an alert to the process and destination.
- Drill from a destination to all processes and alerts.
- Show "would block" versus "blocked" clearly.
- Confirm all enforcement actions.
- Surface degraded modes when Snort, the control socket, or the helper is
  unavailable.

## Security Model

- GUI is unprivileged.
- Daemon is unprivileged and owns normalization, storage, and policy.
- Helper is privileged and exposes only fixed, allowlisted operations.
- Snort is root and is managed by the OS service manager.
- Local IPC only; no TCP listener by default.
- Unix domain sockets use restrictive permissions and peer credential checks.
- Windows will use named pipes with ACLs.
- The GUI cannot send arbitrary Lua or shell commands.
- Rule changes and firewall actions are always audited.
- Enforcement is dry-run by default.
- Distribution builds must be signed and notarized; helper installation must
  be designed with the macOS service APIs rather than ad-hoc privilege
  escalation.

## Platform Support

| Platform | Snort mode | Enforcement | Process attribution | Status |
|---|---|---|---|---|
| macOS 14+ | Passive pcap/BPF | PF | nettop/lsof/netstat | First target |
| Linux | Passive first, inline optional | ufw/nftables | ss/proc/eBPF | Later |
| Windows | Native support uncertain | Defender Firewall/WFP | GetExtendedTcpTable/ETW | Research |

macOS is the first and only supported platform for the first release.

## Repository Layout

```text
pigui/
├── README.md
├── .gitignore
├── Cargo.toml
├── crates/
│   ├── pigui-core/
│   ├── pigui-snort/
│   ├── pigui-collector/
│   ├── pigui-firewall/
│   ├── pigui-daemon/
│   ├── pigui-helper/
│   └── pigui-cli/
├── apps/
│   └── pigui-gui/
├── config/
│   ├── snort/
│   └── rules/
├── packaging/
│   ├── macos/
│   │   ├── LaunchDaemons/
│   │   ├── LaunchAgents/
│   │   └── scripts/
│   ├── linux/
│   └── windows/
├── scripts/
│   ├── build-snort.sh
│   ├── dev-env.sh
│   ├── run-dev.sh
│   └── install-macos.sh
└── tests/
    └── fixtures/
```

Not all paths exist yet. The first implementation commit should create the Rust
workspace and Tauri shell.

## Development Contract with Parent Snort

PIGUI resolves the Snort binary in this order:

1. `PIGUI_SNORT_BIN`
2. `../build/src/snort` for an in-tree development build
3. `../install/bin/snort`
4. `/usr/local/snort/bin/snort`
5. `snort` in `PATH`
6. Homebrew Snort, with a warning that the control socket may be unavailable

PIGUI configuration environment variables:

```text
PIGUI_SNORT_BIN
PIGUI_SNORT_CONFIG
PIGUI_SNORT_LUA_PATH
PIGUI_RUN_DIR
PIGUI_LOG_DIR
PIGUI_DB_PATH
```

Development defaults are recorded in `.env.example`. Copy it to `.env` when
needed; `.env` is ignored by git.

Verified parent Snort build for macOS development:

```bash
export HOMEBREW_PREFIX="$(brew --prefix)"
export PATH="$HOMEBREW_PREFIX/opt/flex/bin:$PATH"
export PKG_CONFIG_PATH="$HOMEBREW_PREFIX/opt/libpcap/lib/pkgconfig:$HOMEBREW_PREFIX/opt/libdnet/lib/pkgconfig:$HOMEBREW_PREFIX/opt/daq/lib/pkgconfig:$HOMEBREW_PREFIX/opt/luajit/lib/pkgconfig:$HOMEBREW_PREFIX/opt/hwloc/lib/pkgconfig:$HOMEBREW_PREFIX/opt/openssl@3/lib/pkgconfig:$HOMEBREW_PREFIX/opt/pcre2/lib/pkgconfig:$HOMEBREW_PREFIX/opt/vectorscan/lib/pkgconfig:$HOMEBREW_PREFIX/opt/jemalloc/lib/pkgconfig:$HOMEBREW_PREFIX/opt/xz/lib/pkgconfig"
export CMAKE_PREFIX_PATH="$HOMEBREW_PREFIX/opt/libpcap:$HOMEBREW_PREFIX/opt/libdnet:$HOMEBREW_PREFIX/opt/daq:$HOMEBREW_PREFIX/opt/luajit:$HOMEBREW_PREFIX/opt/hwloc:$HOMEBREW_PREFIX/opt/openssl@3:$HOMEBREW_PREFIX/opt/pcre2:$HOMEBREW_PREFIX/opt/vectorscan:$HOMEBREW_PREFIX/opt/jemalloc:$HOMEBREW_PREFIX/opt/xz"

./configure_cmake.sh \
  --prefix=/usr/local/snort \
  --enable-shell \
  --enable-jemalloc \
  --disable-docs \
  --with-openssl="$HOMEBREW_PREFIX/opt/openssl@3" \
  --with-flex-prefix="$HOMEBREW_PREFIX/opt/flex" \
  --with-pcap-includes="$HOMEBREW_PREFIX/opt/libpcap/include" \
  --with-pcap-libraries="$HOMEBREW_PREFIX/opt/libpcap/lib" \
  --with-daq-includes="$HOMEBREW_PREFIX/opt/daq/include" \
  --with-daq-libraries="$HOMEBREW_PREFIX/opt/daq/lib" \
  --with-dnet-includes="$HOMEBREW_PREFIX/opt/libdnet/include" \
  --with-dnet-libraries="$HOMEBREW_PREFIX/opt/libdnet/lib" \
  --with-luajit-includes="$HOMEBREW_PREFIX/opt/luajit/include/luajit-2.1" \
  --with-luajit-libraries="$HOMEBREW_PREFIX/opt/luajit/lib" \
  --with-pcre2-includes="$HOMEBREW_PREFIX/opt/pcre2/include" \
  --with-pcre2-libraries="$HOMEBREW_PREFIX/opt/pcre2/lib" \
  --with-hyperscan-includes="$HOMEBREW_PREFIX/opt/vectorscan/include" \
  --with-hyperscan-libraries="$HOMEBREW_PREFIX/opt/vectorscan/lib"

# Homebrew's jemalloc and xz headers are outside the default include search.
cmake -S . -B build \
  -DCMAKE_CXX_FLAGS="-I$HOMEBREW_PREFIX/opt/jemalloc/include -I$HOMEBREW_PREFIX/opt/xz/include" \
  -DCMAKE_C_FLAGS="-I$HOMEBREW_PREFIX/opt/jemalloc/include -I$HOMEBREW_PREFIX/opt/xz/include"

cd build
make -j"$(sysctl -n hw.ncpu)"
./src/snort -V
./src/snort -c ../lua/snort.lua -T
```

PIGUI must detect whether the selected Snort supports the control socket. If
it does not, PIGUI enters signal/file-only mode and reports the reduced
capability in the GUI.

Current decision: PIGUI does not install Snort system-wide. The canonical Snort
binary for the development phase is `../build/src/snort`, or the path supplied
through `PIGUI_SNORT_BIN`. The system Snort installation, launchd-managed Snort
service, and production packaging are deferred until PIGUI has a working local
prototype.

## Runtime Paths

Proposed macOS production paths:

```text
/Applications/PIGUI.app
/Library/PrivilegedHelperTools/com.pigui.helper
/Library/LaunchDaemons/com.pigui.snort.plist
/Library/LaunchDaemons/com.pigui.daemon.plist
/Library/LaunchDaemons/com.pigui.helper.plist
/Library/Application Support/PIGUI/
/Library/Logs/PIGUI/
/var/run/pigui/
```

The paths above are production proposals only. During the current phase PIGUI
uses `../build/src/snort` and keeps runtime state under `pigui/var/`.
Development paths must not require writing to the parent Snort source tree.

## Milestones

| Milestone | Deliverable | Status |
|---|---|---|
| M0 | Branch, README, architecture, repository guardrails | Complete |
| M1 | Rust workspace and Tauri scaffold | Complete |
| M2 | Core models, config, SQLite schema, fixture parsers | Partial: alerts/destinations schema and parser complete |
| M3 | Snort discovery, config generation, control adapter, log ingestion | Partial: live config generation, alert/extractor ingestion complete; control adapter pending |
| M4 | macOS process/socket collector and correlation | Partial: nettop collector and tuple joins complete; Network Extension later |
| M5 | Rule bundle manager and validation pipeline | Planned |
| M6 | PF helper in dry-run mode | Planned |
| M7 | Daemon API and GUI MVP | Partial: live processes/connections/destinations/alerts API and tabs complete |
| M8 | launchd packaging and macOS system integration | Planned |
| M9 | Hardening, retention, audit, tests, documentation | Planned |
| M10 | Linux/ufw/nftables and Windows research | Later |

## Risks

- Snort on macOS is passive; PIGUI can detect, but PF does the enforcement.
- Process attribution by polling is imperfect, especially for short flows and
  UDP.
- Domains are ambiguous for shared/CDN IPs and hidden DNS.
- Snort control-socket commands are not a stable public ABI.
- Log volume can grow quickly; retention and rotation are required from day one.
- The privileged helper is the highest-risk component and must remain narrow.
- Native Windows Snort support is uncertain.
- Living inside the Snort 3 repository has GPLv2 implications.
- Tauri does not provide native AppKit controls; a SwiftUI shell may be added
  later if needed without changing the daemon protocol.

## Decisions

Resolved:

- GUI stack: Rust + Tauri 2 with a Svelte frontend.
- Storage: SQLite first; GUI preferences use a separate GUI-local SQLite database.
- macOS first; Linux and Windows later.
- PIGUI consumes Snort as an external process, not a linked library.
- Snort control socket is preferred for management, with signal/file fallback.
- Enforcement is firewall-based and off by default.
- PIGUI is GPLv2-compatible for now because it lives in the Snort 3 tree.

Still open:

- Minimum macOS version. Current proposal: macOS 14+.
- Whether the daemon and helper are separate binaries in the first milestone or
  start as one development-only service and split before release.
- Whether process-aware blocking is a later Network Extension effort.
- Whether the ruleset is native Snort syntax or a custom DSL requiring a
  compiler.
- Windows native sensor versus WSL2/container/remote Linux sensor.
- Distribution and notarization workflow.

## License

PIGUI is intended to be GPLv2-compatible while it lives inside the Snort 3
repository. Confirm the final licensing and distribution model before any
closed-source distribution or separate commercial packaging.

## Phase 1 Quick Start

Phase 1 implements the first runnable vertical slice without touching the
parent Snort build:

1. Resolve the parent Snort binary, defaulting to `../build/src/snort` without
   installing Snort system-wide.
2. Tail one `alert_json` fixture.
3. Normalize alerts into SQLite.
4. Display alerts and destinations in a minimal Tauri window.
5. Report Snort capability status, including whether the control socket exists.

```bash
cd pigui
cp .env.example .env        # optional; scripts fall back to .env.example

./scripts/probe-snort.sh    # resolve Snort and print capabilities
./scripts/run-dev.sh        # daemon on the fixture, then the Tauri window
```

Headless checks:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

./target/debug/pigui-cli ingest \
  --file tests/fixtures/alert_json/valid.jsonl

./target/debug/pigui-daemon \
  --alerts-file tests/fixtures/alert_json/valid.jsonl

# in another shell
./target/debug/pigui-cli status
./target/debug/pigui-cli alerts --limit 10
./target/debug/pigui-cli destinations --limit 10
```

The daemon replays the alert file from the beginning on startup and relies on
the SQLite dedupe index, so restarting it does not duplicate events. Use
`--from-end` to skip existing content.

## Phase 2 Quick Start — Live Capture

Live capture uses a PIGUI-generated Snort configuration, the extractor JSONL
file, and the macOS `nettop` collector. Snort needs `sudo` for BPF access;
metadata only is stored (no packet payloads).

```bash
cd pigui
./scripts/run-live.sh
```

This requests sudo credentials, validates the generated Snort config, starts
Snort on `en0`, starts the daemon with `var/lib/pigui-live.db`, and opens the
Tauri window. Useful commands:

```bash
./scripts/snort-live.sh          # run Snort in the foreground
./scripts/stop-live.sh           # stop Snort and the daemon

./target/debug/pigui-cli snort generate-config
./target/debug/pigui-cli snort status
./target/debug/pigui-cli flows --limit 20
./target/debug/pigui-cli processes --limit 20
./target/debug/pigui-cli connections --limit 20
```

Live data comes from two sources:

- `nettop` snapshots provide active connections, process names, PIDs, and byte
  counters every second.
- Snort extractor records provide completed `conn` events and DNS/TLS/HTTP/QUIC
  metadata used to enrich destinations and completed connections.

Expected limits: passive capture only sees this Mac's traffic, not other LAN
devices; HTTPS hostnames come from SNI/DNS, not payload decryption; short-lived
flows and process attribution are best-effort.
