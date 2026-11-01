# Security model

PIGUI separates presentation, ingestion, and privileged actions. The current
implementation only has unprivileged presentation and ingestion plus a
root-run Snort process. The helper, policy engine, and firewall enforcement are
planned.

## Privilege model

| Component | Privilege | Current behavior |
|---|---|---|
| `PIGUI.app` | User | Reads daemon state over the Unix socket |
| `pigui-daemon` | Unprivileged | Ingests logs, polls `nettop`, stores SQLite, serves RPC |
| Snort | Root | Passive capture through BPF; writes telemetry files |
| `pigui-helper` | Root | Planned; currently a stub that prints a message |
| OS collectors | Daemon thread | Run as the daemon user; attribution is best-effort |

The daemon is deliberately unprivileged. Do not describe or deploy it as a root
service. Root is limited to Snort and, later, the narrow helper.

## Trust boundaries

1. **Untrusted network input** → Snort. Parsing and detection happen in Snort.
2. **Snort output files** → daemon. Files are treated as untrusted input and
   parsed defensively; malformed records are skipped.
3. **OS collector output** → daemon. `nettop` and `ps` output is parsed into
   process and socket samples.
4. **GUI** → daemon. The GUI is an unprivileged RPC client.
5. **Daemon** → helper (planned). Only fixed, allowlisted privileged actions.
6. **Daemon/GUI** → Snort. The GUI never talks to Snort. The daemon does not
   manage Snort either; the dev scripts start and stop it, and the daemon reads
   status from the PID file.

## Local IPC

Current daemon socket:

- Unix domain socket only.
- No TCP listener.
- Parent directory mode `0700`.
- Socket mode `0600`.
- Newline-delimited JSON.
- `shutdown` is exposed to any client that can open the socket.

Current gaps:

- No peer credential check (`SO_PEERCRED`/`LOCAL_PEERCRED` equivalent).
- No per-method authorization.
- No request authentication.

These must be addressed before the helper is added. The planned helper should
verify the daemon's identity and authorize only its documented action surface.

## Security requirements

Current:

- GUI is unprivileged.
- Daemon is unprivileged.
- Snort is root and managed as an external process.
- Local IPC only by default.
- The GUI cannot send arbitrary Lua or shell commands.
- Development state stays under `pigui/var/`.

Planned:

- Helper exposes only fixed, allowlisted operations.
- Unix sockets use restrictive permissions and peer credential checks.
- Windows will use named pipes with ACLs.
- Rule changes and firewall actions are always audited.
- Enforcement is dry-run by default.
- Distribution builds are signed and notarized.
- Helper installation uses the macOS service APIs, not ad-hoc privilege
  escalation.

## Rules and policy

Status: **planned**. Snort remains the rule execution engine. PIGUI will own the
bundle lifecycle.

Proposed layout:

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
- A custom DSL, if added, must compile to Snort rules before activation.

Planned policy actions:

| Action | Meaning |
|---|---|
| `ignore` | Store or drop the event without surfacing it |
| `alert` | Surface the event, no enforcement |
| `block_src` | Block the source IP for a TTL |
| `block_dst` | Block the destination IP for a TTL |
| `quarantine` | Apply a stronger temporary block policy |
| `manual` | Require operator confirmation |

There is no policy engine, rule bundle store, or activation pipeline in the
current code.

## Firewall enforcement

Status: **planned**. The `pigui-firewall` crate currently contains types, a
dry-run backend, and a PF placeholder that returns `NotImplemented`.

macOS plan:

- Own a PF anchor and table.
- Do not rewrite the system-wide `pf.conf`.
- Prefer table-based IP blocking for fast updates.
- Apply TTLs and maximum table sizes.
- Record every action in the audit log.

Linux plan:

- Start with `ufw` for a simple backend.
- Add `nftables` or `ipset` for high-rate dynamic blocking.
- Keep the same firewall trait and action model.

Windows plan:

- Windows Defender Firewall or WFP.
- Native Windows Snort remains a separate research track.

Important distinction:

- PF, ufw, and nftables block IP/port traffic.
- They do not natively block a process.
- Process-aware blocking requires a macOS Network Extension, Linux
  cgroups/eBPF, or Windows WFP/program rules.
- The UI must state clearly whether an action blocks a destination or a
  process.

## Enforcement safety

These are requirements for the planned implementation, not current behavior:

- Alert-only by default.
- Dry-run mode for all enforcement.
- Allowlist loopback, gateway, DNS/DHCP, management, SSH/RDP, and update hosts.
- TTL-based blocks with automatic expiry.
- Maximum block count and rate.
- Rollback and flush operations.
- Confirmation for destructive actions.
- Audit actor, rule, reason, and result.

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
