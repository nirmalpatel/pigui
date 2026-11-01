# Security model

PIGUI separates presentation, ingestion, and privileged actions. Presentation
and ingestion are unprivileged. The packaged helper is a narrow root XPC service
that stages Snort into a root-owned payload, launches it, drops Snort to the
console user, and exposes only allowlisted capture and dry-run firewall actions.
Policy and PF enforcement remain planned.

## Privilege model

| Component | Privilege | Current behavior |
|---|---|---|
| `PIGUI.app` | User | Reads daemon state over the Unix socket |
| `pigui-daemon` | Unprivileged | Ingests logs, polls `nettop`, stores SQLite, serves RPC |
| Snort | Root | Passive capture through BPF; writes telemetry files |
| `pigui-helper` | Root | SMAppService LaunchDaemon; XPC; staged payload; audit; dry-run firewall |
| OS collectors | Daemon thread | Run as the daemon user; attribution is best-effort |

The daemon is deliberately unprivileged. Do not describe or deploy it as a root
service. Root is limited to Snort and the narrow helper.

## Trust boundaries

1. **Untrusted network input** → Snort. Parsing and detection happen in Snort.
2. **Snort output files** → daemon. Files are treated as untrusted input and
   parsed defensively; malformed records are skipped.
3. **OS collector output** → daemon. `nettop` and `ps` output is parsed into
   process and socket samples.
4. **GUI** → daemon. The GUI is an unprivileged RPC client.
5. **Daemon** → helper. Mach-service XPC only; fixed, allowlisted actions;
   code-signature validation in both directions.
6. **Daemon/GUI** → Snort. The GUI never talks to Snort. The daemon does not
   manage Snort either; the dev scripts start and stop it, and the daemon reads
   status from the PID file.

## Password handling

PIGUI never asks for, receives, logs, or stores a machine password. The app has
no password field and no password parameter in its RPC or XPC protocols. It does
not call `sudo`, `AuthorizationExecuteWithPrivileges`, `getpass`, or
`readpassphrase`.

Privilege is granted by the operating system:

- `SMAppService` registers the user daemon and the root helper.
- An administrator approves the LaunchDaemon in System Settings.
- If a future installer needs authorization, Apple Installer owns the password
  dialog.
- The helper receives only an allowlisted action; it never receives a
  credential.

A compromised operating system or a spoofed system dialog is outside PIGUI's
control, which is why onboarding tells users that PIGUI never asks for a
password. Users can revoke the background item at any time in System Settings.

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

The packaged helper verifies the XPC client code signature before accepting a
connection. It accepts only the signed daemon (`com.pigui.daemon`) and the
signed in-bundle diagnostic client (`com.pigui.helperctl`), both anchored to the
app's Developer ID team. The Unix socket still needs peer credential checks or a
move to XPC before it should be treated as a hardened boundary.

## Security requirements

Current:

- GUI is unprivileged.
- Daemon is unprivileged.
- Snort is root and managed as an external process.
- Local IPC only by default.
- The GUI cannot send arbitrary Lua or shell commands.
- Development state stays under `pigui/var/`.

Requirements:

- Helper exposes only fixed, allowlisted operations. Implemented.
- Helper runs from an SMAppService LaunchDaemon and validates XPC peers by code
  signature. Implemented.
- Helper stages Snort, dylibs, Lua, and rules into a root-owned read-only
  payload before execution. Implemented.
- Unix sockets use restrictive permissions and peer credential checks. Planned.
- Windows will use named pipes with ACLs. Planned.
- Rule changes and firewall actions are always audited. Privileged helper
  actions are audited now; rule changes are planned.
- Enforcement is dry-run by default. Implemented.
- Distribution builds are signed and notarized. Planned; packaging supports it.
- Helper installation uses SMAppService, not ad-hoc privilege escalation.
  Implemented.

## Release trust

Distribution uses a Developer ID Application signature, Hardened Runtime, and a
notarized, stapled app bundle and DMG. Gatekeeper should report `accepted` with
`source=Notarized Developer ID`. The app itself must be stapled, not only the
DMG, so launchd will accept the `SMAppService` LaunchDaemon.

The only Hardened Runtime exceptions are on the Snort binary:
`com.apple.security.cs.allow-jit` and
`com.apple.security.cs.allow-unsigned-executable-memory`, required by LuaJIT.
They are not applied to the app, daemon, or helper. PIGUI is distributed
outside the Mac App Store and does not use App Sandbox, because the root
LaunchDaemon and BPF capture are incompatible with the App Store sandbox model.

Notarization credentials live in the macOS Keychain. Certificates, private keys,
and app-specific passwords are never stored in the repository. A notarization
ticket applies only to the exact artifact that was submitted; every rebuilt
release must be notarized again.

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
