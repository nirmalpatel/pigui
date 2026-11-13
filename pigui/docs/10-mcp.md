# MCP analysis interface

Status: **implemented**. `pigui-mcp` exposes read-only PIGUI telemetry to MCP
clients such as OpenCode. It is an observation interface, not an enforcement
interface.

## Architecture

```text
OpenCode / model
      |
      | MCP over stdio (newline-delimited JSON-RPC)
      v
pigui-mcp (unprivileged, read-only)
      |
      | DaemonClient -> Unix-domain socket
      v
pigui-daemon (unprivileged)
      |
      | SQLite, ingestion tasks, collectors
      v
PIGUI database, Snort telemetry files, nettop/ps
```

Hard boundaries:

- `pigui-mcp` never opens SQLite or reads Snort files directly.
- It never executes shell commands, calls the privileged helper, or listens on
  TCP.
- It only calls allowlisted read-only daemon methods. Unknown methods fail
  closed and there is no raw-RPC tool.
- All logs go to stderr. Stdout is reserved for MCP frames.
- It cannot start/stop capture, change settings, alter trust, modify firewall
  state, prune data, or shut down the daemon.

`capture.status` is intentionally not exposed because its daemon handler can
clear stale capture state. The `status` tool uses `status`, `health`, and
`snort.status` instead.

## Setup

```bash
cd pigui
cargo build -p pigui-mcp
```

The repository-root `opencode.json` starts the server through
`pigui/scripts/run-mcp.sh`. OpenCode 1.19.2 opens local servers with the legacy
`initialize` handshake, so `pigui-mcp` uses the MIT-licensed `rust-mcp-sdk`
2025-11-25 compatibility line. The project config intentionally keeps only
fields the installed OpenCode applies. Restart OpenCode after changing the
config, then:

```bash
opencode mcp list
```

Expect `pigui connected`. The security review is available as:

```text
/pigui-security-review "last 24 hours"
```

The MCP server also exposes a `security_review` prompt, which OpenCode names
`/pigui:security_review`.

For a global OpenCode configuration, add the same server entry under
`~/.config/opencode/opencode.json` and point `cwd` at the absolute PIGUI
directory. The project configuration remains the recommended default.

## Tools

| Tool | Purpose |
|---|---|
| `pigui_status` | Capture, Snort, health, coverage, and degraded reasons |
| `pigui_overview` | Time-windowed traffic aggregates and coverage |
| `pigui_findings` | Evidence-based intruder-hunt leads |
| `pigui_alerts` | Alert drill-down |
| `pigui_destinations` | Destination drill-down |
| `pigui_destination_detail` | One IP with processes and recent alerts |
| `pigui_flows` | Live flows |
| `pigui_processes` | Process inventory |
| `pigui_process_detail` | One PID with destinations |
| `pigui_connections` | Completed connections |
| `pigui_domains` | Registrable-domain summaries |
| `pigui_dns` | DNS observations |
| `pigui_tls` | TLS/SNI observations |
| `pigui_http` | HTTP observations |
| `pigui_quic` | QUIC observations |
| `pigui_watched_domains` | Watchlist status |
| `pigui_maintenance` | Database size, row counts, retention evidence |
| `pigui_firewall_summary` | Read-only enforcement context |

All tools set `readOnlyHint: true`, `destructiveHint: false`,
`idempotentHint: true`, and `openWorldHint: false`.

Most list tools accept `{limit, offset, q, sort, dir}`. `domains` also accepts
`trust=all|unknown|trusted|suspicious|ignored|needs_review`. Detail tools
require `{ip}` or `{pid}`. Analysis tools accept
`{since, until, limit, min_severity, include_noise, baseline}`.

## Output contract

- Default list rows: 50.
- Hard row cap: `PIGUI_MCP_MAX_ROWS` (default 200).
- Hard response cap: `PIGUI_MCP_MAX_BYTES` (default 65536 bytes of JSON text).
- Rows and bytes are clipped rather than rejected; results set `truncated`.
- `total` and `returned` are included where the daemon provides totals.
- Unix timestamps are accompanied by ISO-8601 UTC fields.
- Control characters are sanitized. Long hostnames, URIs, and user agents are
  truncated.
- OS usernames are replaced with `<redacted>` by default. Process names, paths,
  PIDs, IPs, ports, domains, and timestamps are preserved for attribution.
- Errors are returned as MCP tool errors (`isError: true`) so the model can
  recover. Daemon connection errors include the socket guidance.

Environment controls:

| Variable | Default | Purpose |
|---|---|---|
| `PIGUI_MCP_MAX_ROWS` | `200` | Hard row cap |
| `PIGUI_MCP_MAX_BYTES` | `65536` | Hard JSON text cap |
| `PIGUI_MCP_REDACT_USERS` | `1` | Replace usernames with `<redacted>` |
| `PIGUI_MCP_INCLUDE_NOISE` | `0` | Set to `1` to include noise evidence by default |
| `RUST_LOG` | `warn` | Stderr logging filter |

## Analysis RPC

The daemon exposes two read-only methods used by the MCP analysis tools:

- `analysis.overview`: windowed totals, top processes/destinations/domains,
  alert breakdown, protocol/port distribution, trust breakdown, new domains,
  noise suppression, and optional baseline comparison.
- `analysis.findings`: heuristic leads with severity, confidence, evidence,
  first/last seen, and suggested drill-down tools.

Defaults:

- Window: last 24 hours.
- Maximum window: 30 days, clamped with a limitation.
- Finding limit: 20, maximum 100.
- Noise: multicast, broadcast, loopback, link-local, and noisy SID `116:444`
  are suppressed unless requested.
- Baseline: `analysis.overview` compares with the immediately preceding
  equal-length window. `analysis.findings` remains window-based and reports this
  as a limitation.

Finding categories include high-priority alert clusters, unknown-trust egress,
new-domain egress, no-domain/direct-IP traffic, rare ports, outbound-heavy
transfers, beaconing, fan-out, DNS tunneling indicators, invalid TLS, path and
user anomalies, and new process egress.

Findings are leads, not verdicts. Every finding includes evidence and a
confidence value. Beaconing and DNS tunneling heuristics are intentionally
noisy and should be validated with drill-down tools.

## Privacy and limitations

Tool results contain network metadata and may be sent to the configured model
provider for inference. Usernames are redacted by default; process paths and
network identifiers are preserved because they are useful for attribution.

The interface cannot inspect packet payloads, decrypt TLS or QUIC, reliably
attribute short-lived or UDP flows, or prove that an IP or domain is benign or
malicious. PTR identity and Tranco trust are not proof of legitimacy. Absence
of HTTP or QUIC observations is not evidence of absence. Containment remains a
separate human-approved action through the GUI, CLI, or privileged helper.
