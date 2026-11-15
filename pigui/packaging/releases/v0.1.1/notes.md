# PIGUI v0.1.1 (macOS arm64)

PIGUI is an early-stage network security application built around Snort 3. It
runs Snort as an external passive sensor and adds process attribution, a local
manager daemon, a privileged firewall helper, and an Activity Monitor-style GUI.

> PIGUI is an early implementation. Expect rough edges and missing features.
> This release is not a finished security product.

## What's changed

- Added a read-only MCP analysis server (`pigui-mcp`) for OpenCode and other MCP
  clients. The binary is bundled in the app and exposes daemon telemetry such as
  status, overview, findings, alerts, flows, processes, connections, domains,
  DNS, TLS, HTTP, QUIC, watched domains, maintenance, and firewall state.
- Added `analysis.overview` and `analysis.findings` daemon RPC methods for
  windowed aggregates, evidence-based findings, noise suppression, and baseline
  comparison.
- Added PF-based firewall integration with compiled block and allow rules,
  dynamic blocks, a Firewall tab with a rule editor, CLI diagnostics, helper
  endpoints, and firewall audit records.
- Added the application icon and in-app icon treatment.
- Capture now registers its services and starts automatically on launch. macOS
  Login Items approval is the only manual setup step.
- Simplified the Capture tab and moved manual controls and diagnostics under an
  Advanced section.
- DNS queries now show Tranco and user-override trust, including rows with no
  query value.
- Production startup now restarts a stale daemon when the app binary changes,
  even if the version string is unchanged.
- Tab headers show total database rows, and pagination clearly distinguishes
  matching rows from total rows.
- DNS answer values wrap instead of stretching the table.
- Ships the Tranco top-1M list as the default trusted-domain list. User trust
  overrides still take precedence.
- Refreshed the GUI with sortable tables and paginated views.
- Added a Settings page and streamlined development/production configuration
  parity.
- Fixed the privileged helper to report the installed application version.
- Detects and repairs stale background services after an app update.
- Updated application terminology and vocabulary throughout the UI and docs.
- Expanded daemon storage, ingestion, RPC, and settings handling.
- Updated development, architecture, data, firewall, MCP, and RPC documentation.

## Requirements

- macOS 14 or newer
- Apple silicon (`arm64`)
- Optional: an MCP client such as OpenCode for the read-only analysis interface

## Download

- `PIGUI-0.1.1-macos-arm64.dmg`
- `SHA256SUMS`

The DMG is signed with a Developer ID Application certificate, notarized by
Apple, and stapled. Open the DMG and drag **PIGUI** into **Applications**.

## Install and enable capture

1. Open the DMG and drag `PIGUI.app` to `Applications`.
2. Launch PIGUI from `/Applications`.
3. If macOS asks, approve PIGUI in Login Items & Extensions.

PIGUI registers its services, selects the default interface, and starts capture
automatically. Manual controls are under **Capture → Advanced and diagnostics**.

PIGUI never asks for a password. macOS owns the approval dialog, and the root
helper never receives a credential.

## MCP analysis (optional)

The app bundle includes the read-only MCP server at:

```text
/Applications/PIGUI.app/Contents/MacOS/pigui-mcp
```

Point your MCP client at that path. OpenCode example:

```json
{
  "mcp": {
    "pigui": {
      "type": "local",
      "command": ["/Applications/PIGUI.app/Contents/MacOS/pigui-mcp"],
      "enabled": true
    }
  }
}
```

PIGUI must be running and capture must be started before telemetry results are
available. The MCP server is unprivileged and cannot start or stop capture,
change settings, modify trust, alter firewall state, or prune data. See
`docs/10-mcp.md` in the source tree for tools, limits, and privacy details.

## Verify the download

From the directory containing the DMG and `SHA256SUMS`:

```bash
shasum -a 256 -c SHA256SUMS
spctl -a -vvv -t install PIGUI-0.1.1-macos-arm64.dmg
```

SHA-256:

```text
92f47fd91ee305105322f95fc130adc760d6f42aed1dbfc74e24494214f96f42
```

## Known limitations

- This is an early implementation; interfaces and behavior may change.
- macOS arm64 only. Linux and Windows support is in progress.
- MCP analysis sends network metadata to the configured model provider. OS
  usernames are redacted by default; process paths and network identifiers are
  preserved for attribution.
- Passive capture only sees this machine's traffic.
- HTTPS hostnames come from DNS/SNI, not payload decryption.
- Process attribution and short-lived flow attribution are best-effort.
- Snort runs through the privileged helper; the daemon itself does not run as
  root.

## Source and license

- Source tag: <https://github.com/nirmalpatel/pigui/tree/pigui-v0.1.1>
- License: GPL-2.0-only
- This release bundles Snort 3, also distributed under GPLv2.

See `NOTICE` and `COPYING` in the repository for details.
