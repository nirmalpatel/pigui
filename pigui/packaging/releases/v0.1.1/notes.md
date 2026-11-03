# PIGUI v0.1.1 (macOS arm64)

PIGUI is an early-stage network security application built around Snort 3. It
runs Snort as an external passive sensor and adds process attribution, a local
manager daemon, a privileged firewall helper, and an Activity Monitor-style GUI.

> PIGUI is an early implementation. Expect rough edges and missing features.
> This release is not a finished security product.

## What's changed

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
- Added the application icon and in-app icon treatment.
- Fixed the privileged helper to report the installed application version.
- Detects and repairs stale background services after an app update.
- Updated application terminology and vocabulary throughout the UI and docs.
- Expanded daemon storage, ingestion, RPC, and settings handling.
- Updated development, architecture, data, and RPC documentation.

## Requirements

- macOS 14 or newer
- Apple silicon (`arm64`)

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

## Verify the download

From the directory containing the DMG and `SHA256SUMS`:

```bash
shasum -a 256 -c SHA256SUMS
spctl -a -vvv -t install PIGUI-0.1.1-macos-arm64.dmg
```

SHA-256:

```text
2c635338f2d9d0a47b7ebab6fc3afd20a62f4a618f776fc8ee0bf3ee3f8e99ed
```

## Known limitations

- This is an early implementation; interfaces and behavior may change.
- macOS arm64 only. Linux and Windows support is in progress.
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
