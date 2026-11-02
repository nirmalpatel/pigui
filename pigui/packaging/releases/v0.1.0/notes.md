# PIGUI v0.1.0 (macOS arm64)

PIGUI is an early-stage network security application built around Snort 3. It
runs Snort as an external passive sensor and adds process attribution, a local
manager daemon, a privileged firewall helper, and an Activity Monitor-style GUI.

> PIGUI is an early implementation. Expect rough edges and missing features.
> This release is not a finished security product.

## Requirements

- macOS 14 or newer
- Apple silicon (`arm64`)

## Download

- `PIGUI-0.1.0-macos-arm64.dmg`
- `SHA256SUMS`

The DMG is signed with a Developer ID Application certificate, notarized by
Apple, and stapled. Open the DMG and drag **PIGUI** into **Applications**.

## Install and enable capture

1. Open the DMG and drag `PIGUI.app` to `Applications`.
2. Launch PIGUI from `/Applications`.
3. Open the **Capture** tab.
4. Click **Register helper**.
5. Click **Open Login Items settings** and approve PIGUI.
6. Click **Check again** until the helper shows `enabled`.
7. Enter the capture interface, usually `en0`, and click **Enable capture**.

PIGUI never asks for a password. macOS owns the approval dialog, and the root
helper never receives a credential.

## Verify the download

From the directory containing the DMG and `SHA256SUMS`:

```bash
shasum -a 256 -c SHA256SUMS
spctl -a -vvv -t install PIGUI-0.1.0-macos-arm64.dmg
```

SHA-256:

```text
118210aee2f02fcc35324bb1f2e14c8ce930bd05d596230a72d936fc6fb4d473
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

- Source tag: <https://github.com/nirmalpatel/pigui/tree/pigui-v0.1.0>
- License: GPL-2.0-only
- This release bundles Snort 3, also distributed under GPLv2.

See `NOTICE` and `COPYING` in the repository for details.
