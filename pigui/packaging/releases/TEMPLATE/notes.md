# PIGUI v<version> (macOS <arch>)

<short summary>

> PIGUI is an early implementation. Expect rough edges and missing features.
> This release is not a finished security product.

## Requirements

- macOS <min-version> or newer
- <arch>

## Download

- `PIGUI-<version>-macos-<arch>.dmg`
- `SHA256SUMS`

## Install and enable capture

1. Open the DMG and drag `PIGUI.app` to `Applications`.
2. Launch PIGUI from `/Applications`.
3. Open the **Capture** tab.
4. Click **Register helper**.
5. Click **Open Login Items settings** and approve PIGUI.
6. Click **Check again** until the helper shows `enabled`.
7. Enter the capture interface, usually `en0`, and click **Enable capture**.

## Verify the download

```bash
shasum -a 256 -c SHA256SUMS
spctl -a -vvv -t install PIGUI-<version>-macos-<arch>.dmg
```

SHA-256:

```text
<dmg-sha256>
```

## Known limitations

- This is an early implementation; interfaces and behavior may change.
- macOS <arch> only. Linux and Windows support is in progress.
- Passive capture only sees this machine's traffic.
- HTTPS hostnames come from DNS/SNI, not payload decryption.
- Process attribution and short-lived flow attribution are best-effort.
- Snort runs through the privileged helper; the daemon itself does not run as
  root.

## Source and license

- Source tag: <https://github.com/nirmalpatel/pigui/tree/pigui-v<version>>
- License: GPL-2.0-only
- This release bundles Snort 3, also distributed under GPLv2.

See `NOTICE` and `COPYING` in the repository for details.
