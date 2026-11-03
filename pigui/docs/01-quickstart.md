# Quick start

This covers the development workflow. PIGUI uses the in-tree Snort build by
default; nothing is installed system-wide.

There is one development command:

```bash
cd pigui
./scripts/run-dev.sh
```

For the packaged macOS app, see [Packaged macOS app](#packaged-macos-app) at the
end of this document.

## Before you start

- macOS (currently supported; Linux and Windows support is in progress)
- Rust 1.85 or newer with Cargo
- Node.js 22 and npm
- A Snort 3 binary. The default is `../build/src/snort`, relative to `pigui/`.
  Override with `PIGUI_SNORT_BIN`. See
  [05-snort-compile.md](05-snort-compile.md) to build Snort.
- `sudo` access for live BPF capture.

## Start the dev app

From `pigui/`:

```bash
./scripts/run-dev.sh
```

This starts the whole app:

1. Stops any stale PIGUI/Snort process from a previous run.
2. Requests `sudo` and selects the capture interface.
3. Generates and validates `var/snort/snort.lua`.
4. Builds and starts the dev capture helper as a temporary root LaunchDaemon.
5. Builds and starts `pigui-daemon`.
6. Starts capture through daemon -> helper -> Snort.
7. Runs `npm install` and `npm run tauri dev` in `apps/pigui-gui`.

Press Ctrl-C to stop Snort, the daemon, and the app together. If a previous run
was killed and left processes behind, use the same script:

```bash
./scripts/run-dev.sh --stop
```

You do **not** need a `.env` file. The dev script uses `.env` when it exists
and otherwise falls back to `.env.example`. Create a `.env` only when you need
to override defaults.

## Optional: customize the environment

```bash
cp .env.example .env    # only needed to override defaults
```

Relative paths in `.env` are resolved against `PIGUI_HOME`, which defaults to
the current working directory. The dev script sets `PIGUI_HOME` to `pigui/`.

Check what PIGUI found:

```bash
./scripts/probe-snort.sh
```

This prints the resolved binary, version, shell/control-socket support,
extractor and `alert_json` availability, DAQ modules, and configuration
validation status.

## Tests

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Tests use recorded fixtures under `tests/fixtures/`; they are not part of the
app startup path.

## Telemetry checks

While the dev app is running:

```bash
./scripts/check-telemetry.sh
```

Snort output goes to `var/log/snort/snort.log`. The daemon log is
`var/log/dev-daemon.log`.

Useful commands:

```bash
./target/debug/pigui-cli snort status
./target/debug/pigui-cli flows --limit 20
./target/debug/pigui-cli processes --limit 20
./target/debug/pigui-cli connections --limit 20
```

Live data comes from two sources:

- `nettop` snapshots every second provide active connections, process names,
  PIDs, interfaces, and byte counters.
- Snort extractor records provide completed `conn` events and DNS/TLS/HTTP/QUIC
  metadata used to enrich destinations and completed connections.

## Expected limits

- Passive capture only sees this machine's traffic, not other LAN devices.
- HTTPS hostnames come from DNS/SNI, not payload decryption.
- Domains can be missing or ambiguous for shared/CDN IPs and hidden DNS.
- Short-lived flows and process attribution are best-effort.
- Snort must run as root for BPF access; the daemon does not.
- Live metadata is stored, not packet payloads.

## Troubleshooting

Common failures are covered in [08-development.md](08-development.md#troubleshooting):

- daemon socket never appears
- extractor stays idle
- Snort fails to start or validate
- `nettop` collection fails
- UI cannot reach the daemon

## Packaged macOS app

Download `PIGUI-<version>-macos-arm64.dmg` and `SHA256SUMS` from the
[GitHub releases page](https://github.com/nirmalpatel/pigui/releases). Verify
the download, open the DMG, and drag `PIGUI.app` to `Applications`:

```bash
shasum -a 256 -c SHA256SUMS
spctl -a -vvv -t install PIGUI-<version>-macos-arm64.dmg
```

Then launch PIGUI and use the **Capture** tab to register and approve the
helper. macOS requires the app to be in `/Applications` for the
`SMAppService` LaunchDaemon flow. The packaged app does not use `sudo`.

See [`packaging/macos/README.md`](../packaging/macos/README.md) for packaging,
signing, and notarization details.
