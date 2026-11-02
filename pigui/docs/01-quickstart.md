# Quick start

This covers the current development workflow. It does not install Snort
system-wide. PIGUI uses the in-tree Snort build by default.

For the signed macOS app, use the **Capture** tab to register and approve the
SMAppService helper, then enable capture. The packaged app does not use `sudo`.
See [`packaging/macos/README.md`](../packaging/macos/README.md).

## Install the macOS app

Download `PIGUI-<version>-macos-arm64.dmg` and `SHA256SUMS` from the
[GitHub releases page](https://github.com/nirmalpatel/pigui/releases). Verify
the download, open the DMG, and drag `PIGUI.app` to `Applications`:

```bash
shasum -a 256 -c SHA256SUMS
spctl -a -vvv -t install PIGUI-<version>-macos-arm64.dmg
```

Then launch PIGUI and use the **Capture** tab to register and approve the
helper. macOS requires the app to be in `/Applications` for the
`SMAppService` LaunchDaemon flow.

## Prerequisites

- macOS (currently supported; Linux and Windows support is in progress)
- Rust 1.85 or newer with Cargo
- Node.js 22 and npm
- A Snort 3 binary. The default is `../build/src/snort`, relative to `pigui/`.
  Override with `PIGUI_SNORT_BIN`.
- A Snort source `lua/` tree for defaults. The default is `../lua`.
- `sudo` access for live BPF capture.

See [05-snort-compile.md](05-snort-compile.md) to build Snort.

## Environment

```bash
cd pigui
cp .env.example .env    # optional; scripts fall back to .env.example
```

Relative paths in `.env` are resolved against `PIGUI_HOME`, which defaults to
the current working directory. The dev scripts set `PIGUI_HOME` to `pigui/`.

Check what PIGUI found:

```bash
./scripts/probe-snort.sh
```

This prints the resolved binary, version, shell/control-socket support,
extractor and `alert_json` availability, DAQ modules, and configuration
validation status.

## Fixture mode

Fixture mode runs the daemon against a recorded `alert_json` file and opens the
Tauri window.

```bash
./scripts/run-dev.sh
```

The script:

1. Builds `pigui-daemon`.
2. Starts it on `tests/fixtures/alert_json/valid.jsonl`.
3. Waits for `var/run/pigui-daemon.sock`.
4. Runs `npm install` and `npm run tauri dev` in `apps/pigui-gui`.

The daemon replays the alert file from the beginning by default. Inserts are
deduplicated by the SQLite index, so restarts do not duplicate events. Use
`--from-end` with `pigui-daemon` to skip existing content.

### Headless fixture checks

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

## Live capture

Live mode runs Snort on an interface, generates the Snort configuration, tails
the alert and extractor files, and starts the `nettop` collector.

```bash
./scripts/run-live.sh
```

The script:

1. Requests `sudo` credentials.
2. Detects the default interface with `route` unless
   `PIGUI_SNORT_INTERFACE` is set.
3. Generates and validates `var/snort/snort.lua`.
4. Starts Snort with `--create-pidfile` under `var/log/snort/`.
5. Starts the daemon with `var/lib/pigui-live.db`.
6. Opens the Tauri window.

Snort output goes to `var/log/snort/snort.log`. The daemon log is
`var/log/live-daemon.log`.

Useful commands:

```bash
./scripts/snort-live.sh          # run Snort in the foreground
./scripts/stop-live.sh           # stop Snort and the daemon
./scripts/check-telemetry.sh     # show extractor, DNS, TLS, and domain counts

./target/debug/pigui-cli snort generate-config
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
