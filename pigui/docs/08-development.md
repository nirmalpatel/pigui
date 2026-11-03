# Development

This covers the workspace, common commands, fixtures, environment variables,
platform-adapter work, and troubleshooting.

## Workspace commands

From `pigui/`:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

## GUI commands

From `pigui/apps/pigui-gui/`:

```bash
npm install
npm run dev        # Vite only
npm run tauri dev  # Tauri shell only; use scripts/run-dev.sh for the full app
npm run build      # production frontend build
npm run check      # svelte-check
```

The Tauri app looks up `PIGUI_HOME` when set. In debug builds it defaults to the
repository `pigui/` directory. A packaged app uses
`~/Library/Application Support/PIGUI`. All data and settings live in the daemon
database; there is no separate GUI database.

## macOS packaging

From `pigui/`:

```bash
./packaging/macos/build-app.sh
./packaging/macos/verify-bundle.sh target/macos/PIGUI.app
```

The unsigned build is written to `target/macos/PIGUI.app`. Set
`PIGUI_SIGN_IDENTITY`, `PIGUI_TEAM_ID`, `PIGUI_NOTARY_PROFILE`, and
`PIGUI_NOTARIZE=1` for a signed and notarized DMG. See
[`packaging/macos/README.md`](../packaging/macos/README.md).

The packaged app includes `pigui-servicectl`, used by `pigui-cli service` and
the GUI to register services through `SMAppService`:

```bash
target/macos/PIGUI.app/Contents/MacOS/pigui-cli service status
target/macos/PIGUI.app/Contents/MacOS/pigui-cli service register-agent
target/macos/PIGUI.app/Contents/MacOS/pigui-cli service register-helper
```

`register-helper` requires a signed app and administrator approval in System
Settings. It never asks PIGUI for a password.

The helper XPC bridge is available for diagnostics once the helper is running:

```bash
target/macos/PIGUI.app/Contents/MacOS/pigui-cli helper status
target/macos/PIGUI.app/Contents/MacOS/pigui-cli helper apply-block 198.51.100.10 --ttl 60
```

The helper accepts only fixed methods. `apply_block` and `flush_firewall` are
dry-run until PF execution is implemented.

## Signed macOS release

Verify signing credentials first:

```bash
./packaging/macos/check-signing.sh
```

Both the Developer ID Application certificate and the `notarytool` keychain
profile must report OK. Then build:

```bash
PIGUI_SIGN_IDENTITY="Developer ID Application: Example Corp (ABCDE12345)" \
PIGUI_TEAM_ID="ABCDE12345" \
PIGUI_NOTARY_PROFILE="pigui-notary" \
PIGUI_NOTARIZE=1 \
./packaging/macos/build-app.sh
```

The script signs every nested binary, notarizes and staples the app bundle,
creates the DMG, then notarizes and staples the DMG. The app-level ticket is
required for the `SMAppService` LaunchDaemon. Record the DMG SHA-256,
submission IDs, and build environment in
`packaging/releases/v<version>/macos-<arch>.md`.

A notarization ticket applies only to the exact DMG that was submitted. Any
rebuild requires a new submission. Do not rebuild a release DMG after
notarization; bump the version instead.

`stapler staple` can fail with a transient CloudKit/network error. Retry the
staple operation; do not rebuild unless the artifact actually changed.

## Scripts

| Script | Purpose |
|---|---|
| `scripts/dev-env.sh` | Loads `.env` or `.env.example`, sets defaults, creates `var/` |
| `scripts/run-dev.sh` | Starts and stops Snort + daemon + Tauri dev |
| `scripts/probe-snort.sh` | Prints resolved Snort capabilities |
| `scripts/check-telemetry.sh` | Prints status, extractor size, DNS, and domains |

## Environment reference

PIGUI has two runtime environments: `dev` when running from the source tree and
`prod` when running inside `PIGUI.app`. The daemon detects this automatically;
there is no mode variable.

| Variable | Default | Purpose |
|---|---|---|
| `PIGUI_HOME` | current directory | Base for relative paths |
| `PIGUI_SNORT_BIN` | `../build/src/snort` | Snort binary |
| `PIGUI_SNORT_CONFIG` | `../lua/snort.lua` if present | Source Snort config |
| `PIGUI_SNORT_LUA_PATH` | `../lua` if present | Source Lua tree |
| `PIGUI_RUN_DIR` | `var/run` | Sockets, runtime files |
| `PIGUI_LOG_DIR` | `var/log` | Log directory |
| `PIGUI_DB_PATH` | `var/lib/pigui.db` | SQLite database |
| `PIGUI_ALERT_JSON` | `<snort log>/alert_json.txt` | Alert file to tail |
| `PIGUI_SOCKET` | `var/run/pigui-daemon.sock` | Daemon RPC socket |
| `PIGUI_SNORT_INTERFACE` | auto-detected | Capture interface |
| `PIGUI_SNORT_LOG_DIR` | `var/log/snort` | Snort log output |
| `PIGUI_SNORT_CONFIG_DIR` | `var/snort` | Generated Snort config |
| `PIGUI_EXTRACTOR_JSON` | `<log>/file_connector_pigui_transmit` | Extractor JSONL |
| `PIGUI_SNORT_PIDFILE` | `<log>/snort.pid` | Snort PID file |
| `PIGUI_SNORT_CONTROL_SOCKET` | `var/run/snort.sock` | Reserved for planned control client |
| `PIGUI_PROCESS_POLL_MS` | `1000` | Bootstrap `nettop` poll interval; the Settings tab value takes precedence once stored |
| `RUST_LOG` | `info` | Tracing filter |

Relative paths are resolved against `PIGUI_HOME`.

## Fixtures

Fixtures live under `tests/fixtures/`:

- `alert_json/valid.jsonl` — valid IPv4/IPv6/TCP/UDP alerts, a duplicate, and
  a minimal alert.
- `alert_json/malformed.jsonl` — malformed and partial records.
- `extractor/live.jsonl` — one record per extractor service.

The alert fixtures follow the exact `alert_json` field selection PIGUI
requests. The extractor fixture follows `config/snort/pigui.lua`. Fixtures are
schema-derived; no packet capture or capture script is checked in yet.

To test parsing changes:

```bash
./target/debug/pigui-cli ingest --file tests/fixtures/alert_json/valid.jsonl
cargo test -p pigui-core
cargo test -p pigui-daemon
```

Fixtures are for tests only and are not part of `run-dev.sh`. When testing
ingestion manually, the daemon replays alert files from the beginning and
relies on the dedupe index, so repeat runs are safe.

## Adding a platform adapter

Keep platform differences behind traits and preserve the RPC model.

Collectors:

1. Implement `pigui_collector::Collector` for the platform.
2. Return a `CollectorSnapshot` with `ProcessSample` and `SocketSample` rows.
3. Keep process names, PIDs, interfaces, and byte counters filled when
   available.
4. Wire it into `spawn_process_collector` behind platform selection.

Firewall:

1. Implement `pigui_firewall::FirewallBackend`.
2. Add the backend name, `apply_block`, and `flush`.
3. Do not call platform firewalls from the GUI or the unprivileged daemon.
4. Add an allowlist, TTL handling, rate limits, and audit before enabling.

Portability gaps to address for Windows:

- The RPC server uses `tokio::net::UnixListener`.
- The client uses `std::os::unix::net::UnixStream`.
- The tailer uses `std::os::unix::fs::MetadataExt`.
- Snort status uses `std::os::unix::fs::FileTypeExt`.
- Process existence uses `kill -0`.

A Windows port needs named pipes with ACLs, a pipe client, and Windows-specific
file metadata/process checks. Do not assume the Unix code compiles there.

## Troubleshooting

### Daemon socket never appears

- Run the daemon in the foreground to see the error:
  `./target/debug/pigui-daemon --alerts-file tests/fixtures/alert_json/valid.jsonl`
- Confirm `PIGUI_HOME` and `PIGUI_SOCKET` are the same for the daemon and the
  client. The dev scripts set `PIGUI_HOME` to `pigui/`.
- Check that `var/run/` exists and is writable.
- Check whether another daemon is already using the socket or database.

### Extractor stays idle

- Confirm the generated config contains `default_filter = 'pick'`.
- Confirm the extractor file is growing:
  `wc -c var/log/snort/file_connector_pigui_transmit`
- Confirm Snort can write to the log directory.
- Run `./scripts/check-telemetry.sh`.
- If alerts arrive but extractor rows do not, inspect the generated
  `var/snort/snort.lua` and the Snort log.

### Snort fails to start or validate

- Validate manually:
  `./build/src/snort -c pigui/var/snort/snort.lua -T`
- Confirm `../lua/snort.lua` and `../lua/snort_defaults.lua` exist relative to
  `pigui/`.
- Confirm the capture interface is correct.
- Check `var/log/snort/snort.log`.
- The PID file may be root-owned. The live script chowns it to the current
  user; do not delete it while Snort is running.

### `nettop` collection fails

- `nettop` is macOS-only.
- Check `collector_error` in `pigui-cli status`.
- Confirm the configured interface is active.
- Process attribution for other users may be limited by privileges.

### Helper registration or login-item approval is stale

Use the Capture tab or the packaged `pigui-servicectl` to unregister and
re-register the service. Do not use `sfltool resetbtm` to remove one PIGUI
item; it resets all background-item approvals for every app.

### Tauri build fails after moving the checkout

If `tauri dev` fails in `pigui-gui` with an error such as:

```text
failed to read plugin permissions: failed to read file
'/old/path/pigui/apps/pigui-gui/src-tauri/target/debug/build/...'
```

the Tauri build cache contains absolute paths from the old checkout location.
Remove the GUI target cache and retry:

```bash
rm -rf apps/pigui-gui/src-tauri/target
./scripts/run-dev.sh
```

This cache is regenerable build output and is safe to delete.

### UI cannot reach the daemon

- In a packaged build, click **Start daemon** in the error banner. The GUI starts
  the bundled daemon automatically when the socket is missing.
- Check `~/Library/Application Support/PIGUI/var/log/daemon.log` for packaged
  runs.
- In development, start everything with `scripts/run-dev.sh`.
- Confirm the daemon is running and the socket exists.
- Confirm the GUI and daemon use the same `PIGUI_HOME`.
- Packaged builds default to `~/Library/Application Support/PIGUI`; do not
  set `PIGUI_HOME` unless you intentionally want development paths.

### Database is locked

- Run one daemon per database file.
- Stop the old daemon or use `--db`/`PIGUI_DB_PATH`.
- WAL leaves `-wal` and `-shm` files next to the database; keep them together.

### No domains appear

- DNS may have resolved before capture started.
- DoH/DoT or hidden DNS may bypass Snort's DNS extractor.
- Some connections have no SNI or Host.
- PTR is skipped for private addresses and is only a hint.
- Check `pigui-cli dns`, `pigui-cli domains`, and `pigui-cli watched`.

### Test or lint failures

- Use the pinned toolchain in `rust-toolchain.toml`.
- Run `cargo fmt` before `cargo fmt --check`.
- Clippy is enforced with `-D warnings`; do not add new warnings.
