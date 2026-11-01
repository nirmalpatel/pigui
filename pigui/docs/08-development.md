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
npm run tauri dev  # Tauri shell + daemon client
npm run build      # production frontend build
npm run check      # svelte-check
```

The Tauri app looks up `PIGUI_HOME` when set. In debug builds it defaults to the
repository `pigui/` directory. In release it uses the Tauri app-data directory
for GUI settings.

## Scripts

| Script | Purpose |
|---|---|
| `scripts/dev-env.sh` | Loads `.env` or `.env.example`, sets defaults, creates `var/` |
| `scripts/probe-snort.sh` | Prints resolved Snort capabilities |
| `scripts/run-dev.sh` | Fixture daemon + Tauri dev |
| `scripts/run-live.sh` | Snort + live daemon + Tauri dev |
| `scripts/snort-live.sh` | Runs Snort in the foreground with sudo |
| `scripts/stop-live.sh` | Stops Snort and requests daemon shutdown |
| `scripts/check-telemetry.sh` | Prints status, extractor size, DNS, and domains |

## Environment reference

| Variable | Default | Purpose |
|---|---|---|
| `PIGUI_HOME` | current directory | Base for relative paths |
| `PIGUI_SNORT_BIN` | `../build/src/snort` | Snort binary |
| `PIGUI_SNORT_CONFIG` | `../lua/snort.lua` if present | Source Snort config |
| `PIGUI_SNORT_LUA_PATH` | `../lua` if present | Source Lua tree |
| `PIGUI_RUN_DIR` | `var/run` | Sockets, runtime files |
| `PIGUI_LOG_DIR` | `var/log` | Log directory |
| `PIGUI_DB_PATH` | `var/lib/pigui.db` | SQLite database |
| `PIGUI_ALERT_JSON` | `var/log/alert_json.txt` | Alert file to tail |
| `PIGUI_SOCKET` | `var/run/pigui-daemon.sock` | Daemon RPC socket |
| `PIGUI_MODE` | `fixture` | `fixture` or `live` |
| `PIGUI_FIXTURE_ALERT_JSON` | `tests/fixtures/alert_json/valid.jsonl` | Fixture mode input |
| `PIGUI_SNORT_INTERFACE` | auto-detected | Capture interface |
| `PIGUI_SNORT_LOG_DIR` | `var/log/snort` | Snort log output |
| `PIGUI_SNORT_CONFIG_DIR` | `var/snort` | Generated Snort config |
| `PIGUI_EXTRACTOR_JSON` | `<log>/file_connector_pigui_transmit` | Extractor JSONL |
| `PIGUI_SNORT_PIDFILE` | `<log>/snort.pid` | Snort PID file |
| `PIGUI_SNORT_CONTROL_SOCKET` | `var/run/snort.sock` | Reserved for planned control client |
| `PIGUI_PROCESS_POLL_MS` | `1000` | `nettop` poll interval; minimum 250 |
| `PIGUI_LIVE_DB_PATH` | `var/lib/pigui-live.db` | Live database used by scripts |
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

The daemon replays alert files from the beginning and relies on the dedupe
index, so repeat runs are safe.

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

### UI cannot reach the daemon

- Confirm the daemon is running and the socket exists.
- Confirm the GUI and daemon use the same `PIGUI_HOME`.
- In release builds, `PIGUI_HOME` is not defaulted; set it explicitly or use
  the packaged paths.

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
