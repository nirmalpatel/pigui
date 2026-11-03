# pigui-daemon

`pigui-daemon` is the unprivileged manager process. It owns ingestion,
normalization, SQLite storage, background collection, and the local RPC API.

## Privilege model

The daemon does **not** run as root. It does not need root for its current
duties:

- During development, `scripts/run-dev.sh` starts a temporary root LaunchDaemon
  running the same Swift helper in `--dev` mode. The daemon asks that helper to
  start Snort, which drops to the current user with `-u`/`-g` after capture
  starts. The daemon never runs as root and never invokes `sudo`.
- In the packaged app, the root helper is registered with `SMAppService` and
  starts Snort from a root-owned staged payload. The helper drops Snort to the
  console user; the app never invokes `sudo`.
- The daemon reads Snort output files and polls `nettop` as the current user.
- The packaged `pigui-helper` is the root-owned component for capture lifecycle
  and dry-run firewall actions.

Do not install or launch the daemon as a root LaunchDaemon without revisiting
this model. Running the daemon unprivileged keeps the highest-risk ingestion and
RPC surface out of the root domain.

## Startup

```bash
./target/debug/pigui-daemon [OPTIONS]
```

When launched from the packaged `PIGUI.app`, the GUI starts the bundled daemon
automatically if the Unix socket is missing. Development runs still start the
daemon explicitly through the scripts. Daemon output is written to
`~/Library/Application Support/PIGUI/var/log/daemon.log` in prod.

| Flag | Purpose |
|---|---|
| `--alerts-file <PATH>` | Alert JSONL file to tail; defaults to `PIGUI_ALERT_JSON` |
| `--from-end` | Start at the current end of the alert file instead of replaying it |
| `--once` | Ingest the alert file once and exit |
| `--db <PATH>` | Override the SQLite database path |
| `--socket <PATH>` | Override the daemon socket path |

Configuration comes from `Config::load()`: `PIGUI_HOME`, `.env`, and
environment variables. See [08-development.md](08-development.md#environment-reference)
for the full list.

On startup the daemon:

1. Initializes tracing (`RUST_LOG`, default `info`).
2. Loads configuration and creates runtime directories.
3. Opens SQLite, applies the schema, runs the WAL and synchronous pragmas, and
   migrates/backfills domain data when needed.
4. Probes Snort and logs capability warnings.
5. Starts the alert tailer, the extractor tailer, the process collector
   thread, the name resolver thread, and the RPC server.
6. Waits for Ctrl-C, SIGTERM, or an RPC `shutdown` request.
7. Requests shutdown, stops the API, and removes the socket.

`--once` skips the API and background tasks.

## Background tasks

| Task | Interval | Behavior |
|---|---|---|
| Alert tailer | 500 ms | Polls the alert file, parses `alert_json`, inserts alerts |
| Extractor tailer | 500 ms | Polls the extractor JSONL file, classifies and inserts records |
| Process collector | Settings `collector.poll_ms` (default 1000 ms, minimum 250 ms) | Runs `nettop`, enriches with `ps`, upserts processes and live flows |
| Name resolver | Settings `resolver.loop_secs` (default 30 s) | Resolves PTR candidates and due watched domains |
| Maintenance | Settings `maintenance.interval_secs` (default 300 s) | Prunes old rows using the configured retention limits |
| Capture control | Event-driven RPC | Starts/stops Snort via the dev or packaged helper and records the active interface |
| RPC server | event-driven | Accepts newline-delimited JSON requests on the Unix socket |

The collectors run on dedicated OS threads so the single-threaded async runtime
is not blocked by `nettop`, `ps`, or DNS.

Both tailers start at the beginning of their files by default. The daemon relies
on SQLite dedupe indexes, so replaying does not duplicate rows. Use `--from-end`
for alerts when replay is unwanted.

Path handling:

- The alert file comes from `--alerts-file`, `PIGUI_ALERT_JSON`, or the live
  log directory.
- The extractor file comes from `PIGUI_EXTRACTOR_JSON`.
- Relative paths are resolved against `PIGUI_HOME`.

## Storage

Default database:

- `var/lib/pigui.db` — dev and prod data plus `app_settings`. The daemon is the
  only process that opens it; the GUI uses RPC for settings and maintenance.

The daemon sets `journal_mode = WAL`, `synchronous = NORMAL`, and
`foreign_keys = ON`. See [03-data.md](03-data.md) for schema and retention
details.

## RPC API

Unix domain socket, default `var/run/pigui-daemon.sock`.

- The parent directory is created with mode `0700`.
- The socket is set to mode `0600`.
- There is no TCP listener by default.
- Requests and responses are single-line JSON objects.
- Unknown methods return an RPC error.
- `shutdown` triggers a clean stop and socket removal.

The full method list, payloads, and CLI/GUI mapping are in
[06-rpc-api.md](06-rpc-api.md).

## Status and degraded modes

Settings can be changed at runtime through `settings.get`, `settings.update`,
and `settings.reset`. Collector, resolver, and maintenance loops read the
shared settings snapshot each iteration, so changes apply without restart.

The `status` response reports:

- Snort capabilities, binary, version, and source.
- Environment (`dev` or `prod`), uptime, database, alert file, and socket path.
- Counts for alerts, destinations, flows, processes, DNS, TLS, HTTP, QUIC, and
  domains.
- Snort process status from the PID file.
- Extractor file size, modification time, last ingest time, and an idle flag.
- Collector errors.
- Degraded reasons.

Degraded reasons are derived from Snort capabilities:

- No control socket → signal/file mode.
- No extractor → connection/domain telemetry disabled.
- No `alert_json` → alert ingestion disabled.
- Failed config validation.

The extractor is reported idle when alerts have arrived, the extractor has
ingested nothing, and the daemon has been up for more than 30 seconds. This usually means `default_filter` is missing or the extractor file
is not growing.

## Logging

Tracing output goes to stdout with ANSI disabled when not a terminal. Set
`RUST_LOG` to change verbosity. The dev scripts redirect the daemon to
`var/log/live-daemon.log`.

## Current gaps

- No control-socket client; Snort is managed by process/PID file.
- No signal-based reload or stats dump.
- No policy engine or rule bundle manager.
- PF execution is pending; capture state is persisted and recovered across daemon/helper restarts.
- No log rotation job yet; database retention is implemented.
