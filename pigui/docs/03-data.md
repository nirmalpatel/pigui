# Data management

PIGUI stores normalized security and attribution data in SQLite. Snort provides
packet-derived telemetry. The operating system provides process and socket
ownership. PIGUI joins the two rather than assuming Snort knows about
processes.

## Sources

| Source | Content | Status |
|---|---|---|
| `alert_json` | Alerts with signature, priority, IPs, ports, protocol, action, `app_id`, service | Implemented |
| extractor `conn` | Completed connections with 5-tuple, duration, packets, bytes, state | Implemented |
| extractor `dns` | DNS query, qtype, rcode, answers, TTLs | Implemented |
| extractor `ssl` | TLS SNI, version, certificate metadata, validation status | Implemented |
| extractor `http` | Host, URI, method, user agent, status | Implemented |
| extractor `quic` | QUIC SNI and client protocol | Implemented |
| `nettop` snapshots | Live connections, PID, process name, interface, byte counters | Implemented |
| `ps` | Process name, path, user | Implemented |
| PTR lookups | Reverse DNS hints for public IPs | Implemented |
| Watched domains | Periodic forward resolution matched against observed IPs | Implemented |
| Control socket | Stats, reload, pause/resume, flow dumps | Planned |
| Signals | Reload, stats dump, rotate, shutdown | Planned |
| `perf_monitor` | Base/CPU/flow aggregates | Planned |
| `host_cache` / RNA | Host services, OS awareness | Planned |
| PF/firewall state | Blocks, TTLs, audit | Planned |

Snort sees packets and flows, not processes. Alerts alone do not show all
outgoing traffic. PIGUI therefore consumes extractor `conn` records and polls
`nettop` rather than relying on alerts.

## Generated Snort telemetry

`config/snort/pigui.lua` documents the shape. At runtime, `pigui-cli snort
generate-config` copies the parent `lua/snort.lua` and `snort_defaults.lua` into
`var/snort/`, appends the overrides, copies rule files, and validates with
`snort -T`.

Key settings:

```lua
alert_json =
{
    file = true,
    fields = 'seconds timestamp gid sid rev priority class msg proto src_addr src_port dst_addr dst_port action app_id service rule dir pkt_num',
}

dns = { publish_response = true }

file_connector =
{
    {
        connector = 'pigui_events',
        name = 'pigui',
        direction = 'transmit',
        text_format = true,
    },
}

extractor =
{
    formatting = 'json',
    connector = 'pigui_events',
    time = 'unix',
    default_filter = 'pick',
    protocols =
    {
        { service = 'conn', on_events = 'eof',
          fields = 'ts uid pkt_num id.orig_h id.orig_p id.resp_h id.resp_p proto service conn_state duration orig_pkts resp_pkts orig_bytes resp_bytes' },
        { service = 'dns', on_events = 'response',
          fields = 'ts uid pkt_num id.orig_h id.orig_p id.resp_h id.resp_p proto query qtype_name rcode_name answers TTLs' },
        { service = 'ssl', on_events = 'tls_metadata_event',
          fields = 'ts uid pkt_num id.orig_h id.orig_p id.resp_h id.resp_p server_name version validation_status subject issuer' },
        { service = 'http', on_events = 'eot',
          fields = 'ts uid pkt_num id.orig_h id.orig_p id.resp_h id.resp_p method host uri user_agent status_code' },
        { service = 'quic', on_events = 'handshake',
          fields = 'ts uid pkt_num id.orig_h id.orig_p id.resp_h id.resp_p server_name client_protocol' },
    },
}
```

`default_filter = 'pick'` is required. Without it Snort validates but emits no
extractor records. `dns.publish_response = true` is required for DNS answers.

Snort's file connector does not add a service discriminator. PIGUI identifies
extractor records by field presence, in this order:

1. `query` or `qtype_name` → DNS
2. `client_protocol` → QUIC
3. `validation_status`, `subject`, or `issuer` → TLS
4. `method`, `uri`, or `status_code` → HTTP
5. `conn_state`, `duration`, `orig_pkts`, `resp_pkts`, or `service` → connection

Unknown records are skipped and counted as parse errors.

## Destination visibility

Destination IP, port, and protocol are available from alerts, extractor
connections, live `nettop` flows, and the planned flow dumps and
`perf_monitor`. PIGUI aggregates destination endpoints from all of these.

## Domain visibility

Domains are derived, not universal:

- DNS responses give query-to-answer mappings.
- TLS SNI gives the requested hostname for HTTPS.
- HTTP `Host` gives the hostname for plaintext HTTP.
- QUIC SNI gives the requested hostname for HTTP/3.
- PTR reverse lookups are low-confidence, rate-limited hints.
- Watched domains are resolved periodically and mapped to observed IPs.

Normalization: hostnames are trimmed, lowercased, trailing dots removed, ports
stripped, and IP literals rejected. The registrable domain is derived with the
Public Suffix List (`api.spotify.com` → `spotify.com`,
`open.spotify.co.uk` → `spotify.co.uk`).

One IP can map to many domains, and mappings change over time. Trust is stored
at the registrable-domain level. A destination's trust is aggregated from its
domains:

- any suspicious domain → suspicious
- all trusted → trusted
- all ignored → ignored
- otherwise unknown

Valid TLS is not treated as trust.

### Default trust

PIGUI ships with the Tranco top-1M list (ID `GQ38K-1m`) compiled into the
daemon. Its registrable domains default to `trusted` without writing anything
to the database. Trust is resolved with this precedence:

1. Explicit user override in `domain_trust`
2. Bundled Tranco default → `trusted`
3. Otherwise `unknown`

The `domain_trust` table therefore stores only user overrides. Setting a domain
back to `unknown` deletes the override and restores the bundled default. Updating
the default list requires a new PIGUI release; there is no runtime download or
import command.

### Domain source precedence

`endpoint_domains` keeps one row per `(ip, domain)` and records the strongest
source seen:

| Rank | Source |
|---|---|
| 4 | `tls` |
| 3 | `quic` |
| 2 | `http` |
| 1 | `dns` |
| 0 | `ptr`, `watched`, legacy |

The highest-ranked source is retained. Observation counts and first/last-seen
timestamps are accumulated.

## Process attribution and reconciliation

The macOS collector runs `nettop -L 1 -x -n` and then enriches PIDs with
`ps -axo pid=,user=,comm=`. It emits process summaries and socket rows. Listen
and wildcard rows are dropped. Flows are filtered to the configured interface
when one is available.

Current join rules:

- Live flow key: `(proto, client_ip, client_port, server_ip, server_port)`.
  `nettop` flows are upserted by this key.
- `nettop` flow rows are deleted when `last_seen` is older than 600 seconds.
- Processes are deleted when `last_seen` is older than 86,400 seconds.
- Completed extractor connections are stored by `uid`.
- Snort extractor protocol names are normalized to lowercase, matching
  `nettop` flows, before the 5-tuple process lookup.
- When a connection is inserted, PIGUI looks up the process from `flows` using
  the same 5-tuple. If a live flow matches, the connection copies the PID and
  process name. Schema migration v5 also lowercases existing connection
  protocols and performs a best-effort backfill from live flows.
- Alerts are not joined to flows by PIGUI yet; they carry their own 5-tuple and
  destination aggregation.

Attribution is best-effort for short-lived flows, UDP, connections that close
between polls, and traffic owned by other users when collection lacks
privilege. A future Network Extension could provide stronger attribution.

## Name resolution

PTR:

- Only public addresses are queried.
- Candidates are endpoints with no known domain and no unexpired PTR result.
- Successful results are cached for 24 hours; failures for 6 hours.
- Results are recorded as `ptr` domain mappings and never auto-trust a domain.

Watched domains:

- Added through the CLI (`pigui-cli watch`) or GUI.
- Re-resolved when older than 900 seconds.
- Resolved IPs are recorded as `watched` mappings.
- Failures are stored on the watched-domain row.

PTR and watched-domain matches are hints, not proof. If DNS occurred before
capture started, historical mappings cannot be reconstructed exactly.

## SQLite schema

Schema version: `6`, stored in `schema_meta`.

### `alerts`

`id, event_ts, ts_text, gid, sid, rev, priority, class, msg, proto, src_ip,
src_port, dst_ip, dst_port, action, app_id, service, rule, direction, pkt_num,
raw_json, ingested_at`

Unique dedupe key: `(event_ts, gid, sid, rev, proto, src_ip, src_port, dst_ip,
dst_port)` with nulls normalized to empty/zero. Indexed by `event_ts` and
`dst_ip`.

### `endpoints`

One row per observed destination IP:

`ip, hostname, first_seen, last_seen, bytes_in, bytes_out, connection_count,
process_count, alert_count, reputation, blocked`

`hostname` is added by migration for older databases.

### `processes`

One row per PID:

`pid, name, path, user, first_seen, last_seen, bytes_in, bytes_out,
connection_count`

### `flows`

Live `nettop` flows:

`id, proto, client_ip, client_port, server_ip, server_port, pid, process_name,
interface, state, bytes_ab, bytes_ba, packets_ab, packets_ba, first_seen,
last_seen`

Unique key: the 5-tuple. Indexed by `last_seen`, `server_ip`, and `pid`.
`packets_ab` and `packets_ba` are currently always zero because `nettop` does
not provide packet counts. Byte direction is normalised: `bytes_ab` is client
to server and `bytes_ba` is server to client, matching `connections`.

Destination rows keep Snort-completed byte and connection totals. Live
`nettop` totals are computed from `flows` on read and exposed separately as
`live_bytes_in`, `live_bytes_out`, and `live_connection_count`.

### `connections`

Completed extractor connections:

`id, uid, ts, proto, client_ip, client_port, server_ip, server_port, service,
conn_state, duration, packets_ab, packets_ba, bytes_ab, bytes_ba, pid,
process_name, created_at`

Unique key: `uid`. Indexed by `ts` and `server_ip`.

### Observations

`dns_observations`: `id, ts, client_ip, query, qtype, rcode, answers, ttl`

`tls_observations`: `id, ts, client_ip, server_ip, server_port, server_name,
version, validation_status, subject, issuer`

`http_observations`: `id, ts, client_ip, server_ip, server_port, method, host,
uri, user_agent, status_code`

`quic_observations`: `id, ts, client_ip, server_ip, server_port, server_name,
client_protocol`

Each has a dedupe index and a timestamp index.

### Domain tables

`domains`: `domain, registrable_domain, first_seen, last_seen,
observation_count`

`endpoint_domains`: `ip, domain, server_port, source, first_seen, last_seen,
observation_count` with primary key `(ip, domain)`

`domain_trust`: user trust overrides, `registrable_domain, state, note,
updated_at`. The bundled Tranco default trust is not stored in SQLite.

`ptr_observations`: `ip, hostname, status, error, first_seen, last_seen,
expires_at`

`watched_domains`: `domain, registrable_domain, enabled, last_resolved_at,
last_error`

### `app_settings`

`key, value, updated_at`. PIGUI stores the validated settings document under
the `app` key. The GUI reads and writes it through RPC, so the daemon remains
the only process that opens the database.

### `capture_state`

One row (`id = 1`) stores the active capture interface, Snort PID, log
directory, capture mode, and start time. The daemon uses the recorded interface
for `nettop` process attribution and restores it across daemon restarts.

### Planned tables

The original design also listed `firewall_actions`, `rule_bundles`,
`sensor_stats`, and `audit_log`. These are **not** in the current schema.

## Retention

Implemented cleanup runs from the daemon maintenance task and is configurable
in the Settings tab:

- Live flows: 10 minutes
- Process rows: 24 hours
- Raw alerts: 30 days
- Completed connections: 7 days
- DNS/TLS/HTTP/QUIC observations: 7 days
- Domains/endpoint mappings: 90 days
- Endpoints: 90 days
- PTR observations: 30 days

`maintenance.stats` reports database size, per-table row counts, the last run,
and rows deleted. `maintenance.prune_now` runs the same cleanup immediately.

Settings are stored in the `app_settings` table in the same `pigui.db`. There
is no separate GUI settings database.

SQLite with WAL is the first storage choice. A separate analytical store can be
evaluated if volume grows.

## Fixtures

- `tests/fixtures/alert_json/valid.jsonl` — IPv4, IPv6, TCP, UDP, duplicate,
  and minimal alerts.
- `tests/fixtures/alert_json/malformed.jsonl` — parser resilience.
- `tests/fixtures/extractor/live.jsonl` — one record per extractor service.

Fixtures are schema-derived. There is no checked-in packet capture or capture
script yet.
