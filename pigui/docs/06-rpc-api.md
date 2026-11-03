# Daemon RPC API

The daemon exposes a local JSON-RPC-like API over a Unix domain socket. The CLI
and GUI both use it. There is no TCP listener.

## Transport

- Socket: `PIGUI_SOCKET`, default `var/run/pigui-daemon.sock`.
- Socket permissions: `0600`; parent directory `0700`.
- Framing: one JSON object per line, newline-terminated, in both directions.
- Client may send multiple requests on one connection; each gets one response.
- The Rust client opens one connection per call with a 5-second timeout.
- Request `id` is copied into the response. Invalid JSON gets `id: 0`.

Request:

```json
{"id":1,"method":"status","params":{}}
```

Success:

```json
{"id":1,"ok":true,"data":{...}}
```

Failure:

```json
{"id":1,"ok":false,"error":"destination not found: 203.0.113.9"}
```

`data` and `error` are omitted when absent.

## Methods

| Method | Params | Result |
|---|---|---|
| `status` | `{}` | `StatusPayload` |
| `health` | `{}` | `HealthPayload` |
| `snort.status` | `{}` | `SnortStatusPayload` |
| `alerts.list` | `{limit?, offset?}` | `AlertList` |
| `destinations.list` | `{limit?, offset?}` | `DestinationList` |
| `destinations.detail` | `{ip}` | `DestinationDetail` |
| `flows.list` | `{limit?, offset?}` | `FlowList` |
| `processes.list` | `{limit?, offset?}` | `ProcessList` |
| `processes.detail` | `{pid}` | `ProcessDetail` |
| `connections.list` | `{limit?, offset?}` | `ConnectionList` |
| `domains.list` | `{limit?, offset?}` | `DomainList` |
| `domains.set_trust` | `{registrable_domain, state, note?}` | `true` |
| `watched.list` | `{}` | `WatchedList` |
| `watched.add` | `{domain}` | `WatchedDomain` |
| `watched.remove` | `{domain}` | `true` |
| `dns.list` | `{limit?, offset?}` | `DnsList` |
| `tls.list` | `{limit?, offset?}` | `TlsList` |
| `http.list` | `{limit?, offset?}` | `HttpList` |
| `quic.list` | `{limit?, offset?, q?, sort?, dir?}` | `QuicList` |
| `settings.get` | `{}` | `AppSettings` |
| `settings.update` | partial settings document | `AppSettings` |
| `settings.reset` | `{}` | `AppSettings` |
| `maintenance.stats` | `{}` | `MaintenanceStats` |
| `maintenance.prune_now` | `{}` | `PruneResult` |
| `shutdown` | `{}` | `true` |

List methods accept `{limit, offset, q, sort, dir}`. `limit` defaults to the
stored page size and is clamped to the configured `limits.max_page_size` (1000
by default). `offset` defaults to 0. `q` performs a server-side LIKE search over
the view's text fields. `sort` is an allowlisted column key and `dir` is `asc`
or `desc`. `total` is the number of rows matching the current query.

Default ordering: alerts/DNS/TLS/HTTP/QUIC and completed connections are
newest-first; flows by last seen; processes by last seen then traffic;
destinations by alert count then last seen; domains by last seen.

Settings are stored in `pigui.db` (`app_settings`) and the GUI reaches them only
through this API.

## Shared payloads

### `StatusPayload`

```json
{
  "capabilities": {
    "binary": "/path/to/snort",
    "source": "in-tree build",
    "version": "3.12.4.0",
    "control_socket": true,
    "shell": true,
    "extractor": true,
    "alert_json": true,
    "config_valid": true,
    "config_path": "/path/to/var/snort/snort.lua",
    "daq_modules": [],
    "warnings": []
  },
  "db_path": "/path/to/var/lib/pigui.db",
  "alert_json": "/path/to/var/log/snort/alert_json.txt",
  "socket_path": "/path/to/var/run/pigui-daemon.sock",
  "uptime_secs": 42,
  "alerts_ingested": 120,
  "parse_errors": 0,
  "alert_count": 120,
  "destination_count": 33,
  "degraded": [],
  "environment": "dev",
  "snort_running": true,
  "snort_pid": 12345,
  "snort_interface": "en0",
  "active_flows": 18,
  "active_processes": 7,
  "extractor_ingested": 500,
  "extractor_file": "/path/to/var/log/snort/file_connector_pigui_transmit",
  "extractor_size": 1048576,
  "extractor_modified": 1750000000,
  "extractor_last_ingest": 1750000001,
  "extractor_idle": false,
  "dns_count": 40,
  "tls_count": 25,
  "http_count": 3,
  "quic_count": 8,
  "domain_count": 12,
  "collector_error": null
}
```

`capabilities.daq_modules` is currently always empty. `degraded` is derived from
capabilities. `extractor_idle` is set when alerts have arrived but extractor records have not.

### `HealthPayload`

```json
{"status":"ok","uptime_secs":42,"alerts_ingested":120,"parse_errors":0}
```

`status` is `ok` when `degraded` is empty, otherwise `degraded`.

### `SnortStatusPayload`

```json
{
  "running": true,
  "pid": 12345,
  "interface": "en0",
  "config_path": "/path/to/var/snort/snort.lua",
  "log_dir": "/path/to/var/log/snort",
  "extractor_json": "/path/to/var/log/snort/file_connector_pigui_transmit",
  "control_socket": null,
  "pidfile": "/path/to/var/log/snort/snort.pid"
}
```

Status is derived from the PID file and `kill -0`; it does not query Snort.

### Alerts

`AlertList`:

```json
{
  "alerts": [
    {
      "id": 1,
      "event_ts": 1750000000,
      "ts_text": "06/15-12:26:40.123456",
      "gid": 1,
      "sid": 1000001,
      "rev": 2,
      "priority": 1,
      "class": "attempted-admin",
      "msg": "Test SSH brute force",
      "proto": "TCP",
      "src_ip": "10.0.0.5",
      "src_port": 51000,
      "dst_ip": "198.51.100.10",
      "dst_port": 22,
      "action": "allowed",
      "app_id": "ssh",
      "service": "ssh",
      "rule": "1:1000001:2",
      "direction": "C2S",
      "pkt_num": 7,
      "ingested_at": 1750000002
    }
  ],
  "total": 1
}
```

Optional fields may be absent. `total` is the total row count, not the page
size.

### Destinations

`DestinationList` contains `destinations` and `total`. A destination:

```json
{
  "ip": "198.51.100.10",
  "hostname": "api.spotify.com",
  "first_seen": 1750000000,
  "last_seen": 1750000100,
  "bytes_in": 200,
  "bytes_out": 100,
  "connection_count": 1,
  "process_count": 1,
  "live_bytes_in": 200,
  "live_bytes_out": 100,
  "live_connection_count": 1,
  "alert_count": 2,
  "reputation": 0,
  "blocked": false,
  "domains": [
    {
      "domain": "api.spotify.com",
      "registrable_domain": "spotify.com",
      "source": "tls",
      "server_port": 443,
      "trust_state": "trusted",
      "first_seen": 1750000050,
      "last_seen": 1750000050
    }
  ],
  "trust_state": "trusted",
  "flags": []
}
```

`flags` values: `new_domain`, `no_domain`, `invalid_tls`, `alerts`,
`unknown_trust`.

`destinations.detail` with `{"ip":"198.51.100.10"}` returns:

```json
{
  "destination": { "...": "Destination" },
  "processes": [
    {
      "pid": 42,
      "process_name": "Spotify",
      "snort_bytes_in": 200,
      "snort_bytes_out": 100,
      "live_bytes_in": 200,
      "live_bytes_out": 100,
      "snort_connection_count": 1,
      "live_connection_count": 1,
      "connection_count": 2,
      "last_seen": 1750000100
    }
  ],
  "recent_alerts": [ { "...": "AlertRecord" } ]
}
```

`bytes_in`/`bytes_out`/`connection_count` on a destination are Snort-completed
values. `live_*` values come from current `nettop` flows. Keeping them separate
avoids double counting. The process list is ordered by total bytes; recent
alerts honour `ui.detail_alert_limit`.

### Flows and processes

`Flow`:

```json
{
  "id": 1,
  "proto": "tcp",
  "client_ip": "10.0.0.5",
  "client_port": 50000,
  "server_ip": "198.51.100.10",
  "server_port": 443,
  "pid": 42,
  "process_name": "Spotify",
  "interface": "en0",
  "state": "Established",
  "bytes_ab": 100,
  "bytes_ba": 200,
  "packets_ab": 0,
  "packets_ba": 0,
  "first_seen": 1750000000,
  "last_seen": 1750000100
}
```

`Process`:

```json
{
  "pid": 42,
  "name": "Spotify",
  "path": "/Applications/Spotify.app",
  "user": "nirmal",
  "first_seen": 1750000000,
  "last_seen": 1750000100,
  "bytes_in": 200,
  "bytes_out": 100,
  "connection_count": 1
}
```

`processes.detail` with `{"pid":42}` returns `process` plus `destinations`.
Each process destination has `ip`, `domains`, `trust_state`, `flags`,
`snort_bytes_in`, `snort_bytes_out`, `live_bytes_in`, `live_bytes_out`,
`snort_connection_count`, `live_connection_count`, `connection_count`, and
`last_seen`. The process row's own `bytes_in`/`bytes_out` are the last `nettop`
snapshot, not Snort totals.

Flow bytes use the same direction convention as connections: `bytes_ab` is
client → server, `bytes_ba` is server → client.

### Connections

`Connection`:

```json
{
  "id": 1,
  "uid": "C1",
  "ts": 1750000000,
  "proto": "tcp",
  "client_ip": "10.0.0.5",
  "client_port": 50000,
  "server_ip": "198.51.100.10",
  "server_port": 443,
  "service": "ssl",
  "conn_state": "SF",
  "duration": 1.25,
  "packets_ab": 2,
  "packets_ba": 3,
  "bytes_ab": 100,
  "bytes_ba": 200,
  "pid": 42,
  "process_name": "Spotify"
}
```

### Domains

`DomainList` contains `domains` and `total`. Domains are grouped by registrable
domain:

```json
{
  "domain": "spotify.com",
  "hostnames": ["api.spotify.com", "open.spotify.com"],
  "sources": ["dns", "tls", "watched"],
  "trust_state": "unknown",
  "first_seen": 1750000000,
  "last_seen": 1750000100,
  "observation_count": 4,
  "endpoint_count": 2,
  "process_count": 1,
  "flags": ["unknown_trust", "new_domain"]
}
```

`domains.set_trust` accepts:

```json
{"registrable_domain":"spotify.com","state":"trusted","note":"music"}
```

Valid states: `unknown`, `trusted`, `suspicious`, `ignored`. Setting `unknown`
deletes the trust row. The domain is normalized; a subdomain is reduced to its
registrable domain.

### Watched domains

`WatchedList` contains `watched`. A watched domain:

```json
{
  "domain": "api.spotify.com",
  "registrable_domain": "spotify.com",
  "enabled": true,
  "last_resolved_at": 1750000000,
  "last_error": null
}
```

`watched.add` and `watched.remove` take `{"domain":"api.spotify.com"}`.

### Protocol observations

`DnsList` contains `observations`:

```json
{
  "id": 1,
  "ts": 1750000000,
  "client_ip": "10.0.0.5",
  "query": "example.com",
  "qtype": "A",
  "rcode": "NOERROR",
  "answers": "93.184.216.34",
  "ttl": "300"
}
```

`TlsList` observations: `id, ts, client_ip, server_ip, server_port,
server_name, version, validation_status, subject, issuer`.

`HttpList` observations: `id, ts, client_ip, server_ip, server_port, method,
host, uri, user_agent, status_code`.

`QuicList` observations: `id, ts, client_ip, server_ip, server_port,
server_name, client_protocol`.

## Errors

Errors are plain strings. Common cases:

- `unknown method: <name>`
- `invalid request: <serde error>`
- `destination not found: <ip>`
- `process not found: <pid>`
- `invalid domain for watched list: <value>`
- store lock or database errors
- invalid query parameters

## CLI and GUI mapping

| CLI | RPC |
|---|---|
| `pigui-cli status` | `status` |
| `pigui-cli alerts` | `alerts.list` |
| `pigui-cli destinations` | `destinations.list` |
| `pigui-cli flows` | `flows.list` |
| `pigui-cli processes` | `processes.list` |
| `pigui-cli connections` | `connections.list` |
| `pigui-cli domains` | `domains.list` |
| `pigui-cli trust <domain> <state>` | `domains.set_trust` |
| `pigui-cli watched` | `watched.list` |
| `pigui-cli watch <domain>` / `--remove` | `watched.add` / `watched.remove` |
| `pigui-cli dns` / `tls` / `http` | `dns.list` / `tls.list` / `http.list` |
| `pigui-cli snort status` | local PID-file status, not RPC |

The GUI uses `status`, list methods, detail methods, trust, watched-domain, and
settings/maintenance methods. It does not currently expose TLS/HTTP/QUIC lists.

## Current security gaps

- The server does not verify peer credentials.
- Access control relies on socket directory and socket file permissions.
- There is no request authentication or per-method authorization.

Peer credential checks and helper authorization are planned. See
[07-security.md](07-security.md).
