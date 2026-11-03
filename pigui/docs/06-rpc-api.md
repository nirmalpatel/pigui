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
| `capture.status` | `{}` | `CaptureStatusPayload` |
| `capture.start` | `{interface}` | `CaptureState` |
| `capture.ensure` | `{}` | `CaptureState` |
| `capture.stop` | `{}` | `true` |
| `capture.helper_status` | `{}` | helper status JSON |
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
| `firewall.status` | `{}` | `FirewallStatusPayload` |
| `firewall.rules.list` | `{}` | `FirewallRuleList` |
| `firewall.rules.create` | `{rule}` | `FirewallRule` |
| `firewall.rules.update` | `{rule}` | `FirewallRule` |
| `firewall.rules.delete` | `{id}` | `true` |
| `firewall.rules.reorder` | `{ids}` | `[FirewallRule]` |
| `firewall.enable` | `{enabled}` | `FirewallState` |
| `firewall.apply` | `{}` | `FirewallStatusPayload` |
| `firewall.reset` | `{}` | `FirewallStatusPayload` |
| `firewall.blocks.list` | `{}` | `FirewallBlockList` |
| `firewall.blocks.add` | `{address, direction, ttl_secs, reason?, source?}` | `FirewallBlock` |
| `firewall.blocks.remove` | `{id?, address?, direction?}` | `true` |
| `firewall.counters` | `{}` | helper counter JSON |
| `firewall.events.list` | `{limit?}` | helper event JSON |
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
  "connection_count": 250,
  "degraded": [],
  "environment": "dev",
  "version": "0.1.1",
  "snort_running": true,
  "snort_pid": 12345,
  "snort_interface": "en0",
  "capture_running": true,
  "capture_interface": "en0",
  "capture_mode": "helper",
  "snort_config_hash": "0123456789abcdef",
  "snort_config_path": "/path/to/var/snort/snort.lua",
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

### `CaptureStatusPayload`

`capture.status` returns the daemon's persisted capture state plus the helper's
current status:

```json
{
  "capture": {
    "interface": "en0",
    "snort_pid": 12345,
    "log_dir": "/Users/me/Library/Application Support/PIGUI/snort",
    "mode": "helper",
    "started_at": 1750000000
  },
  "helper": {
    "ok": true,
    "data": {
      "version": "0.1.1",
      "uid": 0,
      "capture_running": true,
      "snort_pid": 12345,
      "interface": "en0"
    }
  }
}
```

`capture.start` takes `{"interface":"en0"}`. `capture.ensure` takes `{}`; it is
idempotent, auto-selects the interface, and is used on app launch so users do not
need a Start button. `capture.stop` takes `{}`. `capture.helper_status` returns
the raw helper response.

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
deletes the trust override, so a domain in the bundled Tranco default list
returns to `trusted` and other domains return to `unknown`. The domain is
normalized; a subdomain is reduced to its
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
  "ttl": "300",
  "trust_state": "trusted"
}
```

`TlsList` observations: `id, ts, client_ip, server_ip, server_port,
server_name, version, validation_status, subject, issuer`.

`HttpList` observations: `id, ts, client_ip, server_ip, server_port, method,
host, uri, user_agent, status_code`.

`QuicList` observations: `id, ts, client_ip, server_ip, server_port,
server_name, client_protocol`.

## Firewall

`FirewallStatusPayload` combines daemon state, database counts, and the helper's
raw PF status:

```json
{
  "state": {
    "enabled": true,
    "mode": "blocklist",
    "generation": 2,
    "applied_generation": 2,
    "applied_at": 1750000000,
    "last_error": null,
    "pf_enabled_by_pigui": true
  },
  "rule_count": 1,
  "block_count": 0,
  "helper": {"ok": true, "data": {"pf_enabled": true, "...": "..."}},
  "helper_error": null
}
```

`FirewallRule` fields: `id, name, enabled, action, direction, protocol,
local_address, local_port, remote_address, remote_port, interface, log,
priority, created_at, updated_at`. `action` is `allow`, `block`, or `reject`;
`direction` is `in`, `out`, or `both`; `protocol` is `any`, `tcp`, `udp`,
`icmp`, or `icmp6`.

`FirewallRuleList` contains `rules` and `state`.

`FirewallBlock` fields: `id, address, direction, ttl_secs, reason, source,
created_at, expires_at`. `FirewallBlockList` contains `blocks`.

`firewall.apply` compiles enabled rules and calls the root helper. When
`state.enabled` is false, it flushes the PIGUI anchors, clears dynamic tables,
and releases PIGUI's PF enable token. CRUD and enable calls update desired state
but do not apply; the GUI calls `firewall.apply`, and a 15-second daemon
reconciler retries pending applies and removes expired blocks.

`firewall.counters` and `firewall.events.list` return the helper's raw response.
The helper keeps up to 1000 recent pflog events in memory and drains them when
`firewall.events.list` is called. The daemon does not yet persist event history.

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
| `pigui-cli firewall status` | `firewall.status` |
| `pigui-cli firewall rules` | `firewall.rules.list` |
| `pigui-cli firewall apply` | `firewall.apply` |
| `pigui-cli firewall enable <bool>` | `firewall.enable` |
| `pigui-cli firewall reset` | `firewall.reset` |
| `pigui-cli firewall blocks` | `firewall.blocks.list` |
| `pigui-cli firewall block <ip>` | `firewall.blocks.add` |
| `pigui-cli firewall unblock <ip>` | `firewall.blocks.remove` |
| `pigui-cli firewall counters` | `firewall.counters` |
| `pigui-cli firewall events` | `firewall.events.list` |
| `pigui-cli snort status` | local PID-file status, not RPC |

The GUI uses `status`, capture, list, detail, trust, watched-domain, and
settings/maintenance methods. It does not currently expose TLS/HTTP/QUIC lists.

## Current security gaps

- The server does not verify peer credentials.
- Access control relies on socket directory and socket file permissions.
- There is no request authentication or per-method authorization.

Peer credential checks and helper authorization are planned. See
[07-security.md](07-security.md).
