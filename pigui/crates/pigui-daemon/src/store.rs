use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use pigui_collector::CollectorSnapshot;
use pigui_core::domain::{normalize_hostname, registrable_domain};
use pigui_core::error::{Error, Result};
use pigui_core::models::{
    Alert, Connection, Destination, DnsObservation, DomainSummary, EndpointDomain, ExtractorRecord,
    Flow, HttpObservation, Process, QuicObservation, ReviewFlag, TlsObservation, TrustState,
    WatchedDomain,
};
use pigui_core::rpc::{
    AlertRecord, DestinationDetail, DestinationProcess, ListQuery, ProcessDestination,
    ProcessDetail, PruneResult, SortDirection, TableCount,
};
use pigui_core::settings::{AppSettings, ThemeMode};
use rusqlite::{
    Connection as SqlConnection, OpenFlags, OptionalExtension, params, params_from_iter,
    types::Value as SqlValue,
};
use serde::Serialize;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_ts INTEGER NOT NULL,
    ts_text TEXT,
    gid INTEGER NOT NULL,
    sid INTEGER NOT NULL,
    rev INTEGER NOT NULL,
    priority INTEGER,
    class TEXT,
    msg TEXT,
    proto TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    action TEXT,
    app_id TEXT,
    service TEXT,
    rule TEXT,
    direction TEXT,
    pkt_num INTEGER,
    raw_json TEXT NOT NULL,
    ingested_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_dedupe ON alerts (
    event_ts, gid, sid, rev,
    IFNULL(proto, ''), IFNULL(src_ip, ''), IFNULL(src_port, 0),
    IFNULL(dst_ip, ''), IFNULL(dst_port, 0)
);

CREATE INDEX IF NOT EXISTS idx_alerts_event_ts ON alerts (event_ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_dst_ip ON alerts (dst_ip);

CREATE TABLE IF NOT EXISTS endpoints (
    ip TEXT PRIMARY KEY,
    hostname TEXT,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    bytes_in INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0,
    connection_count INTEGER NOT NULL DEFAULT 0,
    process_count INTEGER NOT NULL DEFAULT 0,
    alert_count INTEGER NOT NULL DEFAULT 0,
    reputation INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen ON endpoints (last_seen DESC);

CREATE TABLE IF NOT EXISTS processes (
    pid INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    path TEXT,
    user TEXT,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    bytes_in INTEGER NOT NULL DEFAULT 0,
    bytes_out INTEGER NOT NULL DEFAULT 0,
    connection_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_processes_last_seen ON processes (last_seen DESC);

CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proto TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    client_port INTEGER NOT NULL,
    server_ip TEXT NOT NULL,
    server_port INTEGER NOT NULL,
    pid INTEGER,
    process_name TEXT,
    interface TEXT,
    state TEXT,
    bytes_ab INTEGER NOT NULL DEFAULT 0,
    bytes_ba INTEGER NOT NULL DEFAULT 0,
    packets_ab INTEGER NOT NULL DEFAULT 0,
    packets_ba INTEGER NOT NULL DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    UNIQUE (proto, client_ip, client_port, server_ip, server_port)
);

CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_flows_server_ip ON flows (server_ip);
CREATE INDEX IF NOT EXISTS idx_flows_pid ON flows (pid);

CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT,
    ts INTEGER NOT NULL,
    proto TEXT,
    client_ip TEXT,
    client_port INTEGER,
    server_ip TEXT,
    server_port INTEGER,
    service TEXT,
    conn_state TEXT,
    duration REAL,
    packets_ab INTEGER NOT NULL DEFAULT 0,
    packets_ba INTEGER NOT NULL DEFAULT 0,
    bytes_ab INTEGER NOT NULL DEFAULT 0,
    bytes_ba INTEGER NOT NULL DEFAULT 0,
    pid INTEGER,
    process_name TEXT,
    created_at INTEGER NOT NULL,
    UNIQUE (uid)
);

CREATE INDEX IF NOT EXISTS idx_connections_ts ON connections (ts DESC);
CREATE INDEX IF NOT EXISTS idx_connections_server_ip ON connections (server_ip);

CREATE TABLE IF NOT EXISTS dns_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    client_ip TEXT,
    query TEXT,
    qtype TEXT,
    rcode TEXT,
    answers TEXT,
    ttl TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_dedupe ON dns_observations (
    ts, IFNULL(client_ip, ''), IFNULL(query, ''), IFNULL(qtype, ''), IFNULL(answers, '')
);
CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_observations (ts DESC);

CREATE TABLE IF NOT EXISTS tls_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    client_ip TEXT,
    server_ip TEXT,
    server_port INTEGER,
    server_name TEXT,
    version TEXT,
    validation_status TEXT,
    subject TEXT,
    issuer TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tls_dedupe ON tls_observations (
    ts, IFNULL(server_ip, ''), IFNULL(server_port, 0), IFNULL(server_name, '')
);
CREATE INDEX IF NOT EXISTS idx_tls_ts ON tls_observations (ts DESC);
CREATE INDEX IF NOT EXISTS idx_tls_server_ip ON tls_observations (server_ip);

CREATE TABLE IF NOT EXISTS http_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    client_ip TEXT,
    server_ip TEXT,
    server_port INTEGER,
    method TEXT,
    host TEXT,
    uri TEXT,
    user_agent TEXT,
    status_code TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_http_dedupe ON http_observations (
    ts, IFNULL(server_ip, ''), IFNULL(server_port, 0), IFNULL(method, ''),
    IFNULL(host, ''), IFNULL(uri, '')
);
CREATE INDEX IF NOT EXISTS idx_http_ts ON http_observations (ts DESC);

CREATE TABLE IF NOT EXISTS quic_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    client_ip TEXT,
    server_ip TEXT,
    server_port INTEGER,
    server_name TEXT,
    client_protocol TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_quic_dedupe ON quic_observations (
    ts, IFNULL(server_ip, ''), IFNULL(server_port, 0), IFNULL(server_name, ''),
    IFNULL(client_protocol, '')
);
CREATE INDEX IF NOT EXISTS idx_quic_ts ON quic_observations (ts DESC);

CREATE TABLE IF NOT EXISTS domains (
    domain TEXT PRIMARY KEY,
    registrable_domain TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_domains_registrable ON domains (registrable_domain);
CREATE INDEX IF NOT EXISTS idx_domains_last_seen ON domains (last_seen DESC);

CREATE TABLE IF NOT EXISTS endpoint_domains (
    ip TEXT NOT NULL,
    domain TEXT NOT NULL,
    server_port INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ip, domain)
);

CREATE INDEX IF NOT EXISTS idx_endpoint_domains_domain ON endpoint_domains (domain);
CREATE INDEX IF NOT EXISTS idx_endpoint_domains_last_seen ON endpoint_domains (last_seen DESC);

CREATE TABLE IF NOT EXISTS domain_trust (
    registrable_domain TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    note TEXT,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ptr_observations (
    ip TEXT PRIMARY KEY,
    hostname TEXT,
    status TEXT NOT NULL,
    error TEXT,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ptr_expires_at ON ptr_observations (expires_at);

CREATE TABLE IF NOT EXISTS watched_domains (
    domain TEXT PRIMARY KEY,
    registrable_domain TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_resolved_at INTEGER,
    last_error TEXT
);

"#;

const INSERT_ALERT: &str = r#"
INSERT OR IGNORE INTO alerts (
    event_ts, ts_text, gid, sid, rev, priority, class, msg, proto,
    src_ip, src_port, dst_ip, dst_port, action, app_id, service, rule,
    direction, pkt_num, raw_json, ingested_at
) VALUES (
    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
    ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
    ?18, ?19, ?20, ?21
)
"#;

const UPSERT_ENDPOINT_ALERT: &str = r#"
INSERT INTO endpoints (ip, first_seen, last_seen, alert_count)
VALUES (?1, ?2, ?2, 1)
ON CONFLICT(ip) DO UPDATE SET
    first_seen = MIN(first_seen, excluded.first_seen),
    last_seen = MAX(last_seen, excluded.last_seen),
    alert_count = alert_count + 1
"#;

const UPSERT_ENDPOINT_HOSTNAME: &str = r#"
INSERT INTO endpoints (ip, first_seen, last_seen, hostname)
VALUES (?1, ?2, ?2, ?3)
ON CONFLICT(ip) DO UPDATE SET
    first_seen = MIN(first_seen, excluded.first_seen),
    last_seen = MAX(last_seen, excluded.last_seen),
    hostname = COALESCE(excluded.hostname, hostname)
"#;

const UPSERT_ENDPOINT_BYTES: &str = r#"
INSERT INTO endpoints (ip, first_seen, last_seen, bytes_in, bytes_out, connection_count)
VALUES (?1, ?2, ?2, ?3, ?4, 1)
ON CONFLICT(ip) DO UPDATE SET
    first_seen = MIN(first_seen, excluded.first_seen),
    last_seen = MAX(last_seen, excluded.last_seen),
    bytes_in = bytes_in + excluded.bytes_in,
    bytes_out = bytes_out + excluded.bytes_out,
    connection_count = connection_count + 1
"#;

const UPSERT_ENDPOINT_IDENTITY: &str = r#"
INSERT INTO endpoints (ip, first_seen, last_seen)
VALUES (?1, ?2, ?2)
ON CONFLICT(ip) DO UPDATE SET
    first_seen = MIN(first_seen, excluded.first_seen),
    last_seen = MAX(last_seen, excluded.last_seen)
"#;

const UPSERT_DOMAIN: &str = r#"
INSERT INTO domains (domain, registrable_domain, first_seen, last_seen, observation_count)
VALUES (?1, ?2, ?3, ?3, 1)
ON CONFLICT(domain) DO UPDATE SET
    registrable_domain = excluded.registrable_domain,
    first_seen = MIN(first_seen, excluded.first_seen),
    last_seen = MAX(last_seen, excluded.last_seen),
    observation_count = observation_count + 1
"#;

const UPSERT_ENDPOINT_DOMAIN: &str = r#"
INSERT INTO endpoint_domains (
    ip, domain, server_port, source, first_seen, last_seen, observation_count
) VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1)
ON CONFLICT(ip, domain) DO UPDATE SET
    server_port = CASE
        WHEN excluded.server_port > 0 THEN excluded.server_port
        ELSE endpoint_domains.server_port END,
    source = CASE
        WHEN (CASE excluded.source
            WHEN 'tls' THEN 4 WHEN 'quic' THEN 3 WHEN 'http' THEN 2 WHEN 'dns' THEN 1 ELSE 0 END)
        >= (CASE endpoint_domains.source
            WHEN 'tls' THEN 4 WHEN 'quic' THEN 3 WHEN 'http' THEN 2 WHEN 'dns' THEN 1 ELSE 0 END)
        THEN excluded.source ELSE endpoint_domains.source END,
    first_seen = MIN(first_seen, excluded.first_seen),
    last_seen = MAX(last_seen, excluded.last_seen),
    observation_count = observation_count + 1
"#;

const UPSERT_PROCESS: &str = r#"
INSERT INTO processes (pid, name, path, user, first_seen, last_seen, bytes_in, bytes_out, connection_count)
VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, ?8)
ON CONFLICT(pid) DO UPDATE SET
    name = excluded.name,
    path = excluded.path,
    user = excluded.user,
    last_seen = excluded.last_seen,
    bytes_in = excluded.bytes_in,
    bytes_out = excluded.bytes_out,
    connection_count = excluded.connection_count
"#;

const UPSERT_FLOW: &str = r#"
INSERT INTO flows (
    proto, client_ip, client_port, server_ip, server_port, pid, process_name,
    interface, state, bytes_ab, bytes_ba, packets_ab, packets_ba, first_seen, last_seen
) VALUES (
    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, 0, ?12, ?12
)
ON CONFLICT(proto, client_ip, client_port, server_ip, server_port) DO UPDATE SET
    pid = excluded.pid,
    process_name = excluded.process_name,
    interface = excluded.interface,
    state = excluded.state,
    bytes_ab = excluded.bytes_ab,
    bytes_ba = excluded.bytes_ba,
    last_seen = excluded.last_seen
"#;

const SELECT_ALERT: &str = r#"
SELECT
    id, event_ts, ts_text, gid, sid, rev, priority, class, msg, proto,
    src_ip, src_port, dst_ip, dst_port, action, app_id, service, rule,
    direction, pkt_num, ingested_at
FROM alerts
ORDER BY event_ts DESC, id DESC
LIMIT ?1 OFFSET ?2
"#;

const SELECT_DESTINATION: &str = r#"
SELECT
    e.ip, e.hostname, e.first_seen, e.last_seen, e.bytes_in, e.bytes_out,
    e.connection_count,
    (SELECT COUNT(*) FROM (
        SELECT f.pid FROM flows f WHERE f.server_ip = e.ip AND f.pid IS NOT NULL
        UNION
        SELECT c.pid FROM connections c WHERE c.server_ip = e.ip AND c.pid IS NOT NULL
    )),
    (SELECT COALESCE(SUM(f.bytes_ba), 0) FROM flows f WHERE f.server_ip = e.ip),
    (SELECT COALESCE(SUM(f.bytes_ab), 0) FROM flows f WHERE f.server_ip = e.ip),
    (SELECT COUNT(*) FROM flows f WHERE f.server_ip = e.ip),
    e.alert_count, e.reputation, e.blocked
FROM endpoints e
ORDER BY e.alert_count DESC, e.last_seen DESC, e.ip ASC
LIMIT ?1 OFFSET ?2
"#;

const SELECT_DESTINATION_BY_IP: &str = r#"
SELECT
    e.ip, e.hostname, e.first_seen, e.last_seen, e.bytes_in, e.bytes_out,
    e.connection_count,
    (SELECT COUNT(*) FROM (
        SELECT f.pid FROM flows f WHERE f.server_ip = e.ip AND f.pid IS NOT NULL
        UNION
        SELECT c.pid FROM connections c WHERE c.server_ip = e.ip AND c.pid IS NOT NULL
    )),
    (SELECT COALESCE(SUM(f.bytes_ba), 0) FROM flows f WHERE f.server_ip = e.ip),
    (SELECT COALESCE(SUM(f.bytes_ab), 0) FROM flows f WHERE f.server_ip = e.ip),
    (SELECT COUNT(*) FROM flows f WHERE f.server_ip = e.ip),
    e.alert_count, e.reputation, e.blocked
FROM endpoints e
WHERE e.ip = ?1
LIMIT 1
"#;

const SELECT_ALERT_BY_DST: &str = r#"
SELECT
    id, event_ts, ts_text, gid, sid, rev, priority, class, msg, proto,
    src_ip, src_port, dst_ip, dst_port, action, app_id, service, rule,
    direction, pkt_num, ingested_at
FROM alerts
WHERE dst_ip = ?1
ORDER BY event_ts DESC, id DESC
LIMIT 10
"#;

const SELECT_FLOW: &str = r#"
SELECT
    id, proto, client_ip, client_port, server_ip, server_port, pid, process_name,
    interface, state, bytes_ab, bytes_ba, packets_ab, packets_ba, first_seen, last_seen
FROM flows
ORDER BY last_seen DESC, id DESC
LIMIT ?1 OFFSET ?2
"#;

const SELECT_PROCESS: &str = r#"
SELECT
    pid, name, path, user, first_seen, last_seen, bytes_in, bytes_out, connection_count
FROM processes
ORDER BY last_seen DESC, bytes_in + bytes_out DESC
LIMIT ?1 OFFSET ?2
"#;

const SELECT_PROCESS_BY_PID: &str = r#"
SELECT
    pid, name, path, user, first_seen, last_seen, bytes_in, bytes_out, connection_count
FROM processes
WHERE pid = ?1
LIMIT 1
"#;

const SELECT_CONNECTION: &str = r#"
SELECT
    id, uid, ts, proto, client_ip, client_port, server_ip, server_port, service,
    conn_state, duration, packets_ab, packets_ba, bytes_ab, bytes_ba, pid, process_name
FROM connections
ORDER BY ts DESC, id DESC
LIMIT ?1 OFFSET ?2
"#;

const SELECT_ALERT_BASE: &str = r#"
SELECT
    id, event_ts, ts_text, gid, sid, rev, priority, class, msg, proto,
    src_ip, src_port, dst_ip, dst_port, action, app_id, service, rule,
    direction, pkt_num, ingested_at
FROM alerts
"#;

const SELECT_FLOW_BASE: &str = r#"
SELECT
    id, proto, client_ip, client_port, server_ip, server_port, pid, process_name,
    interface, state, bytes_ab, bytes_ba, packets_ab, packets_ba, first_seen, last_seen
FROM flows
"#;

const SELECT_PROCESS_BASE: &str = r#"
SELECT
    pid, name, path, user, first_seen, last_seen, bytes_in, bytes_out, connection_count
FROM processes
"#;

const SELECT_CONNECTION_BASE: &str = r#"
SELECT
    id, uid, ts, proto, client_ip, client_port, server_ip, server_port, service,
    conn_state, duration, packets_ab, packets_ba, bytes_ab, bytes_ba, pid, process_name
FROM connections
"#;

const DEST_PROCESS_COUNT_SQL: &str = "(SELECT COUNT(*) FROM (SELECT f.pid FROM flows f WHERE f.server_ip = e.ip AND f.pid IS NOT NULL UNION SELECT c.pid FROM connections c WHERE c.server_ip = e.ip AND c.pid IS NOT NULL))";

const SELECT_DESTINATION_BASE: &str = r#"
SELECT
    e.ip, e.hostname, e.first_seen, e.last_seen, e.bytes_in, e.bytes_out,
    e.connection_count,
    (SELECT COUNT(*) FROM (
        SELECT f.pid FROM flows f WHERE f.server_ip = e.ip AND f.pid IS NOT NULL
        UNION
        SELECT c.pid FROM connections c WHERE c.server_ip = e.ip AND c.pid IS NOT NULL
    )),
    (SELECT COALESCE(SUM(f.bytes_ba), 0) FROM flows f WHERE f.server_ip = e.ip),
    (SELECT COALESCE(SUM(f.bytes_ab), 0) FROM flows f WHERE f.server_ip = e.ip),
    (SELECT COUNT(*) FROM flows f WHERE f.server_ip = e.ip),
    e.alert_count, e.reputation, e.blocked
FROM endpoints e
"#;

const SELECT_DOMAIN_BASE: &str = r#"
SELECT d.registrable_domain,
                        COALESCE(t.state, 'unknown'),
                        MIN(d.first_seen),
                        MAX(d.last_seen),
                        SUM(d.observation_count),
                        GROUP_CONCAT(d.domain, char(31)),
                        (SELECT GROUP_CONCAT(source, char(31))
                         FROM (
                             SELECT DISTINCT ed.source AS source
                             FROM endpoint_domains ed
                             JOIN domains dd ON dd.domain = ed.domain
                             WHERE dd.registrable_domain = d.registrable_domain
                         )),
                        (SELECT COUNT(DISTINCT ed.ip)
                         FROM endpoint_domains ed
                         JOIN domains dd ON dd.domain = ed.domain
                         WHERE dd.registrable_domain = d.registrable_domain),
                        (SELECT COUNT(*) FROM (
                            SELECT f.pid
                            FROM flows f
                            JOIN endpoint_domains ed ON ed.ip = f.server_ip
                            JOIN domains dd ON dd.domain = ed.domain
                            WHERE dd.registrable_domain = d.registrable_domain
                              AND f.pid IS NOT NULL
                            UNION
                            SELECT c.pid
                            FROM connections c
                            JOIN endpoint_domains ed ON ed.ip = c.server_ip
                            JOIN domains dd ON dd.domain = ed.domain
                            WHERE dd.registrable_domain = d.registrable_domain
                              AND c.pid IS NOT NULL
                        )),
                        (SELECT EXISTS(
                            SELECT 1
                            FROM alerts a
                            JOIN endpoint_domains ed ON ed.ip = a.dst_ip
                            JOIN domains dd ON dd.domain = ed.domain
                            WHERE dd.registrable_domain = d.registrable_domain
                        )),
                        (SELECT EXISTS(
                            SELECT 1
                            FROM tls_observations t
                            JOIN endpoint_domains ed ON ed.ip = t.server_ip
                            JOIN domains dd ON dd.domain = ed.domain
                            WHERE dd.registrable_domain = d.registrable_domain
                              AND lower(COALESCE(t.validation_status, '')) IN
                                  ('invalid', 'self_signed', 'self signed', 'untrusted')
                        ))
                 FROM domains d
                 LEFT JOIN domain_trust t ON t.registrable_domain = d.registrable_domain
                 /*FILTER*/ GROUP BY d.registrable_domain
"#;

const SELECT_DNS_BASE: &str = r#"
SELECT id, ts, client_ip, query, qtype, rcode, answers, ttl
FROM dns_observations
"#;

const SELECT_TLS_BASE: &str = r#"
SELECT id, ts, client_ip, server_ip, server_port, server_name, version,
       validation_status, subject, issuer
FROM tls_observations
"#;

const SELECT_HTTP_BASE: &str = r#"
SELECT id, ts, client_ip, server_ip, server_port, method, host, uri,
       user_agent, status_code
FROM http_observations
"#;

const SELECT_QUIC_BASE: &str = r#"
SELECT id, ts, client_ip, server_ip, server_port, server_name, client_protocol
FROM quic_observations
"#;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct IngestStats {
    pub inserted: u64,
    pub duplicates: u64,
    pub malformed: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ExtractorStats {
    pub inserted: u64,
    pub duplicates: u64,
}

#[derive(Debug)]
pub struct Store {
    conn: SqlConnection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        let conn = SqlConnection::open(path).map_err(db)?;
        let store = Self::init(conn, true)?;
        let _ = store.import_legacy_gui_settings(path);
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = SqlConnection::open_in_memory().map_err(db)?;
        Self::init(conn, false)
    }

    fn init(conn: SqlConnection, wal: bool) -> Result<Self> {
        if wal {
            conn.pragma_update(None, "journal_mode", "WAL")
                .map_err(db)?;
        }
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(db)?;
        conn.pragma_update(None, "foreign_keys", "ON").map_err(db)?;
        let previous_version = read_schema_version(&conn)?;
        conn.execute_batch(SCHEMA).map_err(db)?;
        ensure_endpoints_hostname(&conn)?;
        if !matches!(previous_version.as_deref(), Some("5")) {
            migrate_v5(&conn)?;
        }
        if !matches!(previous_version.as_deref(), Some("3" | "4" | "5")) {
            backfill_domains(&conn)?;
        }
        set_schema_version(&conn, "5")?;
        Ok(Self { conn })
    }

    /// Insert normalized alerts. Returns inserted/duplicate counts. The caller
    /// is responsible for counting malformed input.
    pub fn insert_alerts(&mut self, entries: &[(Alert, String)]) -> Result<IngestStats> {
        let now = unix_now();
        let tx = self.conn.transaction().map_err(db)?;
        let mut stats = IngestStats::default();

        for (alert, raw) in entries {
            let inserted = tx
                .execute(
                    INSERT_ALERT,
                    params![
                        alert.event_ts,
                        alert.ts_text,
                        alert.gid,
                        alert.sid,
                        alert.rev,
                        alert.priority,
                        alert.class,
                        alert.msg,
                        alert.proto,
                        alert.src_ip,
                        alert.src_port,
                        alert.dst_ip,
                        alert.dst_port,
                        alert.action,
                        alert.app_id,
                        alert.service,
                        alert.rule,
                        alert.direction,
                        alert.pkt_num.map(|value| value as i64),
                        raw,
                        now,
                    ],
                )
                .map_err(db)?;

            if inserted == 1 {
                stats.inserted += 1;
                if let Some(dst_ip) = &alert.dst_ip {
                    tx.execute(UPSERT_ENDPOINT_ALERT, params![dst_ip, alert.event_ts])
                        .map_err(db)?;
                }
            } else {
                stats.duplicates += 1;
            }
        }

        tx.commit().map_err(db)?;
        Ok(stats)
    }

    /// Persist one nettop snapshot: processes, live flows, byte counters.
    pub fn apply_snapshot(&mut self, snapshot: &CollectorSnapshot, now: i64) -> Result<()> {
        let tx = self.conn.transaction().map_err(db)?;

        for process in &snapshot.processes {
            tx.execute(
                UPSERT_PROCESS,
                params![
                    i64::from(process.pid),
                    process.name,
                    process.path,
                    process.user,
                    now,
                    process.bytes_in as i64,
                    process.bytes_out as i64,
                    process.connection_count as i64,
                ],
            )
            .map_err(db)?;
        }

        for socket in &snapshot.sockets {
            tx.execute(UPSERT_ENDPOINT_IDENTITY, params![socket.server_ip, now])
                .map_err(db)?;
            tx.execute(
                UPSERT_FLOW,
                params![
                    socket.proto,
                    socket.client_ip,
                    i64::from(socket.client_port),
                    socket.server_ip,
                    i64::from(socket.server_port),
                    i64::from(socket.pid),
                    socket.process_name,
                    socket.interface,
                    socket.state,
                    socket.bytes_ab as i64,
                    socket.bytes_ba as i64,
                    now,
                ],
            )
            .map_err(db)?;
        }

        tx.commit().map_err(db)?;
        Ok(())
    }

    pub fn insert_extractor_records(
        &mut self,
        records: &[ExtractorRecord],
        now: i64,
    ) -> Result<ExtractorStats> {
        let tx = self.conn.transaction().map_err(db)?;
        let mut stats = ExtractorStats::default();

        for record in records {
            let inserted = match record {
                ExtractorRecord::Conn(event) => insert_conn(&tx, event, now)?,
                ExtractorRecord::Dns(event) => insert_dns(&tx, event, now)?,
                ExtractorRecord::Tls(event) => insert_tls(&tx, event, now)?,
                ExtractorRecord::Http(event) => insert_http(&tx, event, now)?,
                ExtractorRecord::Quic(event) => insert_quic(&tx, event, now)?,
            };
            if inserted {
                stats.inserted += 1;
            } else {
                stats.duplicates += 1;
            }
        }

        tx.commit().map_err(db)?;
        Ok(stats)
    }

    pub fn list_alerts(&self, limit: u32, offset: u32) -> Result<Vec<AlertRecord>> {
        let mut statement = self.conn.prepare(SELECT_ALERT).map_err(db)?;
        let rows = statement
            .query_map(params![limit, offset], |row| {
                Ok(AlertRecord {
                    id: row.get(0)?,
                    alert: Alert {
                        event_ts: row.get(1)?,
                        ts_text: row.get(2)?,
                        gid: row.get(3)?,
                        sid: row.get(4)?,
                        rev: row.get(5)?,
                        priority: row.get(6)?,
                        class: row.get(7)?,
                        msg: row.get(8)?,
                        proto: row.get(9)?,
                        src_ip: row.get(10)?,
                        src_port: row.get(11)?,
                        dst_ip: row.get(12)?,
                        dst_port: row.get(13)?,
                        action: row.get(14)?,
                        app_id: row.get(15)?,
                        service: row.get(16)?,
                        rule: row.get(17)?,
                        direction: row.get(18)?,
                        pkt_num: row.get::<_, Option<i64>>(19)?.map(|value| value as u64),
                    },
                    ingested_at: row.get(20)?,
                })
            })
            .map_err(db)?;

        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    pub fn count_alerts(&self) -> Result<u64> {
        self.count("SELECT COUNT(*) FROM alerts")
    }

    pub fn list_destinations(&self, limit: u32, offset: u32) -> Result<Vec<Destination>> {
        let mut statement = self.conn.prepare(SELECT_DESTINATION).map_err(db)?;
        let rows = statement
            .query_map(params![limit, offset], destination_from_row)
            .map_err(db)?;
        let mut destinations = rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?;
        drop(statement);

        for destination in &mut destinations {
            self.hydrate_destination(destination, true)?;
        }
        Ok(destinations)
    }

    pub fn count_destinations(&self) -> Result<u64> {
        self.count("SELECT COUNT(*) FROM endpoints")
    }

    pub fn endpoint_domains(&self, ip: &str) -> Result<Vec<EndpointDomain>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT ed.domain, d.registrable_domain, ed.source, ed.server_port,
                        COALESCE(t.state, 'unknown'), ed.first_seen, ed.last_seen
                 FROM endpoint_domains ed
                 JOIN domains d ON d.domain = ed.domain
                 LEFT JOIN domain_trust t ON t.registrable_domain = d.registrable_domain
                 WHERE ed.ip = ?1
                 ORDER BY ed.last_seen DESC, ed.domain ASC",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(params![ip], |row| {
                let port: i64 = row.get(3)?;
                let trust: String = row.get(4)?;
                Ok(EndpointDomain {
                    domain: row.get(0)?,
                    registrable_domain: row.get(1)?,
                    source: row.get(2)?,
                    server_port: (port > 0).then_some(port as u16),
                    trust_state: TrustState::parse(&trust).unwrap_or_default(),
                    first_seen: row.get(5)?,
                    last_seen: row.get(6)?,
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    pub fn list_domains(&self, limit: u32, offset: u32) -> Result<Vec<DomainSummary>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT d.registrable_domain,
                        COALESCE(t.state, 'unknown'),
                        MIN(d.first_seen),
                        MAX(d.last_seen),
                        SUM(d.observation_count),
                        GROUP_CONCAT(d.domain, char(31)),
                        (SELECT GROUP_CONCAT(source, char(31))
                         FROM (
                             SELECT DISTINCT ed.source AS source
                             FROM endpoint_domains ed
                             JOIN domains dd ON dd.domain = ed.domain
                             WHERE dd.registrable_domain = d.registrable_domain
                         )),
                        (SELECT COUNT(DISTINCT ed.ip)
                         FROM endpoint_domains ed
                         JOIN domains dd ON dd.domain = ed.domain
                         WHERE dd.registrable_domain = d.registrable_domain),
                        (SELECT COUNT(*) FROM (
                            SELECT f.pid
                            FROM flows f
                            JOIN endpoint_domains ed ON ed.ip = f.server_ip
                            JOIN domains dd ON dd.domain = ed.domain
                            WHERE dd.registrable_domain = d.registrable_domain
                              AND f.pid IS NOT NULL
                            UNION
                            SELECT c.pid
                            FROM connections c
                            JOIN endpoint_domains ed ON ed.ip = c.server_ip
                            JOIN domains dd ON dd.domain = ed.domain
                            WHERE dd.registrable_domain = d.registrable_domain
                              AND c.pid IS NOT NULL
                        )),
                        (SELECT EXISTS(
                            SELECT 1
                            FROM alerts a
                            JOIN endpoint_domains ed ON ed.ip = a.dst_ip
                            JOIN domains dd ON dd.domain = ed.domain
                            WHERE dd.registrable_domain = d.registrable_domain
                        )),
                        (SELECT EXISTS(
                            SELECT 1
                            FROM tls_observations t
                            JOIN endpoint_domains ed ON ed.ip = t.server_ip
                            JOIN domains dd ON dd.domain = ed.domain
                            WHERE dd.registrable_domain = d.registrable_domain
                              AND lower(COALESCE(t.validation_status, '')) IN
                                  ('invalid', 'self_signed', 'self signed', 'untrusted')
                        ))
                 FROM domains d
                 LEFT JOIN domain_trust t ON t.registrable_domain = d.registrable_domain
                 GROUP BY d.registrable_domain
                 ORDER BY MAX(d.last_seen) DESC
                 LIMIT ?1 OFFSET ?2",
            )
            .map_err(db)?;
        let now = unix_now();
        let rows = statement
            .query_map(params![limit, offset], |row| {
                let trust: String = row.get(1)?;
                let trust_state = TrustState::parse(&trust).unwrap_or_default();
                let first_seen: i64 = row.get(2)?;
                let hostnames: Option<String> = row.get(5)?;
                let sources: Option<String> = row.get(6)?;
                let mut flags = Vec::new();
                if trust_state == TrustState::Unknown {
                    flags.push(ReviewFlag::UnknownTrust);
                }
                if now.saturating_sub(first_seen) <= 86_400 {
                    flags.push(ReviewFlag::NewDomain);
                }
                if row.get::<_, i64>(9)? != 0 {
                    flags.push(ReviewFlag::Alerts);
                }
                if row.get::<_, i64>(10)? != 0 {
                    flags.push(ReviewFlag::InvalidTls);
                }
                Ok(DomainSummary {
                    domain: row.get(0)?,
                    hostnames: hostnames
                        .unwrap_or_default()
                        .split('\u{1f}')
                        .filter(|value| !value.is_empty())
                        .map(str::to_string)
                        .collect(),
                    sources: sources
                        .unwrap_or_default()
                        .split('\u{1f}')
                        .filter(|value| !value.is_empty())
                        .map(str::to_string)
                        .collect(),
                    trust_state,
                    first_seen,
                    last_seen: row.get(3)?,
                    observation_count: row.get::<_, i64>(4)? as u64,
                    endpoint_count: row.get::<_, i64>(7)? as u64,
                    process_count: row.get::<_, i64>(8)? as u64,
                    flags,
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    pub fn count_domains(&self) -> Result<u64> {
        self.count("SELECT COUNT(DISTINCT registrable_domain) FROM domains")
    }

    pub fn set_domain_trust(
        &self,
        domain: &str,
        state: TrustState,
        note: Option<&str>,
    ) -> Result<()> {
        let hostname = normalize_hostname(domain)
            .unwrap_or_else(|| domain.trim().trim_end_matches('.').to_ascii_lowercase());
        let registrable = registrable_domain(&hostname);
        if state == TrustState::Unknown {
            self.conn
                .execute(
                    "DELETE FROM domain_trust WHERE registrable_domain = ?1",
                    params![registrable],
                )
                .map_err(db)?;
            return Ok(());
        }
        self.conn
            .execute(
                "INSERT INTO domain_trust (registrable_domain, state, note, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(registrable_domain) DO UPDATE SET
                     state = excluded.state,
                     note = excluded.note,
                     updated_at = excluded.updated_at",
                params![registrable, state.as_str(), note, unix_now()],
            )
            .map_err(db)?;
        Ok(())
    }

    pub fn list_watched_domains(&self) -> Result<Vec<WatchedDomain>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT domain, registrable_domain, enabled, last_resolved_at, last_error
                 FROM watched_domains
                 ORDER BY domain ASC",
            )
            .map_err(db)?;
        let rows = statement
            .query_map([], |row| {
                Ok(WatchedDomain {
                    domain: row.get(0)?,
                    registrable_domain: row.get(1)?,
                    enabled: row.get::<_, i64>(2)? != 0,
                    last_resolved_at: row.get(3)?,
                    last_error: row.get(4)?,
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    pub fn add_watched_domain(&self, domain: &str) -> Result<WatchedDomain> {
        let hostname = normalize_hostname(domain)
            .ok_or_else(|| Error::Parse(format!("invalid domain for watched list: {domain}")))?;
        let registrable = registrable_domain(&hostname);
        self.conn
            .execute(
                "INSERT INTO watched_domains (domain, registrable_domain, enabled)
                 VALUES (?1, ?2, 1)
                 ON CONFLICT(domain) DO UPDATE SET enabled = 1",
                params![hostname, registrable],
            )
            .map_err(db)?;
        self.watched_domain(&hostname)?
            .ok_or_else(|| Error::Database("watched domain was not stored".into()))
    }

    pub fn remove_watched_domain(&self, domain: &str) -> Result<()> {
        let hostname = normalize_hostname(domain)
            .unwrap_or_else(|| domain.trim().trim_end_matches('.').to_ascii_lowercase());
        self.conn
            .execute(
                "DELETE FROM watched_domains WHERE domain = ?1",
                params![hostname],
            )
            .map_err(db)?;
        Ok(())
    }

    pub fn due_watched_domains(
        &self,
        now: i64,
        interval_secs: i64,
        limit: u32,
    ) -> Result<Vec<String>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT domain FROM watched_domains
                 WHERE enabled != 0
                   AND (last_resolved_at IS NULL OR last_resolved_at <= ?1)
                 ORDER BY COALESCE(last_resolved_at, 0) ASC
                 LIMIT ?2",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(params![now - interval_secs, limit], |row| row.get(0))
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    pub fn save_watched_result(
        &self,
        domain: &str,
        ips: &[String],
        error: Option<&str>,
        now: i64,
    ) -> Result<()> {
        self.conn
            .execute(
                "UPDATE watched_domains
                 SET last_resolved_at = ?1, last_error = ?2
                 WHERE domain = ?3",
                params![now, error, domain],
            )
            .map_err(db)?;
        if error.is_none() {
            for ip in ips {
                record_domain_mapping(&self.conn, ip, domain, None, "watched", now)?;
            }
        }
        Ok(())
    }

    pub fn pending_ptr_ips(&self, now: i64, limit: u32) -> Result<Vec<String>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT e.ip FROM endpoints e
                 WHERE NOT EXISTS (
                     SELECT 1 FROM endpoint_domains ed WHERE ed.ip = e.ip
                 )
                 AND NOT EXISTS (
                     SELECT 1 FROM ptr_observations p
                     WHERE p.ip = e.ip AND p.expires_at > ?1
                 )
                 ORDER BY e.last_seen DESC
                 LIMIT ?2",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(params![now, limit], |row| row.get(0))
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    pub fn save_ptr_result(
        &self,
        ip: &str,
        hostname: Option<&str>,
        status: &str,
        error: Option<&str>,
        now: i64,
        ok_ttl_secs: i64,
        fail_ttl_secs: i64,
    ) -> Result<()> {
        let expires_at = now
            + if status == "ok" {
                ok_ttl_secs
            } else {
                fail_ttl_secs
            };
        self.conn
            .execute(
                "INSERT INTO ptr_observations (
                     ip, hostname, status, error, first_seen, last_seen, expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)
                 ON CONFLICT(ip) DO UPDATE SET
                     hostname = excluded.hostname,
                     status = excluded.status,
                     error = excluded.error,
                     last_seen = excluded.last_seen,
                     expires_at = excluded.expires_at",
                params![ip, hostname, status, error, now, expires_at],
            )
            .map_err(db)?;
        if let Some(hostname) = hostname {
            record_domain_mapping(&self.conn, ip, hostname, None, "ptr", now)?;
        }
        Ok(())
    }

    fn watched_domain(&self, domain: &str) -> Result<Option<WatchedDomain>> {
        self.conn
            .query_row(
                "SELECT domain, registrable_domain, enabled, last_resolved_at, last_error
                 FROM watched_domains WHERE domain = ?1",
                params![domain],
                |row| {
                    Ok(WatchedDomain {
                        domain: row.get(0)?,
                        registrable_domain: row.get(1)?,
                        enabled: row.get::<_, i64>(2)? != 0,
                        last_resolved_at: row.get(3)?,
                        last_error: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(db)
    }

    pub fn destination_detail(&self, ip: &str) -> Result<Option<DestinationDetail>> {
        let mut statement = self.conn.prepare(SELECT_DESTINATION_BY_IP).map_err(db)?;
        let destination = statement
            .query_row(params![ip], destination_from_row)
            .optional()
            .map_err(db)?;
        drop(statement);
        let Some(mut destination) = destination else {
            return Ok(None);
        };
        self.hydrate_destination(&mut destination, true)?;
        let processes = self.destination_processes(ip)?;
        let recent_alerts = self.alerts_for_destination(ip)?;
        Ok(Some(DestinationDetail {
            destination,
            processes,
            recent_alerts,
        }))
    }

    pub fn process_detail(&self, pid: u32) -> Result<Option<ProcessDetail>> {
        let mut statement = self.conn.prepare(SELECT_PROCESS_BY_PID).map_err(db)?;
        let process = statement
            .query_row(params![i64::from(pid)], process_from_row)
            .optional()
            .map_err(db)?;
        drop(statement);
        let Some(process) = process else {
            return Ok(None);
        };
        Ok(Some(ProcessDetail {
            process,
            destinations: self.process_destinations(pid)?,
        }))
    }

    fn hydrate_destination(&self, destination: &mut Destination, check_tls: bool) -> Result<()> {
        let domains = self.endpoint_domains(&destination.ip)?;
        let invalid_tls = if check_tls {
            self.has_invalid_tls(&destination.ip)?
        } else {
            false
        };
        if destination.hostname.is_none() {
            destination.hostname = domains.first().map(|domain| domain.domain.clone());
        }
        destination.trust_state = aggregate_trust(&domains);
        destination.flags =
            review_flags(&domains, destination.alert_count, invalid_tls, unix_now());
        destination.domains = domains;
        Ok(())
    }

    fn has_invalid_tls(&self, ip: &str) -> Result<bool> {
        let invalid: i64 = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM tls_observations
                    WHERE server_ip = ?1
                      AND lower(COALESCE(validation_status, '')) IN
                          ('invalid', 'self_signed', 'self signed', 'untrusted')
                )",
                params![ip],
                |row| row.get(0),
            )
            .map_err(db)?;
        Ok(invalid != 0)
    }

    fn destination_processes(&self, ip: &str) -> Result<Vec<DestinationProcess>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT pid, process_name,
                        SUM(CASE WHEN source = 'snort' THEN bytes_ba ELSE 0 END),
                        SUM(CASE WHEN source = 'snort' THEN bytes_ab ELSE 0 END),
                        SUM(CASE WHEN source = 'live' THEN bytes_ba ELSE 0 END),
                        SUM(CASE WHEN source = 'live' THEN bytes_ab ELSE 0 END),
                        SUM(CASE WHEN source = 'snort' THEN 1 ELSE 0 END),
                        SUM(CASE WHEN source = 'live' THEN 1 ELSE 0 END),
                        COUNT(*), MAX(last_seen)
                 FROM (
                     SELECT pid, process_name, bytes_ab, bytes_ba, last_seen, 'live' AS source
                     FROM flows WHERE server_ip = ?1
                     UNION ALL
                     SELECT pid, process_name, bytes_ab, bytes_ba, ts AS last_seen, 'snort' AS source
                     FROM connections WHERE server_ip = ?1
                 )
                 GROUP BY pid, process_name
                 ORDER BY SUM(bytes_ba) + SUM(bytes_ab) DESC",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(params![ip], |row| {
                Ok(DestinationProcess {
                    pid: row.get::<_, Option<i64>>(0)?.map(|value| value as u32),
                    process_name: row.get(1)?,
                    snort_bytes_in: row.get::<_, i64>(2)? as u64,
                    snort_bytes_out: row.get::<_, i64>(3)? as u64,
                    live_bytes_in: row.get::<_, i64>(4)? as u64,
                    live_bytes_out: row.get::<_, i64>(5)? as u64,
                    snort_connection_count: row.get::<_, i64>(6)? as u64,
                    live_connection_count: row.get::<_, i64>(7)? as u64,
                    connection_count: row.get::<_, i64>(8)? as u64,
                    last_seen: row.get(9)?,
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    fn alerts_for_destination(&self, ip: &str) -> Result<Vec<AlertRecord>> {
        let mut statement = self.conn.prepare(SELECT_ALERT_BY_DST).map_err(db)?;
        let rows = statement
            .query_map(params![ip], alert_record_from_row)
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    fn process_destinations(&self, pid: u32) -> Result<Vec<ProcessDestination>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT server_ip,
                        SUM(CASE WHEN source = 'snort' THEN bytes_ba ELSE 0 END),
                        SUM(CASE WHEN source = 'snort' THEN bytes_ab ELSE 0 END),
                        SUM(CASE WHEN source = 'live' THEN bytes_ba ELSE 0 END),
                        SUM(CASE WHEN source = 'live' THEN bytes_ab ELSE 0 END),
                        SUM(CASE WHEN source = 'snort' THEN 1 ELSE 0 END),
                        SUM(CASE WHEN source = 'live' THEN 1 ELSE 0 END),
                        COUNT(*), MAX(last_seen)
                 FROM (
                     SELECT server_ip, bytes_ab, bytes_ba, last_seen, 'live' AS source
                     FROM flows WHERE pid = ?1
                     UNION ALL
                     SELECT server_ip, bytes_ab, bytes_ba, ts AS last_seen, 'snort' AS source
                     FROM connections WHERE pid = ?1
                 )
                 WHERE server_ip IS NOT NULL
                 GROUP BY server_ip
                 ORDER BY SUM(bytes_ba) + SUM(bytes_ab) DESC",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(params![i64::from(pid)], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, i64>(2)? as u64,
                    row.get::<_, i64>(3)? as u64,
                    row.get::<_, i64>(4)? as u64,
                    row.get::<_, i64>(5)? as u64,
                    row.get::<_, i64>(6)? as u64,
                    row.get::<_, i64>(7)? as u64,
                    row.get::<_, i64>(8)?,
                ))
            })
            .map_err(db)?;
        let entries = rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?;
        drop(statement);

        let now = unix_now();
        let mut destinations = Vec::with_capacity(entries.len());
        for (
            ip,
            snort_bytes_in,
            snort_bytes_out,
            live_bytes_in,
            live_bytes_out,
            snort_connection_count,
            live_connection_count,
            connection_count,
            last_seen,
        ) in entries
        {
            let domains = self.endpoint_domains(&ip)?;
            let invalid_tls = self.has_invalid_tls(&ip)?;
            destinations.push(ProcessDestination {
                trust_state: aggregate_trust(&domains),
                flags: review_flags(&domains, 0, invalid_tls, now),
                domains,
                ip,
                snort_bytes_in,
                snort_bytes_out,
                live_bytes_in,
                live_bytes_out,
                snort_connection_count,
                live_connection_count,
                connection_count,
                last_seen,
            });
        }
        Ok(destinations)
    }

    pub fn list_flows(&self, limit: u32, offset: u32) -> Result<Vec<Flow>> {
        let mut statement = self.conn.prepare(SELECT_FLOW).map_err(db)?;
        let rows = statement
            .query_map(params![limit, offset], |row| {
                Ok(Flow {
                    id: row.get(0)?,
                    proto: row.get(1)?,
                    client_ip: row.get(2)?,
                    client_port: row.get(3)?,
                    server_ip: row.get(4)?,
                    server_port: row.get(5)?,
                    pid: row.get::<_, Option<i64>>(6)?.map(|value| value as u32),
                    process_name: row.get(7)?,
                    interface: row.get(8)?,
                    state: row.get(9)?,
                    bytes_ab: row.get::<_, i64>(10)? as u64,
                    bytes_ba: row.get::<_, i64>(11)? as u64,
                    packets_ab: row.get::<_, i64>(12)? as u64,
                    packets_ba: row.get::<_, i64>(13)? as u64,
                    first_seen: row.get(14)?,
                    last_seen: row.get(15)?,
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    pub fn count_flows(&self) -> Result<u64> {
        self.count("SELECT COUNT(*) FROM flows")
    }

    pub fn list_processes(&self, limit: u32, offset: u32) -> Result<Vec<Process>> {
        let mut statement = self.conn.prepare(SELECT_PROCESS).map_err(db)?;
        let rows = statement
            .query_map(params![limit, offset], |row| {
                Ok(Process {
                    pid: row.get::<_, i64>(0)? as u32,
                    name: row.get(1)?,
                    path: row.get(2)?,
                    user: row.get(3)?,
                    first_seen: row.get(4)?,
                    last_seen: row.get(5)?,
                    bytes_in: row.get::<_, i64>(6)? as u64,
                    bytes_out: row.get::<_, i64>(7)? as u64,
                    connection_count: row.get::<_, i64>(8)? as u64,
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    pub fn count_processes(&self) -> Result<u64> {
        self.count("SELECT COUNT(*) FROM processes")
    }

    pub fn list_connections(&self, limit: u32, offset: u32) -> Result<Vec<Connection>> {
        let mut statement = self.conn.prepare(SELECT_CONNECTION).map_err(db)?;
        let rows = statement
            .query_map(params![limit, offset], |row| {
                Ok(Connection {
                    id: row.get(0)?,
                    uid: row.get(1)?,
                    ts: row.get(2)?,
                    proto: row.get(3)?,
                    client_ip: row.get(4)?,
                    client_port: row.get::<_, Option<i64>>(5)?.map(|value| value as u16),
                    server_ip: row.get(6)?,
                    server_port: row.get::<_, Option<i64>>(7)?.map(|value| value as u16),
                    service: row.get(8)?,
                    conn_state: row.get(9)?,
                    duration: row.get(10)?,
                    packets_ab: row.get::<_, i64>(11)? as u64,
                    packets_ba: row.get::<_, i64>(12)? as u64,
                    bytes_ab: row.get::<_, i64>(13)? as u64,
                    bytes_ba: row.get::<_, i64>(14)? as u64,
                    pid: row.get::<_, Option<i64>>(15)?.map(|value| value as u32),
                    process_name: row.get(16)?,
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    pub fn count_connections(&self) -> Result<u64> {
        self.count("SELECT COUNT(*) FROM connections")
    }

    pub fn list_dns(&self, limit: u32, offset: u32) -> Result<Vec<DnsObservation>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT id, ts, client_ip, query, qtype, rcode, answers, ttl
                 FROM dns_observations ORDER BY ts DESC, id DESC LIMIT ?1 OFFSET ?2",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(params![limit, offset], |row| {
                Ok(DnsObservation {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    client_ip: row.get(2)?,
                    query: row.get(3)?,
                    qtype: row.get(4)?,
                    rcode: row.get(5)?,
                    answers: row.get(6)?,
                    ttl: row.get(7)?,
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    pub fn count_dns(&self) -> Result<u64> {
        self.count("SELECT COUNT(*) FROM dns_observations")
    }

    pub fn list_tls(&self, limit: u32, offset: u32) -> Result<Vec<TlsObservation>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT id, ts, client_ip, server_ip, server_port, server_name, version,
                        validation_status, subject, issuer
                 FROM tls_observations ORDER BY ts DESC, id DESC LIMIT ?1 OFFSET ?2",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(params![limit, offset], |row| {
                Ok(TlsObservation {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    client_ip: row.get(2)?,
                    server_ip: row.get(3)?,
                    server_port: row.get::<_, Option<i64>>(4)?.map(|value| value as u16),
                    server_name: row.get(5)?,
                    version: row.get(6)?,
                    validation_status: row.get(7)?,
                    subject: row.get(8)?,
                    issuer: row.get(9)?,
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    pub fn count_tls(&self) -> Result<u64> {
        self.count("SELECT COUNT(*) FROM tls_observations")
    }

    pub fn list_http(&self, limit: u32, offset: u32) -> Result<Vec<HttpObservation>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT id, ts, client_ip, server_ip, server_port, method, host, uri,
                        user_agent, status_code
                 FROM http_observations ORDER BY ts DESC, id DESC LIMIT ?1 OFFSET ?2",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(params![limit, offset], |row| {
                Ok(HttpObservation {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    client_ip: row.get(2)?,
                    server_ip: row.get(3)?,
                    server_port: row.get::<_, Option<i64>>(4)?.map(|value| value as u16),
                    method: row.get(5)?,
                    host: row.get(6)?,
                    uri: row.get(7)?,
                    user_agent: row.get(8)?,
                    status_code: row.get(9)?,
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    pub fn count_http(&self) -> Result<u64> {
        self.count("SELECT COUNT(*) FROM http_observations")
    }

    pub fn list_quic(&self, limit: u32, offset: u32) -> Result<Vec<QuicObservation>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT id, ts, client_ip, server_ip, server_port, server_name, client_protocol
                 FROM quic_observations ORDER BY ts DESC, id DESC LIMIT ?1 OFFSET ?2",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(params![limit, offset], |row| {
                Ok(QuicObservation {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    client_ip: row.get(2)?,
                    server_ip: row.get(3)?,
                    server_port: row.get::<_, Option<i64>>(4)?.map(|value| value as u16),
                    server_name: row.get(5)?,
                    client_protocol: row.get(6)?,
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    pub fn count_quic(&self) -> Result<u64> {
        self.count("SELECT COUNT(*) FROM quic_observations")
    }

    pub fn list_alerts_query(&self, q: &ListQuery) -> Result<Vec<AlertRecord>> {
        let (filter, params) = search_filter(
            &[
                "msg",
                "CAST(sid AS TEXT)",
                "src_ip",
                "dst_ip",
                "action",
                "proto",
                "class",
            ],
            q,
            3,
        );
        let order = order_clause(
            q,
            &[
                ("time", "event_ts"),
                ("sid", "sid"),
                ("priority", "priority"),
                ("proto", "proto"),
                ("source", "src_ip"),
                ("destination", "dst_ip"),
                ("action", "action"),
                ("message", "msg"),
            ],
            "event_ts DESC, id DESC",
        );
        self.list_query_rows(
            SELECT_ALERT_BASE,
            &filter,
            &order,
            params,
            q,
            alert_record_from_row,
        )
    }

    pub fn count_alerts_query(&self, q: &ListQuery) -> Result<u64> {
        let (filter, params) = search_filter(
            &[
                "msg",
                "CAST(sid AS TEXT)",
                "src_ip",
                "dst_ip",
                "action",
                "proto",
                "class",
            ],
            q,
            1,
        );
        self.count_query_rows(SELECT_ALERT_BASE, &filter, params)
    }

    pub fn list_destinations_query(&self, q: &ListQuery) -> Result<Vec<Destination>> {
        let (filter, params) = search_filter(&["e.ip", "e.hostname"], q, 3);
        let order = order_clause(
            q,
            &[
                ("ip", "e.ip"),
                ("domains", "COALESCE(e.hostname, '')"),
                ("trust", "COALESCE(e.hostname, '')"),
                ("flags", "e.alert_count"),
                ("processes", DEST_PROCESS_COUNT_SQL),
                ("connections", "e.connection_count"),
                ("alerts", "e.alert_count"),
                ("bytes_in", "e.bytes_in"),
                ("bytes_out", "e.bytes_out"),
                ("first_seen", "e.first_seen"),
                ("last_seen", "e.last_seen"),
            ],
            "e.alert_count DESC, e.last_seen DESC, e.ip ASC",
        );
        let mut destinations = self.list_query_rows(
            SELECT_DESTINATION_BASE,
            &filter,
            &order,
            params,
            q,
            destination_from_row,
        )?;
        for destination in &mut destinations {
            self.hydrate_destination(destination, true)?;
        }
        Ok(destinations)
    }

    pub fn count_destinations_query(&self, q: &ListQuery) -> Result<u64> {
        let (filter, params) = search_filter(&["e.ip", "e.hostname"], q, 1);
        self.count_query_rows(SELECT_DESTINATION_BASE, &filter, params)
    }

    pub fn list_flows_query(&self, q: &ListQuery) -> Result<Vec<Flow>> {
        let (filter, params) = search_filter(
            &[
                "process_name",
                "proto",
                "state",
                "client_ip",
                "server_ip",
                "interface",
                "CAST(server_port AS TEXT)",
            ],
            q,
            3,
        );
        let order = order_clause(
            q,
            &[
                ("process", "process_name"),
                ("pid", "pid"),
                ("proto", "proto"),
                ("local", "client_ip"),
                ("remote", "server_ip"),
                ("state", "state"),
                ("interface", "interface"),
                ("traffic", "bytes_ab + bytes_ba"),
                ("seen", "last_seen"),
            ],
            "last_seen DESC, id DESC",
        );
        self.list_query_rows(SELECT_FLOW_BASE, &filter, &order, params, q, |row| {
            Ok(Flow {
                id: row.get(0)?,
                proto: row.get(1)?,
                client_ip: row.get(2)?,
                client_port: row.get(3)?,
                server_ip: row.get(4)?,
                server_port: row.get(5)?,
                pid: row.get::<_, Option<i64>>(6)?.map(|value| value as u32),
                process_name: row.get(7)?,
                interface: row.get(8)?,
                state: row.get(9)?,
                bytes_ab: row.get::<_, i64>(10)? as u64,
                bytes_ba: row.get::<_, i64>(11)? as u64,
                packets_ab: row.get::<_, i64>(12)? as u64,
                packets_ba: row.get::<_, i64>(13)? as u64,
                first_seen: row.get(14)?,
                last_seen: row.get(15)?,
            })
        })
    }

    pub fn count_flows_query(&self, q: &ListQuery) -> Result<u64> {
        let (filter, params) = search_filter(
            &[
                "process_name",
                "proto",
                "state",
                "client_ip",
                "server_ip",
                "interface",
                "CAST(server_port AS TEXT)",
            ],
            q,
            1,
        );
        self.count_query_rows(SELECT_FLOW_BASE, &filter, params)
    }

    pub fn list_processes_query(&self, q: &ListQuery) -> Result<Vec<Process>> {
        let (filter, params) = search_filter(&["name", "path", "user", "CAST(pid AS TEXT)"], q, 3);
        let order = order_clause(
            q,
            &[
                ("process", "name"),
                ("pid", "pid"),
                ("user", "user"),
                ("connections", "connection_count"),
                ("bytes_in", "bytes_in"),
                ("bytes_out", "bytes_out"),
                ("path", "path"),
                ("last_seen", "last_seen"),
            ],
            "last_seen DESC, bytes_in + bytes_out DESC",
        );
        self.list_query_rows(
            SELECT_PROCESS_BASE,
            &filter,
            &order,
            params,
            q,
            process_from_row,
        )
    }

    pub fn count_processes_query(&self, q: &ListQuery) -> Result<u64> {
        let (filter, params) = search_filter(&["name", "path", "user", "CAST(pid AS TEXT)"], q, 1);
        self.count_query_rows(SELECT_PROCESS_BASE, &filter, params)
    }

    pub fn list_connections_query(&self, q: &ListQuery) -> Result<Vec<Connection>> {
        let (filter, params) = search_filter(
            &[
                "process_name",
                "proto",
                "server_ip",
                "service",
                "conn_state",
                "CAST(server_port AS TEXT)",
            ],
            q,
            3,
        );
        let order = order_clause(
            q,
            &[
                ("time", "ts"),
                ("process", "process_name"),
                ("pid", "pid"),
                ("proto", "proto"),
                ("remote", "server_ip"),
                ("service", "service"),
                ("state", "conn_state"),
                ("traffic", "bytes_ab + bytes_ba"),
            ],
            "ts DESC, id DESC",
        );
        self.list_query_rows(SELECT_CONNECTION_BASE, &filter, &order, params, q, |row| {
            Ok(Connection {
                id: row.get(0)?,
                uid: row.get(1)?,
                ts: row.get(2)?,
                proto: row.get(3)?,
                client_ip: row.get(4)?,
                client_port: row.get::<_, Option<i64>>(5)?.map(|value| value as u16),
                server_ip: row.get(6)?,
                server_port: row.get::<_, Option<i64>>(7)?.map(|value| value as u16),
                service: row.get(8)?,
                conn_state: row.get(9)?,
                duration: row.get(10)?,
                packets_ab: row.get::<_, i64>(11)? as u64,
                packets_ba: row.get::<_, i64>(12)? as u64,
                bytes_ab: row.get::<_, i64>(13)? as u64,
                bytes_ba: row.get::<_, i64>(14)? as u64,
                pid: row.get::<_, Option<i64>>(15)?.map(|value| value as u32),
                process_name: row.get(16)?,
            })
        })
    }

    pub fn count_connections_query(&self, q: &ListQuery) -> Result<u64> {
        let (filter, params) = search_filter(
            &[
                "process_name",
                "proto",
                "server_ip",
                "service",
                "conn_state",
                "CAST(server_port AS TEXT)",
            ],
            q,
            1,
        );
        self.count_query_rows(SELECT_CONNECTION_BASE, &filter, params)
    }

    pub fn list_dns_query(&self, q: &ListQuery) -> Result<Vec<DnsObservation>> {
        let (filter, params) =
            search_filter(&["query", "answers", "qtype", "rcode", "client_ip"], q, 3);
        let order = order_clause(
            q,
            &[
                ("time", "ts"),
                ("client", "client_ip"),
                ("query", "query"),
                ("type", "qtype"),
                ("rcode", "rcode"),
                ("answers", "answers"),
                ("ttl", "CAST(ttl AS INTEGER)"),
            ],
            "ts DESC, id DESC",
        );
        self.list_query_rows(SELECT_DNS_BASE, &filter, &order, params, q, |row| {
            Ok(DnsObservation {
                id: row.get(0)?,
                ts: row.get(1)?,
                client_ip: row.get(2)?,
                query: row.get(3)?,
                qtype: row.get(4)?,
                rcode: row.get(5)?,
                answers: row.get(6)?,
                ttl: row.get(7)?,
            })
        })
    }

    pub fn count_dns_query(&self, q: &ListQuery) -> Result<u64> {
        let (filter, params) =
            search_filter(&["query", "answers", "qtype", "rcode", "client_ip"], q, 1);
        self.count_query_rows(SELECT_DNS_BASE, &filter, params)
    }

    pub fn list_tls_query(&self, q: &ListQuery) -> Result<Vec<TlsObservation>> {
        let (filter, params) = search_filter(
            &[
                "server_name",
                "client_ip",
                "server_ip",
                "version",
                "validation_status",
            ],
            q,
            3,
        );
        let order = order_clause(
            q,
            &[
                ("time", "ts"),
                ("sniname", "server_name"),
                ("client", "client_ip"),
                ("server", "server_ip"),
                ("version", "version"),
                ("validation", "validation_status"),
            ],
            "ts DESC, id DESC",
        );
        self.list_query_rows(SELECT_TLS_BASE, &filter, &order, params, q, |row| {
            Ok(TlsObservation {
                id: row.get(0)?,
                ts: row.get(1)?,
                client_ip: row.get(2)?,
                server_ip: row.get(3)?,
                server_port: row.get::<_, Option<i64>>(4)?.map(|value| value as u16),
                server_name: row.get(5)?,
                version: row.get(6)?,
                validation_status: row.get(7)?,
                subject: row.get(8)?,
                issuer: row.get(9)?,
            })
        })
    }

    pub fn count_tls_query(&self, q: &ListQuery) -> Result<u64> {
        let (filter, params) = search_filter(
            &[
                "server_name",
                "client_ip",
                "server_ip",
                "version",
                "validation_status",
            ],
            q,
            1,
        );
        self.count_query_rows(SELECT_TLS_BASE, &filter, params)
    }

    pub fn list_http_query(&self, q: &ListQuery) -> Result<Vec<HttpObservation>> {
        let (filter, params) = search_filter(
            &[
                "host",
                "uri",
                "method",
                "client_ip",
                "server_ip",
                "user_agent",
            ],
            q,
            3,
        );
        let order = order_clause(
            q,
            &[
                ("time", "ts"),
                ("method", "method"),
                ("host", "host"),
                ("uri", "uri"),
                ("client", "client_ip"),
                ("server", "server_ip"),
                ("status", "status_code"),
            ],
            "ts DESC, id DESC",
        );
        self.list_query_rows(SELECT_HTTP_BASE, &filter, &order, params, q, |row| {
            Ok(HttpObservation {
                id: row.get(0)?,
                ts: row.get(1)?,
                client_ip: row.get(2)?,
                server_ip: row.get(3)?,
                server_port: row.get::<_, Option<i64>>(4)?.map(|value| value as u16),
                method: row.get(5)?,
                host: row.get(6)?,
                uri: row.get(7)?,
                user_agent: row.get(8)?,
                status_code: row.get(9)?,
            })
        })
    }

    pub fn count_http_query(&self, q: &ListQuery) -> Result<u64> {
        let (filter, params) = search_filter(
            &[
                "host",
                "uri",
                "method",
                "client_ip",
                "server_ip",
                "user_agent",
            ],
            q,
            1,
        );
        self.count_query_rows(SELECT_HTTP_BASE, &filter, params)
    }

    pub fn list_quic_query(&self, q: &ListQuery) -> Result<Vec<QuicObservation>> {
        let (filter, params) = search_filter(
            &["server_name", "client_ip", "server_ip", "client_protocol"],
            q,
            3,
        );
        let order = order_clause(
            q,
            &[
                ("time", "ts"),
                ("sniname", "server_name"),
                ("client", "client_ip"),
                ("server", "server_ip"),
                ("protocol", "client_protocol"),
            ],
            "ts DESC, id DESC",
        );
        self.list_query_rows(SELECT_QUIC_BASE, &filter, &order, params, q, |row| {
            Ok(QuicObservation {
                id: row.get(0)?,
                ts: row.get(1)?,
                client_ip: row.get(2)?,
                server_ip: row.get(3)?,
                server_port: row.get::<_, Option<i64>>(4)?.map(|value| value as u16),
                server_name: row.get(5)?,
                client_protocol: row.get(6)?,
            })
        })
    }

    pub fn count_quic_query(&self, q: &ListQuery) -> Result<u64> {
        let (filter, params) = search_filter(
            &["server_name", "client_ip", "server_ip", "client_protocol"],
            q,
            1,
        );
        self.count_query_rows(SELECT_QUIC_BASE, &filter, params)
    }

    pub fn list_domains_query(&self, q: &ListQuery) -> Result<Vec<DomainSummary>> {
        let (filter, params) = search_filter(&["d.registrable_domain", "d.domain"], q, 3);
        let order = order_clause(
            q,
            &[
                ("domain", "d.registrable_domain"),
                ("hostnames", "COUNT(d.domain)"),
                ("sources", "SUM(d.observation_count)"),
                ("trust", "COALESCE(t.state, 'unknown')"),
                ("flags", "SUM(d.observation_count)"),
                ("ips", "COUNT(DISTINCT d.domain)"),
                ("processes", "SUM(d.observation_count)"),
                ("observed", "SUM(d.observation_count)"),
                ("first_seen", "MIN(d.first_seen)"),
                ("last_seen", "MAX(d.last_seen)"),
            ],
            "MAX(d.last_seen) DESC",
        );
        let base = SELECT_DOMAIN_BASE.replace("/*FILTER*/", &filter);
        self.list_query_rows(&base, "", &order, params, q, |row| {
            let trust: String = row.get(1)?;
            let trust_state = TrustState::parse(&trust).unwrap_or_default();
            let first_seen: i64 = row.get(2)?;
            let hostnames: Option<String> = row.get(5)?;
            let sources: Option<String> = row.get(6)?;
            let now = unix_now();
            let mut flags = Vec::new();
            if trust_state == TrustState::Unknown {
                flags.push(ReviewFlag::UnknownTrust);
            }
            if now.saturating_sub(first_seen) <= 86_400 {
                flags.push(ReviewFlag::NewDomain);
            }
            if row.get::<_, i64>(9)? != 0 {
                flags.push(ReviewFlag::Alerts);
            }
            if row.get::<_, i64>(10)? != 0 {
                flags.push(ReviewFlag::InvalidTls);
            }
            Ok(DomainSummary {
                domain: row.get(0)?,
                hostnames: hostnames
                    .unwrap_or_default()
                    .split('\u{1f}')
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .collect(),
                sources: sources
                    .unwrap_or_default()
                    .split('\u{1f}')
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .collect(),
                trust_state,
                first_seen,
                last_seen: row.get(3)?,
                observation_count: row.get::<_, i64>(4)? as u64,
                endpoint_count: row.get::<_, i64>(7)? as u64,
                process_count: row.get::<_, i64>(8)? as u64,
                flags,
            })
        })
    }

    pub fn count_domains_query(&self, q: &ListQuery) -> Result<u64> {
        let (filter, params) = search_filter(&["d.registrable_domain", "d.domain"], q, 1);
        let base = SELECT_DOMAIN_BASE.replace("/*FILTER*/", &filter);
        self.count_query_rows(&base, "", params)
    }

    fn list_query_rows<T, F>(
        &self,
        base: &str,
        filter: &str,
        order: &str,
        search_params: Vec<SqlValue>,
        q: &ListQuery,
        mapper: F,
    ) -> Result<Vec<T>>
    where
        F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        let (limit, offset) = page_values(q);
        let mut params = vec![SqlValue::Integer(limit), SqlValue::Integer(offset)];
        params.extend(search_params);
        let sql = format!("{base} {filter} {order} LIMIT ?1 OFFSET ?2");
        let mut statement = self.conn.prepare(&sql).map_err(db)?;
        let rows = statement
            .query_map(params_from_iter(params), mapper)
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    fn count_query_rows(
        &self,
        base: &str,
        filter: &str,
        search_params: Vec<SqlValue>,
    ) -> Result<u64> {
        let sql = format!("SELECT COUNT(*) FROM ({base} {filter})");
        let count: i64 = self
            .conn
            .query_row(&sql, params_from_iter(search_params), |row| row.get(0))
            .map_err(db)?;
        Ok(count as u64)
    }

    fn count(&self, sql: &str) -> Result<u64> {
        let count: i64 = self.conn.query_row(sql, [], |row| row.get(0)).map_err(db)?;
        Ok(count as u64)
    }

    pub fn get_settings(&self) -> Result<AppSettings> {
        let stored: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM app_settings WHERE key = ?1",
                params![SETTINGS_KEY],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        let mut settings = stored
            .as_deref()
            .and_then(|value| serde_json::from_str::<AppSettings>(value).ok())
            .unwrap_or_default();
        settings.validate();
        Ok(settings)
    }

    fn import_legacy_gui_settings(&self, db_path: &Path) -> Result<()> {
        let legacy = db_path
            .parent()
            .map(|parent| parent.join("pigui-gui.db"))
            .unwrap_or_else(|| Path::new("pigui-gui.db").to_path_buf());
        if !legacy.is_file() {
            return Ok(());
        }
        let has_settings: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM app_settings WHERE key = ?1",
                params![SETTINGS_KEY],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        if has_settings.is_some() {
            return Ok(());
        }
        let legacy_conn = SqlConnection::open_with_flags(
            &legacy,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(db)?;
        let theme: Option<String> = legacy_conn
            .query_row(
                "SELECT value FROM settings WHERE key = 'ui.theme'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        if let Some(theme) = theme.and_then(|value| ThemeMode::parse(&value)) {
            let mut settings = AppSettings::default();
            settings.theme = theme;
            self.save_settings(&settings)?;
        }
        let migrated = legacy.with_extension("db.migrated");
        let _ = std::fs::rename(&legacy, migrated);
        Ok(())
    }

    pub fn save_settings(&self, settings: &AppSettings) -> Result<()> {
        let mut settings = settings.clone();
        settings.validate();
        let value = serde_json::to_string(&settings)?;
        self.conn
            .execute(
                "INSERT INTO app_settings (key, value, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET
                     value = excluded.value,
                     updated_at = excluded.updated_at",
                params![SETTINGS_KEY, value, unix_now()],
            )
            .map_err(db)?;
        Ok(())
    }

    pub fn update_settings(&self, patch: &serde_json::Value) -> Result<AppSettings> {
        let mut current = serde_json::to_value(self.get_settings()?)?;
        merge_json(&mut current, patch);
        let mut settings: AppSettings = serde_json::from_value(current)?;
        settings.validate();
        self.save_settings(&settings)?;
        Ok(settings)
    }

    pub fn reset_settings(&self) -> Result<AppSettings> {
        let settings = AppSettings::default();
        self.save_settings(&settings)?;
        Ok(settings)
    }

    pub fn table_counts(&self) -> Result<Vec<TableCount>> {
        let tables = [
            "alerts",
            "endpoints",
            "processes",
            "flows",
            "connections",
            "dns_observations",
            "tls_observations",
            "http_observations",
            "quic_observations",
            "domains",
            "endpoint_domains",
            "ptr_observations",
        ];
        let mut counts = Vec::with_capacity(tables.len());
        for table in tables {
            let rows = self.count(&format!("SELECT COUNT(*) FROM {table}"))?;
            counts.push(TableCount {
                name: table.to_string(),
                rows,
            });
        }
        Ok(counts)
    }

    pub fn prune(&self, settings: &AppSettings) -> Result<PruneResult> {
        let now = unix_now();
        let retention = &settings.retention;
        let mut deleted = Vec::new();

        let mut record = |name: &str, rows: u64| {
            if rows > 0 {
                deleted.push(TableCount {
                    name: name.to_string(),
                    rows,
                });
            }
        };

        record(
            "flows",
            delete_older_than(&self.conn, "flows", "last_seen", now - retention.flows_secs)?,
        );
        record(
            "processes",
            delete_older_than(
                &self.conn,
                "processes",
                "last_seen",
                now - retention.processes_secs,
            )?,
        );
        record(
            "alerts",
            delete_older_than(
                &self.conn,
                "alerts",
                "event_ts",
                now - i64::from(retention.alerts_days) * 86_400,
            )?,
        );
        record(
            "connections",
            delete_older_than(
                &self.conn,
                "connections",
                "ts",
                now - i64::from(retention.connections_days) * 86_400,
            )?,
        );
        for table in [
            "dns_observations",
            "tls_observations",
            "http_observations",
            "quic_observations",
        ] {
            record(
                table,
                delete_older_than(
                    &self.conn,
                    table,
                    "ts",
                    now - i64::from(retention.observations_days) * 86_400,
                )?,
            );
        }
        record(
            "ptr_observations",
            delete_older_than(
                &self.conn,
                "ptr_observations",
                "last_seen",
                now - i64::from(retention.ptr_days) * 86_400,
            )?,
        );
        record(
            "endpoint_domains",
            delete_older_than(
                &self.conn,
                "endpoint_domains",
                "last_seen",
                now - i64::from(retention.domains_days) * 86_400,
            )?,
        );
        let domains_cutoff = now - i64::from(retention.domains_days) * 86_400;
        let domains_deleted = self
            .conn
            .execute(
                "DELETE FROM domains
                 WHERE last_seen < ?1
                   AND NOT EXISTS (
                       SELECT 1 FROM endpoint_domains ed WHERE ed.domain = domains.domain
                   )",
                params![domains_cutoff],
            )
            .map_err(db)?;
        record("domains", domains_deleted as u64);
        record(
            "endpoints",
            delete_older_than(
                &self.conn,
                "endpoints",
                "last_seen",
                now - i64::from(retention.endpoints_days) * 86_400,
            )?,
        );

        self.conn.execute_batch("PRAGMA optimize").map_err(db)?;
        let _ = self
            .conn
            .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |_| Ok(()));

        let total_deleted = deleted.iter().map(|entry| entry.rows).sum();
        Ok(PruneResult {
            ran_at: now,
            deleted,
            total_deleted,
        })
    }
}

const SETTINGS_KEY: &str = "app";

fn merge_json(base: &mut serde_json::Value, patch: &serde_json::Value) {
    match (base, patch) {
        (serde_json::Value::Object(base), serde_json::Value::Object(patch)) => {
            for (key, value) in patch {
                merge_json(
                    base.entry(key.clone()).or_insert(serde_json::Value::Null),
                    value,
                );
            }
        }
        (base, patch) => *base = patch.clone(),
    }
}

fn delete_older_than(conn: &SqlConnection, table: &str, column: &str, cutoff: i64) -> Result<u64> {
    let batch = 10_000i64;
    let mut total = 0u64;
    loop {
        let sql = format!(
            "DELETE FROM {table}
             WHERE rowid IN (
                 SELECT rowid FROM {table} WHERE {column} < ?1 LIMIT ?2
             )"
        );
        let removed = conn.execute(&sql, params![cutoff, batch]).map_err(db)? as u64;
        total += removed;
        if removed < batch as u64 {
            break;
        }
    }
    Ok(total)
}

fn ensure_endpoints_hostname(conn: &SqlConnection) -> Result<()> {
    let mut statement = conn.prepare("PRAGMA table_info(endpoints)").map_err(db)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(db)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db)?;
    drop(statement);
    if !columns.iter().any(|column| column == "hostname") {
        conn.execute("ALTER TABLE endpoints ADD COLUMN hostname TEXT", [])
            .map_err(db)?;
    }
    Ok(())
}

fn insert_conn(
    tx: &rusqlite::Transaction<'_>,
    event: &pigui_core::models::extractor::ConnEvent,
    now: i64,
) -> Result<bool> {
    let (pid, process_name) = lookup_process(
        tx,
        event.common.proto.as_deref(),
        event.common.client_ip.as_deref(),
        event.common.client_port,
        event.common.server_ip.as_deref(),
        event.common.server_port,
    )?;

    let inserted = tx
        .execute(
            "INSERT OR IGNORE INTO connections (
                uid, ts, proto, client_ip, client_port, server_ip, server_port, service,
                conn_state, duration, packets_ab, packets_ba, bytes_ab, bytes_ba, pid,
                process_name, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                event.common.uid,
                event.common.ts,
                event.common.proto,
                event.common.client_ip,
                event.common.client_port,
                event.common.server_ip,
                event.common.server_port,
                event.service,
                event.conn_state,
                event.duration,
                event.packets_ab as i64,
                event.packets_ba as i64,
                event.bytes_ab as i64,
                event.bytes_ba as i64,
                pid.map(i64::from),
                process_name,
                now,
            ],
        )
        .map_err(db)?;

    if inserted == 1
        && let Some(server_ip) = &event.common.server_ip
    {
        tx.execute(
            UPSERT_ENDPOINT_BYTES,
            params![
                server_ip,
                event.common.ts,
                event.bytes_ba as i64,
                event.bytes_ab as i64,
            ],
        )
        .map_err(db)?;
    }
    Ok(inserted == 1)
}

fn lookup_process(
    tx: &rusqlite::Transaction<'_>,
    proto: Option<&str>,
    client_ip: Option<&str>,
    client_port: Option<u16>,
    server_ip: Option<&str>,
    server_port: Option<u16>,
) -> Result<(Option<u32>, Option<String>)> {
    let row: Option<(Option<i64>, Option<String>)> = tx
        .query_row(
            "SELECT pid, process_name FROM flows
             WHERE proto = ?1 AND client_ip = ?2 AND client_port = ?3
               AND server_ip = ?4 AND server_port = ?5
             LIMIT 1",
            params![
                proto,
                client_ip,
                client_port.map(i64::from),
                server_ip,
                server_port.map(i64::from)
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(db)?;

    Ok(match row {
        Some((pid, name)) => (pid.map(|value| value as u32), name),
        None => (None, None),
    })
}

fn insert_dns(
    tx: &rusqlite::Transaction<'_>,
    event: &pigui_core::models::extractor::DnsEvent,
    now: i64,
) -> Result<bool> {
    let inserted = tx
        .execute(
            "INSERT OR IGNORE INTO dns_observations (ts, client_ip, query, qtype, rcode, answers, ttl)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event.common.ts,
                event.common.client_ip,
                event.query,
                event.qtype,
                event.rcode,
                event.answers,
                event.ttl,
            ],
        )
        .map_err(db)?;

    if inserted == 1
        && let (Some(query), Some(answers)) = (&event.query, &event.answers)
    {
        for answer in answers.split_whitespace() {
            if answer.parse::<IpAddr>().is_ok() {
                upsert_hostname(tx, answer, query, now)?;
                record_domain_mapping(tx, answer, query, None, "dns", event.common.ts)?;
            }
        }
    }
    Ok(inserted == 1)
}

fn insert_tls(
    tx: &rusqlite::Transaction<'_>,
    event: &pigui_core::models::extractor::TlsEvent,
    now: i64,
) -> Result<bool> {
    let inserted = tx
        .execute(
            "INSERT OR IGNORE INTO tls_observations (
                ts, client_ip, server_ip, server_port, server_name, version,
                validation_status, subject, issuer
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                event.common.ts,
                event.common.client_ip,
                event.common.server_ip,
                event.common.server_port,
                event.server_name,
                event.version,
                event.validation_status,
                event.subject,
                event.issuer,
            ],
        )
        .map_err(db)?;

    if inserted == 1
        && let (Some(ip), Some(hostname)) = (&event.common.server_ip, &event.server_name)
    {
        upsert_hostname(tx, ip, hostname, now)?;
        record_domain_mapping(
            tx,
            ip,
            hostname,
            event.common.server_port,
            "tls",
            event.common.ts,
        )?;
    }
    Ok(inserted == 1)
}

fn insert_http(
    tx: &rusqlite::Transaction<'_>,
    event: &pigui_core::models::extractor::HttpEvent,
    now: i64,
) -> Result<bool> {
    let inserted = tx
        .execute(
            "INSERT OR IGNORE INTO http_observations (
                ts, client_ip, server_ip, server_port, method, host, uri, user_agent, status_code
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                event.common.ts,
                event.common.client_ip,
                event.common.server_ip,
                event.common.server_port,
                event.method,
                event.host,
                event.uri,
                event.user_agent,
                event.status_code,
            ],
        )
        .map_err(db)?;

    if inserted == 1
        && let (Some(ip), Some(hostname)) = (&event.common.server_ip, &event.host)
    {
        upsert_hostname(tx, ip, hostname, now)?;
        record_domain_mapping(
            tx,
            ip,
            hostname,
            event.common.server_port,
            "http",
            event.common.ts,
        )?;
    }
    Ok(inserted == 1)
}

fn insert_quic(
    tx: &rusqlite::Transaction<'_>,
    event: &pigui_core::models::extractor::QuicEvent,
    now: i64,
) -> Result<bool> {
    let inserted = tx
        .execute(
            "INSERT OR IGNORE INTO quic_observations (
                ts, client_ip, server_ip, server_port, server_name, client_protocol
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                event.common.ts,
                event.common.client_ip,
                event.common.server_ip,
                event.common.server_port,
                event.server_name,
                event.client_protocol,
            ],
        )
        .map_err(db)?;

    if inserted == 1
        && let (Some(ip), Some(hostname)) = (&event.common.server_ip, &event.server_name)
    {
        upsert_hostname(tx, ip, hostname, now)?;
        record_domain_mapping(
            tx,
            ip,
            hostname,
            event.common.server_port,
            "quic",
            event.common.ts,
        )?;
    }
    Ok(inserted == 1)
}

fn upsert_hostname(
    tx: &rusqlite::Transaction<'_>,
    ip: &str,
    hostname: &str,
    now: i64,
) -> Result<()> {
    tx.execute(UPSERT_ENDPOINT_HOSTNAME, params![ip, now, hostname])
        .map_err(db)?;
    Ok(())
}

fn record_domain_mapping(
    conn: &SqlConnection,
    ip: &str,
    hostname: &str,
    server_port: Option<u16>,
    source: &str,
    ts: i64,
) -> Result<()> {
    let Some(domain) = normalize_hostname(hostname) else {
        return Ok(());
    };
    let registrable = registrable_domain(&domain);
    conn.execute(UPSERT_DOMAIN, params![domain, registrable, ts])
        .map_err(db)?;
    conn.execute(
        UPSERT_ENDPOINT_DOMAIN,
        params![
            ip,
            domain,
            server_port.map(i64::from).unwrap_or(0),
            source,
            ts
        ],
    )
    .map_err(db)?;
    Ok(())
}

fn read_schema_version(conn: &SqlConnection) -> Result<Option<String>> {
    let table: Option<String> = conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'schema_meta'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(db)?;
    if table.is_none() {
        return Ok(None);
    }
    conn.query_row(
        "SELECT value FROM schema_meta WHERE key = 'version'",
        [],
        |row| row.get(0),
    )
    .optional()
    .map_err(db)
}

fn page_values(q: &ListQuery) -> (i64, i64) {
    (
        i64::from(q.limit.unwrap_or(200)),
        i64::from(q.offset.unwrap_or(0)),
    )
}

fn search_filter(columns: &[&str], q: &ListQuery, start_index: usize) -> (String, Vec<SqlValue>) {
    let Some(term) =
        q.q.as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    else {
        return (String::new(), Vec::new());
    };
    let pattern = format!("%{term}%");
    let mut clauses = Vec::with_capacity(columns.len());
    let mut params = Vec::with_capacity(columns.len());
    for (offset, column) in columns.iter().enumerate() {
        clauses.push(format!(
            "COALESCE({column}, '') LIKE ?{}",
            start_index + offset
        ));
        params.push(SqlValue::Text(pattern.clone()));
    }
    (format!("WHERE ({})", clauses.join(" OR ")), params)
}

fn order_clause(q: &ListQuery, columns: &[(&str, &'static str)], default_order: &str) -> String {
    let Some(sort) = q.sort.as_deref().filter(|sort| !sort.is_empty()) else {
        return format!("ORDER BY {default_order}");
    };
    let expression = columns
        .iter()
        .find(|(column, _)| *column == sort)
        .map(|(_, expression)| *expression)
        .unwrap_or(default_order);
    let direction = q.dir.unwrap_or(SortDirection::Desc).as_str();
    format!("ORDER BY {expression} {direction}")
}

fn set_schema_version(conn: &SqlConnection, version: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO schema_meta (key, value) VALUES ('version', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![version],
    )
    .map_err(db)?;
    Ok(())
}

fn migrate_v5(conn: &SqlConnection) -> Result<()> {
    conn.execute(
        "UPDATE connections SET proto = lower(proto) WHERE proto IS NOT NULL",
        [],
    )
    .map_err(db)?;
    conn.execute(
        "UPDATE connections
         SET pid = (
                 SELECT f.pid FROM flows f
                 WHERE lower(f.proto) = lower(connections.proto)
                   AND f.client_ip = connections.client_ip
                   AND f.client_port = connections.client_port
                   AND f.server_ip = connections.server_ip
                   AND f.server_port = connections.server_port
                 LIMIT 1
             ),
             process_name = (
                 SELECT f.process_name FROM flows f
                 WHERE lower(f.proto) = lower(connections.proto)
                   AND f.client_ip = connections.client_ip
                   AND f.client_port = connections.client_port
                   AND f.server_ip = connections.server_ip
                   AND f.server_port = connections.server_port
                 LIMIT 1
             )
         WHERE pid IS NULL
           AND EXISTS (
                 SELECT 1 FROM flows f
                 WHERE lower(f.proto) = lower(connections.proto)
                   AND f.client_ip = connections.client_ip
                   AND f.client_port = connections.client_port
                   AND f.server_ip = connections.server_ip
                   AND f.server_port = connections.server_port
           )",
        [],
    )
    .map_err(db)?;
    Ok(())
}

fn backfill_domains(conn: &SqlConnection) -> Result<()> {
    let tx = conn.unchecked_transaction().map_err(db)?;

    let endpoint_rows = {
        let mut statement = tx
            .prepare("SELECT ip, hostname, last_seen FROM endpoints WHERE hostname IS NOT NULL")
            .map_err(db)?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?
    };
    for (ip, hostname, ts) in endpoint_rows {
        record_domain_mapping(&tx, &ip, &hostname, None, "legacy", ts)?;
    }

    let dns_rows = {
        let mut statement = tx
            .prepare(
                "SELECT query, answers, ts FROM dns_observations
                 WHERE query IS NOT NULL AND answers IS NOT NULL",
            )
            .map_err(db)?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?
    };
    for (query, answers, ts) in dns_rows {
        for answer in answers.split_whitespace() {
            if answer.parse::<IpAddr>().is_ok() {
                record_domain_mapping(&tx, answer, &query, None, "dns", ts)?;
            }
        }
    }

    let tls_rows = {
        let mut statement = tx
            .prepare(
                "SELECT server_ip, server_name, server_port, ts FROM tls_observations
                 WHERE server_ip IS NOT NULL AND server_name IS NOT NULL",
            )
            .map_err(db)?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?
    };
    for (ip, hostname, port, ts) in tls_rows {
        record_domain_mapping(
            &tx,
            &ip,
            &hostname,
            port.and_then(|value| u16::try_from(value).ok()),
            "tls",
            ts,
        )?;
    }

    let http_rows = {
        let mut statement = tx
            .prepare(
                "SELECT server_ip, host, server_port, ts FROM http_observations
                 WHERE server_ip IS NOT NULL AND host IS NOT NULL",
            )
            .map_err(db)?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?
    };
    for (ip, hostname, port, ts) in http_rows {
        record_domain_mapping(
            &tx,
            &ip,
            &hostname,
            port.and_then(|value| u16::try_from(value).ok()),
            "http",
            ts,
        )?;
    }

    let quic_rows = {
        let mut statement = tx
            .prepare(
                "SELECT server_ip, server_name, server_port, ts FROM quic_observations
                 WHERE server_ip IS NOT NULL AND server_name IS NOT NULL",
            )
            .map_err(db)?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?
    };
    for (ip, hostname, port, ts) in quic_rows {
        record_domain_mapping(
            &tx,
            &ip,
            &hostname,
            port.and_then(|value| u16::try_from(value).ok()),
            "quic",
            ts,
        )?;
    }

    tx.commit().map_err(db)?;
    Ok(())
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn destination_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Destination> {
    Ok(Destination {
        ip: row.get(0)?,
        hostname: row.get(1)?,
        first_seen: row.get(2)?,
        last_seen: row.get(3)?,
        bytes_in: row.get::<_, i64>(4)? as u64,
        bytes_out: row.get::<_, i64>(5)? as u64,
        connection_count: row.get::<_, i64>(6)? as u64,
        process_count: row.get::<_, i64>(7)? as u64,
        live_bytes_in: row.get::<_, i64>(8)? as u64,
        live_bytes_out: row.get::<_, i64>(9)? as u64,
        live_connection_count: row.get::<_, i64>(10)? as u64,
        alert_count: row.get::<_, i64>(11)? as u64,
        reputation: row.get(12)?,
        blocked: row.get::<_, i64>(13)? != 0,
        domains: Vec::new(),
        trust_state: TrustState::Unknown,
        flags: Vec::new(),
    })
}

fn alert_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AlertRecord> {
    Ok(AlertRecord {
        id: row.get(0)?,
        alert: Alert {
            event_ts: row.get(1)?,
            ts_text: row.get(2)?,
            gid: row.get(3)?,
            sid: row.get(4)?,
            rev: row.get(5)?,
            priority: row.get(6)?,
            class: row.get(7)?,
            msg: row.get(8)?,
            proto: row.get(9)?,
            src_ip: row.get(10)?,
            src_port: row.get(11)?,
            dst_ip: row.get(12)?,
            dst_port: row.get(13)?,
            action: row.get(14)?,
            app_id: row.get(15)?,
            service: row.get(16)?,
            rule: row.get(17)?,
            direction: row.get(18)?,
            pkt_num: row.get::<_, Option<i64>>(19)?.map(|value| value as u64),
        },
        ingested_at: row.get(20)?,
    })
}

fn process_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Process> {
    Ok(Process {
        pid: row.get::<_, i64>(0)? as u32,
        name: row.get(1)?,
        path: row.get(2)?,
        user: row.get(3)?,
        first_seen: row.get(4)?,
        last_seen: row.get(5)?,
        bytes_in: row.get::<_, i64>(6)? as u64,
        bytes_out: row.get::<_, i64>(7)? as u64,
        connection_count: row.get::<_, i64>(8)? as u64,
    })
}

fn aggregate_trust(domains: &[EndpointDomain]) -> TrustState {
    if domains.is_empty() {
        return TrustState::Unknown;
    }
    if domains
        .iter()
        .any(|domain| domain.trust_state == TrustState::Suspicious)
    {
        return TrustState::Suspicious;
    }
    if domains
        .iter()
        .all(|domain| domain.trust_state == TrustState::Trusted)
    {
        return TrustState::Trusted;
    }
    if domains
        .iter()
        .all(|domain| domain.trust_state == TrustState::Ignored)
    {
        return TrustState::Ignored;
    }
    TrustState::Unknown
}

fn review_flags(
    domains: &[EndpointDomain],
    alert_count: u64,
    invalid_tls: bool,
    now: i64,
) -> Vec<ReviewFlag> {
    let mut flags = Vec::new();
    if domains.is_empty() {
        flags.push(ReviewFlag::NoDomain);
    }
    if domains
        .iter()
        .any(|domain| domain.trust_state == TrustState::Unknown)
    {
        flags.push(ReviewFlag::UnknownTrust);
    }
    if domains
        .iter()
        .any(|domain| now.saturating_sub(domain.first_seen) <= 86_400)
    {
        flags.push(ReviewFlag::NewDomain);
    }
    if invalid_tls {
        flags.push(ReviewFlag::InvalidTls);
    }
    if alert_count > 0 {
        flags.push(ReviewFlag::Alerts);
    }
    flags
}

fn db(error: rusqlite::Error) -> Error {
    Error::Database(error.to_string())
}

#[cfg(test)]
mod tests {
    use pigui_collector::{CollectorSnapshot, ProcessSample, SocketSample};

    use super::*;

    fn alert(seconds: i64, sid: u32, dst: &str, dst_port: u16) -> (Alert, String) {
        let json = format!(
            r#"{{"seconds":{seconds},"sid":{sid},"gid":1,"rev":1,"proto":"TCP","src_addr":"10.0.0.5","src_port":1234,"dst_addr":"{dst}","dst_port":{dst_port},"action":"allowed"}}"#
        );
        let alert = Alert::parse(&json).unwrap();
        (alert, json)
    }

    fn extractor(line: &str) -> ExtractorRecord {
        ExtractorRecord::parse(line).unwrap()
    }

    #[test]
    fn inserts_and_lists_alerts() {
        let mut store = Store::open_in_memory().unwrap();
        let stats = store
            .insert_alerts(&[alert(10, 1, "198.51.100.10", 443)])
            .unwrap();

        assert_eq!(stats.inserted, 1);
        assert_eq!(stats.duplicates, 0);
        assert_eq!(store.count_alerts().unwrap(), 1);

        let alerts = store.list_alerts(10, 0).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert.sid, 1);
        assert_eq!(alerts[0].alert.dst_ip.as_deref(), Some("198.51.100.10"));
    }

    #[test]
    fn duplicate_alerts_are_ignored() {
        let mut store = Store::open_in_memory().unwrap();
        let entry = alert(10, 1, "198.51.100.10", 443);

        store.insert_alerts(std::slice::from_ref(&entry)).unwrap();
        let stats = store.insert_alerts(&[entry]).unwrap();

        assert_eq!(stats.inserted, 0);
        assert_eq!(stats.duplicates, 1);
        assert_eq!(store.count_alerts().unwrap(), 1);
        assert_eq!(store.count_destinations().unwrap(), 1);
    }

    #[test]
    fn aggregates_destinations() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .insert_alerts(&[
                alert(10, 1, "198.51.100.10", 443),
                alert(20, 2, "198.51.100.10", 80),
                alert(30, 3, "203.0.113.9", 53),
            ])
            .unwrap();

        let destinations = store.list_destinations(10, 0).unwrap();
        assert_eq!(destinations.len(), 2);
        assert_eq!(destinations[0].ip, "198.51.100.10");
        assert_eq!(destinations[0].alert_count, 2);
        assert_eq!(destinations[0].first_seen, 10);
        assert_eq!(destinations[0].last_seen, 20);
    }

    #[test]
    fn stores_live_snapshot() {
        let mut store = Store::open_in_memory().unwrap();
        let snapshot = CollectorSnapshot {
            processes: vec![ProcessSample {
                pid: 42,
                name: "Chrome".into(),
                path: Some("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into()),
                user: Some("nirmal".into()),
                bytes_in: 100,
                bytes_out: 200,
                connection_count: 1,
            }],
            sockets: vec![SocketSample {
                proto: "tcp".into(),
                client_ip: "10.0.0.5".into(),
                client_port: 50000,
                server_ip: "198.51.100.10".into(),
                server_port: 443,
                state: Some("Established".into()),
                interface: Some("en0".into()),
                bytes_ab: 100,
                bytes_ba: 200,
                pid: 42,
                process_name: "Chrome".into(),
            }],
        };

        store.apply_snapshot(&snapshot, 1000).unwrap();

        let flows = store.list_flows(10, 0).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].pid, Some(42));
        assert_eq!(flows[0].process_name.as_deref(), Some("Chrome"));

        let processes = store.list_processes(10, 0).unwrap();
        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].name, "Chrome");
    }

    #[test]
    fn joins_extractor_conn_to_flow_process() {
        let mut store = Store::open_in_memory().unwrap();
        let snapshot = CollectorSnapshot {
            processes: vec![ProcessSample {
                pid: 42,
                name: "Chrome".into(),
                path: Some("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into()),
                user: Some("nirmal".into()),
                bytes_in: 100,
                bytes_out: 200,
                connection_count: 1,
            }],
            sockets: vec![SocketSample {
                proto: "tcp".into(),
                client_ip: "10.0.0.5".into(),
                client_port: 50000,
                server_ip: "198.51.100.10".into(),
                server_port: 443,
                state: Some("Established".into()),
                interface: Some("en0".into()),
                bytes_ab: 100,
                bytes_ba: 200,
                pid: 42,
                process_name: "Chrome".into(),
            }],
        };
        store.apply_snapshot(&snapshot, 1000).unwrap();

        let record = extractor(
            r#"{"ts":1001,"uid":"C1","id.orig_h":"10.0.0.5","id.orig_p":50000,"id.resp_h":"198.51.100.10","id.resp_p":443,"proto":"TCP","service":"ssl","conn_state":"SF","duration":1.0,"orig_pkts":2,"resp_pkts":3,"orig_bytes":100,"resp_bytes":200}"#,
        );
        store.insert_extractor_records(&[record], 1001).unwrap();

        let connections = store.list_connections(10, 0).unwrap();
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].pid, Some(42));
        assert_eq!(connections[0].process_name.as_deref(), Some("Chrome"));
    }

    #[test]
    fn stores_hostname_observations() {
        let mut store = Store::open_in_memory().unwrap();
        let records = vec![
            extractor(
                r#"{"ts":1000,"id.orig_h":"10.0.0.5","id.resp_h":"203.0.113.53","id.resp_p":53,"proto":"udp","query":"example.com","qtype_name":"A","rcode_name":"NOERROR","answers":"93.184.216.34","TTLs":"300"}"#,
            ),
            extractor(
                r#"{"ts":1001,"id.orig_h":"10.0.0.5","id.resp_h":"93.184.216.34","id.resp_p":443,"server_name":"example.com","version":"TLSv1.3","validation_status":"valid"}"#,
            ),
        ];
        store.insert_extractor_records(&records, 1001).unwrap();

        assert_eq!(store.count_dns().unwrap(), 1);
        assert_eq!(store.count_tls().unwrap(), 1);
        let destinations = store.list_destinations(10, 0).unwrap();
        let example = destinations
            .iter()
            .find(|destination| destination.ip == "93.184.216.34")
            .unwrap();
        assert_eq!(example.hostname.as_deref(), Some("example.com"));
        assert_eq!(store.endpoint_domains("93.184.216.34").unwrap().len(), 1);
    }

    #[test]
    fn maps_multiple_domains_to_one_endpoint_and_tracks_trust() {
        let mut store = Store::open_in_memory().unwrap();
        let records = vec![
            extractor(
                r#"{"ts":1000,"id.orig_h":"10.0.0.5","id.resp_h":"93.184.216.34","id.resp_p":443,"server_name":"example.com","version":"TLSv1.3","validation_status":"valid"}"#,
            ),
            extractor(
                r#"{"ts":1001,"id.orig_h":"10.0.0.5","id.resp_h":"93.184.216.34","id.resp_p":443,"server_name":"api.spotify.com","version":"TLSv1.3","validation_status":"valid"}"#,
            ),
            extractor(
                r#"{"ts":1002,"id.orig_h":"10.0.0.5","id.resp_h":"93.184.216.34","id.resp_p":443,"proto":"tcp","service":"ssl","conn_state":"SF","orig_bytes":100,"resp_bytes":200}"#,
            ),
        ];
        store.insert_extractor_records(&records, 1002).unwrap();

        let domains = store.endpoint_domains("93.184.216.34").unwrap();
        assert_eq!(domains.len(), 2);
        assert!(domains.iter().any(|domain| domain.domain == "example.com"));
        assert!(
            domains
                .iter()
                .any(|domain| domain.domain == "api.spotify.com")
        );

        let summaries = store.list_domains(10, 0).unwrap();
        assert_eq!(summaries.len(), 2);
        assert!(
            summaries
                .iter()
                .any(|summary| summary.domain == "spotify.com")
        );

        store
            .set_domain_trust("spotify.com", TrustState::Trusted, Some("music"))
            .unwrap();
        let domains = store.endpoint_domains("93.184.216.34").unwrap();
        let spotify = domains
            .iter()
            .find(|domain| domain.domain == "api.spotify.com")
            .unwrap();
        assert_eq!(spotify.trust_state, TrustState::Trusted);

        let destination = store
            .list_destinations(10, 0)
            .unwrap()
            .into_iter()
            .find(|destination| destination.ip == "93.184.216.34")
            .unwrap();
        assert_eq!(destination.domains.len(), 2);
        assert_eq!(destination.trust_state, TrustState::Unknown);
        assert!(destination.flags.contains(&ReviewFlag::UnknownTrust));
    }

    #[test]
    fn flags_invalid_tls_and_alerts() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .insert_alerts(&[alert(10, 1, "198.51.100.10", 443)])
            .unwrap();
        store
            .insert_extractor_records(
                &[extractor(
                    r#"{"ts":1001,"id.orig_h":"10.0.0.5","id.resp_h":"198.51.100.10","id.resp_p":443,"server_name":"odd.example.com","version":"TLSv1.2","validation_status":"invalid"}"#,
                )],
                1001,
            )
            .unwrap();

        let destination = store
            .list_destinations(10, 0)
            .unwrap()
            .into_iter()
            .find(|destination| destination.ip == "198.51.100.10")
            .unwrap();
        assert!(destination.flags.contains(&ReviewFlag::Alerts));
        assert!(destination.flags.contains(&ReviewFlag::InvalidTls));
        assert!(destination.flags.contains(&ReviewFlag::UnknownTrust));

        let domain = store
            .list_domains(10, 0)
            .unwrap()
            .into_iter()
            .find(|domain| domain.domain == "example.com")
            .unwrap();
        assert!(domain.flags.contains(&ReviewFlag::Alerts));
        assert!(domain.flags.contains(&ReviewFlag::InvalidTls));
    }

    #[test]
    fn watched_domains_map_resolved_ips() {
        let store = Store::open_in_memory().unwrap();
        let watched = store.add_watched_domain("api.spotify.com").unwrap();
        assert_eq!(watched.registrable_domain, "spotify.com");
        assert_eq!(store.list_watched_domains().unwrap().len(), 1);
        assert_eq!(store.due_watched_domains(1000, 0, 10).unwrap().len(), 1);

        store
            .save_watched_result(
                "api.spotify.com",
                &["198.51.100.10".to_string()],
                None,
                1000,
            )
            .unwrap();
        let domains = store.endpoint_domains("198.51.100.10").unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].source, "watched");
        assert!(store.due_watched_domains(1001, 60, 10).unwrap().is_empty());

        store.remove_watched_domain("api.spotify.com").unwrap();
        assert!(store.list_watched_domains().unwrap().is_empty());
    }

    #[test]
    fn ptr_results_are_cached_and_mapped() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .insert_alerts(&[alert(10, 1, "203.0.113.9", 443)])
            .unwrap();
        assert_eq!(store.pending_ptr_ips(100, 10).unwrap().len(), 1);

        store
            .save_ptr_result(
                "203.0.113.9",
                Some("host.example.com"),
                "ok",
                None,
                100,
                86_400,
                21_600,
            )
            .unwrap();
        let domains = store.endpoint_domains("203.0.113.9").unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].source, "ptr");
        assert!(store.pending_ptr_ips(101, 10).unwrap().is_empty());
    }

    #[test]
    fn links_processes_and_destinations_with_domains() {
        let mut store = Store::open_in_memory().unwrap();
        let snapshot = CollectorSnapshot {
            processes: vec![ProcessSample {
                pid: 42,
                name: "Spotify".into(),
                path: Some("/Applications/Spotify.app".into()),
                user: Some("nirmal".into()),
                bytes_in: 100,
                bytes_out: 200,
                connection_count: 1,
            }],
            sockets: vec![SocketSample {
                proto: "tcp".into(),
                client_ip: "10.0.0.5".into(),
                client_port: 50000,
                server_ip: "198.51.100.10".into(),
                server_port: 443,
                state: Some("Established".into()),
                interface: Some("en0".into()),
                bytes_ab: 100,
                bytes_ba: 200,
                pid: 42,
                process_name: "Spotify".into(),
            }],
        };
        store.apply_snapshot(&snapshot, 1000).unwrap();
        store
            .insert_extractor_records(
                &[extractor(
                    r#"{"ts":1001,"id.orig_h":"10.0.0.5","id.resp_h":"198.51.100.10","id.resp_p":443,"server_name":"api.spotify.com","version":"TLSv1.3","validation_status":"valid"}"#,
                )],
                1001,
            )
            .unwrap();

        let process = store.process_detail(42).unwrap().unwrap();
        assert_eq!(process.destinations.len(), 1);
        assert_eq!(process.destinations[0].ip, "198.51.100.10");
        assert_eq!(process.destinations[0].domains.len(), 1);
        assert_eq!(process.destinations[0].domains[0].domain, "api.spotify.com");
        assert_eq!(process.destinations[0].live_bytes_in, 200);
        assert_eq!(process.destinations[0].live_bytes_out, 100);

        let destination = store.destination_detail("198.51.100.10").unwrap().unwrap();
        assert_eq!(destination.processes.len(), 1);
        assert_eq!(destination.processes[0].pid, Some(42));
        assert_eq!(destination.processes[0].live_bytes_in, 200);
        assert_eq!(destination.processes[0].live_bytes_out, 100);
        assert_eq!(destination.destination.domains.len(), 1);
        assert_eq!(destination.destination.live_bytes_in, 200);
        assert_eq!(destination.destination.live_bytes_out, 100);
    }

    #[test]
    fn settings_round_trip_and_reset() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.get_settings().unwrap(), AppSettings::default());

        let updated = store
            .update_settings(&serde_json::json!({
                "theme": "dark",
                "ui": { "page_size": 50 },
                "retention": { "alerts_days": 7 }
            }))
            .unwrap();
        assert_eq!(updated.theme, ThemeMode::Dark);
        assert_eq!(updated.ui.page_size, 50);
        assert_eq!(updated.retention.alerts_days, 7);
        assert_eq!(store.get_settings().unwrap(), updated);

        let reset = store.reset_settings().unwrap();
        assert_eq!(reset, AppSettings::default());
    }

    #[test]
    fn retention_prunes_old_rows_and_keeps_recent_rows() {
        let mut store = Store::open_in_memory().unwrap();
        let now = unix_now();
        store
            .insert_alerts(&[
                alert(10, 1, "198.51.100.10", 443),
                alert(now, 2, "198.51.100.11", 443),
            ])
            .unwrap();
        assert_eq!(store.count_alerts().unwrap(), 2);

        let settings = store.get_settings().unwrap();
        let result = store.prune(&settings).unwrap();
        assert!(result.total_deleted >= 1);
        assert_eq!(store.count_alerts().unwrap(), 1);
        assert_eq!(store.count_destinations().unwrap(), 1);
    }

    #[test]
    fn searches_and_sorts_destinations_and_domains() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .insert_alerts(&[
                alert(10, 1, "198.51.100.10", 443),
                alert(20, 2, "203.0.113.9", 443),
            ])
            .unwrap();
        store
            .insert_extractor_records(
                &[extractor(
                    r#"{"ts":1001,"id.orig_h":"10.0.0.5","id.resp_h":"198.51.100.10","id.resp_p":443,"server_name":"api.spotify.com","version":"TLSv1.3","validation_status":"valid"}"#,
                )],
                1001,
            )
            .unwrap();

        let destinations = store
            .list_destinations_query(&ListQuery {
                q: Some("198.51".into()),
                sort: Some("ip".into()),
                dir: Some(SortDirection::Asc),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(destinations.len(), 1);
        assert_eq!(destinations[0].ip, "198.51.100.10");
        assert_eq!(
            store
                .count_destinations_query(&ListQuery {
                    q: Some("198.51".into()),
                    ..Default::default()
                })
                .unwrap(),
            1
        );

        let domains = store
            .list_domains_query(&ListQuery {
                q: Some("spotify".into()),
                sort: Some("domain".into()),
                dir: Some(SortDirection::Asc),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].domain, "spotify.com");
    }

    #[test]
    fn paginates_filters_and_sorts_alerts() {
        let mut store = Store::open_in_memory().unwrap();
        let mut entries = Vec::new();
        for (index, message) in ["alpha", "beta", "gamma", "delta"].iter().enumerate() {
            let json = format!(
                r#"{{"seconds":{},"sid":{},"gid":1,"rev":1,"proto":"TCP","src_addr":"10.0.0.5","src_port":1234,"dst_addr":"198.51.100.10","dst_port":443,"action":"allowed","msg":"{message}"}}"#,
                100 + index,
                index + 1
            );
            entries.push((Alert::parse(&json).unwrap(), json));
        }
        store.insert_alerts(&entries).unwrap();

        let query = ListQuery {
            limit: Some(2),
            offset: Some(1),
            q: None,
            sort: Some("time".into()),
            dir: Some(SortDirection::Asc),
        };
        let alerts = store.list_alerts_query(&query).unwrap();
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].alert.sid, 2);
        assert_eq!(store.count_alerts_query(&query).unwrap(), 4);

        let filtered = ListQuery {
            q: Some("gamma".into()),
            ..Default::default()
        };
        assert_eq!(store.list_alerts_query(&filtered).unwrap().len(), 1);
        assert_eq!(store.count_alerts_query(&filtered).unwrap(), 1);
    }
}
