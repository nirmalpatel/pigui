use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use pigui_collector::CollectorSnapshot;
use pigui_core::domain::{normalize_hostname, registrable_domain};
use pigui_core::error::{Error, Result};
use pigui_core::models::{
    Alert, Connection, Destination, DnsObservation, DomainSummary, EndpointDomain, ExtractorRecord,
    Flow, HttpObservation, Process, QuicObservation, ReviewFlag, TlsObservation, TrustState,
};
use pigui_core::rpc::{
    AlertRecord, DestinationDetail, DestinationProcess, ProcessDestination, ProcessDetail,
};
use rusqlite::{Connection as SqlConnection, OptionalExtension, params};
use serde::Serialize;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
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

INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('version', '3');
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
    (SELECT COUNT(DISTINCT f.pid) FROM flows f WHERE f.server_ip = e.ip AND f.pid IS NOT NULL),
    e.alert_count, e.reputation, e.blocked
FROM endpoints e
ORDER BY e.alert_count DESC, e.last_seen DESC, e.ip ASC
LIMIT ?1 OFFSET ?2
"#;

const SELECT_DESTINATION_BY_IP: &str = r#"
SELECT
    e.ip, e.hostname, e.first_seen, e.last_seen, e.bytes_in, e.bytes_out,
    e.connection_count,
    (SELECT COUNT(DISTINCT f.pid) FROM flows f WHERE f.server_ip = e.ip AND f.pid IS NOT NULL),
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
        Self::init(conn, true)
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
        if previous_version.as_deref() != Some("3") {
            backfill_domains(&conn)?;
        }
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

        tx.execute("DELETE FROM flows WHERE last_seen < ?1", params![now - 600])
            .map_err(db)?;
        tx.execute(
            "DELETE FROM processes WHERE last_seen < ?1",
            params![now - 86_400],
        )
        .map_err(db)?;

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
                let mut flags = Vec::new();
                if trust_state == TrustState::Unknown {
                    flags.push(ReviewFlag::UnknownTrust);
                }
                if now.saturating_sub(first_seen) <= 86_400 {
                    flags.push(ReviewFlag::NewDomain);
                }
                if row.get::<_, i64>(8)? != 0 {
                    flags.push(ReviewFlag::Alerts);
                }
                if row.get::<_, i64>(9)? != 0 {
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
                    trust_state,
                    first_seen,
                    last_seen: row.get(3)?,
                    observation_count: row.get::<_, i64>(4)? as u64,
                    endpoint_count: row.get::<_, i64>(6)? as u64,
                    process_count: row.get::<_, i64>(7)? as u64,
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
                "SELECT pid, process_name, SUM(bytes_ba), SUM(bytes_ab), COUNT(*), MAX(last_seen)
                 FROM (
                     SELECT pid, process_name, bytes_ab, bytes_ba, last_seen
                     FROM flows WHERE server_ip = ?1
                     UNION ALL
                     SELECT pid, process_name, bytes_ab, bytes_ba, ts AS last_seen
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
                    bytes_in: row.get::<_, i64>(2)? as u64,
                    bytes_out: row.get::<_, i64>(3)? as u64,
                    connection_count: row.get::<_, i64>(4)? as u64,
                    last_seen: row.get(5)?,
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
                "SELECT server_ip, SUM(bytes_ba), SUM(bytes_ab), COUNT(*), MAX(last_seen)
                 FROM (
                     SELECT server_ip, bytes_ab, bytes_ba, last_seen
                     FROM flows WHERE pid = ?1
                     UNION ALL
                     SELECT server_ip, bytes_ab, bytes_ba, ts AS last_seen
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
                    row.get(4)?,
                ))
            })
            .map_err(db)?;
        let entries = rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?;
        drop(statement);

        let now = unix_now();
        let mut destinations = Vec::with_capacity(entries.len());
        for (ip, bytes_in, bytes_out, connection_count, last_seen) in entries {
            let domains = self.endpoint_domains(&ip)?;
            let invalid_tls = self.has_invalid_tls(&ip)?;
            destinations.push(ProcessDestination {
                trust_state: aggregate_trust(&domains),
                flags: review_flags(&domains, 0, invalid_tls, now),
                domains,
                ip,
                bytes_in,
                bytes_out,
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

    fn count(&self, sql: &str) -> Result<u64> {
        let count: i64 = self.conn.query_row(sql, [], |row| row.get(0)).map_err(db)?;
        Ok(count as u64)
    }
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
        alert_count: row.get::<_, i64>(8)? as u64,
        reputation: row.get(9)?,
        blocked: row.get::<_, i64>(10)? != 0,
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
            r#"{"ts":1001,"uid":"C1","id.orig_h":"10.0.0.5","id.orig_p":50000,"id.resp_h":"198.51.100.10","id.resp_p":443,"proto":"tcp","service":"ssl","conn_state":"SF","duration":1.0,"orig_pkts":2,"resp_pkts":3,"orig_bytes":100,"resp_bytes":200}"#,
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

        let destination = store.destination_detail("198.51.100.10").unwrap().unwrap();
        assert_eq!(destination.processes.len(), 1);
        assert_eq!(destination.processes[0].pid, Some(42));
        assert_eq!(destination.destination.domains.len(), 1);
    }
}
