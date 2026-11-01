use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use pigui_core::error::{Error, Result};
use pigui_core::models::{Alert, Destination};
use pigui_core::rpc::AlertRecord;
use rusqlite::{Connection, params};
use serde::Serialize;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('version', '1');

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

const UPSERT_ENDPOINT: &str = r#"
INSERT INTO endpoints (ip, first_seen, last_seen, alert_count)
VALUES (?1, ?2, ?2, 1)
ON CONFLICT(ip) DO UPDATE SET
    first_seen = MIN(first_seen, excluded.first_seen),
    last_seen = MAX(last_seen, excluded.last_seen),
    alert_count = alert_count + 1
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
SELECT ip, first_seen, last_seen, bytes_in, bytes_out, connection_count,
       process_count, alert_count, reputation, blocked
FROM endpoints
ORDER BY alert_count DESC, last_seen DESC, ip ASC
LIMIT ?1 OFFSET ?2
"#;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct IngestStats {
    pub inserted: u64,
    pub duplicates: u64,
    pub malformed: u64,
}

#[derive(Debug)]
pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        let conn = Connection::open(path).map_err(db)?;
        Self::init(conn, true)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(db)?;
        Self::init(conn, false)
    }

    fn init(conn: Connection, wal: bool) -> Result<Self> {
        if wal {
            conn.pragma_update(None, "journal_mode", "WAL")
                .map_err(db)?;
        }
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(db)?;
        conn.pragma_update(None, "foreign_keys", "ON").map_err(db)?;
        conn.execute_batch(SCHEMA).map_err(db)?;
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
                    tx.execute(UPSERT_ENDPOINT, params![dst_ip, alert.event_ts])
                        .map_err(db)?;
                }
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
            .query_map(params![limit, offset], |row| {
                Ok(Destination {
                    ip: row.get(0)?,
                    first_seen: row.get(1)?,
                    last_seen: row.get(2)?,
                    bytes_in: row.get::<_, i64>(3)? as u64,
                    bytes_out: row.get::<_, i64>(4)? as u64,
                    connection_count: row.get::<_, i64>(5)? as u64,
                    process_count: row.get::<_, i64>(6)? as u64,
                    alert_count: row.get::<_, i64>(7)? as u64,
                    reputation: row.get(8)?,
                    blocked: row.get::<_, i64>(9)? != 0,
                })
            })
            .map_err(db)?;

        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    pub fn count_destinations(&self) -> Result<u64> {
        self.count("SELECT COUNT(*) FROM endpoints")
    }

    fn count(&self, sql: &str) -> Result<u64> {
        let count: i64 = self.conn.query_row(sql, [], |row| row.get(0)).map_err(db)?;
        Ok(count as u64)
    }
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn db(error: rusqlite::Error) -> Error {
    Error::Database(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(seconds: i64, sid: u32, dst: &str, dst_port: u16) -> (Alert, String) {
        let json = format!(
            r#"{{"seconds":{seconds},"sid":{sid},"gid":1,"rev":1,"proto":"TCP","src_addr":"10.0.0.5","src_port":1234,"dst_addr":"{dst}","dst_port":{dst_port},"action":"allowed"}}"#
        );
        let alert = Alert::parse(&json).unwrap();
        (alert, json)
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
}
