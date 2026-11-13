use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

use pigui_core::error::{Error, Result};
use pigui_core::models::analysis::{
    AlertBreakdown, AlertCount, AlertSidCount, AnalysisCoverage, AnalysisDestinationSummary,
    AnalysisDomainSummary, AnalysisFinding, AnalysisFindings, AnalysisOverview,
    AnalysisProcessSummary, AnalysisQuery, AnalysisTotals, AnalysisWindow, BaselineAlert,
    BaselineComparison, BaselinePort, BaselineProcess, BaselineWindow, DestinationRef, DomainRef,
    FindingConfidence, FindingSeverity, NoiseExample, NoiseSummary, ProcessRef, ProtocolPort,
    TrustBreakdown,
};
use pigui_core::models::{ReviewFlag, TrustState};
use rusqlite::params;
use serde_json::json;

use super::{Store, db, unix_now};

const MAX_WINDOW_SECS: i64 = 30 * 86_400;
const DEFAULT_WINDOW_SECS: i64 = 86_400;
const DEFAULT_LIMIT: u32 = 20;
const MAX_LIMIT: u32 = 100;
const MIN_EGRESS_BYTES: u64 = 100 * 1024;
const MIN_RARE_PORT_BYTES: u64 = 10 * 1024;
const NOISY_GID: u32 = 116;
const NOISY_SID: u32 = 444;

struct NormalizedAnalysis {
    window: AnalysisWindow,
    limit: u32,
    min_severity: FindingSeverity,
    include_noise: bool,
    baseline: bool,
}

impl Store {
    pub fn analysis_overview(
        &self,
        query: &AnalysisQuery,
        mut coverage: AnalysisCoverage,
    ) -> Result<AnalysisOverview> {
        let normalized = normalize_query(query, unix_now())?;
        let window = &normalized.window;
        let limit = normalized.limit;

        let totals = self.analysis_totals(window.since, window.until)?;
        let top_processes = self.analysis_top_processes(window.since, window.until, limit)?;
        let mut top_destinations =
            self.analysis_top_destinations(window.since, window.until, limit)?;
        if !normalized.include_noise {
            top_destinations.retain(|destination| !is_noise_ip(&destination.ip));
        }
        let top_domains = self.analysis_top_domains(window.since, window.until, limit)?;
        let alert_breakdown = self.analysis_alert_breakdown(
            window.since,
            window.until,
            limit,
            normalized.include_noise,
        )?;
        let protocol_ports = self.analysis_protocol_ports(window.since, window.until, limit)?;
        let trust_breakdown = self.analysis_trust_breakdown(window.since, window.until)?;
        let new_domains = self.analysis_new_domains(window.since, window.until, limit)?;
        let noise = self.analysis_noise(window.since, window.until)?;

        if window.clamped {
            coverage.limitations.push(format!(
                "requested analysis window exceeded the {} day maximum and was clamped",
                MAX_WINDOW_SECS / 86_400
            ));
        }
        if !coverage.snort_running {
            coverage
                .limitations
                .push("Snort is not running; capture coverage may be incomplete".into());
        }
        if coverage.extractor_idle {
            coverage
                .limitations
                .push("the extractor is idle; protocol observations may be missing".into());
        }
        if coverage.parse_errors > 0 {
            coverage.limitations.push(format!(
                "the daemon reported {} parse errors; some telemetry was skipped",
                coverage.parse_errors
            ));
        }
        if let Some(error) = coverage.collector_error.as_deref() {
            coverage
                .limitations
                .push(format!("the OS collector reported an error: {error}"));
        }
        if totals.http == 0 {
            coverage.limitations.push(
                "no HTTP observations in the window; absence is not evidence of absence".into(),
            );
        }
        if totals.quic == 0 {
            coverage.limitations.push(
                "no QUIC observations in the window; absence is not evidence of absence".into(),
            );
        }
        let window_days = window.duration_secs as f64 / 86_400.0;
        if window_days > 7.0 {
            coverage.limitations.push(
                "connection and protocol observation retention is 7 days; older parts of the window may be incomplete"
                    .into(),
            );
        }
        if window_days > 1.0 {
            coverage.limitations.push(
                "process retention is 24 hours; process inventory and baseline comparisons are limited"
                    .into(),
            );
        }

        let baseline = if normalized.baseline {
            window
                .baseline
                .as_ref()
                .map(|baseline| self.analysis_baseline(baseline, window.until, limit))
                .transpose()?
        } else {
            None
        };

        Ok(AnalysisOverview {
            generated_at: unix_now(),
            window: window.clone(),
            coverage,
            totals,
            top_processes,
            top_destinations,
            top_domains,
            alert_breakdown,
            protocol_ports,
            trust_breakdown,
            new_domains,
            noise,
            baseline,
        })
    }

    pub fn analysis_findings(
        &self,
        query: &AnalysisQuery,
        mut limitations: Vec<String>,
    ) -> Result<AnalysisFindings> {
        let normalized = normalize_query(query, unix_now())?;
        let window = &normalized.window;
        let include_noise = normalized.include_noise;
        let limit = normalized.limit as usize;
        let suppressed_noise = self.analysis_noise(window.since, window.until)?;

        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        self.finding_high_priority_alerts(window, include_noise, limit, &mut findings, &mut seen)?;
        self.finding_unknown_trust_egress(window, limit, &mut findings, &mut seen)?;
        self.finding_new_domain_egress(window, limit, &mut findings, &mut seen)?;
        self.finding_no_domain_egress(window, limit, &mut findings, &mut seen)?;
        self.finding_direct_ip_traffic(window, limit, &mut findings, &mut seen)?;
        self.finding_rare_ports(window, limit, &mut findings, &mut seen)?;
        self.finding_outbound_heavy(window, limit, &mut findings, &mut seen)?;
        self.finding_beaconing(window, limit, &mut findings, &mut seen)?;
        self.finding_fan_out(window, limit, &mut findings, &mut seen)?;
        self.finding_dns_tunneling(window, limit, &mut findings, &mut seen)?;
        self.finding_invalid_tls(window, limit, &mut findings, &mut seen)?;
        self.finding_path_anomaly(window, limit, &mut findings, &mut seen)?;
        self.finding_user_anomaly(window, limit, &mut findings, &mut seen)?;
        self.finding_new_process_egress(window, limit, &mut findings, &mut seen)?;

        findings.retain(|finding| finding.severity >= normalized.min_severity);
        findings.sort_by(|left, right| {
            right
                .severity
                .cmp(&left.severity)
                .then_with(|| right.confidence.cmp(&left.confidence))
                .then_with(|| {
                    right
                        .last_seen
                        .unwrap_or(0)
                        .cmp(&left.last_seen.unwrap_or(0))
                })
        });
        findings.truncate(limit);

        if window.clamped {
            limitations.push(format!(
                "requested analysis window exceeded the {} day maximum and was clamped",
                MAX_WINDOW_SECS / 86_400
            ));
        }
        if normalized.baseline {
            limitations.push(
                "baseline comparison is reported by analysis.overview; findings remain window-based"
                    .into(),
            );
        }
        if window.duration_secs > 7 * 86_400 {
            limitations.push(
                "connection and protocol observation retention is 7 days; older parts of the window may be incomplete"
                    .into(),
            );
        }
        if window.duration_secs > 86_400 {
            limitations.push(
                "process retention is 24 hours; process-based findings and baselines are limited"
                    .into(),
            );
        }
        limitations.push(
            "findings are heuristic leads, not verdicts; validate evidence with read-only drill-down tools"
                .into(),
        );

        Ok(AnalysisFindings {
            generated_at: unix_now(),
            window: window.clone(),
            findings,
            suppressed_noise,
            limitations,
        })
    }

    fn analysis_totals(&self, since: i64, until: i64) -> Result<AnalysisTotals> {
        Ok(AnalysisTotals {
            alerts: self.count_window("alerts", "event_ts", since, until)?,
            endpoints: self.count_window("endpoints", "last_seen", since, until)?,
            connections: self.count_window("connections", "ts", since, until)?,
            flows: self.count_window("flows", "last_seen", since, until)?,
            processes: self.count_window("processes", "last_seen", since, until)?,
            dns: self.count_window("dns_observations", "ts", since, until)?,
            tls: self.count_window("tls_observations", "ts", since, until)?,
            http: self.count_window("http_observations", "ts", since, until)?,
            quic: self.count_window("quic_observations", "ts", since, until)?,
            domains: self.count_window("domains", "last_seen", since, until)?,
        })
    }

    fn count_window(
        &self,
        table: &'static str,
        column: &'static str,
        since: i64,
        until: i64,
    ) -> Result<u64> {
        let sql = format!("SELECT COUNT(*) FROM {table} WHERE {column} >= ?1 AND {column} < ?2");
        let count: i64 = self
            .conn
            .query_row(&sql, params![since, until], |row| row.get(0))
            .map_err(db)?;
        Ok(count.max(0) as u64)
    }

    fn analysis_top_processes(
        &self,
        since: i64,
        until: i64,
        limit: u32,
    ) -> Result<Vec<AnalysisProcessSummary>> {
        let mut statement = self
            .conn
            .prepare(
                r#"
                WITH window_conns AS (
                    SELECT c.pid,
                           COUNT(*) AS connection_count,
                           COALESCE(SUM(c.bytes_ab), 0) AS bytes_out,
                           COALESCE(SUM(c.bytes_ba), 0) AS bytes_in,
                           COUNT(DISTINCT c.server_ip) AS destinations,
                           COUNT(DISTINCT CASE WHEN ed.ip IS NULL THEN c.server_ip END)
                               AS unknown_destinations
                    FROM connections c
                    LEFT JOIN endpoint_domains ed ON ed.ip = c.server_ip
                    WHERE c.ts >= ?1 AND c.ts < ?2 AND c.pid IS NOT NULL
                    GROUP BY c.pid
                ),
                live AS (
                    SELECT pid,
                           COUNT(*) AS live_connection_count,
                           COALESCE(SUM(bytes_ab), 0) AS live_bytes_out,
                           COALESCE(SUM(bytes_ba), 0) AS live_bytes_in
                    FROM flows
                    WHERE last_seen >= ?1 AND pid IS NOT NULL
                    GROUP BY pid
                )
                SELECT p.pid, p.name, p.path, p.user,
                       COALESCE(w.bytes_in, 0), COALESCE(w.bytes_out, 0),
                       COALESCE(l.live_bytes_in, 0), COALESCE(l.live_bytes_out, 0),
                       COALESCE(w.connection_count, 0),
                       COALESCE(w.destinations, 0),
                       COALESCE(w.unknown_destinations, 0),
                       p.first_seen, p.last_seen
                FROM processes p
                LEFT JOIN window_conns w ON w.pid = p.pid
                LEFT JOIN live l ON l.pid = p.pid
                WHERE w.pid IS NOT NULL OR l.pid IS NOT NULL
                ORDER BY COALESCE(w.bytes_in, 0) + COALESCE(w.bytes_out, 0)
                       + COALESCE(l.live_bytes_in, 0) + COALESCE(l.live_bytes_out, 0) DESC,
                       p.last_seen DESC
                LIMIT ?3
                "#,
            )
            .map_err(db)?;
        let rows = statement
            .query_map(params![since, until, i64::from(limit)], |row| {
                Ok(AnalysisProcessSummary {
                    pid: row.get::<_, i64>(0)? as u32,
                    name: row.get(1)?,
                    path: row.get(2)?,
                    user: row.get(3)?,
                    bytes_in: row.get::<_, i64>(4)?.max(0) as u64,
                    bytes_out: row.get::<_, i64>(5)?.max(0) as u64,
                    live_bytes_in: row.get::<_, i64>(6)?.max(0) as u64,
                    live_bytes_out: row.get::<_, i64>(7)?.max(0) as u64,
                    connection_count: row.get::<_, i64>(8)?.max(0) as u64,
                    destinations: row.get::<_, i64>(9)?.max(0) as u64,
                    unknown_destinations: row.get::<_, i64>(10)?.max(0) as u64,
                    first_seen: row.get(11)?,
                    last_seen: row.get(12)?,
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    fn analysis_top_destinations(
        &self,
        since: i64,
        until: i64,
        limit: u32,
    ) -> Result<Vec<AnalysisDestinationSummary>> {
        let mut statement = self
            .conn
            .prepare(
                r#"
                WITH window_conns AS (
                    SELECT server_ip,
                           COUNT(*) AS connection_count,
                           COALESCE(SUM(bytes_ab), 0) AS bytes_out,
                           COALESCE(SUM(bytes_ba), 0) AS bytes_in,
                           MIN(ts) AS first_seen,
                           MAX(ts) AS last_seen
                    FROM connections
                    WHERE ts >= ?1 AND ts < ?2 AND server_ip IS NOT NULL
                    GROUP BY server_ip
                ),
                live AS (
                    SELECT server_ip,
                           COUNT(*) AS live_connection_count,
                           COALESCE(SUM(bytes_ab), 0) AS live_bytes_out,
                           COALESCE(SUM(bytes_ba), 0) AS live_bytes_in
                    FROM flows
                    WHERE last_seen >= ?1 AND server_ip IS NOT NULL
                    GROUP BY server_ip
                ),
                window_alerts AS (
                    SELECT dst_ip, COUNT(*) AS alert_count
                    FROM alerts
                    WHERE event_ts >= ?1 AND event_ts < ?2 AND dst_ip IS NOT NULL
                    GROUP BY dst_ip
                )
                SELECT e.ip, e.hostname,
                       COALESCE(w.bytes_in, 0), COALESCE(w.bytes_out, 0),
                       COALESCE(w.connection_count, 0),
                       COALESCE(l.live_bytes_in, 0), COALESCE(l.live_bytes_out, 0),
                       COALESCE(a.alert_count, 0),
                       e.bytes_in, e.bytes_out,
                       COALESCE(w.first_seen, e.first_seen),
                       COALESCE(w.last_seen, e.last_seen)
                FROM endpoints e
                LEFT JOIN window_conns w ON w.server_ip = e.ip
                LEFT JOIN live l ON l.server_ip = e.ip
                LEFT JOIN window_alerts a ON a.dst_ip = e.ip
                WHERE w.server_ip IS NOT NULL OR l.server_ip IS NOT NULL OR a.dst_ip IS NOT NULL
                ORDER BY COALESCE(w.bytes_in, 0) + COALESCE(w.bytes_out, 0)
                       + COALESCE(l.live_bytes_in, 0) + COALESCE(l.live_bytes_out, 0)
                       + COALESCE(a.alert_count, 0) DESC,
                       e.last_seen DESC
                LIMIT ?3
                "#,
            )
            .map_err(db)?;
        let entries = statement
            .query_map(params![since, until, i64::from(limit)], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?.max(0) as u64,
                    row.get::<_, i64>(4)?.max(0) as u64,
                    row.get::<_, i64>(5)?.max(0) as u64,
                    row.get::<_, i64>(6)?.max(0) as u64,
                    row.get::<_, i64>(7)?.max(0) as u64,
                    row.get::<_, i64>(8)?.max(0) as u64,
                    row.get::<_, i64>(9)?.max(0) as u64,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                ))
            })
            .map_err(db)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db)?;
        drop(statement);

        let mut destinations = Vec::with_capacity(entries.len());
        for (
            ip,
            hostname,
            bytes_in,
            bytes_out,
            connection_count,
            live_bytes_in,
            live_bytes_out,
            alert_count,
            endpoint_bytes_in,
            endpoint_bytes_out,
            first_seen,
            last_seen,
        ) in entries
        {
            let domains = self.endpoint_domains(&ip)?;
            let invalid_tls = self.has_invalid_tls(&ip)?;
            let trust_state = super::aggregate_trust(&domains);
            let flags = super::review_flags(&domains, alert_count, invalid_tls, unix_now());
            destinations.push(AnalysisDestinationSummary {
                ip,
                hostname: hostname.or_else(|| domains.first().map(|domain| domain.domain.clone())),
                trust_state,
                flags: flags.into_iter().map(flag_name).collect(),
                domains: domains
                    .iter()
                    .map(|domain| domain.domain.clone())
                    .take(10)
                    .collect(),
                sources: distinct_sources(&domains),
                bytes_in,
                bytes_out,
                live_bytes_in,
                live_bytes_out,
                connection_count,
                alert_count,
                endpoint_bytes_in,
                endpoint_bytes_out,
                first_seen,
                last_seen,
            });
        }
        Ok(destinations)
    }

    fn analysis_top_domains(
        &self,
        since: i64,
        until: i64,
        limit: u32,
    ) -> Result<Vec<AnalysisDomainSummary>> {
        let mut statement = self
            .conn
            .prepare(
                r#"
                WITH window_conns AS (
                    SELECT server_ip,
                           COUNT(*) AS connection_count,
                           COALESCE(SUM(bytes_ab), 0) AS bytes_out,
                           COALESCE(SUM(bytes_ba), 0) AS bytes_in,
                           MIN(ts) AS first_seen,
                           MAX(ts) AS last_seen
                    FROM connections
                    WHERE ts >= ?1 AND ts < ?2 AND server_ip IS NOT NULL
                    GROUP BY server_ip
                ),
                ip_domains AS (
                    SELECT DISTINCT ed.ip, d.registrable_domain
                    FROM endpoint_domains ed
                    JOIN domains d ON d.domain = ed.domain
                )
                SELECT id.registrable_domain,
                       COALESCE(t.state, default_domain_trust(id.registrable_domain), 'unknown'),
                       COUNT(DISTINCT c.server_ip),
                       SUM(c.connection_count),
                       SUM(c.bytes_out),
                       SUM(c.bytes_in),
                       MIN(c.first_seen),
                       MAX(c.last_seen),
                       (SELECT GROUP_CONCAT(DISTINCT d2.domain)
                        FROM endpoint_domains ed2
                        JOIN domains d2 ON d2.domain = ed2.domain
                        WHERE d2.registrable_domain = id.registrable_domain),
                       (SELECT GROUP_CONCAT(DISTINCT ed3.source)
                        FROM endpoint_domains ed3
                        JOIN domains d3 ON d3.domain = ed3.domain
                        WHERE d3.registrable_domain = id.registrable_domain),
                       (SELECT COUNT(DISTINCT c2.pid)
                        FROM connections c2
                        JOIN endpoint_domains ed4 ON ed4.ip = c2.server_ip
                        JOIN domains d4 ON d4.domain = ed4.domain
                        WHERE c2.ts >= ?1 AND c2.ts < ?2
                          AND c2.pid IS NOT NULL
                          AND d4.registrable_domain = id.registrable_domain)
                FROM window_conns c
                JOIN ip_domains id ON id.ip = c.server_ip
                LEFT JOIN domain_trust t ON t.registrable_domain = id.registrable_domain
                GROUP BY id.registrable_domain
                ORDER BY SUM(c.bytes_out + c.bytes_in) DESC,
                         SUM(c.connection_count) DESC
                LIMIT ?3
                "#,
            )
            .map_err(db)?;
        let rows = statement
            .query_map(params![since, until, i64::from(limit)], |row| {
                let hostnames: Option<String> = row.get(8)?;
                let sources: Option<String> = row.get(9)?;
                Ok(AnalysisDomainSummary {
                    registrable_domain: row.get(0)?,
                    trust_state: trust_from_str(row.get::<_, String>(1)?.as_str()),
                    endpoint_count: row.get::<_, i64>(2)?.max(0) as u64,
                    observation_count: row.get::<_, i64>(3)?.max(0) as u64,
                    bytes_out: row.get::<_, i64>(4)?.max(0) as u64,
                    bytes_in: row.get::<_, i64>(5)?.max(0) as u64,
                    first_seen: row.get(6)?,
                    last_seen: row.get(7)?,
                    hostnames: split_distinct(hostnames).into_iter().take(10).collect(),
                    sources: split_distinct(sources),
                    process_count: row.get::<_, i64>(10)?.max(0) as u64,
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    fn analysis_new_domains(
        &self,
        since: i64,
        until: i64,
        limit: u32,
    ) -> Result<Vec<AnalysisDomainSummary>> {
        let mut statement = self
            .conn
            .prepare(
                r#"
                WITH new_domains AS (
                    SELECT registrable_domain,
                           MIN(first_seen) AS first_seen,
                           MAX(last_seen) AS last_seen,
                           SUM(observation_count) AS observation_count
                    FROM domains
                    WHERE first_seen >= ?1 AND first_seen < ?2
                    GROUP BY registrable_domain
                )
                SELECT d.registrable_domain,
                       COALESCE(t.state, default_domain_trust(d.registrable_domain), 'unknown'),
                       d.observation_count,
                       d.first_seen,
                       d.last_seen,
                       (SELECT GROUP_CONCAT(DISTINCT dd.domain)
                        FROM domains dd
                        WHERE dd.registrable_domain = d.registrable_domain),
                       (SELECT GROUP_CONCAT(DISTINCT ed.source)
                        FROM endpoint_domains ed
                        JOIN domains dd ON dd.domain = ed.domain
                        WHERE dd.registrable_domain = d.registrable_domain),
                       (SELECT COUNT(DISTINCT ed.ip)
                        FROM endpoint_domains ed
                        JOIN domains dd ON dd.domain = ed.domain
                        WHERE dd.registrable_domain = d.registrable_domain),
                       (SELECT COUNT(DISTINCT c.pid)
                        FROM connections c
                        JOIN endpoint_domains ed ON ed.ip = c.server_ip
                        JOIN domains dd ON dd.domain = ed.domain
                        WHERE c.ts >= ?1 AND c.ts < ?2
                          AND c.pid IS NOT NULL
                          AND dd.registrable_domain = d.registrable_domain)
                FROM new_domains d
                LEFT JOIN domain_trust t ON t.registrable_domain = d.registrable_domain
                ORDER BY d.first_seen DESC
                LIMIT ?3
                "#,
            )
            .map_err(db)?;
        let rows = statement
            .query_map(params![since, until, i64::from(limit)], |row| {
                let hostnames: Option<String> = row.get(5)?;
                let sources: Option<String> = row.get(6)?;
                Ok(AnalysisDomainSummary {
                    registrable_domain: row.get(0)?,
                    trust_state: trust_from_str(row.get::<_, String>(1)?.as_str()),
                    observation_count: row.get::<_, i64>(2)?.max(0) as u64,
                    first_seen: row.get(3)?,
                    last_seen: row.get(4)?,
                    hostnames: split_distinct(hostnames).into_iter().take(10).collect(),
                    sources: split_distinct(sources),
                    endpoint_count: row.get::<_, i64>(7)?.max(0) as u64,
                    process_count: row.get::<_, i64>(8)?.max(0) as u64,
                    bytes_in: 0,
                    bytes_out: 0,
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    fn analysis_alert_breakdown(
        &self,
        since: i64,
        until: i64,
        limit: u32,
        include_noise: bool,
    ) -> Result<AlertBreakdown> {
        let exclude = if include_noise {
            ""
        } else {
            " AND NOT (gid = 116 AND sid = 444)"
        };
        Ok(AlertBreakdown {
            by_priority: self.alert_counts(
                &format!(
                    "SELECT CAST(COALESCE(priority, 0) AS TEXT), COUNT(*)
                     FROM alerts WHERE event_ts >= ?1 AND event_ts < ?2{exclude}
                     GROUP BY COALESCE(priority, 0)
                     ORDER BY COUNT(*) DESC LIMIT ?3"
                ),
                since,
                until,
                limit,
            )?,
            by_class: self.alert_counts(
                &format!(
                    "SELECT COALESCE(NULLIF(class, ''), 'unknown'), COUNT(*)
                     FROM alerts WHERE event_ts >= ?1 AND event_ts < ?2{exclude}
                     GROUP BY COALESCE(NULLIF(class, ''), 'unknown')
                     ORDER BY COUNT(*) DESC LIMIT ?3"
                ),
                since,
                until,
                limit,
            )?,
            by_action: self.alert_counts(
                &format!(
                    "SELECT COALESCE(NULLIF(action, ''), 'unknown'), COUNT(*)
                     FROM alerts WHERE event_ts >= ?1 AND event_ts < ?2{exclude}
                     GROUP BY COALESCE(NULLIF(action, ''), 'unknown')
                     ORDER BY COUNT(*) DESC LIMIT ?3"
                ),
                since,
                until,
                limit,
            )?,
            by_sid: self.alert_sid_counts(since, until, limit, include_noise)?,
        })
    }

    fn alert_counts(
        &self,
        sql: &str,
        since: i64,
        until: i64,
        limit: u32,
    ) -> Result<Vec<AlertCount>> {
        let mut statement = self.conn.prepare(sql).map_err(db)?;
        let rows = statement
            .query_map(params![since, until, i64::from(limit)], |row| {
                Ok(AlertCount {
                    key: row.get(0)?,
                    count: row.get::<_, i64>(1)?.max(0) as u64,
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    fn alert_sid_counts(
        &self,
        since: i64,
        until: i64,
        limit: u32,
        include_noise: bool,
    ) -> Result<Vec<AlertSidCount>> {
        let exclude = if include_noise {
            ""
        } else {
            " AND NOT (gid = 116 AND sid = 444)"
        };
        let sql = format!(
            "SELECT gid, sid, MAX(msg), MAX(class), COUNT(*), MAX(priority)
             FROM alerts
             WHERE event_ts >= ?1 AND event_ts < ?2{exclude}
             GROUP BY gid, sid
             ORDER BY COUNT(*) DESC, MAX(priority) ASC
             LIMIT ?3"
        );
        let mut statement = self.conn.prepare(&sql).map_err(db)?;
        let rows = statement
            .query_map(params![since, until, i64::from(limit)], |row| {
                Ok(AlertSidCount {
                    gid: row.get::<_, i64>(0)?.max(0) as u32,
                    sid: row.get::<_, i64>(1)?.max(0) as u32,
                    message: row.get(2)?,
                    class: row.get(3)?,
                    count: row.get::<_, i64>(4)?.max(0) as u64,
                    max_priority: row
                        .get::<_, Option<i64>>(5)?
                        .map(|value| value.max(0) as u32),
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    fn analysis_protocol_ports(
        &self,
        since: i64,
        until: i64,
        limit: u32,
    ) -> Result<Vec<ProtocolPort>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT COALESCE(NULLIF(proto, ''), 'unknown'),
                        COALESCE(server_port, 0),
                        COUNT(*),
                        COALESCE(SUM(bytes_ab), 0),
                        COALESCE(SUM(bytes_ba), 0)
                 FROM connections
                 WHERE ts >= ?1 AND ts < ?2
                 GROUP BY COALESCE(NULLIF(proto, ''), 'unknown'), COALESCE(server_port, 0)
                 ORDER BY COUNT(*) DESC, SUM(bytes_ab + bytes_ba) DESC
                 LIMIT ?3",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(params![since, until, i64::from(limit)], |row| {
                let port: i64 = row.get(1)?;
                Ok(ProtocolPort {
                    proto: row.get(0)?,
                    port: u16::try_from(port.max(0)).unwrap_or(0),
                    connection_count: row.get::<_, i64>(2)?.max(0) as u64,
                    bytes_out: row.get::<_, i64>(3)?.max(0) as u64,
                    bytes_in: row.get::<_, i64>(4)?.max(0) as u64,
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    fn analysis_trust_breakdown(&self, since: i64, until: i64) -> Result<TrustBreakdown> {
        let row = self
            .conn
            .query_row(
                r#"
                WITH active AS (
                    SELECT ip FROM endpoints WHERE last_seen >= ?1 AND last_seen < ?2
                ),
                x AS (
                    SELECT a.ip,
                           (SELECT COUNT(*) FROM endpoint_domains ed WHERE ed.ip = a.ip)
                               AS domain_count,
                           (SELECT COUNT(*)
                            FROM endpoint_domains ed
                            JOIN domains d ON d.domain = ed.domain
                            LEFT JOIN domain_trust t
                                ON t.registrable_domain = d.registrable_domain
                            WHERE ed.ip = a.ip
                              AND COALESCE(t.state,
                                    default_domain_trust(d.registrable_domain), 'unknown')
                                  = 'suspicious') AS suspicious_count,
                           (SELECT COUNT(*)
                            FROM endpoint_domains ed
                            JOIN domains d ON d.domain = ed.domain
                            LEFT JOIN domain_trust t
                                ON t.registrable_domain = d.registrable_domain
                            WHERE ed.ip = a.ip
                              AND COALESCE(t.state,
                                    default_domain_trust(d.registrable_domain), 'unknown')
                                  = 'unknown') AS unknown_count,
                           (SELECT COUNT(*)
                            FROM endpoint_domains ed
                            JOIN domains d ON d.domain = ed.domain
                            LEFT JOIN domain_trust t
                                ON t.registrable_domain = d.registrable_domain
                            WHERE ed.ip = a.ip
                              AND COALESCE(t.state,
                                    default_domain_trust(d.registrable_domain), 'unknown')
                                  = 'ignored') AS ignored_count,
                           (SELECT COUNT(*)
                            FROM endpoint_domains ed
                            JOIN domains d ON d.domain = ed.domain
                            LEFT JOIN domain_trust t
                                ON t.registrable_domain = d.registrable_domain
                            WHERE ed.ip = a.ip
                              AND COALESCE(t.state,
                                    default_domain_trust(d.registrable_domain), 'unknown')
                                  = 'trusted') AS trusted_count
                    FROM active a
                )
                SELECT
                    SUM(CASE WHEN domain_count > 0 AND suspicious_count > 0 THEN 1 ELSE 0 END),
                    SUM(CASE WHEN domain_count > 0 AND suspicious_count = 0
                              AND unknown_count > 0 THEN 1 ELSE 0 END),
                    SUM(CASE WHEN domain_count > 0 AND suspicious_count = 0
                              AND unknown_count = 0 AND ignored_count = domain_count
                             THEN 1 ELSE 0 END),
                    SUM(CASE WHEN domain_count > 0 AND suspicious_count = 0
                              AND unknown_count = 0 AND ignored_count < domain_count
                              AND ignored_count + trusted_count = domain_count
                             THEN 1 ELSE 0 END),
                    SUM(CASE WHEN domain_count = 0 THEN 1 ELSE 0 END)
                FROM x
                "#,
                params![since, until],
                |row| {
                    Ok(TrustBreakdown {
                        suspicious: row.get::<_, Option<i64>>(0)?.unwrap_or(0).max(0) as u64,
                        unknown: row.get::<_, Option<i64>>(1)?.unwrap_or(0).max(0) as u64,
                        ignored: row.get::<_, Option<i64>>(2)?.unwrap_or(0).max(0) as u64,
                        trusted: row.get::<_, Option<i64>>(3)?.unwrap_or(0).max(0) as u64,
                        no_domain: row.get::<_, Option<i64>>(4)?.unwrap_or(0).max(0) as u64,
                    })
                },
            )
            .map_err(db)?;
        Ok(row)
    }

    fn analysis_noise(&self, since: i64, until: i64) -> Result<NoiseSummary> {
        let mut summary = NoiseSummary::default();
        let mut statement = self
            .conn
            .prepare(
                "SELECT dst_ip, COUNT(*)
                 FROM alerts
                 WHERE event_ts >= ?1 AND event_ts < ?2 AND dst_ip IS NOT NULL
                 GROUP BY dst_ip
                 ORDER BY COUNT(*) DESC",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(params![since, until], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?.max(0) as u64,
                ))
            })
            .map_err(db)?;
        let mut examples = Vec::new();
        for row in rows {
            let (ip, count) = row.map_err(db)?;
            let Some(category) = noise_ip_category(&ip) else {
                continue;
            };
            match category {
                "multicast" => summary.multicast_alerts += count,
                "broadcast" => summary.broadcast_alerts += count,
                "loopback" => summary.loopback_alerts += count,
                "link_local" => summary.link_local_alerts += count,
                _ => {}
            }
            summary.excluded_total += count;
            if examples.len() < 10 {
                examples.push(NoiseExample {
                    category: category.to_string(),
                    value: ip,
                    count,
                });
            }
        }
        drop(statement);

        let noisy_sid: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM alerts
                 WHERE event_ts >= ?1 AND event_ts < ?2 AND gid = ?3 AND sid = ?4",
                params![since, until, i64::from(NOISY_GID), i64::from(NOISY_SID)],
                |row| row.get(0),
            )
            .map_err(db)?;
        summary.noisy_sid_alerts = noisy_sid.max(0) as u64;
        summary.excluded_total += summary.noisy_sid_alerts;
        if summary.noisy_sid_alerts > 0 && examples.len() < 10 {
            examples.push(NoiseExample {
                category: "noisy_sid".into(),
                value: format!("{NOISY_GID}:{NOISY_SID}"),
                count: summary.noisy_sid_alerts,
            });
        }
        summary.examples = examples;
        Ok(summary)
    }

    fn analysis_baseline(
        &self,
        baseline: &BaselineWindow,
        current_until: i64,
        limit: u32,
    ) -> Result<BaselineComparison> {
        let current_since = baseline.until;
        let current_until = current_until.max(current_since);
        Ok(BaselineComparison {
            new_processes: self.baseline_new_processes(
                current_since,
                current_until,
                baseline.since,
                baseline.until,
                limit,
            )?,
            new_destinations: self.baseline_new_values(
                "connections",
                "server_ip",
                "ts",
                current_since,
                current_until,
                baseline.since,
                baseline.until,
                limit,
            )?,
            new_ports: self.baseline_new_ports(
                current_since,
                current_until,
                baseline.since,
                baseline.until,
                limit,
            )?,
            byte_spikes: self.baseline_byte_spikes(
                current_since,
                current_until,
                baseline.since,
                baseline.until,
                limit,
            )?,
            alert_spikes: self.baseline_alert_spikes(
                current_since,
                current_until,
                baseline.since,
                baseline.until,
                limit,
            )?,
            new_sni: self.baseline_new_values(
                "tls_observations",
                "server_name",
                "ts",
                current_since,
                current_until,
                baseline.since,
                baseline.until,
                limit,
            )?,
            new_dns_queries: self.baseline_new_values(
                "dns_observations",
                "query",
                "ts",
                current_since,
                current_until,
                baseline.since,
                baseline.until,
                limit,
            )?,
            new_domains: self.baseline_new_domains(
                current_since,
                current_until,
                baseline.since,
                baseline.until,
                limit,
            )?,
        })
    }

    fn baseline_new_processes(
        &self,
        current_since: i64,
        current_until: i64,
        previous_since: i64,
        previous_until: i64,
        limit: u32,
    ) -> Result<Vec<BaselineProcess>> {
        let mut statement = self
            .conn
            .prepare(
                r#"
                WITH cur AS (
                    SELECT pid, COALESCE(SUM(bytes_ab + bytes_ba), 0) AS bytes
                    FROM connections
                    WHERE ts >= ?1 AND ts < ?2 AND pid IS NOT NULL
                    GROUP BY pid
                ),
                prev AS (
                    SELECT pid
                    FROM connections
                    WHERE ts >= ?3 AND ts < ?4 AND pid IS NOT NULL
                    GROUP BY pid
                )
                SELECT cur.pid, p.name, p.path, cur.bytes, 0
                FROM cur
                LEFT JOIN prev ON prev.pid = cur.pid
                LEFT JOIN processes p ON p.pid = cur.pid
                WHERE prev.pid IS NULL
                ORDER BY cur.bytes DESC
                LIMIT ?5
                "#,
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![
                    current_since,
                    current_until,
                    previous_since,
                    previous_until,
                    i64::from(limit)
                ],
                |row| {
                    Ok(BaselineProcess {
                        pid: row.get::<_, i64>(0)?.max(0) as u32,
                        name: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                        path: row.get(2)?,
                        current_bytes: row.get::<_, i64>(3)?.max(0) as u64,
                        previous_bytes: row.get::<_, i64>(4)?.max(0) as u64,
                    })
                },
            )
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    fn baseline_byte_spikes(
        &self,
        current_since: i64,
        current_until: i64,
        previous_since: i64,
        previous_until: i64,
        limit: u32,
    ) -> Result<Vec<BaselineProcess>> {
        let mut statement = self
            .conn
            .prepare(
                r#"
                WITH cur AS (
                    SELECT pid, COALESCE(SUM(bytes_ab + bytes_ba), 0) AS bytes
                    FROM connections
                    WHERE ts >= ?1 AND ts < ?2 AND pid IS NOT NULL
                    GROUP BY pid
                ),
                prev AS (
                    SELECT pid, COALESCE(SUM(bytes_ab + bytes_ba), 0) AS bytes
                    FROM connections
                    WHERE ts >= ?3 AND ts < ?4 AND pid IS NOT NULL
                    GROUP BY pid
                )
                SELECT cur.pid, p.name, p.path, cur.bytes, COALESCE(prev.bytes, 0)
                FROM cur
                JOIN prev ON prev.pid = cur.pid
                LEFT JOIN processes p ON p.pid = cur.pid
                WHERE cur.bytes >= ?6
                  AND cur.bytes > COALESCE(prev.bytes, 0) * 2
                ORDER BY cur.bytes - COALESCE(prev.bytes, 0) DESC
                LIMIT ?5
                "#,
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![
                    current_since,
                    current_until,
                    previous_since,
                    previous_until,
                    i64::from(limit),
                    MIN_EGRESS_BYTES as i64
                ],
                |row| {
                    Ok(BaselineProcess {
                        pid: row.get::<_, i64>(0)?.max(0) as u32,
                        name: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                        path: row.get(2)?,
                        current_bytes: row.get::<_, i64>(3)?.max(0) as u64,
                        previous_bytes: row.get::<_, i64>(4)?.max(0) as u64,
                    })
                },
            )
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    #[allow(clippy::too_many_arguments)]
    fn baseline_new_values(
        &self,
        table: &'static str,
        column: &'static str,
        time_column: &'static str,
        current_since: i64,
        current_until: i64,
        previous_since: i64,
        previous_until: i64,
        limit: u32,
    ) -> Result<Vec<String>> {
        let sql = format!(
            "SELECT DISTINCT {column} FROM {table}
             WHERE {time_column} >= ?1 AND {time_column} < ?2
               AND {column} IS NOT NULL
               AND {column} NOT IN (
                   SELECT {column} FROM {table}
                   WHERE {time_column} >= ?3 AND {time_column} < ?4
                     AND {column} IS NOT NULL
               )
             ORDER BY {column}
             LIMIT ?5"
        );
        let mut statement = self.conn.prepare(&sql).map_err(db)?;
        let rows = statement
            .query_map(
                params![
                    current_since,
                    current_until,
                    previous_since,
                    previous_until,
                    i64::from(limit)
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    fn baseline_new_ports(
        &self,
        current_since: i64,
        current_until: i64,
        previous_since: i64,
        previous_until: i64,
        limit: u32,
    ) -> Result<Vec<BaselinePort>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT DISTINCT COALESCE(c.proto, 'unknown'), COALESCE(c.server_port, 0)
                 FROM connections c
                 WHERE c.ts >= ?1 AND c.ts < ?2
                   AND NOT EXISTS (
                       SELECT 1 FROM connections p
                       WHERE p.ts >= ?3 AND p.ts < ?4
                         AND COALESCE(p.proto, 'unknown')
                             = COALESCE(c.proto, 'unknown')
                         AND COALESCE(p.server_port, 0)
                             = COALESCE(c.server_port, 0)
                   )
                 ORDER BY COALESCE(c.server_port, 0), COALESCE(c.proto, 'unknown')
                 LIMIT ?5",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![
                    current_since,
                    current_until,
                    previous_since,
                    previous_until,
                    i64::from(limit)
                ],
                |row| {
                    let port: i64 = row.get(1)?;
                    Ok(BaselinePort {
                        proto: row.get(0)?,
                        port: u16::try_from(port.max(0)).unwrap_or(0),
                    })
                },
            )
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    fn baseline_new_domains(
        &self,
        current_since: i64,
        current_until: i64,
        previous_since: i64,
        previous_until: i64,
        limit: u32,
    ) -> Result<Vec<String>> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT DISTINCT d.registrable_domain
                 FROM connections c
                 JOIN endpoint_domains ed ON ed.ip = c.server_ip
                 JOIN domains d ON d.domain = ed.domain
                 WHERE c.ts >= ?1 AND c.ts < ?2
                   AND d.registrable_domain NOT IN (
                       SELECT d2.registrable_domain
                       FROM connections c2
                       JOIN endpoint_domains ed2 ON ed2.ip = c2.server_ip
                       JOIN domains d2 ON d2.domain = ed2.domain
                       WHERE c2.ts >= ?3 AND c2.ts < ?4
                   )
                 ORDER BY d.registrable_domain
                 LIMIT ?5",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![
                    current_since,
                    current_until,
                    previous_since,
                    previous_until,
                    i64::from(limit)
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    fn baseline_alert_spikes(
        &self,
        current_since: i64,
        current_until: i64,
        previous_since: i64,
        previous_until: i64,
        limit: u32,
    ) -> Result<Vec<BaselineAlert>> {
        let mut statement = self
            .conn
            .prepare(
                r#"
                WITH cur AS (
                    SELECT gid, sid, COUNT(*) AS count, MAX(msg) AS msg
                    FROM alerts
                    WHERE event_ts >= ?1 AND event_ts < ?2
                    GROUP BY gid, sid
                ),
                prev AS (
                    SELECT gid, sid, COUNT(*) AS count
                    FROM alerts
                    WHERE event_ts >= ?3 AND event_ts < ?4
                    GROUP BY gid, sid
                )
                SELECT cur.gid, cur.sid, cur.msg, cur.count, COALESCE(prev.count, 0)
                FROM cur
                JOIN prev ON prev.gid = cur.gid AND prev.sid = cur.sid
                WHERE cur.count >= 5 AND cur.count > prev.count * 2
                ORDER BY cur.count - prev.count DESC
                LIMIT ?5
                "#,
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![
                    current_since,
                    current_until,
                    previous_since,
                    previous_until,
                    i64::from(limit)
                ],
                |row| {
                    Ok(BaselineAlert {
                        gid: row.get::<_, i64>(0)?.max(0) as u32,
                        sid: row.get::<_, i64>(1)?.max(0) as u32,
                        message: row.get(2)?,
                        current_count: row.get::<_, i64>(3)?.max(0) as u64,
                        previous_count: row.get::<_, i64>(4)?.max(0) as u64,
                    })
                },
            )
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    // Finding handlers are defined below.
}

fn normalize_query(query: &AnalysisQuery, now: i64) -> Result<NormalizedAnalysis> {
    let until = query.until.unwrap_or(now);
    let mut since = query.since.unwrap_or(until - DEFAULT_WINDOW_SECS);
    if since >= until {
        return Err(Error::Rpc(
            "analysis window is invalid: since must be earlier than until".into(),
        ));
    }
    let mut clamped = false;
    if until - since > MAX_WINDOW_SECS {
        since = until - MAX_WINDOW_SECS;
        clamped = true;
    }
    let duration_secs = until - since;
    let baseline = query.baseline.unwrap_or(false).then_some(BaselineWindow {
        since: since - duration_secs,
        until: since,
        duration_secs,
    });
    let min_severity = match query.min_severity.as_deref() {
        Some(value) => FindingSeverity::parse(value).ok_or_else(|| {
            Error::Rpc(format!(
                "invalid min_severity '{value}'; expected info, low, medium, high, or critical"
            ))
        })?,
        None => FindingSeverity::Info,
    };
    Ok(NormalizedAnalysis {
        window: AnalysisWindow {
            since,
            until,
            duration_secs,
            baseline: baseline.clone(),
            clamped,
        },
        limit: query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT),
        min_severity,
        include_noise: query.include_noise.unwrap_or(false),
        baseline: baseline.is_some(),
    })
}

fn trust_from_str(value: &str) -> TrustState {
    TrustState::parse(value).unwrap_or_default()
}

fn split_distinct(value: Option<String>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn distinct_sources(domains: &[pigui_core::models::EndpointDomain]) -> Vec<String> {
    let mut sources = BTreeMap::new();
    for domain in domains {
        sources.insert(domain.source.clone(), ());
    }
    sources.into_keys().collect()
}

fn flag_name(flag: ReviewFlag) -> String {
    match flag {
        ReviewFlag::NewDomain => "new_domain",
        ReviewFlag::NoDomain => "no_domain",
        ReviewFlag::InvalidTls => "invalid_tls",
        ReviewFlag::Alerts => "alerts",
        ReviewFlag::UnknownTrust => "unknown_trust",
    }
    .to_string()
}

fn noise_ip_category(ip: &str) -> Option<&'static str> {
    let Ok(address) = ip.parse::<IpAddr>() else {
        return None;
    };
    match address {
        IpAddr::V4(address) => {
            if address.is_multicast() {
                Some("multicast")
            } else if address.is_broadcast() {
                Some("broadcast")
            } else if address.is_loopback() {
                Some("loopback")
            } else if address.is_link_local() {
                Some("link_local")
            } else {
                None
            }
        }
        IpAddr::V6(address) => {
            if address.is_multicast() {
                Some("multicast")
            } else if address.is_loopback() {
                Some("loopback")
            } else if address.is_unicast_link_local() {
                Some("link_local")
            } else {
                None
            }
        }
    }
}

fn is_noise_ip(ip: &str) -> bool {
    noise_ip_category(ip).is_some()
}

impl Store {
    fn finding_high_priority_alerts(
        &self,
        window: &AnalysisWindow,
        include_noise: bool,
        limit: usize,
        findings: &mut Vec<AnalysisFinding>,
        seen: &mut HashSet<(String, String)>,
    ) -> Result<()> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT dst_ip, gid, sid, MAX(msg), MAX(class), COUNT(*),
                        MIN(event_ts), MAX(event_ts), MAX(priority)
                 FROM alerts
                 WHERE event_ts >= ?1 AND event_ts < ?2
                   AND priority IS NOT NULL AND priority <= 2
                   AND dst_ip IS NOT NULL
                 GROUP BY dst_ip, gid, sid
                 HAVING COUNT(*) >= 3
                 ORDER BY COUNT(*) DESC, MAX(priority) ASC
                 LIMIT ?3",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![window.since, window.until, (limit * 4) as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?.max(0) as u32,
                        row.get::<_, i64>(2)?.max(0) as u32,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?.max(0) as u64,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, Option<i64>>(8)?
                            .map(|value| value.max(0) as u32),
                    ))
                },
            )
            .map_err(db)?;
        for row in rows {
            let (ip, gid, sid, message, class, count, first_seen, last_seen, priority) =
                row.map_err(db)?;
            if (!include_noise && (gid == NOISY_GID && sid == NOISY_SID)) || is_noise_ip(&ip) {
                continue;
            }
            let destination = self.destination_ref(&ip)?;
            let finding = make_finding(
                "high_priority_alert",
                &format!("{ip}:{gid}:{sid}"),
                if count >= 20 {
                    FindingSeverity::Critical
                } else {
                    FindingSeverity::High
                },
                FindingConfidence::Medium,
                "High-priority alert cluster",
                format!(
                    "{} priority-{} alerts for {gid}:{sid} were observed toward {ip}",
                    count,
                    priority.unwrap_or(0)
                ),
                json!({
                    "dst_ip": ip,
                    "gid": gid,
                    "sid": sid,
                    "message": message,
                    "class": class,
                    "count": count,
                    "max_priority": priority,
                }),
                None,
                destination,
                None,
                Some(first_seen),
                Some(last_seen),
                vec![
                    "alerts".into(),
                    "destination_detail".into(),
                    "connections".into(),
                ],
            );
            push_finding(findings, seen, finding);
        }
        Ok(())
    }

    fn finding_unknown_trust_egress(
        &self,
        window: &AnalysisWindow,
        limit: usize,
        findings: &mut Vec<AnalysisFinding>,
        seen: &mut HashSet<(String, String)>,
    ) -> Result<()> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT d.registrable_domain,
                        COALESCE(t.state, default_domain_trust(d.registrable_domain), 'unknown'),
                        COALESCE(SUM(c.bytes_ab), 0),
                        COALESCE(SUM(c.bytes_ba), 0),
                        COUNT(DISTINCT c.id),
                        COUNT(DISTINCT c.pid),
                        MIN(c.ts), MAX(c.ts),
                        GROUP_CONCAT(DISTINCT ed.source),
                        GROUP_CONCAT(DISTINCT ed.domain)
                 FROM connections c
                 JOIN endpoint_domains ed ON ed.ip = c.server_ip
                 JOIN domains d ON d.domain = ed.domain
                 LEFT JOIN domain_trust t
                     ON t.registrable_domain = d.registrable_domain
                 WHERE c.ts >= ?1 AND c.ts < ?2
                 GROUP BY d.registrable_domain
                 HAVING SUM(c.bytes_ab) >= ?3
                 ORDER BY SUM(c.bytes_ab) DESC
                 LIMIT ?4",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![
                    window.since,
                    window.until,
                    MIN_EGRESS_BYTES as i64,
                    (limit * 4) as i64
                ],
                |row| {
                    let sources: Option<String> = row.get(8)?;
                    let hostnames: Option<String> = row.get(9)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?.max(0) as u64,
                        row.get::<_, i64>(3)?.max(0) as u64,
                        row.get::<_, i64>(4)?.max(0) as u64,
                        row.get::<_, i64>(5)?.max(0) as u64,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        split_distinct(sources),
                        split_distinct(hostnames),
                    ))
                },
            )
            .map_err(db)?;
        for row in rows {
            let (
                domain,
                trust,
                bytes_out,
                bytes_in,
                connection_count,
                process_count,
                first_seen,
                last_seen,
                sources,
                hostnames,
            ) = row.map_err(db)?;
            let trust_state = trust_from_str(&trust);
            if !matches!(trust_state, TrustState::Unknown | TrustState::Suspicious) {
                continue;
            }
            let weak_identity = !sources.is_empty()
                && sources
                    .iter()
                    .all(|source| matches!(source.as_str(), "ptr" | "watched" | "legacy"));
            let confidence = if weak_identity {
                FindingConfidence::Low
            } else if trust_state == TrustState::Suspicious {
                FindingConfidence::High
            } else {
                FindingConfidence::Medium
            };
            let finding = make_finding(
                "unknown_trust_egress",
                &domain,
                if trust_state == TrustState::Suspicious || bytes_out >= 10 * 1024 * 1024 {
                    FindingSeverity::High
                } else {
                    FindingSeverity::Medium
                },
                confidence,
                "Egress to an untrusted domain",
                format!(
                    "{bytes_out} bytes were sent to {domain} with {trust_state} trust across {connection_count} connections"
                ),
                json!({
                    "registrable_domain": domain,
                    "trust_state": trust,
                    "sources": sources,
                    "hostnames": hostnames,
                    "bytes_out": bytes_out,
                    "bytes_in": bytes_in,
                    "connection_count": connection_count,
                    "process_count": process_count,
                    "weak_identity": weak_identity,
                }),
                None,
                None,
                Some(domain_ref(&domain, trust_state, sources)),
                Some(first_seen),
                Some(last_seen),
                vec![
                    "domains".into(),
                    "connections".into(),
                    "dns".into(),
                    "tls".into(),
                ],
            );
            push_finding(findings, seen, finding);
        }
        Ok(())
    }

    fn finding_new_domain_egress(
        &self,
        window: &AnalysisWindow,
        limit: usize,
        findings: &mut Vec<AnalysisFinding>,
        seen: &mut HashSet<(String, String)>,
    ) -> Result<()> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT d.registrable_domain,
                        COALESCE(t.state, default_domain_trust(d.registrable_domain), 'unknown'),
                        MIN(d.first_seen), MAX(c.ts),
                        COALESCE(SUM(c.bytes_ab), 0),
                        COUNT(DISTINCT c.id),
                        COUNT(DISTINCT c.pid),
                        GROUP_CONCAT(DISTINCT ed.source),
                        GROUP_CONCAT(DISTINCT ed.domain)
                 FROM domains d
                 JOIN endpoint_domains ed ON ed.domain = d.domain
                 JOIN connections c ON c.server_ip = ed.ip
                 LEFT JOIN domain_trust t
                     ON t.registrable_domain = d.registrable_domain
                 WHERE c.ts >= ?1 AND c.ts < ?2
                   AND d.first_seen >= ?1 AND d.first_seen < ?2
                 GROUP BY d.registrable_domain
                 HAVING SUM(c.bytes_ab) >= ?3
                 ORDER BY MIN(d.first_seen) DESC
                 LIMIT ?4",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![
                    window.since,
                    window.until,
                    MIN_EGRESS_BYTES as i64,
                    (limit * 4) as i64
                ],
                |row| {
                    let sources: Option<String> = row.get(7)?;
                    let hostnames: Option<String> = row.get(8)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?.max(0) as u64,
                        row.get::<_, i64>(5)?.max(0) as u64,
                        row.get::<_, i64>(6)?.max(0) as u64,
                        split_distinct(sources),
                        split_distinct(hostnames),
                    ))
                },
            )
            .map_err(db)?;
        for row in rows {
            let (
                domain,
                trust,
                domain_first_seen,
                last_seen,
                bytes_out,
                connection_count,
                process_count,
                sources,
                hostnames,
            ) = row.map_err(db)?;
            let trust_state = trust_from_str(&trust);
            let finding = make_finding(
                "new_domain_egress",
                &domain,
                FindingSeverity::Medium,
                FindingConfidence::Medium,
                "New domain contacted",
                format!(
                    "{domain} was first observed in this window and received {bytes_out} bytes over {connection_count} connections"
                ),
                json!({
                    "registrable_domain": domain,
                    "trust_state": trust,
                    "sources": sources,
                    "hostnames": hostnames,
                    "bytes_out": bytes_out,
                    "connection_count": connection_count,
                    "process_count": process_count,
                }),
                None,
                None,
                Some(domain_ref(&domain, trust_state, sources)),
                Some(domain_first_seen),
                Some(last_seen),
                vec![
                    "domains".into(),
                    "connections".into(),
                    "dns".into(),
                    "tls".into(),
                ],
            );
            push_finding(findings, seen, finding);
        }
        Ok(())
    }

    fn finding_no_domain_egress(
        &self,
        window: &AnalysisWindow,
        limit: usize,
        findings: &mut Vec<AnalysisFinding>,
        seen: &mut HashSet<(String, String)>,
    ) -> Result<()> {
        self.finding_destination_without_identity(
            window,
            limit,
            false,
            "no_domain_egress",
            "Egress to a destination with no domain identity",
            findings,
            seen,
        )
    }

    fn finding_direct_ip_traffic(
        &self,
        window: &AnalysisWindow,
        limit: usize,
        findings: &mut Vec<AnalysisFinding>,
        seen: &mut HashSet<(String, String)>,
    ) -> Result<()> {
        self.finding_destination_without_identity(
            window,
            limit,
            true,
            "direct_ip_traffic",
            "Direct-IP traffic without a domain mapping",
            findings,
            seen,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finding_destination_without_identity(
        &self,
        window: &AnalysisWindow,
        limit: usize,
        non_dns_only: bool,
        category: &str,
        title: &str,
        findings: &mut Vec<AnalysisFinding>,
        seen: &mut HashSet<(String, String)>,
    ) -> Result<()> {
        let extra_filter = if non_dns_only {
            "AND COALESCE(c.service, '') NOT IN ('dns', 'domain')
             AND COALESCE(c.server_port, 0) <> 53"
        } else {
            ""
        };
        let sql = format!(
            "SELECT c.server_ip,
                    COUNT(DISTINCT c.id),
                    COUNT(DISTINCT c.pid),
                    COALESCE(SUM(c.bytes_ab), 0),
                    COALESCE(SUM(c.bytes_ba), 0),
                    MIN(c.ts), MAX(c.ts),
                    MAX(c.pid), MAX(c.process_name),
                    GROUP_CONCAT(DISTINCT CAST(c.server_port AS TEXT))
             FROM connections c
             WHERE c.ts >= ?1 AND c.ts < ?2 AND c.server_ip IS NOT NULL
               AND NOT EXISTS (
                   SELECT 1 FROM endpoint_domains ed WHERE ed.ip = c.server_ip
               )
               {extra_filter}
             GROUP BY c.server_ip
             HAVING SUM(c.bytes_ab) >= ?3
             ORDER BY SUM(c.bytes_ab) DESC
             LIMIT ?4"
        );
        let mut statement = self.conn.prepare(&sql).map_err(db)?;
        let rows = statement
            .query_map(
                params![
                    window.since,
                    window.until,
                    MIN_EGRESS_BYTES as i64,
                    (limit * 4) as i64
                ],
                |row| {
                    let ports: Option<String> = row.get(9)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?.max(0) as u64,
                        row.get::<_, i64>(2)?.max(0) as u64,
                        row.get::<_, i64>(3)?.max(0) as u64,
                        row.get::<_, i64>(4)?.max(0) as u64,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Option<i64>>(7)?
                            .map(|value| value.max(0) as u32),
                        row.get::<_, Option<String>>(8)?,
                        split_distinct(ports),
                    ))
                },
            )
            .map_err(db)?;
        for row in rows {
            let (
                ip,
                connection_count,
                process_count,
                bytes_out,
                bytes_in,
                first_seen,
                last_seen,
                pid,
                process_name,
                ports,
            ) = row.map_err(db)?;
            if is_noise_ip(&ip) {
                continue;
            }
            let process = match (pid, process_name) {
                (Some(pid), Some(name)) => Some(ProcessRef {
                    pid,
                    name,
                    path: None,
                    user: None,
                }),
                _ => None,
            };
            let destination = DestinationRef {
                ip: ip.clone(),
                hostname: None,
                trust_state: TrustState::Unknown,
                domains: Vec::new(),
            };
            let finding = make_finding(
                category,
                &ip,
                FindingSeverity::Medium,
                FindingConfidence::Medium,
                title,
                format!(
                    "{ip} received {bytes_out} bytes over {connection_count} connections without a trustworthy domain identity"
                ),
                json!({
                    "ip": ip,
                    "ports": ports,
                    "bytes_out": bytes_out,
                    "bytes_in": bytes_in,
                    "connection_count": connection_count,
                    "process_count": process_count,
                }),
                process,
                Some(destination),
                None,
                Some(first_seen),
                Some(last_seen),
                vec![
                    "destination_detail".into(),
                    "connections".into(),
                    "dns".into(),
                    "tls".into(),
                ],
            );
            push_finding(findings, seen, finding);
        }
        Ok(())
    }

    fn finding_rare_ports(
        &self,
        window: &AnalysisWindow,
        limit: usize,
        findings: &mut Vec<AnalysisFinding>,
        seen: &mut HashSet<(String, String)>,
    ) -> Result<()> {
        let common = common_ports();
        let mut statement = self
            .conn
            .prepare(
                "SELECT COALESCE(NULLIF(proto, ''), 'unknown'),
                        COALESCE(server_port, 0),
                        COUNT(*),
                        COALESCE(SUM(bytes_ab), 0),
                        COALESCE(SUM(bytes_ba), 0),
                        COUNT(DISTINCT server_ip),
                        MIN(ts), MAX(ts),
                        MAX(pid), MAX(process_name),
                        GROUP_CONCAT(DISTINCT server_ip)
                 FROM connections
                 WHERE ts >= ?1 AND ts < ?2 AND server_port IS NOT NULL
                 GROUP BY COALESCE(NULLIF(proto, ''), 'unknown'), COALESCE(server_port, 0)
                 HAVING COUNT(*) >= 3 AND SUM(bytes_ab) >= ?3
                 ORDER BY SUM(bytes_ab) DESC
                 LIMIT ?4",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![
                    window.since,
                    window.until,
                    MIN_RARE_PORT_BYTES as i64,
                    (limit * 4) as i64
                ],
                |row| {
                    let destinations: Option<String> = row.get(10)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?.max(0) as u16,
                        row.get::<_, i64>(2)?.max(0) as u64,
                        row.get::<_, i64>(3)?.max(0) as u64,
                        row.get::<_, i64>(4)?.max(0) as u64,
                        row.get::<_, i64>(5)?.max(0) as u64,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, Option<i64>>(8)?
                            .map(|value| value.max(0) as u32),
                        row.get::<_, Option<String>>(9)?,
                        split_distinct(destinations),
                    ))
                },
            )
            .map_err(db)?;
        for row in rows {
            let (
                proto,
                port,
                connection_count,
                bytes_out,
                bytes_in,
                destination_count,
                first_seen,
                last_seen,
                pid,
                process_name,
                destinations,
            ) = row.map_err(db)?;
            if port == 0 || common.contains(&port) {
                continue;
            }
            let process = match (pid, process_name) {
                (Some(pid), Some(name)) => Some(ProcessRef {
                    pid,
                    name,
                    path: None,
                    user: None,
                }),
                _ => None,
            };
            let finding = make_finding(
                "rare_port",
                &format!("{proto}:{port}"),
                FindingSeverity::Low,
                FindingConfidence::Low,
                "Traffic to an uncommon destination port",
                format!(
                    "{connection_count} connections used {proto}/{port}, sending {bytes_out} bytes to {destination_count} destinations"
                ),
                json!({
                    "proto": proto,
                    "port": port,
                    "bytes_out": bytes_out,
                    "bytes_in": bytes_in,
                    "connection_count": connection_count,
                    "destination_count": destination_count,
                    "destinations": destinations.into_iter().take(10).collect::<Vec<_>>(),
                }),
                process,
                None,
                None,
                Some(first_seen),
                Some(last_seen),
                vec![
                    "connections".into(),
                    "destination_detail".into(),
                    "process_detail".into(),
                ],
            );
            push_finding(findings, seen, finding);
        }
        Ok(())
    }

    fn finding_outbound_heavy(
        &self,
        window: &AnalysisWindow,
        limit: usize,
        findings: &mut Vec<AnalysisFinding>,
        seen: &mut HashSet<(String, String)>,
    ) -> Result<()> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT server_ip, COALESCE(server_port, 0), COALESCE(proto, 'unknown'),
                        COALESCE(client_ip, ''), pid, process_name, bytes_ab, bytes_ba, ts
                 FROM connections
                 WHERE ts >= ?1 AND ts < ?2
                   AND bytes_ab >= ?3
                   AND bytes_ab > bytes_ba * 5
                 ORDER BY bytes_ab DESC
                 LIMIT ?4",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![
                    window.since,
                    window.until,
                    MIN_EGRESS_BYTES as i64,
                    (limit * 4) as i64
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?.max(0) as u16,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<i64>>(4)?
                            .map(|value| value.max(0) as u32),
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, i64>(6)?.max(0) as u64,
                        row.get::<_, i64>(7)?.max(0) as u64,
                        row.get::<_, i64>(8)?,
                    ))
                },
            )
            .map_err(db)?;
        for row in rows {
            let (ip, port, proto, client_ip, pid, process_name, bytes_out, bytes_in, ts) =
                row.map_err(db)?;
            if is_noise_ip(&ip) {
                continue;
            }
            let process = match (pid, process_name) {
                (Some(pid), Some(name)) => Some(ProcessRef {
                    pid,
                    name,
                    path: None,
                    user: None,
                }),
                _ => None,
            };
            let destination = self.destination_ref(&ip)?;
            let finding = make_finding(
                "outbound_heavy",
                &format!("{ip}:{port}"),
                FindingSeverity::Medium,
                FindingConfidence::Medium,
                "Outbound-heavy transfer",
                format!(
                    "{client_ip} sent {bytes_out} bytes to {ip}:{port}/{proto}, more than five times the return traffic"
                ),
                json!({
                    "server_ip": ip,
                    "server_port": port,
                    "proto": proto,
                    "client_ip": client_ip,
                    "bytes_out": bytes_out,
                    "bytes_in": bytes_in,
                }),
                process,
                destination,
                None,
                Some(ts),
                Some(ts),
                vec![
                    "connections".into(),
                    "destination_detail".into(),
                    "process_detail".into(),
                ],
            );
            push_finding(findings, seen, finding);
        }
        Ok(())
    }

    fn finding_beaconing(
        &self,
        window: &AnalysisWindow,
        limit: usize,
        findings: &mut Vec<AnalysisFinding>,
        seen: &mut HashSet<(String, String)>,
    ) -> Result<()> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT COALESCE(client_ip, ''), server_ip, COALESCE(server_port, 0),
                        COALESCE(proto, 'unknown'), pid, MAX(process_name),
                        COUNT(*), MIN(ts), MAX(ts), GROUP_CONCAT(ts)
                 FROM connections
                 WHERE ts >= ?1 AND ts < ?2 AND server_ip IS NOT NULL
                 GROUP BY COALESCE(client_ip, ''), server_ip,
                          COALESCE(server_port, 0), COALESCE(proto, 'unknown'), pid
                 HAVING COUNT(*) >= 5
                 ORDER BY COUNT(*) DESC
                 LIMIT ?3",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![window.since, window.until, (limit * 4) as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?.max(0) as u16,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<i64>>(4)?
                            .map(|value| value.max(0) as u32),
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, i64>(6)?.max(0) as u64,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, Option<String>>(9)?,
                    ))
                },
            )
            .map_err(db)?;
        for row in rows {
            let (
                client_ip,
                server_ip,
                server_port,
                proto,
                pid,
                process_name,
                count,
                first_seen,
                last_seen,
                timestamps,
            ) = row.map_err(db)?;
            if is_noise_ip(&server_ip) {
                continue;
            }
            let mut times = split_distinct(timestamps)
                .into_iter()
                .filter_map(|value| value.parse::<i64>().ok())
                .collect::<Vec<_>>();
            times.sort_unstable();
            let Some((mean, cv)) = interval_stats(&times) else {
                continue;
            };
            if mean <= 0.0 || cv >= 0.25 {
                continue;
            }
            let process = match (pid, process_name) {
                (Some(pid), Some(name)) => Some(ProcessRef {
                    pid,
                    name,
                    path: None,
                    user: None,
                }),
                _ => None,
            };
            let destination = self.destination_ref(&server_ip)?;
            let finding = make_finding(
                "beaconing",
                &format!("{client_ip}:{server_ip}:{server_port}:{proto}"),
                FindingSeverity::Medium,
                FindingConfidence::Medium,
                "Possible beaconing pattern",
                format!(
                    "{count} connections to {server_ip}:{server_port}/{proto} had a mean interval of {mean:.1}s and coefficient of variation {cv:.2}"
                ),
                json!({
                    "client_ip": client_ip,
                    "server_ip": server_ip,
                    "server_port": server_port,
                    "proto": proto,
                    "connection_count": count,
                    "mean_interval_secs": mean,
                    "coefficient_of_variation": cv,
                }),
                process,
                destination,
                None,
                Some(first_seen),
                Some(last_seen),
                vec![
                    "connections".into(),
                    "destination_detail".into(),
                    "process_detail".into(),
                ],
            );
            push_finding(findings, seen, finding);
        }
        Ok(())
    }

    fn finding_fan_out(
        &self,
        window: &AnalysisWindow,
        limit: usize,
        findings: &mut Vec<AnalysisFinding>,
        seen: &mut HashSet<(String, String)>,
    ) -> Result<()> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT c.pid, MAX(p.name), MAX(p.path), MAX(p.user),
                        COUNT(DISTINCT c.server_ip),
                        COUNT(DISTINCT CASE WHEN ed.ip IS NULL OR e.first_seen >= ?1
                                            THEN c.server_ip END),
                        MIN(c.ts), MAX(c.ts)
                 FROM connections c
                 LEFT JOIN endpoint_domains ed ON ed.ip = c.server_ip
                 LEFT JOIN endpoints e ON e.ip = c.server_ip
                 LEFT JOIN processes p ON p.pid = c.pid
                 WHERE c.ts >= ?1 AND c.ts < ?2 AND c.pid IS NOT NULL
                 GROUP BY c.pid
                 HAVING COUNT(DISTINCT CASE WHEN ed.ip IS NULL OR e.first_seen >= ?1
                                             THEN c.server_ip END) >= 10
                 ORDER BY COUNT(DISTINCT c.server_ip) DESC
                 LIMIT ?3",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![window.since, window.until, (limit * 4) as i64],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?.max(0) as u32,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, i64>(4)?.max(0) as u64,
                        row.get::<_, i64>(5)?.max(0) as u64,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .map_err(db)?;
        for row in rows {
            let (pid, name, path, user, destinations, risky_destinations, first_seen, last_seen) =
                row.map_err(db)?;
            let process = ProcessRef {
                pid,
                name: name.unwrap_or_else(|| format!("pid {pid}")),
                path,
                user,
            };
            let finding = make_finding(
                "fan_out",
                &pid.to_string(),
                FindingSeverity::Medium,
                FindingConfidence::Medium,
                "Process contacting many new or unknown destinations",
                format!(
                    "PID {pid} contacted {destinations} destinations, including {risky_destinations} with no domain identity or first seen in this window"
                ),
                json!({
                    "pid": pid,
                    "destinations": destinations,
                    "new_or_unknown_destinations": risky_destinations,
                }),
                Some(process),
                None,
                None,
                Some(first_seen),
                Some(last_seen),
                vec![
                    "process_detail".into(),
                    "connections".into(),
                    "destinations".into(),
                ],
            );
            push_finding(findings, seen, finding);
        }
        Ok(())
    }

    fn finding_dns_tunneling(
        &self,
        window: &AnalysisWindow,
        limit: usize,
        findings: &mut Vec<AnalysisFinding>,
        seen: &mut HashSet<(String, String)>,
    ) -> Result<()> {
        let mut statement = self
            .conn
            .prepare(
                r#"
                WITH observations AS (
                    SELECT o.*, registrable_host(o.query) AS rd
                    FROM dns_observations o
                    WHERE o.ts >= ?1 AND o.ts < ?2 AND o.query IS NOT NULL
                )
                SELECT obs.rd,
                       COALESCE(t.state, default_domain_trust(obs.rd), 'unknown'),
                       COUNT(*),
                       COUNT(DISTINCT obs.query),
                       SUM(CASE WHEN lower(COALESCE(obs.qtype, '')) = 'txt' THEN 1 ELSE 0 END),
                       SUM(CASE WHEN upper(COALESCE(obs.rcode, '')) IN ('NXDOMAIN', '3')
                                THEN 1 ELSE 0 END),
                       MAX(length(obs.query)),
                       MIN(obs.ts), MAX(obs.ts),
                       GROUP_CONCAT(DISTINCT obs.query)
                FROM observations obs
                LEFT JOIN domain_trust t ON t.registrable_domain = obs.rd
                WHERE obs.rd IS NOT NULL
                GROUP BY obs.rd
                HAVING COUNT(*) >= 5
                ORDER BY COUNT(DISTINCT obs.query) DESC, COUNT(*) DESC
                LIMIT ?3
                "#,
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![window.since, window.until, (limit * 4) as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?.max(0) as u64,
                        row.get::<_, i64>(3)?.max(0) as u64,
                        row.get::<_, i64>(4)?.max(0) as u64,
                        row.get::<_, i64>(5)?.max(0) as u64,
                        row.get::<_, i64>(6)?.max(0) as u64,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, Option<String>>(9)?,
                    ))
                },
            )
            .map_err(db)?;
        for row in rows {
            let (
                domain,
                trust,
                observation_count,
                unique_queries,
                txt_count,
                nxdomain_count,
                max_query_len,
                first_seen,
                last_seen,
                queries,
            ) = row.map_err(db)?;
            let queries = split_distinct(queries);
            let max_label_len = queries
                .iter()
                .flat_map(|query| query.split('.'))
                .map(str::len)
                .max()
                .unwrap_or(0) as u64;
            let entropy = queries
                .iter()
                .map(|query| label_entropy(query, &domain))
                .sum::<f64>()
                / queries.len().max(1) as f64;
            let suspicious = max_label_len >= 40
                || unique_queries >= 50
                || txt_count >= 5
                || nxdomain_count >= 20
                || (entropy >= 3.8 && unique_queries >= 20);
            if !suspicious {
                continue;
            }
            let trust_state = trust_from_str(&trust);
            let finding = make_finding(
                "dns_tunneling",
                &domain,
                FindingSeverity::High,
                FindingConfidence::Low,
                "Possible DNS tunneling indicators",
                format!(
                    "{domain} had {unique_queries} unique queries, max label length {max_label_len}, {txt_count} TXT queries, and {nxdomain_count} NXDOMAIN responses"
                ),
                json!({
                    "registrable_domain": domain,
                    "observation_count": observation_count,
                    "unique_queries": unique_queries,
                    "max_query_length": max_query_len,
                    "max_label_length": max_label_len,
                    "mean_label_entropy": entropy,
                    "txt_count": txt_count,
                    "nxdomain_count": nxdomain_count,
                    "sample_queries": queries.into_iter().take(10).collect::<Vec<_>>(),
                }),
                None,
                None,
                Some(domain_ref(&domain, trust_state, vec!["dns".into()])),
                Some(first_seen),
                Some(last_seen),
                vec!["dns".into(), "domains".into(), "connections".into()],
            );
            push_finding(findings, seen, finding);
        }
        Ok(())
    }

    fn finding_invalid_tls(
        &self,
        window: &AnalysisWindow,
        limit: usize,
        findings: &mut Vec<AnalysisFinding>,
        seen: &mut HashSet<(String, String)>,
    ) -> Result<()> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT COALESCE(server_ip, ''), server_name, version, validation_status,
                        COUNT(*), MIN(ts), MAX(ts)
                 FROM tls_observations
                 WHERE ts >= ?1 AND ts < ?2
                   AND (validation_status IS NOT NULL OR version IS NOT NULL)
                 GROUP BY COALESCE(server_ip, ''), server_name, version, validation_status
                 HAVING COUNT(*) >= 1
                 ORDER BY COUNT(*) DESC
                 LIMIT ?3",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![window.since, window.until, (limit * 4) as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, i64>(4)?.max(0) as u64,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .map_err(db)?;
        for row in rows {
            let (server_ip, server_name, version, validation, count, first_seen, last_seen) =
                row.map_err(db)?;
            let invalid_validation = validation
                .as_deref()
                .map(|value| {
                    !matches!(
                        value.trim().to_ascii_lowercase().as_str(),
                        "valid" | "ok" | "success" | "trusted"
                    )
                })
                .unwrap_or(false);
            let old_version = version
                .as_deref()
                .map(|value| {
                    matches!(
                        value.trim().to_ascii_lowercase().as_str(),
                        "sslv2" | "sslv3" | "ssl3" | "tlsv1" | "tlsv1.0" | "tlsv1.1"
                    )
                })
                .unwrap_or(false);
            if !invalid_validation && !old_version {
                continue;
            }
            if !server_ip.is_empty() && is_noise_ip(&server_ip) {
                continue;
            }
            let destination = if server_ip.is_empty() {
                None
            } else {
                self.destination_ref(&server_ip).ok().flatten()
            };
            let domain = server_name.as_deref().map(|name| {
                let registrable = pigui_core::domain::registrable_domain(name);
                let trust_state = if server_ip.is_empty() {
                    TrustState::Unknown
                } else {
                    self.endpoint_domains(&server_ip)
                        .ok()
                        .map(|domains| super::aggregate_trust(&domains))
                        .unwrap_or_default()
                };
                domain_ref(&registrable, trust_state, vec!["tls".into()])
            });
            let finding = make_finding(
                "invalid_tls",
                &format!("{server_ip}:{}", server_name.as_deref().unwrap_or_default()),
                FindingSeverity::Medium,
                if old_version {
                    FindingConfidence::Medium
                } else {
                    FindingConfidence::High
                },
                "Invalid or weak TLS metadata",
                format!(
                    "TLS to {} used version {} with validation status {} across {count} observations",
                    server_name.as_deref().unwrap_or(&server_ip),
                    version.as_deref().unwrap_or("unknown"),
                    validation.as_deref().unwrap_or("unknown")
                ),
                json!({
                    "server_ip": server_ip,
                    "server_name": server_name,
                    "version": version,
                    "validation_status": validation,
                    "observation_count": count,
                }),
                None,
                destination,
                domain,
                Some(first_seen),
                Some(last_seen),
                vec!["tls".into(), "destination_detail".into(), "domains".into()],
            );
            push_finding(findings, seen, finding);
        }
        Ok(())
    }

    fn finding_path_anomaly(
        &self,
        window: &AnalysisWindow,
        limit: usize,
        findings: &mut Vec<AnalysisFinding>,
        seen: &mut HashSet<(String, String)>,
    ) -> Result<()> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT p.pid, p.name, p.path, p.user,
                        (SELECT MAX(last_seen) FROM flows
                         WHERE pid = p.pid AND last_seen >= ?1),
                        (SELECT MAX(ts) FROM connections
                         WHERE pid = p.pid AND ts >= ?1 AND ts < ?2),
                        COALESCE((SELECT SUM(bytes_ab) FROM connections
                                  WHERE pid = p.pid AND ts >= ?1 AND ts < ?2), 0)
                 FROM processes p
                 WHERE p.path IS NOT NULL AND p.last_seen >= ?1
                 ORDER BY COALESCE((SELECT SUM(bytes_ab) FROM connections
                                    WHERE pid = p.pid AND ts >= ?1 AND ts < ?2), 0) DESC
                 LIMIT ?3",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![window.since, window.until, (limit * 4) as i64],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?.max(0) as u32,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, i64>(6)?.max(0) as u64,
                    ))
                },
            )
            .map_err(db)?;
        for row in rows {
            let (pid, name, path, user, live_last, conn_last, bytes_out) = row.map_err(db)?;
            if !suspicious_path(&path) {
                continue;
            }
            let last_seen = live_last.or(conn_last);
            let process = ProcessRef {
                pid,
                name,
                path: Some(path.clone()),
                user,
            };
            let finding = make_finding(
                "path_anomaly",
                &pid.to_string(),
                FindingSeverity::High,
                FindingConfidence::Medium,
                "Network-active process from an unusual path",
                format!(
                    "PID {pid} is running from {path} and sent {bytes_out} bytes in this window"
                ),
                json!({
                    "pid": pid,
                    "path": path,
                    "bytes_out": bytes_out,
                }),
                Some(process),
                None,
                None,
                last_seen,
                last_seen,
                vec![
                    "process_detail".into(),
                    "connections".into(),
                    "destinations".into(),
                ],
            );
            push_finding(findings, seen, finding);
        }
        Ok(())
    }

    fn finding_user_anomaly(
        &self,
        window: &AnalysisWindow,
        limit: usize,
        findings: &mut Vec<AnalysisFinding>,
        seen: &mut HashSet<(String, String)>,
    ) -> Result<()> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT p.pid, p.name, p.path, p.user,
                        COALESCE((SELECT SUM(bytes_ab) FROM connections
                                  WHERE pid = p.pid AND ts >= ?1 AND ts < ?2), 0),
                        (SELECT MAX(last_seen) FROM flows
                         WHERE pid = p.pid AND last_seen >= ?1)
                 FROM processes p
                 WHERE p.user IS NOT NULL AND p.last_seen >= ?1
                 ORDER BY COALESCE((SELECT SUM(bytes_ab) FROM connections
                                    WHERE pid = p.pid AND ts >= ?1 AND ts < ?2), 0) DESC
                 LIMIT ?3",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![window.since, window.until, (limit * 4) as i64],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?.max(0) as u32,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?.max(0) as u64,
                        row.get::<_, Option<i64>>(5)?,
                    ))
                },
            )
            .map_err(db)?;
        for row in rows {
            let (pid, name, path, user, bytes_out, live_last) = row.map_err(db)?;
            if !unusual_user(&user) {
                continue;
            }
            let process = ProcessRef {
                pid,
                name,
                path,
                user: Some(user.clone()),
            };
            let finding = make_finding(
                "user_anomaly",
                &pid.to_string(),
                FindingSeverity::Medium,
                FindingConfidence::Low,
                "Network-active process with an unusual user context",
                format!(
                    "PID {pid} is running as {user} with outbound activity; expected user context needs operator review"
                ),
                json!({
                    "pid": pid,
                    "user": user,
                    "bytes_out": bytes_out,
                }),
                Some(process),
                None,
                None,
                live_last,
                live_last,
                vec!["process_detail".into(), "connections".into()],
            );
            push_finding(findings, seen, finding);
        }
        Ok(())
    }

    fn finding_new_process_egress(
        &self,
        window: &AnalysisWindow,
        limit: usize,
        findings: &mut Vec<AnalysisFinding>,
        seen: &mut HashSet<(String, String)>,
    ) -> Result<()> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT p.pid, p.name, p.path, p.user, p.first_seen, p.last_seen,
                        COALESCE((SELECT SUM(bytes_ab) FROM connections
                                  WHERE pid = p.pid AND ts >= ?1 AND ts < ?2), 0),
                        COALESCE((SELECT COUNT(*) FROM connections
                                  WHERE pid = p.pid AND ts >= ?1 AND ts < ?2), 0),
                        COALESCE((SELECT SUM(bytes_ab) FROM flows
                                  WHERE pid = p.pid AND last_seen >= ?1), 0)
                 FROM processes p
                 WHERE p.first_seen >= ?1 AND p.first_seen < ?2
                 ORDER BY p.first_seen DESC
                 LIMIT ?3",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(
                params![window.since, window.until, (limit * 4) as i64],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?.max(0) as u32,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?.max(0) as u64,
                        row.get::<_, i64>(7)?.max(0) as u64,
                        row.get::<_, i64>(8)?.max(0) as u64,
                    ))
                },
            )
            .map_err(db)?;
        for row in rows {
            let (pid, name, path, user, first_seen, last_seen, bytes_out, connections, live_out) =
                row.map_err(db)?;
            if bytes_out == 0 && connections == 0 && live_out == 0 {
                continue;
            }
            let process = ProcessRef {
                pid,
                name,
                path,
                user,
            };
            let finding = make_finding(
                "new_process_egress",
                &pid.to_string(),
                FindingSeverity::Medium,
                FindingConfidence::Medium,
                "New process with outbound traffic",
                format!(
                    "PID {pid} was first seen in this window and has outbound traffic ({bytes_out} bytes over {connections} connections)"
                ),
                json!({
                    "pid": pid,
                    "bytes_out": bytes_out,
                    "connection_count": connections,
                    "live_bytes_out": live_out,
                }),
                Some(process),
                None,
                None,
                Some(first_seen),
                Some(last_seen),
                vec![
                    "process_detail".into(),
                    "connections".into(),
                    "destinations".into(),
                ],
            );
            push_finding(findings, seen, finding);
        }
        Ok(())
    }

    fn destination_ref(&self, ip: &str) -> Result<Option<DestinationRef>> {
        let domains = self.endpoint_domains(ip)?;
        if domains.is_empty() {
            return Ok(Some(DestinationRef {
                ip: ip.to_string(),
                hostname: None,
                trust_state: TrustState::Unknown,
                domains: Vec::new(),
            }));
        }
        Ok(Some(DestinationRef {
            ip: ip.to_string(),
            hostname: domains.first().map(|domain| domain.domain.clone()),
            trust_state: super::aggregate_trust(&domains),
            domains: domains
                .iter()
                .map(|domain| domain.domain.clone())
                .take(10)
                .collect(),
        }))
    }
}

#[allow(clippy::too_many_arguments)]
fn make_finding(
    category: &str,
    subject: &str,
    severity: FindingSeverity,
    confidence: FindingConfidence,
    title: &str,
    summary: String,
    evidence: serde_json::Value,
    process: Option<ProcessRef>,
    destination: Option<DestinationRef>,
    domain: Option<DomainRef>,
    first_seen: Option<i64>,
    last_seen: Option<i64>,
    suggested_tools: Vec<String>,
) -> AnalysisFinding {
    AnalysisFinding {
        id: format!("{category}:{subject}"),
        category: category.to_string(),
        severity,
        confidence,
        title: title.to_string(),
        summary,
        evidence,
        process,
        destination,
        domain,
        first_seen,
        last_seen,
        suggested_tools,
    }
}

fn push_finding(
    findings: &mut Vec<AnalysisFinding>,
    seen: &mut HashSet<(String, String)>,
    finding: AnalysisFinding,
) {
    if seen.insert((finding.category.clone(), finding.id.clone())) {
        findings.push(finding);
    }
}

fn domain_ref(domain: &str, trust_state: TrustState, sources: Vec<String>) -> DomainRef {
    DomainRef {
        domain: domain.to_string(),
        trust_state,
        sources,
    }
}

fn interval_stats(times: &[i64]) -> Option<(f64, f64)> {
    if times.len() < 5 {
        return None;
    }
    let intervals = times
        .windows(2)
        .filter_map(|pair| (pair[1] > pair[0]).then_some((pair[1] - pair[0]) as f64))
        .collect::<Vec<_>>();
    if intervals.len() < 4 {
        return None;
    }
    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean <= 0.0 {
        return None;
    }
    let variance = intervals
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / intervals.len() as f64;
    Some((mean, variance.sqrt() / mean))
}

fn label_entropy(query: &str, registrable_domain: &str) -> f64 {
    let suffix_len = registrable_domain.split('.').count();
    let labels = query.split('.').collect::<Vec<_>>();
    if labels.len() <= suffix_len {
        return 0.0;
    }
    let prefix = &labels[..labels.len() - suffix_len];
    let text = prefix.join("");
    if text.is_empty() {
        return 0.0;
    }
    let mut counts = BTreeMap::new();
    for character in text.chars() {
        *counts.entry(character).or_insert(0usize) += 1;
    }
    let len = text.chars().count() as f64;
    -counts
        .values()
        .map(|count| {
            let probability = *count as f64 / len;
            probability * probability.log2()
        })
        .sum::<f64>()
}

fn common_ports() -> HashSet<u16> {
    [
        20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 143, 161, 162, 389, 443, 465, 587, 636, 853,
        993, 995, 3389, 8080, 8443,
    ]
    .into_iter()
    .collect()
}

fn suspicious_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower.starts_with("/tmp/")
        || lower.starts_with("/private/tmp/")
        || lower.starts_with("/users/shared/")
        || lower.contains("/downloads/")
    {
        return true;
    }
    lower
        .split('/')
        .any(|component| component.starts_with('.') && component.len() > 1)
}

fn unusual_user(user: &str) -> bool {
    let lower = user.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "root" | "daemon" | "nobody" | "_windowserver" | "_mdnsresponder"
    ) || lower.starts_with('_')
}

#[cfg(test)]
mod tests {
    use pigui_core::models::Alert;
    use pigui_core::models::ExtractorRecord;

    use super::*;

    fn alert(ts: i64, sid: u32, dst: &str) -> (Alert, String) {
        (
            Alert {
                event_ts: ts,
                ts_text: None,
                gid: 1,
                sid,
                rev: 1,
                priority: Some(1),
                class: Some("test".into()),
                msg: Some("test alert".into()),
                proto: Some("TCP".into()),
                src_ip: Some("10.0.0.5".into()),
                src_port: Some(50000),
                dst_ip: Some(dst.into()),
                dst_port: Some(443),
                action: Some("allowed".into()),
                app_id: None,
                service: None,
                rule: None,
                direction: None,
                pkt_num: None,
            },
            "{}".into(),
        )
    }

    fn extractor(line: &str) -> ExtractorRecord {
        ExtractorRecord::parse(line).unwrap()
    }

    #[test]
    fn overview_respects_window_and_reports_noise() {
        let mut store = Store::open_in_memory().unwrap();
        let mut noisy = alert(1_001, 444, "224.0.0.22");
        noisy.0.gid = 116;
        store
            .insert_alerts(&[
                alert(1_000, 1, "224.0.0.1"),
                noisy,
                alert(1_002, 2, "198.51.100.10"),
                alert(10, 3, "198.51.100.11"),
            ])
            .unwrap();

        let query = AnalysisQuery {
            since: Some(900),
            until: Some(2_000),
            limit: Some(10),
            ..Default::default()
        };
        let overview = store
            .analysis_overview(&query, AnalysisCoverage::default())
            .unwrap();

        assert_eq!(overview.totals.alerts, 3);
        assert_eq!(overview.noise.multicast_alerts, 2);
        assert_eq!(overview.noise.noisy_sid_alerts, 1);
        assert_eq!(overview.top_destinations.len(), 1);
        assert_eq!(overview.window.duration_secs, 1_100);
    }

    #[test]
    fn findings_detect_unknown_domain_and_beaconing() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .insert_extractor_records(
                &[extractor(
                    r#"{"ts":1000,"id.orig_h":"10.0.0.5","id.resp_h":"198.51.100.10","id.resp_p":443,"server_name":"unlisted-pigui-test.example","version":"TLSv1.3","validation_status":"valid"}"#,
                )],
                1000,
            )
            .unwrap();

        let mut records = Vec::new();
        for offset in 0..6 {
            let ts = 1000 + offset * 60;
            records.push(extractor(&format!(
                r#"{{"ts":{ts},"uid":"C{offset}","id.orig_h":"10.0.0.5","id.orig_p":5000{offset},"id.resp_h":"198.51.100.10","id.resp_p":443,"proto":"tcp","service":"ssl","conn_state":"SF","orig_bytes":20000,"resp_bytes":1000}}"#
            )));
        }
        store.insert_extractor_records(&records, 1400).unwrap();

        let query = AnalysisQuery {
            since: Some(900),
            until: Some(2_000),
            limit: Some(50),
            ..Default::default()
        };
        let result = store.analysis_findings(&query, Vec::new()).unwrap();
        let categories = result
            .findings
            .iter()
            .map(|finding| finding.category.as_str())
            .collect::<Vec<_>>();

        assert!(
            categories.contains(&"unknown_trust_egress"),
            "{categories:?}"
        );
        assert!(categories.contains(&"new_domain_egress"), "{categories:?}");
        assert!(categories.contains(&"beaconing"), "{categories:?}");
        assert!(
            result
                .findings
                .iter()
                .all(|finding| !finding.summary.is_empty() && !finding.evidence.is_null())
        );
    }

    #[test]
    fn clamps_oversized_window_and_limit() {
        let store = Store::open_in_memory().unwrap();
        let query = AnalysisQuery {
            since: Some(0),
            until: Some(MAX_WINDOW_SECS + 10),
            limit: Some(10_000),
            ..Default::default()
        };
        let overview = store
            .analysis_overview(&query, AnalysisCoverage::default())
            .unwrap();
        assert!(overview.window.clamped);
        assert_eq!(overview.window.duration_secs, MAX_WINDOW_SECS);
    }

    #[test]
    fn overview_baseline_reports_new_destinations() {
        let mut store = Store::open_in_memory().unwrap();
        store
            .insert_extractor_records(
                &[
                    extractor(
                        r#"{"ts":1000,"uid":"OLD","id.orig_h":"10.0.0.5","id.orig_p":50000,"id.resp_h":"198.51.100.10","id.resp_p":443,"proto":"tcp","service":"ssl","conn_state":"SF","orig_bytes":1000,"resp_bytes":2000}"#,
                    ),
                    extractor(
                        r#"{"ts":2000,"uid":"NEW","id.orig_h":"10.0.0.5","id.orig_p":50001,"id.resp_h":"198.51.100.20","id.resp_p":443,"proto":"tcp","service":"ssl","conn_state":"SF","orig_bytes":1000,"resp_bytes":2000}"#,
                    ),
                ],
                2000,
            )
            .unwrap();

        let query = AnalysisQuery {
            since: Some(1900),
            until: Some(3000),
            limit: Some(10),
            baseline: Some(true),
            ..Default::default()
        };
        let overview = store
            .analysis_overview(&query, AnalysisCoverage::default())
            .unwrap();
        let baseline = overview.baseline.unwrap();
        assert!(
            baseline
                .new_destinations
                .iter()
                .any(|destination| destination == "198.51.100.20")
        );
    }
}
