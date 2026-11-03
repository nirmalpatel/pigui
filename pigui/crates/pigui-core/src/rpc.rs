use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::models::{
    Alert, Connection, Destination, DnsObservation, DomainSummary, EndpointDomain, Flow,
    HttpObservation, Process, QuicObservation, ReviewFlag, SnortCapabilities, TlsObservation,
    TrustState, WatchedDomain,
};

pub const METHOD_STATUS: &str = "status";
pub const METHOD_HEALTH: &str = "health";
pub const METHOD_ALERTS_LIST: &str = "alerts.list";
pub const METHOD_DESTINATIONS_LIST: &str = "destinations.list";
pub const METHOD_FLOWS_LIST: &str = "flows.list";
pub const METHOD_PROCESSES_LIST: &str = "processes.list";
pub const METHOD_CONNECTIONS_LIST: &str = "connections.list";
pub const METHOD_DESTINATIONS_DETAIL: &str = "destinations.detail";
pub const METHOD_PROCESSES_DETAIL: &str = "processes.detail";
pub const METHOD_DOMAINS_LIST: &str = "domains.list";
pub const METHOD_DOMAINS_SET_TRUST: &str = "domains.set_trust";
pub const METHOD_WATCHED_LIST: &str = "watched.list";
pub const METHOD_WATCHED_ADD: &str = "watched.add";
pub const METHOD_WATCHED_REMOVE: &str = "watched.remove";
pub const METHOD_DNS_LIST: &str = "dns.list";
pub const METHOD_TLS_LIST: &str = "tls.list";
pub const METHOD_HTTP_LIST: &str = "http.list";
pub const METHOD_QUIC_LIST: &str = "quic.list";
pub const METHOD_SNORT_STATUS: &str = "snort.status";
pub const METHOD_SETTINGS_GET: &str = "settings.get";
pub const METHOD_SETTINGS_UPDATE: &str = "settings.update";
pub const METHOD_SETTINGS_RESET: &str = "settings.reset";
pub const METHOD_MAINTENANCE_STATS: &str = "maintenance.stats";
pub const METHOD_MAINTENANCE_PRUNE: &str = "maintenance.prune_now";
pub const METHOD_SHUTDOWN: &str = "shutdown";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

impl Request {
    pub fn new(method: impl Into<String>, params: Value) -> Self {
        Self {
            id: 1,
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    pub fn success(id: u64, data: Value) -> Self {
        Self {
            id,
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn failure(id: u64, error: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            data: None,
            error: Some(error.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    Asc,
    #[default]
    Desc,
}

impl SortDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub offset: Option<u32>,
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub sort: Option<String>,
    #[serde(default)]
    pub dir: Option<SortDirection>,
}

pub type AlertsQuery = ListQuery;
pub type DestinationsQuery = ListQuery;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TableCount {
    pub name: String,
    pub rows: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MaintenanceStats {
    pub db_path: String,
    pub db_bytes: u64,
    pub table_counts: Vec<TableCount>,
    pub last_run: Option<i64>,
    pub last_deleted: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PruneResult {
    pub ran_at: i64,
    pub deleted: Vec<TableCount>,
    pub total_deleted: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    pub id: i64,
    #[serde(flatten)]
    pub alert: Alert,
    pub ingested_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertList {
    pub alerts: Vec<AlertRecord>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationList {
    pub destinations: Vec<Destination>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowList {
    pub flows: Vec<Flow>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessList {
    pub processes: Vec<Process>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionList {
    pub connections: Vec<Connection>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationProcess {
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub snort_bytes_in: u64,
    pub snort_bytes_out: u64,
    pub live_bytes_in: u64,
    pub live_bytes_out: u64,
    pub snort_connection_count: u64,
    pub live_connection_count: u64,
    pub connection_count: u64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationDetail {
    pub destination: Destination,
    pub processes: Vec<DestinationProcess>,
    pub recent_alerts: Vec<AlertRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDestination {
    pub ip: String,
    pub domains: Vec<EndpointDomain>,
    pub trust_state: TrustState,
    pub flags: Vec<ReviewFlag>,
    pub snort_bytes_in: u64,
    pub snort_bytes_out: u64,
    pub live_bytes_in: u64,
    pub live_bytes_out: u64,
    pub snort_connection_count: u64,
    pub live_connection_count: u64,
    pub connection_count: u64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDetail {
    pub process: Process,
    pub destinations: Vec<ProcessDestination>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainList {
    pub domains: Vec<DomainSummary>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchedList {
    pub watched: Vec<WatchedDomain>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchedRequest {
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestinationQuery {
    pub ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessQuery {
    pub pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetTrustRequest {
    pub registrable_domain: String,
    pub state: TrustState,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsList {
    pub observations: Vec<DnsObservation>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsList {
    pub observations: Vec<TlsObservation>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpList {
    pub observations: Vec<HttpObservation>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicList {
    pub observations: Vec<QuicObservation>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnortStatusPayload {
    pub running: bool,
    pub pid: Option<u32>,
    pub interface: Option<String>,
    pub config_path: Option<String>,
    pub log_dir: String,
    pub extractor_json: String,
    pub control_socket: Option<String>,
    pub pidfile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusPayload {
    pub capabilities: SnortCapabilities,
    pub db_path: String,
    pub alert_json: String,
    pub socket_path: String,
    pub uptime_secs: u64,
    pub alerts_ingested: u64,
    pub parse_errors: u64,
    pub alert_count: u64,
    pub destination_count: u64,
    pub degraded: Vec<String>,
    #[serde(default)]
    pub environment: String,
    #[serde(default)]
    pub snort_running: bool,
    #[serde(default)]
    pub snort_pid: Option<u32>,
    #[serde(default)]
    pub snort_interface: Option<String>,
    #[serde(default)]
    pub active_flows: u64,
    #[serde(default)]
    pub active_processes: u64,
    #[serde(default)]
    pub extractor_ingested: u64,
    #[serde(default)]
    pub extractor_file: String,
    #[serde(default)]
    pub extractor_size: u64,
    #[serde(default)]
    pub extractor_modified: Option<i64>,
    #[serde(default)]
    pub extractor_last_ingest: Option<i64>,
    #[serde(default)]
    pub extractor_idle: bool,
    #[serde(default)]
    pub dns_count: u64,
    #[serde(default)]
    pub tls_count: u64,
    #[serde(default)]
    pub http_count: u64,
    #[serde(default)]
    pub quic_count: u64,
    #[serde(default)]
    pub domain_count: u64,
    #[serde(default)]
    pub collector_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthPayload {
    pub status: String,
    pub uptime_secs: u64,
    pub alerts_ingested: u64,
    pub parse_errors: u64,
}
