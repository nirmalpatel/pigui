use serde::{Deserialize, Serialize};

use super::TrustState;

/// Parameters for the read-only analysis RPC methods.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisQuery {
    #[serde(default)]
    pub since: Option<i64>,
    #[serde(default)]
    pub until: Option<i64>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub min_severity: Option<String>,
    #[serde(default)]
    pub include_noise: Option<bool>,
    #[serde(default)]
    pub baseline: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisWindow {
    pub since: i64,
    pub until: i64,
    pub duration_secs: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<BaselineWindow>,
    #[serde(default)]
    pub clamped: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineWindow {
    pub since: i64,
    pub until: i64,
    pub duration_secs: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaptureCoverage {
    pub running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RetentionWindow {
    pub flows_secs: i64,
    pub processes_secs: i64,
    pub alerts_days: u32,
    pub connections_days: u32,
    pub observations_days: u32,
    pub domains_days: u32,
    pub endpoints_days: u32,
    pub ptr_days: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisTableCount {
    pub name: String,
    pub rows: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisCoverage {
    pub environment: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<CaptureCoverage>,
    pub snort_running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snort_pid: Option<u32>,
    pub uptime_secs: u64,
    pub parse_errors: u64,
    pub extractor_idle: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector_error: Option<String>,
    pub table_counts: Vec<AnalysisTableCount>,
    pub retention: RetentionWindow,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisTotals {
    pub alerts: u64,
    pub endpoints: u64,
    pub connections: u64,
    pub flows: u64,
    pub processes: u64,
    pub dns: u64,
    pub tls: u64,
    pub http: u64,
    pub quic: u64,
    pub domains: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisProcessSummary {
    pub pid: u32,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub live_bytes_in: u64,
    pub live_bytes_out: u64,
    pub connection_count: u64,
    pub destinations: u64,
    pub unknown_destinations: u64,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisDestinationSummary {
    pub ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub trust_state: TrustState,
    pub flags: Vec<String>,
    pub domains: Vec<String>,
    pub sources: Vec<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub live_bytes_in: u64,
    pub live_bytes_out: u64,
    pub connection_count: u64,
    pub alert_count: u64,
    pub endpoint_bytes_in: u64,
    pub endpoint_bytes_out: u64,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisDomainSummary {
    pub registrable_domain: String,
    pub hostnames: Vec<String>,
    pub sources: Vec<String>,
    pub trust_state: TrustState,
    pub observation_count: u64,
    pub endpoint_count: u64,
    pub process_count: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertCount {
    pub key: String,
    pub count: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertSidCount {
    pub gid: u32,
    pub sid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    pub count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_priority: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertBreakdown {
    pub by_priority: Vec<AlertCount>,
    pub by_class: Vec<AlertCount>,
    pub by_sid: Vec<AlertSidCount>,
    pub by_action: Vec<AlertCount>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolPort {
    pub proto: String,
    pub port: u16,
    pub connection_count: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustBreakdown {
    pub trusted: u64,
    pub unknown: u64,
    pub suspicious: u64,
    pub ignored: u64,
    pub no_domain: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NoiseExample {
    pub category: String,
    pub value: String,
    pub count: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NoiseSummary {
    pub multicast_alerts: u64,
    pub broadcast_alerts: u64,
    pub loopback_alerts: u64,
    pub link_local_alerts: u64,
    pub noisy_sid_alerts: u64,
    pub excluded_total: u64,
    pub examples: Vec<NoiseExample>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineProcess {
    pub pid: u32,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub current_bytes: u64,
    pub previous_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselinePort {
    pub proto: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineAlert {
    pub gid: u32,
    pub sid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub current_count: u64,
    pub previous_count: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineComparison {
    pub new_processes: Vec<BaselineProcess>,
    pub new_destinations: Vec<String>,
    pub new_domains: Vec<String>,
    pub new_ports: Vec<BaselinePort>,
    pub byte_spikes: Vec<BaselineProcess>,
    pub alert_spikes: Vec<BaselineAlert>,
    pub new_sni: Vec<String>,
    pub new_dns_queries: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisOverview {
    pub generated_at: i64,
    pub window: AnalysisWindow,
    pub coverage: AnalysisCoverage,
    pub totals: AnalysisTotals,
    pub top_processes: Vec<AnalysisProcessSummary>,
    pub top_destinations: Vec<AnalysisDestinationSummary>,
    pub top_domains: Vec<AnalysisDomainSummary>,
    pub alert_breakdown: AlertBreakdown,
    pub protocol_ports: Vec<ProtocolPort>,
    pub trust_breakdown: TrustBreakdown,
    pub new_domains: Vec<AnalysisDomainSummary>,
    pub noise: NoiseSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<BaselineComparison>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Info,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

impl FindingSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" | "med" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" | "crit" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingConfidence {
    Low,
    #[default]
    Medium,
    High,
}

impl FindingConfidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessRef {
    pub pid: u32,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DestinationRef {
    pub ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub trust_state: TrustState,
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainRef {
    pub domain: String,
    pub trust_state: TrustState,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisFinding {
    pub id: String,
    pub category: String,
    pub severity: FindingSeverity,
    pub confidence: FindingConfidence,
    pub title: String,
    pub summary: String,
    pub evidence: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<DestinationRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<DomainRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<i64>,
    pub suggested_tools: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisFindings {
    pub generated_at: i64,
    pub window: AnalysisWindow,
    pub findings: Vec<AnalysisFinding>,
    pub suppressed_noise: NoiseSummary,
    pub limitations: Vec<String>,
}
