use serde::{Deserialize, Serialize};

/// Capability report for the selected Snort binary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnortCapabilities {
    pub binary: Option<String>,
    pub source: Option<String>,
    pub version: Option<String>,
    pub control_socket: bool,
    pub shell: bool,
    pub extractor: bool,
    pub alert_json: bool,
    pub config_valid: Option<bool>,
    pub config_path: Option<String>,
    #[serde(default)]
    pub daq_modules: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl SnortCapabilities {
    pub fn degraded_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if !self.control_socket {
            reasons.push("control socket unavailable; using signal/file mode".to_string());
        }
        if !self.extractor {
            reasons.push(
                "extractor inspector unavailable; connection/domain telemetry disabled".to_string(),
            );
        }
        if !self.alert_json {
            reasons.push("alert_json logger unavailable; alert ingestion disabled".to_string());
        }
        if self.config_valid == Some(false) {
            reasons.push("snort configuration validation failed".to_string());
        }
        reasons
    }
}
