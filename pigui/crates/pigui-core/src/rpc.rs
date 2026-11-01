use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::models::{Alert, Destination, SnortCapabilities};

pub const METHOD_STATUS: &str = "status";
pub const METHOD_HEALTH: &str = "health";
pub const METHOD_ALERTS_LIST: &str = "alerts.list";
pub const METHOD_DESTINATIONS_LIST: &str = "destinations.list";
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertsQuery {
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub offset: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DestinationsQuery {
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub offset: Option<u32>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthPayload {
    pub status: String,
    pub uptime_secs: u64,
    pub alerts_ingested: u64,
    pub parse_errors: u64,
}
