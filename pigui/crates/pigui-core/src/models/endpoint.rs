use serde::{Deserialize, Serialize};

/// A remote (destination) endpoint observed in alerts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    pub ip: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connection_count: u64,
    pub process_count: u64,
    pub alert_count: u64,
    pub reputation: i64,
    pub blocked: bool,
}
