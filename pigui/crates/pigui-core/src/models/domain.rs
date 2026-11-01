use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustState {
    #[default]
    Unknown,
    Trusted,
    Suspicious,
    Ignored,
}

impl TrustState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Trusted => "trusted",
            Self::Suspicious => "suspicious",
            Self::Ignored => "ignored",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "unknown" => Some(Self::Unknown),
            "trusted" => Some(Self::Trusted),
            "suspicious" => Some(Self::Suspicious),
            "ignored" => Some(Self::Ignored),
            _ => None,
        }
    }
}

impl std::fmt::Display for TrustState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewFlag {
    NewDomain,
    NoDomain,
    InvalidTls,
    Alerts,
    UnknownTrust,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointDomain {
    pub domain: String,
    pub registrable_domain: String,
    pub source: String,
    pub server_port: Option<u16>,
    pub trust_state: TrustState,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainSummary {
    pub domain: String,
    pub hostnames: Vec<String>,
    pub trust_state: TrustState,
    pub first_seen: i64,
    pub last_seen: i64,
    pub observation_count: u64,
    pub endpoint_count: u64,
    pub process_count: u64,
    pub flags: Vec<ReviewFlag>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_state_round_trips() {
        for state in [
            TrustState::Unknown,
            TrustState::Trusted,
            TrustState::Suspicious,
            TrustState::Ignored,
        ] {
            assert_eq!(TrustState::parse(state.as_str()), Some(state));
        }
        assert_eq!(TrustState::parse("other"), None);
    }
}
