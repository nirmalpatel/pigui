use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub user: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connection_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flow {
    pub id: i64,
    pub proto: String,
    pub client_ip: String,
    pub client_port: u16,
    pub server_ip: String,
    pub server_port: u16,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub interface: Option<String>,
    pub state: Option<String>,
    pub bytes_ab: u64,
    pub bytes_ba: u64,
    pub packets_ab: u64,
    pub packets_ba: u64,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Connection {
    pub id: i64,
    pub uid: Option<String>,
    pub ts: i64,
    pub proto: Option<String>,
    pub client_ip: Option<String>,
    pub client_port: Option<u16>,
    pub server_ip: Option<String>,
    pub server_port: Option<u16>,
    pub service: Option<String>,
    pub conn_state: Option<String>,
    pub duration: Option<f64>,
    pub packets_ab: u64,
    pub packets_ba: u64,
    pub bytes_ab: u64,
    pub bytes_ba: u64,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsObservation {
    pub id: i64,
    pub ts: i64,
    pub client_ip: Option<String>,
    pub query: Option<String>,
    pub qtype: Option<String>,
    pub rcode: Option<String>,
    pub answers: Option<String>,
    pub ttl: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsObservation {
    pub id: i64,
    pub ts: i64,
    pub client_ip: Option<String>,
    pub server_ip: Option<String>,
    pub server_port: Option<u16>,
    pub server_name: Option<String>,
    pub version: Option<String>,
    pub validation_status: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpObservation {
    pub id: i64,
    pub ts: i64,
    pub client_ip: Option<String>,
    pub server_ip: Option<String>,
    pub server_port: Option<u16>,
    pub method: Option<String>,
    pub host: Option<String>,
    pub uri: Option<String>,
    pub user_agent: Option<String>,
    pub status_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuicObservation {
    pub id: i64,
    pub ts: i64,
    pub client_ip: Option<String>,
    pub server_ip: Option<String>,
    pub server_port: Option<u16>,
    pub server_name: Option<String>,
    pub client_protocol: Option<String>,
}
