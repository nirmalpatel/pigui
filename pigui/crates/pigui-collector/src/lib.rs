mod nettop;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use pigui_core::Result;

pub use nettop::{
    default_interface, interface_mismatch_warning, parse_nettop, run_nettop, run_nettop_cached,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSample {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
    pub user: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connection_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketSample {
    pub proto: String,
    pub client_ip: String,
    pub client_port: u16,
    pub server_ip: String,
    pub server_port: u16,
    pub state: Option<String>,
    pub interface: Option<String>,
    pub bytes_ab: u64,
    pub bytes_ba: u64,
    pub pid: u32,
    pub process_name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorSnapshot {
    pub processes: Vec<ProcessSample>,
    pub sockets: Vec<SocketSample>,
}

pub trait Collector {
    fn platform(&self) -> &'static str;
    fn snapshot(&mut self) -> Result<CollectorSnapshot>;
}

/// macOS collector backed by `nettop` CSV output.
#[derive(Debug, Clone)]
pub struct MacosCollector {
    interface: Option<String>,
    metadata: HashMap<u32, (String, String)>,
    ticks: u32,
}

impl MacosCollector {
    pub fn new(interface: Option<String>) -> Self {
        Self {
            interface,
            metadata: HashMap::new(),
            ticks: 0,
        }
    }

    pub fn interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }
}

impl Collector for MacosCollector {
    fn platform(&self) -> &'static str {
        "macos"
    }

    fn snapshot(&mut self) -> Result<CollectorSnapshot> {
        self.ticks = self.ticks.wrapping_add(1);
        let refresh_metadata = self.ticks.is_multiple_of(5);
        run_nettop_cached(
            self.interface.as_deref(),
            &mut self.metadata,
            refresh_metadata,
        )
    }
}
