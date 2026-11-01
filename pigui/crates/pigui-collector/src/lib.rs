use serde::{Deserialize, Serialize};

use pigui_core::Result;
use pigui_core::error::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub name: String,
    pub user: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketSnapshot {
    pub proto: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub pid: Option<u32>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

pub trait Collector {
    fn platform(&self) -> &'static str;
    fn snapshot(&self) -> Result<(Vec<ProcessSnapshot>, Vec<SocketSnapshot>)>;
}

/// Placeholder macOS collector. Attribution lands in milestone M4.
#[derive(Debug, Default)]
pub struct MacosCollector;

impl Collector for MacosCollector {
    fn platform(&self) -> &'static str {
        "macos"
    }

    fn snapshot(&self) -> Result<(Vec<ProcessSnapshot>, Vec<SocketSnapshot>)> {
        Err(Error::NotImplemented(
            "macOS process/socket collector is planned for M4".into(),
        ))
    }
}
