use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use pigui_core::Result;
use pigui_core::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRequest {
    pub ip: String,
    pub direction: Direction,
    pub ttl_secs: u64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockOutcome {
    Applied,
    WouldBlock,
}

pub trait FirewallBackend {
    fn name(&self) -> &'static str;
    fn apply_block(&self, request: &BlockRequest) -> Result<BlockOutcome>;
    fn flush(&self) -> Result<usize>;
}

/// Records intended blocks without touching the system firewall.
#[derive(Debug, Default)]
pub struct DryRunBackend {
    blocks: Mutex<Vec<BlockRequest>>,
}

impl DryRunBackend {
    pub fn blocks(&self) -> Vec<BlockRequest> {
        self.blocks.lock().expect("dry-run lock poisoned").clone()
    }
}

impl FirewallBackend for DryRunBackend {
    fn name(&self) -> &'static str {
        "dry-run"
    }

    fn apply_block(&self, request: &BlockRequest) -> Result<BlockOutcome> {
        self.blocks
            .lock()
            .map_err(|_| Error::NotImplemented("dry-run lock poisoned".into()))?
            .push(request.clone());
        Ok(BlockOutcome::WouldBlock)
    }

    fn flush(&self) -> Result<usize> {
        let mut blocks = self
            .blocks
            .lock()
            .map_err(|_| Error::NotImplemented("dry-run lock poisoned".into()))?;
        let count = blocks.len();
        blocks.clear();
        Ok(count)
    }
}

/// PF backend placeholder. Real anchor/table management lands in M6.
#[derive(Debug, Default)]
pub struct PfBackend;

impl FirewallBackend for PfBackend {
    fn name(&self) -> &'static str {
        "pf"
    }

    fn apply_block(&self, _request: &BlockRequest) -> Result<BlockOutcome> {
        Err(Error::NotImplemented(
            "PF enforcement is planned for M6 and is dry-run only until then".into(),
        ))
    }

    fn flush(&self) -> Result<usize> {
        Err(Error::NotImplemented(
            "PF enforcement is planned for M6".into(),
        ))
    }
}
