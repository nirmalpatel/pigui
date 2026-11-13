use std::time::Duration;

use anyhow::{Context, Result};
use pigui_core::client::DaemonClient;
use serde_json::Value;

pub const ALLOWED_METHODS: &[&str] = &[
    "status",
    "health",
    "snort.status",
    "alerts.list",
    "destinations.list",
    "destinations.detail",
    "flows.list",
    "processes.list",
    "processes.detail",
    "connections.list",
    "domains.list",
    "watched.list",
    "dns.list",
    "tls.list",
    "http.list",
    "quic.list",
    "maintenance.stats",
    "firewall.status",
    "firewall.rules.list",
    "firewall.blocks.list",
    "analysis.overview",
    "analysis.findings",
];

#[derive(Debug, Clone)]
pub struct ReadOnlyDaemon {
    client: DaemonClient,
}

impl ReadOnlyDaemon {
    pub fn new(socket_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            client: DaemonClient::with_timeout(socket_path, Duration::from_secs(30)),
        }
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        ensure_allowed(method)?;
        let client = self.client.clone();
        let call_method = method.to_string();
        tokio::task::spawn_blocking(move || client.call(&call_method, params))
            .await
            .context("daemon call task failed")?
            .map_err(|error| {
                anyhow::anyhow!(
                    "daemon call '{method}' failed: {error}; ensure pigui-daemon is running and PIGUI_SOCKET is correct"
                )
            })
    }
}

pub fn ensure_allowed(method: &str) -> Result<()> {
    if ALLOWED_METHODS.contains(&method) {
        Ok(())
    } else {
        anyhow::bail!("daemon method '{method}' is not on the PIGUI MCP read-only allowlist")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_accepts_read_only_methods() {
        for method in [
            "status",
            "analysis.overview",
            "analysis.findings",
            "firewall.rules.list",
        ] {
            assert!(ensure_allowed(method).is_ok(), "{method}");
        }
    }

    #[test]
    fn allowlist_rejects_mutations_and_unknown_methods() {
        for method in [
            "capture.start",
            "capture.ensure",
            "capture.stop",
            "capture.status",
            "settings.update",
            "domains.set_trust",
            "watched.add",
            "maintenance.prune_now",
            "firewall.apply",
            "firewall.blocks.add",
            "shutdown",
            "raw.rpc",
        ] {
            assert!(ensure_allowed(method).is_err(), "{method}");
        }
    }
}
