use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

use crate::bundle;
use crate::error::{Error, Result};

/// Locate the signed XPC bridge shipped inside PIGUI.app.
pub fn helperctl_path() -> Option<PathBuf> {
    bundle::macos_dir()
        .map(|dir| dir.join("pigui-helperctl"))
        .filter(|path| path.is_file())
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(|dir| dir.join("pigui-helperctl")))
                .filter(|path| path.is_file())
        })
}

/// Send one allowlisted request to the root helper over XPC.
pub fn request(method: &str, params: Value) -> Result<Value> {
    let path = helperctl_path().ok_or_else(|| {
        Error::Config("pigui-helperctl is only available in the packaged PIGUI.app".into())
    })?;
    let payload = json!({ "method": method, "params": params }).to_string();

    let output = Command::new(&path)
        .arg("request")
        .arg(&payload)
        .output()
        .map_err(|error| Error::io(&path, error))?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        let detail = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        return Err(Error::Config(format!("helper {method} failed: {detail}")));
    }

    serde_json::from_str(stdout.trim())
        .map_err(|error| Error::Parse(format!("invalid helper response: {error}")))
}

pub fn status() -> Result<Value> {
    request("status", json!({}))
}

pub fn version() -> Result<Value> {
    request("version", json!({}))
}

pub fn enable_capture(interface: &str) -> Result<Value> {
    request("enable_capture", json!({ "interface": interface }))
}

pub fn disable_capture() -> Result<Value> {
    request("disable_capture", json!({}))
}

pub fn flush_firewall() -> Result<Value> {
    request("flush_firewall", json!({}))
}

pub fn apply_block(ip: &str, direction: &str, ttl_secs: u64, reason: &str) -> Result<Value> {
    request(
        "apply_block",
        json!({
            "ip": ip,
            "direction": direction,
            "ttl_secs": ttl_secs,
            "reason": reason,
        }),
    )
}
