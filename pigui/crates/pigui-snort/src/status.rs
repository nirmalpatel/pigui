use std::path::Path;
use std::process::Command;

use pigui_core::config::Config;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnortStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub interface: Option<String>,
    pub config_path: Option<String>,
    pub log_dir: String,
    pub extractor_json: String,
    pub control_socket: Option<String>,
    pub pidfile: String,
}

pub fn status(config: &Config) -> SnortStatus {
    let pid = read_pidfile(&config.snort_pidfile).filter(|pid| process_exists(*pid));
    let config_path = config.snort_config_dir.join("snort.lua");
    let control_socket = socket_exists(&config.snort_control_socket)
        .then(|| config.snort_control_socket.display().to_string());

    SnortStatus {
        running: pid.is_some(),
        pid,
        interface: config.snort_interface.clone(),
        config_path: config_path
            .is_file()
            .then(|| config_path.display().to_string()),
        log_dir: config.snort_log_dir.display().to_string(),
        extractor_json: config.extractor_json.display().to_string(),
        control_socket,
        pidfile: config.snort_pidfile.display().to_string(),
    }
}

pub fn read_pidfile(path: &Path) -> Option<u32> {
    let text = std::fs::read_to_string(path).ok()?;
    text.split_whitespace().find_map(|token| token.parse().ok())
}

fn socket_exists(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;

    std::fs::metadata(path)
        .map(|metadata| metadata.file_type().is_socket())
        .unwrap_or(false)
}

fn process_exists(pid: u32) -> bool {
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}
