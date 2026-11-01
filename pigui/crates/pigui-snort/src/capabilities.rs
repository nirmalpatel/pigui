use std::path::Path;
use std::process::Command;

use pigui_core::config::Config;
use pigui_core::models::SnortCapabilities;
use pigui_core::paths::resolve_snort;

use crate::discovery;

/// Probe the configured Snort binary without failing hard. Missing capabilities
/// are reported as warnings so the daemon and GUI can show a degraded state.
pub fn probe(config: &Config) -> SnortCapabilities {
    let mut caps = SnortCapabilities::default();

    let resolved = match resolve_snort(config) {
        Ok(resolved) => resolved,
        Err(_) => {
            caps.warnings
                .push("snort binary not found; set PIGUI_SNORT_BIN".to_string());
            return caps;
        }
    };

    caps.binary = Some(resolved.path.display().to_string());
    caps.source = Some(resolved.source.as_str().to_string());
    if let Some(warning) = resolved.source.warning() {
        caps.warnings.push(warning.to_string());
    }

    match discovery::version(&resolved.path) {
        Ok(version) => caps.version = Some(version),
        Err(error) => caps.warnings.push(format!("{error}")),
    }

    let help = discovery::run(&resolved.path, &["--help-options"]).unwrap_or_default();
    caps.control_socket = help.contains("--control-socket");
    caps.shell = help.contains("--shell");

    let modules = discovery::run(&resolved.path, &["--help-modules"]).unwrap_or_default();
    caps.extractor = modules.contains("extractor (");
    caps.alert_json = modules.contains("alert_json (");

    caps.daq_modules = discovery::daq_modules(&resolved.path).unwrap_or_default();

    if let Some(config_path) = &config.snort_config {
        let path = config.resolve(config_path);
        caps.config_path = Some(path.display().to_string());
        if path.is_file() {
            match validate(&resolved.path, &path) {
                Ok((valid, detail)) => {
                    caps.config_valid = Some(valid);
                    if !valid {
                        caps.warnings
                            .push(format!("snort config validation failed: {detail}"));
                    }
                }
                Err(error) => caps.warnings.push(format!("{error}")),
            }
        } else {
            caps.warnings
                .push(format!("snort config not found: {}", path.display()));
        }
    }

    if !caps.control_socket {
        caps.warnings
            .push("control socket unavailable; using signal/file mode".to_string());
    }

    caps
}

fn validate(binary: &Path, config_path: &Path) -> pigui_core::Result<(bool, String)> {
    let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let file = config_path.file_name().unwrap_or(config_path.as_os_str());

    let output = Command::new(binary)
        .current_dir(dir)
        .arg("-c")
        .arg(file)
        .arg("-T")
        .output()
        .map_err(|e| pigui_core::Error::io(binary, e))?;

    let mut detail = String::from_utf8_lossy(&output.stdout).into_owned();
    detail.push_str(&String::from_utf8_lossy(&output.stderr));
    let ok = output.status.success() && detail.contains("successfully validated");
    Ok((ok, tail(&detail, 600)))
}

fn tail(text: &str, limit: usize) -> String {
    let trimmed = text.trim();
    if trimmed.len() <= limit {
        return trimmed.to_string();
    }
    let start = trimmed.len() - limit;
    format!("...{}", &trimmed[start..])
}
