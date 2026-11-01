use std::env;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnortSource {
    Env,
    InTree,
    Installed,
    SystemPath,
    Path,
    Homebrew,
}

impl SnortSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Env => "PIGUI_SNORT_BIN",
            Self::InTree => "in-tree build",
            Self::Installed => "install prefix",
            Self::SystemPath => "/usr/local/snort",
            Self::Path => "PATH",
            Self::Homebrew => "homebrew",
        }
    }

    pub fn warning(self) -> Option<&'static str> {
        match self {
            Self::Homebrew => Some("homebrew snort may lack control socket support"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSnort {
    pub path: PathBuf,
    pub source: SnortSource,
}

/// Resolve the Snort binary in the documented order.
pub fn resolve_snort(config: &Config) -> Result<ResolvedSnort> {
    let mut candidates: Vec<(PathBuf, SnortSource)> = Vec::new();

    if let Some(bin) = &config.snort_bin {
        candidates.push((config.resolve(bin), SnortSource::Env));
    }

    candidates.push((config.home.join("../build/src/snort"), SnortSource::InTree));
    candidates.push((
        config.home.join("../install/bin/snort"),
        SnortSource::Installed,
    ));
    candidates.push((
        PathBuf::from("/usr/local/snort/bin/snort"),
        SnortSource::SystemPath,
    ));

    if let Some(path) = find_in_path("snort") {
        candidates.push((path, SnortSource::Path));
    }

    candidates.push((
        PathBuf::from("/opt/homebrew/bin/snort"),
        SnortSource::Homebrew,
    ));
    candidates.push((PathBuf::from("/usr/local/bin/snort"), SnortSource::Homebrew));

    for (path, source) in candidates {
        if path.is_file() {
            let path = std::fs::canonicalize(&path).unwrap_or(path);
            return Ok(ResolvedSnort { path, source });
        }
    }

    Err(Error::SnortNotFound)
}

fn find_in_path(binary: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

pub fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_takes_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let binary = home.join("custom-snort");
        std::fs::write(&binary, b"#!/bin/sh\n").unwrap();

        let config = Config {
            home: home.clone(),
            snort_bin: Some(binary.clone()),
            snort_config: None,
            snort_lua_path: None,
            run_dir: home.join("var/run"),
            log_dir: home.join("var/log"),
            db_path: home.join("var/lib/pigui.db"),
            alert_json: home.join("var/log/alert_json.txt"),
            socket_path: home.join("var/run/pigui-daemon.sock"),
        };

        let resolved = resolve_snort(&config).unwrap();
        assert_eq!(resolved.source, SnortSource::Env);
        assert_eq!(resolved.path, std::fs::canonicalize(binary).unwrap());
    }
}
