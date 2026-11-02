use std::env;
use std::path::{Path, PathBuf};

use crate::bundle;
use crate::error::{Error, Result};

/// Runtime configuration for PIGUI.
///
/// Relative paths are interpreted relative to the PIGUI home directory, which
/// is the current working directory unless `PIGUI_HOME` is set.
#[derive(Debug, Clone)]
pub struct Config {
    pub home: PathBuf,
    pub snort_bin: Option<PathBuf>,
    pub snort_config: Option<PathBuf>,
    pub snort_lua_path: Option<PathBuf>,
    pub run_dir: PathBuf,
    pub log_dir: PathBuf,
    pub db_path: PathBuf,
    pub alert_json: PathBuf,
    pub socket_path: PathBuf,
    pub environment: String,
    pub snort_interface: Option<String>,
    pub snort_log_dir: PathBuf,
    pub snort_config_dir: PathBuf,
    pub extractor_json: PathBuf,
    pub snort_pidfile: PathBuf,
    pub snort_control_socket: PathBuf,
    pub process_poll_ms: u64,
}

impl Config {
    pub fn load() -> Result<Self> {
        let bundled = bundle::is_bundled();
        if !bundled {
            let _ = dotenvy::dotenv();
        }

        let raw_home = env::var_os("PIGUI_HOME")
            .map(PathBuf::from)
            .or_else(|| bundled.then(bundle::production_home).flatten())
            .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        let home = if raw_home.is_absolute() {
            raw_home
        } else {
            env::current_dir()
                .map(|cwd| cwd.join(&raw_home))
                .unwrap_or(raw_home)
        };
        let home = home.canonicalize().unwrap_or(home);
        if !bundled {
            let _ = dotenvy::from_path(home.join(".env"));
        }

        let run_dir = absolute(&home, path_var("PIGUI_RUN_DIR", home.join("var/run")));
        let log_dir = absolute(&home, path_var("PIGUI_LOG_DIR", home.join("var/log")));

        let snort_bin = optional_path_var("PIGUI_SNORT_BIN").map(|path| absolute(&home, path));
        let snort_config = optional_path_var("PIGUI_SNORT_CONFIG")
            .map(|path| absolute(&home, path))
            .or_else(bundle::snort_config)
            .or_else(|| {
                let candidate = home.join("../lua/snort.lua");
                candidate.is_file().then_some(candidate)
            });
        let snort_lua_path = optional_path_var("PIGUI_SNORT_LUA_PATH")
            .map(|path| absolute(&home, path))
            .or_else(bundle::snort_lua_dir)
            .or_else(|| {
                let candidate = home.join("../lua");
                candidate.is_dir().then_some(candidate)
            });

        let default_db = home.join("var/lib/pigui.db");
        let db_path = absolute(&home, path_var("PIGUI_DB_PATH", default_db));
        let socket_path = absolute(
            &home,
            path_var("PIGUI_SOCKET", run_dir.join("pigui-daemon.sock")),
        );

        let environment = if bundled { "prod" } else { "dev" }.to_string();
        let snort_interface = env::var("PIGUI_SNORT_INTERFACE")
            .ok()
            .filter(|value| !value.is_empty());
        let default_snort_log_dir = if bundled {
            home.join("snort")
        } else {
            log_dir.join("snort")
        };
        let snort_log_dir = absolute(
            &home,
            path_var("PIGUI_SNORT_LOG_DIR", default_snort_log_dir),
        );
        let alert_json = absolute(
            &home,
            path_var("PIGUI_ALERT_JSON", snort_log_dir.join("alert_json.txt")),
        );
        let snort_config_dir = absolute(
            &home,
            path_var("PIGUI_SNORT_CONFIG_DIR", home.join("var/snort")),
        );
        let extractor_json = absolute(
            &home,
            path_var(
                "PIGUI_EXTRACTOR_JSON",
                snort_log_dir.join("file_connector_pigui_transmit"),
            ),
        );
        let snort_pidfile = absolute(
            &home,
            path_var("PIGUI_SNORT_PIDFILE", snort_log_dir.join("snort.pid")),
        );
        let snort_control_socket = absolute(
            &home,
            path_var("PIGUI_SNORT_CONTROL_SOCKET", run_dir.join("snort.sock")),
        );
        let process_poll_ms = env::var("PIGUI_PROCESS_POLL_MS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1_000);

        Ok(Self {
            home,
            snort_bin,
            snort_config,
            snort_lua_path,
            run_dir,
            log_dir,
            db_path,
            alert_json,
            socket_path,
            environment,
            snort_interface,
            snort_log_dir,
            snort_config_dir,
            extractor_json,
            snort_pidfile,
            snort_control_socket,
            process_poll_ms,
        })
    }

    /// Resolve a possibly-relative path against the PIGUI home directory.
    pub fn resolve(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.home.join(path)
        }
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        for dir in [
            &self.run_dir,
            &self.log_dir,
            &self.snort_log_dir,
            &self.snort_config_dir,
        ] {
            std::fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;
        }
        for file in [&self.db_path, &self.alert_json, &self.extractor_json] {
            if let Some(parent) = file.parent() {
                std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
            }
        }
        Ok(())
    }
}

fn absolute(home: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        home.join(path)
    }
}

fn path_var(key: &str, default: PathBuf) -> PathBuf {
    env::var_os(key).map(PathBuf::from).unwrap_or(default)
}

fn optional_path_var(key: &str) -> Option<PathBuf> {
    env::var_os(key)
        .map(PathBuf::from)
        .filter(|value| !value.as_os_str().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_keeps_absolute_paths() {
        let config = test_config();
        let absolute = PathBuf::from("/tmp/pigui-test.db");
        assert_eq!(config.resolve(&absolute), absolute);
    }

    #[test]
    fn resolve_joins_home_for_relative_paths() {
        let config = test_config();
        assert_eq!(
            config.resolve(Path::new("var/run")),
            config.home.join("var/run")
        );
    }

    fn test_config() -> Config {
        let home = PathBuf::from("/tmp/pigui");
        Config {
            home: home.clone(),
            snort_bin: None,
            snort_config: None,
            snort_lua_path: None,
            run_dir: home.join("var/run"),
            log_dir: home.join("var/log"),
            db_path: home.join("var/lib/pigui.db"),
            alert_json: home.join("var/log/alert_json.txt"),
            socket_path: home.join("var/run/pigui-daemon.sock"),
            environment: "dev".to_string(),
            snort_interface: None,
            snort_log_dir: home.join("var/log/snort"),
            snort_config_dir: home.join("var/snort"),
            extractor_json: home.join("var/log/snort/file_connector_pigui_transmit"),
            snort_pidfile: home.join("var/log/snort/snort.pid"),
            snort_control_socket: home.join("var/run/snort.sock"),
            process_poll_ms: 1000,
        }
    }
}
