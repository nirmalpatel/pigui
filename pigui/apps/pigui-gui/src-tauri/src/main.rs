#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pigui_core::client::DaemonClient;
use pigui_core::config::Config;
use pigui_core::rpc::{
    METHOD_ALERTS_LIST, METHOD_CAPTURE_HELPER_STATUS, METHOD_CAPTURE_START, METHOD_CAPTURE_STATUS,
    METHOD_CAPTURE_STOP, METHOD_CONNECTIONS_LIST, METHOD_DESTINATIONS_DETAIL,
    METHOD_DESTINATIONS_LIST, METHOD_DNS_LIST, METHOD_DOMAINS_LIST, METHOD_DOMAINS_SET_TRUST,
    METHOD_FLOWS_LIST, METHOD_MAINTENANCE_PRUNE, METHOD_MAINTENANCE_STATS, METHOD_PROCESSES_DETAIL,
    METHOD_PROCESSES_LIST, METHOD_SETTINGS_GET, METHOD_SETTINGS_RESET, METHOD_SETTINGS_UPDATE,
    METHOD_STATUS, METHOD_WATCHED_ADD, METHOD_WATCHED_LIST, METHOD_WATCHED_REMOVE,
};
use pigui_core::service::{self, ServiceAction};
use pigui_core::settings::AppSettings;
use serde_json::{Value, json};

fn prepare_home() {
    #[cfg(debug_assertions)]
    if std::env::var_os("PIGUI_HOME").is_none() {
        let home = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        if let Ok(home) = home.canonicalize() {
            unsafe {
                std::env::set_var("PIGUI_HOME", home);
            }
        }
    }
}

fn daemon_binary() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let path = exe
        .parent()
        .ok_or_else(|| "PIGUI has no parent directory".to_string())?
        .join("pigui-daemon");
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!(
            "packaged daemon not found at {}; start it from the PIGUI app bundle",
            path.display()
        ))
    }
}

fn agent_service_enabled() -> bool {
    service::run(ServiceAction::Status)
        .map(|output| output.contains("\"agent\":\"enabled\""))
        .unwrap_or(false)
}

fn start_daemon_if_needed() -> Result<String, String> {
    let config = Config::load().map_err(|error| error.to_string())?;
    if config.socket_path.exists() {
        #[cfg(unix)]
        let connected = std::os::unix::net::UnixStream::connect(&config.socket_path).is_ok();
        #[cfg(not(unix))]
        let connected = true;
        if connected {
            return Ok("daemon is already running".to_string());
        }
        let _ = std::fs::remove_file(&config.socket_path);
    }

    if agent_service_enabled() {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if config.socket_path.exists() {
                return Ok("pigui-daemon started by the SMAppService agent".to_string());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        return Err(format!(
            "the SMAppService daemon agent is enabled but did not create {}; re-register the agent or check launchd",
            config.socket_path.display()
        ));
    }

    let daemon = daemon_binary()?;
    std::fs::create_dir_all(&config.log_dir).map_err(|error| error.to_string())?;
    let log_path = config.log_dir.join("daemon.log");
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| error.to_string())?;
    let log_err = log.try_clone().map_err(|error| error.to_string())?;

    let mut command = Command::new(&daemon);
    command
        .stdin(Stdio::null())
        .stdout(log)
        .stderr(log_err)
        .env("PIGUI_HOME", &config.home);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let child = command
        .spawn()
        .map_err(|error| format!("could not start {}: {error}", daemon.display()))?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if config.socket_path.exists() {
            return Ok(format!("started pigui-daemon pid {}", child.id()));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "pigui-daemon started but did not create {}; see {}",
        config.socket_path.display(),
        log_path.display()
    ))
}

fn client() -> Result<DaemonClient, String> {
    let config = Config::load().map_err(|error| error.to_string())?;
    Ok(DaemonClient::new(&config.socket_path))
}

fn list_params(
    limit: Option<u32>,
    offset: Option<u32>,
    q: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
) -> Value {
    json!({
        "limit": limit,
        "offset": offset,
        "q": q,
        "sort": sort,
        "dir": dir,
    })
}

#[tauri::command]
fn get_settings() -> Result<AppSettings, String> {
    let value = client()?
        .call(METHOD_SETTINGS_GET, json!({}))
        .map_err(|error| error.to_string())?;
    serde_json::from_value(value).map_err(|error| error.to_string())
}

#[tauri::command]
fn update_settings(patch: Value) -> Result<AppSettings, String> {
    let value = client()?
        .call(METHOD_SETTINGS_UPDATE, patch)
        .map_err(|error| error.to_string())?;
    serde_json::from_value(value).map_err(|error| error.to_string())
}

#[tauri::command]
fn reset_settings() -> Result<AppSettings, String> {
    let value = client()?
        .call(METHOD_SETTINGS_RESET, json!({}))
        .map_err(|error| error.to_string())?;
    serde_json::from_value(value).map_err(|error| error.to_string())
}

#[tauri::command]
fn maintenance_stats() -> Result<Value, String> {
    client()?
        .call(METHOD_MAINTENANCE_STATS, json!({}))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn prune_now() -> Result<Value, String> {
    client()?
        .call(METHOD_MAINTENANCE_PRUNE, json!({}))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn start_daemon() -> Result<String, String> {
    start_daemon_if_needed()
}

#[tauri::command]
fn open_login_items_settings() -> Result<(), String> {
    let status = Command::new("/usr/bin/open")
        .arg("x-apple.systempreferences:com.apple.LoginItems-Settings.extension")
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err("could not open Login Items & Extensions settings".to_string())
    }
}

#[tauri::command]
fn service_status() -> Result<String, String> {
    service::run(ServiceAction::Status).map_err(|error| error.to_string())
}

#[tauri::command]
fn service_register_agent() -> Result<String, String> {
    service::run(ServiceAction::RegisterAgent).map_err(|error| error.to_string())
}

#[tauri::command]
fn service_unregister_agent() -> Result<String, String> {
    service::run(ServiceAction::UnregisterAgent).map_err(|error| error.to_string())
}

#[tauri::command]
fn service_register_helper() -> Result<String, String> {
    service::run(ServiceAction::RegisterHelper).map_err(|error| error.to_string())
}

#[tauri::command]
fn service_unregister_helper() -> Result<String, String> {
    service::run(ServiceAction::UnregisterHelper).map_err(|error| error.to_string())
}

#[tauri::command]
fn helper_status() -> Result<Value, String> {
    client()?
        .call(METHOD_CAPTURE_HELPER_STATUS, json!({}))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn capture_status() -> Result<Value, String> {
    client()?
        .call(METHOD_CAPTURE_STATUS, json!({}))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn helper_enable_capture(interface: String) -> Result<Value, String> {
    client()?
        .call(METHOD_CAPTURE_START, json!({ "interface": interface }))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn helper_disable_capture() -> Result<Value, String> {
    client()?
        .call(METHOD_CAPTURE_STOP, json!({}))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn get_status() -> Result<Value, String> {
    client()?
        .call(METHOD_STATUS, json!({}))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_alerts(
    limit: Option<u32>,
    offset: Option<u32>,
    q: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
) -> Result<Value, String> {
    client()?
        .call(METHOD_ALERTS_LIST, list_params(limit, offset, q, sort, dir))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_destinations(
    limit: Option<u32>,
    offset: Option<u32>,
    q: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
) -> Result<Value, String> {
    client()?
        .call(
            METHOD_DESTINATIONS_LIST,
            list_params(limit, offset, q, sort, dir),
        )
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_flows(
    limit: Option<u32>,
    offset: Option<u32>,
    q: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
) -> Result<Value, String> {
    client()?
        .call(METHOD_FLOWS_LIST, list_params(limit, offset, q, sort, dir))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_processes(
    limit: Option<u32>,
    offset: Option<u32>,
    q: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
) -> Result<Value, String> {
    client()?
        .call(
            METHOD_PROCESSES_LIST,
            list_params(limit, offset, q, sort, dir),
        )
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_connections(
    limit: Option<u32>,
    offset: Option<u32>,
    q: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
) -> Result<Value, String> {
    client()?
        .call(
            METHOD_CONNECTIONS_LIST,
            list_params(limit, offset, q, sort, dir),
        )
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn destination_detail(ip: String) -> Result<Value, String> {
    client()?
        .call(METHOD_DESTINATIONS_DETAIL, json!({ "ip": ip }))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn process_detail(pid: u32) -> Result<Value, String> {
    client()?
        .call(METHOD_PROCESSES_DETAIL, json!({ "pid": pid }))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_domains(
    limit: Option<u32>,
    offset: Option<u32>,
    q: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
) -> Result<Value, String> {
    client()?
        .call(
            METHOD_DOMAINS_LIST,
            list_params(limit, offset, q, sort, dir),
        )
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_dns(
    limit: Option<u32>,
    offset: Option<u32>,
    q: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
) -> Result<Value, String> {
    client()?
        .call(METHOD_DNS_LIST, list_params(limit, offset, q, sort, dir))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_watched_domains() -> Result<Value, String> {
    client()?
        .call(METHOD_WATCHED_LIST, json!({}))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn add_watched_domain(domain: String) -> Result<Value, String> {
    client()?
        .call(METHOD_WATCHED_ADD, json!({ "domain": domain }))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn remove_watched_domain(domain: String) -> Result<Value, String> {
    client()?
        .call(METHOD_WATCHED_REMOVE, json!({ "domain": domain }))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn set_domain_trust(
    registrable_domain: String,
    state: String,
    note: Option<String>,
) -> Result<Value, String> {
    client()?
        .call(
            METHOD_DOMAINS_SET_TRUST,
            json!({
                "registrable_domain": registrable_domain,
                "state": state,
                "note": note,
            }),
        )
        .map_err(|error| error.to_string())
}

fn main() {
    prepare_home();

    tauri::Builder::default()
        .setup(|app| {
            if let Err(error) = start_daemon_if_needed() {
                eprintln!("could not start pigui-daemon: {error}");
            }
            let _ = app;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_daemon,
            open_login_items_settings,
            service_status,
            service_register_agent,
            service_unregister_agent,
            service_register_helper,
            service_unregister_helper,
            helper_status,
            capture_status,
            helper_enable_capture,
            helper_disable_capture,
            get_status,
            get_settings,
            update_settings,
            reset_settings,
            maintenance_stats,
            prune_now,
            list_alerts,
            list_destinations,
            destination_detail,
            list_domains,
            list_dns,
            list_watched_domains,
            add_watched_domain,
            remove_watched_domain,
            set_domain_trust,
            list_flows,
            list_processes,
            process_detail,
            list_connections
        ])
        .run(tauri::generate_context!())
        .expect("error while running PIGUI");
}
