#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pigui_core::client::DaemonClient;
use pigui_core::config::Config;
use pigui_core::rpc::{
    METHOD_ALERTS_LIST, METHOD_CAPTURE_ENSURE, METHOD_CAPTURE_HELPER_STATUS, METHOD_CAPTURE_START,
    METHOD_CAPTURE_STATUS, METHOD_CAPTURE_STOP, METHOD_CONNECTIONS_LIST,
    METHOD_DESTINATIONS_DETAIL, METHOD_DESTINATIONS_LIST, METHOD_DNS_LIST, METHOD_DOMAINS_LIST,
    METHOD_DOMAINS_SET_TRUST, METHOD_FIREWALL_APPLY, METHOD_FIREWALL_BLOCKS_ADD,
    METHOD_FIREWALL_BLOCKS_LIST, METHOD_FIREWALL_BLOCKS_REMOVE, METHOD_FIREWALL_COUNTERS,
    METHOD_FIREWALL_ENABLE, METHOD_FIREWALL_EVENTS_LIST, METHOD_FIREWALL_RESET,
    METHOD_FIREWALL_RULES_CREATE, METHOD_FIREWALL_RULES_DELETE, METHOD_FIREWALL_RULES_LIST,
    METHOD_FIREWALL_RULES_REORDER, METHOD_FIREWALL_RULES_UPDATE, METHOD_FIREWALL_STATUS,
    METHOD_FLOWS_LIST, METHOD_MAINTENANCE_PRUNE, METHOD_MAINTENANCE_STATS, METHOD_PROCESSES_DETAIL,
    METHOD_PROCESSES_LIST, METHOD_SETTINGS_GET, METHOD_SETTINGS_RESET, METHOD_SETTINGS_UPDATE,
    METHOD_SHUTDOWN, METHOD_STATUS, METHOD_WATCHED_ADD, METHOD_WATCHED_LIST, METHOD_WATCHED_REMOVE,
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

fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

fn service_status_json() -> Result<Value, String> {
    let output = service::run(ServiceAction::Status).map_err(|error| error.to_string())?;
    serde_json::from_str(&output).map_err(|error| format!("invalid service status: {error}"))
}

fn service_field(status: &Value, field: &str) -> String {
    status
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string()
}

fn run_service_with_retry(action: ServiceAction, attempts: u32) -> Result<String, String> {
    let mut last_error = "service command failed".to_string();
    for attempt in 0..attempts {
        match service::run(action) {
            Ok(output) => return Ok(output),
            Err(error) => {
                last_error = error.to_string();
                if attempt + 1 < attempts {
                    std::thread::sleep(Duration::from_millis(750));
                }
            }
        }
    }
    Err(last_error)
}

fn wait_for_service_state(field: &str, expected: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if service_status_json()
            .map(|status| service_field(&status, field) == expected)
            .unwrap_or(false)
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn agent_service_enabled() -> bool {
    service_status_json()
        .map(|status| service_field(&status, "agent") == "enabled")
        .unwrap_or(false)
}

fn daemon_status(config: &Config) -> Result<Value, String> {
    let client = DaemonClient::new(&config.socket_path);
    client
        .call(METHOD_STATUS, json!({}))
        .map_err(|error| error.to_string())
}

fn daemon_version(config: &Config) -> Result<String, String> {
    let value = daemon_status(config)?;
    Ok(value
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string())
}

fn daemon_binary_changed(status: &Value) -> bool {
    let Some(uptime) = status.get("uptime_secs").and_then(Value::as_u64) else {
        return false;
    };
    let Ok(daemon) = daemon_binary() else {
        return false;
    };
    let Ok(modified) = std::fs::metadata(&daemon).and_then(|metadata| metadata.modified()) else {
        return false;
    };
    let Ok(modified) = modified.duration_since(UNIX_EPOCH) else {
        return false;
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return false;
    };
    let started_at = now.as_secs().saturating_sub(uptime);
    started_at.saturating_add(2) < modified.as_secs()
}

fn helper_version() -> Result<String, String> {
    let value = pigui_core::helper::version().map_err(|error| error.to_string())?;
    Ok(value
        .pointer("/data/version")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string())
}

fn wait_for_daemon_version(
    config: &Config,
    expected: &str,
    timeout: Duration,
) -> Result<String, String> {
    let deadline = Instant::now() + timeout;
    let mut last_error = "daemon did not start".to_string();
    while Instant::now() < deadline {
        if config.socket_path.exists() {
            match daemon_version(config) {
                Ok(version) if version == expected => return Ok(version),
                Ok(version) => {
                    last_error = format!("daemon is version {version}, expected {expected}");
                }
                Err(error) => last_error = error,
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(last_error)
}

fn stop_daemon(config: &Config) {
    let client = DaemonClient::new(&config.socket_path);
    let _ = client.call(METHOD_SHUTDOWN, json!({}));
    let deadline = Instant::now() + Duration::from_secs(3);
    while config.socket_path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    if config.socket_path.exists() {
        let _ = std::fs::remove_file(&config.socket_path);
    }
}

fn rotate_log(path: &std::path::Path, max_bytes: u64) {
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    if metadata.len() < max_bytes {
        return;
    }
    let rotated = path.with_extension("log.1");
    let _ = std::fs::remove_file(&rotated);
    let _ = std::fs::rename(path, rotated);
}

fn start_daemon_process(config: &Config) -> Result<u32, String> {
    let daemon = daemon_binary()?;
    std::fs::create_dir_all(&config.log_dir).map_err(|error| error.to_string())?;
    let log_path = config.log_dir.join("daemon.log");
    rotate_log(&log_path, 10 * 1024 * 1024);
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
    Ok(child.id())
}

fn start_direct_daemon_if_needed(config: &Config) -> Result<String, String> {
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

    let pid = start_daemon_process(config)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if config.socket_path.exists() {
            return Ok(format!("started pigui-daemon pid {pid}"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "pigui-daemon started but did not create {}; see {}",
        config.socket_path.display(),
        config.log_dir.join("daemon.log").display()
    ))
}

fn ensure_daemon(config: &Config, expected: &str) -> Result<String, String> {
    let mut stale = false;
    if config.socket_path.exists() {
        match daemon_status(config) {
            Ok(status) => {
                let version = status
                    .get("version")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if version == expected && !daemon_binary_changed(&status) {
                    return Ok(format!("running {version}"));
                }
                stale = true;
                if version == expected {
                    eprintln!("PIGUI daemon binary changed since it started; restarting");
                } else {
                    eprintln!("PIGUI daemon is version {version}; expected {expected}");
                }
            }
            Err(error) => {
                stale = true;
                eprintln!("PIGUI daemon did not respond: {error}");
            }
        }
    }

    if stale {
        stop_daemon(config);
    }

    if agent_service_enabled() {
        let should_restart_agent =
            stale || wait_for_daemon_version(config, expected, Duration::from_secs(3)).is_err();
        if should_restart_agent {
            let _ = run_service_with_retry(ServiceAction::UnregisterAgent, 3);
            wait_for_service_state("agent", "not_registered", Duration::from_secs(5));
            run_service_with_retry(ServiceAction::RegisterAgent, 5)?;
        }
        let version = wait_for_daemon_version(config, expected, Duration::from_secs(10))?;
        return Ok(format!("running {version}"));
    }

    let pid = start_daemon_process(config)?;
    let version = wait_for_daemon_version(config, expected, Duration::from_secs(5))?;
    Ok(format!("started pid {pid}, running {version}"))
}

fn ensure_helper(expected: &str) -> Result<String, String> {
    let status = service_status_json()?;
    let helper_state = service_field(&status, "helper");
    if helper_state == "requires_approval" {
        return Ok("requires approval in Login Items & Extensions".to_string());
    }
    if helper_state != "enabled" {
        return Ok(format!("not registered ({helper_state})"));
    }

    let current = helper_version().unwrap_or_default();
    if current == expected {
        return Ok(format!("running {current}"));
    }

    eprintln!(
        "PIGUI helper is version {}; expected {expected}",
        if current.is_empty() {
            "unknown"
        } else {
            &current
        }
    );
    if !current.is_empty() {
        let _ = pigui_core::helper::disable_capture();
    }
    let _ = run_service_with_retry(ServiceAction::UnregisterHelper, 3);
    wait_for_service_state("helper", "not_registered", Duration::from_secs(5));
    run_service_with_retry(ServiceAction::RegisterHelper, 5)?;

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(version) = helper_version() {
            if version == expected {
                if let Ok(helper_status) = pigui_core::helper::status() {
                    let running = helper_status
                        .pointer("/data/capture_running")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if running {
                        let _ = pigui_core::helper::disable_capture();
                    }
                }
                return Ok(format!("running {version}"));
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let state = service_status_json()
        .map(|status| service_field(&status, "helper"))
        .unwrap_or_else(|_| "unknown".to_string());
    if state == "requires_approval" {
        return Err(
            "PIGUI helper needs approval in System Settings > General > Login Items & Extensions"
                .to_string(),
        );
    }
    Err(format!(
        "helper did not restart with version {expected} (service {state})"
    ))
}

fn reconcile_services() -> Result<String, String> {
    let config = Config::load().map_err(|error| error.to_string())?;
    if config.environment != "prod" {
        return start_direct_daemon_if_needed(&config);
    }
    let expected = app_version();

    let status = service_status_json().unwrap_or(Value::Null);
    if service_field(&status, "agent") == "not_registered" {
        let _ = run_service_with_retry(ServiceAction::RegisterAgent, 3);
    }

    let daemon = ensure_daemon(&config, &expected)?;

    let status = service_status_json().unwrap_or(Value::Null);
    if service_field(&status, "helper") == "not_registered" {
        let _ = run_service_with_retry(ServiceAction::RegisterHelper, 3);
    }

    let helper = ensure_helper(&expected)?;
    Ok(format!("daemon: {daemon}; helper: {helper}"))
}

fn client() -> Result<DaemonClient, String> {
    static CLIENT: OnceLock<DaemonClient> = OnceLock::new();
    if let Some(client) = CLIENT.get() {
        return Ok(client.clone());
    }
    let config = Config::load().map_err(|error| error.to_string())?;
    let client = DaemonClient::new(&config.socket_path);
    let _ = CLIENT.set(client.clone());
    Ok(client)
}

fn call_daemon(method: &str, params: Value) -> Result<Value, String> {
    client()?
        .call(method, params)
        .map_err(|error| error.to_string())
}

async fn call_daemon_async(method: &'static str, params: Value) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || call_daemon(method, params))
        .await
        .map_err(|error| error.to_string())?
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
async fn get_settings() -> Result<AppSettings, String> {
    let value = call_daemon_async(METHOD_SETTINGS_GET, json!({})).await?;
    serde_json::from_value(value).map_err(|error| error.to_string())
}

#[tauri::command]
async fn update_settings(patch: Value) -> Result<AppSettings, String> {
    let value = call_daemon_async(METHOD_SETTINGS_UPDATE, patch).await?;
    serde_json::from_value(value).map_err(|error| error.to_string())
}

#[tauri::command]
async fn reset_settings() -> Result<AppSettings, String> {
    let value = call_daemon_async(METHOD_SETTINGS_RESET, json!({})).await?;
    serde_json::from_value(value).map_err(|error| error.to_string())
}

#[tauri::command]
async fn maintenance_stats() -> Result<Value, String> {
    call_daemon_async(METHOD_MAINTENANCE_STATS, json!({})).await
}

#[tauri::command]
async fn prune_now() -> Result<Value, String> {
    call_daemon_async(METHOD_MAINTENANCE_PRUNE, json!({})).await
}

#[tauri::command]
fn start_daemon() -> Result<String, String> {
    reconcile_services()
}

#[tauri::command]
fn service_reconcile() -> Result<String, String> {
    reconcile_services()
}

#[tauri::command]
async fn service_versions() -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(service_versions_blocking)
        .await
        .map_err(|error| error.to_string())?
}

fn service_versions_blocking() -> Result<Value, String> {
    let config = Config::load().map_err(|error| error.to_string())?;
    let status = service_status_json().unwrap_or(Value::Null);
    let helper_state = service_field(&status, "helper");
    let (daemon, helper) = if config.environment == "prod" {
        let daemon = daemon_version(&config).unwrap_or_default();
        let helper = if helper_state == "enabled" || helper_state == "requires_approval" {
            helper_version().unwrap_or_default()
        } else {
            String::new()
        };
        (daemon, helper)
    } else {
        (String::new(), String::new())
    };
    Ok(json!({
        "app": app_version(),
        "daemon": daemon,
        "helper": helper,
        "agent": service_field(&status, "agent"),
        "helper_service": helper_state,
    }))
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
async fn helper_status() -> Result<Value, String> {
    call_daemon_async(METHOD_CAPTURE_HELPER_STATUS, json!({})).await
}

#[tauri::command]
async fn capture_status() -> Result<Value, String> {
    call_daemon_async(METHOD_CAPTURE_STATUS, json!({})).await
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
async fn ensure_capture() -> Result<Value, String> {
    call_daemon_async(METHOD_CAPTURE_ENSURE, json!({})).await
}

#[tauri::command]
async fn get_status() -> Result<Value, String> {
    call_daemon_async(METHOD_STATUS, json!({})).await
}

#[tauri::command]
async fn list_alerts(
    limit: Option<u32>,
    offset: Option<u32>,
    q: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
) -> Result<Value, String> {
    call_daemon_async(METHOD_ALERTS_LIST, list_params(limit, offset, q, sort, dir)).await
}

#[tauri::command]
async fn list_destinations(
    limit: Option<u32>,
    offset: Option<u32>,
    q: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
) -> Result<Value, String> {
    call_daemon_async(
        METHOD_DESTINATIONS_LIST,
        list_params(limit, offset, q, sort, dir),
    )
    .await
}

#[tauri::command]
async fn list_flows(
    limit: Option<u32>,
    offset: Option<u32>,
    q: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
) -> Result<Value, String> {
    call_daemon_async(METHOD_FLOWS_LIST, list_params(limit, offset, q, sort, dir)).await
}

#[tauri::command]
async fn list_processes(
    limit: Option<u32>,
    offset: Option<u32>,
    q: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
) -> Result<Value, String> {
    call_daemon_async(
        METHOD_PROCESSES_LIST,
        list_params(limit, offset, q, sort, dir),
    )
    .await
}

#[tauri::command]
async fn list_connections(
    limit: Option<u32>,
    offset: Option<u32>,
    q: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
) -> Result<Value, String> {
    call_daemon_async(
        METHOD_CONNECTIONS_LIST,
        list_params(limit, offset, q, sort, dir),
    )
    .await
}

#[tauri::command]
async fn destination_detail(ip: String) -> Result<Value, String> {
    call_daemon_async(METHOD_DESTINATIONS_DETAIL, json!({ "ip": ip })).await
}

#[tauri::command]
async fn process_detail(pid: u32) -> Result<Value, String> {
    call_daemon_async(METHOD_PROCESSES_DETAIL, json!({ "pid": pid })).await
}

#[tauri::command]
async fn list_domains(
    limit: Option<u32>,
    offset: Option<u32>,
    q: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
    trust: Option<String>,
) -> Result<Value, String> {
    let mut params = list_params(limit, offset, q, sort, dir);
    if let Some(trust) = trust {
        params["trust"] = json!(trust);
    }
    call_daemon_async(METHOD_DOMAINS_LIST, params).await
}

#[tauri::command]
async fn list_dns(
    limit: Option<u32>,
    offset: Option<u32>,
    q: Option<String>,
    sort: Option<String>,
    dir: Option<String>,
) -> Result<Value, String> {
    call_daemon_async(METHOD_DNS_LIST, list_params(limit, offset, q, sort, dir)).await
}

#[tauri::command]
async fn list_watched_domains() -> Result<Value, String> {
    call_daemon_async(METHOD_WATCHED_LIST, json!({})).await
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

#[tauri::command]
async fn firewall_status() -> Result<Value, String> {
    call_daemon_async(METHOD_FIREWALL_STATUS, json!({})).await
}

#[tauri::command]
async fn list_firewall_rules() -> Result<Value, String> {
    call_daemon_async(METHOD_FIREWALL_RULES_LIST, json!({})).await
}

#[tauri::command]
fn create_firewall_rule(rule: Value) -> Result<Value, String> {
    client()?
        .call(METHOD_FIREWALL_RULES_CREATE, json!({ "rule": rule }))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn update_firewall_rule(rule: Value) -> Result<Value, String> {
    client()?
        .call(METHOD_FIREWALL_RULES_UPDATE, json!({ "rule": rule }))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn delete_firewall_rule(id: i64) -> Result<Value, String> {
    client()?
        .call(METHOD_FIREWALL_RULES_DELETE, json!({ "id": id }))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn reorder_firewall_rules(ids: Vec<i64>) -> Result<Value, String> {
    client()?
        .call(METHOD_FIREWALL_RULES_REORDER, json!({ "ids": ids }))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn enable_firewall(enabled: bool) -> Result<Value, String> {
    client()?
        .call(METHOD_FIREWALL_ENABLE, json!({ "enabled": enabled }))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn apply_firewall() -> Result<Value, String> {
    client()?
        .call(METHOD_FIREWALL_APPLY, json!({}))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn reset_firewall() -> Result<Value, String> {
    client()?
        .call(METHOD_FIREWALL_RESET, json!({}))
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn list_firewall_blocks() -> Result<Value, String> {
    call_daemon_async(METHOD_FIREWALL_BLOCKS_LIST, json!({})).await
}

#[tauri::command]
fn add_firewall_block(
    address: String,
    direction: String,
    ttl_secs: i64,
    reason: Option<String>,
) -> Result<Value, String> {
    client()?
        .call(
            METHOD_FIREWALL_BLOCKS_ADD,
            json!({
                "address": address,
                "direction": direction,
                "ttl_secs": ttl_secs,
                "reason": reason,
                "source": "manual",
            }),
        )
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn remove_firewall_block(
    id: Option<i64>,
    address: Option<String>,
    direction: Option<String>,
) -> Result<Value, String> {
    client()?
        .call(
            METHOD_FIREWALL_BLOCKS_REMOVE,
            json!({ "id": id, "address": address, "direction": direction }),
        )
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn firewall_counters() -> Result<Value, String> {
    call_daemon_async(METHOD_FIREWALL_COUNTERS, json!({})).await
}

#[tauri::command]
async fn list_firewall_events(limit: Option<u32>) -> Result<Value, String> {
    call_daemon_async(METHOD_FIREWALL_EVENTS_LIST, json!({ "limit": limit })).await
}

fn main() {
    prepare_home();

    tauri::Builder::default()
        .setup(|app| {
            if let Err(error) = reconcile_services() {
                eprintln!("could not reconcile PIGUI services: {error}");
            }
            let _ = app;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_daemon,
            service_reconcile,
            service_versions,
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
            ensure_capture,
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
            list_connections,
            firewall_status,
            list_firewall_rules,
            create_firewall_rule,
            update_firewall_rule,
            delete_firewall_rule,
            reorder_firewall_rules,
            enable_firewall,
            apply_firewall,
            reset_firewall,
            list_firewall_blocks,
            add_firewall_block,
            remove_firewall_block,
            firewall_counters,
            list_firewall_events
        ])
        .run(tauri::generate_context!())
        .expect("error while running PIGUI");
}
