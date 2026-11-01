#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use pigui_core::client::DaemonClient;
use pigui_core::config::Config;
use pigui_core::rpc::{
    METHOD_ALERTS_LIST, METHOD_CONNECTIONS_LIST, METHOD_DESTINATIONS_LIST, METHOD_FLOWS_LIST,
    METHOD_PROCESSES_LIST, METHOD_STATUS,
};
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

fn client() -> Result<DaemonClient, String> {
    let config = Config::load().map_err(|error| error.to_string())?;
    Ok(DaemonClient::new(&config.socket_path))
}

#[tauri::command]
fn get_status() -> Result<Value, String> {
    client()?
        .call(METHOD_STATUS, json!({}))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_alerts(limit: Option<u32>) -> Result<Value, String> {
    client()?
        .call(METHOD_ALERTS_LIST, json!({ "limit": limit.unwrap_or(200) }))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_destinations(limit: Option<u32>) -> Result<Value, String> {
    client()?
        .call(
            METHOD_DESTINATIONS_LIST,
            json!({ "limit": limit.unwrap_or(200) }),
        )
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_flows(limit: Option<u32>) -> Result<Value, String> {
    client()?
        .call(METHOD_FLOWS_LIST, json!({ "limit": limit.unwrap_or(300) }))
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_processes(limit: Option<u32>) -> Result<Value, String> {
    client()?
        .call(
            METHOD_PROCESSES_LIST,
            json!({ "limit": limit.unwrap_or(200) }),
        )
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn list_connections(limit: Option<u32>) -> Result<Value, String> {
    client()?
        .call(
            METHOD_CONNECTIONS_LIST,
            json!({ "limit": limit.unwrap_or(200) }),
        )
        .map_err(|error| error.to_string())
}

fn main() {
    prepare_home();

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_status,
            list_alerts,
            list_destinations,
            list_flows,
            list_processes,
            list_connections
        ])
        .run(tauri::generate_context!())
        .expect("error while running PIGUI");
}
