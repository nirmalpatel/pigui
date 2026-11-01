#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

use pigui_core::client::DaemonClient;
use pigui_core::config::Config;
use pigui_core::rpc::{
    METHOD_ALERTS_LIST, METHOD_CONNECTIONS_LIST, METHOD_DESTINATIONS_LIST, METHOD_FLOWS_LIST,
    METHOD_PROCESSES_LIST, METHOD_STATUS,
};
use pigui_core::settings::{AppSettings, ThemeMode};
use serde_json::{Value, json};
use tauri::Manager;

mod settings;

use settings::UiSettingsStore;

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

fn settings_db_path(app: &tauri::App) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(home) = std::env::var_os("PIGUI_HOME") {
        return Ok(PathBuf::from(home).join("var/lib/pigui-gui.db"));
    }
    Ok(app.path().app_data_dir()?.join("settings.sqlite3"))
}

#[tauri::command]
fn get_settings(store: tauri::State<'_, UiSettingsStore>) -> Result<AppSettings, String> {
    store.get_settings()
}

#[tauri::command]
fn update_settings(
    theme: ThemeMode,
    store: tauri::State<'_, UiSettingsStore>,
) -> Result<AppSettings, String> {
    store.set_theme(theme)?;
    store.get_settings()
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
        .setup(|app| {
            let path = settings_db_path(app)?;
            let store = UiSettingsStore::open(&path).map_err(std::io::Error::other)?;
            app.manage(store);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            get_settings,
            update_settings,
            list_alerts,
            list_destinations,
            list_flows,
            list_processes,
            list_connections
        ])
        .run(tauri::generate_context!())
        .expect("error while running PIGUI");
}
