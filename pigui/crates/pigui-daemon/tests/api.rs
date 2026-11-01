use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use pigui_core::client::DaemonClient;
use pigui_core::config::Config;
use pigui_core::models::{Alert, SnortCapabilities};
use pigui_core::rpc::{
    AlertList, DestinationList, METHOD_ALERTS_LIST, METHOD_DESTINATIONS_LIST, METHOD_SHUTDOWN,
    METHOD_STATUS, StatusPayload,
};
use pigui_daemon::api;
use pigui_daemon::state::AppState;
use pigui_daemon::store::Store;
use serde_json::json;

fn test_config(root: &Path) -> Config {
    let home = root.to_path_buf();
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
    }
}

fn fixture_alerts() -> Vec<(Alert, String)> {
    include_str!("../../../tests/fixtures/alert_json/valid.jsonl")
        .lines()
        .filter_map(|line| {
            Alert::parse(line)
                .ok()
                .map(|alert| (alert, line.to_string()))
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_status_alerts_and_destinations() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(dir.path());
    std::fs::create_dir_all(&config.run_dir).unwrap();

    let mut store = Store::open_in_memory().unwrap();
    store.insert_alerts(&fixture_alerts()).unwrap();

    let state = Arc::new(AppState::new(
        config.clone(),
        store,
        SnortCapabilities::default(),
    ));
    let server = tokio::spawn({
        let state = state.clone();
        async move { api::serve(state).await.unwrap() }
    });

    let mut ready = false;
    for _ in 0..200 {
        if config.socket_path.exists() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(ready, "daemon socket did not appear");

    let client = DaemonClient::new(config.socket_path.clone());

    let status: StatusPayload = client.call_typed(METHOD_STATUS, json!({})).unwrap();
    assert_eq!(status.alert_count, 5);
    assert_eq!(status.destination_count, 4);

    let alerts: AlertList = client
        .call_typed(METHOD_ALERTS_LIST, json!({ "limit": 10 }))
        .unwrap();
    assert_eq!(alerts.total, 5);
    assert_eq!(alerts.alerts.len(), 5);

    let destinations: DestinationList = client
        .call_typed(METHOD_DESTINATIONS_LIST, json!({ "limit": 10 }))
        .unwrap();
    assert_eq!(destinations.total, 4);

    client.call(METHOD_SHUTDOWN, json!({})).unwrap();
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    assert!(!config.socket_path.exists());
}

#[test]
fn fixture_is_parseable() {
    let alerts = fixture_alerts();
    assert_eq!(alerts.len(), 6);
    let unique = alerts
        .iter()
        .map(|(alert, _)| {
            (
                alert.event_ts,
                alert.gid,
                alert.sid,
                alert.rev,
                alert.src_ip.clone(),
                alert.src_port,
                alert.dst_ip.clone(),
                alert.dst_port,
            )
        })
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(unique.len(), 5);
}
