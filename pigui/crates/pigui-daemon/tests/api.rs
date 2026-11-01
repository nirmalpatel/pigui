use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use pigui_collector::{CollectorSnapshot, ProcessSample, SocketSample};
use pigui_core::client::DaemonClient;
use pigui_core::config::Config;
use pigui_core::models::{Alert, ExtractorRecord, SnortCapabilities};
use pigui_core::rpc::{
    AlertList, ConnectionList, DestinationDetail, DestinationList, DomainList, METHOD_ALERTS_LIST,
    METHOD_CONNECTIONS_LIST, METHOD_DESTINATIONS_DETAIL, METHOD_DESTINATIONS_LIST,
    METHOD_DOMAINS_LIST, METHOD_DOMAINS_SET_TRUST, METHOD_FLOWS_LIST, METHOD_PROCESSES_DETAIL,
    METHOD_PROCESSES_LIST, METHOD_SHUTDOWN, METHOD_STATUS, METHOD_WATCHED_ADD, METHOD_WATCHED_LIST,
    METHOD_WATCHED_REMOVE, ProcessDetail, ProcessList, StatusPayload, WatchedList,
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
        mode: "fixture".to_string(),
        snort_interface: None,
        snort_log_dir: home.join("var/log/snort"),
        snort_config_dir: home.join("var/snort"),
        extractor_json: home.join("var/log/snort/file_connector_pigui_transmit"),
        snort_pidfile: home.join("var/log/snort/snort.pid"),
        snort_control_socket: home.join("var/run/snort.sock"),
        process_poll_ms: 1000,
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
    store
        .apply_snapshot(
            &CollectorSnapshot {
                processes: vec![ProcessSample {
                    pid: 42,
                    name: "Chrome".into(),
                    path: Some("/Applications/Google Chrome".into()),
                    user: Some("nirmal".into()),
                    bytes_in: 100,
                    bytes_out: 200,
                    connection_count: 1,
                }],
                sockets: vec![SocketSample {
                    proto: "tcp".into(),
                    client_ip: "10.0.0.5".into(),
                    client_port: 50000,
                    server_ip: "198.51.100.10".into(),
                    server_port: 443,
                    state: Some("Established".into()),
                    interface: Some("en0".into()),
                    bytes_ab: 100,
                    bytes_ba: 200,
                    pid: 42,
                    process_name: "Chrome".into(),
                }],
            },
            1000,
        )
        .unwrap();
    let record = ExtractorRecord::parse(
        r#"{"ts":1001,"uid":"C1","id.orig_h":"10.0.0.5","id.orig_p":50000,"id.resp_h":"198.51.100.10","id.resp_p":443,"proto":"tcp","service":"ssl","conn_state":"SF","duration":1.0,"orig_pkts":2,"resp_pkts":3,"orig_bytes":100,"resp_bytes":200}"#,
    )
    .unwrap();
    store.insert_extractor_records(&[record], 1001).unwrap();
    let tls = ExtractorRecord::parse(
        r#"{"ts":1002,"id.orig_h":"10.0.0.5","id.resp_h":"198.51.100.10","id.resp_p":443,"server_name":"api.spotify.com","version":"TLSv1.3","validation_status":"valid"}"#,
    )
    .unwrap();
    store.insert_extractor_records(&[tls], 1002).unwrap();

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
    assert_eq!(status.tls_count, 1);
    assert_eq!(status.domain_count, 1);
    assert!(!status.extractor_file.is_empty());

    let alerts: AlertList = client
        .call_typed(METHOD_ALERTS_LIST, json!({ "limit": 10 }))
        .unwrap();
    assert_eq!(alerts.total, 5);
    assert_eq!(alerts.alerts.len(), 5);

    let destinations: DestinationList = client
        .call_typed(METHOD_DESTINATIONS_LIST, json!({ "limit": 10 }))
        .unwrap();
    assert_eq!(destinations.total, 4);

    assert_eq!(status.active_flows, 1);
    assert_eq!(status.active_processes, 1);
    let flows = client
        .call_typed::<pigui_core::rpc::FlowList>(METHOD_FLOWS_LIST, json!({ "limit": 10 }))
        .unwrap();
    assert_eq!(flows.flows.len(), 1);
    assert_eq!(flows.flows[0].process_name.as_deref(), Some("Chrome"));

    let processes: ProcessList = client
        .call_typed(METHOD_PROCESSES_LIST, json!({ "limit": 10 }))
        .unwrap();
    assert_eq!(processes.processes.len(), 1);

    let connections: ConnectionList = client
        .call_typed(METHOD_CONNECTIONS_LIST, json!({ "limit": 10 }))
        .unwrap();
    assert_eq!(connections.connections.len(), 1);
    assert_eq!(connections.connections[0].pid, Some(42));

    let detail: DestinationDetail = client
        .call_typed(METHOD_DESTINATIONS_DETAIL, json!({ "ip": "198.51.100.10" }))
        .unwrap();
    assert_eq!(detail.destination.domains.len(), 1);
    assert_eq!(detail.processes[0].pid, Some(42));

    let process_detail: ProcessDetail = client
        .call_typed(METHOD_PROCESSES_DETAIL, json!({ "pid": 42 }))
        .unwrap();
    assert_eq!(process_detail.destinations.len(), 1);

    let domains: DomainList = client
        .call_typed(METHOD_DOMAINS_LIST, json!({ "limit": 10 }))
        .unwrap();
    assert_eq!(domains.total, 1);
    assert_eq!(domains.domains[0].domain, "spotify.com");

    client
        .call(
            METHOD_DOMAINS_SET_TRUST,
            json!({ "registrable_domain": "spotify.com", "state": "trusted" }),
        )
        .unwrap();
    let domains: DomainList = client
        .call_typed(METHOD_DOMAINS_LIST, json!({ "limit": 10 }))
        .unwrap();
    assert_eq!(domains.domains[0].trust_state.as_str(), "trusted");

    client
        .call(METHOD_WATCHED_ADD, json!({ "domain": "open.spotify.com" }))
        .unwrap();
    let watched: WatchedList = client.call_typed(METHOD_WATCHED_LIST, json!({})).unwrap();
    assert_eq!(watched.watched.len(), 1);
    assert_eq!(watched.watched[0].registrable_domain, "spotify.com");
    client
        .call(
            METHOD_WATCHED_REMOVE,
            json!({ "domain": "open.spotify.com" }),
        )
        .unwrap();
    let watched: WatchedList = client.call_typed(METHOD_WATCHED_LIST, json!({})).unwrap();
    assert!(watched.watched.is_empty());

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
