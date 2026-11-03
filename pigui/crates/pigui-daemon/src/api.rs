use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use pigui_core::error::{Error, Result};
use pigui_core::rpc::{
    AlertList, CaptureStartRequest, CaptureState, CaptureStatusPayload, ConnectionList,
    DestinationList, DestinationQuery, DnsList, DomainList, FlowList, HealthPayload, HttpList,
    ListQuery, METHOD_ALERTS_LIST, METHOD_CAPTURE_HELPER_STATUS, METHOD_CAPTURE_START,
    METHOD_CAPTURE_STATUS, METHOD_CAPTURE_STOP, METHOD_CONNECTIONS_LIST,
    METHOD_DESTINATIONS_DETAIL, METHOD_DESTINATIONS_LIST, METHOD_DNS_LIST, METHOD_DOMAINS_LIST,
    METHOD_DOMAINS_SET_TRUST, METHOD_FLOWS_LIST, METHOD_HEALTH, METHOD_HTTP_LIST,
    METHOD_MAINTENANCE_PRUNE, METHOD_MAINTENANCE_STATS, METHOD_PROCESSES_DETAIL,
    METHOD_PROCESSES_LIST, METHOD_QUIC_LIST, METHOD_SETTINGS_GET, METHOD_SETTINGS_RESET,
    METHOD_SETTINGS_UPDATE, METHOD_SHUTDOWN, METHOD_SNORT_STATUS, METHOD_STATUS, METHOD_TLS_LIST,
    METHOD_WATCHED_ADD, METHOD_WATCHED_LIST, METHOD_WATCHED_REMOVE, MaintenanceStats, ProcessList,
    ProcessQuery, QuicList, Request, Response, SetTrustRequest, SnortStatusPayload, StatusPayload,
    TlsList, WatchedList, WatchedRequest,
};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::state::AppState;
use crate::store::Store;

pub async fn serve(state: Arc<AppState>) -> anyhow::Result<()> {
    let path = state.config.socket_path.clone();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }

    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    tracing::info!(socket = %path.display(), "daemon API listening");

    loop {
        if state.is_shutting_down() {
            break;
        }
        tokio::select! {
            _ = state.wait_for_shutdown() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(error) = handle(stream, state).await {
                                tracing::debug!(%error, "rpc connection ended");
                            }
                        });
                    }
                    Err(error) => tracing::warn!(%error, "failed to accept rpc connection"),
                }
            }
        }
    }

    let _ = std::fs::remove_file(&path);
    tracing::info!("daemon API stopped");
    Ok(())
}

async fn handle(stream: UnixStream, state: Arc<AppState>) -> std::io::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => dispatch(&state, request).await,
            Err(error) => Response::failure(0, format!("invalid request: {error}")),
        };

        let mut encoded = serde_json::to_vec(&response).map_err(std::io::Error::other)?;
        encoded.push(b'\n');
        write_half.write_all(&encoded).await?;
    }

    Ok(())
}

async fn dispatch(state: &AppState, request: Request) -> Response {
    let id = request.id;
    let result = match request.method.as_str() {
        METHOD_STATUS => status(state).and_then(|payload| Ok(serde_json::to_value(payload)?)),
        METHOD_HEALTH => health(state).and_then(|payload| Ok(serde_json::to_value(payload)?)),
        METHOD_SNORT_STATUS => {
            snort_status(state).and_then(|payload| Ok(serde_json::to_value(payload)?))
        }
        METHOD_CAPTURE_STATUS => capture_status(state).await,
        METHOD_CAPTURE_START => capture_start(state, request.params).await,
        METHOD_CAPTURE_STOP => capture_stop(state).await,
        METHOD_CAPTURE_HELPER_STATUS => capture_helper_status().await,
        METHOD_ALERTS_LIST => list_alerts(state, request.params),
        METHOD_DESTINATIONS_LIST => list_destinations(state, request.params),
        METHOD_DESTINATIONS_DETAIL => destination_detail(state, request.params),
        METHOD_FLOWS_LIST => list_flows(state, request.params),
        METHOD_PROCESSES_LIST => list_processes(state, request.params),
        METHOD_PROCESSES_DETAIL => process_detail(state, request.params),
        METHOD_CONNECTIONS_LIST => list_connections(state, request.params),
        METHOD_DOMAINS_LIST => list_domains(state, request.params),
        METHOD_DOMAINS_SET_TRUST => set_domain_trust(state, request.params),
        METHOD_WATCHED_LIST => list_watched_domains(state),
        METHOD_WATCHED_ADD => add_watched_domain(state, request.params),
        METHOD_WATCHED_REMOVE => remove_watched_domain(state, request.params),
        METHOD_DNS_LIST => list_dns(state, request.params),
        METHOD_TLS_LIST => list_tls(state, request.params),
        METHOD_HTTP_LIST => list_http(state, request.params),
        METHOD_QUIC_LIST => list_quic(state, request.params),
        METHOD_SETTINGS_GET => settings_get(state),
        METHOD_SETTINGS_UPDATE => settings_update(state, request.params),
        METHOD_SETTINGS_RESET => settings_reset(state),
        METHOD_MAINTENANCE_STATS => maintenance_stats(state),
        METHOD_MAINTENANCE_PRUNE => maintenance_prune(state),
        METHOD_SHUTDOWN => {
            state.request_shutdown();
            Ok(Value::from(true))
        }
        other => Err(Error::Rpc(format!("unknown method: {other}"))),
    };

    match result {
        Ok(data) => Response::success(id, data),
        Err(error) => Response::failure(id, error.to_string()),
    }
}

fn status(state: &AppState) -> Result<StatusPayload> {
    let (
        alert_count,
        destination_count,
        active_flows,
        active_processes,
        dns_count,
        tls_count,
        http_count,
        quic_count,
        domain_count,
    ) = query_store(state, |store| {
        Ok((
            store.count_alerts()?,
            store.count_destinations()?,
            store.count_flows()?,
            store.count_processes()?,
            store.count_dns()?,
            store.count_tls()?,
            store.count_http()?,
            store.count_quic()?,
            store.count_domains()?,
        ))
    })?;
    let snort = pigui_snort::status::status(&state.config);
    let capture = state.capture();
    let capture_interface = capture.as_ref().map(|capture| capture.interface.clone());
    let capture_mode = capture.as_ref().map(|capture| capture.mode.clone());
    let config_path = state
        .capabilities
        .config_path
        .as_deref()
        .map(Path::new)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| state.config.snort_config_dir.join("snort.lua"));
    let snort_config_hash = pigui_snort::config_gen::file_hash(&config_path);
    let extractor_metadata = std::fs::metadata(&state.config.extractor_json).ok();
    let extractor_size = extractor_metadata
        .as_ref()
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let extractor_modified = extractor_metadata
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs() as i64);
    let alerts_ingested = state
        .alerts_ingested
        .load(std::sync::atomic::Ordering::Relaxed);
    let extractor_ingested = state
        .extractor_ingested
        .load(std::sync::atomic::Ordering::Relaxed);
    let extractor_idle = alerts_ingested > 0 && extractor_ingested == 0 && state.uptime_secs() > 30;

    Ok(StatusPayload {
        capabilities: state.capabilities.clone(),
        db_path: state.config.db_path.display().to_string(),
        alert_json: state.config.alert_json.display().to_string(),
        socket_path: state.config.socket_path.display().to_string(),
        uptime_secs: state.uptime_secs(),
        alerts_ingested,
        parse_errors: state
            .parse_errors
            .load(std::sync::atomic::Ordering::Relaxed),
        alert_count,
        destination_count,
        degraded: state.capabilities.degraded_reasons(),
        environment: state.config.environment.clone(),
        snort_running: snort.running,
        snort_pid: snort.pid,
        snort_interface: capture_interface.clone().or(snort.interface),
        capture_running: capture.is_some(),
        capture_interface,
        capture_mode,
        snort_config_hash,
        active_flows,
        active_processes,
        extractor_ingested,
        extractor_file: state.config.extractor_json.display().to_string(),
        extractor_size,
        extractor_modified,
        extractor_last_ingest: state.extractor_last_ingest(),
        extractor_idle,
        dns_count,
        tls_count,
        http_count,
        quic_count,
        domain_count,
        collector_error: state.collector_error(),
    })
}

async fn capture_status(state: &AppState) -> Result<Value> {
    let helper = capture_helper_status().await.unwrap_or(Value::Null);
    let helper_running = helper
        .pointer("/data/capture_running")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut capture = state.capture();
    if capture.is_some() && !helper_running && !helper.is_null() {
        query_store(state, |store| store.clear_capture_state())?;
        state.set_capture(None);
        capture = None;
    }
    Ok(serde_json::to_value(CaptureStatusPayload {
        capture,
        helper,
    })?)
}

async fn capture_start(state: &AppState, params: Value) -> Result<Value> {
    let request: CaptureStartRequest = serde_json::from_value(params)?;
    let requested_interface = request.interface;
    let helper_interface = requested_interface.clone();
    let helper =
        tokio::task::spawn_blocking(move || pigui_core::helper::enable_capture(&helper_interface))
            .await
            .map_err(|error| Error::Rpc(format!("capture helper task failed: {error}")))??;

    let data = helper.get("data").cloned().unwrap_or(Value::Null);
    let capture = CaptureState {
        interface: data
            .get("interface")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| requested_interface.clone()),
        snort_pid: data
            .get("pid")
            .and_then(Value::as_u64)
            .map(|value| value as u32),
        log_dir: data
            .get("log_dir")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        mode: if state.config.environment == "prod" {
            "helper".to_string()
        } else {
            "dev-helper".to_string()
        },
        started_at: crate::store::unix_now(),
    };
    query_store(state, |store| store.save_capture_state(&capture))?;
    state.set_capture(Some(capture.clone()));
    Ok(serde_json::to_value(capture)?)
}

async fn capture_stop(state: &AppState) -> Result<Value> {
    tokio::task::spawn_blocking(pigui_core::helper::disable_capture)
        .await
        .map_err(|error| Error::Rpc(format!("capture helper task failed: {error}")))??;
    query_store(state, |store| store.clear_capture_state())?;
    state.set_capture(None);
    Ok(Value::from(true))
}

async fn capture_helper_status() -> Result<Value> {
    tokio::task::spawn_blocking(pigui_core::helper::status)
        .await
        .map_err(|error| Error::Rpc(format!("capture helper task failed: {error}")))?
}

fn health(state: &AppState) -> Result<HealthPayload> {
    let degraded = state.capabilities.degraded_reasons();
    Ok(HealthPayload {
        status: if degraded.is_empty() {
            "ok".to_string()
        } else {
            "degraded".to_string()
        },
        uptime_secs: state.uptime_secs(),
        alerts_ingested: state
            .alerts_ingested
            .load(std::sync::atomic::Ordering::Relaxed),
        parse_errors: state
            .parse_errors
            .load(std::sync::atomic::Ordering::Relaxed),
    })
}

fn snort_status(state: &AppState) -> Result<SnortStatusPayload> {
    let status = pigui_snort::status::status(&state.config);
    let interface = state
        .capture()
        .map(|capture| capture.interface)
        .or(status.interface);
    Ok(SnortStatusPayload {
        running: status.running,
        pid: status.pid,
        interface,
        config_path: state
            .capabilities
            .config_path
            .clone()
            .or(status.config_path),
        log_dir: status.log_dir,
        extractor_json: status.extractor_json,
        control_socket: status.control_socket,
        pidfile: status.pidfile,
    })
}

fn list_alerts(state: &AppState, params: Value) -> Result<Value> {
    let q = query_list(state, params);
    let (alerts, total) = query_store(state, |store| {
        Ok((store.list_alerts_query(&q)?, store.count_alerts_query(&q)?))
    })?;
    Ok(serde_json::to_value(AlertList { alerts, total })?)
}

fn list_destinations(state: &AppState, params: Value) -> Result<Value> {
    let q = query_list(state, params);
    let (destinations, total) = query_store(state, |store| {
        Ok((
            store.list_destinations_query(&q)?,
            store.count_destinations_query(&q)?,
        ))
    })?;
    Ok(serde_json::to_value(DestinationList {
        destinations,
        total,
    })?)
}

fn destination_detail(state: &AppState, params: Value) -> Result<Value> {
    let query: DestinationQuery = serde_json::from_value(params)?;
    let detail = query_store(state, |store| store.destination_detail(&query.ip))?
        .ok_or_else(|| Error::Rpc(format!("destination not found: {}", query.ip)))?;
    Ok(serde_json::to_value(detail)?)
}

fn process_detail(state: &AppState, params: Value) -> Result<Value> {
    let query: ProcessQuery = serde_json::from_value(params)?;
    let detail = query_store(state, |store| store.process_detail(query.pid))?
        .ok_or_else(|| Error::Rpc(format!("process not found: {}", query.pid)))?;
    Ok(serde_json::to_value(detail)?)
}

fn list_domains(state: &AppState, params: Value) -> Result<Value> {
    let q = query_list(state, params);
    let (domains, total) = query_store(state, |store| {
        Ok((
            store.list_domains_query(&q)?,
            store.count_domains_query(&q)?,
        ))
    })?;
    Ok(serde_json::to_value(DomainList { domains, total })?)
}

fn set_domain_trust(state: &AppState, params: Value) -> Result<Value> {
    let request: SetTrustRequest = serde_json::from_value(params)?;
    query_store(state, |store| {
        store.set_domain_trust(
            &request.registrable_domain,
            request.state,
            request.note.as_deref(),
        )
    })?;
    Ok(Value::from(true))
}

fn list_watched_domains(state: &AppState) -> Result<Value> {
    let watched = query_store(state, |store| store.list_watched_domains())?;
    Ok(serde_json::to_value(WatchedList { watched })?)
}

fn add_watched_domain(state: &AppState, params: Value) -> Result<Value> {
    let request: WatchedRequest = serde_json::from_value(params)?;
    let watched = query_store(state, |store| store.add_watched_domain(&request.domain))?;
    Ok(serde_json::to_value(watched)?)
}

fn remove_watched_domain(state: &AppState, params: Value) -> Result<Value> {
    let request: WatchedRequest = serde_json::from_value(params)?;
    query_store(state, |store| store.remove_watched_domain(&request.domain))?;
    Ok(Value::from(true))
}

fn list_flows(state: &AppState, params: Value) -> Result<Value> {
    let q = query_list(state, params);
    let (flows, total) = query_store(state, |store| {
        Ok((store.list_flows_query(&q)?, store.count_flows_query(&q)?))
    })?;
    Ok(serde_json::to_value(FlowList { flows, total })?)
}

fn list_processes(state: &AppState, params: Value) -> Result<Value> {
    let q = query_list(state, params);
    let (processes, total) = query_store(state, |store| {
        Ok((
            store.list_processes_query(&q)?,
            store.count_processes_query(&q)?,
        ))
    })?;
    Ok(serde_json::to_value(ProcessList { processes, total })?)
}

fn list_connections(state: &AppState, params: Value) -> Result<Value> {
    let q = query_list(state, params);
    let (connections, total) = query_store(state, |store| {
        Ok((
            store.list_connections_query(&q)?,
            store.count_connections_query(&q)?,
        ))
    })?;
    Ok(serde_json::to_value(ConnectionList { connections, total })?)
}

fn list_dns(state: &AppState, params: Value) -> Result<Value> {
    let q = query_list(state, params);
    let (observations, total) = query_store(state, |store| {
        Ok((store.list_dns_query(&q)?, store.count_dns_query(&q)?))
    })?;
    Ok(serde_json::to_value(DnsList {
        observations,
        total,
    })?)
}

fn list_tls(state: &AppState, params: Value) -> Result<Value> {
    let q = query_list(state, params);
    let (observations, total) = query_store(state, |store| {
        Ok((store.list_tls_query(&q)?, store.count_tls_query(&q)?))
    })?;
    Ok(serde_json::to_value(TlsList {
        observations,
        total,
    })?)
}

fn list_http(state: &AppState, params: Value) -> Result<Value> {
    let q = query_list(state, params);
    let (observations, total) = query_store(state, |store| {
        Ok((store.list_http_query(&q)?, store.count_http_query(&q)?))
    })?;
    Ok(serde_json::to_value(HttpList {
        observations,
        total,
    })?)
}

fn list_quic(state: &AppState, params: Value) -> Result<Value> {
    let q = query_list(state, params);
    let (observations, total) = query_store(state, |store| {
        Ok((store.list_quic_query(&q)?, store.count_quic_query(&q)?))
    })?;
    Ok(serde_json::to_value(QuicList {
        observations,
        total,
    })?)
}

fn query_list(state: &AppState, params: Value) -> ListQuery {
    let mut query: ListQuery = serde_json::from_value(params).unwrap_or_default();
    let settings = state.settings();
    query.limit = Some(
        query
            .limit
            .unwrap_or(settings.ui.page_size)
            .clamp(1, settings.limits.max_page_size),
    );
    query.offset = Some(query.offset.unwrap_or(0));
    if let Some(search) = query.q.as_mut() {
        *search = search.trim().to_string();
        if search.is_empty() {
            query.q = None;
        }
    }
    query
}

fn settings_get(state: &AppState) -> Result<Value> {
    Ok(serde_json::to_value(state.settings())?)
}

fn settings_update(state: &AppState, params: Value) -> Result<Value> {
    let settings = query_store(state, |store| store.update_settings(&params))?;
    state.set_settings(settings.clone());
    Ok(serde_json::to_value(settings)?)
}

fn settings_reset(state: &AppState) -> Result<Value> {
    let settings = query_store(state, |store| store.reset_settings())?;
    state.set_settings(settings.clone());
    Ok(serde_json::to_value(settings)?)
}

fn maintenance_stats(state: &AppState) -> Result<Value> {
    let counts = query_store(state, |store| store.table_counts())?;
    let db_path = state.config.db_path.display().to_string();
    let mut db_bytes = std::fs::metadata(&state.config.db_path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    for suffix in ["-wal", "-shm"] {
        let path = format!("{}{suffix}", state.config.db_path.display());
        db_bytes += std::fs::metadata(path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
    }
    let (last_run, last_deleted) = state.maintenance_info();
    Ok(serde_json::to_value(MaintenanceStats {
        db_path,
        db_bytes,
        table_counts: counts,
        last_run,
        last_deleted,
    })?)
}

fn maintenance_prune(state: &AppState) -> Result<Value> {
    let settings = state.settings();
    let result = query_store(state, |store| store.prune(&settings))?;
    state.record_maintenance(&result);
    Ok(serde_json::to_value(result)?)
}

fn query_store<T>(state: &AppState, f: impl FnOnce(&Store) -> Result<T>) -> Result<T> {
    let store = state
        .store
        .lock()
        .map_err(|_| Error::Database("store lock poisoned".into()))?;
    f(&store)
}
