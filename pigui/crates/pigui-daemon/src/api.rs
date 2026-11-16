use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use pigui_core::bundle;
use pigui_core::error::{Error, Result};
use pigui_core::models::analysis::{
    AnalysisCoverage, AnalysisQuery, AnalysisTableCount, CaptureCoverage, RetentionWindow,
};
use pigui_core::rpc::{
    AlertList, CaptureStartRequest, CaptureState, CaptureStatusPayload, ConnectionList,
    DestinationList, DestinationQuery, DnsList, DomainList, FlowList, HealthPayload, HttpList,
    ListQuery, METHOD_ALERTS_LIST, METHOD_ANALYSIS_FINDINGS, METHOD_ANALYSIS_OVERVIEW,
    METHOD_CAPTURE_ENSURE, METHOD_CAPTURE_HELPER_STATUS, METHOD_CAPTURE_START,
    METHOD_CAPTURE_STATUS, METHOD_CAPTURE_STOP, METHOD_CONNECTIONS_LIST,
    METHOD_DESTINATIONS_DETAIL, METHOD_DESTINATIONS_LIST, METHOD_DNS_LIST, METHOD_DOMAINS_LIST,
    METHOD_DOMAINS_SET_TRUST, METHOD_FIREWALL_APPLY, METHOD_FIREWALL_BLOCKS_ADD,
    METHOD_FIREWALL_BLOCKS_LIST, METHOD_FIREWALL_BLOCKS_REMOVE, METHOD_FIREWALL_COUNTERS,
    METHOD_FIREWALL_ENABLE, METHOD_FIREWALL_EVENTS_LIST, METHOD_FIREWALL_RESET,
    METHOD_FIREWALL_RULES_CREATE, METHOD_FIREWALL_RULES_DELETE, METHOD_FIREWALL_RULES_LIST,
    METHOD_FIREWALL_RULES_REORDER, METHOD_FIREWALL_RULES_UPDATE, METHOD_FIREWALL_STATUS,
    METHOD_FLOWS_LIST, METHOD_HEALTH, METHOD_HTTP_LIST, METHOD_MAINTENANCE_PRUNE,
    METHOD_MAINTENANCE_STATS, METHOD_PROCESSES_DETAIL, METHOD_PROCESSES_LIST, METHOD_QUIC_LIST,
    METHOD_SETTINGS_GET, METHOD_SETTINGS_RESET, METHOD_SETTINGS_UPDATE, METHOD_SHUTDOWN,
    METHOD_SNORT_STATUS, METHOD_STATUS, METHOD_TLS_LIST, METHOD_WATCHED_ADD, METHOD_WATCHED_LIST,
    METHOD_WATCHED_REMOVE, MaintenanceStats, ProcessList, ProcessQuery, QuicList, Request,
    Response, SetTrustRequest, SnortStatusPayload, StatusPayload, TlsList, WatchedList,
    WatchedRequest,
};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::firewall;
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

const MAX_RPC_LINE_BYTES: usize = 1024 * 1024;

async fn handle(stream: UnixStream, state: Arc<AppState>) -> std::io::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut buffer = Vec::new();

    loop {
        buffer.clear();
        let read = reader.read_until(b'\n', &mut buffer).await?;
        if read == 0 {
            break;
        }

        let response = if buffer.len() > MAX_RPC_LINE_BYTES {
            Response::failure(0, "request too large")
        } else {
            let line = String::from_utf8_lossy(&buffer);
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<Request>(line) {
                Ok(request) => dispatch(&state, request).await,
                Err(error) => Response::failure(0, format!("invalid request: {error}")),
            }
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
        METHOD_ANALYSIS_OVERVIEW => analysis_overview(state, request.params).await,
        METHOD_ANALYSIS_FINDINGS => analysis_findings(state, request.params).await,
        METHOD_SNORT_STATUS => {
            snort_status(state).and_then(|payload| Ok(serde_json::to_value(payload)?))
        }
        METHOD_CAPTURE_STATUS => capture_status(state).await,
        METHOD_CAPTURE_START => capture_start(state, request.params).await,
        METHOD_CAPTURE_ENSURE => capture_ensure(state).await,
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
        METHOD_FIREWALL_STATUS => firewall::status(state)
            .await
            .and_then(|payload| Ok(serde_json::to_value(payload)?)),
        METHOD_FIREWALL_RULES_LIST => {
            firewall::list_rules(state).and_then(|payload| Ok(serde_json::to_value(payload)?))
        }
        METHOD_FIREWALL_RULES_CREATE => firewall::create_rule(state, request.params)
            .and_then(|payload| Ok(serde_json::to_value(payload)?)),
        METHOD_FIREWALL_RULES_UPDATE => firewall::update_rule(state, request.params)
            .and_then(|payload| Ok(serde_json::to_value(payload)?)),
        METHOD_FIREWALL_RULES_DELETE => {
            firewall::delete_rule(state, request.params).map(Value::from)
        }
        METHOD_FIREWALL_RULES_REORDER => firewall::reorder_rules(state, request.params)
            .and_then(|payload| Ok(serde_json::to_value(payload)?)),
        METHOD_FIREWALL_ENABLE => firewall::enable(state, request.params)
            .and_then(|payload| Ok(serde_json::to_value(payload)?)),
        METHOD_FIREWALL_APPLY => firewall::apply(state)
            .await
            .and_then(|payload| Ok(serde_json::to_value(payload)?)),
        METHOD_FIREWALL_RESET => firewall::reset(state)
            .await
            .and_then(|payload| Ok(serde_json::to_value(payload)?)),
        METHOD_FIREWALL_BLOCKS_LIST => {
            firewall::list_blocks(state).and_then(|payload| Ok(serde_json::to_value(payload)?))
        }
        METHOD_FIREWALL_BLOCKS_ADD => firewall::add_block(state, request.params)
            .await
            .and_then(|payload| Ok(serde_json::to_value(payload)?)),
        METHOD_FIREWALL_BLOCKS_REMOVE => firewall::remove_block(state, request.params)
            .await
            .map(Value::from),
        METHOD_FIREWALL_COUNTERS => firewall::counters().await,
        METHOD_FIREWALL_EVENTS_LIST => firewall::events(request.params).await,
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

const STATUS_CACHE_TTL: Duration = Duration::from_secs(10);

fn status(state: &AppState) -> Result<StatusPayload> {
    if let Some(cached) = state.cached_status(STATUS_CACHE_TTL) {
        return Ok(cached);
    }
    let (
        alert_count,
        destination_count,
        connection_count,
        active_flows,
        active_processes,
        dns_count,
        tls_count,
        http_count,
        quic_count,
        domain_count,
        firewall_state,
        firewall_rule_count,
        firewall_block_count,
    ) = query_store(state, |store| {
        Ok((
            store.count_alerts()?,
            store.count_destinations()?,
            store.count_connections()?,
            store.count_flows()?,
            store.count_processes()?,
            store.count_dns()?,
            store.count_tls()?,
            store.count_http()?,
            store.count_quic()?,
            store.count_domains()?,
            store.get_firewall_state()?,
            store.count_firewall_rules()?,
            store.count_firewall_blocks(crate::store::unix_now())?,
        ))
    })?;
    let snort = pigui_snort::status::status(&state.config);
    let capture = state.capture();
    let capture_interface = capture.as_ref().map(|capture| capture.interface.clone());
    let capture_mode = capture.as_ref().map(|capture| capture.mode.clone());
    let mut degraded = state.capabilities.degraded_reasons();
    if let Some(warning) = capture_interface_warning(capture_interface.as_deref()) {
        degraded.push(warning);
    }
    let config_path = active_snort_config(&state.config);
    let snort_config_hash = pigui_snort::config_gen::file_hash(&config_path);
    let snort_config_path = Some(config_path.display().to_string());
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
    let now = crate::store::unix_now();
    state.observe_extractor_size(extractor_size, now);
    let extractor_idle = state.extractor_is_idle(now, alerts_ingested, extractor_ingested);

    let payload = StatusPayload {
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
        connection_count,
        degraded,
        environment: state.config.environment.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        snort_running: snort.running,
        snort_pid: snort.pid,
        snort_interface: capture_interface.clone().or(snort.interface),
        capture_running: capture.is_some(),
        capture_interface,
        capture_mode,
        capture_follows_default_route: state.config.snort_interface.is_none(),
        snort_config_hash,
        snort_config_path,
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
        firewall_enabled: firewall_state.enabled,
        firewall_mode: firewall_state.mode.as_str().to_string(),
        firewall_rule_count,
        firewall_block_count,
        firewall_needs_apply: firewall_state.needs_apply(),
        collector_error: state.collector_error(),
    };
    state.store_status(payload.clone());
    Ok(payload)
}

async fn capture_status(state: &AppState) -> Result<Value> {
    let _guard = state.capture_lock.lock().await;
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
    let _guard = state.capture_lock.lock().await;
    let capture = capture_start_locked(state, &request.interface).await?;
    Ok(serde_json::to_value(capture)?)
}

pub(crate) async fn capture_start_locked(
    state: &AppState,
    requested_interface: &str,
) -> Result<CaptureState> {
    state.set_capture_suppressed(false);
    let helper_interface = requested_interface.to_string();
    let helper =
        tokio::task::spawn_blocking(move || pigui_core::helper::enable_capture(&helper_interface))
            .await
            .map_err(|error| Error::Rpc(format!("capture helper task failed: {error}")))??;
    let capture = capture_state_from_helper(state, &helper, requested_interface, None);
    query_store(state, |store| store.save_capture_state(&capture))?;
    state.set_capture(Some(capture.clone()));
    Ok(capture)
}

fn capture_state_from_helper(
    state: &AppState,
    helper: &Value,
    fallback_interface: &str,
    fallback_started_at: Option<i64>,
) -> CaptureState {
    let data = helper.get("data").cloned().unwrap_or(Value::Null);
    CaptureState {
        interface: data
            .get("interface")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| fallback_interface.to_string()),
        snort_pid: data
            .get("snort_pid")
            .or_else(|| data.get("pid"))
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
        started_at: data
            .get("started_at")
            .and_then(Value::as_i64)
            .or(fallback_started_at)
            .unwrap_or_else(crate::store::unix_now),
    }
}

async fn capture_ensure(state: &AppState) -> Result<Value> {
    let _guard = state.capture_lock.lock().await;
    state.set_capture_suppressed(false);
    let helper = capture_helper_status().await.ok();
    if let Some(helper) = helper.as_ref() {
        let running = helper
            .pointer("/data/capture_running")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if running {
            if let Some(capture) = state.capture() {
                return Ok(serde_json::to_value(capture)?);
            }
            let interface = helper
                .pointer("/data/interface")
                .and_then(Value::as_str)
                .or(state.config.snort_interface.as_deref())
                .unwrap_or("unknown")
                .to_string();
            let capture = capture_state_from_helper(state, helper, &interface, None);
            query_store(state, |store| store.save_capture_state(&capture))?;
            state.set_capture(Some(capture.clone()));
            return Ok(serde_json::to_value(capture)?);
        }
        if state.capture().is_some() {
            query_store(state, |store| store.clear_capture_state())?;
            state.set_capture(None);
        }
    } else if let Some(capture) = state.capture() {
        return Ok(serde_json::to_value(capture)?);
    }

    let interface = state
        .config
        .snort_interface
        .clone()
        .or_else(pigui_collector::default_interface)
        .ok_or_else(|| Error::Config("no default capture interface found".into()))?;
    let capture = capture_start_locked(state, &interface).await?;
    Ok(serde_json::to_value(capture)?)
}

async fn capture_stop(state: &AppState) -> Result<Value> {
    let _guard = state.capture_lock.lock().await;
    capture_stop_locked(state, true).await?;
    Ok(Value::from(true))
}

pub(crate) async fn capture_stop_locked(state: &AppState, user_initiated: bool) -> Result<()> {
    tokio::task::spawn_blocking(pigui_core::helper::disable_capture)
        .await
        .map_err(|error| Error::Rpc(format!("capture helper task failed: {error}")))??;
    query_store(state, |store| store.clear_capture_state())?;
    state.set_capture(None);
    if user_initiated {
        state.set_capture_suppressed(true);
    }
    Ok(())
}

pub(crate) async fn capture_switch_locked(
    state: &AppState,
    interface: &str,
) -> Result<CaptureState> {
    if let Err(error) = capture_stop_locked(state, false).await {
        tracing::warn!(%error, "capture watcher could not stop capture before switching");
    }
    let mut last_error = None;
    for attempt in 0..5 {
        match capture_start_locked(state, interface).await {
            Ok(capture) => return Ok(capture),
            Err(error) => {
                last_error = Some(error);
                tokio::time::sleep(Duration::from_millis(500 * (attempt + 1))).await;
            }
        }
    }
    Err(last_error.unwrap_or_else(|| Error::Rpc("capture switch failed".into())))
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
        config_path: Some(active_snort_config(&state.config).display().to_string()),
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

fn active_snort_config(config: &pigui_core::config::Config) -> std::path::PathBuf {
    bundle::snort_config().unwrap_or_else(|| config.snort_config_dir.join("snort.lua"))
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

async fn analysis_overview(state: &AppState, params: Value) -> Result<Value> {
    let query: AnalysisQuery = if params.is_null() {
        AnalysisQuery::default()
    } else {
        serde_json::from_value(params)?
    };
    let coverage = analysis_coverage(state)?;
    let store = state.store.clone();
    let payload = tokio::task::spawn_blocking(move || {
        let store = store
            .lock()
            .map_err(|_| Error::Database("store lock poisoned".into()))?;
        store.analysis_overview(&query, coverage)
    })
    .await
    .map_err(|error| Error::Rpc(format!("analysis task failed: {error}")))??;
    Ok(serde_json::to_value(payload)?)
}

async fn analysis_findings(state: &AppState, params: Value) -> Result<Value> {
    let query: AnalysisQuery = if params.is_null() {
        AnalysisQuery::default()
    } else {
        serde_json::from_value(params)?
    };
    let coverage = analysis_coverage(state)?;
    let store = state.store.clone();
    let limitations = coverage.limitations;
    let payload = tokio::task::spawn_blocking(move || {
        let store = store
            .lock()
            .map_err(|_| Error::Database("store lock poisoned".into()))?;
        store.analysis_findings(&query, limitations)
    })
    .await
    .map_err(|error| Error::Rpc(format!("analysis task failed: {error}")))??;
    Ok(serde_json::to_value(payload)?)
}

fn capture_interface_warning(capture_interface: Option<&str>) -> Option<String> {
    let default_interface = pigui_collector::default_interface();
    pigui_collector::interface_mismatch_warning(capture_interface, default_interface.as_deref())
}

fn analysis_coverage(state: &AppState) -> Result<AnalysisCoverage> {
    let settings = state.settings();
    let capture = state.capture();
    let mut limitations = Vec::new();
    if let Some(warning) =
        capture_interface_warning(capture.as_ref().map(|capture| capture.interface.as_str()))
    {
        limitations.push(warning);
    }
    let snort = pigui_snort::status::status(&state.config);
    let alerts_ingested = state
        .alerts_ingested
        .load(std::sync::atomic::Ordering::Relaxed);
    let extractor_ingested = state
        .extractor_ingested
        .load(std::sync::atomic::Ordering::Relaxed);
    let extractor_size = std::fs::metadata(&state.config.extractor_json)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let now = crate::store::unix_now();
    state.observe_extractor_size(extractor_size, now);
    let extractor_idle = state.extractor_is_idle(now, alerts_ingested, extractor_ingested);
    let table_counts = query_store(state, |store| store.table_counts())?
        .into_iter()
        .map(|count| AnalysisTableCount {
            name: count.name,
            rows: count.rows,
        })
        .collect();
    Ok(AnalysisCoverage {
        environment: state.config.environment.clone(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        capture: capture.as_ref().map(|capture| CaptureCoverage {
            running: true,
            interface: Some(capture.interface.clone()),
            mode: Some(capture.mode.clone()),
        }),
        snort_running: snort.running,
        snort_pid: snort.pid,
        uptime_secs: state.uptime_secs(),
        parse_errors: state
            .parse_errors
            .load(std::sync::atomic::Ordering::Relaxed),
        extractor_idle,
        collector_error: state.collector_error(),
        table_counts,
        retention: RetentionWindow {
            flows_secs: settings.retention.flows_secs,
            processes_secs: settings.retention.processes_secs,
            alerts_days: settings.retention.alerts_days,
            connections_days: settings.retention.connections_days,
            observations_days: settings.retention.observations_days,
            domains_days: settings.retention.domains_days,
            endpoints_days: settings.retention.endpoints_days,
            ptr_days: settings.retention.ptr_days,
        },
        limitations,
    })
}

fn query_store<T>(state: &AppState, f: impl FnOnce(&Store) -> Result<T>) -> Result<T> {
    tokio::task::block_in_place(|| {
        let store = state
            .store
            .lock()
            .map_err(|_| Error::Database("store lock poisoned".into()))?;
        f(&store)
    })
}
