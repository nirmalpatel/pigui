use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use pigui_core::error::{Error, Result};
use pigui_core::rpc::{
    AlertList, AlertsQuery, ConnectionList, DestinationList, DestinationQuery, DnsList, DomainList,
    FlowList, HealthPayload, HttpList, METHOD_ALERTS_LIST, METHOD_CONNECTIONS_LIST,
    METHOD_DESTINATIONS_DETAIL, METHOD_DESTINATIONS_LIST, METHOD_DNS_LIST, METHOD_DOMAINS_LIST,
    METHOD_DOMAINS_SET_TRUST, METHOD_FLOWS_LIST, METHOD_HEALTH, METHOD_HTTP_LIST,
    METHOD_PROCESSES_DETAIL, METHOD_PROCESSES_LIST, METHOD_QUIC_LIST, METHOD_SHUTDOWN,
    METHOD_SNORT_STATUS, METHOD_STATUS, METHOD_TLS_LIST, METHOD_WATCHED_ADD, METHOD_WATCHED_LIST,
    METHOD_WATCHED_REMOVE, ProcessList, ProcessQuery, QuicList, Request, Response, SetTrustRequest,
    SnortStatusPayload, StatusPayload, TlsList, WatchedList, WatchedRequest,
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
    let extractor_idle = state.config.mode == "live"
        && alerts_ingested > 0
        && extractor_ingested == 0
        && state.uptime_secs() > 30;

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
        mode: state.config.mode.clone(),
        snort_running: snort.running,
        snort_pid: snort.pid,
        snort_interface: snort.interface,
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
    Ok(SnortStatusPayload {
        running: status.running,
        pid: status.pid,
        interface: status.interface,
        config_path: status.config_path,
        log_dir: status.log_dir,
        extractor_json: status.extractor_json,
        control_socket: status.control_socket,
        pidfile: status.pidfile,
    })
}

fn list_alerts(state: &AppState, params: Value) -> Result<Value> {
    let (limit, offset) = query_limits(params);
    let (alerts, total) = query_store(state, |store| {
        Ok((store.list_alerts(limit, offset)?, store.count_alerts()?))
    })?;
    Ok(serde_json::to_value(AlertList { alerts, total })?)
}

fn list_destinations(state: &AppState, params: Value) -> Result<Value> {
    let (limit, offset) = query_limits(params);
    let (destinations, total) = query_store(state, |store| {
        Ok((
            store.list_destinations(limit, offset)?,
            store.count_destinations()?,
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
    let (limit, offset) = query_limits(params);
    let (domains, total) = query_store(state, |store| {
        Ok((store.list_domains(limit, offset)?, store.count_domains()?))
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
    let (limit, offset) = query_limits(params);
    let (flows, total) = query_store(state, |store| {
        Ok((store.list_flows(limit, offset)?, store.count_flows()?))
    })?;
    Ok(serde_json::to_value(FlowList { flows, total })?)
}

fn list_processes(state: &AppState, params: Value) -> Result<Value> {
    let (limit, offset) = query_limits(params);
    let (processes, total) = query_store(state, |store| {
        Ok((
            store.list_processes(limit, offset)?,
            store.count_processes()?,
        ))
    })?;
    Ok(serde_json::to_value(ProcessList { processes, total })?)
}

fn list_connections(state: &AppState, params: Value) -> Result<Value> {
    let (limit, offset) = query_limits(params);
    let (connections, total) = query_store(state, |store| {
        Ok((
            store.list_connections(limit, offset)?,
            store.count_connections()?,
        ))
    })?;
    Ok(serde_json::to_value(ConnectionList { connections, total })?)
}

fn list_dns(state: &AppState, params: Value) -> Result<Value> {
    let (limit, offset) = query_limits(params);
    let (observations, total) = query_store(state, |store| {
        Ok((store.list_dns(limit, offset)?, store.count_dns()?))
    })?;
    Ok(serde_json::to_value(DnsList {
        observations,
        total,
    })?)
}

fn list_tls(state: &AppState, params: Value) -> Result<Value> {
    let (limit, offset) = query_limits(params);
    let (observations, total) = query_store(state, |store| {
        Ok((store.list_tls(limit, offset)?, store.count_tls()?))
    })?;
    Ok(serde_json::to_value(TlsList {
        observations,
        total,
    })?)
}

fn list_http(state: &AppState, params: Value) -> Result<Value> {
    let (limit, offset) = query_limits(params);
    let (observations, total) = query_store(state, |store| {
        Ok((store.list_http(limit, offset)?, store.count_http()?))
    })?;
    Ok(serde_json::to_value(HttpList {
        observations,
        total,
    })?)
}

fn list_quic(state: &AppState, params: Value) -> Result<Value> {
    let (limit, offset) = query_limits(params);
    let (observations, total) = query_store(state, |store| {
        Ok((store.list_quic(limit, offset)?, store.count_quic()?))
    })?;
    Ok(serde_json::to_value(QuicList {
        observations,
        total,
    })?)
}

fn query_limits(params: Value) -> (u32, u32) {
    let query: AlertsQuery = serde_json::from_value(params).unwrap_or_default();
    (
        query.limit.unwrap_or(200).clamp(1, 1_000),
        query.offset.unwrap_or(0),
    )
}

fn query_store<T>(state: &AppState, f: impl FnOnce(&Store) -> Result<T>) -> Result<T> {
    let store = state
        .store
        .lock()
        .map_err(|_| Error::Database("store lock poisoned".into()))?;
    f(&store)
}
