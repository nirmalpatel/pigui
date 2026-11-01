use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use pigui_core::error::{Error, Result};
use pigui_core::rpc::{
    AlertList, AlertsQuery, DestinationList, DestinationsQuery, HealthPayload, METHOD_ALERTS_LIST,
    METHOD_DESTINATIONS_LIST, METHOD_HEALTH, METHOD_SHUTDOWN, METHOD_STATUS, Request, Response,
    StatusPayload,
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
        METHOD_ALERTS_LIST => list_alerts(state, request.params),
        METHOD_DESTINATIONS_LIST => list_destinations(state, request.params),
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
    let (alert_count, destination_count) = query_store(state, |store| {
        Ok((store.count_alerts()?, store.count_destinations()?))
    })?;

    Ok(StatusPayload {
        capabilities: state.capabilities.clone(),
        db_path: state.config.db_path.display().to_string(),
        alert_json: state.config.alert_json.display().to_string(),
        socket_path: state.config.socket_path.display().to_string(),
        uptime_secs: state.uptime_secs(),
        alerts_ingested: state
            .alerts_ingested
            .load(std::sync::atomic::Ordering::Relaxed),
        parse_errors: state
            .parse_errors
            .load(std::sync::atomic::Ordering::Relaxed),
        alert_count,
        destination_count,
        degraded: state.capabilities.degraded_reasons(),
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

fn list_alerts(state: &AppState, params: Value) -> Result<Value> {
    let query: AlertsQuery = serde_json::from_value(params).unwrap_or_default();
    let limit = query.limit.unwrap_or(100).min(1_000);
    let offset = query.offset.unwrap_or(0);

    let (alerts, total) = query_store(state, |store| {
        Ok((store.list_alerts(limit, offset)?, store.count_alerts()?))
    })?;
    Ok(serde_json::to_value(AlertList { alerts, total })?)
}

fn list_destinations(state: &AppState, params: Value) -> Result<Value> {
    let query: DestinationsQuery = serde_json::from_value(params).unwrap_or_default();
    let limit = query.limit.unwrap_or(100).min(1_000);
    let offset = query.offset.unwrap_or(0);

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

fn query_store<T>(state: &AppState, f: impl FnOnce(&Store) -> Result<T>) -> Result<T> {
    let store = state
        .store
        .lock()
        .map_err(|_| Error::Database("store lock poisoned".into()))?;
    f(&store)
}
