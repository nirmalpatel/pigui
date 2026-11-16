use std::sync::Arc;
use std::time::Duration;

use pigui_core::error::{Error, Result};
use pigui_core::helper;
use pigui_firewall::{
    Direction, FirewallBlock, FirewallBlockList, FirewallBlockRemoveRequest, FirewallBlockRequest,
    FirewallMode, FirewallRule, FirewallRuleIdRequest, FirewallRuleList, FirewallRuleRequest,
    FirewallStatusPayload, FirewallToggleRequest, compile_firewall,
};
use serde_json::Value;
use tokio::time::interval;

use crate::state::AppState;
use crate::store::{Store, unix_now};

pub async fn status(state: &AppState) -> Result<FirewallStatusPayload> {
    let (fw_state, rule_count, block_count) = with_store(state, |store| {
        Ok((
            store.get_firewall_state()?,
            store.count_firewall_rules()?,
            store.count_firewall_blocks(unix_now())?,
        ))
    })?;
    let (helper, helper_error) = match helper_status().await {
        Ok(value) => (value, None),
        Err(error) => (Value::Null, Some(error.to_string())),
    };
    Ok(FirewallStatusPayload {
        state: fw_state,
        rule_count,
        block_count,
        helper,
        helper_error,
    })
}

pub fn list_rules(state: &AppState) -> Result<FirewallRuleList> {
    with_store(state, |store| {
        Ok(FirewallRuleList {
            rules: store.list_firewall_rules()?,
            state: store.get_firewall_state()?,
        })
    })
}

pub fn create_rule(state: &AppState, params: Value) -> Result<FirewallRule> {
    let request: FirewallRuleRequest = serde_json::from_value(params)?;
    with_store(state, |store| store.create_firewall_rule(&request.rule))
}

pub fn update_rule(state: &AppState, params: Value) -> Result<FirewallRule> {
    let request: FirewallRuleRequest = serde_json::from_value(params)?;
    with_store(state, |store| store.update_firewall_rule(&request.rule))
}

pub fn delete_rule(state: &AppState, params: Value) -> Result<bool> {
    let request: FirewallRuleIdRequest = serde_json::from_value(params)?;
    with_store(state, |store| store.delete_firewall_rule(request.id))
}

pub fn reorder_rules(state: &AppState, params: Value) -> Result<Vec<FirewallRule>> {
    let request: pigui_firewall::FirewallReorderRequest = serde_json::from_value(params)?;
    with_store(state, |store| store.reorder_firewall_rules(&request.ids))
}

pub fn enable(state: &AppState, params: Value) -> Result<pigui_firewall::FirewallState> {
    let request: FirewallToggleRequest = serde_json::from_value(params)?;
    with_store(state, |store| {
        let mut current = store.get_firewall_state()?;
        current.enabled = request.enabled;
        store.save_firewall_state(&current)
    })
}

pub async fn apply(state: &AppState) -> Result<FirewallStatusPayload> {
    let _guard = state.firewall_lock.lock().await;

    let (compiled, fw_state) = with_store(state, |store| {
        let rules = store.list_firewall_rules()?;
        Ok((compile_firewall(&rules)?, store.get_firewall_state()?))
    })?;
    let generation = fw_state.generation;

    let response = if fw_state.enabled {
        let block = compiled.block_anchor.clone();
        let allow = compiled.allow_anchor.clone();
        match tokio::task::spawn_blocking(move || {
            helper::firewall_apply(&block, &allow, generation, true)
        })
        .await
        {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => {
                record_error(state, &error);
                return Err(error);
            }
            Err(error) => {
                let error = Error::Rpc(format!("firewall helper task failed: {error}"));
                record_error(state, &error);
                return Err(error);
            }
        }
    } else {
        match tokio::task::spawn_blocking(|| helper::firewall_flush(true)).await {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => {
                record_error(state, &error);
                return Err(error);
            }
            Err(error) => {
                let error = Error::Rpc(format!("firewall helper task failed: {error}"));
                record_error(state, &error);
                return Err(error);
            }
        }
    };

    let applied_at = response
        .pointer("/data/applied_at")
        .and_then(Value::as_i64)
        .unwrap_or_else(unix_now);
    let pf_enabled_by_pigui = response
        .pointer("/data/pf_enabled_by_pigui")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if fw_state.enabled {
        sync_active_blocks(state).await;
    }

    let (next, rule_count, block_count) = with_store(state, |store| {
        let mut next = store.get_firewall_state()?;
        next.applied_generation = generation;
        next.applied_at = Some(applied_at);
        next.last_error = None;
        next.pf_enabled_by_pigui = pf_enabled_by_pigui;
        let next = store.save_firewall_state(&next)?;
        Ok((
            next,
            store.count_firewall_rules()?,
            store.count_firewall_blocks(unix_now())?,
        ))
    })?;

    Ok(FirewallStatusPayload {
        state: next,
        rule_count,
        block_count,
        helper: response,
        helper_error: None,
    })
}

pub async fn reset(state: &AppState) -> Result<FirewallStatusPayload> {
    let _guard = state.firewall_lock.lock().await;

    with_store(state, |store| {
        store.delete_all_firewall_rules()?;
        store.clear_firewall_blocks()?;
        let mut current = store.get_firewall_state()?;
        current.enabled = false;
        current.mode = FirewallMode::Blocklist;
        store.save_firewall_state(&current)?;
        Ok(())
    })?;

    let response = match tokio::task::spawn_blocking(|| helper::firewall_flush(true)).await {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            record_error(state, &error);
            return Err(error);
        }
        Err(error) => {
            let error = Error::Rpc(format!("firewall helper task failed: {error}"));
            record_error(state, &error);
            return Err(error);
        }
    };

    let (next, rule_count, block_count) = with_store(state, |store| {
        let mut next = store.get_firewall_state()?;
        next.applied_generation = next.generation;
        next.applied_at = Some(
            response
                .pointer("/data/applied_at")
                .and_then(Value::as_i64)
                .unwrap_or_else(unix_now),
        );
        next.last_error = None;
        next.pf_enabled_by_pigui = false;
        let next = store.save_firewall_state(&next)?;
        Ok((
            next,
            store.count_firewall_rules()?,
            store.count_firewall_blocks(unix_now())?,
        ))
    })?;

    Ok(FirewallStatusPayload {
        state: next,
        rule_count,
        block_count,
        helper: response,
        helper_error: None,
    })
}

pub fn list_blocks(state: &AppState) -> Result<FirewallBlockList> {
    with_store(state, |store| {
        Ok(FirewallBlockList {
            blocks: store.list_firewall_blocks(unix_now())?,
        })
    })
}

pub async fn add_block(state: &AppState, params: Value) -> Result<FirewallBlock> {
    let request: FirewallBlockRequest = serde_json::from_value(params)?;
    let _guard = state.firewall_lock.lock().await;
    let block = FirewallBlock {
        id: 0,
        address: request.address,
        direction: request.direction,
        ttl_secs: request.ttl_secs,
        reason: request.reason,
        source: request.source,
        created_at: 0,
        expires_at: 0,
    };
    let stored = with_store(state, |store| store.add_firewall_block(&block, unix_now()))?;
    let address = stored.address.clone();
    let direction = stored.direction;
    let ttl_secs = stored.ttl_secs.max(0) as u64;

    match tokio::task::spawn_blocking(move || {
        helper::firewall_block(&address, direction.as_str(), ttl_secs)
    })
    .await
    {
        Ok(Ok(_)) => Ok(stored),
        Ok(Err(error)) => {
            let _ = with_store(state, |store| store.remove_firewall_block(stored.id));
            Err(error)
        }
        Err(error) => {
            let _ = with_store(state, |store| store.remove_firewall_block(stored.id));
            Err(Error::Rpc(format!("firewall helper task failed: {error}")))
        }
    }
}

pub async fn remove_block(state: &AppState, params: Value) -> Result<bool> {
    let request: FirewallBlockRemoveRequest = serde_json::from_value(params)?;
    let _guard = state.firewall_lock.lock().await;

    let block = if let Some(id) = request.id {
        with_store(state, |store| store.get_firewall_block(id))?
    } else if let Some(address) = request.address {
        let direction = request.direction.unwrap_or(Direction::Both);
        with_store(state, |store| {
            store.find_firewall_block(&address, direction)
        })?
    } else {
        return Err(Error::Firewall("block id or address is required".into()));
    };
    let Some(block) = block else {
        return Ok(false);
    };

    let address = block.address.clone();
    let direction = block.direction;
    match tokio::task::spawn_blocking(move || {
        helper::firewall_unblock(&address, Some(direction.as_str()))
    })
    .await
    {
        Ok(Ok(_)) => with_store(state, |store| store.remove_firewall_block(block.id)),
        Ok(Err(error)) => Err(error),
        Err(error) => Err(Error::Rpc(format!("firewall helper task failed: {error}"))),
    }
}

pub async fn counters() -> Result<Value> {
    tokio::task::spawn_blocking(helper::firewall_counters)
        .await
        .map_err(|error| Error::Rpc(format!("firewall helper task failed: {error}")))?
}

pub async fn events(params: Value) -> Result<Value> {
    let request: pigui_firewall::FirewallEventsRequest = serde_json::from_value(params)?;
    let limit = request.limit.unwrap_or(100).clamp(1, 500);
    tokio::task::spawn_blocking(move || helper::firewall_events(limit))
        .await
        .map_err(|error| Error::Rpc(format!("firewall helper task failed: {error}")))?
}

async fn sync_active_blocks(state: &AppState) {
    let blocks = match with_store(state, |store| store.list_firewall_blocks(unix_now())) {
        Ok(blocks) => blocks,
        Err(error) => {
            tracing::warn!(%error, "failed to read active firewall blocks");
            return;
        }
    };
    for block in blocks {
        let address = block.address.clone();
        let direction = block.direction;
        let ttl_secs = block.ttl_secs.max(0) as u64;
        let result = tokio::task::spawn_blocking(move || {
            helper::firewall_block(&address, direction.as_str(), ttl_secs)
        })
        .await;
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                tracing::warn!(%error, block = %block.address, "failed to restore PF block");
            }
            Err(error) => {
                tracing::warn!(%error, block = %block.address, "PF block task failed");
            }
        }
    }
}

pub fn spawn_reconciler(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(30));
        let mut ticks: u64 = 0;
        loop {
            tokio::select! {
                _ = state.wait_for_shutdown() => break,
                _ = ticker.tick() => {}
            }
            ticks = ticks.wrapping_add(1);

            let now = unix_now();
            let expired = match with_store(&state, |store| store.expired_firewall_blocks(now)) {
                Ok(blocks) => blocks,
                Err(error) => {
                    tracing::warn!(%error, "failed to read expired firewall blocks");
                    Vec::new()
                }
            };
            for block in expired {
                let address = block.address.clone();
                let direction = block.direction;
                let result = tokio::task::spawn_blocking(move || {
                    helper::firewall_unblock(&address, Some(direction.as_str()))
                })
                .await;
                match result {
                    Ok(Ok(_)) => {
                        if let Err(error) =
                            with_store(&state, |store| store.remove_firewall_block(block.id))
                        {
                            tracing::warn!(%error, "failed to delete expired firewall block");
                        }
                    }
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "failed to remove expired PF block");
                    }
                    Err(error) => {
                        tracing::warn!(%error, "expired PF block task failed");
                    }
                }
            }

            let (needs_apply, enabled, applied_generation) = match with_store(&state, |store| {
                let current = store.get_firewall_state()?;
                Ok((
                    current.needs_apply(),
                    current.enabled,
                    current.applied_generation,
                ))
            }) {
                Ok(values) => values,
                Err(error) => {
                    tracing::warn!(%error, "failed to read firewall state");
                    continue;
                }
            };

            if needs_apply {
                if let Err(error) = apply(&state).await {
                    tracing::warn!(%error, "firewall reconcile failed");
                }
                continue;
            }

            // While the firewall is disabled, only check for helper drift occasionally.
            if !enabled && !ticks.is_multiple_of(2) {
                continue;
            }

            let helper = match helper_status().await {
                Ok(value) => value,
                Err(error) => {
                    tracing::warn!(%error, "firewall helper status failed");
                    continue;
                }
            };
            let helper_generation = helper
                .pointer("/data/generation")
                .and_then(Value::as_i64)
                .unwrap_or(-1);
            let block_loaded = helper
                .pointer("/data/block_anchor_loaded")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let pf_enabled = helper
                .pointer("/data/pf_enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let pf_owned = helper
                .pointer("/data/pf_enabled_by_pigui")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let drift = if enabled {
                !block_loaded || !pf_enabled || helper_generation != applied_generation
            } else {
                block_loaded || pf_owned
            };
            if drift && let Err(error) = apply(&state).await {
                tracing::warn!(%error, "firewall drift reconcile failed");
            }
        }
    });
}

async fn helper_status() -> Result<Value> {
    tokio::task::spawn_blocking(helper::firewall_status)
        .await
        .map_err(|error| Error::Rpc(format!("firewall helper task failed: {error}")))?
}

fn record_error(state: &AppState, error: &Error) {
    if let Ok(mut current) = with_store(state, |store| store.get_firewall_state()) {
        current.last_error = Some(error.to_string());
        let _ = with_store(state, |store| store.save_firewall_state(&current));
    }
}

fn with_store<T>(state: &AppState, f: impl FnOnce(&Store) -> Result<T>) -> Result<T> {
    tokio::task::block_in_place(|| {
        let store = state
            .store
            .lock()
            .map_err(|_| Error::Database("store lock poisoned".into()))?;
        f(&store)
    })
}
