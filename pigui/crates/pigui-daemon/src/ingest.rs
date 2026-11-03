use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use pigui_collector::{Collector, MacosCollector};
use pigui_core::error::Result;
use pigui_core::models::{Alert, ExtractorRecord};
use pigui_snort::Tailer;
use tokio::time::interval;

use crate::state::AppState;
use crate::store::{IngestStats, Store};

/// Ingest a file once. Used by `--once` and the CLI diagnostics path.
pub fn ingest_file(store: &mut Store, path: &Path) -> Result<IngestStats> {
    let mut tailer = Tailer::new(path);
    let (entries, malformed) = parse_lines(tailer.poll()?);
    let mut stats = store.insert_alerts(&entries)?;
    stats.malformed = malformed;
    Ok(stats)
}

/// Continuously tail the alert file and persist new alerts.
pub async fn run(state: Arc<AppState>, mut tailer: Tailer) {
    let mut ticker = interval(Duration::from_millis(500));
    let path = tailer.path().to_path_buf();

    loop {
        tokio::select! {
            _ = state.wait_for_shutdown() => break,
            _ = ticker.tick() => {}
        }

        let lines = match tailer.poll() {
            Ok(lines) => lines,
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "failed to tail alert file");
                continue;
            }
        };
        if lines.is_empty() {
            continue;
        }

        let (entries, malformed) = parse_lines(lines);
        let mut stats = IngestStats {
            malformed,
            ..IngestStats::default()
        };

        if !entries.is_empty() {
            match state.store.lock() {
                Ok(mut store) => match store.insert_alerts(&entries) {
                    Ok(inserted) => stats.inserted = inserted.inserted,
                    Err(error) => {
                        tracing::error!(%error, "failed to persist alerts");
                    }
                },
                Err(_) => tracing::error!("store lock poisoned; dropping batch"),
            }
        }

        state.record_ingest(&stats);
        if stats.inserted > 0 {
            tracing::info!(
                inserted = stats.inserted,
                duplicates = stats.duplicates,
                malformed = stats.malformed,
                "ingested alert batch"
            );
        }
    }
}

/// Continuously tail the extractor JSONL file and persist protocol records.
pub async fn run_extractor(state: Arc<AppState>, mut tailer: Tailer) {
    let mut ticker = interval(Duration::from_millis(500));
    let path = tailer.path().to_path_buf();

    loop {
        tokio::select! {
            _ = state.wait_for_shutdown() => break,
            _ = ticker.tick() => {}
        }

        let lines = match tailer.poll() {
            Ok(lines) => lines,
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "failed to tail extractor file");
                continue;
            }
        };
        if lines.is_empty() {
            continue;
        }

        let mut records = Vec::with_capacity(lines.len());
        let mut malformed = 0;
        for line in lines {
            match ExtractorRecord::parse(&line) {
                Ok(record) => records.push(record),
                Err(error) => {
                    malformed += 1;
                    tracing::warn!(%error, "skipping malformed extractor record");
                }
            }
        }

        let mut inserted = 0;
        if !records.is_empty() {
            match state.store.lock() {
                Ok(mut store) => match store
                    .insert_extractor_records(&records, crate::store::unix_now())
                {
                    Ok(stats) => inserted = stats.inserted,
                    Err(error) => tracing::error!(%error, "failed to persist extractor records"),
                },
                Err(_) => tracing::error!("store lock poisoned; dropping extractor batch"),
            }
        }

        state.record_extractor(inserted, malformed, crate::store::unix_now());
        if inserted > 0 || malformed > 0 {
            tracing::info!(inserted, malformed, "ingested extractor batch");
        }
    }
}

/// Poll nettop on a dedicated thread so the async runtime is never blocked.
pub fn spawn_process_collector(state: Arc<AppState>) {
    std::thread::spawn(move || {
        let mut current_interface =
            state
                .capture()
                .map(|capture| capture.interface)
                .or_else(|| {
                    state
                        .config
                        .snort_interface
                        .clone()
                        .or_else(pigui_collector::default_interface)
                });
        let mut collector = MacosCollector::new(current_interface.clone());
        let initial_poll = state.settings().collector.poll_ms.max(250);

        tracing::info!(
            interface = current_interface.as_deref().unwrap_or("all"),
            poll_ms = initial_poll,
            "process collector started"
        );

        while !state.is_shutting_down() {
            let interface = state
                .capture()
                .map(|capture| capture.interface)
                .or_else(|| {
                    state
                        .config
                        .snort_interface
                        .clone()
                        .or_else(pigui_collector::default_interface)
                });
            if interface != current_interface {
                tracing::info!(
                    interface = interface.as_deref().unwrap_or("all"),
                    "process collector interface changed"
                );
                collector = MacosCollector::new(interface.clone());
                current_interface = interface;
            }
            match collector.snapshot() {
                Ok(snapshot) => {
                    let now = crate::store::unix_now();
                    match state.store.lock() {
                        Ok(mut store) => match store.apply_snapshot(&snapshot, now) {
                            Ok(()) => state.record_snapshot(now),
                            Err(error) => {
                                state.set_collector_error(error.to_string());
                                tracing::warn!(%error, "failed to store nettop snapshot");
                            }
                        },
                        Err(_) => state.set_collector_error("store lock poisoned"),
                    }
                }
                Err(error) => {
                    state.set_collector_error(error.to_string());
                    tracing::warn!(%error, "nettop collection failed");
                }
            }
            std::thread::sleep(Duration::from_millis(
                state.settings().collector.poll_ms.max(250),
            ));
        }
    });
}

pub fn spawn_maintenance(state: Arc<AppState>) {
    std::thread::spawn(move || {
        loop {
            let settings = state.settings();
            let result = match state.store.lock() {
                Ok(store) => store.prune(&settings),
                Err(_) => return,
            };
            match result {
                Ok(report) => {
                    if report.total_deleted > 0 {
                        tracing::info!(
                            deleted = report.total_deleted,
                            "maintenance pruned old rows"
                        );
                    }
                    state.record_maintenance(&report);
                }
                Err(error) => tracing::warn!(%error, "maintenance prune failed"),
            }

            let interval = state.settings().maintenance.interval_secs.max(30);
            let mut remaining = interval;
            while remaining > 0 && !state.is_shutting_down() {
                let step = remaining.min(1);
                std::thread::sleep(Duration::from_secs(step));
                remaining -= step;
            }
            if state.is_shutting_down() {
                return;
            }
        }
    });
}

pub fn spawn_name_resolver(state: Arc<AppState>) {
    std::thread::spawn(move || {
        while !state.is_shutting_down() {
            resolve_ptr_names(&state);
            resolve_watched_domains(&state);
            let loop_secs = state.settings().resolver.loop_secs.max(5);
            let mut remaining = loop_secs;
            while remaining > 0 && !state.is_shutting_down() {
                let step = remaining.min(1);
                std::thread::sleep(Duration::from_secs(step));
                remaining -= step;
            }
        }
    });
}

fn resolve_ptr_names(state: &Arc<AppState>) {
    let now = crate::store::unix_now();
    let settings = state.settings();
    let ips = match state.store.lock() {
        Ok(store) => store
            .pending_ptr_ips(now, settings.resolver.ptr_batch)
            .unwrap_or_default(),
        Err(_) => return,
    };

    for ip in ips {
        if state.is_shutting_down() {
            break;
        }
        let Ok(address) = ip.parse::<IpAddr>() else {
            continue;
        };
        if !is_public_ip(address) {
            if let Ok(store) = state.store.lock() {
                let _ = store.save_ptr_result(
                    &ip,
                    None,
                    "skipped",
                    Some("non-public address"),
                    now,
                    settings.resolver.ptr_ok_ttl_secs,
                    settings.resolver.ptr_fail_ttl_secs,
                );
            }
            continue;
        }

        let result = dns_lookup::lookup_addr(&address);
        if let Ok(store) = state.store.lock() {
            match result {
                Ok(hostname) => {
                    let _ = store.save_ptr_result(
                        &ip,
                        Some(&hostname),
                        "ok",
                        None,
                        now,
                        settings.resolver.ptr_ok_ttl_secs,
                        settings.resolver.ptr_fail_ttl_secs,
                    );
                }
                Err(error) => {
                    let _ = store.save_ptr_result(
                        &ip,
                        None,
                        "error",
                        Some(&error.to_string()),
                        now,
                        settings.resolver.ptr_ok_ttl_secs,
                        settings.resolver.ptr_fail_ttl_secs,
                    );
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn resolve_watched_domains(state: &Arc<AppState>) {
    let now = crate::store::unix_now();
    let settings = state.settings();
    let due = match state.store.lock() {
        Ok(store) => store
            .due_watched_domains(
                now,
                settings.resolver.watched_interval_secs,
                settings.resolver.watched_batch,
            )
            .unwrap_or_default(),
        Err(_) => return,
    };

    for domain in due {
        if state.is_shutting_down() {
            break;
        }

        let mut ips = Vec::new();
        let mut error = None;
        match (domain.as_str(), 443).to_socket_addrs() {
            Ok(addresses) => {
                for address in addresses {
                    ips.push(address.ip().to_string());
                }
                ips.sort();
                ips.dedup();
            }
            Err(cause) => error = Some(cause.to_string()),
        }

        if let Ok(store) = state.store.lock() {
            let _ = store.save_watched_result(&domain, &ips, error.as_deref(), now);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !(address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
                || address.is_unspecified())
        }
        IpAddr::V6(address) => {
            !(address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_unique_local()
                || address.is_unicast_link_local())
        }
    }
}

fn parse_lines(lines: Vec<String>) -> (Vec<(Alert, String)>, u64) {
    let mut entries = Vec::with_capacity(lines.len());
    let mut malformed = 0;

    for line in lines {
        match Alert::parse(&line) {
            Ok(alert) => entries.push((alert, line)),
            Err(error) => {
                malformed += 1;
                tracing::warn!(%error, "skipping malformed alert");
            }
        }
    }

    (entries, malformed)
}

#[cfg(test)]
mod tests {
    use super::is_public_ip;

    #[test]
    fn filters_non_public_addresses() {
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_public_ip("10.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("192.168.1.1".parse().unwrap()));
        assert!(!is_public_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("fe80::1".parse().unwrap()));
        assert!(!is_public_ip("fd00::1".parse().unwrap()));
    }
}
