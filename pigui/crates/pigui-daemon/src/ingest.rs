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

        state.record_extractor(inserted, malformed);
        if inserted > 0 || malformed > 0 {
            tracing::info!(inserted, malformed, "ingested extractor batch");
        }
    }
}

/// Poll nettop on a dedicated thread so the async runtime is never blocked.
pub fn spawn_process_collector(state: Arc<AppState>) {
    std::thread::spawn(move || {
        let interface = state
            .config
            .snort_interface
            .clone()
            .or_else(pigui_collector::default_interface);
        let collector = MacosCollector::new(interface.clone());
        let poll = Duration::from_millis(state.config.process_poll_ms.max(250));

        tracing::info!(
            interface = interface.as_deref().unwrap_or("all"),
            poll_ms = poll.as_millis(),
            "process collector started"
        );

        while !state.is_shutting_down() {
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
            std::thread::sleep(poll);
        }
    });
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
