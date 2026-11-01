use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use pigui_core::error::Result;
use pigui_core::models::Alert;
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
