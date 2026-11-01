use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use pigui_core::Config;
use pigui_core::models::SnortCapabilities;
use tokio::sync::Notify;

use crate::store::{IngestStats, Store};

#[derive(Debug)]
pub struct AppState {
    pub config: Config,
    pub store: Mutex<Store>,
    pub capabilities: SnortCapabilities,
    pub started_at: Instant,
    pub alerts_ingested: AtomicU64,
    pub parse_errors: AtomicU64,
    shutting_down: AtomicBool,
    shutdown: Notify,
}

impl AppState {
    pub fn new(config: Config, store: Store, capabilities: SnortCapabilities) -> Self {
        Self {
            config,
            store: Mutex::new(store),
            capabilities,
            started_at: Instant::now(),
            alerts_ingested: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            shutting_down: AtomicBool::new(false),
            shutdown: Notify::new(),
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    pub fn record_ingest(&self, stats: &IngestStats) {
        self.alerts_ingested
            .fetch_add(stats.inserted, Ordering::Relaxed);
        self.parse_errors
            .fetch_add(stats.malformed, Ordering::Relaxed);
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    pub fn request_shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        self.shutdown.notify_waiters();
    }

    pub async fn wait_for_shutdown(&self) {
        if self.is_shutting_down() {
            return;
        }
        self.shutdown.notified().await;
    }
}
