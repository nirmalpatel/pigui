use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::Instant;

use pigui_core::Config;
use pigui_core::models::SnortCapabilities;
use pigui_core::rpc::{CaptureState, PruneResult};
use pigui_core::settings::AppSettings;
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
    pub extractor_ingested: AtomicU64,
    pub extractor_last_ingest: AtomicU64,
    pub last_snapshot_ts: AtomicU64,
    settings: RwLock<AppSettings>,
    capture: RwLock<Option<CaptureState>>,
    maintenance_last_run: AtomicU64,
    maintenance_last_deleted: AtomicU64,
    collector_error: Mutex<Option<String>>,
    shutting_down: AtomicBool,
    shutdown: Notify,
}

impl AppState {
    pub fn new(config: Config, store: Store, capabilities: SnortCapabilities) -> Self {
        let settings = store.get_settings().unwrap_or_default();
        let capture = store.get_capture_state().unwrap_or_default();
        Self {
            config,
            store: Mutex::new(store),
            capabilities,
            started_at: Instant::now(),
            alerts_ingested: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            extractor_ingested: AtomicU64::new(0),
            extractor_last_ingest: AtomicU64::new(0),
            last_snapshot_ts: AtomicU64::new(0),
            settings: RwLock::new(settings),
            capture: RwLock::new(capture),
            maintenance_last_run: AtomicU64::new(0),
            maintenance_last_deleted: AtomicU64::new(0),
            collector_error: Mutex::new(None),
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

    pub fn record_extractor(&self, inserted: u64, errors: u64, now: i64) {
        self.extractor_ingested
            .fetch_add(inserted, Ordering::Relaxed);
        self.parse_errors.fetch_add(errors, Ordering::Relaxed);
        self.extractor_last_ingest
            .store(now.max(0) as u64, Ordering::Relaxed);
    }

    pub fn extractor_last_ingest(&self) -> Option<i64> {
        let value = self.extractor_last_ingest.load(Ordering::Relaxed);
        (value > 0).then_some(value as i64)
    }

    pub fn settings(&self) -> AppSettings {
        self.settings
            .read()
            .map(|settings| settings.clone())
            .unwrap_or_default()
    }

    pub fn set_settings(&self, settings: AppSettings) {
        if let Ok(mut current) = self.settings.write() {
            *current = settings;
        }
    }

    pub fn capture(&self) -> Option<CaptureState> {
        self.capture.read().ok().and_then(|capture| capture.clone())
    }

    pub fn set_capture(&self, capture: Option<CaptureState>) {
        if let Ok(mut current) = self.capture.write() {
            *current = capture;
        }
    }

    pub fn record_maintenance(&self, result: &PruneResult) {
        self.maintenance_last_run
            .store(result.ran_at.max(0) as u64, Ordering::Relaxed);
        self.maintenance_last_deleted
            .store(result.total_deleted, Ordering::Relaxed);
    }

    pub fn maintenance_info(&self) -> (Option<i64>, u64) {
        let last_run = self.maintenance_last_run.load(Ordering::Relaxed);
        (
            (last_run > 0).then_some(last_run as i64),
            self.maintenance_last_deleted.load(Ordering::Relaxed),
        )
    }

    pub fn record_snapshot(&self, now: i64) {
        self.last_snapshot_ts
            .store(now.max(0) as u64, Ordering::Relaxed);
        if let Ok(mut error) = self.collector_error.lock() {
            *error = None;
        }
    }

    pub fn set_collector_error(&self, message: impl Into<String>) {
        if let Ok(mut error) = self.collector_error.lock() {
            *error = Some(message.into());
        }
    }

    pub fn collector_error(&self) -> Option<String> {
        self.collector_error
            .lock()
            .ok()
            .and_then(|error| error.clone())
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
