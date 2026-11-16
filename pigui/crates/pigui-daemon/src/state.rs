use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use pigui_core::Config;
use pigui_core::models::SnortCapabilities;
use pigui_core::rpc::{CaptureState, PruneResult, StatusPayload};
use pigui_core::settings::AppSettings;
use tokio::sync::{Mutex as AsyncMutex, watch};

use crate::store::{IngestStats, Store};

#[derive(Debug)]
pub struct AppState {
    pub config: Config,
    pub store: Arc<Mutex<Store>>,
    pub firewall_lock: AsyncMutex<()>,
    pub capture_lock: AsyncMutex<()>,
    pub capabilities: SnortCapabilities,
    pub started_at: Instant,
    pub alerts_ingested: AtomicU64,
    pub parse_errors: AtomicU64,
    pub extractor_ingested: AtomicU64,
    pub extractor_last_ingest: AtomicU64,
    extractor_file_size: AtomicU64,
    extractor_last_growth: AtomicU64,
    pub last_snapshot_ts: AtomicU64,
    settings: RwLock<AppSettings>,
    capture: RwLock<Option<CaptureState>>,
    capture_user_stopped: AtomicBool,
    maintenance_last_run: AtomicU64,
    maintenance_last_deleted: AtomicU64,
    collector_error: Mutex<Option<String>>,
    status_cache: Mutex<Option<(Instant, StatusPayload)>>,
    shutting_down: AtomicBool,
    shutdown: watch::Sender<bool>,
}

impl AppState {
    pub fn new(config: Config, store: Store, capabilities: SnortCapabilities) -> Self {
        let settings = store.get_settings().unwrap_or_default();
        let capture = store.get_capture_state().unwrap_or_default();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let extractor_size = std::fs::metadata(&config.extractor_json)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        Self {
            config,
            store: Arc::new(Mutex::new(store)),
            firewall_lock: AsyncMutex::new(()),
            capture_lock: AsyncMutex::new(()),
            capabilities,
            started_at: Instant::now(),
            alerts_ingested: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            extractor_ingested: AtomicU64::new(0),
            extractor_last_ingest: AtomicU64::new(0),
            extractor_file_size: AtomicU64::new(extractor_size),
            extractor_last_growth: AtomicU64::new(now),
            last_snapshot_ts: AtomicU64::new(0),
            settings: RwLock::new(settings),
            capture: RwLock::new(capture),
            capture_user_stopped: AtomicBool::new(false),
            maintenance_last_run: AtomicU64::new(0),
            maintenance_last_deleted: AtomicU64::new(0),
            collector_error: Mutex::new(None),
            status_cache: Mutex::new(None),
            shutting_down: AtomicBool::new(false),
            shutdown: {
                let (sender, _receiver) = watch::channel(false);
                sender
            },
        }
    }

    pub fn cached_status(&self, max_age: std::time::Duration) -> Option<StatusPayload> {
        self.status_cache.lock().ok().and_then(|cache| {
            cache
                .as_ref()
                .filter(|(cached_at, _)| cached_at.elapsed() <= max_age)
                .map(|(_, payload)| payload.clone())
        })
    }

    pub fn store_status(&self, payload: StatusPayload) {
        if let Ok(mut cache) = self.status_cache.lock() {
            *cache = Some((Instant::now(), payload));
        }
    }

    pub fn invalidate_status(&self) {
        if let Ok(mut cache) = self.status_cache.lock() {
            *cache = None;
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

    /// Track extractor file growth so buffered writes are not mistaken for an
    /// idle extractor. Snort's file connector flushes in 8 KiB chunks.
    pub fn observe_extractor_size(&self, size: u64, now: i64) {
        let previous = self.extractor_file_size.swap(size, Ordering::Relaxed);
        if size != previous && size > 0 {
            self.extractor_last_growth
                .store(now.max(0) as u64, Ordering::Relaxed);
        }
    }

    pub fn extractor_is_idle(
        &self,
        now: i64,
        alerts_ingested: u64,
        extractor_ingested: u64,
    ) -> bool {
        const STARTUP_GRACE_SECS: u64 = 60;
        const NO_GROWTH_GRACE_SECS: u64 = 300;
        let last_growth = self.extractor_last_growth.load(Ordering::Relaxed) as i64;
        let no_growth_secs = now.saturating_sub(last_growth).max(0) as u64;
        alerts_ingested > 0
            && extractor_ingested == 0
            && self.uptime_secs() > STARTUP_GRACE_SECS
            && no_growth_secs >= NO_GROWTH_GRACE_SECS
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
        self.invalidate_status();
    }

    pub fn capture(&self) -> Option<CaptureState> {
        self.capture.read().ok().and_then(|capture| capture.clone())
    }

    pub fn set_capture(&self, capture: Option<CaptureState>) {
        if let Ok(mut current) = self.capture.write() {
            *current = capture;
        }
        self.invalidate_status();
    }

    pub fn capture_suppressed(&self) -> bool {
        self.capture_user_stopped.load(Ordering::Relaxed)
    }

    pub fn set_capture_suppressed(&self, suppressed: bool) {
        self.capture_user_stopped
            .store(suppressed, Ordering::Relaxed);
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
        self.shutdown.send_replace(true);
    }

    pub async fn wait_for_shutdown(&self) {
        if self.is_shutting_down() {
            return;
        }
        let mut receiver = self.shutdown.subscribe();
        if *receiver.borrow_and_update() {
            return;
        }
        let _ = receiver.changed().await;
    }
}
