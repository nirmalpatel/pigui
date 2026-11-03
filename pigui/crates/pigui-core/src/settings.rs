use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    #[default]
    System,
    Light,
    Dark,
}

impl ThemeMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "system" => Some(Self::System),
            "light" => Some(Self::Light),
            "dark" => Some(Self::Dark),
            _ => None,
        }
    }
}

impl std::fmt::Display for ThemeMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UiSettings {
    pub refresh_ms: u64,
    pub page_size: u32,
    pub detail_alert_limit: u32,
    pub stale_after_secs: u64,
}

impl Default for UiSettings {
    fn default() -> Self {
        Self {
            refresh_ms: 2_000,
            page_size: 200,
            detail_alert_limit: 10,
            stale_after_secs: 600,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LimitSettings {
    pub max_page_size: u32,
}

impl Default for LimitSettings {
    fn default() -> Self {
        Self {
            max_page_size: 1_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectorSettings {
    pub poll_ms: u64,
}

impl Default for CollectorSettings {
    fn default() -> Self {
        Self { poll_ms: 1_000 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RetentionSettings {
    pub flows_secs: i64,
    pub processes_secs: i64,
    pub alerts_days: u32,
    pub connections_days: u32,
    pub observations_days: u32,
    pub domains_days: u32,
    pub endpoints_days: u32,
    pub ptr_days: u32,
}

impl Default for RetentionSettings {
    fn default() -> Self {
        Self {
            flows_secs: 600,
            processes_secs: 86_400,
            alerts_days: 30,
            connections_days: 7,
            observations_days: 7,
            domains_days: 90,
            endpoints_days: 90,
            ptr_days: 30,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ResolverSettings {
    pub loop_secs: u64,
    pub ptr_batch: u32,
    pub ptr_ok_ttl_secs: i64,
    pub ptr_fail_ttl_secs: i64,
    pub watched_batch: u32,
    pub watched_interval_secs: i64,
}

impl Default for ResolverSettings {
    fn default() -> Self {
        Self {
            loop_secs: 30,
            ptr_batch: 10,
            ptr_ok_ttl_secs: 86_400,
            ptr_fail_ttl_secs: 21_600,
            watched_batch: 10,
            watched_interval_secs: 900,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MaintenanceSettings {
    pub interval_secs: u64,
}

impl Default for MaintenanceSettings {
    fn default() -> Self {
        Self { interval_secs: 300 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    pub theme: ThemeMode,
    pub ui: UiSettings,
    pub limits: LimitSettings,
    pub collector: CollectorSettings,
    pub retention: RetentionSettings,
    pub resolver: ResolverSettings,
    pub maintenance: MaintenanceSettings,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: ThemeMode::System,
            ui: UiSettings::default(),
            limits: LimitSettings::default(),
            collector: CollectorSettings::default(),
            retention: RetentionSettings::default(),
            resolver: ResolverSettings::default(),
            maintenance: MaintenanceSettings::default(),
        }
    }
}

impl AppSettings {
    pub fn validate(&mut self) {
        self.limits.max_page_size = self.limits.max_page_size.clamp(50, 10_000);
        self.ui.refresh_ms = self.ui.refresh_ms.clamp(500, 60_000);
        self.ui.page_size = self.ui.page_size.clamp(1, self.limits.max_page_size);
        self.ui.detail_alert_limit = self.ui.detail_alert_limit.min(100);
        self.ui.stale_after_secs = self.ui.stale_after_secs.clamp(60, 604_800);

        self.collector.poll_ms = self.collector.poll_ms.clamp(250, 60_000);

        self.retention.flows_secs = self.retention.flows_secs.clamp(60, 86_400);
        self.retention.processes_secs = self.retention.processes_secs.clamp(300, 604_800);
        self.retention.alerts_days = self.retention.alerts_days.clamp(1, 3_650);
        self.retention.connections_days = self.retention.connections_days.clamp(1, 3_650);
        self.retention.observations_days = self.retention.observations_days.clamp(1, 3_650);
        self.retention.domains_days = self.retention.domains_days.clamp(1, 3_650);
        self.retention.endpoints_days = self.retention.endpoints_days.clamp(1, 3_650);
        self.retention.ptr_days = self.retention.ptr_days.clamp(1, 3_650);

        self.resolver.loop_secs = self.resolver.loop_secs.clamp(5, 3_600);
        self.resolver.ptr_batch = self.resolver.ptr_batch.clamp(1, 100);
        self.resolver.ptr_ok_ttl_secs = self.resolver.ptr_ok_ttl_secs.clamp(60, 2_592_000);
        self.resolver.ptr_fail_ttl_secs = self.resolver.ptr_fail_ttl_secs.clamp(60, 2_592_000);
        self.resolver.watched_batch = self.resolver.watched_batch.clamp(1, 100);
        self.resolver.watched_interval_secs =
            self.resolver.watched_interval_secs.clamp(60, 604_800);

        self.maintenance.interval_secs = self.maintenance.interval_secs.clamp(30, 86_400);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_mode_round_trips() {
        for mode in [ThemeMode::System, ThemeMode::Light, ThemeMode::Dark] {
            assert_eq!(ThemeMode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(ThemeMode::parse("sepia"), None);
    }

    #[test]
    fn default_theme_is_system() {
        assert_eq!(AppSettings::default().theme, ThemeMode::System);
    }

    #[test]
    fn validation_keeps_values_in_range() {
        let mut settings = AppSettings::default();
        settings.limits.max_page_size = 1;
        settings.ui.page_size = 500_000;
        settings.collector.poll_ms = 1;
        settings.retention.alerts_days = 0;
        settings.resolver.ptr_batch = 0;
        settings.validate();

        assert_eq!(settings.limits.max_page_size, 50);
        assert_eq!(settings.ui.page_size, 50);
        assert_eq!(settings.collector.poll_ms, 250);
        assert_eq!(settings.retention.alerts_days, 1);
        assert_eq!(settings.resolver.ptr_batch, 1);
    }

    #[test]
    fn partial_json_uses_defaults() {
        let settings: AppSettings =
            serde_json::from_str(r#"{"theme":"dark","ui":{"page_size":50}}"#).unwrap();
        assert_eq!(settings.theme, ThemeMode::Dark);
        assert_eq!(settings.ui.page_size, 50);
        assert_eq!(settings.ui.refresh_ms, 2_000);
        assert_eq!(settings.retention.alerts_days, 30);
    }
}
