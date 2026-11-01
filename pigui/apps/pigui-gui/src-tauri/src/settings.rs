use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pigui_core::settings::{AppSettings, ThemeMode};
use rusqlite::{Connection, OptionalExtension, params};

type Result<T> = std::result::Result<T, String>;

const THEME_KEY: &str = "ui.theme";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
"#;

#[derive(Debug)]
pub struct UiSettingsStore {
    conn: Mutex<Connection>,
}

impl UiSettingsStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let conn = Connection::open(path).map_err(|error| error.to_string())?;
        Self::init(conn)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(|error| error.to_string())?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.busy_timeout(Duration::from_secs(2))
            .map_err(|error| error.to_string())?;
        conn.execute_batch(SCHEMA)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn get_settings(&self) -> Result<AppSettings> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "settings store lock poisoned".to_string())?;
        let stored: Option<String> = conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![THEME_KEY],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| error.to_string())?;
        let theme = stored
            .as_deref()
            .and_then(ThemeMode::parse)
            .unwrap_or_default();
        Ok(AppSettings { theme })
    }

    pub fn set_theme(&self, theme: ThemeMode) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "settings store lock poisoned".to_string())?;
        conn.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET
                 value = excluded.value,
                 updated_at = excluded.updated_at",
            params![THEME_KEY, theme.as_str(), unix_now()],
        )
        .map_err(|error| error.to_string())?;
        Ok(())
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_system_theme() {
        let store = UiSettingsStore::open_in_memory().unwrap();
        assert_eq!(store.get_settings().unwrap().theme, ThemeMode::System);
    }

    #[test]
    fn persists_theme_round_trip() {
        let store = UiSettingsStore::open_in_memory().unwrap();
        store.set_theme(ThemeMode::Light).unwrap();
        assert_eq!(store.get_settings().unwrap().theme, ThemeMode::Light);
        store.set_theme(ThemeMode::Dark).unwrap();
        assert_eq!(store.get_settings().unwrap().theme, ThemeMode::Dark);
    }
}
