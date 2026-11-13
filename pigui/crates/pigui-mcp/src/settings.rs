use std::env;

#[derive(Debug, Clone, Copy)]
pub struct McpSettings {
    pub max_rows: u32,
    pub max_bytes: usize,
    pub redact_users: bool,
    pub include_noise: bool,
}

impl Default for McpSettings {
    fn default() -> Self {
        Self {
            max_rows: 200,
            max_bytes: 65_536,
            redact_users: true,
            include_noise: false,
        }
    }
}

impl McpSettings {
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            max_rows: env_u32("PIGUI_MCP_MAX_ROWS", defaults.max_rows).clamp(1, 10_000),
            max_bytes: env_u32("PIGUI_MCP_MAX_BYTES", defaults.max_bytes as u32)
                .clamp(1_024, 16 * 1024 * 1024) as usize,
            redact_users: env_bool("PIGUI_MCP_REDACT_USERS", defaults.redact_users),
            include_noise: env_bool("PIGUI_MCP_INCLUDE_NOISE", defaults.include_noise),
        }
    }
}

fn env_u32(name: &str, default: u32) -> u32 {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_bool(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        Err(_) => default,
    }
}
