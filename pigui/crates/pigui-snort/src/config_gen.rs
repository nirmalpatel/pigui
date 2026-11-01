use std::path::{Path, PathBuf};

use pigui_core::config::Config;
use pigui_core::error::{Error, Result};
use pigui_core::paths::resolve_snort;

use crate::capabilities::validate_config;

const OVERRIDES: &str = r#"
---------------------------------------------------------------------------
-- PIGUI generated overrides (do not edit by hand)
---------------------------------------------------------------------------

alert_json =
{
    file = true,
    fields = 'seconds timestamp gid sid rev priority class msg proto src_addr src_port dst_addr dst_port action app_id service rule dir pkt_num',
}

dns = { publish_response = true }

file_connector =
{
    {
        connector = 'pigui_events',
        name = 'pigui',
        direction = 'transmit',
        text_format = true,
    },
}

extractor =
{
    formatting = 'json',
    connector = 'pigui_events',
    time = 'unix',
    default_filter = 'skip',
    protocols =
    {
        { service = 'conn', on_events = 'eof',
          fields = 'ts uid pkt_num id.orig_h id.orig_p id.resp_h id.resp_p proto service conn_state duration orig_pkts resp_pkts orig_bytes resp_bytes' },
        { service = 'dns', on_events = 'response',
          fields = 'ts uid pkt_num id.orig_h id.orig_p id.resp_h id.resp_p proto query qtype_name rcode_name answers TTLs' },
        { service = 'ssl', on_events = 'tls_metadata_event',
          fields = 'ts uid pkt_num id.orig_h id.orig_p id.resp_h id.resp_p server_name version validation_status subject issuer' },
        { service = 'http', on_events = 'eot',
          fields = 'ts uid pkt_num id.orig_h id.orig_p id.resp_h id.resp_p method host uri user_agent status_code' },
        { service = 'quic', on_events = 'handshake',
          fields = 'ts uid pkt_num id.orig_h id.orig_p id.resp_h id.resp_p server_name client_protocol' },
    },
}

ips =
{
    variables = default_variables,
    enable_builtin_rules = true,
}
"#;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GeneratedConfig {
    pub path: PathBuf,
    pub hash: String,
    pub valid: bool,
    pub detail: String,
}

pub fn generate(config: &Config) -> Result<GeneratedConfig> {
    let source = config
        .snort_config
        .as_ref()
        .ok_or_else(|| Error::Config("PIGUI_SNORT_CONFIG is not set".into()))?;
    let source = config.resolve(source);
    if !source.is_file() {
        return Err(Error::Config(format!(
            "snort config not found: {}",
            source.display()
        )));
    }

    let source_dir = source
        .parent()
        .ok_or_else(|| Error::Config("snort config has no parent directory".into()))?;
    let defaults = source_dir.join("snort_defaults.lua");
    if !defaults.is_file() {
        return Err(Error::Config(format!(
            "snort_defaults.lua not found next to {}",
            source.display()
        )));
    }

    std::fs::create_dir_all(&config.snort_config_dir)
        .map_err(|error| Error::io(&config.snort_config_dir, error))?;

    let mut content =
        std::fs::read_to_string(&source).map_err(|error| Error::io(&source, error))?;
    content.push_str(OVERRIDES);

    let hash = fnv1a(content.as_bytes());
    let path = config.snort_config_dir.join("snort.lua");

    std::fs::copy(
        &defaults,
        config.snort_config_dir.join("snort_defaults.lua"),
    )
    .map_err(|error| Error::io(&defaults, error))?;

    // The stock config references rule files relative to its own directory.
    if let Ok(entries) = std::fs::read_dir(source_dir) {
        for entry in entries.flatten() {
            let source = entry.path();
            if source.extension().and_then(|value| value.to_str()) != Some("rules") {
                continue;
            }
            if let Some(name) = source.file_name() {
                let destination = config.snort_config_dir.join(name);
                std::fs::copy(&source, &destination)
                    .map_err(|error| Error::io(&destination, error))?;
            }
        }
    }

    atomic_write(&path, content.as_bytes())?;

    let resolved = resolve_snort(config)?;
    let (valid, detail) = validate_config(&resolved.path, &path)?;

    Ok(GeneratedConfig {
        path,
        hash,
        valid,
        detail,
    })
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension("lua.tmp");
    std::fs::write(&temp, bytes).map_err(|error| Error::io(&temp, error))?;
    std::fs::rename(&temp, path).map_err(|error| Error::io(path, error))
}

fn fnv1a(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::fnv1a;

    #[test]
    fn hash_is_stable() {
        assert_eq!(fnv1a(b"hello"), fnv1a(b"hello"));
        assert_ne!(fnv1a(b"hello"), fnv1a(b"world"));
    }
}
