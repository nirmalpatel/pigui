use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("snort binary not found; set PIGUI_SNORT_BIN")]
    SnortNotFound,
    #[error("snort probe failed: {0}")]
    SnortProbe(String),
    #[error("i/o error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("parse error: {0}")]
    Parse(String),
    #[error("database error: {0}")]
    Database(String),
    #[error("rpc error: {0}")]
    Rpc(String),
    #[error("helper not implemented: {0}")]
    NotImplemented(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub fn io(path: impl AsRef<Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
