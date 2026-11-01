use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::rpc::{Request, Response};

/// Blocking client for the PIGUI daemon's Unix-domain socket API.
#[derive(Debug, Clone)]
pub struct DaemonClient {
    socket_path: PathBuf,
    timeout: Duration,
}

impl DaemonClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let mut stream =
            UnixStream::connect(&self.socket_path).map_err(|e| Error::io(&self.socket_path, e))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| Error::io(&self.socket_path, e))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| Error::io(&self.socket_path, e))?;

        let request = Request::new(method, params);
        let encoded = serde_json::to_vec(&request)?;
        stream
            .write_all(&encoded)
            .and_then(|_| stream.write_all(b"\n"))
            .map_err(|e| Error::io(&self.socket_path, e))?;

        let mut line = String::new();
        BufReader::new(stream)
            .read_line(&mut line)
            .map_err(|e| Error::io(&self.socket_path, e))?;

        let response: Response = serde_json::from_str(line.trim())?;
        if response.ok {
            Ok(response.data.unwrap_or(Value::Null))
        } else {
            Err(Error::Rpc(
                response
                    .error
                    .unwrap_or_else(|| "unknown daemon error".into()),
            ))
        }
    }

    pub fn call_typed<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let value = self.call(method, params)?;
        Ok(serde_json::from_value(value)?)
    }
}
