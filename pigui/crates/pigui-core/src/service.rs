use std::path::PathBuf;
use std::process::Command;

use crate::bundle;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    Status,
    RegisterAgent,
    UnregisterAgent,
    RegisterHelper,
    UnregisterHelper,
}

impl ServiceAction {
    pub fn as_arg(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::RegisterAgent => "register-agent",
            Self::UnregisterAgent => "unregister-agent",
            Self::RegisterHelper => "register-helper",
            Self::UnregisterHelper => "unregister-helper",
        }
    }
}

/// Locate the SMAppService registration utility shipped inside PIGUI.app.
pub fn servicectl_path() -> Option<PathBuf> {
    let bundled = bundle::macos_dir().map(|dir| dir.join("pigui-servicectl"));
    if let Some(path) = bundled.filter(|path| path.is_file()) {
        return Some(path);
    }

    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("pigui-servicectl")))
        .filter(|path| path.is_file())
}

/// Run the packaged SMAppService utility. The utility owns all password and
/// approval UI through ServiceManagement; PIGUI never requests credentials.
pub fn run(action: ServiceAction) -> Result<String> {
    let path = servicectl_path().ok_or_else(|| {
        Error::Config("pigui-servicectl is only available in the packaged PIGUI.app".into())
    })?;

    let output = Command::new(&path)
        .arg(action.as_arg())
        .output()
        .map_err(|error| Error::io(&path, error))?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        let detail = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        return Err(Error::Config(format!(
            "{} failed: {detail}",
            action.as_arg()
        )));
    }
    Ok(stdout)
}
