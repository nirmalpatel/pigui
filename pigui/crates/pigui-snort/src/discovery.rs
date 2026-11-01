use std::path::Path;
use std::process::Command;

use pigui_core::error::{Error, Result};

/// Run `snort -V` and extract the reported version.
pub fn version(binary: &Path) -> Result<String> {
    let output = run(binary, &["-V"])?;
    parse_version(&output).ok_or_else(|| {
        Error::SnortProbe("could not find a version string in snort -V output".into())
    })
}

/// DAQ modules are not exposed by a stable Snort CLI flag. Phase 1 reports an
/// empty list rather than scraping fragile build output.
pub fn daq_modules(_binary: &Path) -> Result<Vec<String>> {
    Ok(Vec::new())
}

/// Capture combined stdout/stderr from a Snort invocation.
pub fn run(binary: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .map_err(|e| Error::io(binary, e))?;

    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(text)
}

fn parse_version(text: &str) -> Option<String> {
    text.lines()
        .find(|line| line.contains("Version"))
        .and_then(|line| {
            let mut words = line.split_whitespace();
            while let Some(word) = words.next() {
                if word == "Version" {
                    return words.next().map(ToOwned::to_owned);
                }
            }
            None
        })
}

#[cfg(test)]
mod tests {
    use super::parse_version;

    #[test]
    fn parses_snort_version_banner() {
        let text = "   ,,_     -*> Snort++ <*-\n  o\"  )~   Version 3.12.4.0\n";
        assert_eq!(parse_version(text).as_deref(), Some("3.12.4.0"));
    }

    #[test]
    fn returns_none_without_version() {
        assert_eq!(parse_version("no banner here"), None);
    }
}
