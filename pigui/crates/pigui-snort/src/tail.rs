use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use pigui_core::error::{Error, Result};

/// Simple polling tailer for newline-delimited files.
///
/// It tolerates partial lines, truncation, and rotation (inode changes). No
/// platform-specific notification APIs are required.
#[derive(Debug)]
pub struct Tailer {
    path: PathBuf,
    offset: u64,
    inode: Option<u64>,
    pending: Vec<u8>,
}

impl Tailer {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            offset: 0,
            inode: None,
            pending: Vec::new(),
        }
    }

    /// Start watching at the current end of the file.
    pub fn from_end(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let mut tailer = Self::new(path);
        if let Ok(meta) = fs::metadata(&tailer.path) {
            tailer.offset = meta.len();
            tailer.inode = Some(meta.ino());
        }
        Ok(tailer)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn poll(&mut self) -> Result<Vec<String>> {
        let meta = match fs::metadata(&self.path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(Error::io(&self.path, error)),
        };

        let inode = meta.ino();
        if self.inode != Some(inode) || meta.len() < self.offset {
            self.offset = 0;
            self.pending.clear();
            self.inode = Some(inode);
        }

        if meta.len() == self.offset {
            return Ok(Vec::new());
        }

        let mut file = File::open(&self.path).map_err(|e| Error::io(&self.path, e))?;
        file.seek(SeekFrom::Start(self.offset))
            .map_err(|e| Error::io(&self.path, e))?;

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| Error::io(&self.path, e))?;
        if bytes.is_empty() {
            return Ok(Vec::new());
        }

        self.offset += bytes.len() as u64;
        self.pending.extend_from_slice(&bytes);

        let mut lines = Vec::new();
        let mut consumed = 0;
        for (index, byte) in self.pending.iter().enumerate() {
            if *byte != b'\n' {
                continue;
            }
            let mut line = &self.pending[consumed..index];
            if line.last() == Some(&b'\r') {
                line = &line[..line.len() - 1];
            }
            let text = String::from_utf8_lossy(line).into_owned();
            if !text.trim().is_empty() {
                lines.push(text);
            }
            consumed = index + 1;
        }
        if consumed > 0 {
            self.pending.drain(..consumed);
        }

        Ok(lines)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn append(path: &Path, text: &str) {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        file.write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn reads_only_complete_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alerts.jsonl");
        append(&path, "{\"a\":1}\n{\"b\":");
        let mut tailer = Tailer::new(&path);

        assert_eq!(tailer.poll().unwrap(), vec!["{\"a\":1}"]);

        append(&path, "2}\n");
        assert_eq!(tailer.poll().unwrap(), vec!["{\"b\":2}"]);
    }

    #[test]
    fn ignores_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut tailer = Tailer::new(dir.path().join("missing.jsonl"));
        assert!(tailer.poll().unwrap().is_empty());
    }

    #[test]
    fn resets_after_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alerts.jsonl");
        append(&path, "old\n");
        let mut tailer = Tailer::new(&path);
        assert_eq!(tailer.poll().unwrap(), vec!["old"]);

        fs::write(&path, "n\n").unwrap();
        assert_eq!(tailer.poll().unwrap(), vec!["n"]);
        append(&path, "ew\n");
        assert_eq!(tailer.poll().unwrap(), vec!["ew"]);
    }

    #[test]
    fn from_end_skips_existing_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alerts.jsonl");
        append(&path, "old\n");

        let mut tailer = Tailer::from_end(&path).unwrap();
        assert!(tailer.poll().unwrap().is_empty());

        append(&path, "new\n");
        assert_eq!(tailer.poll().unwrap(), vec!["new"]);
    }
}
