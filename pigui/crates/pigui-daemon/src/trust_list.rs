use std::io::{BufRead, BufReader, Cursor};
use std::sync::LazyLock;

use pigui_core::domain::{normalize_hostname, registrable_domain};
use pigui_core::models::TrustState;

const TRANCO_ARCHIVE: &[u8] = include_bytes!("../assets/tranco_GQ38K-1m.csv.zip");

pub const TRANCO_LIST_ID: &str = "Tranco GQ38K top-1m";

static DEFAULT_TRUSTED: LazyLock<TrustedDomains> =
    LazyLock::new(|| match TrustedDomains::from_tranco_zip(TRANCO_ARCHIVE) {
        Ok(domains) => domains,
        Err(error) => {
            tracing::error!(%error, "failed to load bundled trusted domain list");
            TrustedDomains::empty()
        }
    });

pub fn default_trust_state(domain: &str) -> Option<TrustState> {
    DEFAULT_TRUSTED
        .contains(domain)
        .then_some(TrustState::Trusted)
}

#[derive(Debug, Default)]
pub struct TrustedDomains {
    blob: Vec<u8>,
    offsets: Vec<u32>,
}

impl TrustedDomains {
    pub fn empty() -> Self {
        Self {
            blob: Vec::new(),
            offsets: vec![0],
        }
    }

    fn from_tranco_zip(data: &[u8]) -> Result<Self, String> {
        let cursor = Cursor::new(data);
        let mut archive = zip::ZipArchive::new(cursor)
            .map_err(|error| format!("invalid zip archive: {error}"))?;
        let mut entries = Vec::with_capacity(1_000_000);
        let mut found_csv = false;

        for index in 0..archive.len() {
            let file = archive
                .by_index(index)
                .map_err(|error| format!("failed to read zip entry {index}: {error}"))?;
            if !file.name().to_ascii_lowercase().ends_with(".csv") {
                continue;
            }
            found_csv = true;
            let reader = BufReader::new(file);
            for (line_number, line) in reader.lines().enumerate() {
                let line = line
                    .map_err(|error| format!("failed to read csv line {line_number}: {error}"))?;
                let Some((rank, domain)) = line.split_once(',') else {
                    continue;
                };
                if rank.trim().parse::<u64>().is_err() {
                    continue;
                }
                let Some(hostname) = normalize_hostname(domain) else {
                    continue;
                };
                entries.push(registrable_domain(&hostname));
            }
        }

        if !found_csv {
            return Err("archive does not contain a csv file".into());
        }

        Ok(Self::from_entries(entries))
    }

    fn from_entries(entries: Vec<String>) -> Self {
        let mut entries = entries;
        entries.retain(|entry| !entry.is_empty());
        entries.sort_unstable();
        entries.dedup();

        let total_bytes = entries.iter().map(String::len).sum();
        let mut blob = Vec::with_capacity(total_bytes);
        let mut offsets = Vec::with_capacity(entries.len() + 1);
        offsets.push(0);
        for entry in entries {
            blob.extend_from_slice(entry.as_bytes());
            offsets.push(blob.len() as u32);
        }

        Self { blob, offsets }
    }

    fn len(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    fn entry(&self, index: usize) -> &[u8] {
        let start = self.offsets[index] as usize;
        let end = self.offsets[index + 1] as usize;
        &self.blob[start..end]
    }

    pub fn contains(&self, domain: &str) -> bool {
        let target = domain.as_bytes();
        let mut low = 0;
        let mut high = self.len();

        while low < high {
            let middle = low + (high - low) / 2;
            match self.entry(middle).cmp(target) {
                std::cmp::Ordering::Less => low = middle + 1,
                std::cmp::Ordering::Greater => high = middle,
                std::cmp::Ordering::Equal => return true,
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_bundled_tranco_list() {
        let domains = TrustedDomains::from_tranco_zip(TRANCO_ARCHIVE).unwrap();

        assert!(domains.len() > 100_000);
        assert!(domains.contains("google.com"));
        assert!(domains.contains("cloudflare.com"));
        assert!(!domains.contains("not-in-the-tranco-list.invalid"));
        assert_eq!(default_trust_state("google.com"), Some(TrustState::Trusted));
    }

    #[test]
    fn sorts_and_deduplicates_entries() {
        let domains = TrustedDomains::from_entries(vec![
            "spotify.com".into(),
            "cloudflare.com".into(),
            "spotify.com".into(),
            String::new(),
        ]);

        assert_eq!(domains.len(), 2);
        assert!(domains.contains("cloudflare.com"));
        assert!(domains.contains("spotify.com"));
        assert!(!domains.contains("example.com"));
    }
}
