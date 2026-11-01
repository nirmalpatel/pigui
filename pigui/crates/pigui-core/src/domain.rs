use std::net::IpAddr;

pub fn normalize_hostname(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches('.');
    let host = match trimmed.rsplit_once(':') {
        Some((name, port)) if port.parse::<u16>().is_ok() && !name.contains(':') => name,
        _ => trimmed,
    }
    .to_ascii_lowercase();

    if host.is_empty() || host.len() > 253 || !host.contains('.') {
        return None;
    }
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    if host
        .chars()
        .any(|character| character.is_whitespace() || matches!(character, '/' | '\\' | '@' | ':'))
    {
        return None;
    }
    Some(host)
}

pub fn registrable_domain(hostname: &str) -> String {
    psl::domain_str(hostname).unwrap_or(hostname).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_hostnames() {
        assert_eq!(
            normalize_hostname("API.Spotify.com."),
            Some("api.spotify.com".into())
        );
        assert_eq!(normalize_hostname("127.0.0.1"), None);
        assert_eq!(
            normalize_hostname("api.spotify.com:443"),
            Some("api.spotify.com".into())
        );
        assert_eq!(normalize_hostname("localhost"), None);
        assert_eq!(normalize_hostname("bad host"), None);
    }

    #[test]
    fn extracts_registrable_domains() {
        assert_eq!(registrable_domain("api.spotify.com"), "spotify.com");
        assert_eq!(registrable_domain("open.spotify.co.uk"), "spotify.co.uk");
        assert_eq!(registrable_domain("scdn.co"), "scdn.co");
    }
}
