use serde_json::Value;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Common {
    pub ts: i64,
    pub uid: Option<String>,
    pub pkt_num: Option<u64>,
    pub proto: Option<String>,
    pub client_ip: Option<String>,
    pub client_port: Option<u16>,
    pub server_ip: Option<String>,
    pub server_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConnEvent {
    pub common: Common,
    pub service: Option<String>,
    pub conn_state: Option<String>,
    pub duration: Option<f64>,
    pub packets_ab: u64,
    pub packets_ba: u64,
    pub bytes_ab: u64,
    pub bytes_ba: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsEvent {
    pub common: Common,
    pub query: Option<String>,
    pub qtype: Option<String>,
    pub rcode: Option<String>,
    pub answers: Option<String>,
    pub ttl: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsEvent {
    pub common: Common,
    pub server_name: Option<String>,
    pub version: Option<String>,
    pub validation_status: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpEvent {
    pub common: Common,
    pub method: Option<String>,
    pub host: Option<String>,
    pub uri: Option<String>,
    pub user_agent: Option<String>,
    pub status_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicEvent {
    pub common: Common,
    pub server_name: Option<String>,
    pub client_protocol: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExtractorRecord {
    Conn(ConnEvent),
    Dns(DnsEvent),
    Tls(TlsEvent),
    Http(HttpEvent),
    Quic(QuicEvent),
}

impl ExtractorRecord {
    pub fn parse(line: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(line.trim())
            .map_err(|e| Error::Parse(format!("invalid extractor JSON: {e}")))?;
        let common = Common {
            ts: get_ts(&value)?,
            uid: get_str(&value, "uid"),
            pkt_num: get_u64(&value, "pkt_num"),
            proto: get_str(&value, "proto"),
            client_ip: get_str(&value, "id.orig_h"),
            client_port: get_u16(&value, "id.orig_p"),
            server_ip: get_str(&value, "id.resp_h"),
            server_port: get_u16(&value, "id.resp_p"),
        };

        if value.get("query").is_some() || value.get("qtype_name").is_some() {
            return Ok(Self::Dns(DnsEvent {
                common,
                query: get_str(&value, "query"),
                qtype: get_str(&value, "qtype_name"),
                rcode: get_str(&value, "rcode_name"),
                answers: get_str(&value, "answers"),
                ttl: get_str(&value, "TTLs"),
            }));
        }

        if value.get("client_protocol").is_some() {
            return Ok(Self::Quic(QuicEvent {
                common,
                server_name: get_str(&value, "server_name"),
                client_protocol: get_str(&value, "client_protocol"),
            }));
        }

        if value.get("server_name").is_some()
            || value.get("version").is_some()
            || value.get("validation_status").is_some()
            || value.get("subject").is_some()
            || value.get("issuer").is_some()
        {
            return Ok(Self::Tls(TlsEvent {
                common,
                server_name: get_str(&value, "server_name"),
                version: get_str(&value, "version"),
                validation_status: get_str(&value, "validation_status"),
                subject: get_str(&value, "subject"),
                issuer: get_str(&value, "issuer"),
            }));
        }

        if value.get("method").is_some()
            || value.get("host").is_some()
            || value.get("uri").is_some()
            || value.get("status_code").is_some()
        {
            return Ok(Self::Http(HttpEvent {
                common,
                method: get_str(&value, "method"),
                host: get_str(&value, "host"),
                uri: get_str(&value, "uri"),
                user_agent: get_str(&value, "user_agent"),
                status_code: get_str(&value, "status_code"),
            }));
        }

        if value.get("conn_state").is_some()
            || value.get("duration").is_some()
            || value.get("orig_pkts").is_some()
            || value.get("resp_pkts").is_some()
            || value.get("service").is_some()
        {
            return Ok(Self::Conn(ConnEvent {
                common,
                service: get_str(&value, "service"),
                conn_state: get_str(&value, "conn_state"),
                duration: get_f64(&value, "duration"),
                packets_ab: get_u64(&value, "orig_pkts").unwrap_or(0),
                packets_ba: get_u64(&value, "resp_pkts").unwrap_or(0),
                bytes_ab: get_u64(&value, "orig_bytes").unwrap_or(0),
                bytes_ba: get_u64(&value, "resp_bytes").unwrap_or(0),
            }));
        }

        Err(Error::Parse(
            "unrecognized extractor record (no known service fields)".into(),
        ))
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Conn(_) => "conn",
            Self::Dns(_) => "dns",
            Self::Tls(_) => "ssl",
            Self::Http(_) => "http",
            Self::Quic(_) => "quic",
        }
    }

    pub fn common(&self) -> &Common {
        match self {
            Self::Conn(event) => &event.common,
            Self::Dns(event) => &event.common,
            Self::Tls(event) => &event.common,
            Self::Http(event) => &event.common,
            Self::Quic(event) => &event.common,
        }
    }
}

fn get_ts(value: &Value) -> Result<i64> {
    if let Some(number) = value.get("ts").and_then(Value::as_f64) {
        return Ok(number as i64);
    }
    if let Some(number) = value.get("ts").and_then(Value::as_i64) {
        return Ok(number);
    }
    if let Some(text) = value.get("ts").and_then(Value::as_str) {
        if let Ok(number) = text.parse::<f64>() {
            return Ok(number as i64);
        }
        if let Ok(number) = text.parse::<i64>() {
            return Ok(number);
        }
    }
    Err(Error::Parse(
        "extractor record missing timestamp 'ts'".into(),
    ))
}

fn get_str(value: &Value, key: &str) -> Option<String> {
    match value.get(key) {
        Some(Value::String(text)) => {
            let text = text.trim();
            (!text.is_empty()).then(|| text.to_string())
        }
        Some(Value::Number(number)) => Some(number.to_string()),
        Some(Value::Bool(flag)) => Some(flag.to_string()),
        _ => None,
    }
}

fn get_u64(value: &Value, key: &str) -> Option<u64> {
    match value.get(key) {
        Some(Value::Number(number)) => number.as_u64(),
        Some(Value::String(text)) => text.trim().parse().ok(),
        _ => None,
    }
}

fn get_u16(value: &Value, key: &str) -> Option<u16> {
    get_u64(value, key).and_then(|number| u16::try_from(number).ok())
}

fn get_f64(value: &Value, key: &str) -> Option<f64> {
    match value.get(key) {
        Some(Value::Number(number)) => number.as_f64(),
        Some(Value::String(text)) => text.trim().parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_conn_record() {
        let line = r#"{"ts":1750000000.5,"uid":"C1","pkt_num":3,"id.orig_h":"10.0.0.5","id.orig_p":50000,"id.resp_h":"198.51.100.10","id.resp_p":443,"proto":"tcp","service":"ssl","conn_state":"SF","duration":1.25,"orig_pkts":10,"resp_pkts":12,"orig_bytes":1000,"resp_bytes":2000}"#;
        let ExtractorRecord::Conn(event) = ExtractorRecord::parse(line).unwrap() else {
            panic!("expected conn");
        };
        assert_eq!(event.common.ts, 1_750_000_000);
        assert_eq!(event.service.as_deref(), Some("ssl"));
        assert_eq!(event.bytes_ba, 2000);
    }

    #[test]
    fn parses_dns_record() {
        let line = r#"{"ts":1750000001,"id.orig_h":"10.0.0.5","id.orig_p":53000,"id.resp_h":"203.0.113.53","id.resp_p":53,"proto":"udp","query":"example.com","qtype_name":"A","rcode_name":"NOERROR","answers":"93.184.216.34","TTLs":"300"}"#;
        let ExtractorRecord::Dns(event) = ExtractorRecord::parse(line).unwrap() else {
            panic!("expected dns");
        };
        assert_eq!(event.query.as_deref(), Some("example.com"));
        assert_eq!(event.answers.as_deref(), Some("93.184.216.34"));
    }

    #[test]
    fn parses_tls_record() {
        let line = r#"{"ts":1750000002,"id.orig_h":"10.0.0.5","id.orig_p":50001,"id.resp_h":"198.51.100.10","id.resp_p":443,"server_name":"example.com","version":"TLSv1.3","validation_status":"valid","subject":"CN=example.com","issuer":"CN=Test CA"}"#;
        let ExtractorRecord::Tls(event) = ExtractorRecord::parse(line).unwrap() else {
            panic!("expected tls");
        };
        assert_eq!(event.server_name.as_deref(), Some("example.com"));
    }

    #[test]
    fn parses_tls_record_without_validation_fields() {
        let line = r#"{"ts":1750000002,"id.orig_h":"10.0.0.5","id.orig_p":50001,"id.resp_h":"198.51.100.10","id.resp_p":443,"server_name":"example.com","version":"TLS 1.3"}"#;
        let ExtractorRecord::Tls(event) = ExtractorRecord::parse(line).unwrap() else {
            panic!("expected tls");
        };
        assert_eq!(event.server_name.as_deref(), Some("example.com"));
        assert_eq!(event.version.as_deref(), Some("TLS 1.3"));
    }

    #[test]
    fn parses_http_record() {
        let line = r#"{"ts":1750000003,"id.orig_h":"10.0.0.5","id.orig_p":50002,"id.resp_h":"198.51.100.10","id.resp_p":80,"method":"GET","host":"example.com","uri":"/index.html","user_agent":"test","status_code":"200"}"#;
        let ExtractorRecord::Http(event) = ExtractorRecord::parse(line).unwrap() else {
            panic!("expected http");
        };
        assert_eq!(event.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn parses_quic_record() {
        let line = r#"{"ts":1750000004,"id.orig_h":"10.0.0.5","id.orig_p":50003,"id.resp_h":"198.51.100.10","id.resp_p":443,"server_name":"example.com","client_protocol":"h3"}"#;
        let ExtractorRecord::Quic(event) = ExtractorRecord::parse(line).unwrap() else {
            panic!("expected quic");
        };
        assert_eq!(event.client_protocol.as_deref(), Some("h3"));
    }

    #[test]
    fn rejects_unknown_record() {
        assert!(ExtractorRecord::parse(r#"{"ts":1,"foo":"bar"}"#).is_err());
    }
}
