use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A normalized Snort `alert_json` event.
///
/// Only the fields PIGUI selects are required. Unknown fields are ignored so
/// that Snort can add fields without breaking ingestion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub event_ts: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts_text: Option<String>,
    pub gid: u32,
    pub sid: u32,
    pub rev: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pkt_num: Option<u64>,
}

impl Alert {
    pub fn parse(line: &str) -> Result<Self> {
        let raw: RawAlert = serde_json::from_str(line.trim())
            .map_err(|e| Error::Parse(format!("invalid alert_json: {e}")))?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: RawAlert) -> Result<Self> {
        let event_ts = raw
            .seconds
            .ok_or_else(|| Error::Parse("alert_json missing integer 'seconds'".into()))?;

        Ok(Self {
            event_ts,
            ts_text: raw.timestamp,
            gid: raw.gid.unwrap_or(1),
            sid: raw
                .sid
                .ok_or_else(|| Error::Parse("alert_json missing 'sid'".into()))?,
            rev: raw.rev.unwrap_or(1),
            priority: raw.priority,
            class: raw.class,
            msg: raw.msg,
            proto: raw.proto,
            src_ip: raw.src_addr,
            src_port: raw.src_port,
            dst_ip: raw.dst_addr,
            dst_port: raw.dst_port,
            action: raw.action,
            app_id: raw.app_id,
            service: raw.service,
            rule: raw.rule,
            direction: raw.dir,
            pkt_num: raw.pkt_num,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawAlert {
    seconds: Option<i64>,
    timestamp: Option<String>,
    gid: Option<u32>,
    sid: Option<u32>,
    rev: Option<u32>,
    priority: Option<u32>,
    class: Option<String>,
    msg: Option<String>,
    proto: Option<String>,
    src_addr: Option<String>,
    src_port: Option<u16>,
    dst_addr: Option<String>,
    dst_port: Option<u16>,
    action: Option<String>,
    app_id: Option<String>,
    service: Option<String>,
    rule: Option<String>,
    dir: Option<String>,
    pkt_num: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str = r#"{"seconds":1750000000,"timestamp":"06/15-12:26:40.123456","gid":1,"sid":1000001,"rev":2,"priority":1,"class":"attempted-admin","msg":"Test SSH brute force","proto":"TCP","src_addr":"10.0.0.5","src_port":51000,"dst_addr":"198.51.100.10","dst_port":22,"action":"allowed","app_id":"ssh","service":"ssh","rule":"1:1000001:2","dir":"C2S","pkt_num":7}"#;

    #[test]
    fn parses_normalized_alert() {
        let alert = Alert::parse(LINE).unwrap();
        assert_eq!(alert.event_ts, 1_750_000_000);
        assert_eq!(alert.sid, 1_000_001);
        assert_eq!(alert.rev, 2);
        assert_eq!(alert.src_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(alert.dst_port, Some(22));
        assert_eq!(alert.direction.as_deref(), Some("C2S"));
    }

    #[test]
    fn ignores_unknown_fields() {
        let line = r#"{"seconds":1,"sid":2,"future_field":"ignored"}"#;
        let alert = Alert::parse(line).unwrap();
        assert_eq!(alert.sid, 2);
        assert_eq!(alert.gid, 1);
        assert_eq!(alert.rev, 1);
    }

    #[test]
    fn rejects_missing_seconds() {
        let line = r#"{"sid":2,"proto":"TCP"}"#;
        assert!(Alert::parse(line).is_err());
    }

    #[test]
    fn rejects_missing_sid() {
        let line = r#"{"seconds":1}"#;
        assert!(Alert::parse(line).is_err());
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(Alert::parse("{not json").is_err());
    }
}
