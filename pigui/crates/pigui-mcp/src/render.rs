use serde_json::{Map, Value};

use crate::redact::redact_users;
use crate::settings::McpSettings;
use crate::timefmt::add_timestamps;

pub struct Rendered {
    pub text: String,
    pub structured: Map<String, Value>,
}

pub fn render_tool_value(mut value: Value, settings: &McpSettings) -> Rendered {
    if settings.redact_users {
        redact_users(&mut value);
    }
    sanitize_value(&mut value, None);
    add_timestamps(&mut value);
    if cap_arrays(&mut value, settings.max_rows) {
        mark_truncated(&mut value, "row cap applied");
    }
    annotate_returns(&mut value);

    if let Value::Object(ref mut object) = value
        && let Some(total) = object.get("total").and_then(Value::as_u64)
    {
        for key in [
            "alerts",
            "destinations",
            "flows",
            "processes",
            "connections",
            "domains",
            "observations",
            "watched",
        ] {
            if let Some(rows) = object.get(key).and_then(Value::as_array)
                && (rows.len() as u64) < total
            {
                object.insert("truncated".into(), Value::Bool(true));
                object
                    .entry("truncated_reason")
                    .or_insert_with(|| Value::String("row limit applied".into()));
            }
        }
    }

    let mut text = serde_json::to_string(&value).unwrap_or_else(|error| {
        format!("{{\"error\":\"failed to serialize tool result: {error}\"}}")
    });

    while text.len() > settings.max_bytes && pop_one_array_item(&mut value) {
        mark_truncated(&mut value, "response byte cap applied");
        text = serde_json::to_string(&value).unwrap_or_default();
    }

    if text.len() > settings.max_bytes {
        shrink_strings(&mut value, 256);
        mark_truncated(&mut value, "response byte cap applied");
        text = serde_json::to_string(&value).unwrap_or_default();
    }

    if text.len() > settings.max_bytes {
        let fallback = serde_json::json!({
            "truncated": true,
            "truncated_reason": format!(
                "response exceeded PIGUI_MCP_MAX_BYTES ({}) after truncation",
                settings.max_bytes
            ),
        });
        text = serde_json::to_string(&fallback).unwrap_or_else(|_| "{}".into());
        value = fallback;
    }

    let structured = match value {
        Value::Object(object) => object,
        other => {
            let mut object = Map::new();
            object.insert("result".into(), other);
            object
        }
    };
    Rendered { text, structured }
}

fn annotate_returns(value: &mut Value) {
    match value {
        Value::Object(object) => {
            if object.contains_key("total") {
                let returned = [
                    "alerts",
                    "destinations",
                    "flows",
                    "processes",
                    "connections",
                    "domains",
                    "observations",
                    "watched",
                ]
                .iter()
                .find_map(|key| object.get(*key).and_then(Value::as_array).map(Vec::len));
                if let Some(returned) = returned {
                    object
                        .entry("returned")
                        .or_insert_with(|| Value::from(returned as u64));
                }
            }
            for child in object.values_mut() {
                annotate_returns(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                annotate_returns(item);
            }
        }
        _ => {}
    }
}

fn cap_arrays(value: &mut Value, max_rows: u32) -> bool {
    match value {
        Value::Array(items) => {
            let mut truncated = items.len() > max_rows as usize;
            if truncated {
                items.truncate(max_rows as usize);
            }
            for item in items {
                truncated |= cap_arrays(item, max_rows);
            }
            truncated
        }
        Value::Object(object) => object.values_mut().fold(false, |truncated, child| {
            truncated | cap_arrays(child, max_rows)
        }),
        _ => false,
    }
}

fn sanitize_value(value: &mut Value, key: Option<&str>) {
    match value {
        Value::String(text) => {
            let cleaned = sanitize_text(text);
            let limit = key.and_then(string_limit).unwrap_or(1_024);
            *text = truncate_chars(&cleaned, limit);
        }
        Value::Object(object) => {
            for (child_key, child) in object.iter_mut() {
                sanitize_value(child, Some(child_key));
            }
        }
        Value::Array(items) => {
            for item in items {
                sanitize_value(item, key);
            }
        }
        _ => {}
    }
}

fn sanitize_text(text: &str) -> String {
    text.chars()
        .map(|character| match character {
            '\u{0000}'..='\u{001f}' | '\u{007f}'..='\u{009f}' => ' ',
            other => other,
        })
        .collect()
}

fn string_limit(key: &str) -> Option<usize> {
    match key {
        "user_agent" | "uri" | "hostname" | "server_name" | "query" | "answers" => Some(512),
        "path" => Some(2_048),
        "user" => Some(128),
        _ => None,
    }
}

fn truncate_chars(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    let mut truncated = text.chars().take(limit).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn pop_one_array_item(value: &mut Value) -> bool {
    match value {
        Value::Array(items) => {
            if !items.is_empty() {
                items.pop();
                return true;
            }
            items.iter_mut().any(pop_one_array_item)
        }
        Value::Object(object) => object.values_mut().any(pop_one_array_item),
        _ => false,
    }
}

fn mark_truncated(value: &mut Value, reason: &str) {
    if let Value::Object(object) = value {
        object.insert("truncated".into(), Value::Bool(true));
        object.insert("truncated_reason".into(), Value::String(reason.into()));
    }
}

fn shrink_strings(value: &mut Value, limit: usize) {
    match value {
        Value::String(text) => {
            *text = truncate_chars(text, limit);
        }
        Value::Array(items) => {
            for item in items {
                shrink_strings(item, limit);
            }
        }
        Value::Object(object) => {
            for child in object.values_mut() {
                shrink_strings(child, limit);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn settings() -> McpSettings {
        McpSettings {
            max_rows: 10,
            max_bytes: 4_096,
            redact_users: true,
            include_noise: false,
        }
    }

    #[test]
    fn caps_rows_and_annotates_returns() {
        let rows = (0..50).map(|value| json!({"n": value})).collect::<Vec<_>>();
        let rendered = render_tool_value(json!({"alerts": rows, "total": 50}), &settings());
        let parsed: Value = serde_json::from_str(&rendered.text).unwrap();
        assert_eq!(parsed["alerts"].as_array().unwrap().len(), 10);
        assert_eq!(parsed["truncated"], true);
        assert_eq!(parsed["returned"], 10);
    }

    #[test]
    fn truncates_oversized_responses() {
        let rows = (0..50)
            .map(|value| json!({"n": value, "text": "x".repeat(400)}))
            .collect::<Vec<_>>();
        let rendered = render_tool_value(json!({"alerts": rows, "total": 50}), &settings());
        assert!(rendered.text.len() <= 4_096);
        assert_eq!(rendered.structured["truncated"], true);
    }

    #[test]
    fn redacts_and_sanitizes() {
        let rendered = render_tool_value(
            json!({"user": "nirmal", "message": "bad\u{0007}text", "ts": 0}),
            &settings(),
        );
        let parsed: Value = serde_json::from_str(&rendered.text).unwrap();
        assert_eq!(parsed["user"], "<redacted>");
        assert_eq!(parsed["message"], "bad text");
        assert_eq!(parsed["ts_iso"], "1970-01-01T00:00:00Z");
    }
}
