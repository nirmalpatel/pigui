use serde_json::Value;

pub fn format_utc(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

pub fn add_timestamps(value: &mut Value) {
    match value {
        Value::Object(object) => {
            let mut additions = Vec::new();
            for (key, child) in object.iter() {
                if timestamp_key(key)
                    && let Some(seconds) = child.as_i64()
                {
                    additions.push((format!("{key}_iso"), format_utc(seconds)));
                }
            }
            for (key, value) in additions {
                object.entry(key).or_insert(Value::String(value));
            }
            for child in object.values_mut() {
                add_timestamps(child);
            }
        }
        Value::Array(items) => {
            for item in items {
                add_timestamps(item);
            }
        }
        _ => {}
    }
}

fn timestamp_key(key: &str) -> bool {
    matches!(
        key,
        "ts" | "first_seen"
            | "last_seen"
            | "since"
            | "until"
            | "generated_at"
            | "event_ts"
            | "started_at"
            | "updated_at"
            | "created_at"
            | "ingested_at"
            | "expires_at"
            | "last_ingest"
            | "last_run"
            | "ran_at"
            | "applied_at"
    ) || key.ends_with("_ts")
        || (key.ends_with("_at") && !key.ends_with("_iso"))
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    (year + i64::from(month <= 2), month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn formats_epoch_and_leap_day() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn adds_iso_fields_recursively() {
        let mut value = json!({
            "ts": 0,
            "nested": [{"first_seen": 1_709_164_800, "port": 443}]
        });
        add_timestamps(&mut value);
        assert_eq!(value["ts_iso"], "1970-01-01T00:00:00Z");
        assert_eq!(value["nested"][0]["first_seen_iso"], "2024-02-29T00:00:00Z");
        assert!(value["nested"][0].get("port_iso").is_none());
    }
}
