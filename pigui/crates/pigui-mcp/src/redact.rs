use serde_json::Value;

pub fn redact_users(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, child) in object.iter_mut() {
                if key == "user" && child.is_string() {
                    *child = Value::String("<redacted>".into());
                } else {
                    redact_users(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_users(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_user_but_not_user_agent() {
        let mut value = json!({
            "user": "nirmal",
            "user_agent": "Mozilla/5.0",
            "nested": [{"user": "root", "name": "curl"}]
        });
        redact_users(&mut value);
        assert_eq!(value["user"], "<redacted>");
        assert_eq!(value["user_agent"], "Mozilla/5.0");
        assert_eq!(value["nested"][0]["user"], "<redacted>");
        assert_eq!(value["nested"][0]["name"], "curl");
    }
}
