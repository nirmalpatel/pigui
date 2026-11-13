use std::net::IpAddr;

use rust_mcp_sdk::schema::{
    CallToolResult, TextContent, Tool, ToolAnnotations, ToolInputSchema,
    schema_utils::CallToolError,
};
use serde_json::{Map, Value, json};

use crate::daemon::ReadOnlyDaemon;
use crate::render::render_tool_value;
use crate::settings::McpSettings;

const DEFAULT_LIST_LIMIT: u32 = 50;

pub fn tool_definitions() -> Vec<Tool> {
    vec![
        tool(
            "status",
            "PIGUI status",
            "Read-only capture, Snort, health, and coverage status. Start here before interpreting telemetry.",
            empty_properties(),
            &[],
        ),
        tool(
            "overview",
            "PIGUI traffic overview",
            "Time-windowed read-only aggregates for traffic, processes, destinations, domains, alerts, ports, trust, and noise.",
            analysis_properties(),
            &[],
        ),
        tool(
            "findings",
            "PIGUI intruder-hunt findings",
            "Read-only evidence-based leads with severity, confidence, evidence, and suggested drill-down tools. Findings are not verdicts.",
            analysis_findings_properties(),
            &[],
        ),
        list_tool(
            "alerts",
            "PIGUI alerts",
            "Read-only Snort alert drill-down.",
            &[
                "time",
                "sid",
                "priority",
                "proto",
                "source",
                "destination",
                "action",
                "message",
            ],
            None,
        ),
        list_tool(
            "destinations",
            "PIGUI destinations",
            "Read-only destination endpoint drill-down.",
            &[
                "ip",
                "domains",
                "trust",
                "flags",
                "processes",
                "connections",
                "alerts",
                "bytes_in",
                "bytes_out",
                "first_seen",
                "last_seen",
            ],
            None,
        ),
        tool(
            "destination_detail",
            "PIGUI destination detail",
            "Read-only detail for one destination IP, including processes and recent alerts.",
            json!({
                "ip": {"type": "string", "description": "Destination IP address."}
            }),
            &["ip"],
        ),
        list_tool(
            "flows",
            "PIGUI live flows",
            "Read-only live nettop flow snapshot.",
            &[
                "process",
                "pid",
                "proto",
                "local",
                "remote",
                "state",
                "interface",
                "traffic",
                "seen",
            ],
            None,
        ),
        list_tool(
            "processes",
            "PIGUI processes",
            "Read-only process inventory with network byte counters.",
            &[
                "process",
                "pid",
                "user",
                "connections",
                "bytes_in",
                "bytes_out",
                "path",
                "last_seen",
            ],
            None,
        ),
        tool(
            "process_detail",
            "PIGUI process detail",
            "Read-only detail for one PID, including destinations and trust context.",
            json!({
                "pid": {"type": "integer", "minimum": 1, "description": "Process ID."}
            }),
            &["pid"],
        ),
        list_tool(
            "connections",
            "PIGUI connections",
            "Read-only completed connection records from the Snort extractor.",
            &[
                "time", "process", "pid", "proto", "remote", "service", "state", "traffic",
            ],
            None,
        ),
        list_tool(
            "domains",
            "PIGUI domains",
            "Read-only registrable-domain summaries. Use trust=needs_review for unknown or suspicious domains.",
            &[
                "domain",
                "hostnames",
                "sources",
                "trust",
                "flags",
                "ips",
                "processes",
                "observed",
                "first_seen",
                "last_seen",
            ],
            Some(json!({
                "trust": {
                    "type": "string",
                    "enum": ["all", "unknown", "trusted", "suspicious", "ignored", "needs_review"],
                    "description": "Optional trust filter."
                }
            })),
        ),
        list_tool(
            "dns",
            "PIGUI DNS observations",
            "Read-only DNS query observations and trust context.",
            &[
                "time", "client", "query", "type", "rcode", "answers", "ttl", "trust",
            ],
            None,
        ),
        list_tool(
            "tls",
            "PIGUI TLS observations",
            "Read-only TLS SNI, version, and validation observations.",
            &[
                "time",
                "sniname",
                "client",
                "server",
                "version",
                "validation",
            ],
            None,
        ),
        list_tool(
            "http",
            "PIGUI HTTP observations",
            "Read-only HTTP host, URI, method, user-agent, and status observations.",
            &[
                "time", "method", "host", "uri", "client", "server", "status",
            ],
            None,
        ),
        list_tool(
            "quic",
            "PIGUI QUIC observations",
            "Read-only QUIC SNI and client-protocol observations.",
            &["time", "sniname", "client", "server", "protocol"],
            None,
        ),
        tool(
            "watched_domains",
            "PIGUI watched domains",
            "Read-only forward-resolution watchlist status.",
            empty_properties(),
            &[],
        ),
        tool(
            "maintenance",
            "PIGUI maintenance stats",
            "Read-only database size, table row counts, and retention evidence.",
            empty_properties(),
            &[],
        ),
        tool(
            "firewall_summary",
            "PIGUI firewall summary",
            "Read-only firewall state, rules, and dynamic blocks. This cannot modify enforcement.",
            empty_properties(),
            &[],
        ),
    ]
}

pub async fn call_tool(
    daemon: &ReadOnlyDaemon,
    settings: &McpSettings,
    name: &str,
    arguments: Option<Map<String, Value>>,
) -> Result<CallToolResult, CallToolError> {
    let arguments = arguments.unwrap_or_default();
    match name {
        "status" => status(daemon, settings).await,
        "overview" => analysis(daemon, settings, "analysis.overview", &arguments).await,
        "findings" => analysis(daemon, settings, "analysis.findings", &arguments).await,
        "alerts" => {
            list(
                daemon,
                settings,
                "alerts.list",
                &arguments,
                &[
                    "time",
                    "sid",
                    "priority",
                    "proto",
                    "source",
                    "destination",
                    "action",
                    "message",
                ],
                None,
            )
            .await
        }
        "destinations" => {
            list(
                daemon,
                settings,
                "destinations.list",
                &arguments,
                &[
                    "ip",
                    "domains",
                    "trust",
                    "flags",
                    "processes",
                    "connections",
                    "alerts",
                    "bytes_in",
                    "bytes_out",
                    "first_seen",
                    "last_seen",
                ],
                None,
            )
            .await
        }
        "destination_detail" => {
            let ip = required_string(&arguments, "ip")?;
            if ip.parse::<IpAddr>().is_err() {
                return Err(tool_error("ip must be a valid IPv4 or IPv6 address"));
            }
            let value = daemon
                .call("destinations.detail", json!({ "ip": ip }))
                .await
                .map_err(tool_error)?;
            result(value, settings)
        }
        "flows" => {
            list(
                daemon,
                settings,
                "flows.list",
                &arguments,
                &[
                    "process",
                    "pid",
                    "proto",
                    "local",
                    "remote",
                    "state",
                    "interface",
                    "traffic",
                    "seen",
                ],
                None,
            )
            .await
        }
        "processes" => {
            list(
                daemon,
                settings,
                "processes.list",
                &arguments,
                &[
                    "process",
                    "pid",
                    "user",
                    "connections",
                    "bytes_in",
                    "bytes_out",
                    "path",
                    "last_seen",
                ],
                None,
            )
            .await
        }
        "process_detail" => {
            let pid = required_u32(&arguments, "pid")?;
            let value = daemon
                .call("processes.detail", json!({ "pid": pid }))
                .await
                .map_err(tool_error)?;
            result(value, settings)
        }
        "connections" => {
            list(
                daemon,
                settings,
                "connections.list",
                &arguments,
                &[
                    "time", "process", "pid", "proto", "remote", "service", "state", "traffic",
                ],
                None,
            )
            .await
        }
        "domains" => {
            let trust = optional_string(&arguments, "trust")?;
            if let Some(ref trust) = trust
                && !matches!(
                    trust.as_str(),
                    "all" | "unknown" | "trusted" | "suspicious" | "ignored" | "needs_review"
                )
            {
                return Err(tool_error(
                    "trust must be all, unknown, trusted, suspicious, ignored, or needs_review",
                ));
            }
            list(
                daemon,
                settings,
                "domains.list",
                &arguments,
                &[
                    "domain",
                    "hostnames",
                    "sources",
                    "trust",
                    "flags",
                    "ips",
                    "processes",
                    "observed",
                    "first_seen",
                    "last_seen",
                ],
                trust,
            )
            .await
        }
        "dns" => {
            list(
                daemon,
                settings,
                "dns.list",
                &arguments,
                &[
                    "time", "client", "query", "type", "rcode", "answers", "ttl", "trust",
                ],
                None,
            )
            .await
        }
        "tls" => {
            list(
                daemon,
                settings,
                "tls.list",
                &arguments,
                &[
                    "time",
                    "sniname",
                    "client",
                    "server",
                    "version",
                    "validation",
                ],
                None,
            )
            .await
        }
        "http" => {
            list(
                daemon,
                settings,
                "http.list",
                &arguments,
                &[
                    "time", "method", "host", "uri", "client", "server", "status",
                ],
                None,
            )
            .await
        }
        "quic" => {
            list(
                daemon,
                settings,
                "quic.list",
                &arguments,
                &["time", "sniname", "client", "server", "protocol"],
                None,
            )
            .await
        }
        "watched_domains" => {
            let value = daemon
                .call("watched.list", json!({}))
                .await
                .map_err(tool_error)?;
            result(value, settings)
        }
        "maintenance" => {
            let value = daemon
                .call("maintenance.stats", json!({}))
                .await
                .map_err(tool_error)?;
            result(value, settings)
        }
        "firewall_summary" => firewall_summary(daemon, settings).await,
        other => Err(CallToolError::unknown_tool(other)),
    }
}

async fn status(
    daemon: &ReadOnlyDaemon,
    settings: &McpSettings,
) -> Result<CallToolResult, CallToolError> {
    let mut output = Map::new();
    let status = daemon.call("status", json!({})).await.map_err(tool_error)?;
    output.insert("status".into(), status);
    for (key, method) in [("health", "health"), ("snort", "snort.status")] {
        match daemon.call(method, json!({})).await {
            Ok(value) => {
                output.insert(key.into(), value);
            }
            Err(error) => {
                output.insert(format!("{key}_error"), Value::String(error.to_string()));
            }
        }
    }
    result(Value::Object(output), settings)
}

async fn firewall_summary(
    daemon: &ReadOnlyDaemon,
    settings: &McpSettings,
) -> Result<CallToolResult, CallToolError> {
    let mut output = Map::new();
    let status = daemon
        .call("firewall.status", json!({}))
        .await
        .map_err(tool_error)?;
    output.insert("status".into(), status);
    for (key, method) in [
        ("rules", "firewall.rules.list"),
        ("blocks", "firewall.blocks.list"),
    ] {
        match daemon.call(method, json!({})).await {
            Ok(value) => {
                output.insert(key.into(), value);
            }
            Err(error) => {
                output.insert(format!("{key}_error"), Value::String(error.to_string()));
            }
        }
    }
    result(Value::Object(output), settings)
}

async fn list(
    daemon: &ReadOnlyDaemon,
    settings: &McpSettings,
    method: &str,
    arguments: &Map<String, Value>,
    sort_keys: &[&str],
    trust: Option<String>,
) -> Result<CallToolResult, CallToolError> {
    let limit = arguments
        .get("limit")
        .and_then(Value::as_u64)
        .map(|value| value as u32)
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, settings.max_rows);
    let offset = arguments
        .get("offset")
        .and_then(Value::as_u64)
        .map(|value| value as u32)
        .unwrap_or(0);
    let search = optional_string(arguments, "q")?;
    if let Some(ref search) = search
        && search.chars().count() > 256
    {
        return Err(tool_error("q must be 256 characters or fewer"));
    }
    let sort = optional_string(arguments, "sort")?;
    if let Some(ref sort) = sort
        && !sort_keys.contains(&sort.as_str())
    {
        return Err(tool_error(format!(
            "sort must be one of: {}",
            sort_keys.join(", ")
        )));
    }
    let direction = optional_string(arguments, "dir")?.unwrap_or_else(|| "desc".into());
    if !matches!(direction.as_str(), "asc" | "desc") {
        return Err(tool_error("dir must be asc or desc"));
    }

    let mut params = Map::new();
    params.insert("limit".into(), Value::from(limit));
    params.insert("offset".into(), Value::from(offset));
    if let Some(search) = search {
        params.insert("q".into(), Value::String(search));
    }
    if let Some(sort) = sort {
        params.insert("sort".into(), Value::String(sort));
    }
    params.insert("dir".into(), Value::String(direction));
    if let Some(trust) = trust {
        params.insert("trust".into(), Value::String(trust));
    }
    let value = daemon
        .call(method, Value::Object(params))
        .await
        .map_err(tool_error)?;
    result(value, settings)
}

async fn analysis(
    daemon: &ReadOnlyDaemon,
    settings: &McpSettings,
    method: &str,
    arguments: &Map<String, Value>,
) -> Result<CallToolResult, CallToolError> {
    let since = optional_i64(arguments, "since")?;
    let until = optional_i64(arguments, "until")?;
    if let (Some(since), Some(until)) = (since, until)
        && since >= until
    {
        return Err(tool_error("since must be earlier than until"));
    }
    let limit = arguments
        .get("limit")
        .and_then(Value::as_u64)
        .map(|value| value as u32)
        .unwrap_or(20)
        .clamp(1, settings.max_rows.min(100));
    let min_severity = optional_string(arguments, "min_severity")?;
    let include_noise = arguments
        .get("include_noise")
        .and_then(Value::as_bool)
        .unwrap_or(settings.include_noise);
    let baseline = arguments
        .get("baseline")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let query = pigui_core::models::analysis::AnalysisQuery {
        since,
        until,
        limit: Some(limit),
        min_severity,
        include_noise: Some(include_noise),
        baseline: Some(baseline),
    };
    let params = serde_json::to_value(query).map_err(|error| tool_error(error.to_string()))?;
    let value = daemon.call(method, params).await.map_err(tool_error)?;
    result(value, settings)
}

fn result(value: Value, settings: &McpSettings) -> Result<CallToolResult, CallToolError> {
    let rendered = render_tool_value(value, settings);
    Ok(
        CallToolResult::text_content(vec![TextContent::from(rendered.text)])
            .with_structured_content(rendered.structured),
    )
}

fn tool_error(message: impl std::fmt::Display) -> CallToolError {
    CallToolError::from_message(message.to_string())
}

fn required_string(arguments: &Map<String, Value>, key: &str) -> Result<String, CallToolError> {
    match arguments.get(key).and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => Ok(value.trim().to_string()),
        _ => Err(tool_error(format!("{key} is required"))),
    }
}

fn optional_string(
    arguments: &Map<String, Value>,
    key: &str,
) -> Result<Option<String>, CallToolError> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            let trimmed = value.trim();
            Ok((!trimmed.is_empty()).then(|| trimmed.to_string()))
        }
        Some(_) => Err(tool_error(format!("{key} must be a string"))),
    }
}

fn optional_i64(arguments: &Map<String, Value>, key: &str) -> Result<Option<i64>, CallToolError> {
    match arguments.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number
            .as_i64()
            .map(Some)
            .ok_or_else(|| tool_error(format!("{key} must be an integer Unix timestamp"))),
        Some(_) => Err(tool_error(format!(
            "{key} must be an integer Unix timestamp"
        ))),
    }
}

fn required_u32(arguments: &Map<String, Value>, key: &str) -> Result<u32, CallToolError> {
    let value = arguments
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| tool_error(format!("{key} is required and must be an integer")))?;
    u32::try_from(value).map_err(|_| tool_error(format!("{key} is out of range")))
}

fn empty_properties() -> Value {
    json!({})
}

fn analysis_properties() -> Value {
    json!({
        "since": {"type": "integer", "description": "Unix seconds. Defaults to 24 hours before until."},
        "until": {"type": "integer", "description": "Unix seconds. Defaults to now."},
        "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
        "include_noise": {"type": "boolean", "description": "Include multicast, broadcast, loopback, link-local, and noisy-SID evidence."},
        "baseline": {"type": "boolean", "description": "Compare with the immediately preceding equal-length window."}
    })
}

fn analysis_findings_properties() -> Value {
    let mut properties = analysis_properties();
    if let Value::Object(object) = &mut properties {
        object.insert(
            "min_severity".into(),
            json!({
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"],
                "description": "Minimum finding severity."
            }),
        );
    }
    properties
}

fn list_tool(
    name: &str,
    title: &str,
    description: &str,
    sort_keys: &[&str],
    extra: Option<Value>,
) -> Tool {
    tool(
        name,
        title,
        description,
        list_properties(sort_keys, extra),
        &[],
    )
}

fn list_properties(sort_keys: &[&str], extra: Option<Value>) -> Value {
    let mut properties = Map::new();
    properties.insert(
        "limit".into(),
        json!({"type": "integer", "minimum": 1, "default": 50}),
    );
    properties.insert(
        "offset".into(),
        json!({"type": "integer", "minimum": 0, "default": 0}),
    );
    properties.insert(
        "q".into(),
        json!({"type": "string", "maxLength": 256, "description": "Search term."}),
    );
    properties.insert(
        "sort".into(),
        json!({"type": "string", "enum": sort_keys, "description": "Sort key."}),
    );
    properties.insert(
        "dir".into(),
        json!({"type": "string", "enum": ["asc", "desc"], "default": "desc"}),
    );
    if let Some(Value::Object(extra)) = extra {
        for (key, value) in extra {
            properties.insert(key, value);
        }
    }
    Value::Object(properties)
}

fn tool(name: &str, title: &str, description: &str, properties: Value, required: &[&str]) -> Tool {
    let properties = match properties {
        Value::Object(object) => Some(
            object
                .into_iter()
                .map(|(key, value)| (key, value.as_object().cloned().unwrap_or_default()))
                .collect(),
        ),
        _ => None,
    };
    Tool {
        name: name.to_string(),
        title: Some(title.to_string()),
        description: Some(description.to_string()),
        input_schema: ToolInputSchema::new(
            required.iter().map(|value| (*value).to_string()).collect(),
            properties,
            None,
        ),
        annotations: Some(ToolAnnotations {
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: Some(false),
            read_only_hint: Some(true),
            title: Some(title.to_string()),
        }),
        execution: None,
        icons: Vec::new(),
        meta: None,
        output_schema: None,
    }
}
