use std::path::PathBuf;

use clap::{Parser, Subcommand};
use pigui_core::client::DaemonClient;
use pigui_core::config::Config;
use pigui_core::helper;
use pigui_core::paths::resolve_snort;
use pigui_core::rpc::{
    AlertList, AlertsQuery, ConnectionList, DestinationList, DnsList, DomainList, FlowList,
    HttpList, METHOD_ALERTS_LIST, METHOD_CONNECTIONS_LIST, METHOD_DESTINATIONS_LIST,
    METHOD_DNS_LIST, METHOD_DOMAINS_LIST, METHOD_DOMAINS_SET_TRUST, METHOD_FLOWS_LIST,
    METHOD_HTTP_LIST, METHOD_PROCESSES_LIST, METHOD_STATUS, METHOD_TLS_LIST, METHOD_WATCHED_ADD,
    METHOD_WATCHED_LIST, METHOD_WATCHED_REMOVE, ProcessList, StatusPayload, TlsList, WatchedList,
};
use pigui_core::service::{self, ServiceAction};
use pigui_daemon::ingest;
use pigui_daemon::store::Store;
use serde_json::json;

#[derive(Debug, Parser)]
#[command(name = "pigui-cli", version, about = "PIGUI headless management CLI")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Probe the configured Snort binary and print capabilities.
    Probe,
    /// Show daemon status.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// List ingested alerts through the daemon.
    Alerts {
        #[arg(long, default_value_t = 20)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// List destination endpoints through the daemon.
    Destinations {
        #[arg(long, default_value_t = 20)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// List live flows from the nettop collector.
    Flows {
        #[arg(long, default_value_t = 40)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// List active processes.
    Processes {
        #[arg(long, default_value_t = 40)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// List completed connections from the Snort extractor.
    Connections {
        #[arg(long, default_value_t = 40)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// List DNS observations.
    Dns {
        #[arg(long, default_value_t = 20)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// List TLS observations.
    Tls {
        #[arg(long, default_value_t = 20)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// List observed domains grouped by registrable domain.
    Domains {
        #[arg(long, default_value_t = 40)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// Set trust for a registrable domain.
    Trust {
        domain: String,
        #[arg(value_parser = ["unknown", "trusted", "suspicious", "ignored"])]
        state: String,
    },
    /// List watched domains used for forward-resolution matching.
    Watched {
        #[arg(long)]
        json: bool,
    },
    /// Add or remove a watched domain.
    Watch {
        domain: String,
        #[arg(long)]
        remove: bool,
    },
    /// List HTTP observations.
    Http {
        #[arg(long, default_value_t = 20)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
    /// Ingest an alert_json file directly into SQLite.
    Ingest {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Snort configuration and process helpers.
    Snort {
        #[command(subcommand)]
        command: SnortCommand,
    },
    /// Register or inspect macOS background services.
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    /// Call the packaged privileged helper over XPC.
    Helper {
        #[command(subcommand)]
        command: HelperCommand,
    },
}

#[derive(Debug, Subcommand)]
enum SnortCommand {
    /// Generate and validate the live Snort configuration.
    GenerateConfig,
    /// Validate the generated Snort configuration.
    Validate,
    /// Show live Snort process status.
    Status {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    /// Show SMAppService registration status.
    Status,
    /// Register the unprivileged user daemon.
    RegisterAgent,
    /// Unregister the unprivileged user daemon.
    UnregisterAgent,
    /// Register the root helper. macOS requires administrator approval.
    RegisterHelper,
    /// Unregister the root helper.
    UnregisterHelper,
}

impl ServiceCommand {
    fn action(&self) -> ServiceAction {
        match self {
            Self::Status => ServiceAction::Status,
            Self::RegisterAgent => ServiceAction::RegisterAgent,
            Self::UnregisterAgent => ServiceAction::UnregisterAgent,
            Self::RegisterHelper => ServiceAction::RegisterHelper,
            Self::UnregisterHelper => ServiceAction::UnregisterHelper,
        }
    }
}

#[derive(Debug, Subcommand)]
enum HelperCommand {
    /// Show helper version, root state, and capture status.
    Status,
    /// Show the helper protocol version.
    Version,
    /// Start Snort capture through the root helper.
    EnableCapture { interface: String },
    /// Stop Snort capture.
    DisableCapture,
    /// Flush dry-run firewall state.
    FlushFirewall,
    /// Request a dry-run firewall block.
    ApplyBlock {
        ip: String,
        #[arg(long, default_value = "both")]
        direction: String,
        #[arg(long, default_value_t = 0)]
        ttl: u64,
        #[arg(long, default_value = "operator request")]
        reason: String,
    },
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut config = Config::load()?;

    match args.command {
        Command::Probe => {
            let capabilities = pigui_snort::probe(&config);
            println!("{}", serde_json::to_string_pretty(&capabilities)?);
        }
        Command::Status { json } => {
            let client = client(&config);
            let status: StatusPayload = client.call_typed(METHOD_STATUS, json!({}))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                print_status(&status, &config);
            }
        }
        Command::Alerts { limit, json } => {
            let list: AlertList = client(&config).call_typed(
                METHOD_ALERTS_LIST,
                serde_json::to_value(AlertsQuery {
                    limit: Some(limit),
                    offset: None,
                })?,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                print_alerts(&list);
            }
        }
        Command::Destinations { limit, json } => {
            let list: DestinationList = client(&config).call_typed(
                METHOD_DESTINATIONS_LIST,
                serde_json::to_value(AlertsQuery {
                    limit: Some(limit),
                    offset: None,
                })?,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                print_destinations(&list);
            }
        }
        Command::Flows { limit, json } => {
            let list: FlowList = client(&config).call_typed(
                METHOD_FLOWS_LIST,
                serde_json::to_value(AlertsQuery {
                    limit: Some(limit),
                    offset: None,
                })?,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                print_flows(&list);
            }
        }
        Command::Processes { limit, json } => {
            let list: ProcessList = client(&config).call_typed(
                METHOD_PROCESSES_LIST,
                serde_json::to_value(AlertsQuery {
                    limit: Some(limit),
                    offset: None,
                })?,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                print_processes(&list);
            }
        }
        Command::Connections { limit, json } => {
            let list: ConnectionList = client(&config).call_typed(
                METHOD_CONNECTIONS_LIST,
                serde_json::to_value(AlertsQuery {
                    limit: Some(limit),
                    offset: None,
                })?,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                print_connections(&list);
            }
        }
        Command::Domains { limit, json } => {
            let list: DomainList = client(&config).call_typed(
                METHOD_DOMAINS_LIST,
                serde_json::to_value(AlertsQuery {
                    limit: Some(limit),
                    offset: None,
                })?,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                print_domains(&list);
            }
        }
        Command::Trust { domain, state } => {
            let result = client(&config).call(
                METHOD_DOMAINS_SET_TRUST,
                json!({ "registrable_domain": domain, "state": state }),
            )?;
            println!("{result}");
        }
        Command::Watched { json } => {
            let list: WatchedList = client(&config).call_typed(METHOD_WATCHED_LIST, json!({}))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                print_watched(&list);
            }
        }
        Command::Watch { domain, remove } => {
            let method = if remove {
                METHOD_WATCHED_REMOVE
            } else {
                METHOD_WATCHED_ADD
            };
            let result = client(&config).call(method, json!({ "domain": domain }))?;
            println!("{result}");
        }
        Command::Dns { limit, json } => {
            let list: DnsList = client(&config).call_typed(
                METHOD_DNS_LIST,
                serde_json::to_value(AlertsQuery {
                    limit: Some(limit),
                    offset: None,
                })?,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                print_dns(&list);
            }
        }
        Command::Tls { limit, json } => {
            let list: TlsList = client(&config).call_typed(
                METHOD_TLS_LIST,
                serde_json::to_value(AlertsQuery {
                    limit: Some(limit),
                    offset: None,
                })?,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                print_tls(&list);
            }
        }
        Command::Http { limit, json } => {
            let list: HttpList = client(&config).call_typed(
                METHOD_HTTP_LIST,
                serde_json::to_value(AlertsQuery {
                    limit: Some(limit),
                    offset: None,
                })?,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                print_http(&list);
            }
        }
        Command::Ingest { file, db } => {
            if let Some(db) = db {
                config.db_path = config.resolve(&db);
            }
            let mut store = Store::open(&config.db_path)?;
            let stats = ingest::ingest_file(&mut store, &file)?;
            println!("{}", serde_json::to_string_pretty(&stats)?);
        }
        Command::Snort { command } => match command {
            SnortCommand::GenerateConfig => {
                let generated = pigui_snort::generate_config(&config)?;
                println!("{}", serde_json::to_string_pretty(&generated)?);
                if !generated.valid {
                    anyhow::bail!("generated Snort configuration failed validation");
                }
            }
            SnortCommand::Validate => {
                let binary = resolve_snort(&config)?;
                let path = config.snort_config_dir.join("snort.lua");
                let (valid, detail) = pigui_snort::validate_config(&binary.path, &path)?;
                println!("valid: {valid}");
                if !detail.is_empty() {
                    println!("{detail}");
                }
                if !valid {
                    anyhow::bail!("Snort configuration failed validation");
                }
            }
            SnortCommand::Status { json } => {
                let status = pigui_snort::status::status(&config);
                if json {
                    println!("{}", serde_json::to_string_pretty(&status)?);
                } else {
                    println!("running:       {}", yes_no(status.running));
                    println!("pid:           {}", optional(status.pid));
                    println!(
                        "interface:     {}",
                        status.interface.as_deref().unwrap_or("-")
                    );
                    println!(
                        "config:        {}",
                        status.config_path.as_deref().unwrap_or("-")
                    );
                    println!("log dir:       {}", status.log_dir);
                    println!("extractor:     {}", status.extractor_json);
                    println!(
                        "control sock:  {}",
                        status.control_socket.as_deref().unwrap_or("-")
                    );
                    println!("pidfile:       {}", status.pidfile);
                }
            }
        },
        Command::Service { command } => {
            print!("{}", service::run(command.action())?);
        }
        Command::Helper { command } => {
            let result = match command {
                HelperCommand::Status => helper::status()?,
                HelperCommand::Version => helper::version()?,
                HelperCommand::EnableCapture { interface } => helper::enable_capture(&interface)?,
                HelperCommand::DisableCapture => helper::disable_capture()?,
                HelperCommand::FlushFirewall => helper::flush_firewall()?,
                HelperCommand::ApplyBlock {
                    ip,
                    direction,
                    ttl,
                    reason,
                } => helper::apply_block(&ip, &direction, ttl, &reason)?,
            };
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    }

    Ok(())
}

fn client(config: &Config) -> DaemonClient {
    DaemonClient::new(&config.socket_path)
}

fn print_status(status: &StatusPayload, config: &Config) {
    let caps = &status.capabilities;
    println!("PIGUI daemon status");
    println!("  mode:            {}", status.mode);
    println!("  uptime:          {}s", status.uptime_secs);
    println!(
        "  version:         {}",
        caps.version.as_deref().unwrap_or("unknown")
    );
    println!(
        "  binary:          {}",
        caps.binary.as_deref().unwrap_or("not found")
    );
    println!(
        "  source:          {}",
        caps.source.as_deref().unwrap_or("unknown")
    );
    println!("  control socket:  {}", yes_no(caps.control_socket));
    println!("  shell:           {}", yes_no(caps.shell));
    println!("  extractor:       {}", yes_no(caps.extractor));
    println!("  alert_json:      {}", yes_no(caps.alert_json));
    println!(
        "  config valid:    {}",
        match caps.config_valid {
            Some(true) => "yes",
            Some(false) => "no",
            None => "not checked",
        }
    );
    println!("  snort running:   {}", yes_no(status.snort_running));
    println!("  snort pid:       {}", optional(status.snort_pid));
    println!(
        "  interface:       {}",
        status.snort_interface.as_deref().unwrap_or("-")
    );
    println!("  database:        {}", status.db_path);
    println!("  socket:          {}", status.socket_path);
    println!("  alert file:      {}", status.alert_json);
    println!("  alerts stored:   {}", status.alert_count);
    println!("  destinations:    {}", status.destination_count);
    println!("  active flows:    {}", status.active_flows);
    println!("  active procs:    {}", status.active_processes);
    println!("  alerts ingested: {}", status.alerts_ingested);
    println!("  extractor rows:  {}", status.extractor_ingested);
    println!("  extractor file:  {}", status.extractor_file);
    println!("  extractor size:  {} bytes", status.extractor_size);
    println!(
        "  extractor last:  {}",
        optional(status.extractor_last_ingest)
    );
    println!("  extractor idle:  {}", yes_no(status.extractor_idle));
    println!("  dns records:     {}", status.dns_count);
    println!("  tls records:     {}", status.tls_count);
    println!("  http records:    {}", status.http_count);
    println!("  quic records:    {}", status.quic_count);
    println!("  domains:         {}", status.domain_count);
    println!("  parse errors:    {}", status.parse_errors);
    println!("  config dir:      {}", config.home.display());

    if let Some(error) = &status.collector_error {
        println!("collector error:  {error}");
    }
    if !status.degraded.is_empty() {
        println!("degraded:");
        for reason in &status.degraded {
            println!("  - {reason}");
        }
    }
    if !caps.warnings.is_empty() {
        println!("warnings:");
        for warning in &caps.warnings {
            println!("  - {warning}");
        }
    }
}

fn print_alerts(list: &AlertList) {
    println!("{} alerts (showing {})", list.total, list.alerts.len());
    println!(
        "{:<12} {:<10} {:<5} {:<6} {:<22} {:<22} {:<8} message",
        "time", "sid", "prio", "proto", "source", "destination", "action"
    );
    for record in &list.alerts {
        let alert = &record.alert;
        let source = format!(
            "{}:{}",
            alert.src_ip.as_deref().unwrap_or("-"),
            alert.src_port.unwrap_or(0)
        );
        let destination = format!(
            "{}:{}",
            alert.dst_ip.as_deref().unwrap_or("-"),
            alert.dst_port.unwrap_or(0)
        );
        println!(
            "{:<12} {:<10} {:<5} {:<6} {:<22} {:<22} {:<8} {}",
            alert.event_ts,
            alert.sid,
            alert
                .priority
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".into()),
            alert.proto.as_deref().unwrap_or("-"),
            source,
            destination,
            alert.action.as_deref().unwrap_or("-"),
            alert.msg.as_deref().unwrap_or("-"),
        );
    }
}

fn print_destinations(list: &DestinationList) {
    println!(
        "{} destinations (showing {})",
        list.total,
        list.destinations.len()
    );
    println!(
        "{:<24} {:<28} {:<10} {:<8} {:<10} {:<10} blocked",
        "ip", "hostname", "trust", "alerts", "processes", "flow bytes"
    );
    for destination in &list.destinations {
        println!(
            "{:<24} {:<28} {:<10} {:<8} {:<10} {:<10} {}",
            destination.ip,
            destination.hostname.as_deref().unwrap_or("-"),
            destination.trust_state,
            destination.alert_count,
            destination.process_count,
            destination.bytes_in + destination.bytes_out,
            yes_no(destination.blocked),
        );
    }
}

fn print_domains(list: &DomainList) {
    println!("{} domains (showing {})", list.total, list.domains.len());
    println!(
        "{:<32} {:<10} {:<8} {:<10} {:<10} {:<16} hostnames",
        "domain", "trust", "ips", "processes", "observed", "sources"
    );
    for domain in &list.domains {
        println!(
            "{:<32} {:<10} {:<8} {:<10} {:<10} {:<16} {}",
            domain.domain,
            domain.trust_state,
            domain.endpoint_count,
            domain.process_count,
            domain.observation_count,
            domain.sources.join(","),
            domain.hostnames.join(","),
        );
    }
}

fn print_watched(list: &WatchedList) {
    println!("{} watched domains", list.watched.len());
    println!(
        "{:<32} {:<32} {:<10} last resolved",
        "domain", "registrable", "status"
    );
    for watched in &list.watched {
        println!(
            "{:<32} {:<32} {:<10} {}",
            watched.domain,
            watched.registrable_domain,
            if watched.enabled {
                "enabled"
            } else {
                "disabled"
            },
            optional(watched.last_resolved_at),
        );
    }
}

fn print_flows(list: &FlowList) {
    println!("{} flows (showing {})", list.total, list.flows.len());
    println!(
        "{:<10} {:<8} {:<6} {:<20} {:<34} {:<12} {:<22} bytes ab/ba",
        "process", "pid", "proto", "state", "remote", "interface", "local"
    );
    for flow in &list.flows {
        let local = format!("{}:{}", flow.client_ip, flow.client_port);
        let remote = format!("{}:{}", flow.server_ip, flow.server_port);
        let bytes = format!("{}/{}", flow.bytes_ab, flow.bytes_ba);
        println!(
            "{:<10} {:<8} {:<6} {:<20} {:<34} {:<12} {:<22} {}",
            flow.process_name.as_deref().unwrap_or("-"),
            optional(flow.pid),
            flow.proto,
            flow.state.as_deref().unwrap_or("-"),
            remote,
            flow.interface.as_deref().unwrap_or("-"),
            local,
            bytes,
        );
    }
}

fn print_processes(list: &ProcessList) {
    println!(
        "{} processes (showing {})",
        list.total,
        list.processes.len()
    );
    println!(
        "{:<8} {:<24} {:<8} {:<14} {:<14} last seen",
        "pid", "name", "conns", "bytes in", "bytes out"
    );
    for process in &list.processes {
        println!(
            "{:<8} {:<24} {:<8} {:<14} {:<14} {}",
            process.pid,
            process.name,
            process.connection_count,
            process.bytes_in,
            process.bytes_out,
            process.last_seen,
        );
    }
}

fn print_connections(list: &ConnectionList) {
    println!(
        "{} connections (showing {})",
        list.total,
        list.connections.len()
    );
    println!(
        "{:<12} {:<12} {:<8} {:<6} {:<34} {:<12} {:<10} bytes ab/ba",
        "time", "process", "pid", "proto", "remote", "service", "state"
    );
    for connection in &list.connections {
        let remote = format!(
            "{}:{}",
            connection.server_ip.as_deref().unwrap_or("-"),
            connection.server_port.unwrap_or(0)
        );
        let bytes = format!("{}/{}", connection.bytes_ab, connection.bytes_ba);
        println!(
            "{:<12} {:<12} {:<8} {:<6} {:<34} {:<12} {:<10} {}",
            connection.ts,
            connection.process_name.as_deref().unwrap_or("-"),
            optional(connection.pid),
            connection.proto.as_deref().unwrap_or("-"),
            remote,
            connection.service.as_deref().unwrap_or("-"),
            connection.conn_state.as_deref().unwrap_or("-"),
            bytes,
        );
    }
}

fn print_dns(list: &DnsList) {
    println!(
        "{} DNS observations (showing {})",
        list.total,
        list.observations.len()
    );
    println!(
        "{:<12} {:<24} {:<10} {:<12} answers",
        "time", "query", "type", "rcode"
    );
    for observation in &list.observations {
        println!(
            "{:<12} {:<24} {:<10} {:<12} {}",
            observation.ts,
            observation.query.as_deref().unwrap_or("-"),
            observation.qtype.as_deref().unwrap_or("-"),
            observation.rcode.as_deref().unwrap_or("-"),
            observation.answers.as_deref().unwrap_or("-"),
        );
    }
}

fn print_tls(list: &TlsList) {
    println!(
        "{} TLS observations (showing {})",
        list.total,
        list.observations.len()
    );
    println!(
        "{:<12} {:<28} {:<16} {:<34} status",
        "time", "server name", "version", "server ip"
    );
    for observation in &list.observations {
        let server = format!(
            "{}:{}",
            observation.server_ip.as_deref().unwrap_or("-"),
            observation.server_port.unwrap_or(0)
        );
        println!(
            "{:<12} {:<28} {:<16} {:<34} {}",
            observation.ts,
            observation.server_name.as_deref().unwrap_or("-"),
            observation.version.as_deref().unwrap_or("-"),
            server,
            observation.validation_status.as_deref().unwrap_or("-"),
        );
    }
}

fn print_http(list: &HttpList) {
    println!(
        "{} HTTP observations (showing {})",
        list.total,
        list.observations.len()
    );
    println!(
        "{:<12} {:<8} {:<28} {:<10} uri",
        "time", "method", "host", "status"
    );
    for observation in &list.observations {
        println!(
            "{:<12} {:<8} {:<28} {:<10} {}",
            observation.ts,
            observation.method.as_deref().unwrap_or("-"),
            observation.host.as_deref().unwrap_or("-"),
            observation.status_code.as_deref().unwrap_or("-"),
            observation.uri.as_deref().unwrap_or("-"),
        );
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn optional<T: std::fmt::Display>(value: Option<T>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string())
}
