use std::path::PathBuf;

use clap::{Parser, Subcommand};
use pigui_core::client::DaemonClient;
use pigui_core::config::Config;
use pigui_core::rpc::{
    AlertList, AlertsQuery, DestinationList, DestinationsQuery, METHOD_ALERTS_LIST,
    METHOD_DESTINATIONS_LIST, METHOD_STATUS, StatusPayload,
};
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
    /// Ingest an alert_json file directly into SQLite.
    Ingest {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        db: Option<PathBuf>,
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
            let client = DaemonClient::new(&config.socket_path);
            let status: StatusPayload = client.call_typed(METHOD_STATUS, json!({}))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                print_status(&status, &config);
            }
        }
        Command::Alerts { limit, json } => {
            let client = DaemonClient::new(&config.socket_path);
            let query = AlertsQuery {
                limit: Some(limit),
                offset: None,
            };
            let list: AlertList =
                client.call_typed(METHOD_ALERTS_LIST, serde_json::to_value(query)?)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                print_alerts(&list);
            }
        }
        Command::Destinations { limit, json } => {
            let client = DaemonClient::new(&config.socket_path);
            let query = DestinationsQuery {
                limit: Some(limit),
                offset: None,
            };
            let list: DestinationList =
                client.call_typed(METHOD_DESTINATIONS_LIST, serde_json::to_value(query)?)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else {
                print_destinations(&list);
            }
        }
        Command::Ingest { file, db } => {
            if let Some(db) = db {
                config.db_path = db;
            }
            let mut store = Store::open(&config.db_path)?;
            let stats = ingest::ingest_file(&mut store, &file)?;
            println!("{}", serde_json::to_string_pretty(&stats)?);
        }
    }

    Ok(())
}

fn print_status(status: &StatusPayload, config: &Config) {
    let caps = &status.capabilities;
    println!("PIGUI daemon status");
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
    println!("  database:        {}", status.db_path);
    println!("  socket:          {}", status.socket_path);
    println!("  alert file:      {}", status.alert_json);
    println!("  alerts stored:   {}", status.alert_count);
    println!("  destinations:    {}", status.destination_count);
    println!("  ingested total:  {}", status.alerts_ingested);
    println!("  parse errors:    {}", status.parse_errors);
    println!("  config dir:      {}", config.home.display());

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
        "{:<24} {:<8} {:<12} {:<12} blocked",
        "ip", "alerts", "first seen", "last seen"
    );
    for destination in &list.destinations {
        println!(
            "{:<24} {:<8} {:<12} {:<12} {}",
            destination.ip,
            destination.alert_count,
            destination.first_seen,
            destination.last_seen,
            yes_no(destination.blocked),
        );
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
