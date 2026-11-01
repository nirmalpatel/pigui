use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use pigui_core::Config;
use pigui_daemon::api;
use pigui_daemon::ingest;
use pigui_daemon::state::AppState;
use pigui_daemon::store::Store;
use pigui_snort::Tailer;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "pigui-daemon",
    version,
    about = "PIGUI ingestion and local API daemon"
)]
struct Args {
    /// Alert JSON file to tail. Defaults to PIGUI_ALERT_JSON.
    #[arg(long)]
    alerts_file: Option<PathBuf>,

    /// Start reading at the current end of the alert file.
    #[arg(long)]
    from_end: bool,

    /// Ingest the alert file once and exit.
    #[arg(long)]
    once: bool,

    /// Override the SQLite database path.
    #[arg(long)]
    db: Option<PathBuf>,

    /// Override the daemon socket path.
    #[arg(long)]
    socket: Option<PathBuf>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let args = Args::parse();

    let mut config = Config::load()?;
    if let Some(db) = args.db {
        config.db_path = config.resolve(&db);
    }
    if let Some(socket) = args.socket {
        config.socket_path = config.resolve(&socket);
    }

    let alerts_file = args
        .alerts_file
        .map(|path| config.resolve(&path))
        .unwrap_or_else(|| config.alert_json.clone());
    config.alert_json = alerts_file.clone();
    config.ensure_dirs()?;

    let mut store = Store::open(&config.db_path)?;

    if args.once {
        if !alerts_file.is_file() {
            anyhow::bail!("alert file not found: {}", alerts_file.display());
        }
        let stats = ingest::ingest_file(&mut store, &alerts_file)?;
        println!("{}", serde_json::to_string_pretty(&stats)?);
        return Ok(());
    }

    let capabilities = pigui_snort::probe(&config);
    for warning in &capabilities.warnings {
        tracing::warn!(warning = %warning);
    }

    let tailer = if args.from_end {
        Tailer::from_end(&alerts_file)?
    } else {
        Tailer::new(&alerts_file)
    };

    let state = Arc::new(AppState::new(config.clone(), store, capabilities));

    let api_state = state.clone();
    let api_task = tokio::spawn(async move {
        if let Err(error) = api::serve(api_state).await {
            tracing::error!(%error, "daemon API failed");
        }
    });

    let ingest_state = state.clone();
    tokio::spawn(async move {
        ingest::run(ingest_state, tailer).await;
    });

    tracing::info!(
        db = %config.db_path.display(),
        alerts = %alerts_file.display(),
        socket = %config.socket_path.display(),
        "pigui-daemon started"
    );

    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("received interrupt"),
        _ = terminate_signal() => tracing::info!("received terminate signal"),
        _ = state.wait_for_shutdown() => tracing::info!("shutdown requested via api"),
    }

    state.request_shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), api_task).await;
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(std::io::stdout().is_terminal())
        .try_init();
}

#[cfg(unix)]
async fn terminate_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    match signal(SignalKind::terminate()) {
        Ok(mut stream) => {
            stream.recv().await;
        }
        Err(_) => std::future::pending::<()>().await,
    }
}

#[cfg(not(unix))]
async fn terminate_signal() {
    std::future::pending::<()>().await;
}
