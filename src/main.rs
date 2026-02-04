//! monarch-lazyvpn - TUI WireGuard multi-provider VPN manager

mod app;
mod core;
mod system;
mod tui;
mod utils;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::{error, info, Level};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

// Global guard to keep logging active for the lifetime of the program
static LOG_GUARD: Mutex<Option<tracing_appender::non_blocking::WorkerGuard>> = Mutex::new(None);

/// TUI WireGuard multi-provider VPN manager
#[derive(Parser)]
#[command(name = "monarch-lazyvpn")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Run in debug mode
    #[arg(short, long)]
    debug: bool,

    /// Output format (for CLI commands)
    #[arg(long, value_enum, default_value = "text")]
    format: OutputFormat,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to a VPN server
    Connect {
        /// Server ID or name to connect to
        server: String,
    },
    /// Disconnect from VPN
    Disconnect,
    /// Show current VPN status
    Status,
    /// List available servers
    #[command(name = "list-servers")]
    ListServers {
        /// Filter by country
        #[arg(short, long)]
        country: Option<String>,
    },
    /// Import a WireGuard config file
    Import {
        /// Path to the .conf file
        path: PathBuf,
    },
    /// Reset all configuration (config, credentials, cache, state)
    Reset {
        /// Skip confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = if cli.debug { Level::DEBUG } else { Level::INFO };

    // Only log to file in TUI mode
    if cli.command.is_none() {
        setup_file_logging(log_level)?;
    } else {
        // CLI mode: minimal logging to stderr
        tracing_subscriber::registry()
            .with(fmt::layer().with_writer(std::io::stderr))
            .with(EnvFilter::from_default_env().add_directive(log_level.into()))
            .init();
    }

    // Handle CLI commands (headless mode)
    if let Some(command) = cli.command {
        return run_cli_command(command, cli.format).await;
    }

    // TUI mode
    info!("Starting monarch-lazyvpn TUI...");

    // Create PID file
    system::cleanup::create_pid_file()?;

    // Setup signal handlers for graceful shutdown
    // Handle SIGINT (Ctrl+C), SIGTERM (kill), and SIGHUP (terminal closed/Alt+F4)
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

    // Create channel to forward shutdown signals to TUI
    let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel::<&'static str>(1);

    // Spawn signal handler task
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = sigint.recv() => {
                info!("Received SIGINT (Ctrl+C)");
                let _ = shutdown_tx_clone.send("SIGINT").await;
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM");
                let _ = shutdown_tx_clone.send("SIGTERM").await;
            }
            _ = sighup.recv() => {
                info!("Received SIGHUP (terminal closed)");
                let _ = shutdown_tx_clone.send("SIGHUP").await;
            }
        }
    });

    // Run cleanup before starting
    system::cleanup::cleanup_orphaned_state().await?;

    // Create and run TUI
    let mut tui_app = tui::TuiApp::new(shutdown_rx).await?;

    // Run TUI - it will handle shutdown signals internally
    if let Err(e) = tui_app.run().await {
        error!("TUI error: {}", e);
    }

    // Cleanup
    tui::restore()?;
    system::cleanup::remove_pid_file()?;

    info!("Goodbye!");
    Ok(())
}

/// Setup file logging with size-based rotation (5MB, keep 3 files, gzip compression)
fn setup_file_logging(level: Level) -> anyhow::Result<()> {
    let config_dir = core::config::AppConfig::config_dir()?;
    std::fs::create_dir_all(&config_dir)?;

    // Perform rotation check before starting logging
    let log_file = config_dir.join("debug.log");
    rotate_log_if_needed(&log_file)?;

    // Use non-rotating appender (we handle rotation manually)
    let file_appender = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file)?;

    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
        )
        .with(EnvFilter::from_default_env().add_directive(level.into()))
        .init();

    // Store guard globally to keep logging active for program lifetime
    *LOG_GUARD.lock().unwrap() = Some(guard);

    Ok(())
}

/// Rotate log file if it exceeds 5MB
/// Keeps last 3 rotated files (debug.log.1.gz, .2.gz, .3.gz)
fn rotate_log_if_needed(log_file: &std::path::Path) -> anyhow::Result<()> {
    const MAX_LOG_SIZE: u64 = 5 * 1024 * 1024; // 5MB
    const MAX_ROTATED_FILES: u32 = 3;

    if !log_file.exists() {
        return Ok(());
    }

    let metadata = std::fs::metadata(log_file)?;
    if metadata.len() < MAX_LOG_SIZE {
        return Ok(()); // No rotation needed
    }

    info!("Rotating log file (size: {} bytes)", metadata.len());

    // Rotate existing backups: .2.gz -> .3.gz, .1.gz -> .2.gz
    for i in (1..MAX_ROTATED_FILES).rev() {
        let old = log_file.with_extension(format!("log.{}.gz", i));
        let new = log_file.with_extension(format!("log.{}.gz", i + 1));
        if old.exists() {
            if new.exists() {
                let _ = std::fs::remove_file(&new); // Remove oldest
            }
            std::fs::rename(&old, &new)?;
        }
    }

    // Compress current log to .1.gz
    let rotated = log_file.with_extension("log.1.gz");
    compress_log_file(log_file, &rotated)?;

    // Truncate current log
    std::fs::write(log_file, "")?;

    Ok(())
}

/// Compress log file with gzip
fn compress_log_file(
    source: &std::path::Path,
    dest: &std::path::Path,
) -> anyhow::Result<()> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::{Read, Write};

    let mut input = std::fs::File::open(source)?;
    let output = std::fs::File::create(dest)?;
    let mut encoder = GzEncoder::new(output, Compression::default());

    let mut buffer = Vec::new();
    input.read_to_end(&mut buffer)?;
    encoder.write_all(&buffer)?;
    encoder.finish()?;

    Ok(())
}

/// Run a CLI command in headless mode
async fn run_cli_command(command: Commands, format: OutputFormat) -> anyhow::Result<()> {
    use core::connection::ConnectionState;
    use serde_json::json;

    match command {
        Commands::Status => {
            let config = core::config::AppConfig::load()?;
            let connection = core::connection::ConnectionManager::new(&config.interface_name)?;

            let status = match connection.state() {
                ConnectionState::Connected => "connected",
                ConnectionState::Connecting => "connecting",
                ConnectionState::Disconnecting => "disconnecting",
                ConnectionState::Disconnected => "disconnected",
                ConnectionState::Error(_) => "error",
            };

            if format == OutputFormat::Json {
                let output = json!({
                    "status": status,
                    "server": connection.current_server().map(|s| &s.name),
                    "interface": connection.interface(),
                    "uptime": connection.uptime_string(),
                    "error": connection.last_error(),
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("Status: {}", status);
                if let Some(server) = connection.current_server() {
                    println!("Server: {}", server.name);
                }
                if connection.is_connected() {
                    println!("Interface: {}", connection.interface());
                    println!("Uptime: {}", connection.uptime_string());
                }
                if let Some(err) = connection.last_error() {
                    println!("Error: {}", err);
                }
            }
        }

        Commands::Connect { server } => {
            let mut app = app::App::new().await?;
            app.initialize().await?;

            // Find server
            let target = app
                .get_servers()
                .into_iter()
                .find(|s| s.id == server || s.name.contains(&server));

            match target {
                Some(s) => {
                    println!("Connecting to {}...", s.name);
                    app.connect(&s).await?;
                    println!("Connected!");
                }
                None => {
                    eprintln!("Server not found: {}", server);
                    std::process::exit(1);
                }
            }
        }

        Commands::Disconnect => {
            let mut app = app::App::new().await?;

            if !app.connection.is_connected() {
                if format == OutputFormat::Json {
                    println!(r#"{{"error": "Not connected"}}"#);
                } else {
                    eprintln!("Not connected");
                }
                std::process::exit(2);
            }

            app.disconnect().await?;

            if format == OutputFormat::Json {
                println!(r#"{{"status": "disconnected"}}"#);
            } else {
                println!("Disconnected");
            }
        }

        Commands::ListServers { country } => {
            let mut app = app::App::new().await?;
            app.initialize().await?;

            let servers: Vec<_> = app
                .get_servers()
                .into_iter()
                .filter(|s| {
                    country.as_ref().map_or(true, |c| {
                        s.country.to_lowercase().contains(&c.to_lowercase())
                            || s.country_code.to_lowercase() == c.to_lowercase()
                    })
                })
                .collect();

            if format == OutputFormat::Json {
                let output: Vec<_> = servers
                    .iter()
                    .map(|s| {
                        json!({
                            "id": s.id,
                            "name": s.name,
                            "country": s.country,
                            "country_code": s.country_code,
                            "city": s.city,
                            "ip": s.ip,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{:<20} {:<15} {:<15} {}", "ID", "Country", "City", "Name");
                println!("{}", "-".repeat(60));
                for s in servers {
                    println!(
                        "{:<20} {:<15} {:<15} {}",
                        s.id, s.country_code, s.city, s.name
                    );
                }
            }
        }

        Commands::Import { path } => {
            let mut app = app::App::new().await?;

            println!("Importing config from {:?}...", path);
            app.import_config(&path).await?;

            if format == OutputFormat::Json {
                println!(r#"{{"status": "imported"}}"#);
            } else {
                println!("Config imported successfully!");
            }
        }

        Commands::Reset { yes } => {
            if !yes {
                println!("This will delete all configuration, credentials, cache, and state.");
                println!("Are you sure? [y/N] ");

                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            let config_dir = core::config::AppConfig::config_dir()?;

            // Remove config directory
            if config_dir.exists() {
                std::fs::remove_dir_all(&config_dir)?;
                println!("Removed config directory: {:?}", config_dir);
            }

            // Clear keyring credentials
            let mut credential_manager = system::keyring::CredentialManager::new();
            for provider in &["protonvpn", "mullvad", "custom"] {
                if credential_manager.retrieve(provider).is_ok() {
                    let _ = credential_manager.delete(provider);
                    println!("Removed credentials for: {}", provider);
                }
            }

            if format == OutputFormat::Json {
                println!(r#"{{"status": "reset"}}"#);
            } else {
                println!("Configuration reset complete!");
            }
        }
    }

    Ok(())
}
