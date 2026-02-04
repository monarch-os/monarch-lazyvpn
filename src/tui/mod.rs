//! Terminal User Interface module

pub mod events;
pub mod ui;
pub mod widgets;

use crate::app::App;
use crate::core::error::Result;
use crate::system::network::NetworkStats;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;
use std::io::{self, Stdout};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error};

/// Interval between stats updates (10 seconds)
const STATS_UPDATE_INTERVAL: Duration = Duration::from_secs(10);

/// Stats update results from background task
#[derive(Debug)]
pub enum StatsUpdate {
    PublicIp(String),
    Throughput(f64, f64),
}

pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Initialize the terminal
pub fn init() -> Result<Tui> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

/// Restore the terminal to its original state
pub fn restore() -> Result<()> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
    Ok(())
}

/// Main TUI application runner
pub struct TuiApp {
    terminal: Tui,
    app: App,
    tick_rate: Duration,
    last_stats_update: Instant,
    /// Channel to receive stats updates from background task
    stats_rx: mpsc::Receiver<StatsUpdate>,
    /// Shared network stats for background task
    network_stats: Arc<NetworkStats>,
    /// Flag to signal stats task to update
    stats_request_tx: mpsc::Sender<String>,
}

impl TuiApp {
    /// Create a new TUI application
    pub async fn new() -> Result<Self> {
        let terminal = init()?;
        let app = App::new().await?;

        // Create channels for stats communication
        let (stats_tx, stats_rx) = mpsc::channel::<StatsUpdate>(16);
        let (stats_request_tx, stats_request_rx) = mpsc::channel::<String>(4);

        // Create shared network stats
        let network_stats = Arc::new(NetworkStats::new());

        // Spawn background stats worker
        Self::spawn_stats_worker(
            Arc::clone(&network_stats),
            stats_tx,
            stats_request_rx,
        );

        Ok(Self {
            terminal,
            app,
            tick_rate: Duration::from_millis(100), // Fast tick for smooth spinner
            last_stats_update: Instant::now(),
            stats_rx,
            network_stats,
            stats_request_tx,
        })
    }

    /// Spawn background task for network stats collection
    fn spawn_stats_worker(
        network_stats: Arc<NetworkStats>,
        tx: mpsc::Sender<StatsUpdate>,
        mut request_rx: mpsc::Receiver<String>,
    ) {
        tokio::spawn(async move {
            debug!("Stats worker started");
            while let Some(interface) = request_rx.recv().await {
                // Fetch public IP (can take up to 15s in worst case)
                if let Ok(ip) = network_stats.get_public_ip().await {
                    let _ = tx.send(StatsUpdate::PublicIp(ip)).await;
                }

                // Fetch throughput (fast, just reads /sys)
                if let Ok((rx, tx_rate)) = network_stats.get_throughput(&interface).await {
                    let _ = tx.send(StatsUpdate::Throughput(rx, tx_rate)).await;
                }
            }
            debug!("Stats worker stopped");
        });
    }

    /// Run the main event loop
    pub async fn run(&mut self) -> Result<()> {
        // Initialize app
        self.app.initialize().await?;

        loop {
            // Draw UI first
            self.terminal.draw(|f| ui::render(f, &mut self.app))?;

            // Poll for events with short timeout to keep spinner animating
            if event::poll(self.tick_rate)? {
                if let Event::Key(key) = event::read()? {
                    // Handle key events (non-blocking for most, spawns tasks for long ops)
                    match events::handle_key_event(&mut self.app, key).await {
                        Ok(should_continue) => {
                            if !should_continue {
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Error handling key event: {}", e);
                            self.app.error_message = Some(e.to_string());
                        }
                    }
                }
            }

            // Tick spinner animation when busy
            if self.app.is_busy() {
                self.app.tick_spinner();
            }

            // Check if should quit
            if self.app.should_quit {
                break;
            }

            // Check for pending async operation results
            self.app.check_pending_operation().await;

            // Check for pending refresh results (non-blocking)
            self.app.check_pending_refresh();

            // Process any stats updates from background task (non-blocking)
            self.process_stats_updates();

            // Request stats update periodically - only when connected and interval elapsed
            if self.app.connection.is_connected()
                && self.last_stats_update.elapsed() >= STATS_UPDATE_INTERVAL
            {
                self.request_stats_update();
                self.last_stats_update = Instant::now();
            }

            // Request immediate IP refresh after connection (flag set by finalize_connect)
            if self.app.needs_ip_refresh {
                self.app.needs_ip_refresh = false;
                // Invalidate IP cache before requesting update to get fresh IP
                self.network_stats.invalidate_ip_cache().await;
                self.request_stats_update();
                self.last_stats_update = Instant::now();
            }
        }

        // Cleanup - choose shutdown method based on config
        if self.app.config.keep_vpn_on_exit {
            self.app.shutdown_preserving_vpn().await?;
        } else {
            self.app.shutdown().await?;
        }
        Ok(())
    }

    /// Request stats update from background task (non-blocking)
    fn request_stats_update(&self) {
        let interface = self.app.connection.interface().to_string();
        // Use try_send to avoid blocking
        let _ = self.stats_request_tx.try_send(interface);
    }

    /// Process stats updates from background task (non-blocking)
    fn process_stats_updates(&mut self) {
        // Drain all available updates without blocking
        while let Ok(update) = self.stats_rx.try_recv() {
            match update {
                StatsUpdate::PublicIp(ip) => {
                    self.app.current_public_ip = Some(ip.clone());
                    // Persist IP immediately so status binary can read it
                    if self.app.connection.is_connected() {
                        self.app.connection.set_current_public_ip(Some(ip));
                        let _ = self.app.connection.persist_state();
                    }
                }
                StatsUpdate::Throughput(_rx, _tx) => {
                    // Throughput stats are available but not currently displayed
                    // Could be stored in app for UI if needed
                }
            }
        }
    }
}

impl Drop for TuiApp {
    fn drop(&mut self) {
        let _ = restore();
    }
}
