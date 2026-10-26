use crate::app::App;
use crate::core::{
  config::AppConfig,
  connection::ConnectionState,
  provider::{get_provider, ProviderType},
  server::Server,
};
use crate::system::{cleanup, network::NetworkStats};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::{mpsc, watch};

#[derive(Clone)]
pub struct PasswordRequest {
  pub prompt: String,
  pub reply: std::sync::mpsc::SyncSender<Option<String>>,
}

#[derive(Clone)]
pub struct Snapshot {
  pub servers: Arc<Vec<Server>>,
  pub config: AppConfig,
  pub state: ConnectionState,
  pub active: Option<Server>,
  pub public_ip: Option<String>,
  pub interface: String,
  pub uptime: String,
  pub killswitch_active: bool,
  pub busy: bool,
  pub message: Option<String>,
  pub failed: bool,
  pub password: Option<PasswordRequest>,
  pub exited: bool,
}

impl Default for Snapshot {
  fn default() -> Self {
    Self {
      servers: Arc::new(Vec::new()),
      config: AppConfig::default(),
      state: ConnectionState::Disconnected,
      active: None,
      public_ip: None,
      interface: String::new(),
      uptime: String::new(),
      killswitch_active: false,
      busy: true,
      message: Some("Loading profiles…".into()),
      failed: false,
      password: None,
      exited: false,
    }
  }
}

pub enum Command {
  Connect(String),
  Disconnect,
  Favorite(String),
  Refresh,
  Import(PathBuf),
  Killswitch,
  Ipv6,
  KeepVpn,
  Rename(String, String),
  Delete(String),
  SaveCustom(
    String,
    Box<crate::core::provider::WgConfig>,
    tokio::sync::oneshot::Sender<Result<(), String>>,
  ),
  Dismiss,
  Shutdown,
}

pub struct Engine {
  pub commands: mpsc::UnboundedSender<Command>,
  pub snapshots: watch::Receiver<Snapshot>,
  thread: Option<std::thread::JoinHandle<()>>,
  stopping: Arc<std::sync::atomic::AtomicBool>,
}

impl Engine {
  pub fn start(preview: bool) -> Self {
    let (commands, rx) = mpsc::unbounded_channel();
    let (tx, snapshots) = watch::channel(Snapshot::default());
    let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop = stopping.clone();
    let thread = std::thread::spawn(move || {
      let result = (|| -> anyhow::Result<()> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
          .worker_threads(2)
          .enable_all()
          .build()?;
        runtime.block_on(async {
          if preview {
            run_preview(rx, &tx).await;
            Ok(())
          } else {
            run(rx, &tx, stop).await
          }
        })
      })();
      if let Err(error) = result {
        tx.send_modify(|s| {
          s.busy = false;
          s.failed = true;
          s.password = None;
          s.message = Some(error.to_string());
        });
      } else {
        tx.send_modify(|s| s.exited = true);
      }
    });
    Self {
      commands,
      snapshots,
      thread: Some(thread),
      stopping,
    }
  }

  pub fn stop(&mut self) {
    self
      .stopping
      .store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = self.commands.send(Command::Shutdown);
    if let Some(thread) = self.thread.take() {
      let _ = thread.join();
    }
  }
}

impl Drop for Engine {
  fn drop(&mut self) {
    self.stop();
  }
}

fn snapshot(app: &App, servers: Arc<Vec<Server>>) -> Snapshot {
  Snapshot {
    servers,
    config: app.config.clone(),
    state: app.connection.state().clone(),
    active: app.connection.current_server().cloned(),
    public_ip: app.current_public_ip.clone(),
    interface: app.connection.interface().into(),
    uptime: app.connection.uptime_string(),
    killswitch_active: app.connection.is_killswitch_active(),
    busy: app.is_busy(),
    message: app
      .error_message
      .clone()
      .or_else(|| app.info_message.clone()),
    failed: app.error_message.is_some(),
    password: None,
    exited: false,
  }
}

async fn apply(app: &mut App, command: Command) -> anyhow::Result<()> {
  if app.is_busy() {
    anyhow::bail!("An operation is already in progress");
  }
  app.clear_messages();
  match command {
    Command::Connect(id) => {
      let server = app
        .get_servers()
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| anyhow::anyhow!("This profile is no longer available"))?;
      if !server.is_custom {
        let kind = match server.provider.as_str() {
          "protonvpn" => ProviderType::ProtonVPN,
          other => anyhow::bail!("Unsupported provider: {other}"),
        };
        app.provider_credentials = Some(app.credentials.retrieve(&server.provider)?);
        app.active_provider = Some(get_provider(kind));
      }
      app.start_connect(server)?;
    }
    Command::Disconnect => {
      app.start_disconnect()?;
    }
    Command::Favorite(id) => {
      configure(app, |config| config.toggle_favorite(&id))?;
    }
    Command::Refresh => {
      app.start_refresh()?;
    }
    Command::Import(path) => {
      app.import_config(&path).await?;
      if let Some(provider) = app.active_provider.as_ref().map(|p| p.name().to_owned()) {
        if provider != "custom" {
          app.add_configured_provider(&provider)?;
        }
      }
    }
    Command::Killswitch | Command::Ipv6 => {
      // These settings are consumed when a tunnel starts, not applied live.
      anyhow::ensure!(
        !app.connection.is_connected(),
        "Disconnect before changing protection settings"
      );
      configure(app, |config| {
        if matches!(command, Command::Killswitch) {
          config.killswitch_enabled = !config.killswitch_enabled;
        } else {
          config.ipv6_disabled = !config.ipv6_disabled;
        }
      })?;
    }
    Command::KeepVpn => {
      configure(app, |config| {
        config.keep_vpn_on_exit = !config.keep_vpn_on_exit
      })?;
    }
    Command::Rename(id, name) => {
      select_custom(app, &id)?;
      app.cancel_rename();
      app.request_rename_custom();
      if app.rename_target.is_some() {
        app.rename_buffer = name;
        app.confirm_rename_custom();
      }
    }
    Command::Delete(id) => {
      select_custom(app, &id)?;
      app.cancel_delete();
      app.request_delete_custom();
      app.confirm_delete_custom();
    }
    Command::SaveCustom(id, config, reply) => {
      let result = super::editor::save(app, &id, *config);
      let _ = reply.send(result.as_ref().map(|_| ()).map_err(ToString::to_string));
      result?;
    }
    Command::Dismiss | Command::Shutdown => {}
  }
  Ok(())
}

fn select_custom(app: &mut App, id: &str) -> anyhow::Result<()> {
  anyhow::ensure!(
    app.get_servers().iter().any(|s| s.id == id && s.is_custom),
    "This personal profile is no longer available"
  );
  app.select_server_by_id(id);
  Ok(())
}

fn configure(app: &mut App, change: impl FnOnce(&mut AppConfig)) -> anyhow::Result<()> {
  let previous = app.config.clone();
  change(&mut app.config);
  if let Err(error) = app.config.save() {
    app.config = previous;
    return Err(error.into());
  }
  Ok(())
}

async fn run(
  mut rx: mpsc::UnboundedReceiver<Command>,
  tx: &watch::Sender<Snapshot>,
  stopping: Arc<std::sync::atomic::AtomicBool>,
) -> anyhow::Result<()> {
  cleanup::create_pid_file()?;
  let result = run_owned(&mut rx, tx, stopping).await;
  cleanup::remove_pid_file()?;
  result
}

async fn run_owned(
  rx: &mut mpsc::UnboundedReceiver<Command>,
  tx: &watch::Sender<Snapshot>,
  stopping: Arc<std::sync::atomic::AtomicBool>,
) -> anyhow::Result<()> {
  let mut app = App::new().await?;
  let password_updates = tx.clone();
  app.credentials.set_password_prompt(move |prompt| {
    let (reply, answer) = std::sync::mpsc::sync_channel(1);
    password_updates.send_modify(|s| {
      s.password = Some(PasswordRequest {
        prompt: prompt.into(),
        reply: reply.clone(),
      });
      s.busy = true;
    });
    let started = std::time::Instant::now();
    loop {
      if stopping.load(std::sync::atomic::Ordering::Relaxed)
        || started.elapsed() > Duration::from_secs(120)
      {
        return Err(crate::core::error::VpnError::KeyringError(
          "Password request cancelled".into(),
        ));
      }
      match answer.recv_timeout(Duration::from_millis(100)) {
        Ok(Some(password)) if !password.is_empty() => return Ok(password),
        Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
          return Err(crate::core::error::VpnError::KeyringError(
            "Password request cancelled".into(),
          ));
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
      }
    }
  });
  app.initialize().await?;
  let mut servers = Arc::new(app.get_servers());
  tx.send_replace(snapshot(&app, servers.clone()));
  let mut tick = tokio::time::interval(Duration::from_millis(200));
  let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
  let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
  let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
  let (ip_tx, mut ip_rx) = mpsc::channel(4);
  let mut generation = 0_u64;
  let mut ip_task: Option<tokio::task::JoinHandle<()>> = None;
  let mut last_ip = std::time::Instant::now() - Duration::from_secs(30);
  let mut last_render = std::time::Instant::now();
  let mut shutting_down = false;
  loop {
    let mut publish = false;
    tokio::select! {
      command = rx.recv(), if !shutting_down => {
        publish = true;
        match command {
          None | Some(Command::Shutdown) => shutting_down = true,
          Some(command) => {
            if matches!(command, Command::Connect(_) | Command::Disconnect) {
              generation += 1;
              if let Some(task) = ip_task.take() { task.abort(); }
            }
            let importing = matches!(command, Command::Import(_));
            if importing { tx.send_modify(|s| { s.busy = true; s.message = Some("Importing configuration…".into()); }); }
            if let Err(error) = apply(&mut app, command).await { app.error_message = Some(error.to_string()); }
            servers = Arc::new(app.get_servers());
          }
        }
      }
      _ = terminate.recv(), if !shutting_down => shutting_down = true,
      _ = interrupt.recv(), if !shutting_down => shutting_down = true,
      _ = hangup.recv(), if !shutting_down => shutting_down = true,
      Some((epoch, ip)) = ip_rx.recv() => {
        if epoch == generation && app.connection.is_connected() {
          publish = true;
          app.current_public_ip = ip;
          app.connection.set_current_public_ip(app.current_public_ip.clone());
          let _ = app.connection.persist_state();
        }
      }
      _ = tick.tick() => {
        let was_busy = app.is_busy();
        app.check_pending_operation().await;
        let refreshing = app.is_refreshing;
        app.check_pending_refresh();
        if refreshing && !app.is_refreshing { servers = Arc::new(app.get_servers()); }
        publish = was_busy != app.is_busy() || (refreshing && !app.is_refreshing)
          || (app.connection.is_connected() && last_render.elapsed() >= Duration::from_secs(1));
        if app.connection.is_connected() && !app.is_busy()
          && (app.needs_ip_refresh || last_ip.elapsed() >= Duration::from_secs(30))
          && ip_task.as_ref().is_none_or(|task| task.is_finished()) {
          app.needs_ip_refresh = false;
          last_ip = std::time::Instant::now();
          let sender = ip_tx.clone();
          let epoch = generation;
          ip_task = Some(tokio::spawn(async move {
            let ip = NetworkStats::new().get_public_ip().await.ok();
            let _ = sender.send((epoch, ip)).await;
          }));
        }
      }
    }
    if publish {
      tx.send_replace(snapshot(&app, servers.clone()));
      last_render = std::time::Instant::now();
    }
    // Let an in-flight tunnel transition settle before applying the exit policy.
    if shutting_down && !app.is_busy() {
      break;
    }
  }
  if let Some(task) = ip_task {
    task.abort();
  }
  if app.config.keep_vpn_on_exit {
    app.shutdown_preserving_vpn().await?;
  } else {
    app.shutdown().await?;
  }
  Ok(())
}

pub fn preview_snapshot() -> Snapshot {
  let mut servers: Vec<Server> = [
    ("FR#42", "France", "FR", "Paris"),
    ("FR#51", "France", "FR", "Marseille"),
    ("CH#18", "Switzerland", "CH", "Zurich"),
    ("NL#12", "Netherlands", "NL", "Amsterdam"),
    ("DE#09", "Germany", "DE", "Frankfurt"),
  ]
  .into_iter()
  .map(|(name, country, code, city)| {
    Server::from_gluetun(
      name.into(),
      country.into(),
      code.into(),
      city.into(),
      "192.0.2.1".into(),
      String::new(),
      "protonvpn".into(),
    )
  })
  .collect();
  servers.push(Server::from_custom(
    "Homelab".into(),
    "192.0.2.2".into(),
    String::new(),
    Some("10.0.0.0/8".into()),
  ));
  Snapshot {
    active: Some(servers[0].clone()),
    servers: Arc::new(servers),
    busy: false,
    state: ConnectionState::Connected,
    public_ip: Some("203.0.113.42".into()),
    interface: "wg0".into(),
    uptime: "12m".into(),
    killswitch_active: true,
    config: AppConfig {
      favorites: vec!["FR#42".into(), "CH#18".into()],
      ..Default::default()
    },
    message: None,
    ..Default::default()
  }
}

async fn run_preview(mut rx: mpsc::UnboundedReceiver<Command>, tx: &watch::Sender<Snapshot>) {
  let mut state = preview_snapshot();
  tx.send_replace(state.clone());
  while let Some(command) = rx.recv().await {
    match command {
      Command::Shutdown => break,
      Command::Favorite(id) => state.config.toggle_favorite(&id),
      Command::SaveCustom(id, config, reply) => {
        let result = super::editor::validate(&config).map_err(|e| e.to_string());
        if result.is_ok() {
          let servers = Arc::make_mut(&mut state.servers);
          if let Some(server) = servers.iter_mut().find(|server| server.id == id) {
            server.allowed_ips = config.allowed_ips.clone().unwrap_or_default();
            server.ip = config
              .endpoint
              .as_deref()
              .unwrap_or_default()
              .rsplit_once(':')
              .map(|(host, _)| host.to_string())
              .unwrap_or_default();
            server.pubkey = config.public_key.clone().unwrap_or_default();
          }
          state.message = Some("Preview: changes kept in memory only.".into());
        }
        let _ = reply.send(result);
      }
      Command::Dismiss => state.message = None,
      _ => state.message = Some("Preview only — no VPN or configuration changes.".into()),
    }
    tx.send_replace(state.clone());
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn preview_never_dispatches_network_or_import_actions() {
    let (commands, rx) = mpsc::unbounded_channel();
    let (tx, mut snapshots) = watch::channel(Snapshot::default());
    let worker = tokio::spawn(async move { run_preview(rx, &tx).await });
    snapshots.changed().await.unwrap();
    let initial = snapshots.borrow_and_update().clone();
    commands.send(Command::Disconnect).unwrap();
    snapshots.changed().await.unwrap();
    assert_eq!(
      snapshots.borrow_and_update().state,
      ConnectionState::Connected
    );
    commands
      .send(Command::Import(PathBuf::from("/nonexistent.conf")))
      .unwrap();
    snapshots.changed().await.unwrap();
    assert_eq!(
      snapshots.borrow_and_update().servers.len(),
      initial.servers.len()
    );
    commands.send(Command::Favorite("FR#42".into())).unwrap();
    snapshots.changed().await.unwrap();
    assert!(!snapshots.borrow_and_update().config.is_favorite("FR#42"));
    commands.send(Command::Shutdown).unwrap();
    worker.await.unwrap();
  }
}
