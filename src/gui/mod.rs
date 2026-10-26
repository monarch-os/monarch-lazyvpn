mod assets;
mod editor;
mod engine;
mod theme;
mod view;

use clap::Parser;
use gpui_kit::{px, size, AppContext, Bounds, TitlebarOptions, WindowBounds, WindowOptions};

#[derive(Parser)]
#[command(
  name = "monarch-lazyvpn-gui",
  about = "Compact graphical WireGuard manager"
)]
struct Args {
  /// Show sample profiles without reading credentials or changing network/configuration.
  #[arg(long)]
  preview: bool,
}

pub fn run() -> anyhow::Result<()> {
  let args = Args::parse();
  tracing_subscriber::fmt()
    .with_writer(std::io::stderr)
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .init();
  launch(args.preview, || Ok(()))
}

pub fn launch(preview: bool, initialize: impl FnOnce() -> anyhow::Result<()>) -> anyhow::Result<()> {
  let runtime = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(2)
    .enable_all()
    .build()?;
  let Some(mut instance) = runtime.block_on(crate::system::instance::open(true, preview))? else {
    return Ok(());
  };
  if !preview {
    instance.publish_pid(&crate::core::config::AppConfig::config_dir()?)?;
  }
  initialize()?;
  {
    let _runtime = runtime.enter();
    instance.serve_activation()?;
  }
  let mut engine = engine::Engine::start(preview);
  let commands = engine.commands.clone();
  let snapshots = engine.snapshots.clone();
  gpui_kit::application()
    .with_assets(assets::Assets)
    .run(move |cx| {
      gpui_omarchy::init(cx);
      theme::path()
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| theme::parse(&bytes))
        .unwrap_or_else(theme::monarch)
        .apply(cx);
      cx.on_window_closed(|cx, _| {
        if cx.windows().is_empty() {
          cx.quit();
        }
      })
      .detach();
      cx.open_window(
        WindowOptions {
          window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
            None,
            size(px(880.), px(540.)),
            cx,
          ))),
          window_min_size: Some(size(px(680.), px(420.))),
          titlebar: Some(TitlebarOptions {
            title: Some("LazyVPN".into()),
            ..Default::default()
          }),
          app_id: Some("monarch-lazyvpn".into()),
          ..Default::default()
        },
        |window, cx| cx.new(|cx| view::VpnView::new(commands, snapshots, preview, window, cx)),
      )
      .expect("open LazyVPN window");
      cx.activate(true);
    });
  engine.stop();
  Ok(())
}
