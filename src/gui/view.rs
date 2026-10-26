use super::{
  assets,
  engine::{Command, Snapshot},
  theme,
};
use crate::core::{
  connection::ConnectionState,
  provider::{custom::CustomProvider, WgConfig},
  server::Server,
};
use gpui_kit::{base::input::InputState, prelude::*, *};
use gpui_omarchy::{button, checkbox, focus_scope, input, ActiveTheme, ButtonVariant};
use std::{collections::HashSet, path::PathBuf, time::Duration};
use tokio::sync::{mpsc, watch};

fn checked(value: bool) -> gpui_kit::base::CheckboxState {
  if value {
    gpui_kit::base::CheckboxState::Checked
  } else {
    gpui_kit::base::CheckboxState::Unchecked
  }
}

#[derive(Clone, Debug, PartialEq)]
enum Row {
  Group(String, String, usize),
  Server(usize),
}

enum Dialog {
  Import(PathBuf),
  Delete(Server),
  Rename(Server),
  Edit(Server, Vec<Entity<InputState>>),
}

pub struct VpnView {
  snapshot: Snapshot,
  commands: mpsc::UnboundedSender<Command>,
  search: Entity<InputState>,
  rename: Entity<InputState>,
  password: Entity<InputState>,
  focus: FocusHandle,
  scroll: UniformListScrollHandle,
  selected: Option<String>,
  selected_group: Option<String>,
  rows: Vec<Row>,
  collapsed: HashSet<String>,
  favorites: bool,
  saving: bool,
  help: bool,
  preview: bool,
  preview_configs: std::collections::HashMap<String, WgConfig>,
  dialog: Option<Dialog>,
  local_error: Option<String>,
  _subscriptions: Vec<Subscription>,
}

fn filtered_rows(
  snapshot: &Snapshot,
  query: &str,
  favorites: bool,
  collapsed: &HashSet<String>,
) -> Vec<Row> {
  let query = query.to_lowercase();
  let mut groups: indexmap::IndexMap<String, (String, Vec<usize>)> = indexmap::IndexMap::new();
  for (index, server) in snapshot.servers.iter().enumerate() {
    if favorites && !snapshot.config.is_favorite(&server.id) {
      continue;
    }
    if ![
      &server.name,
      &server.country,
      &server.country_code,
      &server.city,
      &server.provider,
    ]
    .iter()
    .any(|field| field.to_lowercase().contains(&query))
    {
      continue;
    }
    groups
      .entry(server.provider.clone())
      .or_insert_with(|| (server.provider_display_name().into(), Vec::new()))
      .1
      .push(index);
  }
  let mut rows = Vec::new();
  for (provider, (label, indices)) in groups {
    rows.push(Row::Group(provider.clone(), label, indices.len()));
    if !collapsed.contains(&provider) {
      rows.extend(indices.into_iter().map(Row::Server));
    }
  }
  rows
}

impl VpnView {
  pub fn new(
    commands: mpsc::UnboundedSender<Command>,
    mut snapshots: watch::Receiver<Snapshot>,
    preview: bool,
    window: &mut Window,
    cx: &mut Context<Self>,
  ) -> Self {
    let search =
      cx.new(|cx| InputState::new(window, cx).placeholder("Search country, city or profile…"));
    let rename = cx.new(|cx| InputState::new(window, cx).placeholder("Profile name"));
    let password = cx.new(|cx| {
      InputState::new(window, cx)
        .placeholder("Credential password")
        .masked(true)
    });
    let subscription = cx.observe(&search, |this, _, cx| {
      this.filter(cx);
      cx.notify();
    });
    let snapshot = snapshots.borrow_and_update().clone();
    let selected = snapshot.active.as_ref().map(|s| s.id.clone());
    let focus = cx.focus_handle();
    window.focus(&focus, cx);
    cx.spawn(async move |this, cx| {
      let mut previous_theme = Vec::new();
      let mut theme_tick = 0;
      let mut stream_closed = false;
      loop {
        cx.background_executor()
          .timer(Duration::from_millis(150))
          .await;
        let changed = match snapshots.has_changed() {
          Ok(changed) => changed,
          Err(_) if !stream_closed => {
            stream_closed = true;
            true
          }
          Err(_) => false,
        };
        let update = changed.then(|| snapshots.borrow_and_update().clone());
        theme_tick += 1;
        let palette = if theme_tick % 7 == 0 {
          theme::path()
            .and_then(|path| std::fs::read(path).ok())
            .and_then(|bytes| {
              if bytes == previous_theme {
                return None;
              }
              let theme = theme::parse(&bytes);
              previous_theme = bytes;
              theme
            })
        } else {
          None
        };
        if this
          .update(cx, |this, cx| {
            if let Some(palette) = palette {
              palette.apply(cx);
            }
            if let Some(snapshot) = update {
              if snapshot.exited {
                cx.quit();
              }
              let refilter = !std::sync::Arc::ptr_eq(&snapshot.servers, &this.snapshot.servers)
                || snapshot.config.favorites != this.snapshot.config.favorites;
              if this.snapshot.servers.is_empty() && this.selected.is_none() {
                this.selected = snapshot.active.as_ref().map(|server| server.id.clone());
              }
              this.snapshot = snapshot;
              if refilter {
                this.filter(cx);
              }
              cx.notify();
            }
          })
          .is_err()
        {
          break;
        }
      }
    })
    .detach();
    let mut view = Self {
      snapshot,
      commands,
      search,
      rename,
      password,
      focus,
      selected,
      selected_group: None,
      scroll: UniformListScrollHandle::new(),
      rows: Vec::new(),
      collapsed: HashSet::new(),
      favorites: false,
      saving: false,
      help: false,
      preview,
      preview_configs: Default::default(),
      dialog: None,
      local_error: None,
      _subscriptions: vec![subscription],
    };
    view.filter(cx);
    view
  }

  fn filter(&mut self, cx: &App) {
    self.rows = filtered_rows(
      &self.snapshot,
      self.search.read(cx).value().as_ref(),
      self.favorites,
      &self.collapsed,
    );
    if self.selected_group.as_ref().is_some_and(|provider| {
      self
        .rows
        .iter()
        .any(|row| matches!(row, Row::Group(id, _, _) if id == provider))
    }) {
      self.selected = None;
      return;
    }
    self.selected_group = None;
    let visible: Vec<&Server> = self
      .rows
      .iter()
      .filter_map(|row| match row {
        Row::Server(index) => self.snapshot.servers.get(*index),
        _ => None,
      })
      .collect();
    if !visible
      .iter()
      .any(|server| Some(&server.id) == self.selected.as_ref())
    {
      self.selected = visible.first().map(|server| server.id.clone());
    }
    if self.selected.is_none() {
      if let Some(Row::Group(provider, _, _)) = self.rows.first() {
        self.selected_group = Some(provider.clone());
      }
    }
  }

  fn server(&self) -> Option<&Server> {
    self
      .snapshot
      .servers
      .iter()
      .find(|server| Some(&server.id) == self.selected.as_ref())
  }

  fn send(&mut self, command: Command, cx: &mut Context<Self>) {
    if self.snapshot.busy {
      return;
    }
    self.local_error = self
      .commands
      .send(command)
      .err()
      .map(|_| "VPN worker is unavailable. Close and reopen LazyVPN.".into());
    cx.notify();
  }

  fn activate(&mut self, cx: &mut Context<Self>) {
    if let Some(provider) = self.selected_group.clone() {
      self.set_group_collapsed(!self.collapsed.contains(&provider), false, cx);
      return;
    }
    let Some(id) = self.selected.clone() else {
      return;
    };
    if self.snapshot.active.as_ref().is_some_and(|s| s.id == id)
      && matches!(self.snapshot.state, ConnectionState::Connected)
    {
      self.send(Command::Disconnect, cx);
    } else {
      self.send(Command::Connect(id), cx);
    }
  }

  fn favorite(&mut self, cx: &mut Context<Self>) {
    if let Some(id) = self.selected.clone() {
      self.send(Command::Favorite(id), cx);
    }
  }

  fn navigate(&mut self, direction: isize, cx: &mut Context<Self>) {
    if self.rows.is_empty() {
      return;
    }
    let current = self
      .rows
      .iter()
      .position(|row| match row {
        Row::Group(provider, _, _) => self.selected_group.as_ref() == Some(provider),
        Row::Server(index) => self.selected.as_ref() == Some(&self.snapshot.servers[*index].id),
      })
      .unwrap_or(0);
    let index = (current as isize + direction).clamp(0, self.rows.len() as isize - 1) as usize;
    match &self.rows[index] {
      Row::Group(provider, _, _) => {
        self.selected_group = Some(provider.clone());
        self.selected = None;
      }
      Row::Server(server) => {
        self.selected = Some(self.snapshot.servers[*server].id.clone());
        self.selected_group = None;
      }
    }
    self.scroll.scroll_to_item(index, ScrollStrategy::Nearest);
    cx.notify();
  }

  fn set_group_collapsed(&mut self, collapse: bool, enter_child: bool, cx: &mut Context<Self>) {
    if !collapse && enter_child && self.selected_group.is_none() {
      return;
    }
    let Some(provider) = self
      .selected_group
      .clone()
      .or_else(|| self.server().map(|server| server.provider.clone()))
    else {
      return;
    };
    let was_collapsed = self.collapsed.contains(&provider);
    if collapse {
      self.collapsed.insert(provider.clone());
    } else {
      self.collapsed.remove(&provider);
    }
    self.selected = None;
    self.selected_group = Some(provider.clone());
    self.filter(cx);
    if let Some(index) = self
      .rows
      .iter()
      .position(|row| matches!(row, Row::Group(id, _, _) if *id == provider))
    {
      self.scroll.scroll_to_item(index, ScrollStrategy::Nearest);
      if !collapse && !was_collapsed && enter_child {
        if let Some(Row::Server(server)) = self.rows.get(index + 1) {
          self.selected = Some(self.snapshot.servers[*server].id.clone());
          self.selected_group = None;
          self
            .scroll
            .scroll_to_item(index + 1, ScrollStrategy::Nearest);
        }
      }
    }
    cx.notify();
  }

  fn import(&mut self, cx: &mut Context<Self>) {
    if self.snapshot.busy {
      return;
    }
    let paths = cx.prompt_for_paths(PathPromptOptions {
      files: true,
      directories: false,
      multiple: false,
      prompt: Some("Import WireGuard .conf".into()),
    });
    cx.spawn(async move |this, cx| {
      let result = paths.await;
      let _ = this.update(cx, |this, cx| {
        match result {
          Ok(Ok(Some(paths))) => {
            if let Some(path) = paths.into_iter().next() {
              if path.extension().is_some_and(|ext| ext == "conf") {
                this.dialog = Some(Dialog::Import(path));
              } else {
                this.local_error = Some("Choose a WireGuard file ending in .conf.".into());
              }
            }
          }
          Ok(Ok(None)) => {}
          _ => {
            this.local_error =
              Some("Could not open the file picker. Check your desktop portal.".into())
          }
        }
        cx.notify();
      });
    })
    .detach();
  }

  fn start_rename(&mut self, window: &mut Window, cx: &mut Context<Self>) {
    if let Some(server) = self.server().filter(|s| s.is_custom).cloned() {
      self.rename.update(cx, |state, cx| {
        state.set_value(server.name.clone(), window, cx);
        state.focus(window, cx);
      });
      self.dialog = Some(Dialog::Rename(server));
      cx.notify();
    }
  }

  fn confirm(&mut self, window: &mut Window, cx: &mut Context<Self>) {
    if self.saving || self.snapshot.busy {
      return;
    }
    if let Some(Dialog::Edit(server, fields)) = &self.dialog {
      let values: Vec<Option<String>> = fields
        .iter()
        .map(|field| {
          let value = field.read(cx).value().trim().to_owned();
          (!value.is_empty()).then_some(value)
        })
        .collect();
      let keepalive = match values[5].as_deref().map(str::parse::<u16>).transpose() {
        Ok(value) => value,
        Err(_) => {
          self.local_error = Some("Keepalive must be between 0 and 65535 seconds".into());
          cx.notify();
          return;
        }
      };
      let config = WgConfig {
        address: values[0].clone(),
        dns: values[1].clone(),
        endpoint: values[2].clone(),
        allowed_ips: values[3].clone(),
        public_key: values[4].clone(),
        persistent_keepalive: keepalive.map(u32::from),
        private_key: values[6].clone(),
        ..Default::default()
      };
      if let Err(error) = super::editor::validate(&config) {
        self.local_error = Some(error.to_string());
        cx.notify();
        return;
      }
      let (reply, answer) = tokio::sync::oneshot::channel();
      let preview_config = self.preview.then(|| (server.id.clone(), config.clone()));
      if self
        .commands
        .send(Command::SaveCustom(
          server.id.clone(),
          Box::new(config),
          reply,
        ))
        .is_err()
      {
        self.local_error = Some("VPN worker is unavailable".into());
        cx.notify();
        return;
      }
      self.saving = true;
      self.local_error = None;
      cx.spawn(async move |this, cx| {
        let result = answer
          .await
          .unwrap_or_else(|_| Err("Could not save: VPN worker is unavailable or busy".into()));
        let _ = this.update(cx, |this, cx| {
          this.saving = false;
          match result {
            Ok(()) => {
              if let Some((id, mut config)) = preview_config {
                config.private_key = None;
                this.preview_configs.insert(id, config);
              }
              this.dialog = None;
            }
            Err(error) => this.local_error = Some(error),
          }
          cx.notify();
        });
      })
      .detach();
      cx.notify();
      return;
    }
    let command = match self.dialog.take() {
      Some(Dialog::Import(path)) => Command::Import(path),
      Some(Dialog::Delete(server)) => Command::Delete(server.id),
      Some(Dialog::Rename(server)) => {
        Command::Rename(server.id, self.rename.read(cx).value().to_string())
      }
      Some(Dialog::Edit(_, _)) | None => return,
    };
    window.focus(&self.focus, cx);
    self.send(command, cx);
  }

  fn start_edit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
    let Some(server) = self.server().filter(|s| s.is_custom).cloned() else {
      return;
    };
    let config = if let Some(config) = self.preview_configs.get(&server.id) {
      config.clone()
    } else if self.preview {
      WgConfig {
        address: Some("10.0.0.2/32".into()),
        dns: Some("1.1.1.1".into()),
        endpoint: Some(format!("{}:51820", server.ip)),
        allowed_ips: Some(server.allowed_ips.clone()),
        public_key: Some(if server.pubkey.is_empty() {
          "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=".into()
        } else {
          server.pubkey.clone()
        }),
        persistent_keepalive: Some(25),
        ..Default::default()
      }
    } else {
      match CustomProvider::load_sanitized_config(&server.name) {
        Ok(config) => config,
        Err(error) => {
          self.local_error = Some(error.to_string());
          cx.notify();
          return;
        }
      }
    };
    let fields = [
      config.address,
      config.dns,
      config.endpoint,
      config.allowed_ips,
      config.public_key,
      config.persistent_keepalive.map(|value| value.to_string()),
      None,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, value)| {
      cx.new(|cx| {
        let mut state = InputState::new(window, cx).masked(index == 6);
        state.set_value(value.unwrap_or_default(), window, cx);
        state
      })
    })
    .collect();
    self.dialog = Some(Dialog::Edit(server, fields));
    self.local_error = None;
    cx.notify();
  }

  fn key(&mut self, event: &KeyDownEvent, window: &mut Window, cx: &mut Context<Self>) {
    let key = event.keystroke.key.as_str();
    if self.snapshot.password.is_some() {
      if key == "escape" {
        self.answer_password(false, window, cx);
      }
      return;
    }
    if key == "escape" {
      if self.saving {
        return;
      }
      self.dialog = None;
      self.help = false;
      window.focus(&self.focus, cx);
      cx.notify();
      return;
    }
    if self.dialog.is_some() {
      return;
    }
    if self.search.read(cx).focus_handle(cx).is_focused(window) {
      return;
    }
    if event.keystroke.modifiers.control || event.keystroke.modifiers.platform {
      return;
    }
    match key {
      "j" | "down" => self.navigate(1, cx),
      "k" | "up" => self.navigate(-1, cx),
      "h" | "left" => self.set_group_collapsed(true, false, cx),
      "l" | "right" => self.set_group_collapsed(false, true, cx),
      "enter" if self.focus.is_focused(window) => self.activate(cx),
      "f" => self.favorite(cx),
      "/" => self.search.update(cx, |state, cx| state.focus(window, cx)),
      "r" => self.send(Command::Refresh, cx),
      "d" => self.send(Command::Disconnect, cx),
      "i" => self.import(cx),
      "?" => {
        self.help = !self.help;
        cx.notify();
      }
      "q" => cx.quit(),
      _ => {}
    }
  }

  fn answer_password(&mut self, accept: bool, window: &mut Window, cx: &mut Context<Self>) {
    if let Some(request) = self.snapshot.password.take() {
      let answer = accept.then(|| self.password.read(cx).value().to_string());
      let _ = request.reply.try_send(answer);
      self
        .password
        .update(cx, |state, cx| state.set_value("", window, cx));
      window.focus(&self.focus, cx);
      cx.notify();
    }
  }

  fn render_row(&mut self, index: usize, cx: &mut Context<Self>) -> AnyElement {
    let t = cx.omarchy().clone();
    match self.rows[index].clone() {
      Row::Group(provider, label, count) => {
        let collapsed = self.collapsed.contains(&provider);
        let selected = self.selected_group.as_ref() == Some(&provider);
        div()
          .id(("group", index))
          .w_full()
          .h(px(28.))
          .px_3()
          .flex()
          .items_center()
          .gap_2()
          .text_size(px(12.))
          .text_color(t.accent)
          .bg(if selected { t.selection } else { t.background })
          .border_l_2()
          .border_color(if selected { t.accent } else { t.background })
          .cursor_pointer()
          .on_click(cx.listener(move |this, _, window, cx| {
            this.selected_group = Some(provider.clone());
            this.selected = None;
            this.set_group_collapsed(!collapsed, false, cx);
            window.focus(&this.focus, cx);
          }))
          .child(if collapsed { "▸" } else { "▾" })
          .child(label)
          .child(div().text_color(t.secondary).child(count.to_string()))
          .into_any_element()
      }
      Row::Server(server_index) => {
        let server = self.snapshot.servers[server_index].clone();
        let selected = self.selected.as_ref() == Some(&server.id);
        let active = self
          .snapshot
          .active
          .as_ref()
          .is_some_and(|s| s.id == server.id)
          && matches!(self.snapshot.state, ConnectionState::Connected);
        let favorite = self.snapshot.config.is_favorite(&server.id);
        let label = if server.is_custom {
          server.name.clone()
        } else if server.city.is_empty() {
          server.country.clone()
        } else {
          format!("{} · {}", server.country, server.city)
        };
        let flag = assets::flag(&server.country_code).filter(|_| !server.is_custom);
        let mut row = div()
          .id(("server", index))
          .w_full()
          .h(px(28.))
          .px_3()
          .flex()
          .items_center()
          .gap_2()
          .border_l_2()
          .border_color(if selected { t.accent } else { t.background })
          .bg(if selected { t.selection } else { t.background })
          .cursor_pointer()
          .hover(|s| s.bg(t.hover_fill()))
          .on_click(cx.listener(move |this, _, window, cx| {
            this.selected = Some(server.id.clone());
            this.selected_group = None;
            window.focus(&this.focus, cx);
            cx.notify();
          }));
        row = row.child(if let Some(path) = flag {
          img(path)
            .w(px(16.))
            .h(px(12.))
            .flex_shrink_0()
            .into_any_element()
        } else {
          div()
            .w(px(16.))
            .text_color(t.accent)
            .child("◇")
            .into_any_element()
        });
        row
          .child(div().flex_1().min_w_0().truncate().child(label))
          .child(
            div()
              .text_size(px(11.))
              .text_color(t.secondary)
              .child(self.snapshot.servers[server_index].name.clone()),
          )
          .child(
            div()
              .w(px(10.))
              .text_color(t.success)
              .child(if active { "●" } else { "" }),
          )
          .child(
            div()
              .w(px(10.))
              .text_color(t.accent)
              .child(if favorite { "★" } else { "" }),
          )
          .into_any_element()
      }
    }
  }

  fn fact(&self, label: &str, value: impl Into<SharedString>, cx: &App) -> Div {
    div()
      .flex()
      .justify_between()
      .gap_3()
      .text_size(px(12.))
      .child(
        div()
          .text_color(cx.omarchy().secondary)
          .child(label.to_owned()),
      )
      .child(
        div()
          .min_w_0()
          .truncate()
          .text_color(cx.omarchy().bright)
          .child(value.into()),
      )
  }

  fn detail_panel(&mut self, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
    let t = cx.omarchy().clone();
    if let Some(request) = &self.snapshot.password {
      return div()
        .flex_1()
        .min_w_0()
        .p_3()
        .flex()
        .flex_col()
        .gap_3()
        .child(div().text_color(t.accent).child("Encrypted credentials"))
        .child(request.prompt.clone())
        .child(input("credential-password", &self.password, window, cx))
        .child(
          div()
            .flex()
            .gap_2()
            .child(
              button("unlock", "Continue", ButtonVariant::Outline, cx).on_click(
                cx.listener(|this, _, window, cx| this.answer_password(true, window, cx)),
              ),
            )
            .child(
              button("cancel-password", "Cancel", ButtonVariant::Secondary, cx).on_click(
                cx.listener(|this, _, window, cx| this.answer_password(false, window, cx)),
              ),
            ),
        )
        .into_any_element();
    }
    let connected = matches!(self.snapshot.state, ConnectionState::Connected);
    let busy = self.snapshot.busy;
    let state = match &self.snapshot.state {
      ConnectionState::Connected => "● Connected",
      ConnectionState::Connecting => "◌ Connecting…",
      ConnectionState::Disconnecting => "◌ Disconnecting…",
      ConnectionState::Disconnected => "○ Disconnected",
      ConnectionState::Error(_) => "! Connection error",
    };
    let active = self
      .snapshot
      .active
      .as_ref()
      .map(|s| format!("{} / {}", s.provider_display_name(), s.name))
      .unwrap_or_else(|| "No active tunnel".into());
    let mut panel = div()
      .w_full()
      .flex_shrink_0()
      .min_w_0()
      .p_3()
      .flex()
      .flex_col()
      .gap_1()
      .child(
        div()
          .text_size(px(12.))
          .text_color(if connected { t.success } else { t.warning })
          .child(state),
      )
      .child(
        div()
          .text_size(px(11.))
          .text_color(t.secondary)
          .truncate()
          .child(active),
      )
      .child(self.fact(
        "Public IP",
        if connected {
          self.snapshot.public_ip.as_deref().unwrap_or("Not verified")
        } else {
          "—"
        },
        cx,
      ))
      .child(self.fact(
        "Interface",
        if connected {
          self.snapshot.interface.as_str()
        } else {
          "—"
        },
        cx,
      ));
    if connected {
      panel = panel
        .child(self.fact("Uptime", self.snapshot.uptime.clone(), cx))
        .child(self.fact(
          "Kill switch",
          if self.snapshot.killswitch_active {
            "Active"
          } else {
            "Inactive"
          },
          cx,
        ));
    }
    let server = self.server().cloned();
    if let Some(server) = server.as_ref() {
      let same = self
        .snapshot
        .active
        .as_ref()
        .is_some_and(|active| active.id == server.id);
      let action = if connected && same {
        "Disconnect"
      } else if connected {
        "Switch server"
      } else {
        "Connect"
      };
      panel = panel.child(
        div()
          .mt_2()
          .border_t_1()
          .border_color(t.border)
          .pt_2()
          .flex()
          .flex_col()
          .gap_1()
          .child(
            div()
              .text_size(px(11.))
              .text_color(t.accent)
              .child("Selected profile"),
          )
          .child(div().text_color(t.bright).child(if server.is_custom {
            server.name.clone()
          } else {
            format!("{} · {}", server.country, server.city)
          }))
          .child(
            div()
              .text_size(px(11.))
              .text_color(t.secondary)
              .child(format!(
                "{} / {}",
                server.provider_display_name(),
                server.name
              )),
          )
          .child(
            div()
              .flex()
              .gap_2()
              .child(
                button("connect", action, ButtonVariant::Primary, cx)
                  .bg(t.accent)
                  .text_color(t.on_accent)
                  .disabled(busy)
                  .on_click(cx.listener(|this, _, _, cx| this.activate(cx))),
              )
              .child(
                button(
                  "favorite",
                  if self.snapshot.config.is_favorite(&server.id) {
                    "★"
                  } else {
                    "☆"
                  },
                  ButtonVariant::Secondary,
                  cx,
                )
                .disabled(busy)
                .accessibility_label("Toggle favorite")
                .on_click(cx.listener(|this, _, _, cx| this.favorite(cx))),
              ),
          ),
      );
      if server.is_custom {
        let disabled = busy || self.saving || (connected && same);
        let target = server.clone();
        panel = panel.child(
          div()
            .flex()
            .gap_2()
            .mt_1()
            .child(
              button("edit", "Edit", ButtonVariant::Primary, cx)
                .bg(t.accent.opacity(0.12))
                .disabled(disabled)
                .on_click(cx.listener(|this, _, window, cx| this.start_edit(window, cx))),
            )
            .child(
              button("rename", "Rename", ButtonVariant::Primary, cx)
                .bg(t.accent.opacity(0.12))
                .disabled(disabled)
                .on_click(cx.listener(|this, _, window, cx| this.start_rename(window, cx))),
            )
            .child(
              button("delete", "Delete", ButtonVariant::Danger, cx)
                .bg(t.danger.opacity(0.12))
                .disabled(disabled)
                .on_click(cx.listener(move |this, _, _, cx| {
                  this.dialog = Some(Dialog::Delete(target.clone()));
                  cx.notify();
                })),
            ),
        );
        if connected && same {
          panel = panel.child(
            div()
              .text_size(px(10.))
              .text_color(t.secondary)
              .child("Disconnect this profile to edit or delete it."),
          );
        }
      }
      panel = panel
        .child(self.fact("Endpoint", server.ip.clone(), cx))
        .child(self.fact("Routes", server.allowed_ips.clone(), cx));
      if server.is_split_tunnel() {
        panel = panel.child(
          div()
            .text_size(px(11.))
            .text_color(t.warning)
            .child("Split tunnel: kill switch is not applied."),
        );
      }
    } else if connected {
      panel = panel.child(
        button("disconnect", "Disconnect", ButtonVariant::Outline, cx)
          .disabled(busy)
          .on_click(cx.listener(|this, _, _, cx| this.send(Command::Disconnect, cx))),
      );
    }
    panel = panel.child(
      div()
        .mt_2()
        .border_t_1()
        .border_color(t.border)
        .pt_2()
        .flex()
        .flex_col()
        .gap_1()
        .child(
          div()
            .text_size(px(11.))
            .text_color(t.accent)
            .child("Protection preferences"),
        )
        .child(
          checkbox(
            "killswitch",
            "Kill switch",
            checked(self.snapshot.config.killswitch_enabled),
            cx,
          )
          .disabled(busy || connected)
          .on_change({
            let view = cx.entity();
            move |_, _, _, cx| view.update(cx, |this, cx| this.send(Command::Killswitch, cx))
          }),
        )
        .child(
          checkbox(
            "ipv6",
            "Block IPv6",
            checked(self.snapshot.config.ipv6_disabled),
            cx,
          )
          .disabled(busy || connected)
          .on_change({
            let view = cx.entity();
            move |_, _, _, cx| view.update(cx, |this, cx| this.send(Command::Ipv6, cx))
          }),
        )
        .child(
          div()
            .text_size(px(10.))
            .text_color(t.secondary)
            .child(if connected {
              "Disconnect to change protection."
            } else {
              "Applied on the next connection."
            }),
        )
        .child(
          checkbox(
            "keep-vpn",
            "Keep VPN on exit",
            checked(self.snapshot.config.keep_vpn_on_exit),
            cx,
          )
          .disabled(busy)
          .on_change({
            let view = cx.entity();
            move |_, _, _, cx| view.update(cx, |this, cx| this.send(Command::KeepVpn, cx))
          }),
        ),
    );
    if self.dialog.is_some() {
      let (title, description) = match self.dialog.as_ref().unwrap() {
        Dialog::Import(path) => (
          "Import configuration",
          format!(
            "{} — provider detected automatically.",
            path.file_name().unwrap_or_default().to_string_lossy()
          ),
        ),
        Dialog::Delete(server) => (
          "Delete profile?",
          format!("Remove {} and its saved credentials.", server.name),
        ),
        Dialog::Rename(_) => ("Rename profile", "Choose a new profile name.".into()),
        Dialog::Edit(server, _) => ("Edit configuration", server.name.clone()),
      };
      if matches!(self.dialog, Some(Dialog::Edit(_, _))) {
        panel = div().w_full().p_3();
      }
      let mut dialog = div()
        .mt_2()
        .p_3()
        .bg(t.surface)
        .border_1()
        .border_color(t.accent)
        .flex()
        .flex_col()
        .gap_2()
        .child(div().text_color(t.bright).child(title))
        .child(div().text_size(px(11.)).child(description));
      if matches!(self.dialog, Some(Dialog::Rename(_))) {
        dialog = dialog.child(input("rename-input", &self.rename, window, cx));
      }
      if let Some(Dialog::Edit(_, fields)) = &self.dialog {
        for (index, label) in [
          "Address",
          "DNS",
          "Endpoint",
          "Allowed IPs",
          "Peer public key",
          "Keepalive (seconds)",
          "New private key (blank = keep current)",
        ]
        .iter()
        .enumerate()
        {
          dialog = dialog
            .child(div().text_size(px(11.)).child(*label))
            .child(input(("edit-field", index), &fields[index], window, cx));
        }
      }
      panel = panel.child(
        dialog.child(
          div()
            .flex()
            .gap_2()
            .child(
              button(
                "confirm",
                if self.saving { "Saving…" } else { "Confirm" },
                if matches!(self.dialog, Some(Dialog::Delete(_))) {
                  ButtonVariant::Danger
                } else {
                  ButtonVariant::Primary
                },
                cx,
              )
              .disabled(busy || self.saving)
              .on_click(cx.listener(|this, _, window, cx| this.confirm(window, cx))),
            )
            .child(
              button("cancel", "Cancel", ButtonVariant::Secondary, cx)
                .disabled(self.saving)
                .on_click(cx.listener(|this, _, window, cx| {
                  this.dialog = None;
                  window.focus(&this.focus, cx);
                  cx.notify();
                })),
            ),
        ),
      );
    }
    div()
      .id("details-scroll")
      .flex_1()
      .min_w_0()
      .h_full()
      .overflow_y_scroll()
      .child(panel)
      .into_any_element()
  }
}

impl Render for VpnView {
  fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
    let t = cx.omarchy().clone();
    let list = uniform_list(
      "servers",
      self.rows.len(),
      cx.processor(|this, range: std::ops::Range<usize>, _, cx| {
        range
          .map(|index| this.render_row(index, cx))
          .collect::<Vec<_>>()
      }),
    )
    .track_scroll(&self.scroll)
    .flex_1()
    .min_h_0();
    let mut left = div()
      .w(relative(0.60))
      .min_w_0()
      .h_full()
      .border_r_1()
      .border_color(t.border)
      .flex()
      .flex_col()
      .child(
        div()
          .p_3()
          .flex()
          .gap_2()
          .child(
            div()
              .flex_1()
              .min_w_0()
              .child(input("search", &self.search, window, cx).py_1()),
          )
          .child(
            button(
              "filter-favorites",
              if self.favorites { "★" } else { "☆" },
              ButtonVariant::Secondary,
              cx,
            )
            .accessibility_label("Filter favorites")
            .on_click(cx.listener(|this, _, _, cx| {
              this.favorites = !this.favorites;
              this.filter(cx);
              cx.notify();
            })),
          ),
      )
      .child(
        div()
          .px_3()
          .pb_1()
          .flex()
          .justify_between()
          .text_size(px(11.))
          .text_color(t.secondary)
          .child("Server")
          .child("Profile"),
      );
    if self.rows.is_empty() {
      left = left.child(div().p_3().flex_1().text_color(t.secondary).child(
        if self.snapshot.busy {
          "Loading profiles…"
        } else if self.snapshot.servers.is_empty() {
          "Import a WireGuard .conf file to add a provider or personal profile."
        } else {
          "No matching profiles."
        },
      ));
    } else {
      left = left.child(list);
    }
    left = left.child(
      div()
        .p_3()
        .flex()
        .gap_2()
        .child(
          button("import", "+ Import .conf", ButtonVariant::Outline, cx)
            .disabled(self.snapshot.busy)
            .on_click(cx.listener(|this, _, _, cx| this.import(cx))),
        )
        .child(
          button("refresh", "Refresh", ButtonVariant::Secondary, cx)
            .disabled(self.snapshot.busy)
            .on_click(cx.listener(|this, _, _, cx| this.send(Command::Refresh, cx))),
        ),
    );
    let details = self.detail_panel(window, cx);
    let mut root = focus_scope("lazyvpn")
      .track_focus(&self.focus)
      .size_full()
      .flex()
      .flex_col()
      .bg(t.background)
      .text_color(t.foreground)
      .font_family(t.mono_font.clone())
      .text_size(px(13.))
      .on_key_down(cx.listener(Self::key))
      .child(
        div()
          .px_3()
          .py_2()
          .bg(t.surface)
          .flex()
          .justify_between()
          .child(div().text_color(t.bright).child("lazyvpn / WireGuard"))
          .child(
            div()
              .text_size(px(11.))
              .text_color(t.accent)
              .child(if self.preview {
                "Preview · no system changes"
              } else {
                "Monarch"
              }),
          ),
      )
      .child(div().flex().flex_1().min_h_0().child(left).child(details));
    if let Some(message) = self.local_error.as_ref().or(self.snapshot.message.as_ref()) {
      root = root.child(
        div()
          .px_3()
          .py_2()
          .bg(t.surface)
          .flex()
          .items_center()
          .gap_2()
          .child(
            div()
              .flex_1()
              .text_size(px(11.))
              .text_color(if self.snapshot.failed || self.local_error.is_some() {
                t.danger
              } else {
                t.foreground
              })
              .child(message.clone()),
          )
          .child(
            button("dismiss", "×", ButtonVariant::Secondary, cx)
              .accessibility_label("Dismiss message")
              .on_click(cx.listener(|this, _, _, cx| {
                this.local_error = None;
                this.send(Command::Dismiss, cx);
              })),
          ),
      );
    }
    if self.help {
      root = root.child(div().px_3().py_2().bg(t.surface).text_size(px(11.)).child("j/k or ↑/↓: select · h/l or ←/→: collapse/expand · Enter: toggle group or connect/disconnect · d: disconnect · f: favorite · /: search · r: refresh · i: import · Esc: close dialog · q: quit"));
    }
    root.child(
      div()
        .px_3()
        .py_2()
        .border_t_1()
        .border_color(t.border)
        .bg(t.surface)
        .flex()
        .justify_between()
        .text_size(px(10.))
        .child("↑ ↓ navigate   ← → fold   Enter activate   f favorite   / search")
        .child(
          button("help", "? Help", ButtonVariant::Secondary, cx).on_click(cx.listener(
            |this, _, _, cx| {
              this.help = !this.help;
              cx.notify();
            },
          )),
        ),
    )
  }
}

#[cfg(test)]
mod tests {
  use super::{filtered_rows, Row};
  use crate::gui::engine::preview_snapshot;
  use std::collections::HashSet;

  #[test]
  fn search_and_favorites_intersect_without_losing_group_headers() {
    let snapshot = preview_snapshot();
    let rows = filtered_rows(&snapshot, "fr", true, &HashSet::new());
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1], Row::Server(0));
    assert!(filtered_rows(&snapshot, "unknown", false, &HashSet::new()).is_empty());
  }

  #[test]
  fn collapsing_provider_keeps_other_profiles_visible() {
    let rows = filtered_rows(
      &preview_snapshot(),
      "",
      false,
      &HashSet::from(["protonvpn".into()]),
    );
    assert_eq!(rows.len(), 3);
    assert_eq!(rows.last(), Some(&Row::Server(5)));
  }
}
