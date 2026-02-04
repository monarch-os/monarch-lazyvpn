//! Provider selection menu widget

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph},
};

/// Available VPN providers
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProviderOption {
    ProtonVPN,
    Mullvad,
}

impl ProviderOption {
    pub fn id(&self) -> &'static str {
        match self {
            ProviderOption::ProtonVPN => "protonvpn",
            ProviderOption::Mullvad => "mullvad",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            ProviderOption::ProtonVPN => "ProtonVPN",
            ProviderOption::Mullvad => "Mullvad",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            ProviderOption::ProtonVPN => "Import a ProtonVPN WireGuard config",
            ProviderOption::Mullvad => "Import a Mullvad WireGuard config",
        }
    }

    pub fn all() -> &'static [ProviderOption] {
        &[ProviderOption::ProtonVPN, ProviderOption::Mullvad]
    }
}

/// Provider selection menu state
pub struct ProviderMenu {
    pub active: bool,
    pub selected: usize,
}

impl Default for ProviderMenu {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderMenu {
    pub fn new() -> Self {
        Self {
            active: false,
            selected: 0,
        }
    }

    pub fn open(&mut self) {
        self.active = true;
        self.selected = 0;
    }

    pub fn close(&mut self) {
        self.active = false;
    }

    pub fn select_next(&mut self) {
        let options = ProviderOption::all();
        if self.selected < options.len() - 1 {
            self.selected += 1;
        }
    }

    pub fn select_previous(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn selected_provider(&self) -> ProviderOption {
        ProviderOption::all()[self.selected]
    }
}

/// Render the provider selection menu
pub fn render_provider_menu(frame: &mut Frame, area: Rect, menu: &ProviderMenu) {
    let popup_width = 50u16.min(area.width - 4);
    let popup_height = 12u16.min(area.height - 4);
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(x, y, popup_width, popup_height);

    // Clear background
    frame.render_widget(Clear, popup_area);

    // Create layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Length(2), Constraint::Min(0), Constraint::Length(1)])
        .split(popup_area);

    // Title/instruction
    let instruction = Paragraph::new("Select a VPN provider to configure:")
        .style(Style::default().fg(Color::White));

    // Provider list
    let items: Vec<ListItem> = ProviderOption::all()
        .iter()
        .enumerate()
        .map(|(i, provider)| {
            let style = if i == menu.selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            let prefix = if i == menu.selected { "> " } else { "  " };
            ListItem::new(format!("{}{}", prefix, provider.display_name())).style(style)
        })
        .collect();

    let list = List::new(items);

    // Help text
    let help = Paragraph::new("[Enter] Select  [Esc] Cancel")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);

    // Container block
    let block = Block::default()
        .title(" Add VPN Provider ")
        .title_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .style(Style::default().bg(Color::Black));

    frame.render_widget(block, popup_area);
    frame.render_widget(instruction, chunks[0]);
    frame.render_widget(list, chunks[1]);
    frame.render_widget(help, chunks[2]);
}

/// Render first launch message when no providers are configured
pub fn render_first_launch_message(frame: &mut Frame, area: Rect) {
    let popup_width = 50u16.min(area.width - 4);
    let popup_height = 10u16.min(area.height - 4);
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(x, y, popup_width, popup_height);

    // Clear background
    frame.render_widget(Clear, popup_area);

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "No VPN providers configured",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Press [P] to add a VPN provider"),
        Line::from("Press [I] to import a custom WireGuard config"),
        Line::from(""),
        Line::from(Span::styled(
            "Press [?] for help",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .title(" Welcome ")
                .title_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .style(Style::default().bg(Color::Black)),
        )
        .alignment(Alignment::Center);

    frame.render_widget(paragraph, popup_area);
}
