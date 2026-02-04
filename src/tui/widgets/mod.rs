//! TUI widgets

mod file_picker;
mod provider_menu;
mod server_list;
mod status_panel;

pub use file_picker::{render_file_picker, FilePicker};
pub use provider_menu::{render_first_launch_message, render_provider_menu, ProviderMenu, ProviderOption};
pub use server_list::render_server_list;
pub use status_panel::{render_current_status, render_profile_config};

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

/// Render help popup
pub fn render_help_popup(frame: &mut Frame, area: Rect) {
    let popup_width = 60u16.min(area.width - 4);
    let popup_height = 20u16.min(area.height - 4);
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(x, y, popup_width, popup_height);

    // Clear background
    frame.render_widget(Clear, popup_area);

    let help_text = vec![
        Line::from(vec![Span::styled(
            "Navigation",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from("  ↑/k       Move up"),
        Line::from("  ↓/j       Move down"),
        Line::from("  g         Go to top"),
        Line::from("  G         Go to bottom"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Actions",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from("  Enter     Connect to selected server"),
        Line::from("  d         Disconnect"),
        Line::from("  r         Refresh server list"),
        Line::from("  f         Toggle favorite"),
        Line::from("  K         Toggle killswitch"),
        Line::from("  o         Cycle server list mode"),
        Line::from("  i         Import custom config"),
        Line::from("  P         Add VPN provider"),
        Line::from("  /         Search servers"),
        Line::from(""),
        Line::from(vec![Span::styled(
            "General",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from("  ?         Show this help"),
        Line::from("  q         Quit"),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .title(" Help ")
                .title_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .style(Style::default().bg(Color::Black)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(help, popup_area);
}
