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
    let popup_height = 24u16.min(area.height - 4);
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
        Line::from("  R         Rename custom config"),
        Line::from("  x/Del     Delete custom config"),
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

/// Render an input popup for renaming a custom config
pub fn render_rename_popup(frame: &mut Frame, area: Rect, buffer: &str) {
    let popup_width = 50u16.min(area.width - 4);
    let popup_height = 7u16.min(area.height - 4);
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(x, y, popup_width, popup_height);

    // Clear background
    frame.render_widget(Clear, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(popup_area);

    let instruction =
        Paragraph::new("New name:").style(Style::default().fg(Color::White));

    // Input field with a block cursor
    let input = Paragraph::new(Line::from(vec![
        Span::styled(buffer, Style::default().fg(Color::Yellow)),
        Span::styled("█", Style::default().fg(Color::Yellow)),
    ]));

    let help = Paragraph::new("[Enter] Confirm  [Esc] Cancel")
        .style(Style::default().fg(Color::DarkGray))
        .alignment(Alignment::Center);

    let block = Block::default()
        .title(" Rename custom config ")
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
    frame.render_widget(input, chunks[1]);
    frame.render_widget(help, chunks[3]);
}

/// Render a confirmation popup for deleting a custom config
pub fn render_delete_confirm(frame: &mut Frame, area: Rect, config_name: &str) {
    let popup_width = 50u16.min(area.width - 4);
    let popup_height = 7u16.min(area.height - 4);
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(x, y, popup_width, popup_height);

    // Clear background
    frame.render_widget(Clear, popup_area);

    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::raw("Delete custom config "),
            Span::styled(
                format!("'{}'", config_name),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("?"),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "[y] Yes    [n/Esc] No",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .title(" Confirm deletion ")
                .title_style(
                    Style::default()
                        .fg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red))
                .style(Style::default().bg(Color::Black)),
        )
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: false });

    frame.render_widget(paragraph, popup_area);
}
