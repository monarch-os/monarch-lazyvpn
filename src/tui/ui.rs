//! UI layout and rendering

use crate::app::App;
use crate::tui::widgets::{
    render_current_status, render_file_picker, render_first_launch_message, render_help_popup,
    render_profile_config, render_provider_menu, render_server_list,
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph},
};

/// Main render function
pub fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.size();

    // Main layout: content area + help bar at bottom (full width)
    let vertical_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    // Content area: server list (left) + right panel
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(vertical_chunks[0]);

    // Right panel: split vertically into status (top) and config (bottom)
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(12), Constraint::Min(0)])
        .split(main_chunks[1]);

    // Render server list (left panel)
    render_server_list(frame, app, main_chunks[0]);

    // Render current status (top right)
    render_current_status(frame, app, right_chunks[0]);

    // Render profile config (bottom right)
    render_profile_config(frame, app, right_chunks[1]);

    // Render help bar (full width at bottom)
    render_help_bar(frame, app, vertical_chunks[1]);

    // Render messages overlay
    render_messages(frame, app, area);

    // Render help popup if active
    if app.show_help {
        render_help_popup(frame, area);
    }

    // Render file picker if active
    if app.file_picker.active {
        render_file_picker(frame, area, &mut app.file_picker);
    }

    // Render provider menu if active
    if app.provider_menu.active {
        render_provider_menu(frame, area, &app.provider_menu);
    }

    // Render first launch message if no providers configured and no popup active
    if app.is_first_launch() && !app.file_picker.active && !app.provider_menu.active && !app.show_help && !app.is_refreshing {
        render_first_launch_message(frame, area);
    }

    // Render loading overlay when refreshing servers
    if app.is_refreshing {
        render_loading_overlay(frame, area, app.spinner_char(), "Loading servers...");
    }
}

/// Render a loading overlay with spinner
fn render_loading_overlay(frame: &mut Frame, area: Rect, spinner: &str, message: &str) {
    let popup_width = 30u16.min(area.width - 4);
    let popup_height = 5u16;
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(x, y, popup_width, popup_height);

    // Clear background
    frame.render_widget(Clear, popup_area);

    let text = format!("{} {}", spinner, message);
    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .title(" Please wait ")
                .title_style(
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .style(Style::default().bg(Color::Black)),
        )
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Yellow));

    frame.render_widget(paragraph, popup_area);
}

/// Render the help bar at the bottom
fn render_help_bar(frame: &mut Frame, app: &App, area: Rect) {
    let help_text = if app.search_mode {
        format!(
            " Search: {} │ [Enter] Connect  [Esc] Cancel",
            app.search_filter
        )
    } else {
        " [q] Quit  [↑↓/jk] Navigate  [Enter] Connect  [d] Disconnect  [r] Refresh  [f] Favorite  [K] Killswitch  [P] Provider  [/] Search  [?] Help".to_string()
    };

    let style = if app.search_mode {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let help = Paragraph::new(help_text).style(style).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(help, area);
}

/// Render error/info messages
fn render_messages(frame: &mut Frame, app: &App, area: Rect) {
    let message = if let Some(ref err) = app.error_message {
        Some((err.as_str(), Color::Red))
    } else if let Some(ref info) = app.info_message {
        Some((info.as_str(), Color::Green))
    } else {
        None
    };

    if let Some((msg, color)) = message {
        // Calculate centered position
        let msg_width = (msg.len() + 4).min(area.width as usize - 4) as u16;
        let msg_height = 3u16;
        let x = (area.width.saturating_sub(msg_width)) / 2;
        let y = area.height.saturating_sub(6);

        let msg_area = Rect::new(x, y, msg_width, msg_height);

        // Clear background
        frame.render_widget(Clear, msg_area);

        // Render message
        let msg_block = Paragraph::new(msg)
            .style(Style::default().fg(color))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(color))
                    .style(Style::default().bg(Color::Black)),
            )
            .alignment(Alignment::Center);

        frame.render_widget(msg_block, msg_area);
    }
}
