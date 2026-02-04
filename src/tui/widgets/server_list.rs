//! Server list widget with tree view (providers as collapsible groups)

use crate::app::{App, TreeListItem};
use crate::core::server::Server;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
};
use unicode_width::UnicodeWidthStr;

/// Render a provider header line
fn render_provider_header(
    name: &str,
    display_name: &str,
    server_count: usize,
    expanded: bool,
    is_selected: bool,
) -> ListItem<'static> {
    let expand_char = if expanded { "▼" } else { "▶" };

    let provider_color = match name {
        "protonvpn" => Color::Magenta,
        "custom" => Color::Green,
        _ => Color::Cyan,
    };

    let style = if is_selected {
        Style::default()
            .fg(provider_color)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(provider_color)
    };

    let line = Line::from(vec![
        Span::styled(format!("{} ", expand_char), style),
        Span::styled(display_name.to_string(), style.add_modifier(Modifier::BOLD)),
        Span::styled(
            format!(" ({})", server_count),
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    ListItem::new(line)
}

/// Render a server line (indented under provider)
fn render_server_line(
    server: &Server,
    is_connected: bool,
    is_favorite: bool,
) -> ListItem<'static> {
    let mut line_parts: Vec<Span> = Vec::new();

    // Indentation for tree structure
    line_parts.push(Span::raw("    "));

    // Favorite star
    if is_favorite {
        line_parts.push(Span::styled("★ ", Style::default().fg(Color::Yellow)));
    } else {
        line_parts.push(Span::raw("  "));
    }

    // Connection indicator
    if is_connected {
        line_parts.push(Span::styled("● ", Style::default().fg(Color::Green)));
    } else {
        line_parts.push(Span::raw("  "));
    }

    // Country flag - emoji flags are 2 Regional Indicator chars that render as 1 glyph
    // Use Zero-Width Joiner and padding to ensure proper terminal rendering
    let flag = server.country_flag();
    let flag_width = flag.width();
    let display_flag = if flag_width < 2 {
        // If terminal sees it as separate chars, add ZWJ to combine them
        format!("{}\u{200D}  ", flag) // ZWJ + double space
    } else {
        // Terminal already combines them, just add spacing
        format!("{}  ", flag) // Double space for alignment
    };
    line_parts.push(Span::raw(display_flag));

    // Server display name - format depends on provider
    let name_style = if is_connected {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    } else if is_favorite {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    };

    // ProtonVPN format: "<FLAG> Country, City - ServerName"
    // Other providers: just server name
    let display_text = if server.provider == "protonvpn" {
        format!("{}, {} - {}", server.country, server.city, server.name)
    } else {
        server.name.clone()
    };

    line_parts.push(Span::styled(display_text, name_style));

    // Features
    let features = server.feature_icons();
    if !features.is_empty() {
        line_parts.push(Span::styled(
            format!(" [{}]", features),
            Style::default().fg(Color::DarkGray),
        ));
    }

    ListItem::new(Line::from(line_parts))
}

/// Render the server list with tree view
pub fn render_server_list(frame: &mut Frame, app: &mut App, area: Rect) {
    // Clear the area first to prevent ghost artifacts from emoji rendering issues
    frame.render_widget(Clear, area);

    let tree_items = app.get_tree_items();
    let selected_index = app.tree_state.selected_index;

    let items: Vec<ListItem> = tree_items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let is_selected = i == selected_index;
            match item {
                TreeListItem::ProviderHeader {
                    name,
                    display_name,
                    server_count,
                    expanded,
                } => render_provider_header(name, display_name, *server_count, *expanded, is_selected),
                TreeListItem::Server(server) => {
                    let is_connected = app.connection.is_connected()
                        && app.connection.current_server().map(|s| &s.id) == Some(&server.id);
                    let is_favorite = app.config.is_favorite(&server.id);
                    render_server_line(server, is_connected, is_favorite)
                }
            }
        })
        .collect();

    // Count total servers for title
    let server_count: usize = tree_items
        .iter()
        .filter(|item| matches!(item, TreeListItem::Server(_)))
        .count();

    let title = if app.search_mode && !app.search_filter.is_empty() {
        format!(" Servers ({} matching) ", server_count)
    } else {
        format!(" Servers ({}) ", server_count)
    };

    let title_style = if !app.has_provider() {
        Style::default().fg(Color::Red)
    } else {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    };

    let list = List::new(items)
        .block(
            Block::default()
                .title(title)
                .title_style(title_style)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    let mut state = ListState::default();
    state.select(Some(app.tree_state.selected_index));

    frame.render_stateful_widget(list, area, &mut state);

    // Fix emoji rendering artifacts in Kitty: overwrite empty lines below the list
    let inner_height = area.height.saturating_sub(2) as usize;
    let items_count = tree_items.len();
    if items_count < inner_height {
        let empty_start_y = area.y + 1 + items_count as u16;
        let empty_count = inner_height - items_count;
        let inner_width = area.width.saturating_sub(2);
        let blank_line = format!("│{}│", " ".repeat(inner_width as usize));

        for i in 0..empty_count {
            let y = empty_start_y + i as u16;
            frame.render_widget(
                Paragraph::new(blank_line.clone())
                    .style(Style::default().fg(Color::DarkGray)),
                Rect::new(area.x, y, area.width, 1),
            );
        }
    }

    // Show setup message if no provider
    if !app.has_provider() {
        let setup_msg = Paragraph::new("Press [i] to import a WireGuard config")
            .style(Style::default().fg(Color::Yellow))
            .alignment(Alignment::Center);

        let msg_area = Rect::new(area.x + 2, area.y + area.height / 2, area.width - 4, 1);
        frame.render_widget(setup_msg, msg_area);
    }
}
