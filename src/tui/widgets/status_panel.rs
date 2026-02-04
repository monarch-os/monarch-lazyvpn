//! Status panel widgets - split into Current Status and Profile Config

use crate::app::App;
use crate::core::connection::ConnectionState;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph},
};

/// Render the current status panel (top right)
pub fn render_current_status(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    // Connection status with animated spinner
    let (status_text, status_color) = match app.connection.state() {
        ConnectionState::Connected => ("● Connected".to_string(), Color::Green),
        ConnectionState::Connecting => (
            format!("{} Connecting...", app.spinner_char()),
            Color::Yellow,
        ),
        ConnectionState::Disconnecting => (
            format!("{} Disconnecting...", app.spinner_char()),
            Color::Yellow,
        ),
        ConnectionState::Disconnected => ("○ Disconnected".to_string(), Color::Red),
        ConnectionState::Error(_) => ("✗ Error".to_string(), Color::Red),
    };

    lines.push(Line::from(vec![
        Span::styled("Status: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            &status_text,
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        ),
    ]));

    // Active profile (if connected)
    if let Some(server) = app.connection.current_server() {
        lines.push(Line::from(vec![
            Span::styled("Profile: ", Style::default().fg(Color::DarkGray)),
            Span::styled(&server.name, Style::default().fg(Color::Cyan)),
        ]));
    }

    // Public IP
    if let Some(ref ip) = app.current_public_ip {
        lines.push(Line::from(vec![
            Span::styled("Public IP: ", Style::default().fg(Color::DarkGray)),
            Span::styled(ip, Style::default().fg(Color::Green)),
        ]));
    } else if app.connection.is_connected() {
        lines.push(Line::from(vec![
            Span::styled("Public IP: ", Style::default().fg(Color::DarkGray)),
            Span::styled("Checking...", Style::default().fg(Color::Yellow)),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled("Public IP: ", Style::default().fg(Color::DarkGray)),
            Span::styled("N/A", Style::default().fg(Color::DarkGray)),
        ]));
    }

    lines.push(Line::from(""));

    // Killswitch - show actual state (disabled for split-tunnel)
    let is_split_tunnel_connected = app.connection.is_connected()
        && app.connection.current_server().map(|s| s.is_split_tunnel()).unwrap_or(false);

    let ks_status = if is_split_tunnel_connected {
        ("Disabled (split-tunnel)", Color::Yellow)
    } else if app.config.killswitch_enabled {
        ("Enabled", Color::Green)
    } else {
        ("Disabled", Color::Yellow)
    };
    lines.push(Line::from(vec![
        Span::styled("Killswitch: ", Style::default().fg(Color::DarkGray)),
        Span::styled(ks_status.0, Style::default().fg(ks_status.1)),
    ]));

    // IPv6
    let ipv6_status = if app.config.ipv6_disabled {
        ("Blocked", Color::Green)
    } else {
        ("Allowed", Color::Yellow)
    };
    lines.push(Line::from(vec![
        Span::styled("IPv6: ", Style::default().fg(Color::DarkGray)),
        Span::styled(ipv6_status.0, Style::default().fg(ipv6_status.1)),
    ]));

    // LAN Access (only show if killswitch enabled)
    if app.config.killswitch_enabled {
        let lan_status = if app.config.killswitch_allow_lan {
            ("Allowed", Color::Yellow)
        } else {
            ("Blocked", Color::Green)
        };
        lines.push(Line::from(vec![
            Span::styled("LAN Access: ", Style::default().fg(Color::DarkGray)),
            Span::styled(lan_status.0, Style::default().fg(lan_status.1)),
        ]));
    }

    // Error display
    if let ConnectionState::Error(ref e) = app.connection.state() {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("Error: ", Style::default().fg(Color::Red)),
            Span::styled(e, Style::default().fg(Color::Red)),
        ]));
    }

    let status = Paragraph::new(lines).block(
        Block::default()
            .title(" Current Status ")
            .title_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(status, area);
}

/// Render the profile config panel (bottom right)
pub fn render_profile_config(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();

    // Get selected server from list
    let selected_server = app.selected_server();
    let connected_server = app.connection.current_server();

    // Determine title based on selection
    let title = match (&selected_server, connected_server) {
        (Some(sel), Some(conn)) if sel.id == conn.id => " Config (Active) ",
        (Some(_), _) => " Config (Selected) ",
        (None, Some(_)) => " Config (Active) ",
        (None, None) => " Config ",
    };

    // Use selected server, or fall back to connected server
    let server = selected_server.or_else(|| connected_server.cloned());

    if let Some(server) = server {
        // Server name & Location
        lines.push(Line::from(vec![
            Span::styled("Server: ", Style::default().fg(Color::DarkGray)),
            Span::styled(server.name.clone(), Style::default().fg(Color::Cyan)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Location: ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!(
                "{} {}, {}",
                server.country_flag(),
                server.country,
                server.city
            )),
        ]));

        lines.push(Line::from(""));

        // [Interface] section
        lines.push(Line::from(vec![Span::styled(
            "[Interface]",
            Style::default().fg(Color::Yellow),
        )]));

        if let Some(ref creds) = app.provider_credentials {
            lines.push(Line::from(vec![
                Span::styled("PrivateKey = ", Style::default().fg(Color::DarkGray)),
                Span::styled("••••••••••••••••", Style::default().fg(Color::Red)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("Address = ", Style::default().fg(Color::DarkGray)),
                Span::raw(creds.address.clone()),
            ]));
        }

        if let Some(ref provider) = app.active_provider {
            lines.push(Line::from(vec![
                Span::styled("DNS = ", Style::default().fg(Color::DarkGray)),
                Span::raw(provider.dns()),
            ]));
        }

        lines.push(Line::from(""));

        // [Peer] section
        lines.push(Line::from(vec![Span::styled(
            "[Peer]",
            Style::default().fg(Color::Yellow),
        )]));

        // Truncate pubkey for display
        let pubkey_display = if server.pubkey.len() > 24 {
            format!(
                "{}...{}",
                &server.pubkey[..12],
                &server.pubkey[server.pubkey.len() - 8..]
            )
        } else {
            server.pubkey.clone()
        };
        lines.push(Line::from(vec![
            Span::styled("PublicKey = ", Style::default().fg(Color::DarkGray)),
            Span::raw(pubkey_display),
        ]));

        let port = app
            .active_provider
            .as_ref()
            .map(|p| p.port())
            .unwrap_or(51820);
        lines.push(Line::from(vec![
            Span::styled("Endpoint = ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!("{}:{}", server.ip, port)),
        ]));

        lines.push(Line::from(vec![
            Span::styled("AllowedIPs = ", Style::default().fg(Color::DarkGray)),
            Span::raw(server.allowed_ips.clone()),
        ]));

        lines.push(Line::from(vec![
            Span::styled(
                "PersistentKeepalive = ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::raw("25"),
        ]));
    } else if app.active_provider.is_none() && !app.config.has_configured_providers() {
        // No provider configured
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "No provider configured",
            Style::default().fg(Color::DarkGray),
        )]));
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "Press [P] to add a provider",
            Style::default().fg(Color::Yellow),
        )]));
        lines.push(Line::from(vec![Span::styled(
            "Press [I] to import a config",
            Style::default().fg(Color::Yellow),
        )]));
    } else {
        // No server selected
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(
            "Select a server to preview",
            Style::default().fg(Color::DarkGray),
        )]));
    }

    let config = Paragraph::new(lines).block(
        Block::default()
            .title(title)
            .title_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(config, area);
}
