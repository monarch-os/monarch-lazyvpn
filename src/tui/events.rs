//! Event handling for TUI

use crate::app::{App, TreeListItem};
use crate::core::error::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tracing::debug;

/// Handle a key event, returns true if the app should continue
pub async fn handle_key_event(app: &mut App, key: KeyEvent) -> Result<bool> {
    // Clear messages on any key (unless busy)
    if !app.is_busy() {
        app.clear_messages();
    }

    // Handle delete confirmation popup
    if app.pending_delete.is_some() {
        return handle_delete_confirm_key(app, key).await;
    }

    // Handle rename input popup
    if app.rename_target.is_some() {
        return handle_rename_key(app, key).await;
    }

    // Handle file picker mode
    if app.file_picker.active {
        return handle_file_picker_key(app, key).await;
    }

    // Handle provider menu mode
    if app.provider_menu.active {
        return handle_provider_menu_key(app, key).await;
    }

    // Handle search mode separately
    if app.search_mode {
        return handle_search_key(app, key).await;
    }

    // Handle help popup
    if app.show_help {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?')) {
            app.show_help = false;
        }
        return Ok(true);
    }

    match key.code {
        // Quit
        KeyCode::Char('q') => {
            app.should_quit = true;
            return Ok(false);
        }

        // Ctrl+C - force quit
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.should_quit = true;
            return Ok(false);
        }

        // Navigation
        KeyCode::Up | KeyCode::Char('k') => {
            app.select_previous();
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.select_next();
        }
        KeyCode::Home | KeyCode::Char('g') => {
            app.tree_state.selected_index = 0;
        }
        KeyCode::End | KeyCode::Char('G') => {
            let max = app.get_tree_items().len().saturating_sub(1);
            app.tree_state.selected_index = max;
        }

        // Expand/collapse tree nodes
        KeyCode::Right | KeyCode::Char('l') => {
            app.expand_current();
        }
        KeyCode::Left | KeyCode::Char('h') => {
            app.collapse_current();
        }
        KeyCode::Char(' ') => {
            // Space toggles expand/collapse on headers
            app.toggle_current_expand();
        }

        // Connect/disconnect/hot-swap based on current state
        KeyCode::Enter => {
            // Ignore if busy
            if app.is_busy() {
                return Ok(true);
            }

            // Check what's selected
            match app.selected_item() {
                Some(TreeListItem::ProviderHeader { .. }) => {
                    // Toggle expand/collapse on header
                    app.toggle_current_expand();
                }
                Some(TreeListItem::Server(server)) => {
                    // Check if we're trying to connect to the same server
                    let same_server = app.connection.current_server()
                        .map(|s| s.id == server.id)
                        .unwrap_or(false);

                    if same_server && app.connection.is_connected() {
                        // Toggle: disconnect if pressing Enter on active server
                        debug!("Disconnecting from active server");
                        if let Err(e) = app.start_disconnect() {
                            app.error_message = Some(format!("Disconnect failed: {}", e));
                        }
                    } else {
                        // Connect (hot-swap if already connected to different server)
                        debug!("Starting connection to {}", server.name);
                        if let Err(e) = app.start_connect(server) {
                            app.error_message = Some(format!("Connection failed: {}", e));
                        }
                    }
                }
                None => {}
            }
        }

        // Disconnect
        KeyCode::Char('d') => {
            // Ignore if busy
            if app.is_busy() {
                return Ok(true);
            }

            if app.connection.is_connected() {
                debug!("Starting disconnect");
                if let Err(e) = app.start_disconnect() {
                    app.error_message = Some(format!("Disconnect failed: {}", e));
                }
            }
        }

        // Refresh servers (non-blocking)
        KeyCode::Char('r') => {
            // Ignore if busy
            if app.is_busy() {
                return Ok(true);
            }

            debug!("Starting server refresh");
            if let Err(e) = app.start_refresh() {
                app.error_message = Some(format!("Refresh failed: {}", e));
            }
        }

        // Toggle killswitch
        KeyCode::Char('K') => {
            app.toggle_killswitch();
        }

        // Toggle favorite
        KeyCode::Char('f') => {
            app.toggle_favorite();
        }

        // Cycle server list mode
        KeyCode::Char('o') => {
            app.config.cycle_server_list_mode();
            let _ = app.config.save();
            app.info_message = Some(format!(
                "Server list mode: {:?}",
                app.config.server_list_mode
            ));
        }

        // Search
        KeyCode::Char('/') => {
            app.start_search();
        }

        // Help
        KeyCode::Char('?') => {
            app.show_help = true;
        }

        // Import config - open file picker
        KeyCode::Char('i') => {
            app.file_picker.open();
        }

        // Delete selected custom config (with confirmation)
        KeyCode::Char('x') | KeyCode::Delete => {
            // Ignore if busy
            if app.is_busy() {
                return Ok(true);
            }
            app.request_delete_custom();
        }

        // Rename selected custom config
        KeyCode::Char('R') => {
            // Ignore if busy
            if app.is_busy() {
                return Ok(true);
            }
            app.request_rename_custom();
        }

        // Add provider - open provider menu
        KeyCode::Char('p') | KeyCode::Char('P') => {
            app.provider_menu.open();
        }

        // Clear error state (when in error state)
        KeyCode::Char('c') => {
            if app.connection.is_error() {
                if let Err(e) = app.connection.clear_error() {
                    app.error_message = Some(format!("Failed to clear error: {}", e));
                } else {
                    app.info_message = Some("Error cleared".to_string());
                }
            }
        }

        _ => {}
    }

    Ok(true)
}

/// Handle key events in file picker mode
async fn handle_file_picker_key(app: &mut App, key: KeyEvent) -> Result<bool> {
    match key.code {
        // Cancel
        KeyCode::Esc | KeyCode::Char('q') => {
            app.file_picker.close();
            app.pending_provider_import = None;
        }

        // Navigation
        KeyCode::Up | KeyCode::Char('k') => {
            app.file_picker.select_previous();
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.file_picker.select_next();
        }
        KeyCode::Home | KeyCode::Char('g') => {
            app.file_picker.select_first();
        }
        KeyCode::End | KeyCode::Char('G') => {
            app.file_picker.select_last();
        }

        // Go to home directory
        KeyCode::Char('~') => {
            app.file_picker.go_home();
        }

        // Go to parent directory
        KeyCode::Backspace => {
            app.file_picker.go_parent();
        }

        // Select/Enter directory or file
        KeyCode::Enter => {
            if let Some(selected_path) = app.file_picker.enter() {
                // File was selected, import it
                app.file_picker.close();
                debug!("Importing config from {:?}", selected_path);

                // Check if this import is for a specific provider
                let pending_provider = app.pending_provider_import.take();

                if let Err(e) = app.import_config(&selected_path).await {
                    app.error_message = Some(format!("Import failed: {}", e));
                } else {
                    // Import succeeded - add provider to configured list if needed
                    if let Some(provider) = pending_provider {
                        if let Err(e) = app.add_configured_provider(&provider) {
                            app.error_message = Some(format!("Failed to add provider: {}", e));
                        }
                    }
                }
            }
            // If None, we navigated into a directory
        }

        _ => {}
    }

    Ok(true)
}

/// Handle key events in provider menu mode
async fn handle_provider_menu_key(app: &mut App, key: KeyEvent) -> Result<bool> {
    match key.code {
        // Cancel
        KeyCode::Esc | KeyCode::Char('q') => {
            app.provider_menu.close();
        }

        // Navigation
        KeyCode::Up | KeyCode::Char('k') => {
            app.provider_menu.select_previous();
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.provider_menu.select_next();
        }

        // Select provider and open file picker
        KeyCode::Enter => {
            let provider = app.provider_menu.selected_provider();
            app.pending_provider_import = Some(provider.id().to_string());
            app.provider_menu.close();
            app.file_picker.open();
        }

        _ => {}
    }

    Ok(true)
}

/// Handle key events in the delete confirmation popup
async fn handle_delete_confirm_key(app: &mut App, key: KeyEvent) -> Result<bool> {
    match key.code {
        // Confirm deletion
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            app.confirm_delete_custom();
        }
        // Cancel deletion
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc | KeyCode::Char('q') => {
            app.cancel_delete();
        }
        _ => {}
    }

    Ok(true)
}

/// Handle key events in the rename input popup
async fn handle_rename_key(app: &mut App, key: KeyEvent) -> Result<bool> {
    match key.code {
        // Confirm rename
        KeyCode::Enter => {
            app.confirm_rename_custom();
        }
        // Cancel rename
        KeyCode::Esc => {
            app.cancel_rename();
        }
        KeyCode::Backspace => {
            app.rename_pop();
        }
        KeyCode::Char(c) => {
            app.rename_push(c);
        }
        _ => {}
    }

    Ok(true)
}

/// Handle key events in search mode
async fn handle_search_key(app: &mut App, key: KeyEvent) -> Result<bool> {
    match key.code {
        KeyCode::Esc => {
            app.end_search();
            app.search_filter.clear();
            app.tree_state.selected_index = 0;
        }
        KeyCode::Enter => {
            app.end_search();

            // Ignore if busy
            if app.is_busy() {
                return Ok(true);
            }

            // Keep filter applied, try to connect (or hot-swap if already connected)
            if let Some(server) = app.selected_server() {
                // Check if we're trying to connect to the same server
                let same_server = app.connection.current_server()
                    .map(|s| s.id == server.id)
                    .unwrap_or(false);

                if same_server && app.connection.is_connected() {
                    app.info_message = Some("Already connected to this server".to_string());
                } else {
                    if let Err(e) = app.start_connect(server) {
                        app.error_message = Some(format!("Connection failed: {}", e));
                    }
                }
            }
        }
        KeyCode::Backspace => {
            app.search_pop();
        }
        KeyCode::Up => {
            app.select_previous();
        }
        KeyCode::Down => {
            app.select_next();
        }
        KeyCode::Char(c) => {
            app.search_push(c);
        }
        _ => {}
    }

    Ok(true)
}
