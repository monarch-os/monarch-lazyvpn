//! File picker widget for importing WireGuard configs

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
};
use std::fs;
use std::path::{Path, PathBuf};

/// File picker state
#[derive(Debug)]
pub struct FilePicker {
    /// Current directory
    pub current_dir: PathBuf,
    /// List of entries in current directory
    pub entries: Vec<FileEntry>,
    /// Selected index
    pub selected: usize,
    /// List state for scrolling
    pub list_state: ListState,
    /// Filter extension (e.g., "conf")
    pub filter_ext: Option<String>,
    /// Error message
    pub error: Option<String>,
    /// Is active/visible
    pub active: bool,
}

/// A file or directory entry
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub is_hidden: bool,
}

impl FilePicker {
    /// Create a new file picker starting at home directory
    pub fn new() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"));
        let mut picker = Self {
            current_dir: home,
            entries: Vec::new(),
            selected: 0,
            list_state: ListState::default(),
            filter_ext: Some("conf".to_string()),
            error: None,
            active: false,
        };
        picker.refresh();
        picker.list_state.select(Some(0));
        picker
    }

    /// Open the file picker
    pub fn open(&mut self) {
        self.active = true;
        self.error = None;
        self.refresh();
    }

    /// Close the file picker
    pub fn close(&mut self) {
        self.active = false;
    }

    /// Refresh directory listing
    pub fn refresh(&mut self) {
        self.entries.clear();
        self.error = None;

        // Add parent directory entry if not at root
        if self.current_dir.parent().is_some() {
            self.entries.push(FileEntry {
                name: "..".to_string(),
                path: self.current_dir.parent().unwrap().to_path_buf(),
                is_dir: true,
                is_hidden: false,
            });
        }

        // Read directory
        match fs::read_dir(&self.current_dir) {
            Ok(read_dir) => {
                let mut dirs: Vec<FileEntry> = Vec::new();
                let mut files: Vec<FileEntry> = Vec::new();

                for entry in read_dir.flatten() {
                    let path = entry.path();
                    let name = entry.file_name().to_string_lossy().to_string();
                    let is_hidden = name.starts_with('.');
                    let is_dir = path.is_dir();

                    // Skip hidden files (except ..)
                    if is_hidden {
                        continue;
                    }

                    // For files, apply extension filter
                    if !is_dir {
                        if let Some(ref ext) = self.filter_ext {
                            let has_ext = path
                                .extension()
                                .map(|e| e.to_string_lossy().to_lowercase() == ext.to_lowercase())
                                .unwrap_or(false);
                            if !has_ext {
                                continue;
                            }
                        }
                    }

                    let entry = FileEntry {
                        name,
                        path,
                        is_dir,
                        is_hidden,
                    };

                    if is_dir {
                        dirs.push(entry);
                    } else {
                        files.push(entry);
                    }
                }

                // Sort alphabetically
                dirs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
                files.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

                // Directories first, then files
                self.entries.extend(dirs);
                self.entries.extend(files);
            }
            Err(e) => {
                self.error = Some(format!("Cannot read directory: {}", e));
            }
        }

        // Reset selection
        self.selected = 0;
        self.list_state.select(Some(0));
    }

    /// Navigate to a directory
    pub fn navigate_to(&mut self, path: &Path) {
        if path.is_dir() {
            self.current_dir = path.to_path_buf();
            self.refresh();
        }
    }

    /// Move selection up
    pub fn select_previous(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
            self.list_state.select(Some(self.selected));
        }
    }

    /// Move selection down
    pub fn select_next(&mut self) {
        if self.selected < self.entries.len().saturating_sub(1) {
            self.selected += 1;
            self.list_state.select(Some(self.selected));
        }
    }

    /// Jump to top
    pub fn select_first(&mut self) {
        self.selected = 0;
        self.list_state.select(Some(0));
    }

    /// Jump to bottom
    pub fn select_last(&mut self) {
        self.selected = self.entries.len().saturating_sub(1);
        self.list_state.select(Some(self.selected));
    }

    /// Get currently selected entry
    pub fn selected_entry(&self) -> Option<&FileEntry> {
        self.entries.get(self.selected)
    }

    /// Handle Enter key - navigate into dir or return selected file
    pub fn enter(&mut self) -> Option<PathBuf> {
        if let Some(entry) = self.selected_entry().cloned() {
            if entry.is_dir {
                self.navigate_to(&entry.path);
                None
            } else {
                // Return selected file path
                Some(entry.path)
            }
        } else {
            None
        }
    }

    /// Go to home directory
    pub fn go_home(&mut self) {
        if let Some(home) = dirs::home_dir() {
            self.navigate_to(&home);
        }
    }

    /// Go to parent directory
    pub fn go_parent(&mut self) {
        if let Some(parent) = self.current_dir.parent() {
            let parent = parent.to_path_buf();
            self.navigate_to(&parent);
        }
    }
}

impl Default for FilePicker {
    fn default() -> Self {
        Self::new()
    }
}

/// Render the file picker popup
pub fn render_file_picker(frame: &mut Frame, area: Rect, picker: &mut FilePicker) {
    // Calculate popup size (80% of screen, max 80x30)
    let popup_width = (area.width * 80 / 100).min(80).max(40);
    let popup_height = (area.height * 80 / 100).min(30).max(10);
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(x, y, popup_width, popup_height);

    // Clear background
    frame.render_widget(Clear, popup_area);

    // Split into title area, list area, and help area
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Current path
            Constraint::Min(5),    // File list
            Constraint::Length(2), // Help text
        ])
        .split(popup_area);

    // Current path header
    let path_display = picker.current_dir.display().to_string();
    let path_text = if path_display.len() > (popup_width as usize - 4) {
        format!(
            "...{}",
            &path_display[path_display.len() - (popup_width as usize - 7)..]
        )
    } else {
        path_display
    };

    let path_widget = Paragraph::new(path_text)
        .style(Style::default().fg(Color::Cyan))
        .block(
            Block::default()
                .title(" Import WireGuard Config ")
                .title_style(
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        );
    frame.render_widget(path_widget, chunks[0]);

    // File list
    let items: Vec<ListItem> = picker
        .entries
        .iter()
        .map(|entry| {
            let icon = if entry.is_dir { "" } else { "" };
            let style = if entry.is_dir {
                Style::default()
                    .fg(Color::Blue)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(format!(" {} {}", icon, entry.name)).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::LEFT | Borders::RIGHT)
                .border_style(Style::default().fg(Color::Green)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    frame.render_stateful_widget(list, chunks[1], &mut picker.list_state);

    // Help text or error
    let help_text = if let Some(ref err) = picker.error {
        Paragraph::new(err.as_str()).style(Style::default().fg(Color::Red))
    } else {
        Paragraph::new(" ↑↓ Navigate  Enter Select  ~ Home  Backspace Parent  Esc Cancel")
            .style(Style::default().fg(Color::DarkGray))
    };

    let help_widget = help_text.block(
        Block::default()
            .borders(Borders::LEFT | Borders::RIGHT | Borders::BOTTOM)
            .border_style(Style::default().fg(Color::Green)),
    );
    frame.render_widget(help_widget, chunks[2]);
}
