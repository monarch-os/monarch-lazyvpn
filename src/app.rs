//! Main application state and logic

use crate::core::config::AppConfig;
use crate::core::connection::{ConnectionManager, ConnectionState};
use crate::core::error::{Result, VpnError};
use crate::core::provider::{custom::CustomProvider, detect_provider, get_provider, ProviderType, VpnProvider, WgConfig};
use crate::core::server::Server;
use crate::system::firewall::{cleanup_orphaned_killswitch, Ipv6Protection, Killswitch};
use crate::system::keyring::{CredentialManager, ProviderCredentials};
use crate::system::network::NetworkStats;
use crate::system::wireguard::WgManager;
use crate::tui::widgets::FilePicker;
use crate::utils::gluetun::{get_servers, ServerCache};
use indexmap::IndexMap;
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

const IP_VERIFY_RETRIES: u32 = 3;
const IP_VERIFY_DELAY_MS: u64 = 2000;
/// Global timeout for operations (90s = wg-quick 30s + nft 10s + margin)
const OPERATION_TIMEOUT_SECS: u64 = 90;

/// Spinner animation frames
pub const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Item in the tree view (flattened for rendering)
#[derive(Debug, Clone)]
pub enum TreeListItem {
    /// Provider group header
    ProviderHeader {
        name: String,
        display_name: String,
        server_count: usize,
        expanded: bool,
    },
    /// Individual server
    Server(Server),
}

/// State for the tree view navigation
#[derive(Debug, Clone, Default)]
pub struct TreeViewState {
    /// Provider expansion state (provider_name -> expanded)
    pub expanded: HashMap<String, bool>,
    /// Selected index in the flattened tree list
    pub selected_index: usize,
}

impl TreeViewState {
    /// Create a new tree view state
    pub fn new() -> Self {
        Self {
            expanded: HashMap::new(),
            selected_index: 0,
        }
    }

    /// Create tree view state from config
    pub fn from_config(config: &AppConfig) -> Self {
        Self {
            expanded: config.provider_expanded.clone(),
            selected_index: 0,
        }
    }

    /// Check if a provider is expanded (default: false = collapsed)
    pub fn is_expanded(&self, provider: &str) -> bool {
        *self.expanded.get(provider).unwrap_or(&false)
    }

    /// Toggle expansion state for a provider
    pub fn toggle_expand(&mut self, provider: &str) {
        let entry = self.expanded.entry(provider.to_string()).or_insert(true);
        *entry = !*entry;
    }

    /// Expand a provider
    pub fn expand(&mut self, provider: &str) {
        self.expanded.insert(provider.to_string(), true);
    }

    /// Collapse a provider
    pub fn collapse(&mut self, provider: &str) {
        self.expanded.insert(provider.to_string(), false);
    }
}

/// Result of a background operation
#[derive(Debug)]
pub enum OperationResult {
    ConnectSuccess(String),  // server name
    ConnectError(String),
    DisconnectSuccess,
    DisconnectError(String),
    ImportSuccess,
    ImportError(String),
    RefreshSuccess(usize),  // server count
    RefreshError(String),
}

/// Main application state
pub struct App {
    /// Application configuration
    pub config: AppConfig,

    /// Connection manager
    pub connection: ConnectionManager,

    /// WireGuard manager
    pub wg: WgManager,

    /// Credential manager
    pub credentials: CredentialManager,

    /// Network stats collector
    pub network_stats: NetworkStats,

    /// Server cache
    pub server_cache: Option<ServerCache>,

    /// Tree view state (selection and expansion)
    pub tree_state: TreeViewState,

    /// Search filter
    pub search_filter: String,

    /// Is in search mode
    pub search_mode: bool,

    /// Active provider
    pub active_provider: Option<Box<dyn VpnProvider>>,

    /// Provider credentials
    pub provider_credentials: Option<ProviderCredentials>,

    /// Current public IP
    pub current_public_ip: Option<String>,

    /// Should quit
    pub should_quit: bool,

    /// Show help popup
    pub show_help: bool,

    /// File picker for importing configs
    pub file_picker: FilePicker,

    /// Error message to display
    pub error_message: Option<String>,

    /// Info message to display
    pub info_message: Option<String>,

    /// Spinner frame index for animations
    pub spinner_frame: usize,

    /// Pending operation result receiver
    pending_operation: Option<oneshot::Receiver<OperationResult>>,

    /// Timestamp when operation started (for timeout detection)
    operation_started_at: Option<Instant>,

    /// Pending refresh result receiver (separate from main operations)
    pending_refresh: Option<oneshot::Receiver<std::result::Result<ServerCache, String>>>,

    /// Refreshing flag
    pub is_refreshing: bool,

    /// Flag to request immediate IP refresh after connection
    pub needs_ip_refresh: bool,

    /// Provider menu for adding new providers
    pub provider_menu: crate::tui::widgets::ProviderMenu,

    /// Provider being imported (set when file picker opens after provider selection)
    pub pending_provider_import: Option<String>,

    /// Effective killswitch state for current connection (accounts for split-tunnel)
    pending_killswitch_enabled: bool,
}

impl App {
    /// Create a new application instance
    pub async fn new() -> Result<Self> {
        // Load config
        let config = AppConfig::load()?;

        // Create connection manager
        let connection = ConnectionManager::new(&config.interface_name)?;

        // Create WireGuard manager
        let wg = WgManager::new(&config.interface_name);

        // Create credential manager
        let credentials = CredentialManager::new();

        // Create network stats
        let network_stats = NetworkStats::new();

        let tree_state = TreeViewState::from_config(&config);

        Ok(Self {
            config,
            connection,
            wg,
            credentials,
            network_stats,
            server_cache: None,
            tree_state,
            search_filter: String::new(),
            search_mode: false,
            active_provider: None,
            provider_credentials: None,
            current_public_ip: None,
            should_quit: false,
            show_help: false,
            file_picker: FilePicker::new(),
            error_message: None,
            info_message: None,
            spinner_frame: 0,
            pending_operation: None,
            operation_started_at: None,
            pending_refresh: None,
            is_refreshing: false,
            needs_ip_refresh: false,
            provider_menu: crate::tui::widgets::ProviderMenu::new(),
            pending_provider_import: None,
            pending_killswitch_enabled: false,
        })
    }

    /// Initialize application (load cache, cleanup, etc.)
    pub async fn initialize(&mut self) -> Result<()> {
        // Use system detection to recover VPN state (async)
        // This replaces the sync recover_state from ConnectionManager::new()
        let detection_message = self.connection.recover_state_with_detection().await?;
        let connection_restored = self.connection.is_connected();

        // Cleanup any orphaned state from previous crashes
        // Skip cleanup if we restored a connection (don't clean up our own interface)
        if !connection_restored {
            self.cleanup_orphaned_state().await?;
        }

        // Load server cache
        self.refresh_servers(false, true).await?; // silent on startup

        // Try to load existing provider credentials
        self.load_provider_credentials()?;

        // If we restored a connection, request IP refresh and select the connected server
        if connection_restored {
            self.needs_ip_refresh = true;

            // Use detection message if available, or fall back to server name
            if let Some(msg) = detection_message {
                info!("{}", msg);
                self.info_message = Some(msg);
            } else if let Some(server) = self.connection.current_server() {
                info!("Restored connection to server: {}", server.name);
                self.info_message = Some(format!("Restored connection to {}", server.name));
            }

            // Auto-select the connected server in the list if it's one we know
            if let Some(server) = self.connection.current_server().cloned() {
                if !server.id.starts_with("external-") {
                    self.select_server_by_id(&server.id);
                }
            }
        }

        Ok(())
    }

    /// Select a server by its ID in the tree view
    fn select_server_by_id(&mut self, server_id: &str) {
        // First, find the provider of this server and expand it
        let servers = self.get_servers();
        if let Some(server) = servers.iter().find(|s| s.id == server_id) {
            let provider = server.provider.clone();
            self.tree_state.expand(&provider);
            self.config.provider_expanded = self.tree_state.expanded.clone();
        }

        // Now find the index of the server in the tree
        let items = self.get_tree_items();
        for (i, item) in items.iter().enumerate() {
            if let TreeListItem::Server(s) = item {
                if s.id == server_id {
                    self.tree_state.selected_index = i;
                    return;
                }
            }
        }
    }

    /// Cleanup orphaned state from previous crashes
    async fn cleanup_orphaned_state(&mut self) -> Result<()> {
        info!("Checking for orphaned state...");

        // Cleanup orphaned WireGuard interfaces first
        if let Err(e) = WgManager::cleanup_all_interfaces().await {
            warn!("Failed to cleanup orphaned interfaces: {}", e);
        }

        // Cleanup orphaned killswitch rules
        cleanup_orphaned_killswitch().await?;

        // Cleanup orphaned IPv6 state
        if let Ok(ipv6) = Ipv6Protection::new() {
            if ipv6.has_orphaned_state() {
                warn!("Found orphaned IPv6 state, recovering...");
                ipv6.recover_from_crash().await?;
            }
        }

        // Cleanup orphaned temp files
        self.cleanup_temp_files()?;

        Ok(())
    }

    /// Cleanup temp config files
    fn cleanup_temp_files(&self) -> Result<()> {
        let uid = unsafe { libc::getuid() };
        let temp_dir = std::path::PathBuf::from(format!("/run/user/{}", uid));

        if temp_dir.exists() {
            for entry in std::fs::read_dir(&temp_dir)? {
                let entry = entry?;
                let path = entry.path();
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("monarch-vpn-") && name.ends_with(".conf") {
                        warn!("Removing orphaned temp config: {:?}", path);
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }

        Ok(())
    }

    /// Load provider credentials from keyring
    fn load_provider_credentials(&mut self) -> Result<()> {
        // Try to load ProtonVPN credentials first
        if self.credentials.exists("protonvpn") {
            match self.credentials.retrieve("protonvpn") {
                Ok(creds) => {
                    self.provider_credentials = Some(creds);
                    self.active_provider = Some(get_provider(ProviderType::ProtonVPN));
                    info!("Loaded ProtonVPN credentials from keyring");
                    return Ok(());
                }
                Err(e) => {
                    warn!("Failed to load ProtonVPN credentials: {}", e);
                }
            }
        }

        // Check for custom configs
        if let Ok(custom_configs) = CustomProvider::list_custom_configs() {
            if !custom_configs.is_empty() {
                // Try to load credentials for the first custom config
                for config_name in &custom_configs {
                    let provider_name = format!("custom/{}", config_name);
                    if self.credentials.exists(&provider_name) {
                        match self.credentials.retrieve(&provider_name) {
                            Ok(creds) => {
                                self.provider_credentials = Some(creds);
                                self.active_provider = Some(get_provider(ProviderType::Custom));
                                info!("Loaded custom config credentials for '{}'", config_name);
                                return Ok(());
                            }
                            Err(e) => {
                                warn!("Failed to load credentials for '{}': {}", config_name, e);
                            }
                        }
                    }
                }
                // If we have custom configs but no credentials, still set the provider
                // so the configs are visible (user may need to re-import)
                info!("Found {} custom config(s), setting custom provider", custom_configs.len());
                self.active_provider = Some(get_provider(ProviderType::Custom));
            }
        }

        Ok(())
    }

    /// Refresh server list
    /// If `silent` is true, don't show info_message (used during startup)
    pub async fn refresh_servers(&mut self, force: bool, silent: bool) -> Result<()> {
        // If no providers configured, don't fetch from gluetun
        if !self.config.has_configured_providers() {
            info!("No providers configured, skipping server fetch");
            self.server_cache = Some(crate::utils::gluetun::ServerCache::empty());
            return Ok(());
        }

        info!("Refreshing server list...");


        match get_servers(force).await {
            Ok(cache) => {
                // Filter servers to only configured providers
                let filtered_servers: Vec<Server> = cache.servers
                    .into_iter()
                    .filter(|s| self.config.configured_providers.contains(&s.provider))
                    .collect();

                let count = filtered_servers.len();
                self.server_cache = Some(crate::utils::gluetun::ServerCache {
                    metadata: cache.metadata,
                    servers: filtered_servers,
                });
                info!("Loaded {} servers", count);
                if !silent {
                    self.info_message = Some(format!("Loaded {} servers", count));
                }
            }
            Err(e) => {
                error!("Failed to refresh servers: {}", e);
                self.error_message = Some(format!("Failed to refresh: {}", e));
            }
        }

        Ok(())
    }

    /// Check if this is first launch (no providers configured)
    pub fn is_first_launch(&self) -> bool {
        !self.config.has_configured_providers()
    }

    /// Add a configured provider and start async server refresh
    pub fn add_configured_provider(&mut self, provider: &str) -> Result<()> {
        self.config.add_provider(provider);
        self.config.save()?;
        info!("Added provider: {}", provider);

        // Start async refresh for the newly added provider
        self.start_refresh()?;

        Ok(())
    }

    /// Get filtered server list
    pub fn get_servers(&self) -> Vec<Server> {
        let cache = match &self.server_cache {
            Some(c) => c,
            None => return Vec::new(),
        };

        // Get all servers from configured providers (already filtered in cache)
        let mut servers: Vec<Server> = cache.servers.clone();

        // Always include custom configs (they have their own credentials in keyring)
        let custom_provider = CustomProvider::new();
        let custom_servers = custom_provider.list_servers(cache);
        for server in custom_servers {
            // Avoid duplicates
            if !servers.iter().any(|s| s.id == server.id) {
                servers.push(server);
            }
        }

        // Apply search filter
        if !self.search_filter.is_empty() {
            let filter = self.search_filter.to_lowercase();
            servers.retain(|s| {
                s.name.to_lowercase().contains(&filter)
                    || s.country.to_lowercase().contains(&filter)
                    || s.city.to_lowercase().contains(&filter)
            });
        }

        // Sort: favorites first, then by country
        servers.sort_by(|a, b| {
            let a_fav = self.config.is_favorite(&a.id);
            let b_fav = self.config.is_favorite(&b.id);

            match (a_fav, b_fav) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.country.cmp(&b.country).then(a.name.cmp(&b.name)),
            }
        });

        servers
    }

    /// Get tree items (flattened list with headers and servers)
    pub fn get_tree_items(&self) -> Vec<TreeListItem> {
        let servers = self.get_servers();
        if servers.is_empty() {
            return Vec::new();
        }

        // Group servers by provider, preserving insertion order
        let mut groups: IndexMap<String, Vec<Server>> = IndexMap::new();
        for server in servers {
            groups
                .entry(server.provider.clone())
                .or_default()
                .push(server);
        }

        // Build flattened list with headers
        let mut items = Vec::new();
        for (provider, provider_servers) in &groups {
            let expanded = self.tree_state.is_expanded(provider);
            let display_name = provider_servers
                .first()
                .map(|s| s.provider_display_name().to_string())
                .unwrap_or_else(|| provider.clone());

            // Add header
            items.push(TreeListItem::ProviderHeader {
                name: provider.clone(),
                display_name,
                server_count: provider_servers.len(),
                expanded,
            });

            // Add servers if expanded
            if expanded {
                for server in provider_servers {
                    items.push(TreeListItem::Server(server.clone()));
                }
            }
        }

        items
    }

    /// Get currently selected server (None if header is selected)
    pub fn selected_server(&self) -> Option<Server> {
        let items = self.get_tree_items();
        match items.get(self.tree_state.selected_index)? {
            TreeListItem::Server(server) => Some(server.clone()),
            TreeListItem::ProviderHeader { .. } => None,
        }
    }

    /// Get currently selected item
    pub fn selected_item(&self) -> Option<TreeListItem> {
        let items = self.get_tree_items();
        items.get(self.tree_state.selected_index).cloned()
    }

    /// Import a WireGuard config file
    pub async fn import_config(&mut self, path: &Path) -> Result<()> {
        info!("Importing config from {:?}", path);

        // Read and parse config
        let content = std::fs::read_to_string(path)?;
        let wg_config = WgConfig::parse(&content);

        // Detect provider
        let provider_type = detect_provider(&wg_config, self.config.provider_hint.as_deref());
        info!("Detected provider: {:?}", provider_type);

        // Get provider implementation
        let provider = get_provider(provider_type.clone());

        // Import config and extract credentials
        let credentials = provider.import_config(path)?;

        // Store in keyring
        self.credentials
            .store(&credentials.provider_name, &credentials)?;

        self.active_provider = Some(provider);
        self.provider_credentials = Some(credentials);

        // Only refresh servers from gluetun for non-custom providers
        // Custom configs are loaded dynamically from the config directory
        if provider_type != ProviderType::Custom {
            self.refresh_servers(true, true).await?; // silent, import message follows
        }

        self.info_message = Some("Config imported successfully!".to_string());
        Ok(())
    }

    /// Connect to a server
    /// If already connected, performs a hot-swap (disconnect + reconnect)
    pub async fn connect(&mut self, server: &Server) -> Result<()> {
        // If already connected, disconnect first (hot-swap)
        if self.connection.is_connected() {
            info!("Hot-swap: disconnecting from current server to connect to {}", server.name);
            // Perform a partial disconnect that keeps killswitch enabled
            self.disconnect_for_reconnect().await?;
        }

        // For custom servers, load credentials from keyring using server name
        let (credentials, provider): (ProviderCredentials, Box<dyn VpnProvider>) = if server.is_custom {
            let provider_name = format!("custom/{}", server.name);
            let creds = self.credentials.retrieve(&provider_name).map_err(|e| {
                VpnError::ProviderError(format!("Failed to load credentials for '{}': {}", server.name, e))
            })?;
            (creds, Box::new(CustomProvider::new()))
        } else {
            let creds = self.provider_credentials.as_ref().ok_or_else(|| {
                VpnError::ProviderError("No provider credentials configured".to_string())
            })?.clone();
            let prov = self.active_provider.as_ref().ok_or_else(|| {
                VpnError::ProviderError("No provider configured".to_string())
            })?;
            // Clone the provider type to avoid borrow issues
            (creds, get_provider(ProviderType::ProtonVPN))
        };

        // Start connecting
        self.connection.start_connecting(server.clone())?;

        // Step 1: Cache original public IP
        info!("Caching original public IP...");
        match self.network_stats.get_public_ip().await {
            Ok(ip) => {
                self.connection.set_original_ip(ip.clone());
                debug!("Original IP: {}", ip);
            }
            Err(e) => {
                warn!("Failed to get original IP: {}", e);
            }
        }

        // Step 2: Generate config
        let config_content = provider.generate_wg_config(&credentials, server);

        // Step 3: Find available interface
        let interface = match WgManager::find_available_interface() {
            Ok(iface) => iface,
            Err(e) => {
                self.connection.set_error(e.to_string())?;
                return Err(e);
            }
        };
        self.wg.set_interface(&interface);
        self.connection.set_interface(&interface);

        // Step 4: Enable killswitch BEFORE connecting (if enabled)
        if self.config.killswitch_enabled {
            info!("Enabling killswitch before connection...");
            let killswitch = Killswitch::new(
                &interface,
                &server.ip,
                self.config.killswitch_allow_lan,
                self.config.killswitch_lan_ranges.clone(),
            );

            if let Err(e) = killswitch.enable().await {
                self.connection
                    .set_error(format!("Killswitch failed: {}", e))?;
                return Err(e);
            }

            // Verify killswitch is active
            if let Err(e) = killswitch.verify().await {
                self.connection
                    .set_error(format!("Killswitch verification failed: {}", e))?;
                // Cleanup
                let _ = killswitch.disable().await;
                return Err(e);
            }
        }

        // Step 5: Disable IPv6 if enabled
        if self.config.ipv6_disabled {
            if let Ok(ipv6) = Ipv6Protection::new() {
                if let Err(e) = ipv6.disable().await {
                    warn!("Failed to disable IPv6 (non-fatal): {}", e);
                }
            }
        }

        // Step 6: Connect via wg-quick
        info!("Connecting via wg-quick...");
        match self.wg.connect(&config_content).await {
            Ok(_) => {}
            Err(e) => {
                error!("wg-quick failed: {}", e);
                // Cleanup
                self.cleanup_on_failure().await;
                self.connection.set_error(e.to_string())?;
                return Err(e);
            }
        }

        // Step 7: Verify IP changed
        info!("Verifying IP change...");
        self.network_stats.invalidate_ip_cache().await;

        let mut ip_verified = false;
        for attempt in 1..=IP_VERIFY_RETRIES {
            tokio::time::sleep(std::time::Duration::from_millis(IP_VERIFY_DELAY_MS)).await;

            match self.network_stats.get_public_ip().await {
                Ok(new_ip) => {
                    self.current_public_ip = Some(new_ip.clone());
                    if let Some(ref original) = self.connection.original_ip() {
                        if new_ip != *original {
                            info!("IP changed from {} to {}", original, new_ip);
                            ip_verified = true;
                            break;
                        }
                    }
                    debug!("Attempt {}: IP is {}", attempt, new_ip);
                }
                Err(e) => {
                    warn!("Attempt {}: Failed to get IP: {}", attempt, e);
                }
            }
        }

        if !ip_verified {
            // Check if interface is up as fallback
            if !crate::system::network::check_interface_up(&interface).await {
                self.cleanup_on_failure().await;
                self.connection
                    .set_error("VPN interface is not up".to_string())?;
                return Err(VpnError::ConnectionError("VPN interface is not up".into()));
            }
            warn!("Could not verify IP change, but interface is up");
        }

        // Success!
        self.connection.set_connected()?;

        // Update config
        self.config.last_server = Some(server.id.clone());
        self.config.was_connected_on_exit = true;
        self.config.save()?;

        // Send notification
        self.send_notification(
            "VPN Connected",
            &format!("Connected to {}", server.display_name()),
            false,
        );

        self.info_message = Some(format!("Connected to {}", server.name));
        Ok(())
    }

    /// Internal disconnect for reconnection (keeps killswitch if enabled)
    async fn disconnect_for_reconnect(&mut self) -> Result<()> {
        self.connection.start_disconnecting()?;

        let interface = self.connection.interface().to_string();

        // Step 1: Disconnect via wg-quick
        info!("Disconnecting current VPN for reconnect...");
        self.wg.set_interface(&interface);
        if let Err(e) = self.wg.disconnect().await {
            warn!("wg-quick down failed during reconnect: {}", e);
            // Continue anyway
        }

        // Note: We do NOT restore IPv6 or disable killswitch here
        // The new connection will handle those

        // Clear connection state but don't persist as disconnected
        self.connection.set_disconnected()?;
        self.current_public_ip = None;

        info!("Ready for reconnection");
        Ok(())
    }

    /// Disconnect from VPN
    pub async fn disconnect(&mut self) -> Result<()> {
        if !self.connection.is_connected() {
            return Err(VpnError::NotConnected);
        }

        self.connection.start_disconnecting()?;

        let interface = self.connection.interface().to_string();

        // Step 1: Disconnect via wg-quick
        info!("Disconnecting via wg-quick...");
        self.wg.set_interface(&interface);
        if let Err(e) = self.wg.disconnect().await {
            warn!("wg-quick down failed: {}", e);
            // Continue with cleanup anyway
        }

        // Step 2: Restore IPv6
        if self.config.ipv6_disabled {
            if let Ok(ipv6) = Ipv6Protection::new() {
                if let Err(e) = ipv6.restore().await {
                    warn!("Failed to restore IPv6: {}", e);
                }
            }
        }

        // Step 3: Disable killswitch
        if self.config.killswitch_enabled {
            let killswitch = Killswitch::new(&interface, "", false, vec![]);
            if let Err(e) = killswitch.disable().await {
                warn!("Failed to disable killswitch: {}", e);
            }
        }

        // Update state
        self.connection.set_disconnected()?;
        self.current_public_ip = None;
        self.network_stats.invalidate_ip_cache().await;

        // Update config
        self.config.was_connected_on_exit = false;
        self.config.save()?;

        // Send notification
        self.send_notification("VPN Disconnected", "You are now disconnected", false);

        self.info_message = Some("Disconnected".to_string());
        Ok(())
    }

    /// Cleanup after connection failure
    async fn cleanup_on_failure(&mut self) {
        let interface = self.connection.interface().to_string();

        // Restore IPv6
        if self.config.ipv6_disabled {
            if let Ok(ipv6) = Ipv6Protection::new() {
                let _ = ipv6.restore().await;
            }
        }

        // Disable killswitch
        if self.config.killswitch_enabled {
            let killswitch = Killswitch::new(&interface, "", false, vec![]);
            let _ = killswitch.disable().await;
        }
    }

    /// Toggle favorite status for selected server
    pub fn toggle_favorite(&mut self) {
        if let Some(server) = self.selected_server() {
            let server_id = server.id.clone();
            self.config.toggle_favorite(&server_id);
            let _ = self.config.save();
        }
    }

    /// Toggle killswitch
    pub fn toggle_killswitch(&mut self) {
        self.config.killswitch_enabled = !self.config.killswitch_enabled;
        let _ = self.config.save();
        self.info_message = Some(format!(
            "Killswitch {}",
            if self.config.killswitch_enabled {
                "enabled"
            } else {
                "disabled"
            }
        ));
    }

    /// Send system notification
    pub fn send_notification(&self, title: &str, body: &str, critical: bool) {
        if !self.config.notifications_enabled {
            return;
        }

        let urgency = if critical {
            notify_rust::Urgency::Critical
        } else {
            notify_rust::Urgency::Normal
        };

        let _ = notify_rust::Notification::new()
            .summary(title)
            .body(body)
            .urgency(urgency)
            .timeout(5000)
            .show();
    }

    /// Graceful shutdown - disconnects VPN (legacy behavior when keep_vpn_on_exit is false)
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down...");

        if self.connection.is_connected() {
            self.disconnect().await?;
        }

        self.config.save()?;
        Ok(())
    }

    /// Graceful shutdown that preserves VPN connection
    /// Called when keep_vpn_on_exit is true (default)
    /// Persists connection state without tearing down the WireGuard interface
    pub async fn shutdown_preserving_vpn(&mut self) -> Result<()> {
        info!("Shutting down (preserving VPN connection)...");

        if self.connection.is_connected() {
            // Use already known public IP from the app state
            info!("Persisting public IP: {:?}", self.current_public_ip);
            self.connection.set_current_public_ip(self.current_public_ip.clone());

            // Persist state so we can restore on next startup
            self.config.was_connected_on_exit = true;
            self.connection.persist_state()?;
            info!(
                "VPN connection preserved - interface {} will remain active",
                self.connection.interface()
            );
        } else {
            self.config.was_connected_on_exit = false;
        }

        self.config.save()?;
        Ok(())
    }

    /// Move selection up
    pub fn select_previous(&mut self) {
        if self.tree_state.selected_index > 0 {
            self.tree_state.selected_index -= 1;
        }
    }

    /// Move selection down
    pub fn select_next(&mut self) {
        let max = self.get_tree_items().len().saturating_sub(1);
        if self.tree_state.selected_index < max {
            self.tree_state.selected_index += 1;
        }
    }

    /// Toggle expand/collapse for current item (if it's a header)
    pub fn toggle_current_expand(&mut self) {
        if let Some(TreeListItem::ProviderHeader { name, .. }) = self.selected_item() {
            self.tree_state.toggle_expand(&name);
            // Persist to config
            self.config.provider_expanded = self.tree_state.expanded.clone();
            let _ = self.config.save();
        }
    }

    /// Expand current provider (if header selected)
    pub fn expand_current(&mut self) {
        if let Some(TreeListItem::ProviderHeader { name, expanded, .. }) = self.selected_item() {
            if !expanded {
                self.tree_state.expand(&name);
                self.config.provider_expanded = self.tree_state.expanded.clone();
                let _ = self.config.save();
            }
        }
    }

    /// Collapse current provider (if header selected or server under provider)
    pub fn collapse_current(&mut self) {
        match self.selected_item() {
            Some(TreeListItem::ProviderHeader { name, expanded, .. }) => {
                if expanded {
                    self.tree_state.collapse(&name);
                    self.config.provider_expanded = self.tree_state.expanded.clone();
                    let _ = self.config.save();
                }
            }
            Some(TreeListItem::Server(server)) => {
                // Collapse the parent provider and move selection to header
                let provider = server.provider.clone();
                self.tree_state.collapse(&provider);
                self.config.provider_expanded = self.tree_state.expanded.clone();
                let _ = self.config.save();
                // Find the header index and select it
                let items = self.get_tree_items();
                for (i, item) in items.iter().enumerate() {
                    if let TreeListItem::ProviderHeader { name, .. } = item {
                        if name == &provider {
                            self.tree_state.selected_index = i;
                            break;
                        }
                    }
                }
            }
            None => {}
        }
    }

    /// Start search mode
    pub fn start_search(&mut self) {
        self.search_mode = true;
        self.search_filter.clear();
    }

    /// End search mode
    pub fn end_search(&mut self) {
        self.search_mode = false;
    }

    /// Add character to search
    pub fn search_push(&mut self, c: char) {
        self.search_filter.push(c);
        self.tree_state.selected_index = 0;
    }

    /// Remove character from search
    pub fn search_pop(&mut self) {
        self.search_filter.pop();
        self.tree_state.selected_index = 0;
    }

    /// Clear messages
    pub fn clear_messages(&mut self) {
        self.error_message = None;
        self.info_message = None;
    }

    /// Has provider configured
    pub fn has_provider(&self) -> bool {
        self.active_provider.is_some() && self.provider_credentials.is_some()
    }

    /// Advance spinner animation frame
    pub fn tick_spinner(&mut self) {
        self.spinner_frame = (self.spinner_frame + 1) % SPINNER_FRAMES.len();
    }

    /// Get current spinner character
    pub fn spinner_char(&self) -> &'static str {
        SPINNER_FRAMES[self.spinner_frame]
    }

    /// Check if app is busy (connecting/disconnecting, refreshing, or has pending operation)
    pub fn is_busy(&self) -> bool {
        self.pending_operation.is_some()
            || self.is_refreshing
            || matches!(
                self.connection.state(),
                ConnectionState::Connecting | ConnectionState::Disconnecting
            )
    }

    /// Check for pending operation results (non-blocking)
    pub async fn check_pending_operation(&mut self) {
        if let Some(ref mut rx) = self.pending_operation {
            // Check for operation timeout
            if let Some(started) = self.operation_started_at {
                if started.elapsed().as_secs() > OPERATION_TIMEOUT_SECS {
                    error!(
                        "Operation timed out after {}s - forcing cleanup",
                        OPERATION_TIMEOUT_SECS
                    );
                    self.error_message =
                        Some(format!("Operation timed out after {}s", OPERATION_TIMEOUT_SECS));
                    self.pending_operation = None;
                    self.operation_started_at = None;

                    // Force cleanup
                    let _ = self.connection.set_disconnected();
                    self.spawn_cleanup_task();
                    return;
                }
            }

            // Try to receive without blocking
            match rx.try_recv() {
                Ok(result) => {
                    self.handle_operation_result(result);
                    self.pending_operation = None;
                    self.operation_started_at = None;
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    // Still waiting, do nothing
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    // Channel closed without result (task panicked?)
                    error!("Background task panicked or was cancelled - cleaning up");
                    self.error_message =
                        Some("Operation failed unexpectedly - cleaning up".to_string());
                    self.pending_operation = None;
                    self.operation_started_at = None;

                    // Reset connection state and cleanup
                    let _ = self.connection.set_disconnected();
                    self.spawn_cleanup_task();
                }
            }
        }
    }

    /// Spawn a cleanup task to restore system state after failure
    fn spawn_cleanup_task(&self) {
        let interface = self.connection.interface().to_string();
        let killswitch_enabled = self.config.killswitch_enabled;
        let ipv6_disabled = self.config.ipv6_disabled;

        tokio::spawn(async move {
            info!("Running cleanup after operation failure...");

            // Try to disconnect interface if it exists
            if WgManager::interface_exists(&interface).unwrap_or(false) {
                let mut wg = WgManager::new(&interface);
                if let Err(e) = wg.disconnect().await {
                    error!("Cleanup: Failed to disconnect interface: {}", e);
                }
            }

            // Disable killswitch
            if killswitch_enabled {
                let ks = Killswitch::new(&interface, "", false, vec![]);
                if let Err(e) = ks.disable().await {
                    error!("Cleanup: Failed to disable killswitch: {}", e);
                }
            }

            // Restore IPv6
            if ipv6_disabled {
                if let Ok(ipv6) = Ipv6Protection::new() {
                    if let Err(e) = ipv6.restore().await {
                        error!("Cleanup: Failed to restore IPv6: {}", e);
                    }
                }
            }

            info!("Cleanup completed");
        });
    }

    /// Start refresh operation in background (non-blocking)
    pub fn start_refresh(&mut self) -> Result<()> {
        if self.is_refreshing {
            return Err(VpnError::ConnectionError("Refresh already in progress".into()));
        }

        self.is_refreshing = true;


        let (tx, rx) = oneshot::channel();
        self.pending_refresh = Some(rx);

        tokio::spawn(async move {
            info!("Background refresh started");
            let result = match get_servers(true).await {
                Ok(cache) => {
                    let count = cache.servers.len();
                    info!("Background refresh completed: {} servers", count);
                    Ok(cache)
                }
                Err(e) => {
                    error!("Background refresh failed: {}", e);
                    Err(e.to_string())
                }
            };
            let _ = tx.send(result);
        });

        Ok(())
    }

    /// Check for pending refresh results (non-blocking)
    pub fn check_pending_refresh(&mut self) {
        if let Some(ref mut rx) = self.pending_refresh {
            match rx.try_recv() {
                Ok(result) => {
                    self.is_refreshing = false;
                    self.pending_refresh = None;
                    match result {
                        Ok(cache) => {
                            // Filter servers to only configured providers
                            let filtered_servers: Vec<Server> = cache.servers
                                .into_iter()
                                .filter(|s| self.config.configured_providers.contains(&s.provider))
                                .collect();

                            let count = filtered_servers.len();
                            self.server_cache = Some(crate::utils::gluetun::ServerCache {
                                metadata: cache.metadata,
                                servers: filtered_servers,
                            });
                            self.info_message = Some(format!("Loaded {} servers", count));
                        }
                        Err(e) => {
                            self.error_message = Some(format!("Refresh failed: {}", e));
                        }
                    }
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    // Still waiting
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.is_refreshing = false;
                    self.pending_refresh = None;
                    self.error_message = Some("Refresh failed unexpectedly".to_string());
                }
            }
        }
    }

    /// Handle operation result
    fn handle_operation_result(&mut self, result: OperationResult) {
        match result {
            OperationResult::ConnectSuccess(server_name) => {
                self.finalize_connect(true);
                self.info_message = Some(format!("Connected to {}", server_name));
            }
            OperationResult::ConnectError(e) => {
                self.finalize_connect(false);
                self.error_message = Some(format!("Connection failed: {}", e));
            }
            OperationResult::DisconnectSuccess => {
                self.finalize_disconnect();
                self.info_message = Some("Disconnected".to_string());
            }
            OperationResult::DisconnectError(e) => {
                // Still finalize even on error
                self.finalize_disconnect();
                self.error_message = Some(format!("Disconnect failed: {}", e));
            }
            OperationResult::ImportSuccess => {
                self.info_message = Some("Config imported successfully".to_string());
            }
            OperationResult::ImportError(e) => {
                self.error_message = Some(format!("Import failed: {}", e));
            }
            OperationResult::RefreshSuccess(count) => {
                self.info_message = Some(format!("Loaded {} servers", count));
            }
            OperationResult::RefreshError(e) => {
                self.error_message = Some(format!("Refresh failed: {}", e));
            }
        }
    }

    /// Start connect operation in background
    pub fn start_connect(&mut self, server: Server) -> Result<()> {
        if self.pending_operation.is_some() {
            return Err(VpnError::ConnectionError("Operation already in progress".into()));
        }

        // For custom servers, load credentials from keyring using server name
        let (credentials, config_content) = if server.is_custom {
            let provider_name = format!("custom/{}", server.name);
            let creds = self.credentials.retrieve(&provider_name).map_err(|e| {
                VpnError::ProviderError(format!("Failed to load credentials for '{}': {}", server.name, e))
            })?;
            let provider = CustomProvider::new();
            let config = provider.generate_wg_config(&creds, &server);
            (creds, config)
        } else {
            let creds = self.provider_credentials.clone().ok_or_else(|| {
                VpnError::ProviderError("No provider credentials configured".to_string())
            })?;
            let config = self.active_provider.as_ref()
                .map(|p| p.generate_wg_config(&creds, &server))
                .ok_or_else(|| VpnError::ProviderError("No provider configured".to_string()))?;
            (creds, config)
        };

        // Check if we need to do a hot-swap (disconnect first)
        let current_interface = if self.connection.is_connected() {
            Some(self.connection.interface().to_string())
        } else {
            None
        };

        // Force state to connecting (even if was connected - for hot-swap)
        let _ = self.connection.set_disconnected(); // Reset state first
        self.connection.start_connecting(server.clone())?;

        // Clear public IP so UI shows "Checking..." during connection
        self.current_public_ip = None;

        // Find available interface (or reuse current for hot-swap)
        let interface = if let Some(ref curr_iface) = current_interface {
            // For hot-swap, REUSE the same interface after disconnecting it
            // This avoids wg0 -> wg1 -> wg2 accumulation
            curr_iface.clone()
        } else {
            WgManager::find_available_interface()?
        };
        self.wg.set_interface(&interface);
        self.connection.set_interface(&interface);

        // Create channel for result
        let (tx, rx) = oneshot::channel();
        self.pending_operation = Some(rx);
        self.operation_started_at = Some(Instant::now());

        // Clone what we need for the spawned task
        let server_name = server.name.clone();
        let server_ip = server.ip.clone();
        let is_split_tunnel = server.is_split_tunnel();

        // Disable killswitch for split-tunnel configs (they only route specific IPs)
        let killswitch_enabled = if is_split_tunnel {
            if self.config.killswitch_enabled {
                info!("Split-tunnel config detected, killswitch disabled for this connection");
                self.info_message = Some("Split-tunnel: killswitch disabled".to_string());
            }
            false
        } else {
            self.config.killswitch_enabled
        };

        // Store effective killswitch state for finalize_connect
        self.pending_killswitch_enabled = killswitch_enabled;

        let killswitch_allow_lan = self.config.killswitch_allow_lan;
        let killswitch_lan_ranges = self.config.killswitch_lan_ranges.clone();
        let ipv6_disabled = self.config.ipv6_disabled;
        let interface_clone = interface.clone();
        let old_interface = current_interface;

        // Spawn the connect operation
        tokio::spawn(async move {
            let result = Self::do_connect(
                config_content,
                interface_clone,
                server_ip,
                server_name.clone(),
                killswitch_enabled,
                killswitch_allow_lan,
                killswitch_lan_ranges,
                ipv6_disabled,
                old_interface,
            ).await;

            let op_result = match result {
                Ok(_) => OperationResult::ConnectSuccess(server_name),
                Err(e) => OperationResult::ConnectError(e.to_string()),
            };

            let _ = tx.send(op_result);
        });

        Ok(())
    }

    /// Actual connect logic (runs in background task)
    async fn do_connect(
        config_content: String,
        interface: String,
        server_ip: String,
        server_name: String,
        killswitch_enabled: bool,
        killswitch_allow_lan: bool,
        killswitch_lan_ranges: Vec<String>,
        ipv6_disabled: bool,
        old_interface: Option<String>,
    ) -> Result<()> {
        // Step 0: Hot-swap - disconnect old interface if needed
        if let Some(ref old_iface) = old_interface {
            info!("Hot-swap: disconnecting old interface {}...", old_iface);
            let mut old_wg = WgManager::new(old_iface);
            if let Err(e) = old_wg.disconnect().await {
                warn!("Failed to disconnect old interface: {}", e);
            }

            // Wait for interface to be fully down (up to 3 seconds)
            let mut interface_down = false;
            for i in 0..30 {
                if !WgManager::interface_exists(old_iface).unwrap_or(false) {
                    interface_down = true;
                    info!("Old interface {} removed after {}ms", old_iface, i * 100);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }

            if !interface_down {
                // Force removal via ip link delete
                warn!("Interface {} still exists, forcing removal...", old_iface);
                let _ = tokio::process::Command::new("sudo")
                    .args(["ip", "link", "delete", old_iface])
                    .output()
                    .await;

                // Wait a bit more
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            // Note: We keep killswitch enabled during hot-swap for security
        }

        // Step 1: Enable/update killswitch BEFORE connecting (if enabled)
        let killswitch = if killswitch_enabled {
            info!("Enabling killswitch before connection...");
            let ks = Killswitch::new(
                &interface,
                &server_ip,
                killswitch_allow_lan,
                killswitch_lan_ranges,
            );

            ks.enable().await?;
            ks.verify().await?;
            Some(ks)
        } else {
            None
        };

        // Step 2: Disable IPv6 if enabled (may already be disabled from previous connection)
        if ipv6_disabled {
            if let Ok(ipv6) = Ipv6Protection::new() {
                if let Err(e) = ipv6.disable().await {
                    warn!("Failed to disable IPv6 (non-fatal): {}", e);
                }
            }
        }

        // Step 3: Connect via wg-quick
        info!("Connecting to {} via wg-quick...", server_name);
        let mut wg = WgManager::new(&interface);

        match wg.connect(&config_content).await {
            Ok(_) => {
                info!("VPN connected successfully to {}", server_name);
                Ok(())
            }
            Err(e) => {
                // CRITICAL: Rollback killswitch if connection failed
                error!("wg-quick failed, rolling back killswitch...");
                if let Some(ks) = killswitch {
                    if let Err(disable_err) = ks.disable().await {
                        error!(
                            "CRITICAL: Failed to disable killswitch after failed connection: {}",
                            disable_err
                        );
                    }
                }

                // Restore IPv6 if we disabled it
                if ipv6_disabled {
                    if let Ok(ipv6) = Ipv6Protection::new() {
                        if let Err(restore_err) = ipv6.restore().await {
                            error!("Failed to restore IPv6 after failed connection: {}", restore_err);
                        }
                    }
                }

                Err(e)
            }
        }
    }

    /// Finalize connection after background task completes
    pub fn finalize_connect(&mut self, success: bool) {
        if success {
            // Update killswitch_active based on effective value (accounts for split-tunnel)
            self.connection.set_killswitch_active(self.pending_killswitch_enabled);

            let _ = self.connection.set_connected();
            if let Some(server) = self.connection.current_server() {
                self.config.last_server = Some(server.id.clone());
            }
            self.config.was_connected_on_exit = true;
            let _ = self.config.save();

            // Request immediate IP refresh
            self.needs_ip_refresh = true;

            // Send notification
            if let Some(server) = self.connection.current_server() {
                self.send_notification(
                    "VPN Connected",
                    &format!("Connected to {}", server.display_name()),
                    false,
                );
            }
        } else {
            // Clear killswitch flag on failure
            self.connection.set_killswitch_active(false);
            let _ = self.connection.set_disconnected();
            // Cleanup on failure is handled by do_connect rollback
            // No additional cleanup needed here
        }
    }

    /// Start disconnect operation in background
    pub fn start_disconnect(&mut self) -> Result<()> {
        if self.pending_operation.is_some() {
            return Err(VpnError::ConnectionError("Operation already in progress".into()));
        }

        if !self.connection.is_connected() {
            return Err(VpnError::NotConnected);
        }

        self.connection.start_disconnecting()?;

        let (tx, rx) = oneshot::channel();
        self.pending_operation = Some(rx);
        self.operation_started_at = Some(Instant::now());

        let interface = self.connection.interface().to_string();
        let killswitch_enabled = self.config.killswitch_enabled;
        let ipv6_disabled = self.config.ipv6_disabled;

        tokio::spawn(async move {
            let result = Self::do_disconnect(interface, killswitch_enabled, ipv6_disabled).await;

            let op_result = match result {
                Ok(_) => OperationResult::DisconnectSuccess,
                Err(e) => OperationResult::DisconnectError(e.to_string()),
            };

            let _ = tx.send(op_result);
        });

        Ok(())
    }

    /// Actual disconnect logic (runs in background task)
    async fn do_disconnect(
        interface: String,
        killswitch_enabled: bool,
        ipv6_disabled: bool,
    ) -> Result<()> {
        // Step 1: Disconnect via wg-quick
        info!("Disconnecting via wg-quick...");
        let mut wg = WgManager::new(&interface);
        if let Err(e) = wg.disconnect().await {
            warn!("wg-quick down failed: {}", e);
        }

        // Step 2: Restore IPv6
        if ipv6_disabled {
            if let Ok(ipv6) = Ipv6Protection::new() {
                if let Err(e) = ipv6.restore().await {
                    warn!("Failed to restore IPv6: {}", e);
                }
            }
        }

        // Step 3: Disable killswitch
        if killswitch_enabled {
            let killswitch = Killswitch::new(&interface, "", false, vec![]);
            if let Err(e) = killswitch.disable().await {
                warn!("Failed to disable killswitch: {}", e);
            }
        }

        info!("VPN disconnected");
        Ok(())
    }

    /// Finalize disconnect after background task completes
    pub fn finalize_disconnect(&mut self) {
        // Clear killswitch flag when disconnecting
        self.connection.set_killswitch_active(false);
        let _ = self.connection.set_disconnected();
        self.current_public_ip = None;
        self.config.was_connected_on_exit = false;
        let _ = self.config.save();
        self.send_notification("VPN Disconnected", "You are now disconnected", false);
    }
}
