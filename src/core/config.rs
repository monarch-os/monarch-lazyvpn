//! Application configuration with versioning and migration support

use crate::core::error::{Result, VpnError};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Current config version - increment when adding breaking changes
const CONFIG_VERSION: u32 = 1;

/// Server list display mode
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ServerListMode {
    #[default]
    Provider,
    Country,
    Mixed,
}

/// Flag display style
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FlagStyle {
    /// Use emoji flags (🇺🇸, 🇫🇷) - requires terminal/font support
    #[default]
    Emoji,
    /// Use text codes ([US], [FR]) - works everywhere
    Code,
    /// No flags, just country name
    None,
}

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Config version for migration support
    #[serde(default = "default_version")]
    pub config_version: u32,

    /// Enable killswitch (block traffic if VPN down)
    #[serde(default = "default_true")]
    pub killswitch_enabled: bool,

    /// Allow LAN traffic when killswitch is enabled
    #[serde(default)]
    pub killswitch_allow_lan: bool,

    /// LAN ranges to allow when killswitch_allow_lan is true
    #[serde(default = "default_lan_ranges")]
    pub killswitch_lan_ranges: Vec<String>,

    /// Disable IPv6 to prevent leaks
    #[serde(default = "default_true")]
    pub ipv6_disabled: bool,

    /// Last connected server ID
    #[serde(default)]
    pub last_server: Option<String>,

    /// WireGuard interface name (default: wg0)
    #[serde(default = "default_interface")]
    pub interface_name: String,

    /// Enable system notifications
    #[serde(default = "default_true")]
    pub notifications_enabled: bool,

    /// Auto-reconnect on network change
    #[serde(default = "default_true")]
    pub auto_reconnect: bool,

    /// Prompt to reconnect on startup if was connected
    #[serde(default = "default_true")]
    pub reconnect_prompt: bool,

    /// Server list display mode
    #[serde(default)]
    pub server_list_mode: ServerListMode,

    /// Favorite server IDs
    #[serde(default)]
    pub favorites: Vec<String>,

    /// Provider hint for auto-detection override
    #[serde(default)]
    pub provider_hint: Option<String>,

    /// Was connected on last exit (for reconnect prompt)
    #[serde(default)]
    pub was_connected_on_exit: bool,

    /// Keep VPN connected when application exits (default: true)
    /// If false, VPN will disconnect on app exit (legacy behavior)
    #[serde(default = "default_true")]
    pub keep_vpn_on_exit: bool,

    /// Provider expansion state in tree view (provider_name -> expanded)
    #[serde(default)]
    pub provider_expanded: HashMap<String, bool>,

    /// List of configured providers (providers with valid credentials)
    #[serde(default)]
    pub configured_providers: Vec<String>,
}

fn default_version() -> u32 {
    CONFIG_VERSION
}

fn default_true() -> bool {
    true
}

fn default_interface() -> String {
    "wg0".to_string()
}

fn default_lan_ranges() -> Vec<String> {
    vec![
        "192.168.0.0/16".to_string(),
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
    ]
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            config_version: CONFIG_VERSION,
            killswitch_enabled: true,
            killswitch_allow_lan: false,
            killswitch_lan_ranges: default_lan_ranges(),
            ipv6_disabled: true,
            last_server: None,
            interface_name: default_interface(),
            notifications_enabled: true,
            auto_reconnect: true,
            reconnect_prompt: true,
            server_list_mode: ServerListMode::default(),
            favorites: Vec::new(),
            provider_hint: None,
            was_connected_on_exit: false,
            keep_vpn_on_exit: true,
            provider_expanded: HashMap::new(),
            configured_providers: Vec::new(),
        }
    }
}


impl AppConfig {
    /// Get the config directory path
    pub fn config_dir() -> Result<PathBuf> {
        ProjectDirs::from("com", "monarch", "monarch-lazyvpn")
            .map(|dirs| dirs.config_dir().to_path_buf())
            .ok_or_else(|| VpnError::ConfigError("Cannot determine config directory".into()))
    }

    /// Get the config file path
    pub fn config_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("config.toml"))
    }

    /// Get the cache directory path
    pub fn cache_dir() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("cache"))
    }

    /// Get the servers directory path (for custom configs)
    pub fn servers_dir() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("servers"))
    }

    /// Load config from file or create default
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;

        if path.exists() {
            let content = fs::read_to_string(&path)?;
            let mut config: AppConfig = toml::from_str(&content)?;
            config.migrate()?;
            Ok(config)
        } else {
            let config = AppConfig::default();
            config.save()?;
            Ok(config)
        }
    }

    /// Save config to file
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)?;
        fs::write(&path, content)?;
        Ok(())
    }

    /// Migrate config from older versions
    fn migrate(&mut self) -> Result<()> {
        if self.config_version < CONFIG_VERSION {
            // Future migrations go here
            // Example:
            // if self.config_version < 2 {
            //     // Migrate from v1 to v2
            //     self.new_field = default_value();
            // }

            self.config_version = CONFIG_VERSION;
            self.save()?;
        }
        Ok(())
    }

    /// Toggle a server in favorites
    pub fn toggle_favorite(&mut self, server_id: &str) {
        if let Some(pos) = self.favorites.iter().position(|id| id == server_id) {
            self.favorites.remove(pos);
        } else {
            self.favorites.push(server_id.to_string());
        }
    }

    /// Check if a server is a favorite
    pub fn is_favorite(&self, server_id: &str) -> bool {
        self.favorites.contains(&server_id.to_string())
    }

    /// Cycle through server list modes
    pub fn cycle_server_list_mode(&mut self) {
        self.server_list_mode = match self.server_list_mode {
            ServerListMode::Provider => ServerListMode::Country,
            ServerListMode::Country => ServerListMode::Mixed,
            ServerListMode::Mixed => ServerListMode::Provider,
        };
    }

    /// Check if any providers are configured
    pub fn has_configured_providers(&self) -> bool {
        !self.configured_providers.is_empty()
    }

    /// Add a provider to the configured list
    pub fn add_provider(&mut self, provider: &str) {
        if !self.configured_providers.contains(&provider.to_string()) {
            self.configured_providers.push(provider.to_string());
        }
    }

    /// Remove a provider from the configured list
    pub fn remove_provider(&mut self, provider: &str) {
        self.configured_providers.retain(|p| p != provider);
    }

    /// Check if a provider is configured
    pub fn is_provider_configured(&self, provider: &str) -> bool {
        self.configured_providers.contains(&provider.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.config_version, CONFIG_VERSION);
        assert!(config.killswitch_enabled);
        assert!(!config.killswitch_allow_lan);
        assert!(config.ipv6_disabled);
        assert_eq!(config.interface_name, "wg0");
        assert!(config.keep_vpn_on_exit); // default true - VPN stays connected on exit
    }

    #[test]
    fn test_keep_vpn_on_exit_default() {
        // Test that keep_vpn_on_exit defaults to true when missing from config
        let toml_without_field = r#"
            config_version = 1
            killswitch_enabled = true
            interface_name = "wg0"
        "#;
        let config: AppConfig = toml::from_str(toml_without_field).unwrap();
        assert!(config.keep_vpn_on_exit);
    }

    #[test]
    fn test_keep_vpn_on_exit_explicit_false() {
        // Test that keep_vpn_on_exit can be explicitly set to false
        let toml_with_false = r#"
            config_version = 1
            keep_vpn_on_exit = false
        "#;
        let config: AppConfig = toml::from_str(toml_with_false).unwrap();
        assert!(!config.keep_vpn_on_exit);
    }

    #[test]
    fn test_toggle_favorite() {
        let mut config = AppConfig::default();
        assert!(!config.is_favorite("server1"));

        config.toggle_favorite("server1");
        assert!(config.is_favorite("server1"));

        config.toggle_favorite("server1");
        assert!(!config.is_favorite("server1"));
    }

    #[test]
    fn test_cycle_server_list_mode() {
        let mut config = AppConfig::default();
        assert_eq!(config.server_list_mode, ServerListMode::Provider);

        config.cycle_server_list_mode();
        assert_eq!(config.server_list_mode, ServerListMode::Country);

        config.cycle_server_list_mode();
        assert_eq!(config.server_list_mode, ServerListMode::Mixed);

        config.cycle_server_list_mode();
        assert_eq!(config.server_list_mode, ServerListMode::Provider);
    }
}
