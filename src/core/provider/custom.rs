//! Custom config provider implementation
//!
//! Handles manually imported WireGuard .conf files.
//! Extracts private key to keyring, stores remaining config without secrets.

use crate::core::config::AppConfig;
use crate::core::error::{Result, VpnError};
use crate::core::provider::{VpnProvider, WgConfig};
use crate::core::server::{validate_wg_key, Server};
use crate::system::keyring::ProviderCredentials;
use crate::utils::gluetun::ServerCache;
use std::fs;
use std::path::Path;

/// Custom provider for manually imported configs
pub struct CustomProvider;

impl CustomProvider {
    pub fn new() -> Self {
        Self
    }

    /// Get stored configs directory
    fn servers_dir() -> Result<std::path::PathBuf> {
        AppConfig::servers_dir()
    }

    /// Save config without private key
    fn save_sanitized_config(name: &str, config: &WgConfig) -> Result<()> {
        let servers_dir = Self::servers_dir()?;
        fs::create_dir_all(&servers_dir)?;

        let config_path = servers_dir.join(format!("{}.conf", name));

        // Build sanitized config (without PrivateKey)
        let mut content = String::new();
        content.push_str("[Interface]\n");
        // Don't include PrivateKey - it's in keyring
        content.push_str("# PrivateKey stored in keyring\n");
        if let Some(ref addr) = config.address {
            content.push_str(&format!("Address = {}\n", addr));
        }
        if let Some(ref dns) = config.dns {
            content.push_str(&format!("DNS = {}\n", dns));
        }
        content.push_str("\n[Peer]\n");
        if let Some(ref pubkey) = config.public_key {
            content.push_str(&format!("PublicKey = {}\n", pubkey));
        }
        if let Some(ref endpoint) = config.endpoint {
            content.push_str(&format!("Endpoint = {}\n", endpoint));
        }
        if let Some(ref allowed) = config.allowed_ips {
            content.push_str(&format!("AllowedIPs = {}\n", allowed));
        }
        if let Some(keepalive) = config.persistent_keepalive {
            content.push_str(&format!("PersistentKeepalive = {}\n", keepalive));
        }

        fs::write(&config_path, content)?;
        Ok(())
    }

    /// Load sanitized config
    pub fn load_sanitized_config(name: &str) -> Result<WgConfig> {
        let servers_dir = Self::servers_dir()?;
        let config_path = servers_dir.join(format!("{}.conf", name));

        if !config_path.exists() {
            return Err(VpnError::ConfigError(format!(
                "Custom config '{}' not found",
                name
            )));
        }

        let content = fs::read_to_string(&config_path)?;
        Ok(WgConfig::parse(&content))
    }

    /// List all custom configs
    pub fn list_custom_configs() -> Result<Vec<String>> {
        let servers_dir = Self::servers_dir()?;

        if !servers_dir.exists() {
            return Ok(Vec::new());
        }

        let mut configs = Vec::new();
        for entry in fs::read_dir(&servers_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == "conf").unwrap_or(false) {
                if let Some(name) = path.file_stem().and_then(|n| n.to_str()) {
                    configs.push(name.to_string());
                }
            }
        }

        Ok(configs)
    }

    /// Create Server from custom config
    pub fn server_from_config(name: &str, config: &WgConfig) -> Result<Server> {
        let pubkey = config
            .public_key
            .clone()
            .ok_or_else(|| VpnError::ConfigParseError("Missing PublicKey in config".to_string()))?;

        let ip = config
            .endpoint
            .as_ref()
            .and_then(|e| e.split(':').next())
            .ok_or_else(|| VpnError::ConfigParseError("Missing Endpoint in config".to_string()))?
            .to_string();

        Ok(Server::from_custom(name.to_string(), ip, pubkey, config.allowed_ips.clone()))
    }
}

impl Default for CustomProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl VpnProvider for CustomProvider {
    fn name(&self) -> &str {
        "custom"
    }

    fn display_name(&self) -> &str {
        "Custom Config"
    }

    fn dns(&self) -> &str {
        // Custom configs use their own DNS from the config
        ""
    }

    fn port(&self) -> u16 {
        // Custom configs use port from endpoint
        51820
    }

    fn list_servers(&self, _cache: &ServerCache) -> Vec<Server> {
        // List servers from custom configs, not from gluetun cache
        match Self::list_custom_configs() {
            Ok(configs) => configs
                .iter()
                .filter_map(|name| {
                    Self::load_sanitized_config(name)
                        .ok()
                        .and_then(|config| Self::server_from_config(name, &config).ok())
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn import_config(&self, path: &Path) -> Result<ProviderCredentials> {
        let content = fs::read_to_string(path).map_err(|e| {
            VpnError::ConfigParseError(format!("Failed to read config file: {}", e))
        })?;

        let config = WgConfig::parse(&content);

        // Validate required fields
        let private_key = config.private_key.clone().ok_or_else(|| {
            VpnError::ConfigParseError("Missing PrivateKey in config".to_string())
        })?;

        let address = config
            .address
            .clone()
            .ok_or_else(|| VpnError::ConfigParseError("Missing Address in config".to_string()))?;

        // Validate private key format
        if !validate_wg_key(&private_key) {
            return Err(VpnError::ConfigParseError(
                "Invalid PrivateKey format (must be 44 chars, base64, ending with =)".to_string(),
            ));
        }

        // Extract config name from filename
        let name = path
            .file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or("custom")
            .to_string();

        // Save sanitized config (without private key)
        Self::save_sanitized_config(&name, &config)?;

        Ok(ProviderCredentials {
            private_key,
            address,
            provider_name: format!("custom/{}", name),
        })
    }

    fn generate_wg_config(&self, creds: &ProviderCredentials, server: &Server) -> String {
        // For custom configs, reconstruct from sanitized config + keyring key
        let config_name = creds
            .provider_name
            .strip_prefix("custom/")
            .unwrap_or(&server.name);

        if let Ok(config) = Self::load_sanitized_config(config_name) {
            let dns = config.dns.as_deref().unwrap_or("1.1.1.1");
            let allowed_ips = config.allowed_ips.as_deref().unwrap_or("0.0.0.0/0, ::/0");
            let keepalive = config.persistent_keepalive.unwrap_or(25);

            // Parse port from endpoint
            let port = config
                .endpoint
                .as_ref()
                .and_then(|e| e.rsplit(':').next())
                .and_then(|p| p.parse().ok())
                .unwrap_or(51820);

            // Filter out IPv6 from AllowedIPs to avoid issues on systems with IPv6 disabled
            let ipv4_allowed = allowed_ips
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.contains(':'))
                .collect::<Vec<_>>()
                .join(", ");
            let final_allowed = if ipv4_allowed.is_empty() {
                "0.0.0.0/0".to_string()
            } else {
                ipv4_allowed
            };

            format!(
                "[Interface]\n\
                 PrivateKey = {}\n\
                 Address = {}\n\
                 DNS = {}\n\
                 \n\
                 [Peer]\n\
                 PublicKey = {}\n\
                 Endpoint = {}:{}\n\
                 AllowedIPs = {}\n\
                 PersistentKeepalive = {}\n",
                creds.private_key,
                creds.address,
                dns,
                server.pubkey,
                server.ip,
                port,
                final_allowed,
                keepalive
            )
        } else {
            // Fallback: basic config (IPv4 only)
            format!(
                "[Interface]\n\
                 PrivateKey = {}\n\
                 Address = {}\n\
                 DNS = 1.1.1.1\n\
                 \n\
                 [Peer]\n\
                 PublicKey = {}\n\
                 Endpoint = {}:51820\n\
                 AllowedIPs = 0.0.0.0/0\n\
                 PersistentKeepalive = 25\n",
                creds.private_key, creds.address, server.pubkey, server.ip
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_info() {
        let provider = CustomProvider::new();
        assert_eq!(provider.name(), "custom");
        assert_eq!(provider.display_name(), "Custom Config");
    }

    #[test]
    fn test_wg_config_parsing_and_validation() {
        // Test WgConfig parsing without calling import_config
        // (import_config writes to real config dir, polluting user data)
        let content = r#"[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = serverkey1234567890123456789012345678901=
Endpoint = 5.6.7.8:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"#;

        let config = WgConfig::parse(content);

        // Verify all fields are parsed correctly
        assert_eq!(
            config.private_key,
            Some("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=".to_string())
        );
        assert_eq!(config.address, Some("10.0.0.2/32".to_string()));
        assert_eq!(config.dns, Some("1.1.1.1".to_string()));
        assert_eq!(
            config.public_key,
            Some("serverkey1234567890123456789012345678901=".to_string())
        );
        assert_eq!(config.endpoint, Some("5.6.7.8:51820".to_string()));
        assert_eq!(config.allowed_ips, Some("0.0.0.0/0".to_string()));
        assert_eq!(config.persistent_keepalive, Some(25));

        // Verify key validation
        assert!(validate_wg_key("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="));
        assert!(!validate_wg_key("invalid-key"));
    }

    #[test]
    fn test_parse_wg_config() {
        let content = r#"
[Interface]
PrivateKey = testkey123456789012345678901234567890=
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = serverpubkey1234567890123456789012345=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"#;

        let config = WgConfig::parse(content);

        assert!(config.private_key.is_some());
        assert_eq!(config.address, Some("10.0.0.2/32".to_string()));
        assert_eq!(config.dns, Some("1.1.1.1".to_string()));
        assert!(config.public_key.is_some());
        assert_eq!(config.endpoint, Some("1.2.3.4:51820".to_string()));
        assert_eq!(config.persistent_keepalive, Some(25));
    }
}
