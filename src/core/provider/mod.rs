//! VPN Provider abstraction and implementations

pub mod custom;
pub mod protonvpn;

use crate::core::error::Result;
use crate::core::server::Server;
use crate::system::keyring::ProviderCredentials;
use crate::utils::gluetun::ServerCache;
use std::path::Path;

/// Provider type enumeration
#[derive(Debug, Clone, PartialEq)]
pub enum ProviderType {
    ProtonVPN,
    Mullvad,
    Custom,
    Unknown,
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderType::ProtonVPN => write!(f, "protonvpn"),
            ProviderType::Mullvad => write!(f, "mullvad"),
            ProviderType::Custom => write!(f, "custom"),
            ProviderType::Unknown => write!(f, "unknown"),
        }
    }
}

/// VPN Provider trait for multi-provider support
pub trait VpnProvider: Send + Sync {
    /// Internal provider name (e.g., "protonvpn")
    fn name(&self) -> &str;

    /// Display name for UI (e.g., "ProtonVPN")
    fn display_name(&self) -> &str;

    /// Provider DNS server
    fn dns(&self) -> &str;

    /// WireGuard port
    fn port(&self) -> u16;

    /// List available servers from cache
    fn list_servers(&self, cache: &ServerCache) -> Vec<Server>;

    /// Import config file and extract credentials
    fn import_config(&self, path: &Path) -> Result<ProviderCredentials>;

    /// Generate WireGuard config for a server
    fn generate_wg_config(&self, creds: &ProviderCredentials, server: &Server) -> String;
}

/// Parsed WireGuard config structure
#[derive(Debug, Clone, Default)]
pub struct WgConfig {
    pub private_key: Option<String>,
    pub address: Option<String>,
    pub dns: Option<String>,
    pub public_key: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: Option<String>,
    pub persistent_keepalive: Option<u32>,
}

impl WgConfig {
    /// Parse a WireGuard .conf file
    pub fn parse(content: &str) -> Self {
        let mut config = WgConfig::default();
        let mut in_interface = false;
        let mut in_peer = false;

        for line in content.lines() {
            let line = line.trim();

            if line.starts_with('[') {
                in_interface = line.to_lowercase().contains("interface");
                in_peer = line.to_lowercase().contains("peer");
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim().to_lowercase();
                let value = value.trim().to_string();

                match key.as_str() {
                    "privatekey" if in_interface => config.private_key = Some(value),
                    "address" if in_interface => config.address = Some(value),
                    "dns" if in_interface => config.dns = Some(value),
                    "publickey" if in_peer => config.public_key = Some(value),
                    "endpoint" if in_peer => config.endpoint = Some(value),
                    "allowedips" if in_peer => config.allowed_ips = Some(value),
                    "persistentkeepalive" if in_peer => {
                        config.persistent_keepalive = value.parse().ok()
                    }
                    _ => {}
                }
            }
        }

        config
    }
}

/// Detect provider from WireGuard config
pub fn detect_provider(config: &WgConfig, hint: Option<&str>) -> ProviderType {
    // Check user hint first
    if let Some(hint) = hint {
        match hint.to_lowercase().as_str() {
            "protonvpn" | "proton" => return ProviderType::ProtonVPN,
            "mullvad" => return ProviderType::Mullvad,
            "custom" => return ProviderType::Custom,
            _ => {}
        }
    }

    // Detect from DNS
    if let Some(ref dns) = config.dns {
        match dns.as_str() {
            "10.2.0.1" => return ProviderType::ProtonVPN,
            "10.64.0.1" => return ProviderType::Mullvad,
            _ => {}
        }
    }

    // Detect from Address range
    if let Some(ref address) = config.address {
        if address.starts_with("10.2.") {
            return ProviderType::ProtonVPN;
        }
        if address.starts_with("10.64.") || address.starts_with("10.65.") {
            return ProviderType::Mullvad;
        }
    }

    // Detect from endpoint patterns
    if let Some(ref endpoint) = config.endpoint {
        if endpoint.contains("protonvpn") || endpoint.contains("proton") {
            return ProviderType::ProtonVPN;
        }
        if endpoint.contains("mullvad") {
            return ProviderType::Mullvad;
        }
    }

    ProviderType::Unknown
}

/// Get a provider implementation by type
pub fn get_provider(provider_type: ProviderType) -> Box<dyn VpnProvider> {
    match provider_type {
        ProviderType::ProtonVPN => Box::new(protonvpn::ProtonVpnProvider::new()),
        ProviderType::Mullvad => {
            // Mullvad not implemented yet, fallback to custom
            Box::new(custom::CustomProvider::new())
        }
        ProviderType::Custom | ProviderType::Unknown => Box::new(custom::CustomProvider::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_wg_config() {
        let content = r#"
[Interface]
PrivateKey = abcdefghijklmnopqrstuvwxyz123456789012=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = serverPublicKey12345678901234567890123=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"#;

        let config = WgConfig::parse(content);

        assert_eq!(
            config.private_key,
            Some("abcdefghijklmnopqrstuvwxyz123456789012=".to_string())
        );
        assert_eq!(config.address, Some("10.2.0.2/32".to_string()));
        assert_eq!(config.dns, Some("10.2.0.1".to_string()));
        assert_eq!(
            config.public_key,
            Some("serverPublicKey12345678901234567890123=".to_string())
        );
        assert_eq!(config.endpoint, Some("1.2.3.4:51820".to_string()));
        assert_eq!(config.persistent_keepalive, Some(25));
    }

    #[test]
    fn test_detect_provider_from_dns() {
        let config = WgConfig {
            dns: Some("10.2.0.1".to_string()),
            ..Default::default()
        };

        assert_eq!(detect_provider(&config, None), ProviderType::ProtonVPN);
    }

    #[test]
    fn test_detect_provider_from_hint() {
        let config = WgConfig::default();
        assert_eq!(
            detect_provider(&config, Some("protonvpn")),
            ProviderType::ProtonVPN
        );
    }

    #[test]
    fn test_detect_provider_from_address() {
        let config = WgConfig {
            address: Some("10.2.5.123/32".to_string()),
            ..Default::default()
        };

        assert_eq!(detect_provider(&config, None), ProviderType::ProtonVPN);
    }
}
