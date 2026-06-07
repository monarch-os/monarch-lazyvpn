//! ProtonVPN provider implementation

use crate::core::error::{Result, VpnError};
use crate::core::provider::{VpnProvider, WgConfig};
use crate::core::server::{validate_wg_key, Server};
use crate::system::keyring::ProviderCredentials;
use crate::utils::gluetun::ServerCache;
use std::fs;
use std::path::Path;

const PROTONVPN_DNS: &str = "10.2.0.1";
const PROTONVPN_PORT: u16 = 51820;

/// Keep only the IPv4 entries from a (possibly dual-stack) comma-separated
/// address list. IPv6 entries contain ':' and are dropped so the generated
/// config stays IPv4-only. Falls back to the original value if no IPv4 entry
/// is found (shouldn't happen for ProtonVPN).
fn ipv4_only_addresses(address: &str) -> String {
    let ipv4: Vec<&str> = address
        .split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty() && !p.contains(':'))
        .collect();

    if ipv4.is_empty() {
        address.trim().to_string()
    } else {
        ipv4.join(", ")
    }
}

/// ProtonVPN provider
pub struct ProtonVpnProvider;

impl ProtonVpnProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ProtonVpnProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl VpnProvider for ProtonVpnProvider {
    fn name(&self) -> &str {
        "protonvpn"
    }

    fn display_name(&self) -> &str {
        "ProtonVPN"
    }

    fn dns(&self) -> &str {
        PROTONVPN_DNS
    }

    fn port(&self) -> u16 {
        PROTONVPN_PORT
    }

    fn list_servers(&self, cache: &ServerCache) -> Vec<Server> {
        cache
            .servers
            .iter()
            .filter(|s| s.provider.to_lowercase() == "protonvpn")
            .cloned()
            .collect()
    }

    fn import_config(&self, path: &Path) -> Result<ProviderCredentials> {
        let content = fs::read_to_string(path).map_err(|e| {
            VpnError::ConfigParseError(format!("Failed to read config file: {}", e))
        })?;

        let config = WgConfig::parse(&content);

        // Validate required fields
        let private_key = config.private_key.ok_or_else(|| {
            VpnError::ConfigParseError("Missing PrivateKey in config".to_string())
        })?;

        let address = config
            .address
            .ok_or_else(|| VpnError::ConfigParseError("Missing Address in config".to_string()))?;

        // Validate private key format
        if !validate_wg_key(&private_key) {
            return Err(VpnError::ConfigParseError(
                "Invalid PrivateKey format (must be 44 chars, base64, ending with =)".to_string(),
            ));
        }

        Ok(ProviderCredentials {
            private_key,
            address,
            provider_name: self.name().to_string(),
        })
    }

    fn generate_wg_config(&self, creds: &ProviderCredentials, server: &Server) -> String {
        // Use IPv4 only to avoid issues on systems with IPv6 disabled.
        // ProtonVPN ships dual-stack configs (e.g. "10.2.0.2/32, 2a07:b944::2:2/128");
        // keep only the IPv4 part, otherwise wg-quick's `ip -6 address add` fails when
        // IPv6 has been disabled before connecting.
        let address = ipv4_only_addresses(&creds.address);
        format!(
            "[Interface]\n\
             PrivateKey = {}\n\
             Address = {}\n\
             DNS = {}\n\
             \n\
             [Peer]\n\
             PublicKey = {}\n\
             Endpoint = {}:{}\n\
             AllowedIPs = 0.0.0.0/0\n\
             PersistentKeepalive = 25\n",
            creds.private_key,
            address,
            self.dns(),
            server.pubkey,
            server.ip,
            self.port()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_provider_info() {
        let provider = ProtonVpnProvider::new();
        assert_eq!(provider.name(), "protonvpn");
        assert_eq!(provider.display_name(), "ProtonVPN");
        assert_eq!(provider.dns(), "10.2.0.1");
        assert_eq!(provider.port(), 51820);
    }

    #[test]
    fn test_import_valid_config() {
        let provider = ProtonVpnProvider::new();

        let mut temp = NamedTempFile::new().unwrap();
        writeln!(
            temp,
            r#"[Interface]
PrivateKey = YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = serverkey1234567890123456789012345678901=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
"#
        )
        .unwrap();

        let creds = provider.import_config(temp.path()).unwrap();

        assert_eq!(
            creds.private_key,
            "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
        );
        assert_eq!(creds.address, "10.2.0.2/32");
        assert_eq!(creds.provider_name, "protonvpn");
    }

    #[test]
    fn test_import_missing_private_key() {
        let provider = ProtonVpnProvider::new();

        let mut temp = NamedTempFile::new().unwrap();
        writeln!(
            temp,
            r#"[Interface]
Address = 10.2.0.2/32
DNS = 10.2.0.1
"#
        )
        .unwrap();

        let result = provider.import_config(temp.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_wg_config() {
        let provider = ProtonVpnProvider::new();

        let creds = ProviderCredentials {
            private_key: "userPrivateKey123456789012345678901234=".to_string(),
            address: "10.2.0.2/32".to_string(),
            provider_name: "protonvpn".to_string(),
        };

        let server = Server {
            id: "US-NY#1".to_string(),
            name: "US-NY#1".to_string(),
            country: "United States".to_string(),
            country_code: "US".to_string(),
            city: "New York".to_string(),
            ip: "1.2.3.4".to_string(),
            pubkey: "serverPublicKey12345678901234567890123=".to_string(),
            features: Default::default(),
            provider: "protonvpn".to_string(),
            is_custom: false,
            allowed_ips: "0.0.0.0/0".to_string(),
        };

        let config = provider.generate_wg_config(&creds, &server);

        assert!(config.contains("PrivateKey = userPrivateKey123456789012345678901234="));
        assert!(config.contains("Address = 10.2.0.2/32"));
        assert!(config.contains("DNS = 10.2.0.1"));
        assert!(config.contains("PublicKey = serverPublicKey12345678901234567890123="));
        assert!(config.contains("Endpoint = 1.2.3.4:51820"));
    }

    #[test]
    fn test_ipv4_only_addresses() {
        // Dual-stack ProtonVPN address -> IPv4 only
        assert_eq!(
            ipv4_only_addresses("10.2.0.2/32, 2a07:b944::2:2/128"),
            "10.2.0.2/32"
        );
        // Already IPv4 only -> unchanged
        assert_eq!(ipv4_only_addresses("10.2.0.2/32"), "10.2.0.2/32");
        // Multiple IPv4 entries preserved
        assert_eq!(
            ipv4_only_addresses("10.2.0.2/32, 10.3.0.2/32"),
            "10.2.0.2/32, 10.3.0.2/32"
        );
        // No IPv4 entry -> fall back to original (trimmed)
        assert_eq!(ipv4_only_addresses("2a07:b944::2:2/128"), "2a07:b944::2:2/128");
    }

    #[test]
    fn test_generate_wg_config_strips_ipv6_address() {
        let provider = ProtonVpnProvider::new();

        let creds = ProviderCredentials {
            private_key: "userPrivateKey123456789012345678901234=".to_string(),
            address: "10.2.0.2/32, 2a07:b944::2:2/128".to_string(),
            provider_name: "protonvpn".to_string(),
        };

        let server = Server {
            id: "CH#242".to_string(),
            name: "CH#242".to_string(),
            country: "Switzerland".to_string(),
            country_code: "CH".to_string(),
            city: "Zurich".to_string(),
            ip: "149.88.27.219".to_string(),
            pubkey: "serverPublicKey12345678901234567890123=".to_string(),
            features: Default::default(),
            provider: "protonvpn".to_string(),
            is_custom: false,
            allowed_ips: "0.0.0.0/0".to_string(),
        };

        let config = provider.generate_wg_config(&creds, &server);

        // IPv4 address kept, IPv6 dropped (would break wg-quick when IPv6 is disabled)
        assert!(config.contains("Address = 10.2.0.2/32\n"));
        assert!(!config.contains("2a07:b944"));
        assert!(!config.contains("::"));
    }
}
