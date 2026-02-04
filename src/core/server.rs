//! Server model and data structures

use serde::{Deserialize, Serialize};

/// Server features
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServerFeatures {
    #[serde(default)]
    pub p2p: bool,
    #[serde(default)]
    pub tor: bool,
    #[serde(default)]
    pub streaming: bool,
    #[serde(default)]
    pub secure_core: bool,
}

/// VPN Server information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    /// Unique identifier (e.g., "US-NY#42")
    pub id: String,

    /// Server name for display
    pub name: String,

    /// Country name
    pub country: String,

    /// Country code (2-letter ISO)
    pub country_code: String,

    /// City name
    pub city: String,

    /// Server IP address
    pub ip: String,

    /// WireGuard public key
    pub pubkey: String,

    /// Server features
    #[serde(default)]
    pub features: ServerFeatures,

    /// Provider name (e.g., "protonvpn", "mullvad")
    pub provider: String,

    /// Is this a custom config server
    #[serde(default)]
    pub is_custom: bool,

    /// AllowedIPs for WireGuard config (default: 0.0.0.0/0)
    #[serde(default = "default_allowed_ips")]
    pub allowed_ips: String,
}

fn default_allowed_ips() -> String {
    "0.0.0.0/0".to_string()
}

impl Server {
    /// Create a new server from gluetun data
    pub fn from_gluetun(
        name: String,
        country: String,
        country_code: String,
        city: String,
        ip: String,
        pubkey: String,
        provider: String,
    ) -> Self {
        // Use name directly as ID to avoid collisions (e.g., SE-UK#1 vs IS-UK#1)
        let id = name.clone();

        Self {
            id,
            name,
            country,
            country_code,
            city,
            ip,
            pubkey,
            features: ServerFeatures::default(),
            provider,
            is_custom: false,
            allowed_ips: default_allowed_ips(),
        }
    }

    /// Create a custom server from imported config
    pub fn from_custom(name: String, ip: String, pubkey: String, allowed_ips: Option<String>) -> Self {
        Self {
            id: format!("custom-{}", name),
            name: name.clone(),
            country: "Custom".to_string(),
            country_code: "XX".to_string(),
            city: "Custom".to_string(),
            ip,
            pubkey,
            features: ServerFeatures::default(),
            provider: "custom".to_string(),
            is_custom: true,
            allowed_ips: allowed_ips.unwrap_or_else(default_allowed_ips),
        }
    }

    /// Get country flag emoji
    /// Returns flag emoji with variation selector for proper terminal rendering
    pub fn country_flag(&self) -> String {
        // Custom configs or invalid country codes use globe icon
        if self.is_custom || self.country_code.len() != 2 {
            return "🌐\u{FE0F}".to_string();
        }

        // Convert ASCII to regional indicator symbols
        // 'A' (65) -> Regional Indicator A (127462)
        let flag: String = self
            .country_code
            .to_uppercase()
            .chars()
            .filter_map(|c| {
                if c.is_ascii_alphabetic() {
                    char::from_u32(c as u32 + 127397)
                } else {
                    None
                }
            })
            .collect();

        if flag.chars().count() == 2 {
            // Add VS16 (Variation Selector-16) to force emoji presentation
            format!("{}\u{FE0F}", flag)
        } else {
            "🌐\u{FE0F}".to_string()
        }
    }

    /// Get feature icons
    pub fn feature_icons(&self) -> String {
        let mut icons = String::new();

        if self.features.p2p {
            icons.push_str("P2P ");
        }
        if self.features.tor {
            icons.push_str("TOR ");
        }
        if self.features.streaming {
            icons.push_str("📺 ");
        }
        if self.features.secure_core {
            icons.push_str("🔒 ");
        }

        icons.trim().to_string()
    }

    /// Get display name with flag
    pub fn display_name(&self) -> String {
        format!("{} {} - {}", self.country_flag(), self.country, self.name)
    }

    /// Get human-readable provider name
    pub fn provider_display_name(&self) -> &str {
        match self.provider.as_str() {
            "protonvpn" => "ProtonVPN",
            "mullvad" => "Mullvad",
            "custom" => "Custom",
            other => other,
        }
    }

    /// Check if this is a split-tunnel config (not routing all traffic)
    /// Split-tunnel configs don't have 0.0.0.0/0 in AllowedIPs
    pub fn is_split_tunnel(&self) -> bool {
        !self.allowed_ips.contains("0.0.0.0/0")
    }
}

/// Validate WireGuard public/private key format
pub fn validate_wg_key(key: &str) -> bool {
    // WireGuard keys are 32 bytes, base64 encoded = 44 chars ending with =
    if key.len() != 44 || !key.ends_with('=') {
        return false;
    }

    // Check if it's valid base64
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(key)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_country_flag() {
        let server = Server {
            id: "test".to_string(),
            name: "Test".to_string(),
            country: "United States".to_string(),
            country_code: "US".to_string(),
            city: "New York".to_string(),
            ip: "1.2.3.4".to_string(),
            pubkey: "test".to_string(),
            features: ServerFeatures::default(),
            provider: "test".to_string(),
            is_custom: false,
            allowed_ips: "0.0.0.0/0".to_string(),
        };

        // Flag includes Variation Selector-16 for proper emoji rendering
        assert_eq!(server.country_flag(), "🇺🇸\u{FE0F}");
    }

    #[test]
    fn test_validate_wg_key_valid() {
        // Valid WireGuard key (44 chars, base64, ends with =)
        let valid_key = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";
        assert!(validate_wg_key(valid_key));
    }

    #[test]
    fn test_validate_wg_key_invalid_length() {
        let short_key = "YWJjZGVm";
        assert!(!validate_wg_key(short_key));
    }

    #[test]
    fn test_validate_wg_key_invalid_ending() {
        let bad_ending = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTa";
        assert!(!validate_wg_key(bad_ending));
    }
}
