//! Error types for monarch-lazyvpn

use thiserror::Error;

/// Main error type for VPN operations
#[derive(Error, Debug)]
pub enum VpnError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Config parse error: {0}")]
    ConfigParseError(String),

    #[error("Keyring error: {0}")]
    KeyringError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Firewall error: {0}")]
    FirewallError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Provider error: {0}")]
    ProviderError(String),

    #[error("Timeout error: {0}")]
    TimeoutError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Interface not available: {0}")]
    InterfaceNotAvailable(String),

    #[error("Already connected")]
    AlreadyConnected,

    #[error("Not connected")]
    NotConnected,

    #[error("Another instance is running")]
    InstanceAlreadyRunning,

    #[error("Encryption error: {0}")]
    EncryptionError(String),
}

impl From<toml::de::Error> for VpnError {
    fn from(e: toml::de::Error) -> Self {
        VpnError::ConfigParseError(e.to_string())
    }
}

impl From<toml::ser::Error> for VpnError {
    fn from(e: toml::ser::Error) -> Self {
        VpnError::SerializationError(e.to_string())
    }
}

impl From<serde_json::Error> for VpnError {
    fn from(e: serde_json::Error) -> Self {
        VpnError::SerializationError(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, VpnError>;
