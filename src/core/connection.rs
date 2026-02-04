//! VPN connection state machine with persistence

use crate::core::config::AppConfig;
use crate::core::error::{Result, VpnError};
use crate::core::server::Server;
use crate::system::wireguard::WgManager;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Connection states
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error(String),
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Disconnected => write!(f, "Disconnected"),
            ConnectionState::Connecting => write!(f, "Connecting"),
            ConnectionState::Connected => write!(f, "Connected"),
            ConnectionState::Disconnecting => write!(f, "Disconnecting"),
            ConnectionState::Error(e) => write!(f, "Error: {}", e),
        }
    }
}

/// Detected VPN state from system inspection
#[derive(Debug, Clone)]
pub struct DetectedVpnState {
    pub interface: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Option<String>,
    pub is_split_tunnel: bool,
    pub handshake_age: Option<Duration>,
}

/// Detect active VPN connections from system state (sysfs + wg show)
/// This function requires privileges for `wg show` commands
pub async fn detect_system_vpn_state() -> Option<DetectedVpnState> {
    // List WireGuard interfaces via sysfs (no privileges needed)
    let interfaces = WgManager::list_wireguard_interfaces_sysfs();

    if interfaces.is_empty() {
        return None;
    }

    // For each interface, try to get details via wg show (requires privileges)
    // Return the first interface with a recent handshake, or just the first one
    let mut best_candidate: Option<DetectedVpnState> = None;

    for iface in &interfaces {
        // Get WireGuard details (these require privileges)
        let endpoint = WgManager::get_wg_endpoint(iface).await;
        let allowed_ips = WgManager::get_wg_allowed_ips(iface).await;
        let handshake_age = WgManager::get_wg_handshake_age(iface).await;

        let is_split_tunnel = allowed_ips
            .as_ref()
            .map(|ips| !ips.contains("0.0.0.0/0"))
            .unwrap_or(false);

        let detected = DetectedVpnState {
            interface: iface.clone(),
            endpoint,
            allowed_ips,
            is_split_tunnel,
            handshake_age,
        };

        // Prefer interface with recent handshake (< 5 min)
        if let Some(age) = detected.handshake_age {
            if age < Duration::from_secs(300) {
                // Found a recently active interface
                return Some(detected);
            }
        }

        // Keep track of first candidate
        if best_candidate.is_none() {
            best_candidate = Some(detected);
        }
    }

    // Return best candidate (first interface found)
    best_candidate
}

/// Persisted connection state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedState {
    pub state: ConnectionState,
    pub server_id: Option<String>,
    pub server_name: Option<String>,
    pub interface: String,
    pub connected_at: Option<DateTime<Utc>>,
    pub pid: u32,
    pub was_connected_on_exit: bool,
    /// Additional server fields for better UI restoration
    #[serde(default)]
    pub server_country: Option<String>,
    #[serde(default)]
    pub server_country_code: Option<String>,
    #[serde(default)]
    pub server_city: Option<String>,
    #[serde(default)]
    pub server_provider: Option<String>,
    /// Public IP address when connected (for status display when app is closed)
    #[serde(default)]
    pub public_ip: Option<String>,
    /// Server allowed IPs (for split-tunnel detection)
    #[serde(default)]
    pub server_allowed_ips: Option<String>,
    /// Killswitch state (for status binary without privileges)
    #[serde(default)]
    pub killswitch_active: bool,
}

/// Connection manager with state machine
pub struct ConnectionManager {
    state: ConnectionState,
    current_server: Option<Server>,
    interface: String,
    connected_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    original_public_ip: Option<String>,
    /// Current public IP (when connected via VPN)
    current_public_ip: Option<String>,
    /// Killswitch active state (for status binary)
    killswitch_active: bool,
    state_file: PathBuf,
}

impl ConnectionManager {
    /// Create a new connection manager
    pub fn new(interface: &str) -> Result<Self> {
        let config_dir = AppConfig::config_dir()?;
        let state_file = config_dir.join(".connection_state");

        let mut manager = Self {
            state: ConnectionState::Disconnected,
            current_server: None,
            interface: interface.to_string(),
            connected_at: None,
            last_error: None,
            original_public_ip: None,
            current_public_ip: None,
            killswitch_active: false,
            state_file,
        };

        // Try to recover state
        manager.recover_state()?;

        Ok(manager)
    }

    /// Get current connection state
    pub fn state(&self) -> &ConnectionState {
        &self.state
    }

    /// Get current server
    pub fn current_server(&self) -> Option<&Server> {
        self.current_server.as_ref()
    }

    /// Get interface name
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Set interface name
    pub fn set_interface(&mut self, interface: &str) {
        self.interface = interface.to_string();
    }

    /// Get connection duration
    pub fn uptime(&self) -> Option<chrono::Duration> {
        self.connected_at.map(|t| Utc::now() - t)
    }

    /// Format uptime as human-readable string
    pub fn uptime_string(&self) -> String {
        match self.uptime() {
            Some(duration) => {
                let secs = duration.num_seconds();
                let hours = secs / 3600;
                let mins = (secs % 3600) / 60;
                let secs = secs % 60;

                if hours > 0 {
                    format!("{}h {}m {}s", hours, mins, secs)
                } else if mins > 0 {
                    format!("{}m {}s", mins, secs)
                } else {
                    format!("{}s", secs)
                }
            }
            None => "N/A".to_string(),
        }
    }

    /// Get last error
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Get original public IP (before connecting)
    pub fn original_ip(&self) -> Option<&str> {
        self.original_public_ip.as_deref()
    }

    /// Set original public IP
    pub fn set_original_ip(&mut self, ip: String) {
        self.original_public_ip = Some(ip);
    }

    /// Set the current public IP (when connected via VPN)
    pub fn set_current_public_ip(&mut self, ip: Option<String>) {
        self.current_public_ip = ip;
    }

    /// Set killswitch active state
    pub fn set_killswitch_active(&mut self, active: bool) {
        self.killswitch_active = active;
    }

    /// Get killswitch active state
    pub fn is_killswitch_active(&self) -> bool {
        self.killswitch_active
    }

    /// Transition to connecting state
    pub fn start_connecting(&mut self, server: Server) -> Result<()> {
        if self.state == ConnectionState::Connected {
            return Err(VpnError::AlreadyConnected);
        }

        self.state = ConnectionState::Connecting;
        self.current_server = Some(server);
        self.last_error = None;
        self.persist_state()?;

        info!("Connection state: Connecting");
        Ok(())
    }

    /// Transition to connected state
    pub fn set_connected(&mut self) -> Result<()> {
        self.state = ConnectionState::Connected;
        self.connected_at = Some(Utc::now());
        self.persist_state()?;

        info!("Connection state: Connected");
        Ok(())
    }

    /// Transition to disconnecting state
    pub fn start_disconnecting(&mut self) -> Result<()> {
        if self.state == ConnectionState::Disconnected {
            return Err(VpnError::NotConnected);
        }

        self.state = ConnectionState::Disconnecting;
        self.persist_state()?;

        info!("Connection state: Disconnecting");
        Ok(())
    }

    /// Transition to disconnected state
    pub fn set_disconnected(&mut self) -> Result<()> {
        self.state = ConnectionState::Disconnected;
        self.current_server = None;
        self.connected_at = None;
        self.original_public_ip = None;
        self.persist_state()?;

        info!("Connection state: Disconnected");
        Ok(())
    }

    /// Transition to error state
    pub fn set_error(&mut self, error: String) -> Result<()> {
        self.last_error = Some(error.clone());
        self.state = ConnectionState::Error(error);
        self.persist_state()?;

        Ok(())
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    /// Check if in error state
    pub fn is_error(&self) -> bool {
        matches!(self.state, ConnectionState::Error(_))
    }

    /// Clear error state and return to Disconnected
    pub fn clear_error(&mut self) -> Result<()> {
        if matches!(self.state, ConnectionState::Error(_)) {
            info!("Clearing error state, returning to Disconnected");
            self.state = ConnectionState::Disconnected;
            self.last_error = None;
            self.current_server = None;
            self.connected_at = None;
            self.persist_state()?;
        }
        Ok(())
    }

    /// Check if transitioning
    pub fn is_transitioning(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Connecting | ConnectionState::Disconnecting
        )
    }

    /// Persist state to disk
    pub fn persist_state(&self) -> Result<()> {
        let persisted = PersistedState {
            state: self.state.clone(),
            server_id: self.current_server.as_ref().map(|s| s.id.clone()),
            server_name: self.current_server.as_ref().map(|s| s.name.clone()),
            interface: self.interface.clone(),
            connected_at: self.connected_at,
            pid: std::process::id(),
            was_connected_on_exit: self.state == ConnectionState::Connected,
            // Additional server fields for better restoration
            server_country: self.current_server.as_ref().map(|s| s.country.clone()),
            server_country_code: self.current_server.as_ref().map(|s| s.country_code.clone()),
            server_city: self.current_server.as_ref().map(|s| s.city.clone()),
            server_provider: self.current_server.as_ref().map(|s| s.provider.clone()),
            public_ip: self.current_public_ip.clone(),
            server_allowed_ips: self.current_server.as_ref().map(|s| s.allowed_ips.clone()),
            killswitch_active: self.killswitch_active,
        };

        // Ensure directory exists
        if let Some(parent) = self.state_file.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(&persisted)?;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.state_file)?;

        file.write_all(content.as_bytes())?;
        debug!("Persisted connection state: {:?}", self.state);

        Ok(())
    }

    /// Load persisted state
    fn load_state(&self) -> Result<Option<PersistedState>> {
        if !self.state_file.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&self.state_file)?;
        let state: PersistedState = serde_json::from_str(&content)?;
        Ok(Some(state))
    }

    /// Remove state file
    fn remove_state_file(&self) {
        if self.state_file.exists() {
            let _ = fs::remove_file(&self.state_file);
        }
    }

    /// Check if a process is running
    fn is_pid_running(pid: u32) -> bool {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }

    /// Recover state on startup (detect orphaned/crashed state or restore preserved connection)
    fn recover_state(&mut self) -> Result<()> {
        let persisted = match self.load_state()? {
            Some(s) => s,
            None => return Ok(()),
        };

        // Check if the process that created this state is still running
        if Self::is_pid_running(persisted.pid) {
            // Another instance is running
            return Err(VpnError::InstanceAlreadyRunning);
        }

        // Check if interface actually exists
        let interface_exists =
            std::path::Path::new(&format!("/sys/class/net/{}", persisted.interface)).exists();

        // Handle preserved VPN connection (graceful exit with keep_vpn_on_exit=true)
        if persisted.was_connected_on_exit && interface_exists {
            info!(
                "Restoring preserved VPN connection on interface {}",
                persisted.interface
            );
            self.interface = persisted.interface;
            self.state = ConnectionState::Connected;
            self.connected_at = persisted.connected_at;

            // Restore server info if available
            if let (Some(server_id), Some(server_name)) =
                (persisted.server_id.clone(), persisted.server_name.clone())
            {
                let provider = persisted.server_provider.unwrap_or_default();
                // Create a server object with restored fields for display purposes
                self.current_server = Some(crate::core::server::Server {
                    id: server_id,
                    name: server_name,
                    country: persisted.server_country.unwrap_or_default(),
                    country_code: persisted.server_country_code.unwrap_or_default(),
                    city: persisted.server_city.unwrap_or_default(),
                    ip: String::new(),
                    pubkey: String::new(),
                    provider: provider.clone(),
                    features: crate::core::server::ServerFeatures::default(),
                    is_custom: provider == "custom",
                    allowed_ips: persisted.server_allowed_ips.unwrap_or_else(|| "0.0.0.0/0".to_string()),
                });
            }

            // Update PID in persisted state to current process
            self.persist_state()?;

            info!(
                "VPN connection restored - connected since {:?}",
                self.connected_at
            );
            return Ok(());
        }

        // Handle case where was_connected_on_exit=true but interface is gone
        if persisted.was_connected_on_exit && !interface_exists {
            info!(
                "Previous VPN connection lost (interface {} no longer exists)",
                persisted.interface
            );
            self.remove_state_file();
            self.state = ConnectionState::Disconnected;
            return Ok(());
        }

        // Previous instance crashed or exited uncleanly (was_connected_on_exit=false)
        match persisted.state {
            ConnectionState::Connected | ConnectionState::Connecting => {
                warn!(
                    "Found orphaned state from PID {} (was {:?})",
                    persisted.pid, persisted.state
                );

                if interface_exists {
                    warn!(
                        "VPN interface {} still exists - previous instance may have crashed",
                        persisted.interface
                    );
                    // Will need cleanup
                    self.interface = persisted.interface;
                    self.state = ConnectionState::Error(
                        "Previous instance crashed while connected".to_string(),
                    );
                } else {
                    // Interface gone, just clean up state
                    self.remove_state_file();
                    self.state = ConnectionState::Disconnected;
                }
            }
            ConnectionState::Disconnecting => {
                warn!("Previous instance crashed while disconnecting");
                // Interface may or may not exist
                self.state = ConnectionState::Disconnected;
                self.remove_state_file();
            }
            ConnectionState::Disconnected | ConnectionState::Error(_) => {
                // Clean state, just remove file
                self.remove_state_file();
            }
        }

        Ok(())
    }

    /// Async recover state using system detection
    /// This should be called after ConnectionManager::new() to properly detect VPN state
    /// Returns a description of detected state for UI display
    pub async fn recover_state_with_detection(&mut self) -> Result<Option<String>> {
        // First, detect system VPN state
        let detected = detect_system_vpn_state().await;

        // Load persisted state file if exists
        let persisted = self.load_state()?;

        match (&detected, &persisted) {
            // Case 1: VPN detected + metadata available
            (Some(det), Some(per)) if per.interface == det.interface => {
                // Verify interface still exists (mitigate TOCTOU race)
                let iface_path = format!("/sys/class/net/{}", det.interface);
                if !std::path::Path::new(&iface_path).exists() {
                    info!(
                        "Interface {} disappeared during detection, treating as disconnected",
                        det.interface
                    );
                    self.remove_state_file();
                    self.state = ConnectionState::Disconnected;
                    return Ok(None);
                }

                info!(
                    "Detected active VPN on {} with metadata from previous session",
                    det.interface
                );
                self.interface = det.interface.clone();
                self.state = ConnectionState::Connected;
                self.connected_at = per.connected_at;
                self.killswitch_active = per.killswitch_active;

                // Restore server info
                if let (Some(server_id), Some(server_name)) =
                    (per.server_id.clone(), per.server_name.clone())
                {
                    let provider = per.server_provider.clone().unwrap_or_default();
                    // Use persisted allowed_ips (reliable), fallback to detected, then default
                    let allowed_ips = per.server_allowed_ips.clone()
                        .or_else(|| det.allowed_ips.clone())
                        .unwrap_or_else(|| "0.0.0.0/0".to_string());
                    self.current_server = Some(Server {
                        id: server_id,
                        name: server_name.clone(),
                        country: per.server_country.clone().unwrap_or_default(),
                        country_code: per.server_country_code.clone().unwrap_or_default(),
                        city: per.server_city.clone().unwrap_or_default(),
                        ip: String::new(),
                        pubkey: String::new(),
                        provider: provider.clone(),
                        features: crate::core::server::ServerFeatures::default(),
                        is_custom: provider == "custom",
                        allowed_ips,
                    });
                    self.persist_state()?;
                    return Ok(Some(format!("Restored connection to {}", server_name)));
                }
                self.persist_state()?;
                Ok(Some(format!("Restored connection on {}", det.interface)))
            }

            // Case 2: VPN detected + no matching metadata (external VPN)
            (Some(det), _) => {
                // Verify interface still exists (mitigate TOCTOU race)
                let iface_path = format!("/sys/class/net/{}", det.interface);
                if !std::path::Path::new(&iface_path).exists() {
                    info!(
                        "Interface {} disappeared during detection, treating as disconnected",
                        det.interface
                    );
                    self.state = ConnectionState::Disconnected;
                    return Ok(None);
                }

                info!(
                    "Detected active VPN on {} without metadata (external connection)",
                    det.interface
                );
                self.interface = det.interface.clone();
                self.state = ConnectionState::Connected;
                self.connected_at = Some(Utc::now());
                self.killswitch_active = false; // Unknown

                // Create placeholder server
                self.current_server = Some(Server {
                    id: format!("external-{}", det.interface),
                    name: format!("Unknown ({})", det.interface),
                    country: String::new(),
                    country_code: String::new(),
                    city: String::new(),
                    ip: det.endpoint.clone().unwrap_or_default(),
                    pubkey: String::new(),
                    provider: "external".to_string(),
                    features: crate::core::server::ServerFeatures::default(),
                    is_custom: true,
                    allowed_ips: det.allowed_ips.clone().unwrap_or_else(|| "0.0.0.0/0".to_string()),
                });

                self.persist_state()?;
                Ok(Some(format!("Detected active VPN on {}", det.interface)))
            }

            // Case 3: No VPN detected + state file says "Connected"
            (None, Some(per)) if per.was_connected_on_exit => {
                info!(
                    "State file says connected but no VPN interface found - cleaning up"
                );
                self.remove_state_file();
                self.state = ConnectionState::Disconnected;
                Ok(None)
            }

            // Case 4: No VPN detected + state file exists but not connected
            (None, Some(_)) => {
                self.remove_state_file();
                self.state = ConnectionState::Disconnected;
                Ok(None)
            }

            // Case 5: No VPN detected + no state file
            (None, None) => {
                self.state = ConnectionState::Disconnected;
                Ok(None)
            }
        }
    }

    /// Check if we should prompt for reconnection
    pub fn should_prompt_reconnect(&self) -> bool {
        match self.load_state() {
            Ok(Some(state)) => {
                state.was_connected_on_exit
                    && !Self::is_pid_running(state.pid)
                    && matches!(
                        state.state,
                        ConnectionState::Connected | ConnectionState::Disconnected
                    )
            }
            _ => false,
        }
    }

    /// Get server ID for reconnection
    pub fn get_reconnect_server_id(&self) -> Option<String> {
        self.load_state().ok().flatten().and_then(|s| s.server_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_display() {
        assert_eq!(ConnectionState::Disconnected.to_string(), "Disconnected");
        assert_eq!(ConnectionState::Connected.to_string(), "Connected");
        assert_eq!(ConnectionState::Connecting.to_string(), "Connecting");
        assert_eq!(ConnectionState::Disconnecting.to_string(), "Disconnecting");
        assert_eq!(
            ConnectionState::Error("test".to_string()).to_string(),
            "Error: test"
        );
    }

    #[test]
    fn test_uptime_string() {
        let mut manager = ConnectionManager {
            state: ConnectionState::Disconnected,
            current_server: None,
            interface: "wg0".to_string(),
            connected_at: None,
            last_error: None,
            original_public_ip: None,
            current_public_ip: None,
            killswitch_active: false,
            state_file: PathBuf::from("/tmp/test_state"),
        };

        assert_eq!(manager.uptime_string(), "N/A");

        // Test with connection time - hours
        manager.connected_at = Some(Utc::now() - chrono::Duration::seconds(3661));
        let uptime = manager.uptime_string();
        assert!(uptime.contains("h"));
        assert!(uptime.contains("m"));

        // Test with minutes only
        manager.connected_at = Some(Utc::now() - chrono::Duration::seconds(125));
        let uptime = manager.uptime_string();
        assert!(uptime.contains("m"));
        assert!(uptime.contains("s"));

        // Test with seconds only
        manager.connected_at = Some(Utc::now() - chrono::Duration::seconds(45));
        let uptime = manager.uptime_string();
        assert!(uptime.contains("s"));
        assert!(!uptime.contains("m"));
    }

    #[test]
    fn test_state_transitions() {
        let mut manager = ConnectionManager {
            state: ConnectionState::Disconnected,
            current_server: None,
            interface: "wg0".to_string(),
            connected_at: None,
            last_error: None,
            original_public_ip: None,
            current_public_ip: None,
            killswitch_active: false,
            state_file: PathBuf::from("/tmp/test_state_transitions"),
        };

        // Disconnected -> Connecting
        assert!(!manager.is_connected());
        assert!(!manager.is_transitioning());

        // Can't disconnect when already disconnected
        assert!(manager.start_disconnecting().is_err());

        // Can't connect when already connected
        let test_server = crate::core::server::Server {
            id: "test".to_string(),
            name: "Test Server".to_string(),
            country: "US".to_string(),
            country_code: "US".to_string(),
            city: "New York".to_string(),
            ip: "1.2.3.4".to_string(),
            pubkey: "testkey123456789012345678901234567890123=".to_string(),
            provider: "test".to_string(),
            features: crate::core::server::ServerFeatures::default(),
            is_custom: false,
            allowed_ips: "0.0.0.0/0".to_string(),
        };

        manager.start_connecting(test_server).ok();
        assert!(manager.is_transitioning());
        assert_eq!(*manager.state(), ConnectionState::Connecting);

        // Connecting -> Connected
        manager.set_connected().ok();
        assert!(manager.is_connected());
        assert!(!manager.is_transitioning());
        assert!(manager.connected_at.is_some());

        // Connected -> Disconnecting
        manager.start_disconnecting().ok();
        assert!(manager.is_transitioning());

        // Disconnecting -> Disconnected
        manager.set_disconnected().ok();
        assert!(!manager.is_connected());
        assert!(manager.connected_at.is_none());
        assert!(manager.current_server().is_none());
    }

    #[test]
    fn test_error_state() {
        let mut manager = ConnectionManager {
            state: ConnectionState::Disconnected,
            current_server: None,
            interface: "wg0".to_string(),
            connected_at: None,
            last_error: None,
            original_public_ip: None,
            current_public_ip: None,
            killswitch_active: false,
            state_file: PathBuf::from("/tmp/test_error_state"),
        };

        manager.set_error("Test error message".to_string()).ok();

        match manager.state() {
            ConnectionState::Error(msg) => assert_eq!(msg, "Test error message"),
            _ => panic!("Expected Error state"),
        }

        assert_eq!(manager.last_error(), Some("Test error message"));
    }

    #[test]
    fn test_original_ip_tracking() {
        let mut manager = ConnectionManager {
            state: ConnectionState::Disconnected,
            current_server: None,
            interface: "wg0".to_string(),
            connected_at: None,
            last_error: None,
            original_public_ip: None,
            current_public_ip: None,
            killswitch_active: false,
            state_file: PathBuf::from("/tmp/test_ip"),
        };

        assert_eq!(manager.original_ip(), None);

        manager.set_original_ip("1.2.3.4".to_string());
        assert_eq!(manager.original_ip(), Some("1.2.3.4"));

        manager.set_disconnected().ok();
        assert_eq!(manager.original_ip(), None);
    }

    #[test]
    fn test_persisted_state_serialization() {
        // Test that PersistedState correctly serializes was_connected_on_exit
        let state = PersistedState {
            state: ConnectionState::Connected,
            server_id: Some("server-123".to_string()),
            server_name: Some("Test Server".to_string()),
            interface: "wg0".to_string(),
            connected_at: Some(Utc::now()),
            pid: 12345,
            was_connected_on_exit: true,
            server_country: Some("United States".to_string()),
            server_country_code: Some("US".to_string()),
            server_city: Some("New York".to_string()),
            server_provider: Some("protonvpn".to_string()),
            public_ip: Some("203.0.113.42".to_string()),
            server_allowed_ips: Some("0.0.0.0/0".to_string()),
            killswitch_active: true,
        };

        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"was_connected_on_exit\":true"));
        assert!(json.contains("\"server_country\":\"United States\""));
        assert!(json.contains("\"public_ip\":\"203.0.113.42\""));
        assert!(json.contains("\"killswitch_active\":true"));

        // Deserialize and verify
        let parsed: PersistedState = serde_json::from_str(&json).unwrap();
        assert!(parsed.was_connected_on_exit);
        assert_eq!(parsed.server_id, Some("server-123".to_string()));
        assert_eq!(parsed.server_name, Some("Test Server".to_string()));
        assert_eq!(parsed.interface, "wg0");
        assert_eq!(parsed.server_country, Some("United States".to_string()));
        assert_eq!(parsed.server_country_code, Some("US".to_string()));
    }

    #[test]
    fn test_persisted_state_with_was_connected_false() {
        // Test state when app was not connected on exit (crash scenario)
        let state = PersistedState {
            state: ConnectionState::Connecting,
            server_id: Some("server-456".to_string()),
            server_name: Some("Crashed Server".to_string()),
            interface: "wg1".to_string(),
            connected_at: None,
            pid: 99999,
            was_connected_on_exit: false,
            server_country: None,
            server_country_code: None,
            server_city: None,
            server_provider: None,
            public_ip: None,
            server_allowed_ips: None,
            killswitch_active: false,
        };

        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"was_connected_on_exit\":false"));
        assert!(json.contains("\"killswitch_active\":false"));

        let parsed: PersistedState = serde_json::from_str(&json).unwrap();
        assert!(!parsed.was_connected_on_exit);
        assert!(!parsed.killswitch_active);
        assert_eq!(parsed.state, ConnectionState::Connecting);
    }

    #[test]
    fn test_persisted_state_backward_compatibility() {
        // Test that old state files without new fields can still be parsed
        let old_json = r#"{
            "state": "Connected",
            "server_id": "old-server",
            "server_name": "Old Server",
            "interface": "wg0",
            "connected_at": null,
            "pid": 1234,
            "was_connected_on_exit": true
        }"#;

        let parsed: PersistedState = serde_json::from_str(old_json).unwrap();
        assert!(parsed.was_connected_on_exit);
        assert_eq!(parsed.server_id, Some("old-server".to_string()));
        // New fields should default to None/false
        assert_eq!(parsed.server_country, None);
        assert_eq!(parsed.server_country_code, None);
        assert_eq!(parsed.server_city, None);
        assert_eq!(parsed.server_provider, None);
        assert_eq!(parsed.server_allowed_ips, None);
        assert!(!parsed.killswitch_active);
    }

    #[test]
    fn test_recover_state_no_file() {
        // Test recovery when no state file exists
        let temp_dir = std::env::temp_dir();
        let state_file = temp_dir.join("nonexistent_state_file_12345");

        // Ensure file doesn't exist
        let _ = std::fs::remove_file(&state_file);

        let manager = ConnectionManager {
            state: ConnectionState::Disconnected,
            current_server: None,
            interface: "wg0".to_string(),
            connected_at: None,
            last_error: None,
            original_public_ip: None,
            current_public_ip: None,
            killswitch_active: false,
            state_file: state_file.clone(),
        };

        // load_state should return None for non-existent file
        let loaded = manager.load_state().unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_persist_and_load_state() {
        let temp_dir = std::env::temp_dir();
        let state_file = temp_dir.join(format!("test_persist_load_{}", std::process::id()));

        let mut manager = ConnectionManager {
            state: ConnectionState::Connected,
            current_server: Some(crate::core::server::Server {
                id: "persist-test".to_string(),
                name: "Persist Test Server".to_string(),
                country: "US".to_string(),
                country_code: "US".to_string(),
                city: "Test City".to_string(),
                ip: "10.0.0.1".to_string(),
                pubkey: "testpubkey".to_string(),
                provider: "test".to_string(),
                features: crate::core::server::ServerFeatures::default(),
                is_custom: false,
                allowed_ips: "0.0.0.0/0".to_string(),
            }),
            interface: "wg_test".to_string(),
            connected_at: Some(Utc::now()),
            last_error: None,
            original_public_ip: None,
            current_public_ip: Some("203.0.113.99".to_string()),
            killswitch_active: true,
            state_file: state_file.clone(),
        };

        // Persist state
        manager.persist_state().unwrap();

        // Verify file exists
        assert!(state_file.exists());

        // Load state and verify
        let loaded = manager.load_state().unwrap().unwrap();
        assert_eq!(loaded.state, ConnectionState::Connected);
        assert_eq!(loaded.server_id, Some("persist-test".to_string()));
        assert_eq!(loaded.server_name, Some("Persist Test Server".to_string()));
        assert_eq!(loaded.interface, "wg_test");
        assert!(loaded.was_connected_on_exit); // Should be true because state is Connected
        assert_eq!(loaded.pid, std::process::id());

        // Cleanup
        let _ = std::fs::remove_file(&state_file);
    }
}
