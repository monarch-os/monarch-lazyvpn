//! Network change detection and auto-reconnect

use crate::core::error::{Result, VpnError};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Network change event
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// Interface went up
    InterfaceUp(String),
    /// Interface went down
    InterfaceDown(String),
    /// IP address changed
    AddressChanged(String),
    /// Default route changed
    RouteChanged,
}

/// Network state for comparison
#[derive(Debug, Clone, Default)]
struct NetworkState {
    interfaces: HashSet<String>,
    default_gateway: Option<String>,
}

impl NetworkState {
    /// Get current network state
    fn current() -> Self {
        let mut state = NetworkState::default();

        // Get list of up interfaces
        if let Ok(entries) = fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                
                // Check if interface is up
                let operstate_path = entry.path().join("operstate");
                if let Ok(operstate) = fs::read_to_string(&operstate_path) {
                    if operstate.trim() == "up" {
                        state.interfaces.insert(name);
                    }
                }
            }
        }

        // Get default gateway
        if let Ok(content) = fs::read_to_string("/proc/net/route") {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && parts[1] == "00000000" {
                    // Default route found
                    let gateway_hex = parts[2];
                    if let Some(gateway) = hex_to_ip(gateway_hex) {
                        state.default_gateway = Some(gateway);
                        break;
                    }
                }
            }
        }

        state
    }

    /// Compare with another state and return changes
    fn diff(&self, other: &NetworkState) -> Vec<NetworkEvent> {
        let mut events = Vec::new();

        // Check for interfaces that went down
        for iface in &self.interfaces {
            if !other.interfaces.contains(iface) {
                events.push(NetworkEvent::InterfaceDown(iface.clone()));
            }
        }

        // Check for interfaces that came up
        for iface in &other.interfaces {
            if !self.interfaces.contains(iface) {
                events.push(NetworkEvent::InterfaceUp(iface.clone()));
            }
        }

        // Check for gateway change
        if self.default_gateway != other.default_gateway {
            events.push(NetworkEvent::RouteChanged);
        }

        events
    }
}

/// Convert hex IP from /proc/net/route to dotted decimal
fn hex_to_ip(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }

    let bytes: std::result::Result<Vec<u8>, _> = (0..4)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16))
        .collect();

    match bytes {
        Ok(b) => Some(format!("{}.{}.{}.{}", b[3], b[2], b[1], b[0])),
        Err(_) => None,
    }
}

/// Network monitor for detecting changes
pub struct NetworkMonitor {
    last_state: NetworkState,
    vpn_interface: Option<String>,
}

impl NetworkMonitor {
    /// Create a new network monitor
    pub fn new() -> Self {
        Self {
            last_state: NetworkState::current(),
            vpn_interface: None,
        }
    }

    /// Set the VPN interface to monitor
    pub fn set_vpn_interface(&mut self, interface: &str) {
        self.vpn_interface = Some(interface.to_string());
    }

    /// Clear VPN interface (on disconnect)
    pub fn clear_vpn_interface(&mut self) {
        self.vpn_interface = None;
    }

    /// Check for network changes
    pub fn check_changes(&mut self) -> Vec<NetworkEvent> {
        let current = NetworkState::current();
        let events = self.last_state.diff(&current);
        self.last_state = current;
        events
    }

    /// Check if VPN interface is still up
    pub fn is_vpn_up(&self) -> bool {
        if let Some(ref iface) = self.vpn_interface {
            self.last_state.interfaces.contains(iface)
        } else {
            false
        }
    }

    /// Check if VPN interface went down unexpectedly
    pub fn vpn_went_down(&mut self) -> bool {
        if let Some(ref iface) = self.vpn_interface {
            let current = NetworkState::current();
            let was_up = self.last_state.interfaces.contains(iface);
            let is_up = current.interfaces.contains(iface);
            self.last_state = current;
            was_up && !is_up
        } else {
            false
        }
    }
}

impl Default for NetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Async network change watcher
pub struct NetworkWatcher {
    tx: mpsc::Sender<NetworkEvent>,
    monitor: NetworkMonitor,
    running: bool,
}

impl NetworkWatcher {
    /// Create a new network watcher
    pub fn new() -> (Self, mpsc::Receiver<NetworkEvent>) {
        let (tx, rx) = mpsc::channel(16);
        (
            Self {
                tx,
                monitor: NetworkMonitor::new(),
                running: false,
            },
            rx,
        )
    }

    /// Start watching for network changes
    pub async fn start(&mut self) {
        self.running = true;
        info!("Network watcher started");

        while self.running {
            // Poll for changes every second
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            let events = self.monitor.check_changes();
            for event in events {
                debug!("Network event: {:?}", event);
                if self.tx.send(event).await.is_err() {
                    warn!("Failed to send network event");
                    break;
                }
            }
        }
    }

    /// Stop watching
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Set VPN interface to monitor
    pub fn set_vpn_interface(&mut self, interface: &str) {
        self.monitor.set_vpn_interface(interface);
    }

    /// Clear VPN interface
    pub fn clear_vpn_interface(&mut self) {
        self.monitor.clear_vpn_interface();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_ip() {
        assert_eq!(hex_to_ip("0100A8C0"), Some("192.168.0.1".to_string()));
        assert_eq!(hex_to_ip("0101A8C0"), Some("192.168.1.1".to_string()));
        assert_eq!(hex_to_ip("invalid"), None);
    }

    #[test]
    fn test_network_state() {
        let state = NetworkState::current();
        // Should be able to get network state without crashing
        // lo might be down in some container environments
        let _ = state.interfaces;
    }

    #[test]
    fn test_network_monitor() {
        let mut monitor = NetworkMonitor::new();
        
        // First check should return no events (initial state)
        let events = monitor.check_changes();
        assert!(events.is_empty());
    }
}
