//! WireGuard wg-quick wrapper with secure temp file handling

use crate::core::error::{Result, VpnError};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

const WG_QUICK_TIMEOUT_SECS: u64 = 30;
const MAX_INTERFACES: u8 = 10;
const SYS_CLASS_NET: &str = "/sys/class/net";

/// WireGuard interface manager
pub struct WgManager {
    interface: String,
    temp_config_path: Option<PathBuf>,
}

impl WgManager {
    /// Create a new WireGuard manager with specified interface
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
            temp_config_path: None,
        }
    }

    /// Find an available WireGuard interface name
    pub fn find_available_interface() -> Result<String> {
        for i in 0..MAX_INTERFACES {
            let name = format!("wg{}", i);
            if !Self::interface_exists(&name)? {
                debug!("Found available interface: {}", name);
                return Ok(name);
            }
        }

        Err(VpnError::InterfaceNotAvailable(format!(
            "All interfaces wg0-wg{} are in use",
            MAX_INTERFACES - 1
        )))
    }

    /// List all active WireGuard interfaces
    pub fn list_active_interfaces() -> Result<Vec<String>> {
        let mut interfaces = Vec::new();
        for i in 0..MAX_INTERFACES {
            let name = format!("wg{}", i);
            if Self::interface_exists(&name)? {
                interfaces.push(name);
            }
        }
        Ok(interfaces)
    }

    /// Cleanup all orphaned WireGuard interfaces
    pub async fn cleanup_all_interfaces() -> Result<()> {
        let interfaces = Self::list_active_interfaces()?;

        if interfaces.is_empty() {
            return Ok(());
        }

        warn!("Found {} orphaned WireGuard interface(s): {:?}", interfaces.len(), interfaces);

        for iface in interfaces {
            info!("Cleaning up interface: {}", iface);
            let mut manager = WgManager::new(&iface);
            if let Err(e) = manager.disconnect().await {
                warn!("Failed to cleanup {}: {}", iface, e);
            }
        }

        Ok(())
    }

    /// Check if an interface exists
    pub fn interface_exists(name: &str) -> Result<bool> {
        let path = PathBuf::from(format!("{}/{}", SYS_CLASS_NET, name));
        Ok(path.exists())
    }

    /// List all WireGuard interfaces via sysfs (no privileges needed)
    ///
    /// Detects WireGuard interfaces by checking the uevent file for DEVTYPE=wireguard
    pub fn list_wireguard_interfaces_sysfs() -> Vec<String> {
        let mut interfaces = Vec::new();

        let net_dir = match fs::read_dir(SYS_CLASS_NET) {
            Ok(dir) => dir,
            Err(_) => return interfaces,
        };

        for entry in net_dir.flatten() {
            let iface_name = match entry.file_name().into_string() {
                Ok(name) => name,
                Err(_) => continue,
            };

            // Check if it's a WireGuard interface via uevent
            let uevent_path = entry.path().join("uevent");
            if let Ok(content) = fs::read_to_string(&uevent_path) {
                if content.contains("DEVTYPE=wireguard") {
                    interfaces.push(iface_name);
                }
            }
        }

        interfaces.sort();
        interfaces
    }

    /// Get temp config directory (secure)
    fn temp_dir() -> Result<PathBuf> {
        // Use /run/user/{uid}/ for security (tmpfs, user-only)
        let uid = unsafe { libc::getuid() };
        let path = PathBuf::from(format!("/run/user/{}", uid));

        if !path.exists() {
            // Fallback to XDG_RUNTIME_DIR or /tmp with warning
            if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
                return Ok(PathBuf::from(runtime_dir));
            }
            warn!("Secure temp directory not available, falling back to /tmp");
            return Ok(PathBuf::from("/tmp"));
        }

        Ok(path)
    }

    /// Create temp config file with secure permissions
    /// The filename must be <interface>.conf for wg-quick to work
    fn create_temp_config(&mut self, config_content: &str) -> Result<PathBuf> {
        let temp_dir = Self::temp_dir()?;
        // wg-quick requires the config file to be named <interface>.conf
        let filename = format!("{}.conf", self.interface);
        let path = temp_dir.join(filename);

        // Create file with 0600 permissions BEFORE writing content
        {
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)?;

            // Verify permissions
            let metadata = file.metadata()?;
            let perms = metadata.permissions();
            if perms.mode() & 0o777 != 0o600 {
                fs::remove_file(&path)?;
                return Err(VpnError::IoError(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Failed to set secure file permissions",
                )));
            }
        }

        // Now write content to the secured file
        fs::write(&path, config_content)?;

        self.temp_config_path = Some(path.clone());
        debug!("Created temp config at {:?}", path);

        Ok(path)
    }

    /// Securely delete temp config (zero-overwrite before unlink)
    fn secure_delete_temp_config(&mut self) {
        if let Some(ref path) = self.temp_config_path {
            if path.exists() {
                // Get file size
                if let Ok(metadata) = fs::metadata(path) {
                    let size = metadata.len() as usize;

                    // Overwrite with zeros
                    if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
                        let zeros = vec![0u8; size];
                        let _ = file.write_all(&zeros);
                        let _ = file.sync_all();
                    }
                }

                // Delete file
                if let Err(e) = fs::remove_file(path) {
                    error!("Failed to remove temp config: {}", e);
                } else {
                    debug!("Securely deleted temp config: {:?}", path);
                }
            }
        }
        self.temp_config_path = None;
    }

    /// Check if pkexec is available
    fn has_pkexec() -> bool {
        std::process::Command::new("which")
            .arg("pkexec")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Run a command with privilege elevation
    async fn run_privileged(&self, args: &[&str]) -> Result<String> {
        let (cmd, cmd_args): (&str, Vec<&str>) = if Self::has_pkexec() {
            ("pkexec", args.to_vec())
        } else {
            ("sudo", args.to_vec())
        };

        debug!("Running: {} {:?}", cmd, cmd_args);

        let result = timeout(
            Duration::from_secs(WG_QUICK_TIMEOUT_SECS),
            Command::new(cmd)
                .args(&cmd_args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output(),
        )
        .await;

        match result {
            Ok(Ok(output)) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();

                if output.status.success() {
                    Ok(stdout)
                } else {
                    Err(VpnError::ConnectionError(format!(
                        "Command failed: {}",
                        if stderr.is_empty() { &stdout } else { &stderr }
                    )))
                }
            }
            Ok(Err(e)) => Err(VpnError::ConnectionError(format!(
                "Failed to execute command: {}",
                e
            ))),
            Err(_) => {
                // Timeout - try to kill the process
                warn!("Command timed out after {}s", WG_QUICK_TIMEOUT_SECS);
                Err(VpnError::TimeoutError(format!(
                    "Command timed out after {}s",
                    WG_QUICK_TIMEOUT_SECS
                )))
            }
        }
    }

    /// Connect to VPN using wg-quick
    pub async fn connect(&mut self, config_content: &str) -> Result<()> {
        // Check if interface already exists
        if Self::interface_exists(&self.interface)? {
            return Err(VpnError::AlreadyConnected);
        }

        // Create secure temp config
        let config_path = self.create_temp_config(config_content)?;
        let config_path_str = config_path.to_string_lossy();

        info!("Connecting via wg-quick up...");

        let result = self
            .run_privileged(&["wg-quick", "up", &config_path_str])
            .await;

        // Always cleanup temp config
        self.secure_delete_temp_config();

        result.map(|_| {
            info!("VPN connected successfully on {}", self.interface);
        })
    }

    /// Disconnect from VPN
    pub async fn disconnect(&mut self) -> Result<()> {
        if !Self::interface_exists(&self.interface)? {
            return Err(VpnError::NotConnected);
        }

        info!("Disconnecting interface {}...", self.interface);

        // Try wg-quick down first (works if config is in /etc/wireguard/)
        let wg_quick_result = self
            .run_privileged(&["wg-quick", "down", &self.interface])
            .await;

        if wg_quick_result.is_ok() {
            info!("VPN disconnected via wg-quick");
            return Ok(());
        }

        // Fallback: manually tear down the interface
        // This is needed when using temp config files outside /etc/wireguard/
        warn!("wg-quick down failed, using manual teardown");

        // Step 1: Delete the interface
        let ip_result = self
            .run_privileged(&["ip", "link", "delete", "dev", &self.interface])
            .await;

        if let Err(e) = ip_result {
            // Check if interface is already gone
            if Self::interface_exists(&self.interface)? {
                return Err(VpnError::ConnectionError(format!(
                    "Failed to delete interface: {}",
                    e
                )));
            }
        }

        // Step 2: Clean up nftables table created by wg-quick
        // wg-quick creates a table named "wg-quick-<interface>"
        let table_name = format!("wg-quick-{}", self.interface);
        let nft_result = self
            .run_privileged(&["nft", "delete", "table", "ip", &table_name])
            .await;

        if let Err(e) = nft_result {
            // Not critical - table might not exist
            debug!("Could not delete nftables table {}: {}", table_name, e);
        } else {
            info!("Cleaned up nftables table {}", table_name);
        }

        info!("VPN disconnected (manual teardown)");
        Ok(())
    }

    /// Check if VPN interface is up
    pub fn is_connected(&self) -> Result<bool> {
        Self::interface_exists(&self.interface)
    }

    /// Get interface name
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Set interface name
    pub fn set_interface(&mut self, interface: &str) {
        self.interface = interface.to_string();
    }

    /// Get interface statistics
    pub fn get_stats(&self) -> Result<InterfaceStats> {
        if !Self::interface_exists(&self.interface)? {
            return Err(VpnError::NotConnected);
        }

        let rx_bytes = fs::read_to_string(format!(
            "/sys/class/net/{}/statistics/rx_bytes",
            self.interface
        ))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

        let tx_bytes = fs::read_to_string(format!(
            "/sys/class/net/{}/statistics/tx_bytes",
            self.interface
        ))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

        Ok(InterfaceStats { rx_bytes, tx_bytes })
    }

    /// Validate interface name to prevent command injection
    /// Only allows alphanumeric characters, underscores, and hyphens
    fn is_valid_interface_name(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= 15 // Linux interface name limit
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    }

    /// Get WireGuard endpoint for an interface via `wg show`
    /// Returns the endpoint (IP:port) of the first peer
    pub async fn get_wg_endpoint(iface: &str) -> Option<String> {
        if !Self::is_valid_interface_name(iface) {
            return None;
        }

        let output = Command::new("wg")
            .args(["show", iface, "endpoints"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Format: <peer_pubkey>\t<endpoint>\n
        // Take first line, split by tab, get second part
        stdout
            .lines()
            .next()
            .and_then(|line| line.split('\t').nth(1))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "(none)")
    }

    /// Get WireGuard allowed-ips for an interface via `wg show`
    /// Returns the allowed IPs of the first peer
    pub async fn get_wg_allowed_ips(iface: &str) -> Option<String> {
        if !Self::is_valid_interface_name(iface) {
            return None;
        }

        let output = Command::new("wg")
            .args(["show", iface, "allowed-ips"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Format: <peer_pubkey>\t<allowed_ips>\n
        // Take first line, split by tab, get second part
        stdout
            .lines()
            .next()
            .and_then(|line| line.split('\t').nth(1))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Get WireGuard latest handshake age for an interface
    /// Returns the duration since the last handshake
    pub async fn get_wg_handshake_age(iface: &str) -> Option<std::time::Duration> {
        if !Self::is_valid_interface_name(iface) {
            return None;
        }

        let output = Command::new("wg")
            .args(["show", iface, "latest-handshakes"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Format: <peer_pubkey>\t<timestamp>\n
        // timestamp is Unix seconds, 0 means never
        let timestamp: u64 = stdout
            .lines()
            .next()
            .and_then(|line| line.split('\t').nth(1))
            .and_then(|s| s.trim().parse().ok())?;

        if timestamp == 0 {
            return None; // Never had a handshake
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;

        let handshake_time = std::time::Duration::from_secs(timestamp);

        if now > handshake_time {
            Some(now - handshake_time)
        } else {
            Some(std::time::Duration::ZERO)
        }
    }
}

impl Drop for WgManager {
    fn drop(&mut self) {
        // Ensure temp config is cleaned up
        self.secure_delete_temp_config();
    }
}

/// Interface statistics
#[derive(Debug, Clone)]
pub struct InterfaceStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl InterfaceStats {
    /// Format bytes as human-readable string
    pub fn format_bytes(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;

        if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} B", bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(InterfaceStats::format_bytes(0), "0 B");
        assert_eq!(InterfaceStats::format_bytes(500), "500 B");
        assert_eq!(InterfaceStats::format_bytes(1024), "1.00 KB");
        assert_eq!(InterfaceStats::format_bytes(1536), "1.50 KB");
        assert_eq!(InterfaceStats::format_bytes(1048576), "1.00 MB");
        assert_eq!(InterfaceStats::format_bytes(1572864), "1.50 MB");
        assert_eq!(InterfaceStats::format_bytes(1073741824), "1.00 GB");
        assert_eq!(InterfaceStats::format_bytes(2147483648), "2.00 GB");
    }

    #[test]
    fn test_interface_name() {
        let manager = WgManager::new("wg0");
        assert_eq!(manager.interface(), "wg0");

        let mut manager2 = WgManager::new("wg1");
        assert_eq!(manager2.interface(), "wg1");
        manager2.set_interface("wg5");
        assert_eq!(manager2.interface(), "wg5");
    }

    #[test]
    fn test_find_available_interface() {
        // This test can only verify the function runs without panic
        // Actual availability depends on system state
        let result = WgManager::find_available_interface();
        // Should return either Ok(interface_name) or Err if all 10 interfaces are taken
        match result {
            Ok(iface) => {
                assert!(iface.starts_with("wg"));
                assert!(iface.len() >= 3); // "wg0" minimum
            }
            Err(VpnError::InterfaceNotAvailable(_)) => {
                // All interfaces taken - acceptable in test
            }
            _ => panic!("Unexpected error type"),
        }
    }

    #[test]
    fn test_temp_dir() {
        let temp_dir = WgManager::temp_dir();
        assert!(temp_dir.is_ok());
        let path = temp_dir.unwrap();
        // Should be /run/user/{uid} or fallback to XDG_RUNTIME_DIR or /tmp
        assert!(
            path.to_string_lossy().contains("/run/user/")
                || path.to_string_lossy().contains("/tmp")
                || std::env::var("XDG_RUNTIME_DIR")
                    .map(|d| path == std::path::PathBuf::from(d))
                    .unwrap_or(false)
        );
    }

    #[test]
    fn test_interface_exists() {
        // Test for loopback interface which should always exist
        assert!(WgManager::interface_exists("lo").unwrap_or(false));

        // Test for non-existent interface
        assert!(!WgManager::interface_exists("nonexistent9999").unwrap_or(true));
    }

    #[test]
    fn test_max_interfaces_constant() {
        assert_eq!(MAX_INTERFACES, 10);
        // Verify error message format
        let result = WgManager::find_available_interface();
        if let Err(VpnError::InterfaceNotAvailable(msg)) = result {
            assert!(msg.contains("wg0-wg9"));
        }
    }

    #[test]
    fn test_parse_wg_endpoint_output() {
        // Test parsing of `wg show <iface> endpoints` output
        let output = "abc123pubkey=\t1.2.3.4:51820\n";
        let result = output
            .lines()
            .next()
            .and_then(|line| line.split('\t').nth(1))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "(none)");
        assert_eq!(result, Some("1.2.3.4:51820".to_string()));
    }

    #[test]
    fn test_parse_wg_endpoint_output_multi_peer() {
        // Test with multiple peers - should take first
        let output = "peer1pubkey=\t1.2.3.4:51820\npeer2pubkey=\t5.6.7.8:51820\n";
        let result = output
            .lines()
            .next()
            .and_then(|line| line.split('\t').nth(1))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "(none)");
        assert_eq!(result, Some("1.2.3.4:51820".to_string()));
    }

    #[test]
    fn test_parse_wg_endpoint_none() {
        // Test with no endpoint (local peer)
        let output = "abc123pubkey=\t(none)\n";
        let result = output
            .lines()
            .next()
            .and_then(|line| line.split('\t').nth(1))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "(none)");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_wg_allowed_ips_output() {
        // Test parsing of `wg show <iface> allowed-ips` output
        let output = "abc123pubkey=\t0.0.0.0/0, ::/0\n";
        let result = output
            .lines()
            .next()
            .and_then(|line| line.split('\t').nth(1))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        assert_eq!(result, Some("0.0.0.0/0, ::/0".to_string()));
    }

    #[test]
    fn test_parse_wg_allowed_ips_split_tunnel() {
        // Test with split tunnel config (specific IPs only)
        let output = "abc123pubkey=\t10.0.0.0/8, 192.168.1.0/24\n";
        let result = output
            .lines()
            .next()
            .and_then(|line| line.split('\t').nth(1))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        assert_eq!(result, Some("10.0.0.0/8, 192.168.1.0/24".to_string()));
        // Check it's a split tunnel (doesn't contain 0.0.0.0/0)
        assert!(!result.unwrap().contains("0.0.0.0/0"));
    }

    #[test]
    fn test_parse_wg_handshake_output() {
        // Test parsing of `wg show <iface> latest-handshakes` output
        let output = "abc123pubkey=\t1707123456\n";
        let result: Option<u64> = output
            .lines()
            .next()
            .and_then(|line| line.split('\t').nth(1))
            .and_then(|s| s.trim().parse().ok());
        assert_eq!(result, Some(1707123456));
    }

    #[test]
    fn test_parse_wg_handshake_never() {
        // Test with no handshake yet (timestamp 0)
        let output = "abc123pubkey=\t0\n";
        let result: Option<u64> = output
            .lines()
            .next()
            .and_then(|line| line.split('\t').nth(1))
            .and_then(|s| s.trim().parse().ok());
        assert_eq!(result, Some(0));
        // 0 means never had a handshake
    }

    #[test]
    fn test_list_wireguard_interfaces_sysfs() {
        // This test verifies the function runs without error
        // Actual detection depends on system state
        let interfaces = WgManager::list_wireguard_interfaces_sysfs();
        // Should return a vector (possibly empty)
        assert!(interfaces.len() <= MAX_INTERFACES as usize);
        // All interface names should start with reasonable characters
        for iface in &interfaces {
            assert!(!iface.is_empty());
        }
    }
}
