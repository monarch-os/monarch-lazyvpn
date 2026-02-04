//! nftables killswitch implementation

use crate::core::error::{Result, VpnError};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

const NFT_TIMEOUT_SECS: u64 = 10;

const TABLE_NAME: &str = "monarch_killswitch";
const CHAIN_INPUT: &str = "input";
const CHAIN_OUTPUT: &str = "output";
const CHAIN_FORWARD: &str = "forward";

/// Killswitch manager using nftables
pub struct Killswitch {
    interface: String,
    server_ip: String,
    allow_lan: bool,
    lan_ranges: Vec<String>,
}

impl Killswitch {
    /// Create a new killswitch instance
    pub fn new(interface: &str, server_ip: &str, allow_lan: bool, lan_ranges: Vec<String>) -> Self {
        Self {
            interface: interface.to_string(),
            server_ip: server_ip.to_string(),
            allow_lan,
            lan_ranges,
        }
    }

    /// Generate nftables ruleset
    fn generate_ruleset(&self) -> String {
        let mut rules = String::new();

        // Flush existing table if exists
        rules.push_str(&format!("table inet {} {{\n", TABLE_NAME));
        rules.push_str("  # Monarch LazyVPN Killswitch\n\n");

        // Input chain
        rules.push_str(&format!("  chain {} {{\n", CHAIN_INPUT));
        rules.push_str("    type filter hook input priority 0; policy drop;\n");
        rules.push_str("\n");
        rules.push_str("    # Allow loopback\n");
        rules.push_str("    iifname \"lo\" accept\n");
        rules.push_str("\n");
        rules.push_str("    # Allow established connections\n");
        rules.push_str("    ct state established,related accept\n");
        rules.push_str("\n");
        rules.push_str(&format!(
            "    # Allow traffic through VPN interface\n    iifname \"{}\" accept\n",
            self.interface
        ));

        // LAN exceptions
        if self.allow_lan {
            rules.push_str("\n    # Allow LAN traffic\n");
            for range in &self.lan_ranges {
                rules.push_str(&format!("    ip saddr {} accept\n", range));
            }
        }

        rules.push_str("  }\n\n");

        // Output chain
        rules.push_str(&format!("  chain {} {{\n", CHAIN_OUTPUT));
        rules.push_str("    type filter hook output priority 0; policy drop;\n");
        rules.push_str("\n");
        rules.push_str("    # Allow loopback\n");
        rules.push_str("    oifname \"lo\" accept\n");
        rules.push_str("\n");
        rules.push_str("    # Allow established connections\n");
        rules.push_str("    ct state established,related accept\n");
        rules.push_str("\n");
        rules.push_str(&format!(
            "    # Allow traffic to VPN server\n    ip daddr {} accept\n",
            self.server_ip
        ));
        rules.push_str("\n");
        rules.push_str(&format!(
            "    # Allow traffic through VPN interface\n    oifname \"{}\" accept\n",
            self.interface
        ));

        // LAN exceptions
        if self.allow_lan {
            rules.push_str("\n    # Allow LAN traffic\n");
            for range in &self.lan_ranges {
                rules.push_str(&format!("    ip daddr {} accept\n", range));
            }
        }

        rules.push_str("  }\n\n");

        // Forward chain (block all)
        rules.push_str(&format!("  chain {} {{\n", CHAIN_FORWARD));
        rules.push_str("    type filter hook forward priority 0; policy drop;\n");
        rules.push_str("  }\n");

        rules.push_str("}\n\n");

        // Block IPv6 completely
        rules.push_str("table ip6 monarch_killswitch_v6 {\n");
        rules.push_str("  chain input {\n");
        rules.push_str("    type filter hook input priority 0; policy drop;\n");
        rules.push_str("    iifname \"lo\" accept\n");
        rules.push_str("  }\n");
        rules.push_str("  chain output {\n");
        rules.push_str("    type filter hook output priority 0; policy drop;\n");
        rules.push_str("    oifname \"lo\" accept\n");
        rules.push_str("  }\n");
        rules.push_str("  chain forward {\n");
        rules.push_str("    type filter hook forward priority 0; policy drop;\n");
        rules.push_str("  }\n");
        rules.push_str("}\n");

        rules
    }

    /// Write ruleset to temp file
    fn write_ruleset(&self) -> Result<std::path::PathBuf> {
        let uid = unsafe { libc::getuid() };
        let path = std::path::PathBuf::from(format!(
            "/run/user/{}/monarch-killswitch.nft",
            uid
        ));

        let ruleset = self.generate_ruleset();

        // Create file with 0600 permissions
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;

        file.write_all(ruleset.as_bytes())?;
        debug!("Wrote nftables ruleset to {:?}", path);

        Ok(path)
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

    /// Run nft command with privileges and timeout
    async fn run_nft(&self, args: &[&str]) -> Result<String> {
        let (cmd, cmd_args): (&str, Vec<&str>) = if Self::has_pkexec() {
            let mut a = vec!["nft"];
            a.extend_from_slice(args);
            ("pkexec", a)
        } else {
            let mut a = vec![];
            a.extend_from_slice(args);
            ("sudo", {
                let mut s = vec!["nft"];
                s.extend_from_slice(args);
                s
            })
        };

        debug!("Running: {} {:?}", cmd, cmd_args);

        let output = timeout(
            Duration::from_secs(NFT_TIMEOUT_SECS),
            Command::new(cmd)
                .args(&cmd_args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output(),
        )
        .await
        .map_err(|_| {
            VpnError::TimeoutError(format!(
                "nft command timed out after {}s",
                NFT_TIMEOUT_SECS
            ))
        })?
        .map_err(|e| VpnError::FirewallError(format!("Failed to run nft: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if output.status.success() {
            Ok(stdout)
        } else {
            Err(VpnError::FirewallError(format!(
                "nft command failed: {}",
                if stderr.is_empty() { &stdout } else { &stderr }
            )))
        }
    }

    /// Enable killswitch (atomic apply)
    pub async fn enable(&self) -> Result<()> {
        info!("Enabling killswitch...");

        // Write ruleset to file
        let ruleset_path = self.write_ruleset()?;
        let path_str = ruleset_path.to_string_lossy();

        // Apply atomically with nft -f
        let result = self.run_nft(&["-f", &path_str]).await;

        // Cleanup ruleset file
        let _ = fs::remove_file(&ruleset_path);

        result?;

        // Verify rules were applied
        self.verify().await?;

        info!("Killswitch enabled successfully");
        Ok(())
    }

    /// Disable killswitch (atomic deletion of both tables)
    pub async fn disable(&self) -> Result<()> {
        info!("Disabling killswitch...");

        // Create batch script for atomic deletion
        let batch_script = format!(
            "delete table inet {}\ndelete table ip6 monarch_killswitch_v6\n",
            TABLE_NAME
        );

        // Write to temp file
        let uid = unsafe { libc::getuid() };
        let temp_path =
            std::path::PathBuf::from(format!("/run/user/{}/monarch-ks-disable.nft", uid));

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp_path)
            .map_err(|e| VpnError::FirewallError(format!("Failed to create temp file: {}", e)))?;

        file.write_all(batch_script.as_bytes())
            .map_err(|e| VpnError::FirewallError(format!("Failed to write batch script: {}", e)))?;

        // Apply atomically (nft -f tolerates missing tables)
        let result = self.run_nft(&["-f", &temp_path.to_string_lossy()]).await;

        // Cleanup temp file
        let _ = fs::remove_file(&temp_path);

        // Handle result - ignore "table does not exist" errors
        match result {
            Ok(_) => {
                info!("Killswitch disabled");
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("No such file")
                    || err_str.contains("does not exist")
                    || err_str.contains("No such table")
                {
                    info!("Killswitch tables already removed");
                } else {
                    error!("Failed to disable killswitch: {}", e);
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Verify killswitch is active
    pub async fn verify(&self) -> Result<()> {
        let output = self
            .run_nft(&["list", "table", "inet", TABLE_NAME])
            .await?;

        // Check for expected chains
        if !output.contains(CHAIN_INPUT)
            || !output.contains(CHAIN_OUTPUT)
            || !output.contains(&self.interface)
        {
            return Err(VpnError::FirewallError(
                "Killswitch rules not properly applied".to_string(),
            ));
        }

        debug!("Killswitch verified active");
        Ok(())
    }

    /// Check if killswitch is active
    pub async fn is_active(&self) -> bool {
        self.run_nft(&["list", "table", "inet", TABLE_NAME])
            .await
            .is_ok()
    }
}

/// Check for orphaned killswitch rules
pub async fn has_orphaned_killswitch() -> bool {
    // Check if table exists
    let output = Command::new("nft")
        .args(["list", "tables"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await;

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.contains(TABLE_NAME)
        }
        Err(_) => false,
    }
}

/// Cleanup orphaned killswitch rules
pub async fn cleanup_orphaned_killswitch() -> Result<()> {
    if has_orphaned_killswitch().await {
        warn!("Found orphaned killswitch rules, cleaning up...");

        let has_pkexec = Killswitch::has_pkexec();
        let (cmd, args_inet, args_v6): (&str, Vec<&str>, Vec<&str>) = if has_pkexec {
            (
                "pkexec",
                vec!["nft", "delete", "table", "inet", TABLE_NAME],
                vec!["nft", "delete", "table", "ip6", "monarch_killswitch_v6"],
            )
        } else {
            (
                "sudo",
                vec!["nft", "delete", "table", "inet", TABLE_NAME],
                vec!["nft", "delete", "table", "ip6", "monarch_killswitch_v6"],
            )
        };

        let _ = Command::new(cmd)
            .args(&args_inet)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .await;

        let _ = Command::new(cmd)
            .args(&args_v6)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .await;

        info!("Orphaned killswitch rules cleaned up");
    }

    Ok(())
}

/// IPv6 leak protection manager
pub struct Ipv6Protection {
    state_file: std::path::PathBuf,
}

/// IPv6 state for crash recovery
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Ipv6State {
    original_value: i32,
    timestamp: String,
    pid: u32,
}

impl Ipv6Protection {
    /// Create a new IPv6 protection instance
    pub fn new() -> Result<Self> {
        let config_dir = crate::core::config::AppConfig::config_dir()?;
        Ok(Self {
            state_file: config_dir.join(".ipv6_state"),
        })
    }

    /// Get current IPv6 state via sysctl
    async fn get_ipv6_state() -> Result<i32> {
        let output = Command::new("sysctl")
            .args(["-n", "net.ipv6.conf.all.disable_ipv6"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| VpnError::NetworkError(format!("Failed to read IPv6 state: {}", e)))?;

        let value = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<i32>()
            .unwrap_or(0);

        Ok(value)
    }

    /// Set IPv6 state via sysctl
    async fn set_ipv6_state(disable: bool) -> Result<()> {
        let value = if disable { "1" } else { "0" };
        let sysctl_arg = format!("net.ipv6.conf.all.disable_ipv6={}", value);

        let has_pkexec = Killswitch::has_pkexec();
        let (cmd, args): (&str, Vec<&str>) = if has_pkexec {
            ("pkexec", vec!["sysctl", "-w", &sysctl_arg])
        } else {
            ("sudo", vec!["sysctl", "-w", &sysctl_arg])
        };

        let output = Command::new(cmd)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| VpnError::NetworkError(format!("Failed to set IPv6 state: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("sysctl failed (falling back to nftables-only IPv6 blocking): {}", stderr);
            // Fallback is handled by nftables rules in firewall.rs
        }

        Ok(())
    }

    /// Check if a process is running
    fn is_pid_running(pid: u32) -> bool {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }

    /// Save current state before disabling
    fn save_state(&self, original_value: i32) -> Result<()> {
        let state = Ipv6State {
            original_value,
            timestamp: chrono::Utc::now().to_rfc3339(),
            pid: std::process::id(),
        };

        let content = serde_json::to_string_pretty(&state)?;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.state_file)?;

        file.write_all(content.as_bytes())?;
        debug!("Saved IPv6 state: {:?}", state);

        Ok(())
    }

    /// Load saved state
    fn load_state(&self) -> Result<Option<Ipv6State>> {
        if !self.state_file.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&self.state_file)?;
        let state: Ipv6State = serde_json::from_str(&content)
            .map_err(|e| VpnError::ConfigParseError(format!("Invalid IPv6 state file: {}", e)))?;

        Ok(Some(state))
    }

    /// Remove state file
    fn remove_state(&self) {
        if self.state_file.exists() {
            let _ = fs::remove_file(&self.state_file);
        }
    }

    /// Recover from crash if needed
    pub async fn recover_from_crash(&self) -> Result<()> {
        if let Some(state) = self.load_state()? {
            // Check if the process that created this state is still running
            if !Self::is_pid_running(state.pid) {
                warn!(
                    "Found orphaned IPv6 state from dead process {}. Restoring...",
                    state.pid
                );

                // Restore original value
                let restore_to = if state.original_value == 0 {
                    false // Enable IPv6
                } else {
                    true // Keep IPv6 disabled
                };

                Self::set_ipv6_state(restore_to).await?;
                self.remove_state();
                info!("IPv6 state restored to original value: {}", state.original_value);
            }
        }

        Ok(())
    }

    /// Disable IPv6 for leak protection
    pub async fn disable(&self) -> Result<()> {
        info!("Disabling IPv6 for leak protection...");

        // First, recover from any previous crash
        self.recover_from_crash().await?;

        // Get current state
        let current = Self::get_ipv6_state().await?;

        // Save state before changing
        self.save_state(current)?;

        // Disable IPv6
        Self::set_ipv6_state(true).await?;

        info!("IPv6 disabled");
        Ok(())
    }

    /// Restore IPv6 to original state
    pub async fn restore(&self) -> Result<()> {
        info!("Restoring IPv6 state...");

        let should_disable_ipv6 = match self.load_state()? {
            Some(state) => {
                debug!("Restoring IPv6 to saved value: {}", state.original_value);
                // original_value: 0 = enabled, 1 = disabled
                // Return true if we should disable (original was disabled)
                state.original_value == 1
            }
            None => {
                // Fallback: assume IPv6 was enabled, so don't disable
                warn!("No saved IPv6 state found, defaulting to enabled");
                false
            }
        };

        Self::set_ipv6_state(should_disable_ipv6).await?;
        self.remove_state();

        info!("IPv6 state restored");
        Ok(())
    }

    /// Check for orphaned IPv6 state file
    pub fn has_orphaned_state(&self) -> bool {
        if let Ok(Some(state)) = self.load_state() {
            !Self::is_pid_running(state.pid)
        } else {
            false
        }
    }
}

impl Default for Ipv6Protection {
    fn default() -> Self {
        Self::new().expect("Failed to create IPv6 protection")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ruleset_basic() {
        let ks = Killswitch::new("wg0", "1.2.3.4", false, vec![]);
        let ruleset = ks.generate_ruleset();

        assert!(ruleset.contains("table inet monarch_killswitch"));
        assert!(ruleset.contains("chain input"));
        assert!(ruleset.contains("chain output"));
        assert!(ruleset.contains("policy drop"));
        assert!(ruleset.contains("iifname \"wg0\" accept"));
        assert!(ruleset.contains("ip daddr 1.2.3.4 accept"));
    }

    #[test]
    fn test_generate_ruleset_with_lan() {
        let lan_ranges = vec!["192.168.0.0/16".to_string(), "10.0.0.0/8".to_string()];
        let ks = Killswitch::new("wg0", "1.2.3.4", true, lan_ranges);
        let ruleset = ks.generate_ruleset();

        assert!(ruleset.contains("ip saddr 192.168.0.0/16 accept"));
        assert!(ruleset.contains("ip daddr 10.0.0.0/8 accept"));
    }

    #[test]
    fn test_generate_ruleset_ipv6_block() {
        let ks = Killswitch::new("wg0", "1.2.3.4", false, vec![]);
        let ruleset = ks.generate_ruleset();

        assert!(ruleset.contains("table ip6 monarch_killswitch_v6"));
        assert!(ruleset.contains("policy drop"));
    }
}
