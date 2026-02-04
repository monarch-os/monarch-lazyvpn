//! Crash recovery and cleanup utilities

use crate::core::config::AppConfig;
use crate::core::error::Result;
use crate::system::firewall::{cleanup_orphaned_killswitch, Ipv6Protection};
use std::fs;
use std::path::PathBuf;
use tracing::{info, warn};

/// Check if a PID is running
fn is_pid_running(pid: u32) -> bool {
    PathBuf::from(format!("/proc/{}", pid)).exists()
}

/// Cleanup orphaned state from previous crashes
pub async fn cleanup_orphaned_state() -> Result<()> {
    info!("Running crash recovery check...");

    // 1. Check for stale PID file
    cleanup_stale_pid_file()?;

    // 2. Cleanup orphaned killswitch rules
    cleanup_orphaned_killswitch().await?;

    // 3. Cleanup orphaned IPv6 state
    if let Ok(ipv6) = Ipv6Protection::new() {
        if ipv6.has_orphaned_state() {
            warn!("Found orphaned IPv6 state, recovering...");
            ipv6.recover_from_crash().await?;
        }
    }

    // 4. Cleanup orphaned temp config files
    cleanup_temp_configs()?;

    // 5. Cleanup orphaned connection state
    cleanup_connection_state()?;

    info!("Crash recovery check complete");
    Ok(())
}

/// Check and cleanup stale PID file
fn cleanup_stale_pid_file() -> Result<()> {
    let config_dir = AppConfig::config_dir()?;
    let pid_file = config_dir.join(".pid");

    if pid_file.exists() {
        if let Ok(content) = fs::read_to_string(&pid_file) {
            if let Ok(pid) = content.trim().parse::<u32>() {
                if !is_pid_running(pid) {
                    warn!("Found stale PID file for dead process {}", pid);
                    fs::remove_file(&pid_file)?;
                }
            }
        }
    }

    Ok(())
}

/// Cleanup orphaned temp config files
fn cleanup_temp_configs() -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let temp_dir = PathBuf::from(format!("/run/user/{}", uid));

    if !temp_dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(&temp_dir)? {
        let entry = entry?;
        let path = entry.path();

        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with("monarch-vpn-") && name.ends_with(".conf") {
                warn!("Removing orphaned temp config: {:?}", path);

                // Secure delete: overwrite with zeros before removing
                if let Ok(metadata) = fs::metadata(&path) {
                    let size = metadata.len() as usize;
                    let zeros = vec![0u8; size];
                    if let Ok(mut file) = fs::OpenOptions::new().write(true).open(&path) {
                        use std::io::Write;
                        let _ = file.write_all(&zeros);
                        let _ = file.sync_all();
                    }
                }

                fs::remove_file(&path)?;
            }
        }
    }

    Ok(())
}

/// Cleanup orphaned connection state
fn cleanup_connection_state() -> Result<()> {
    let config_dir = AppConfig::config_dir()?;
    let state_file = config_dir.join(".connection_state");

    if !state_file.exists() {
        return Ok(());
    }

    // Try to parse state and check if owner process is running
    if let Ok(content) = fs::read_to_string(&state_file) {
        if let Ok(state) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(pid) = state.get("pid").and_then(|p| p.as_u64()) {
                let pid = pid as u32;
                if !is_pid_running(pid) {
                    // Check if this is a preserved connection (intentionally left running)
                    let was_connected_on_exit = state
                        .get("was_connected_on_exit")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    // Check if VPN interface still exists
                    let interface_exists = state
                        .get("interface")
                        .and_then(|i| i.as_str())
                        .map(|interface| PathBuf::from(format!("/sys/class/net/{}", interface)).exists())
                        .unwrap_or(false);

                    if was_connected_on_exit && interface_exists {
                        // This is a preserved connection - don't clean up
                        // ConnectionManager::recover_state() will handle restoration
                        info!(
                            "Found preserved VPN connection state - will be restored on startup"
                        );
                        return Ok(());
                    }

                    warn!("Found orphaned connection state from dead process {}", pid);

                    // Check if VPN interface exists (for non-preserved cases)
                    if let Some(interface) = state.get("interface").and_then(|i| i.as_str()) {
                        let iface_path = format!("/sys/class/net/{}", interface);
                        if PathBuf::from(&iface_path).exists() {
                            warn!(
                                "VPN interface {} still exists - may need manual cleanup",
                                interface
                            );
                            // Don't auto-disconnect - could be dangerous
                            // Just warn and let user handle it
                        }
                    }

                    // Remove stale state file (only for non-preserved connections)
                    fs::remove_file(&state_file)?;
                }
            }
        }
    }

    Ok(())
}

/// Create PID file
pub fn create_pid_file() -> Result<()> {
    let config_dir = AppConfig::config_dir()?;
    fs::create_dir_all(&config_dir)?;

    let pid_file = config_dir.join(".pid");

    // Check if already running
    if pid_file.exists() {
        if let Ok(content) = fs::read_to_string(&pid_file) {
            if let Ok(pid) = content.trim().parse::<u32>() {
                if is_pid_running(pid) {
                    return Err(crate::core::error::VpnError::InstanceAlreadyRunning);
                }
            }
        }
    }

    // Write our PID
    fs::write(&pid_file, format!("{}", std::process::id()))?;
    Ok(())
}

/// Remove PID file
pub fn remove_pid_file() -> Result<()> {
    let config_dir = AppConfig::config_dir()?;
    let pid_file = config_dir.join(".pid");

    if pid_file.exists() {
        fs::remove_file(&pid_file)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_pid_running() {
        // Current process should be running
        assert!(is_pid_running(std::process::id()));

        // PID 1 (init) should be running
        assert!(is_pid_running(1));

        // Very high PID should not exist
        assert!(!is_pid_running(999999999));
    }
}
