//! Crash recovery and cleanup utilities

use crate::core::error::Result;
use crate::system::firewall::{cleanup_orphaned_killswitch, Ipv6Protection};
use std::fs;
use std::path::PathBuf;
use tracing::{info, warn};

/// Cleanup orphaned state from previous crashes
pub async fn cleanup_orphaned_state() -> Result<()> {
    info!("Running crash recovery check...");

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

    info!("Crash recovery check complete");
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
