//! Lightweight status binary for Waybar/Polybar integration
//!
//! Usage in Waybar config:
//! ```json
//! "custom/vpn": {
//!     "exec": "monarch-lazyvpn-status",
//!     "return-type": "json",
//!     "interval": 5
//! }
//! ```
//!
//! Usage in Polybar config:
//! ```ini
//! [module/vpn]
//! type = custom/script
//! exec = monarch-lazyvpn-status --format=text
//! interval = 5
//! ```

use clap::{Parser, ValueEnum};
use serde::Serialize;
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "monarch-lazyvpn-status")]
#[command(about = "Lightweight VPN status for Waybar/Polybar")]
struct Cli {
    /// Output format
    #[arg(short, long, value_enum, default_value = "waybar")]
    format: Format,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    /// Waybar JSON format
    Waybar,
    /// Plain text (Polybar)
    Text,
    /// Full JSON
    Json,
}

/// nf-md-vpn. The single glyph every visible state uses; the class carries the
/// state, so the bar colours one icon rather than swapping between several.
const VPN_GLYPH: &str = "󰖂";

/// Waybar custom module output
#[derive(Serialize)]
struct WaybarOutput {
    text: String,
    tooltip: String,
    class: String,
    percentage: u8,
}

fn main() {
    let cli = Cli::parse();

    let status = read_status();

    match cli.format {
        Format::Waybar => {
            let output = WaybarOutput {
                text: status.text.clone(),
                tooltip: status.tooltip.clone(),
                class: status.class.clone(),
                percentage: if status.connected { 100 } else { 0 },
            };
            println!("{}", serde_json::to_string(&output).unwrap_or_default());
        }
        Format::Text => {
            println!("{}", status.text);
        }
        Format::Json => {
            let output = json!({
                "connected": status.connected,
                "server": status.server,
                "ip": status.ip,
                "uptime": status.uptime,
                "interface": status.interface,
                "killswitch_active": status.killswitch_active,
                "split_tunnel": status.split_tunnel,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&output).unwrap_or_default()
            );
        }
    }
}

struct Status {
    connected: bool,
    server: Option<String>,
    ip: Option<String>,
    uptime: Option<String>,
    interface: Option<String>,
    killswitch_active: bool,
    split_tunnel: bool,
    text: String,
    tooltip: String,
    class: String,
}

/// List WireGuard interfaces via sysfs (no privileges needed)
fn list_wireguard_interfaces_sysfs() -> Vec<String> {
    let mut interfaces = Vec::new();

    let net_dir = match fs::read_dir("/sys/class/net") {
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

/// Validate interface name to prevent path traversal
fn is_valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15 // Linux interface name limit
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Read interface statistics from sysfs
fn read_interface_stats(iface: &str) -> (u64, u64) {
    // Validate interface name to prevent path traversal
    if !is_valid_interface_name(iface) {
        return (0, 0);
    }

    let rx_bytes = fs::read_to_string(format!("/sys/class/net/{}/statistics/rx_bytes", iface))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

    let tx_bytes = fs::read_to_string(format!("/sys/class/net/{}/statistics/tx_bytes", iface))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

    (rx_bytes, tx_bytes)
}

/// Check if allowed_ips indicates split tunnel (not routing all traffic)
fn is_split_tunnel(allowed_ips: Option<&str>) -> bool {
    match allowed_ips {
        Some(ips) => !ips.contains("0.0.0.0/0"),
        None => false,
    }
}

fn read_status() -> Status {
    let config_dir = get_config_dir();
    let state_file = config_dir.join(".connection_state");

    // Load .connection_state if exists (for metadata)
    let state: Option<serde_json::Value> = if state_file.exists() {
        fs::read_to_string(&state_file)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
    } else {
        None
    };

    // Extract interface name from state file if available
    let state_interface = state
        .as_ref()
        .and_then(|s| s.get("interface"))
        .and_then(|s| s.as_str());

    // SYSFS-FIRST: Detect active WireGuard interfaces
    let wg_interfaces = list_wireguard_interfaces_sysfs();

    // Determine which interface to use:
    // 1. If state has an interface, check if it exists in sysfs
    // 2. Otherwise, use first detected WireGuard interface
    let active_interface = if let Some(iface) = state_interface {
        if wg_interfaces.contains(&iface.to_string()) {
            Some(iface.to_string())
        } else {
            // State says connected but interface is gone
            wg_interfaces.first().cloned()
        }
    } else {
        wg_interfaces.first().cloned()
    };

    // No WireGuard interface active -> disconnected
    let active_interface = match active_interface {
        Some(iface) => iface,
        None => return disconnected_status(state.as_ref()),
    };

    // We have an active interface - check if we have metadata from .connection_state
    let has_metadata = state.as_ref().map_or(false, |s| {
        s.get("interface")
            .and_then(|i| i.as_str())
            .map_or(false, |i| i == active_interface)
    });

    // Extract metadata if available
    let (server_name, killswitch_active, allowed_ips, connected_at, provider, city) = if has_metadata {
        let s = state.as_ref().unwrap();
        (
            s.get("server_name").and_then(|v| v.as_str()).map(String::from),
            s.get("killswitch_active").and_then(|v| v.as_bool()).unwrap_or(false),
            s.get("server_allowed_ips").and_then(|v| v.as_str()),
            s.get("connected_at").and_then(|v| v.as_str()),
            s.get("server_provider").and_then(|v| v.as_str()),
            s.get("server_city").and_then(|v| v.as_str()),
        )
    } else {
        (None, false, None, None, None, None)
    };

    let split_tunnel = is_split_tunnel(allowed_ips);

    // Get public IP (from state first, then fetch with cache)
    let ip = state
        .as_ref()
        .and_then(|s| s.get("public_ip"))
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| fetch_public_ip_cached(state.as_ref()));

    // Calculate uptime if we have connected_at
    let uptime = connected_at.and_then(|t| {
        chrono::DateTime::parse_from_rfc3339(t).ok().map(|dt| {
            let now = chrono::Utc::now();
            let duration = now.signed_duration_since(dt.with_timezone(&chrono::Utc));
            format_duration(duration)
        })
    });

    // Read stats
    let (rx_bytes, tx_bytes) = read_interface_stats(&active_interface);

    // Build text and tooltip based on whether we have metadata
    // Text is just an icon, details go in tooltip
    let (text, tooltip) = if let Some(ref server) = server_name {
        // We have metadata from monarch-lazyvpn.
        //
        // One glyph for every visible state — the state is carried by the class
        // (which the bar maps to a colour), never by a different icon. Swapping
        // in a second glyph made the pill read as a different widget at a
        // glance, and left no room for the states that actually matter.
        let text = VPN_GLYPH.to_string();

        let mut tooltip_lines = vec![format!("Connected to {}", server)];
        if let Some(p) = provider {
            tooltip_lines.push(format!("Provider: {}", p));
        }
        if let Some(c) = city {
            tooltip_lines.push(format!("Location: {}", c));
        }
        tooltip_lines.push(format!("IP: {}", ip.as_deref().unwrap_or("Unknown")));
        tooltip_lines.push(format!("Uptime: {}", uptime.as_deref().unwrap_or("Unknown")));
        tooltip_lines.push(format!("Interface: {}", active_interface));
        tooltip_lines.push(format!("Traffic: ↓{} ↑{}", format_bytes(rx_bytes), format_bytes(tx_bytes)));
        if killswitch_active {
            tooltip_lines.push("Killswitch: Active".to_string());
        } else {
            tooltip_lines.push("Killswitch: Inactive".to_string());
        }
        if split_tunnel {
            tooltip_lines.push("Mode: Split Tunnel".to_string());
        }

        (text, tooltip_lines.join("\n"))
    } else {
        // No metadata - VPN established externally (Task 8)
        let text = VPN_GLYPH.to_string();
        let tooltip = format!(
            "WireGuard interface {} active\nIP: {}\nTraffic: ↓{} ↑{}",
            active_interface,
            ip.as_deref().unwrap_or("Unknown"),
            format_bytes(rx_bytes),
            format_bytes(tx_bytes)
        );
        (text, tooltip)
    };

    Status {
        connected: true,
        server: server_name,
        ip,
        uptime,
        interface: Some(active_interface),
        killswitch_active,
        split_tunnel,
        text,
        tooltip,
        class: if killswitch_active {
            "connected-ks".to_string()
        } else {
            "connected".to_string()
        },
    }
}

/// Format bytes as human-readable string
fn format_bytes(bytes: u64) -> String {
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

/// Status with no WireGuard interface up.
///
/// Two very different situations hide behind "disconnected", and only one of
/// them is worth a pill in the bar:
///
/// * the killswitch is still loaded — every packet is being dropped and the
///   user is looking at a dead network with no idea why. That is the state the
///   bar has to shout about, so it gets the VPN glyph and a `ks-blocking` class
///   for the bar to colour as an alert.
/// * nothing is running at all — normal, uninteresting, and it used to sit in
///   the bar as a permanent unlocked padlock. It now returns empty text, which
///   is how both Waybar and the Monarch bar plugin collapse a module.
///
/// The killswitch is a set of nft rules, and `nft list tables` needs root, so
/// this binary — unprivileged, re-run every few seconds — cannot look at them
/// directly. It reads the last state written by monarch-lazyvpn instead: the
/// file outlives a tunnel that dropped unexpectedly and is only cleared when
/// the app next starts (see cleanup::cleanup_connection_state), which is
/// exactly the window where the rules are still loaded. That makes this an
/// inference from the last known state rather than a live reading of nftables.
fn disconnected_status(state: Option<&serde_json::Value>) -> Status {
    let killswitch_active = state
        .and_then(|s| s.get("killswitch_active"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if killswitch_active {
        return Status {
            connected: false,
            server: None,
            ip: None,
            uptime: None,
            interface: None,
            killswitch_active: true,
            split_tunnel: false,
            text: VPN_GLYPH.to_string(),
            tooltip: "VPN: Disconnected\nKillswitch: Active (blocking all traffic)".to_string(),
            class: "ks-blocking".to_string(),
        };
    }

    Status {
        connected: false,
        server: None,
        ip: None,
        uptime: None,
        interface: None,
        killswitch_active: false,
        split_tunnel: false,
        text: String::new(),
        tooltip: "Not connected to VPN".to_string(),
        class: "disconnected".to_string(),
    }
}

fn get_config_dir() -> PathBuf {
    directories::ProjectDirs::from("com", "monarch", "monarch-lazyvpn")
        .map(|dirs| dirs.config_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("~/.config/monarch-lazyvpn"))
}

/// Fetch public IP with caching to avoid repeated HTTP requests
fn fetch_public_ip_cached(state: Option<&serde_json::Value>) -> Option<String> {
    let config_dir = get_config_dir();
    let ip_cache = config_dir.join(".ip_cache");

    // Check if main app is running (don't write cache if so)
    let main_app_running = state
        .and_then(|s| s.get("pid"))
        .and_then(|p| p.as_u64())
        .map(|pid| PathBuf::from(format!("/proc/{}", pid)).exists())
        .unwrap_or(false);

    // Check cache first
    if ip_cache.exists() {
        if let Ok(metadata) = fs::metadata(&ip_cache) {
            if let Ok(modified) = metadata.modified() {
                if let Ok(elapsed) = modified.elapsed() {
                    // Use cached IP if less than 30 seconds old
                    if elapsed.as_secs() < 30 {
                        if let Ok(ip) = fs::read_to_string(&ip_cache) {
                            let ip = ip.trim().to_string();
                            if !ip.is_empty() {
                                return Some(ip);
                            }
                        }
                    }
                }
            }
        }
    }

    // Cache is stale or doesn't exist - fetch new IP
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return None,
    };

    // Try ipv4.ident.me first, fallback to ifconfig.io
    let ip = client
        .get("https://ipv4.ident.me")
        .send()
        .ok()
        .and_then(|r| r.text().ok())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            client
                .get("https://ifconfig.io/ip")
                .send()
                .ok()
                .and_then(|r| r.text().ok())
                .map(|s| s.trim().to_string())
        });

    // Write to cache only if main app is not running (with secure permissions)
    if let Some(ref ip_str) = ip {
        if !main_app_running && !ip_str.is_empty() {
            // Use 0600 permissions to match other state files
            if let Ok(mut file) = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&ip_cache)
            {
                let _ = file.write_all(ip_str.as_bytes());
            }
        }
    }

    ip
}

fn format_duration(duration: chrono::Duration) -> String {
    let secs = duration.num_seconds();
    let hours = secs / 3600;
    let mins = (secs % 3600) / 60;

    if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else if mins > 0 {
        format!("{}m", mins)
    } else {
        format!("{}s", secs)
    }
}
