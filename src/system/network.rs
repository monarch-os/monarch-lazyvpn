//! Network statistics and IP checking

use crate::core::error::{Result, VpnError};
use std::fs;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, warn};

const PUBLIC_IP_TIMEOUT_SECS: u64 = 5;
const PING_TIMEOUT_SECS: u64 = 5;
const IP_CACHE_SECS: u64 = 30;

/// Cached public IP
struct IpCache {
    ip: String,
    fetched_at: Instant,
}

/// Network stats collector with caching
pub struct NetworkStats {
    ip_cache: RwLock<Option<IpCache>>,
    last_rx: AtomicU64,
    last_tx: AtomicU64,
    last_stats_time: RwLock<Option<Instant>>,
}

impl NetworkStats {
    pub fn new() -> Self {
        Self {
            ip_cache: RwLock::new(None),
            last_rx: AtomicU64::new(0),
            last_tx: AtomicU64::new(0),
            last_stats_time: RwLock::new(None),
        }
    }

    /// Get public IP with caching
    pub async fn get_public_ip(&self) -> Result<String> {
        // Check cache first
        {
            let cache = self.ip_cache.read().await;
            if let Some(ref c) = *cache {
                if c.fetched_at.elapsed() < Duration::from_secs(IP_CACHE_SECS) {
                    debug!("Using cached public IP: {}", c.ip);
                    return Ok(c.ip.clone());
                }
            }
        }

        // Fetch new IP
        let ip = self.fetch_public_ip().await?;

        // Update cache
        {
            let mut cache = self.ip_cache.write().await;
            *cache = Some(IpCache {
                ip: ip.clone(),
                fetched_at: Instant::now(),
            });
        }

        Ok(ip)
    }

    /// Fetch public IP from services
    async fn fetch_public_ip(&self) -> Result<String> {
        // Try primary service
        match self.try_ip_service("https://api.ipify.org").await {
            Ok(ip) => return Ok(ip),
            Err(e) => {
                warn!("Primary IP service failed: {}", e);
            }
        }

        // Fallback
        match self.try_ip_service("https://ifconfig.me/ip").await {
            Ok(ip) => return Ok(ip),
            Err(e) => {
                warn!("Fallback IP service failed: {}", e);
            }
        }

        // Last resort - try icanhazip
        self.try_ip_service("https://icanhazip.com").await
    }

    /// Try to get IP from a service
    async fn try_ip_service(&self, url: &str) -> Result<String> {
        let client = reqwest::Client::new();

        let response = timeout(
            Duration::from_secs(PUBLIC_IP_TIMEOUT_SECS),
            client.get(url).send(),
        )
        .await
        .map_err(|_| VpnError::TimeoutError("IP fetch timed out".into()))?
        .map_err(|e| VpnError::NetworkError(format!("HTTP error: {}", e)))?;

        let ip = response
            .text()
            .await
            .map_err(|e| VpnError::NetworkError(format!("Failed to read response: {}", e)))?
            .trim()
            .to_string();

        // Validate IP format (basic check)
        if ip.is_empty() || (!ip.contains('.') && !ip.contains(':')) {
            return Err(VpnError::NetworkError(format!("Invalid IP response: {}", ip)));
        }

        debug!("Got public IP: {}", ip);
        Ok(ip)
    }

    /// Invalidate IP cache (call after VPN state change)
    pub async fn invalidate_ip_cache(&self) {
        let mut cache = self.ip_cache.write().await;
        *cache = None;
    }

    /// Get interface statistics (rx/tx bytes)
    pub fn get_interface_stats(&self, interface: &str) -> Result<(u64, u64)> {
        let rx_path = format!("/sys/class/net/{}/statistics/rx_bytes", interface);
        let tx_path = format!("/sys/class/net/{}/statistics/tx_bytes", interface);

        let rx_bytes = fs::read_to_string(&rx_path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        let tx_bytes = fs::read_to_string(&tx_path)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        Ok((rx_bytes, tx_bytes))
    }

    /// Get throughput (bytes/sec since last call)
    pub async fn get_throughput(&self, interface: &str) -> Result<(f64, f64)> {
        let (rx, tx) = self.get_interface_stats(interface)?;
        let now = Instant::now();

        let mut last_time = self.last_stats_time.write().await;
        let last_rx = self.last_rx.load(Ordering::Relaxed);
        let last_tx = self.last_tx.load(Ordering::Relaxed);

        let (rx_rate, tx_rate) = if let Some(ref prev_time) = *last_time {
            let elapsed = now.duration_since(*prev_time).as_secs_f64();
            if elapsed > 0.0 {
                let rx_diff = rx.saturating_sub(last_rx) as f64;
                let tx_diff = tx.saturating_sub(last_tx) as f64;
                (rx_diff / elapsed, tx_diff / elapsed)
            } else {
                (0.0, 0.0)
            }
        } else {
            (0.0, 0.0)
        };

        // Update state
        self.last_rx.store(rx, Ordering::Relaxed);
        self.last_tx.store(tx, Ordering::Relaxed);
        *last_time = Some(now);

        Ok((rx_rate, tx_rate))
    }

    /// Ping a host and get latency in ms
    pub async fn ping_latency(&self, host: &str) -> Result<f64> {
        let output = timeout(
            Duration::from_secs(PING_TIMEOUT_SECS),
            Command::new("ping")
                .args(["-c", "1", "-W", "3", host])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output(),
        )
        .await
        .map_err(|_| VpnError::TimeoutError("Ping timed out".into()))?
        .map_err(|e| VpnError::NetworkError(format!("Ping failed: {}", e)))?;

        if !output.status.success() {
            return Err(VpnError::NetworkError("Ping failed".into()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse "time=X.XX ms" from ping output
        for line in stdout.lines() {
            if let Some(idx) = line.find("time=") {
                let time_str = &line[idx + 5..];
                if let Some(end) = time_str.find(' ') {
                    if let Ok(ms) = time_str[..end].parse::<f64>() {
                        return Ok(ms);
                    }
                }
            }
        }

        Err(VpnError::NetworkError("Failed to parse ping output".into()))
    }

    /// Check if we have network connectivity
    pub async fn has_connectivity(&self) -> bool {
        // Try to ping a reliable host
        self.ping_latency("1.1.1.1").await.is_ok()
    }

    /// Format bytes/sec as human-readable
    pub fn format_rate(bytes_per_sec: f64) -> String {
        const KB: f64 = 1024.0;
        const MB: f64 = KB * 1024.0;
        const GB: f64 = MB * 1024.0;

        if bytes_per_sec >= GB {
            format!("{:.2} GB/s", bytes_per_sec / GB)
        } else if bytes_per_sec >= MB {
            format!("{:.2} MB/s", bytes_per_sec / MB)
        } else if bytes_per_sec >= KB {
            format!("{:.2} KB/s", bytes_per_sec / KB)
        } else {
            format!("{:.0} B/s", bytes_per_sec)
        }
    }

    /// Format bytes as human-readable
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

impl Default for NetworkStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if VPN interface is up via ip link
pub async fn check_interface_up(interface: &str) -> bool {
    let output = Command::new("ip")
        .args(["link", "show", interface])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await;

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.contains("state UP") || stdout.contains(",UP")
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_rate() {
        assert_eq!(NetworkStats::format_rate(500.0), "500 B/s");
        assert_eq!(NetworkStats::format_rate(1024.0), "1.00 KB/s");
        assert_eq!(NetworkStats::format_rate(1048576.0), "1.00 MB/s");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(NetworkStats::format_bytes(500), "500 B");
        assert_eq!(NetworkStats::format_bytes(1024), "1.00 KB");
        assert_eq!(NetworkStats::format_bytes(1048576), "1.00 MB");
        assert_eq!(NetworkStats::format_bytes(1073741824), "1.00 GB");
    }
}
