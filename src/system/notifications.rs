//! System notifications via libnotify

use notify_rust::{Notification, Urgency};
use tracing::{debug, warn};

const APP_NAME: &str = "monarch-lazyvpn";

/// Send a notification
pub fn notify(title: &str, body: &str, critical: bool) {
    let urgency = if critical {
        Urgency::Critical
    } else {
        Urgency::Normal
    };

    let result = Notification::new()
        .appname(APP_NAME)
        .summary(title)
        .body(body)
        .urgency(urgency)
        .timeout(if critical { 0 } else { 5000 }) // Critical stays until dismissed
        .show();

    match result {
        Ok(_) => debug!("Sent notification: {}", title),
        Err(e) => warn!("Failed to send notification: {}", e),
    }
}

/// Notify connection success
pub fn notify_connected(server_name: &str, public_ip: Option<&str>) {
    let body = if let Some(ip) = public_ip {
        format!("Connected to {}\nPublic IP: {}", server_name, ip)
    } else {
        format!("Connected to {}", server_name)
    };

    notify("VPN Connected", &body, false);
}

/// Notify disconnection
pub fn notify_disconnected() {
    notify(
        "VPN Disconnected",
        "You are now disconnected from VPN",
        false,
    );
}

/// Notify connection error
pub fn notify_error(error: &str) {
    notify("VPN Error", error, true);
}

/// Notify unexpected disconnect
pub fn notify_unexpected_disconnect(server_name: &str) {
    notify(
        "VPN Connection Lost",
        &format!("Unexpectedly disconnected from {}", server_name),
        true,
    );
}

/// Notify killswitch activated
pub fn notify_killswitch_active() {
    notify("Killswitch Active", "All non-VPN traffic is blocked", false);
}

/// Notify killswitch deactivated
pub fn notify_killswitch_inactive() {
    notify(
        "Killswitch Disabled",
        "Traffic blocking has been disabled",
        false,
    );
}

/// Notify auto-reconnect attempt
pub fn notify_reconnecting(server_name: &str, attempt: u32) {
    notify(
        "VPN Reconnecting",
        &format!(
            "Attempting to reconnect to {} (attempt {})",
            server_name, attempt
        ),
        false,
    );
}

#[cfg(test)]
mod tests {
    // Notification tests would require a running D-Bus session
    // Skip in CI environments
}
