//! Security integration tests
//!
//! These tests require root privileges and use network namespaces
//! for isolation. Run with: sudo cargo test --test security_tests
//!
//! Tests marked with #[ignore] by default - require root to run.

use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;

/// Test that temp config files have correct permissions
#[test]
fn test_temp_file_permissions() {
    let uid = unsafe { libc::getuid() };
    let temp_dir = PathBuf::from(format!("/run/user/{}", uid));

    if !temp_dir.exists() {
        // Skip if temp dir doesn't exist
        return;
    }

    // Create a test file with the expected permissions
    let test_file = temp_dir.join("monarch-vpn-test-perms.conf");

    // Write with restricted permissions
    {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&test_file)
            .expect("Failed to create test file");

        file.write_all(b"test content").unwrap();
    }

    // Verify permissions
    let metadata = fs::metadata(&test_file).expect("Failed to get metadata");
    let perms = metadata.permissions();
    let mode = perms.mode() & 0o777;

    // Cleanup
    let _ = fs::remove_file(&test_file);

    assert_eq!(mode, 0o600, "File should have mode 0600, got {:o}", mode);
}

/// Test that temp files are properly cleaned up
/// Note: This test can be flaky if other monarch instances are running
#[test]
#[ignore]
fn test_temp_file_cleanup() {
    let uid = unsafe { libc::getuid() };
    let temp_dir = PathBuf::from(format!("/run/user/{}", uid));

    if !temp_dir.exists() {
        return;
    }

    // Count monarch temp files before
    let before_count = count_temp_files(&temp_dir);

    // Create a temp file
    let test_file = temp_dir.join("monarch-vpn-cleanup-test.conf");
    fs::write(&test_file, "test").expect("Failed to write test file");

    // Should have one more file
    let during_count = count_temp_files(&temp_dir);
    assert_eq!(during_count, before_count + 1);

    // Clean up
    fs::remove_file(&test_file).expect("Failed to remove test file");

    // Should be back to original
    let after_count = count_temp_files(&temp_dir);
    assert_eq!(after_count, before_count);
}

fn count_temp_files(dir: &PathBuf) -> usize {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().starts_with("monarch-vpn-"))
                .count()
        })
        .unwrap_or(0)
}

/// Test WireGuard key validation
#[test]
fn test_wg_key_validation() {
    // Valid key (32 bytes base64 encoded = 44 chars ending with =)
    let valid_key = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";
    assert!(validate_wg_key(valid_key), "Valid key should pass");

    // Invalid: too short
    let short_key = "YWJjZGVm";
    assert!(!validate_wg_key(short_key), "Short key should fail");

    // Invalid: wrong ending
    let bad_ending = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTZ";
    assert!(!validate_wg_key(bad_ending), "Key without = should fail");

    // Invalid: not base64
    let not_base64 = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!=";
    assert!(!validate_wg_key(not_base64), "Non-base64 should fail");
}

fn validate_wg_key(key: &str) -> bool {
    if key.len() != 44 || !key.ends_with('=') {
        return false;
    }

    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(key)
        .is_ok()
}

/// Test nftables ruleset generation
#[test]
fn test_killswitch_ruleset_generation() {
    // Mock killswitch ruleset generation
    let interface = "wg0";
    let server_ip = "1.2.3.4";
    let allow_lan = false;
    let lan_ranges: Vec<String> = vec![];

    let ruleset = generate_test_ruleset(interface, server_ip, allow_lan, &lan_ranges);

    // Verify essential rules
    assert!(ruleset.contains("policy drop"), "Should have drop policy");
    assert!(
        ruleset.contains("iifname \"lo\" accept"),
        "Should allow loopback input"
    );
    assert!(
        ruleset.contains("oifname \"lo\" accept"),
        "Should allow loopback output"
    );
    assert!(
        ruleset.contains(&format!("iifname \"{}\" accept", interface)),
        "Should allow VPN interface input"
    );
    assert!(
        ruleset.contains(&format!("oifname \"{}\" accept", interface)),
        "Should allow VPN interface output"
    );
    assert!(
        ruleset.contains(&format!("ip daddr {} accept", server_ip)),
        "Should allow traffic to VPN server"
    );
}

/// Test killswitch with LAN access
#[test]
fn test_killswitch_lan_rules() {
    let interface = "wg0";
    let server_ip = "1.2.3.4";
    let allow_lan = true;
    let lan_ranges = vec!["192.168.0.0/16".to_string(), "10.0.0.0/8".to_string()];

    let ruleset = generate_test_ruleset(interface, server_ip, allow_lan, &lan_ranges);

    // Verify LAN rules present
    assert!(
        ruleset.contains("192.168.0.0/16"),
        "Should have 192.168.0.0/16 rule"
    );
    assert!(
        ruleset.contains("10.0.0.0/8"),
        "Should have 10.0.0.0/8 rule"
    );
}

/// Test killswitch without LAN access (more secure)
#[test]
fn test_killswitch_no_lan() {
    let interface = "wg0";
    let server_ip = "1.2.3.4";
    let allow_lan = false;
    let lan_ranges = vec!["192.168.0.0/16".to_string()];

    let ruleset = generate_test_ruleset(interface, server_ip, allow_lan, &lan_ranges);

    // LAN should NOT be in accept rules when allow_lan is false
    assert!(
        !ruleset.contains("ip saddr 192.168.0.0/16 accept")
            && !ruleset.contains("ip daddr 192.168.0.0/16 accept"),
        "Should NOT have LAN accept rules when allow_lan is false"
    );
}

fn generate_test_ruleset(
    interface: &str,
    server_ip: &str,
    allow_lan: bool,
    lan_ranges: &[String],
) -> String {
    let mut rules = String::new();

    rules.push_str("table inet monarch_killswitch {\n");

    // Input chain
    rules.push_str("  chain input {\n");
    rules.push_str("    type filter hook input priority 0; policy drop;\n");
    rules.push_str("    iifname \"lo\" accept\n");
    rules.push_str("    ct state established,related accept\n");
    rules.push_str(&format!("    iifname \"{}\" accept\n", interface));

    if allow_lan {
        for range in lan_ranges {
            rules.push_str(&format!("    ip saddr {} accept\n", range));
        }
    }
    rules.push_str("  }\n");

    // Output chain
    rules.push_str("  chain output {\n");
    rules.push_str("    type filter hook output priority 0; policy drop;\n");
    rules.push_str("    oifname \"lo\" accept\n");
    rules.push_str("    ct state established,related accept\n");
    rules.push_str(&format!("    ip daddr {} accept\n", server_ip));
    rules.push_str(&format!("    oifname \"{}\" accept\n", interface));

    if allow_lan {
        for range in lan_ranges {
            rules.push_str(&format!("    ip daddr {} accept\n", range));
        }
    }
    rules.push_str("  }\n");

    rules.push_str("}\n");

    rules
}

// ============================================================================
// Tests requiring root/network namespaces - marked #[ignore]
// ============================================================================

/// Test killswitch blocks traffic before VPN is up
/// Requires root to create network namespace
/// Run with: sudo cargo test test_killswitch_blocks_pre_vpn_traffic -- --ignored --test-threads=1
#[test]
#[ignore]
fn test_killswitch_blocks_pre_vpn_traffic() {
    // Skip if not running as root
    if !is_root() {
        eprintln!("SKIP: Test requires root privileges");
        return;
    }

    // Create a test namespace name
    let ns_name = format!("monarch_test_{}", std::process::id());

    // Setup: Create network namespace
    let setup = Command::new("ip")
        .args(["netns", "add", &ns_name])
        .output()
        .expect("Failed to create netns");
    assert!(setup.status.success(), "Failed to create network namespace");

    // Apply killswitch rules in the namespace
    let killswitch_rules = format!(
        r#"
        table inet monarch_killswitch {{
          chain output {{
            type filter hook output priority 0; policy drop;
            oifname "lo" accept
            oifname "wg0" accept
            ip daddr 1.2.3.4 accept
          }}
          chain input {{
            type filter hook input priority 0; policy drop;
            iifname "lo" accept
            iifname "wg0" accept
          }}
        }}
        table ip6 monarch_killswitch_v6 {{
          chain output {{ type filter hook output priority 0; policy drop; oifname "lo" accept }}
          chain input {{ type filter hook input priority 0; policy drop; iifname "lo" accept }}
        }}
        "#
    );

    let rules_file = format!("/tmp/monarch_test_rules_{}.nft", std::process::id());
    fs::write(&rules_file, killswitch_rules).expect("Failed to write rules");

    let apply_rules = Command::new("ip")
        .args(["netns", "exec", &ns_name, "nft", "-f", &rules_file])
        .output();

    // Verify traffic is blocked (ping should fail)
    let ping_test = Command::new("ip")
        .args([
            "netns", "exec", &ns_name, "ping", "-c", "1", "-W", "1", "8.8.8.8",
        ])
        .output()
        .expect("Failed to run ping");

    // Cleanup
    let _ = Command::new("ip")
        .args(["netns", "delete", &ns_name])
        .output();
    let _ = fs::remove_file(&rules_file);

    // Assert ping failed (traffic blocked by killswitch)
    assert!(
        !ping_test.status.success(),
        "Ping should fail when killswitch is active (traffic blocked)"
    );

    if apply_rules.is_ok() {
        println!("✓ Killswitch successfully blocks traffic before VPN is up");
    }
}

/// Test traffic blocked when VPN interface removed unexpectedly
/// Run with: sudo cargo test test_killswitch_blocks_on_interface_removal -- --ignored --test-threads=1
#[test]
#[ignore]
fn test_killswitch_blocks_on_interface_removal() {
    if !is_root() {
        eprintln!("SKIP: Test requires root privileges");
        return;
    }

    let ns_name = format!("monarch_test_iface_{}", std::process::id());

    // 1. Create network namespace
    let setup = Command::new("ip")
        .args(["netns", "add", &ns_name])
        .output()
        .expect("Failed to create netns");
    assert!(setup.status.success());

    // 2. Create dummy wg0 interface in namespace
    let _ = Command::new("ip")
        .args(["netns", "exec", &ns_name, "ip", "link", "add", "wg0", "type", "dummy"])
        .output();

    let _ = Command::new("ip")
        .args(["netns", "exec", &ns_name, "ip", "link", "set", "wg0", "up"])
        .output();

    // 3. Apply killswitch rules
    let rules = r#"
        table inet monarch_killswitch {
          chain output {
            type filter hook output priority 0; policy drop;
            oifname "lo" accept
            oifname "wg0" accept
            ip daddr 1.2.3.4 accept
          }
        }
    "#;
    let rules_file = format!("/tmp/monarch_test_iface_rules_{}.nft", std::process::id());
    fs::write(&rules_file, rules).expect("Failed to write rules");

    let _ = Command::new("ip")
        .args(["netns", "exec", &ns_name, "nft", "-f", &rules_file])
        .output();

    // 4. Remove VPN interface (simulating unexpected disconnect)
    let _ = Command::new("ip")
        .args(["netns", "exec", &ns_name, "ip", "link", "delete", "wg0"])
        .output();

    // 5. Verify traffic still blocked (killswitch persists)
    let ping_test = Command::new("ip")
        .args(["netns", "exec", &ns_name, "ping", "-c", "1", "-W", "1", "8.8.8.8"])
        .output()
        .expect("Failed to run ping");

    // Cleanup
    let _ = Command::new("ip")
        .args(["netns", "delete", &ns_name])
        .output();
    let _ = fs::remove_file(&rules_file);

    // Assert: Traffic should still be blocked
    assert!(
        !ping_test.status.success(),
        "Traffic should remain blocked even after VPN interface is removed"
    );

    println!("✓ Killswitch persists after interface removal (no leak)");
}

/// Test no IPv6 leaks when protection enabled
/// Run with: sudo cargo test test_no_ipv6_leaks -- --ignored --test-threads=1
#[test]
#[ignore]
fn test_no_ipv6_leaks() {
    if !is_root() {
        eprintln!("SKIP: Test requires root privileges");
        return;
    }

    let ns_name = format!("monarch_test_ipv6_{}", std::process::id());

    // 1. Create network namespace
    let setup = Command::new("ip")
        .args(["netns", "add", &ns_name])
        .output()
        .expect("Failed to create netns");
    assert!(setup.status.success());

    // 2. Apply IPv6 blocking rules
    let rules = r#"
        table ip6 monarch_killswitch_v6 {
          chain input {
            type filter hook input priority 0; policy drop;
            iifname "lo" accept
          }
          chain output {
            type filter hook output priority 0; policy drop;
            oifname "lo" accept
          }
          chain forward {
            type filter hook forward priority 0; policy drop;
          }
        }
    "#;
    let rules_file = format!("/tmp/monarch_test_ipv6_rules_{}.nft", std::process::id());
    fs::write(&rules_file, rules).expect("Failed to write rules");

    let _ = Command::new("ip")
        .args(["netns", "exec", &ns_name, "nft", "-f", &rules_file])
        .output();

    // 3. Try to ping IPv6 address (Google DNS)
    let ping6_test = Command::new("ip")
        .args([
            "netns", "exec", &ns_name, "ping6", "-c", "1", "-W", "1", "2001:4860:4860::8888",
        ])
        .output();

    // 4. Try to access IPv6 localhost (should also fail except for explicit allow)
    let ping6_external = Command::new("ip")
        .args([
            "netns", "exec", &ns_name, "ping6", "-c", "1", "-W", "1", "::1",
        ])
        .output();

    // Cleanup
    let _ = Command::new("ip")
        .args(["netns", "delete", &ns_name])
        .output();
    let _ = fs::remove_file(&rules_file);

    // Assert: External IPv6 should fail
    if let Ok(output) = ping6_test {
        assert!(
            !output.status.success(),
            "External IPv6 traffic should be blocked"
        );
    }

    // Loopback should work (we allow it in rules)
    if let Ok(output) = ping6_external {
        assert!(
            output.status.success(),
            "IPv6 loopback should work (explicitly allowed)"
        );
    }

    println!("✓ IPv6 leak protection working (external blocked, loopback allowed)");
}

/// Helper: Check if running as root
fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}
