use assert_cmd::cargo::cargo_bin_cmd;
use fs2::FileExt;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;

#[test]
fn unrelated_live_pid_does_not_block_status() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("monarch-lazyvpn");
    std::fs::create_dir(&config).unwrap();
    std::fs::write(
        config.join(".connection_state"),
        json!({
            "state": "Disconnected",
            "server_id": null,
            "server_name": null,
            "interface": "wg_test_missing",
            "connected_at": null,
            "pid": std::process::id(),
            "was_connected_on_exit": false
        })
        .to_string(),
    )
    .unwrap();

    let before = std::fs::read(config.join(".connection_state")).unwrap();
    cargo_bin_cmd!("monarch-lazyvpn")
        .env("XDG_CONFIG_HOME", temp.path())
        .args(["--format", "json", "status"])
        .assert()
        .success()
        .stdout(predicates::str::contains("\"status\": \"disconnected\""));
    assert_eq!(
        before,
        std::fs::read(config.join(".connection_state")).unwrap()
    );
}

#[test]
fn busy_instance_blocks_reset_without_touching_configuration() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = temp.path().join("monarch-lazyvpn");
    std::fs::create_dir(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let lock = std::fs::File::create(runtime.join("instance.lock")).unwrap();
    lock.set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    lock.lock_exclusive().unwrap();
    let config_home = temp.path().join("config");
    let config = config_home.join("monarch-lazyvpn");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("sentinel"), "keep").unwrap();

    cargo_bin_cmd!("monarch-lazyvpn")
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_RUNTIME_DIR", temp.path())
        .args(["reset", "--yes"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("LazyVPN is already running"));
    assert_eq!(
        std::fs::read_to_string(config.join("sentinel")).unwrap(),
        "keep"
    );

    cargo_bin_cmd!("monarch-lazyvpn")
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_RUNTIME_DIR", temp.path())
        .args(["--format", "json", "status"])
        .assert()
        .success();
    assert!(!config.join("config.toml").exists());
}

#[test]
#[cfg(feature = "gui")]
fn second_launch_requests_activation_before_initializing_vpn() {
    use std::io::{Read, Write};
    let temp = tempfile::tempdir().unwrap();
    let runtime = temp.path().join("monarch-lazyvpn");
    std::fs::create_dir(&runtime).unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let lock = std::fs::File::create(runtime.join("instance.lock")).unwrap();
    lock.set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    lock.lock_exclusive().unwrap();
    let listener = std::os::unix::net::UnixListener::bind(runtime.join("activate.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "No activation request"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("{e}"),
            }
        };
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut request = [0; 9];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"activate\n");
        stream.write_all(b"ok\n").unwrap();
    });
    cargo_bin_cmd!("monarch-lazyvpn")
        .env("XDG_CONFIG_HOME", temp.path().join("untouched"))
        .env("XDG_RUNTIME_DIR", temp.path())
        .timeout(std::time::Duration::from_secs(5))
        .assert()
        .success();
    server.join().unwrap();
    assert!(!temp.path().join("untouched").exists());
}
