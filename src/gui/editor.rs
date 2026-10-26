use crate::{
  app::App,
  core::{config::AppConfig, provider::WgConfig, server::validate_wg_key},
};
use std::{io::Write, net::IpAddr, path::Path};

pub fn validate(config: &WgConfig) -> anyhow::Result<()> {
  anyhow::ensure!(
    config
      .persistent_keepalive
      .is_none_or(|value| value <= 65535),
    "Keepalive must be between 0 and 65535 seconds"
  );
  for field in [
    &config.address,
    &config.dns,
    &config.public_key,
    &config.endpoint,
    &config.allowed_ips,
    &config.private_key,
  ]
  .into_iter()
  .flatten()
  {
    anyhow::ensure!(
      !field.chars().any(char::is_control),
      "Fields must contain a single line"
    );
  }
  for (label, value) in [
    ("Address", &config.address),
    ("Allowed IPs", &config.allowed_ips),
  ] {
    let value = value
      .as_deref()
      .filter(|v| !v.trim().is_empty())
      .ok_or_else(|| anyhow::anyhow!("{label} is required"))?;
    for cidr in value.split(',').map(str::trim) {
      let (ip, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("{label}: use CIDR notation, for example 10.0.0.2/32"))?;
      let ip: IpAddr = ip
        .parse()
        .map_err(|_| anyhow::anyhow!("{label}: invalid IP address"))?;
      let prefix: u8 = prefix
        .parse()
        .map_err(|_| anyhow::anyhow!("{label}: invalid network prefix"))?;
      anyhow::ensure!(
        prefix <= if ip.is_ipv4() { 32 } else { 128 },
        "{label}: invalid network prefix"
      );
    }
    anyhow::ensure!(
      value.split(',').any(|cidr| cidr
        .trim()
        .split_once('/')
        .is_some_and(|(ip, _)| ip.parse::<std::net::Ipv4Addr>().is_ok())),
      "{label}: this VPN engine requires at least one IPv4 network"
    );
  }
  let key = config.public_key.as_deref().unwrap_or_default();
  anyhow::ensure!(
    validate_wg_key(key),
    "Peer public key must be a valid WireGuard key"
  );
  if let Some(key) = &config.private_key {
    anyhow::ensure!(
      validate_wg_key(key),
      "Private key must be a valid WireGuard key"
    );
  }
  let endpoint = config.endpoint.as_deref().unwrap_or_default();
  let (host, port) = endpoint
    .rsplit_once(':')
    .ok_or_else(|| anyhow::anyhow!("Endpoint must contain a host and port"))?;
  anyhow::ensure!(
    !host.is_empty() && !host.chars().any(char::is_whitespace),
    "Endpoint host is invalid"
  );
  if host.starts_with('[') {
    anyhow::ensure!(
      host.ends_with(']')
        && host[1..host.len() - 1]
          .parse::<std::net::Ipv6Addr>()
          .is_ok(),
      "Endpoint IPv6 address is invalid"
    );
  } else {
    anyhow::ensure!(
      host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')),
      "Endpoint host is invalid"
    );
  }
  anyhow::ensure!(
    port.parse::<u16>().is_ok_and(|p| p > 0),
    "Endpoint port must be between 1 and 65535"
  );
  if let Some(dns) = &config.dns {
    anyhow::ensure!(
      dns.split(',').all(|s| {
        let s = s.trim();
        !s.is_empty()
          && (s.parse::<IpAddr>().is_ok()
            || s
              .bytes()
              .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')))
      }),
      "DNS must contain IP addresses or search domains separated by commas"
    );
  }
  Ok(())
}

fn sanitized(config: &WgConfig) -> String {
  let mut output = "[Interface]\n# PrivateKey stored in keyring\n".to_string();
  for (name, value) in [("Address", &config.address), ("DNS", &config.dns)] {
    if let Some(value) = value {
      output.push_str(&format!("{name} = {value}\n"));
    }
  }
  output.push_str("\n[Peer]\n");
  for (name, value) in [
    ("PublicKey", &config.public_key),
    ("Endpoint", &config.endpoint),
    ("AllowedIPs", &config.allowed_ips),
  ] {
    if let Some(value) = value {
      output.push_str(&format!("{name} = {value}\n"));
    }
  }
  if let Some(value) = config.persistent_keepalive {
    output.push_str(&format!("PersistentKeepalive = {value}\n"));
  }
  output
}

fn prepare(path: &Path, config: &WgConfig) -> anyhow::Result<tempfile::NamedTempFile> {
  let mut file = tempfile::NamedTempFile::new_in(
    path
      .parent()
      .ok_or_else(|| anyhow::anyhow!("Invalid config path"))?,
  )?;
  file.write_all(sanitized(config).as_bytes())?;
  file.as_file().sync_all()?;
  Ok(file)
}

pub fn save(app: &mut App, id: &str, mut config: WgConfig) -> anyhow::Result<()> {
  let server = app
    .get_servers()
    .into_iter()
    .find(|s| s.id == id && s.is_custom)
    .ok_or_else(|| anyhow::anyhow!("This personal profile is no longer available"))?;
  anyhow::ensure!(
    !app.connection.is_connected() || !app.connection.current_server().is_some_and(|s| s.id == id),
    "Disconnect this profile before editing it"
  );
  validate(&config)?;
  let path = AppConfig::servers_dir()?.join(format!("{}.conf", server.name));
  anyhow::ensure!(
    path.is_file(),
    "This personal profile is no longer available"
  );
  let provider = format!("custom/{}", server.name);
  let old_credentials = app.credentials.retrieve(&provider)?;
  let mut credentials = old_credentials.clone();
  credentials.address = config.address.clone().unwrap();
  if let Some(key) = config.private_key.take() {
    credentials.private_key = key;
  }
  let file = prepare(&path, &config)?;
  app.credentials.store(&provider, &credentials)?;
  if let Err(error) = file.persist(&path) {
    if let Err(rollback) = app.credentials.store(&provider, &old_credentials) {
      anyhow::bail!("Could not save the profile ({error}) or restore credentials ({rollback}). Re-import the original configuration.");
    }
    return Err(error.into());
  }
  if app
    .provider_credentials
    .as_ref()
    .is_some_and(|c| c.provider_name == provider)
  {
    app.provider_credentials = Some(credentials);
  }
  app.info_message = Some(format!("Saved '{}'", server.name));
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  fn config() -> WgConfig {
    WgConfig {
      address: Some("10.0.0.2/32".into()),
      dns: Some("1.1.1.1".into()),
      public_key: Some("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=".into()),
      endpoint: Some("vpn.example.com:51820".into()),
      allowed_ips: Some("10.0.0.0/8".into()),
      persistent_keepalive: Some(25),
      ..Default::default()
    }
  }

  #[test]
  fn validates_routes_endpoints_and_rejects_config_injection() {
    let mut draft = config();
    assert!(validate(&draft).is_ok());
    draft.address = Some("10.0.0.2/33".into());
    assert!(validate(&draft).is_err());
    draft = config();
    draft.endpoint = Some("[2001:db8::1]:51820".into());
    assert!(validate(&draft).is_ok());
    let server =
      crate::core::provider::custom::CustomProvider::server_from_config("test", &draft).unwrap();
    assert_eq!(server.ip, "[2001:db8::1]");
    draft.endpoint = Some("example.com:0".into());
    assert!(validate(&draft).is_err());
    draft = config();
    draft.dns = Some("1.1.1.1\nPostUp = command".into());
    assert!(validate(&draft).is_err());
    draft = config();
    draft.allowed_ips = Some("::/0".into());
    assert!(validate(&draft).is_err());
  }

  #[test]
  fn persisted_edits_do_not_contain_private_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("profile.conf");
    std::fs::write(&path, "previous configuration").unwrap();
    let mut draft = config();
    draft.private_key = Some("private-secret".into());
    let file = prepare(&path, &draft).unwrap();
    assert_eq!(
      std::fs::read_to_string(&path).unwrap(),
      "previous configuration"
    );
    file.persist(&path).unwrap();
    let saved = std::fs::read_to_string(path).unwrap();
    assert!(!saved.contains("private-secret"));
    assert!(!saved.contains("PrivateKey ="));
    let parsed = WgConfig::parse(&saved);
    assert_eq!(parsed.endpoint, draft.endpoint);
    assert_eq!(parsed.allowed_ips, draft.allowed_ips);
  }
}
