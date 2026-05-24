//! Gluetun server list fetcher with caching

use crate::core::config::AppConfig;
use crate::core::error::{Result, VpnError};
use crate::core::server::{validate_wg_key, Server, ServerFeatures};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Base URL for gluetun's per-provider server files.
///
/// Since gluetun v3.40 the monolithic `servers.json` was split: the file in the
/// `qdm12/gluetun` repo is now only a manifest of `{ "<provider>": { "filepath": ... } }`
/// and no longer carries any server data. The actual servers moved to the companion
/// `qdm12/gluetun-servers` repository, one file per provider, each shaped as
/// `{ "version": N, "timestamp": N, "servers": [ ... ] }`.
const GLUETUN_SERVERS_BASE_URL: &str =
    "https://raw.githubusercontent.com/qdm12/gluetun-servers/main/pkg/servers";
const CACHE_EXPIRY_HOURS: i64 = 24;
const CACHE_MAX_AGE_DAYS: i64 = 7;
const MIN_FETCH_INTERVAL_SECS: u64 = 300; // 5 minutes
const FETCH_TIMEOUT_SECS: u64 = 30;
const MAX_RETRIES: u32 = 3;

/// Gluetun server entry from a per-provider JSON file
#[derive(Debug, Deserialize)]
struct GluetunServer {
    vpn: Option<String>,
    country: Option<String>,
    region: Option<String>,
    city: Option<String>,
    hostname: Option<String>,
    server_name: Option<String>,
    wgpubkey: Option<String>,
    ips: Option<Vec<String>>,
    // Explicit feature flags. Newer provider data (e.g. ProtonVPN) encodes
    // features as booleans rather than substrings in the hostname.
    #[serde(default)]
    secure_core: Option<bool>,
    #[serde(default)]
    stream: Option<bool>,
    #[serde(default)]
    tor: Option<bool>,
    #[serde(default)]
    p2p: Option<bool>,
}

/// A single per-provider server file from the `qdm12/gluetun-servers` repo.
///
/// Shape: `{ "version": N, "timestamp": N, "servers": [ ... ] }`.
/// Only `servers` is needed here; other fields are ignored.
#[derive(Debug, Deserialize)]
struct ProviderServersFile {
    #[serde(default)]
    servers: Vec<GluetunServer>,
}

/// Cache metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct CacheMetadata {
    pub fetched_at: DateTime<Utc>,
    pub last_fetch_attempt: DateTime<Utc>,
    pub provider_count: usize,
    pub server_count: usize,
}

/// Cached server data
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerCache {
    pub metadata: CacheMetadata,
    pub servers: Vec<Server>,
}

impl ServerCache {
    /// Create an empty cache (for first launch with no providers)
    pub fn empty() -> Self {
        Self {
            metadata: CacheMetadata {
                fetched_at: Utc::now(),
                last_fetch_attempt: Utc::now(),
                provider_count: 0,
                server_count: 0,
            },
            servers: Vec::new(),
        }
    }

    /// Get cache file path
    fn cache_path() -> Result<PathBuf> {
        let cache_dir = AppConfig::cache_dir()?;
        fs::create_dir_all(&cache_dir)?;
        Ok(cache_dir.join("servers.json"))
    }

    /// Load cache from disk
    pub fn load() -> Result<Option<Self>> {
        let path = Self::cache_path()?;
        if !path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&path)?;
        let cache: ServerCache = serde_json::from_str(&content)?;
        Ok(Some(cache))
    }

    /// Save cache to disk
    pub fn save(&self) -> Result<()> {
        let path = Self::cache_path()?;
        let content = serde_json::to_string_pretty(self)?;
        fs::write(&path, content)?;
        Ok(())
    }

    /// Check if cache is expired (>24h)
    pub fn is_expired(&self) -> bool {
        let age = Utc::now() - self.metadata.fetched_at;
        age > Duration::hours(CACHE_EXPIRY_HOURS)
    }

    /// Check if cache is stale (>7 days)
    pub fn is_stale(&self) -> bool {
        let age = Utc::now() - self.metadata.fetched_at;
        age > Duration::days(CACHE_MAX_AGE_DAYS)
    }

    /// Check if we can attempt a new fetch (rate limiting)
    pub fn can_fetch(&self) -> bool {
        let since_last = Utc::now() - self.metadata.last_fetch_attempt;
        since_last > Duration::seconds(MIN_FETCH_INTERVAL_SECS as i64)
    }

    /// Get servers for a specific provider
    pub fn get_provider_servers(&self, provider: &str) -> Vec<&Server> {
        self.servers
            .iter()
            .filter(|s| s.provider.to_lowercase() == provider.to_lowercase())
            .collect()
    }

    /// Check whether the cache holds servers for every requested provider.
    /// Used to force a refresh when a provider is newly configured but its
    /// servers are not yet cached.
    pub fn has_all_providers(&self, providers: &[String]) -> bool {
        providers.iter().all(|p| {
            self.servers
                .iter()
                .any(|s| s.provider.eq_ignore_ascii_case(p))
        })
    }
}

/// Server fetcher with retry and caching
pub struct ServerFetcher {
    client: reqwest::Client,
}

impl ServerFetcher {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// Fetch servers for the given providers with retry logic
    pub async fn fetch(&self, providers: &[String]) -> Result<ServerCache> {
        let mut last_error = None;

        for attempt in 1..=MAX_RETRIES {
            match self.fetch_once(providers).await {
                Ok(cache) => return Ok(cache),
                Err(e) => {
                    warn!(
                        "Fetch attempt {}/{} failed: {}",
                        attempt, MAX_RETRIES, e
                    );
                    last_error = Some(e);

                    if attempt < MAX_RETRIES {
                        // Exponential backoff
                        let delay = std::time::Duration::from_secs(2u64.pow(attempt));
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| VpnError::NetworkError("Unknown fetch error".into())))
    }

    /// Single fetch attempt: download every requested provider's server file.
    async fn fetch_once(&self, providers: &[String]) -> Result<ServerCache> {
        info!("Fetching server lists from gluetun for providers: {:?}", providers);

        let mut all_servers = Vec::new();
        let mut last_error = None;

        for provider in providers {
            match self.fetch_provider(provider).await {
                Ok(mut servers) => {
                    debug!("Fetched {} servers for provider '{}'", servers.len(), provider);
                    all_servers.append(&mut servers);
                }
                Err(e) => {
                    warn!("Failed to fetch servers for provider '{}': {}", provider, e);
                    last_error = Some(e);
                }
            }
        }

        // If nothing could be fetched, surface the error so the retry kicks in.
        // If at least one provider succeeded, keep the partial result.
        if all_servers.is_empty() {
            if let Some(e) = last_error {
                return Err(e);
            }
        }

        let provider_count = all_servers
            .iter()
            .map(|s| &s.provider)
            .collect::<HashSet<_>>()
            .len();

        let cache = ServerCache {
            metadata: CacheMetadata {
                fetched_at: Utc::now(),
                last_fetch_attempt: Utc::now(),
                provider_count,
                server_count: all_servers.len(),
            },
            servers: all_servers,
        };

        cache.save()?;
        info!(
            "Cached {} servers from {} providers",
            cache.metadata.server_count, cache.metadata.provider_count
        );

        Ok(cache)
    }

    /// Fetch and parse a single provider's server file.
    async fn fetch_provider(&self, provider: &str) -> Result<Vec<Server>> {
        let url = format!("{}/{}.json", GLUETUN_SERVERS_BASE_URL, provider);

        let response = timeout(
            std::time::Duration::from_secs(FETCH_TIMEOUT_SECS),
            self.client.get(&url).send(),
        )
        .await
        .map_err(|_| {
            VpnError::TimeoutError(format!("Server fetch timed out for provider '{}'", provider))
        })?
        .map_err(|e| {
            VpnError::NetworkError(format!("HTTP request failed for '{}': {}", provider, e))
        })?;

        if !response.status().is_success() {
            return Err(VpnError::NetworkError(format!(
                "HTTP error for provider '{}': {}",
                provider,
                response.status()
            )));
        }

        let data: ProviderServersFile = response.json().await.map_err(|e| {
            VpnError::NetworkError(format!("JSON parse failed for '{}': {}", provider, e))
        })?;

        Ok(self.parse_servers(provider, data.servers))
    }

    /// Parse a single provider's server entries into `Server` structs
    fn parse_servers(&self, provider: &str, entries: Vec<GluetunServer>) -> Vec<Server> {
        let mut servers = Vec::new();
        let mut seen_ids: HashSet<String> = HashSet::new();
        let mut skipped = 0;
        let mut duplicates = 0;

        for gs in entries {
            // Only include WireGuard servers
            if gs.vpn.as_deref() != Some("wireguard") {
                continue;
            }

            // Validate required fields
            let pubkey = match &gs.wgpubkey {
                Some(k) if !k.is_empty() => k.clone(),
                _ => {
                    skipped += 1;
                    continue;
                }
            };

            // Validate public key format
            if !validate_wg_key(&pubkey) {
                debug!("Skipping server with invalid pubkey: {:?}", gs.hostname);
                skipped += 1;
                continue;
            }

            // Prefer an IPv4 address for the WireGuard endpoint (some providers,
            // e.g. Mullvad, list IPv6 addresses alongside IPv4).
            let ip = match gs
                .ips
                .as_ref()
                .and_then(|ips| ips.iter().find(|ip| !ip.contains(':')).or_else(|| ips.first()))
            {
                Some(ip) => ip.clone(),
                None => {
                    skipped += 1;
                    continue;
                }
            };

            let country = gs.country.clone().unwrap_or_else(|| "Unknown".into());
            let country_code = Self::country_to_code(&country);
            let city = gs
                .city
                .clone()
                .or_else(|| gs.region.clone())
                .unwrap_or_else(|| "Unknown".into());
            let name = gs
                .server_name
                .clone()
                .or_else(|| gs.hostname.clone())
                .unwrap_or_else(|| format!("{}#{}", city, servers.len()));

            let mut server = Server::from_gluetun(
                name,
                country.clone(),
                country_code,
                city,
                ip,
                pubkey,
                provider.to_string(),
            );

            // Prefer explicit feature flags from the data, falling back to
            // hostname heuristics for providers that only encode them in the name.
            let hostname_lower = gs.hostname.as_deref().unwrap_or("").to_lowercase();
            server.features = ServerFeatures {
                p2p: gs.p2p.unwrap_or(false) || hostname_lower.contains("p2p"),
                tor: gs.tor.unwrap_or(false) || hostname_lower.contains("tor"),
                streaming: gs.stream.unwrap_or(false) || hostname_lower.contains("stream"),
                secure_core: gs.secure_core.unwrap_or(false)
                    || hostname_lower.contains("secure")
                    || hostname_lower.contains("plus"),
            };

            // Deduplicate by unique key (provider + name)
            let unique_key = format!("{}:{}", server.provider, server.name);
            if seen_ids.contains(&unique_key) {
                duplicates += 1;
                continue;
            }
            seen_ids.insert(unique_key);

            servers.push(server);
        }

        if skipped > 0 {
            debug!("[{}] Skipped {} invalid server entries", provider, skipped);
        }
        if duplicates > 0 {
            debug!("[{}] Skipped {} duplicate server entries", provider, duplicates);
        }

        servers
    }

    /// Convert country name to 2-letter ISO code
    fn country_to_code(country: &str) -> String {
        // Comprehensive country name to ISO 3166-1 alpha-2 code mapping
        let code = match country.to_lowercase().as_str() {
            // A
            "afghanistan" => "AF",
            "albania" => "AL",
            "algeria" => "DZ",
            "andorra" => "AD",
            "angola" => "AO",
            "argentina" => "AR",
            "armenia" => "AM",
            "australia" => "AU",
            "austria" | "osterreich" | "österreich" => "AT",
            "azerbaijan" => "AZ",
            // B
            "bahamas" => "BS",
            "bahrain" => "BH",
            "bangladesh" => "BD",
            "belarus" => "BY",
            "belgium" | "belgique" | "belgie" => "BE",
            "belize" => "BZ",
            "bolivia" => "BO",
            "bosnia" | "bosnia and herzegovina" => "BA",
            "brazil" | "brasil" => "BR",
            "brunei" => "BN",
            "bulgaria" => "BG",
            // C
            "cambodia" => "KH",
            "cameroon" => "CM",
            "canada" => "CA",
            "chile" => "CL",
            "china" => "CN",
            "colombia" => "CO",
            "costa rica" => "CR",
            "croatia" | "hrvatska" => "HR",
            "cyprus" => "CY",
            "czech republic" | "czechia" | "czech" => "CZ",
            // D
            "denmark" | "danmark" => "DK",
            "dominican republic" => "DO",
            // E
            "ecuador" => "EC",
            "egypt" => "EG",
            "el salvador" => "SV",
            "estonia" => "EE",
            "ethiopia" => "ET",
            // F
            "finland" | "suomi" => "FI",
            "france" => "FR",
            // G
            "georgia" => "GE",
            "germany" | "deutschland" => "DE",
            "ghana" => "GH",
            "greece" | "hellas" => "GR",
            "greenland" => "GL",
            "guatemala" => "GT",
            // H
            "honduras" => "HN",
            "hong kong" => "HK",
            "hungary" | "magyarorszag" | "magyarország" => "HU",
            // I
            "iceland" | "island" => "IS",
            "india" => "IN",
            "indonesia" => "ID",
            "iran" => "IR",
            "iraq" => "IQ",
            "ireland" => "IE",
            "isle of man" => "IM",
            "israel" => "IL",
            "italy" | "italia" => "IT",
            // J
            "jamaica" => "JM",
            "japan" | "nippon" => "JP",
            "jordan" => "JO",
            // K
            "kazakhstan" => "KZ",
            "kenya" => "KE",
            "south korea" | "korea" | "korea, south" | "republic of korea" => "KR",
            "north korea" | "korea, north" => "KP",
            "kuwait" => "KW",
            "kyrgyzstan" => "KG",
            // L
            "laos" => "LA",
            "latvia" => "LV",
            "lebanon" => "LB",
            "liechtenstein" => "LI",
            "lithuania" => "LT",
            "luxembourg" => "LU",
            // M
            "macao" | "macau" => "MO",
            "macedonia" | "north macedonia" => "MK",
            "malaysia" => "MY",
            "maldives" => "MV",
            "malta" => "MT",
            "mexico" | "méxico" => "MX",
            "moldova" => "MD",
            "monaco" => "MC",
            "mongolia" => "MN",
            "montenegro" => "ME",
            "morocco" => "MA",
            // N
            "nepal" => "NP",
            "netherlands" | "holland" | "the netherlands" => "NL",
            "new zealand" => "NZ",
            "nicaragua" => "NI",
            "nigeria" => "NG",
            "norway" | "norge" => "NO",
            // O
            "oman" => "OM",
            // P
            "pakistan" => "PK",
            "panama" => "PA",
            "paraguay" => "PY",
            "peru" => "PE",
            "philippines" => "PH",
            "poland" | "polska" => "PL",
            "portugal" => "PT",
            "puerto rico" => "PR",
            // Q
            "qatar" => "QA",
            // R
            "romania" => "RO",
            "russia" | "russian federation" => "RU",
            // S
            "saudi arabia" => "SA",
            "serbia" => "RS",
            "singapore" => "SG",
            "slovakia" => "SK",
            "slovenia" => "SI",
            "south africa" => "ZA",
            "spain" | "espana" | "españa" => "ES",
            "sri lanka" => "LK",
            "sweden" | "sverige" => "SE",
            "switzerland" | "suisse" | "schweiz" => "CH",
            // T
            "taiwan" => "TW",
            "tajikistan" => "TJ",
            "tanzania" => "TZ",
            "thailand" => "TH",
            "tunisia" => "TN",
            "turkey" | "türkiye" | "turkiye" => "TR",
            "turkmenistan" => "TM",
            // U
            "uganda" => "UG",
            "ukraine" => "UA",
            "united arab emirates" | "uae" => "AE",
            "united kingdom" | "uk" | "great britain" | "england" | "scotland" | "wales" => "GB",
            "united states" | "usa" | "us" | "united states of america" => "US",
            "uruguay" => "UY",
            "uzbekistan" => "UZ",
            // V
            "venezuela" => "VE",
            "vietnam" | "viet nam" => "VN",
            // Y
            "yemen" => "YE",
            // Z
            "zambia" => "ZM",
            "zimbabwe" => "ZW",
            _ => {
                // Try to extract code from hostname pattern like "xx.vpn.example.com"
                // or fallback to first two chars uppercase
                warn!("Unknown country: '{}', using fallback", country);
                return country.chars().take(2).collect::<String>().to_uppercase();
            }
        };
        code.to_string()
    }
}

impl Default for ServerFetcher {
    fn default() -> Self {
        Self::new()
    }
}

/// Get servers for the given providers, using cache if available and valid
pub async fn get_servers(force_refresh: bool, providers: &[String]) -> Result<ServerCache> {
    let cache = ServerCache::load()?;

    if let Some(mut cache) = cache {
        // A newly configured provider may not be present in an otherwise-fresh
        // cache; in that case we still want to fetch (subject to rate limiting).
        let missing_provider = !cache.has_all_providers(providers);

        if force_refresh {
            if !cache.can_fetch() {
                warn!("Rate limited: please wait before refreshing again");
                return Ok(cache);
            }
        } else if cache.is_stale() {
            warn!(
                "Server cache is older than {} days - refresh recommended",
                CACHE_MAX_AGE_DAYS
            );
            // Still return cache but warn
            if cache.can_fetch() {
                // Try to refresh in background
                match ServerFetcher::new().fetch(providers).await {
                    Ok(new_cache) => return Ok(new_cache),
                    Err(e) => {
                        warn!("Failed to refresh cache: {}. Using stale cache.", e);
                        return Ok(cache);
                    }
                }
            }
            return Ok(cache);
        } else if !cache.is_expired() && !missing_provider {
            debug!("Using cached server list");
            return Ok(cache);
        } else if missing_provider && !cache.can_fetch() {
            // Cache lacks a configured provider but we are rate limited:
            // return what we have rather than failing.
            warn!("Cache is missing some configured providers but a refresh is rate limited");
            return Ok(cache);
        }

        // Update last fetch attempt time
        cache.metadata.last_fetch_attempt = Utc::now();
        let _ = cache.save();
    }

    // Fetch new data
    let fetcher = ServerFetcher::new();
    match fetcher.fetch(providers).await {
        Ok(cache) => Ok(cache),
        Err(e) => {
            // If we have old cache, use it
            if let Ok(Some(old_cache)) = ServerCache::load() {
                warn!("Fetch failed: {}. Using cached data.", e);
                Ok(old_cache)
            } else {
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_country_to_code() {
        assert_eq!(ServerFetcher::country_to_code("United States"), "US");
        assert_eq!(ServerFetcher::country_to_code("Germany"), "DE");
        assert_eq!(ServerFetcher::country_to_code("Switzerland"), "CH");
        assert_eq!(ServerFetcher::country_to_code("Unknown Country"), "UN");
    }

    // A valid 44-char base64 WireGuard public key for use in tests.
    const TEST_WG_KEY: &str = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";

    fn parse(provider: &str, json: &str) -> Vec<Server> {
        let file: ProviderServersFile = serde_json::from_str(json).expect("valid provider file");
        ServerFetcher::new().parse_servers(provider, file.servers)
    }

    #[test]
    fn test_parse_per_provider_protonvpn_format() {
        // New per-provider file shape: { "version", "timestamp", "servers": [...] }
        let json = format!(
            r#"{{
                "version": 4,
                "timestamp": 1700000000,
                "servers": [
                    {{
                        "vpn": "wireguard",
                        "country": "Switzerland",
                        "city": "Zurich",
                        "server_name": "CH#1",
                        "hostname": "ch-01.protonvpn.net",
                        "wgpubkey": "{key}",
                        "ips": ["1.2.3.4"],
                        "secure_core": true,
                        "stream": true,
                        "tor": false
                    }},
                    {{
                        "vpn": "openvpn",
                        "country": "Switzerland",
                        "city": "Zurich",
                        "server_name": "CH#2",
                        "hostname": "ch-02.protonvpn.net",
                        "ips": ["1.2.3.4"]
                    }}
                ]
            }}"#,
            key = TEST_WG_KEY
        );

        let servers = parse("protonvpn", &json);
        // OpenVPN server is filtered out; only the WireGuard one remains.
        assert_eq!(servers.len(), 1);
        let s = &servers[0];
        assert_eq!(s.provider, "protonvpn");
        assert_eq!(s.country_code, "CH");
        assert_eq!(s.ip, "1.2.3.4");
        assert!(s.features.secure_core);
        assert!(s.features.streaming);
        assert!(!s.features.tor);
    }

    #[test]
    fn test_parse_per_provider_mullvad_prefers_ipv4() {
        let json = format!(
            r#"{{
                "version": 4,
                "servers": [
                    {{
                        "vpn": "wireguard",
                        "country": "Sweden",
                        "city": "Gothenburg",
                        "hostname": "se-got-wg-001",
                        "wgpubkey": "{key}",
                        "ips": ["2a03:1b20::1", "185.65.135.1"]
                    }}
                ]
            }}"#,
            key = TEST_WG_KEY
        );

        let servers = parse("mullvad", &json);
        assert_eq!(servers.len(), 1);
        // IPv4 is preferred over the IPv6 address even though it is listed second.
        assert_eq!(servers[0].ip, "185.65.135.1");
        assert_eq!(servers[0].country_code, "SE");
    }

    #[test]
    fn test_parse_skips_invalid_and_missing_fields() {
        let json = r#"{
            "servers": [
                { "vpn": "wireguard", "country": "France", "wgpubkey": "too-short", "ips": ["1.1.1.1"] },
                { "vpn": "wireguard", "country": "France", "ips": ["1.1.1.1"] }
            ]
        }"#;
        let servers = parse("protonvpn", json);
        assert!(servers.is_empty());
    }

    #[test]
    fn test_has_all_providers() {
        let cache = ServerCache {
            metadata: CacheMetadata {
                fetched_at: Utc::now(),
                last_fetch_attempt: Utc::now(),
                provider_count: 1,
                server_count: 1,
            },
            servers: vec![Server::from_gluetun(
                "CH#1".into(),
                "Switzerland".into(),
                "CH".into(),
                "Zurich".into(),
                "1.2.3.4".into(),
                TEST_WG_KEY.into(),
                "protonvpn".into(),
            )],
        };

        assert!(cache.has_all_providers(&["protonvpn".to_string()]));
        assert!(cache.has_all_providers(&["ProtonVPN".to_string()]));
        assert!(!cache.has_all_providers(&["protonvpn".to_string(), "mullvad".to_string()]));
    }
}
