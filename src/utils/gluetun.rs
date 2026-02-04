//! Gluetun server list fetcher with caching

use crate::core::config::AppConfig;
use crate::core::error::{Result, VpnError};
use crate::core::server::{validate_wg_key, Server, ServerFeatures};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tokio::time::timeout;
use tracing::{debug, info, warn};

const GLUETUN_SERVERS_URL: &str =
    "https://raw.githubusercontent.com/qdm12/gluetun/master/internal/storage/servers.json";
const CACHE_EXPIRY_HOURS: i64 = 24;
const CACHE_MAX_AGE_DAYS: i64 = 7;
const MIN_FETCH_INTERVAL_SECS: u64 = 300; // 5 minutes
const FETCH_TIMEOUT_SECS: u64 = 30;
const MAX_RETRIES: u32 = 3;

/// Gluetun server entry from JSON
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
}

/// Provider data containing version and servers list
#[derive(Debug, Deserialize)]
struct ProviderData {
    #[serde(default)]
    servers: Vec<GluetunServer>,
}

/// Gluetun servers.json structure (new format)
#[derive(Debug, Deserialize)]
struct GluetunData {
    #[serde(default)]
    version: u32,
    #[serde(flatten)]
    providers: HashMap<String, ProviderData>,
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

    /// Fetch servers from gluetun with retry logic
    pub async fn fetch(&self) -> Result<ServerCache> {
        let mut last_error = None;

        for attempt in 1..=MAX_RETRIES {
            match self.fetch_once().await {
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

    /// Single fetch attempt
    async fn fetch_once(&self) -> Result<ServerCache> {
        info!("Fetching server list from gluetun...");

        let response = timeout(
            std::time::Duration::from_secs(FETCH_TIMEOUT_SECS),
            self.client.get(GLUETUN_SERVERS_URL).send(),
        )
        .await
        .map_err(|_| VpnError::TimeoutError("Server fetch timed out".into()))?
        .map_err(|e| VpnError::NetworkError(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(VpnError::NetworkError(format!(
                "HTTP error: {}",
                response.status()
            )));
        }

        let data: GluetunData = response
            .json()
            .await
            .map_err(|e| VpnError::NetworkError(format!("JSON parse failed: {}", e)))?;

        let servers = self.parse_servers(data)?;

        let cache = ServerCache {
            metadata: CacheMetadata {
                fetched_at: Utc::now(),
                last_fetch_attempt: Utc::now(),
                provider_count: servers
                    .iter()
                    .map(|s| &s.provider)
                    .collect::<std::collections::HashSet<_>>()
                    .len(),
                server_count: servers.len(),
            },
            servers,
        };

        cache.save()?;
        info!(
            "Cached {} servers from {} providers",
            cache.metadata.server_count, cache.metadata.provider_count
        );

        Ok(cache)
    }

    /// Parse gluetun JSON into Server structs
    fn parse_servers(&self, data: GluetunData) -> Result<Vec<Server>> {
        let mut servers = Vec::new();
        let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut skipped = 0;
        let mut duplicates = 0;

        for (provider, provider_data) in data.providers {
            // Skip non-provider keys
            if provider == "version" {
                continue;
            }

            for gs in provider_data.servers {
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

                let ip = match &gs.ips {
                    Some(ips) if !ips.is_empty() => ips[0].clone(),
                    _ => {
                        skipped += 1;
                        continue;
                    }
                };

                let country = gs.country.clone().unwrap_or_else(|| "Unknown".into());
                let country_code = Self::country_to_code(&country);
                let city = gs.city.clone().or(gs.region.clone()).unwrap_or_else(|| "Unknown".into());
                let name = gs.server_name.clone()
                    .or(gs.hostname.clone())
                    .unwrap_or_else(|| format!("{}#{}", city, servers.len()));

                let mut server = Server::from_gluetun(
                    name,
                    country.clone(),
                    country_code,
                    city,
                    ip,
                    pubkey,
                    provider.clone(),
                );

                // Parse features from server name/hostname
                if let Some(ref hostname) = gs.hostname {
                    let hostname_lower = hostname.to_lowercase();
                    server.features = ServerFeatures {
                        p2p: hostname_lower.contains("p2p"),
                        tor: hostname_lower.contains("tor"),
                        streaming: hostname_lower.contains("stream"),
                        secure_core: hostname_lower.contains("secure") || hostname_lower.contains("plus"),
                    };
                }

                // Deduplicate by unique key (provider + name)
                let unique_key = format!("{}:{}", server.provider, server.name);
                if seen_ids.contains(&unique_key) {
                    duplicates += 1;
                    continue;
                }
                seen_ids.insert(unique_key);

                servers.push(server);
            }
        }

        if skipped > 0 {
            debug!("Skipped {} invalid server entries", skipped);
        }
        if duplicates > 0 {
            debug!("Skipped {} duplicate server entries", duplicates);
        }

        Ok(servers)
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

/// Get servers, using cache if available and valid
pub async fn get_servers(force_refresh: bool) -> Result<ServerCache> {
    let cache = ServerCache::load()?;

    if let Some(mut cache) = cache {
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
                match ServerFetcher::new().fetch().await {
                    Ok(new_cache) => return Ok(new_cache),
                    Err(e) => {
                        warn!("Failed to refresh cache: {}. Using stale cache.", e);
                        return Ok(cache);
                    }
                }
            }
            return Ok(cache);
        } else if !cache.is_expired() && !force_refresh {
            debug!("Using cached server list");
            return Ok(cache);
        }

        // Update last fetch attempt time
        cache.metadata.last_fetch_attempt = Utc::now();
        let _ = cache.save();
    }

    // Fetch new data
    let fetcher = ServerFetcher::new();
    match fetcher.fetch().await {
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
}
