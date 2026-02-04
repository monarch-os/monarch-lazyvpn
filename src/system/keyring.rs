//! Secure credential storage with keyring and encrypted file fallback

use crate::core::config::AppConfig;
use crate::core::error::{Result, VpnError};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

const SERVICE_NAME: &str = "monarch-lazyvpn";
const KEYFILE_EXPIRY_HOURS: u64 = 24;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Provider credentials stored in keyring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCredentials {
    pub private_key: String,
    pub address: String,
    pub provider_name: String,
}

/// Encrypted credentials file format
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedCredentials {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    password_hash: Vec<u8>,
}

/// Session cache for password (encrypted)
#[derive(Debug, Serialize, Deserialize)]
struct KeyfileCache {
    encrypted_password: Vec<u8>,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    verification_hash: Vec<u8>,
    timestamp: u64,
}

/// Credential manager with keyring and encrypted fallback
pub struct CredentialManager {
    use_fallback: bool,
    fallback_password: Option<String>,
}

impl CredentialManager {
    /// Create a new credential manager
    pub fn new() -> Self {
        let use_fallback = !Self::is_keyring_available();
        Self {
            use_fallback,
            fallback_password: None,
        }
    }

    /// Check if system keyring (libsecret/D-Bus) is available
    fn is_keyring_available() -> bool {
        // Try to access keyring - if it fails, fallback mode
        match keyring::Entry::new(SERVICE_NAME, "test") {
            Ok(entry) => {
                // Try a dummy operation to verify D-Bus is working
                match entry.get_password() {
                    Err(keyring::Error::NoEntry) => true, // Keyring works, just no entry
                    Err(keyring::Error::PlatformFailure(_)) => false,
                    Err(keyring::Error::NoStorageAccess(_)) => false,
                    _ => true,
                }
            }
            Err(_) => false,
        }
    }

    /// Get path for encrypted credentials file
    fn encrypted_file_path(provider: &str) -> Result<PathBuf> {
        let config_dir = AppConfig::config_dir()?;
        fs::create_dir_all(&config_dir)?;
        Ok(config_dir.join(format!(".credentials_{}.enc", provider)))
    }

    /// Get path for keyfile cache
    fn keyfile_path() -> Result<PathBuf> {
        let config_dir = AppConfig::config_dir()?;
        Ok(config_dir.join(".keyfile"))
    }

    /// Derive encryption key from password using Argon2id
    fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
        let mut key = [0u8; KEY_LEN];
        Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| VpnError::EncryptionError(format!("Key derivation failed: {}", e)))?;
        Ok(key)
    }

    /// Hash password for verification
    fn hash_password(password: &str, salt: &[u8]) -> Result<Vec<u8>> {
        let mut hash = [0u8; 32];
        Argon2::default()
            .hash_password_into(password.as_bytes(), salt, &mut hash)
            .map_err(|e| VpnError::EncryptionError(format!("Password hashing failed: {}", e)))?;
        Ok(hash.to_vec())
    }

    /// Encrypt credentials with AES-256-GCM
    fn encrypt(data: &[u8], password: &str) -> Result<EncryptedCredentials> {
        let mut rng = rand::thread_rng();

        // Generate random salt and nonce
        let mut salt = vec![0u8; SALT_LEN];
        let mut nonce_bytes = vec![0u8; NONCE_LEN];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce_bytes);

        // Derive key
        let key = Self::derive_key(password, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| VpnError::EncryptionError(format!("Cipher init failed: {}", e)))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| VpnError::EncryptionError(format!("Encryption failed: {}", e)))?;

        // Hash password for verification
        let password_hash = Self::hash_password(password, &salt)?;

        Ok(EncryptedCredentials {
            salt,
            nonce: nonce_bytes,
            ciphertext,
            password_hash,
        })
    }

    /// Decrypt credentials
    fn decrypt(encrypted: &EncryptedCredentials, password: &str) -> Result<Vec<u8>> {
        // Verify password first
        let password_hash = Self::hash_password(password, &encrypted.salt)?;
        if password_hash != encrypted.password_hash {
            return Err(VpnError::EncryptionError("Invalid password".to_string()));
        }

        // Derive key and decrypt
        let key = Self::derive_key(password, &encrypted.salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| VpnError::EncryptionError(format!("Cipher init failed: {}", e)))?;

        let nonce = Nonce::from_slice(&encrypted.nonce);
        cipher
            .decrypt(nonce, encrypted.ciphertext.as_slice())
            .map_err(|e| VpnError::EncryptionError(format!("Decryption failed: {}", e)))
    }

    /// Check if cached password is still valid and retrieve it
    fn get_cached_password(&self) -> Result<Option<String>> {
        let keyfile_path = Self::keyfile_path()?;
        if !keyfile_path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&keyfile_path)?;
        let cache: KeyfileCache = serde_json::from_str(&content)
            .map_err(|_| VpnError::EncryptionError("Invalid keyfile".to_string()))?;

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expiry = Duration::from_secs(KEYFILE_EXPIRY_HOURS * 3600);
        if now - cache.timestamp > expiry.as_secs() {
            // Expired, remove cache
            let _ = fs::remove_file(&keyfile_path);
            return Ok(None);
        }

        // Decrypt the cached password using machine-specific key
        let machine_key = Self::get_machine_key()?;
        let key = Self::derive_key(&machine_key, &cache.salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| VpnError::EncryptionError(format!("Cipher init failed: {}", e)))?;

        let nonce = Nonce::from_slice(&cache.nonce);
        let password_bytes = cipher
            .decrypt(nonce, cache.encrypted_password.as_slice())
            .map_err(|_| VpnError::EncryptionError("Cache decryption failed".to_string()))?;

        let password = String::from_utf8(password_bytes)
            .map_err(|_| VpnError::EncryptionError("Invalid cached password".to_string()))?;

        Ok(Some(password))
    }

    /// Get machine-specific key for cache encryption
    fn get_machine_key() -> Result<String> {
        // Use machine-id as basis for encryption key (session-specific, not stored)
        let machine_id = fs::read_to_string("/etc/machine-id")
            .or_else(|_| fs::read_to_string("/var/lib/dbus/machine-id"))
            .map_err(|_| VpnError::EncryptionError("Cannot read machine-id".to_string()))?;

        Ok(format!("monarch-lazyvpn-{}", machine_id.trim()))
    }

    /// Save encrypted password to cache
    fn cache_password(&self, password: &str) -> Result<()> {
        let keyfile_path = Self::keyfile_path()?;

        let mut rng = rand::thread_rng();
        let mut salt = vec![0u8; SALT_LEN];
        let mut nonce_bytes = vec![0u8; NONCE_LEN];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce_bytes);

        // Encrypt password with machine-specific key
        let machine_key = Self::get_machine_key()?;
        let key = Self::derive_key(&machine_key, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| VpnError::EncryptionError(format!("Cipher init failed: {}", e)))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let encrypted_password = cipher
            .encrypt(nonce, password.as_bytes())
            .map_err(|e| VpnError::EncryptionError(format!("Encryption failed: {}", e)))?;

        // Create verification hash
        let verification_hash = Self::hash_password(password, &salt)?;

        let cache = KeyfileCache {
            encrypted_password,
            salt,
            nonce: nonce_bytes,
            verification_hash,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        let content = serde_json::to_string(&cache)?;

        // Create file with 0600 permissions
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&keyfile_path)?;

        file.write_all(content.as_bytes())?;
        Ok(())
    }

    /// Prompt for password (interactive)
    pub fn prompt_password(prompt: &str) -> Result<String> {
        rpassword::prompt_password(prompt)
            .map_err(|e| VpnError::KeyringError(format!("Failed to read password: {}", e)))
    }

    /// Set fallback password for session
    pub fn set_fallback_password(&mut self, password: String) {
        self.fallback_password = Some(password);
    }

    /// Store credentials
    pub fn store(&mut self, provider: &str, credentials: &ProviderCredentials) -> Result<()> {
        let data = serde_json::to_string(credentials)?;

        if self.use_fallback {
            // Use encrypted file fallback
            let password = if let Some(ref pwd) = self.fallback_password {
                pwd.clone()
            } else if let Some(cached) = self.get_cached_password()? {
                self.fallback_password = Some(cached.clone());
                cached
            } else {
                let pwd = Self::prompt_password("Enter encryption password for credentials: ")?;
                self.fallback_password = Some(pwd.clone());
                self.cache_password(&pwd)?;
                pwd
            };

            let encrypted = Self::encrypt(data.as_bytes(), &password)?;
            let path = Self::encrypted_file_path(provider)?;

            // Create file with 0600 permissions
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)?;

            let content = serde_json::to_string(&encrypted)?;
            file.write_all(content.as_bytes())?;
        } else {
            // Use system keyring
            let entry = keyring::Entry::new(SERVICE_NAME, provider)
                .map_err(|e| VpnError::KeyringError(format!("Failed to create entry: {}", e)))?;

            entry
                .set_password(&data)
                .map_err(|e| VpnError::KeyringError(format!("Failed to store: {}", e)))?;
        }

        Ok(())
    }

    /// Retrieve credentials
    pub fn retrieve(&mut self, provider: &str) -> Result<ProviderCredentials> {
        if self.use_fallback {
            let path = Self::encrypted_file_path(provider)?;
            if !path.exists() {
                return Err(VpnError::KeyringError(format!(
                    "No credentials found for provider: {}",
                    provider
                )));
            }

            let content = fs::read_to_string(&path)?;
            let encrypted: EncryptedCredentials = serde_json::from_str(&content)?;

            let password = if let Some(ref pwd) = self.fallback_password {
                pwd.clone()
            } else if let Some(cached) = self.get_cached_password()? {
                self.fallback_password = Some(cached.clone());
                cached
            } else {
                let pwd = Self::prompt_password("Enter decryption password: ")?;
                self.fallback_password = Some(pwd.clone());
                self.cache_password(&pwd)?;
                pwd
            };

            let data = Self::decrypt(&encrypted, &password)?;
            let credentials: ProviderCredentials = serde_json::from_slice(&data)?;
            Ok(credentials)
        } else {
            let entry = keyring::Entry::new(SERVICE_NAME, provider)
                .map_err(|e| VpnError::KeyringError(format!("Failed to create entry: {}", e)))?;

            let data = entry
                .get_password()
                .map_err(|e| VpnError::KeyringError(format!("Failed to retrieve: {}", e)))?;

            let credentials: ProviderCredentials = serde_json::from_str(&data)?;
            Ok(credentials)
        }
    }

    /// Delete credentials
    pub fn delete(&self, provider: &str) -> Result<()> {
        if self.use_fallback {
            let path = Self::encrypted_file_path(provider)?;
            if path.exists() {
                fs::remove_file(&path)?;
            }
        } else {
            let entry = keyring::Entry::new(SERVICE_NAME, provider)
                .map_err(|e| VpnError::KeyringError(format!("Failed to create entry: {}", e)))?;

            entry
                .delete_password()
                .map_err(|e| VpnError::KeyringError(format!("Failed to delete: {}", e)))?;
        }

        Ok(())
    }

    /// Check if credentials exist for provider
    pub fn exists(&self, provider: &str) -> bool {
        if self.use_fallback {
            Self::encrypted_file_path(provider)
                .map(|p| p.exists())
                .unwrap_or(false)
        } else {
            keyring::Entry::new(SERVICE_NAME, provider)
                .and_then(|e| e.get_password())
                .is_ok()
        }
    }

    /// Check if using fallback mode
    pub fn is_using_fallback(&self) -> bool {
        self.use_fallback
    }
}

impl Default for CredentialManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let data = b"test secret data";
        let password = "testpassword123";

        let encrypted = CredentialManager::encrypt(data, password).unwrap();
        let decrypted = CredentialManager::decrypt(&encrypted, password).unwrap();

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_wrong_password() {
        let data = b"test secret data";
        let password = "correct_password";
        let wrong_password = "wrong_password";

        let encrypted = CredentialManager::encrypt(data, password).unwrap();
        let result = CredentialManager::decrypt(&encrypted, wrong_password);

        assert!(result.is_err());
        if let Err(VpnError::EncryptionError(msg)) = result {
            assert!(msg.contains("Invalid password"));
        }
    }

    #[test]
    fn test_derive_key_consistency() {
        let password = "test_password";
        let salt = vec![1u8; SALT_LEN];

        let key1 = CredentialManager::derive_key(password, &salt).unwrap();
        let key2 = CredentialManager::derive_key(password, &salt).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_salts() {
        let password = "test_password";
        let salt1 = vec![1u8; SALT_LEN];
        let salt2 = vec![2u8; SALT_LEN];

        let key1 = CredentialManager::derive_key(password, &salt1).unwrap();
        let key2 = CredentialManager::derive_key(password, &salt2).unwrap();

        assert_ne!(key1, key2, "Different salts should produce different keys");
    }

    #[test]
    fn test_hash_password_consistency() {
        let password = "test_password";
        let salt = vec![1u8; SALT_LEN];

        let hash1 = CredentialManager::hash_password(password, &salt).unwrap();
        let hash2 = CredentialManager::hash_password(password, &salt).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_encrypted_credentials_structure() {
        let data = b"test data";
        let password = "password123";

        let encrypted = CredentialManager::encrypt(data, password).unwrap();

        // Verify structure
        assert_eq!(encrypted.salt.len(), SALT_LEN);
        assert_eq!(encrypted.nonce.len(), NONCE_LEN);
        assert!(!encrypted.ciphertext.is_empty());
        assert!(!encrypted.password_hash.is_empty());

        // Verify password hash is valid
        let verify_hash = CredentialManager::hash_password(password, &encrypted.salt).unwrap();
        assert_eq!(encrypted.password_hash, verify_hash);
    }

    #[test]
    fn test_machine_key_retrieval() {
        // Test machine key can be retrieved (won't test actual value as it's system-specific)
        let result = CredentialManager::get_machine_key();

        // Should succeed on Linux systems with machine-id
        // May fail on non-standard systems, which is acceptable
        if result.is_ok() {
            let key = result.unwrap();
            assert!(key.starts_with("monarch-lazyvpn-"));
            assert!(key.len() > "monarch-lazyvpn-".len());
        }
    }

    #[test]
    fn test_keyring_available_check() {
        // Just verify the function runs without panic
        let _available = CredentialManager::is_keyring_available();
        // Result depends on system configuration
    }
}
