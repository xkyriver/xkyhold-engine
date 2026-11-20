//! Secrets kept in the system keyring: the Secret Service (GNOME Keyring,
//! KWallet) on Linux, the Credential Manager on Windows. They are the
//! repository master key, so automatic backups need no password, and the
//! Google refresh token. The password itself is never stored.
//!
//! Without a keyring, nothing is stored: the app asks for the password at
//! each backup and automatic backup is unavailable.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use keyring_core::{Entry, Error as KeyringError};

#[cfg(not(windows))]
const SERVICE: &str = "xkyhold-lx";
#[cfg(windows)]
const SERVICE: &str = "xkyhold-wd";

#[derive(Debug)]
pub struct SecretsError(pub String);

impl std::fmt::Display for SecretsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the keyring could not be used: {}", self.0)
    }
}

impl std::error::Error for SecretsError {}

pub type Result<T> = std::result::Result<T, SecretsError>;

/// Where secrets live. Keys are short ASCII names such as
/// `repo-key:<repo id>` or `google-refresh:<account>`.
pub trait SecretStore: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn set(&self, key: &str, secret: &[u8]) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
}

pub fn repo_key(repo_id: &str) -> String {
    format!("repo-key:{repo_id}")
}

pub fn google_refresh(account: &str) -> String {
    format!("google-refresh:{account}")
}

/// The system keyring: the desktop's Secret Service over D-Bus on Linux,
/// the Credential Manager on Windows. The name is kept from XkyHold-lx.
pub struct SecretService;

/// The same keyring under a name that fits every system.
pub type SystemKeyring = SecretService;

impl SecretService {
    /// Connects to the keyring; fails if there is none. On Linux a session
    /// bus alone is not enough: a lookup must answer (a fresh user started
    /// with `machinectl shell` has the bus and no keyring daemon).
    pub fn connect() -> Result<Self> {
        #[cfg(not(windows))]
        let store = zbus_secret_service_keyring_store::Store::new().map_err(|e| SecretsError(e.to_string()))?;
        #[cfg(windows)]
        let store = windows_native_keyring_store::Store::new().map_err(|e| SecretsError(e.to_string()))?;
        keyring_core::set_default_store(store);
        let service = SecretService;
        service.get("probe")?;
        Ok(service)
    }

    fn entry(key: &str) -> Result<Entry> {
        Entry::new(SERVICE, key).map_err(|e| SecretsError(e.to_string()))
    }
}

impl SecretStore for SecretService {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match Self::entry(key)?.get_secret() {
            Ok(secret) => Ok(Some(secret)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => Err(SecretsError(e.to_string())),
        }
    }

    fn set(&self, key: &str, secret: &[u8]) -> Result<()> {
        Self::entry(key)?.set_secret(secret).map_err(|e| SecretsError(e.to_string()))
    }

    fn delete(&self, key: &str) -> Result<()> {
        match Self::entry(key)?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(e) => Err(SecretsError(e.to_string())),
        }
    }
}

/// Secrets in memory, for tests and for a session without a Secret Service.
#[derive(Default, Clone)]
pub struct MemorySecrets(Arc<Mutex<HashMap<String, Vec<u8>>>>);

impl SecretStore for MemorySecrets {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().get(key).cloned())
    }

    fn set(&self, key: &str, secret: &[u8]) -> Result<()> {
        self.0.lock().unwrap().insert(key.to_owned(), secret.to_vec());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    /// Writes, reads back and deletes one entry in the real Credential
    /// Manager of the user running the test, under a test-only key.
    #[test]
    fn credential_manager_round_trip() {
        let keyring = SystemKeyring::connect().unwrap();
        let key = "test-only:secrets-round-trip";
        keyring.set(key, &[0, 1, 2, 255]).unwrap();
        assert_eq!(keyring.get(key).unwrap(), Some(vec![0, 1, 2, 255]));
        keyring.delete(key).unwrap();
        assert_eq!(keyring.get(key).unwrap(), None);
        keyring.delete(key).unwrap();
    }
}
