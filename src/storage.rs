use std::collections::HashMap;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// CapabilityType — enum polimórfico snake_case
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityType {
    Email,
    Calendar,
    Contacts,
    Chat,
    Drive,
    Tasks,
}

// ---------------------------------------------------------------------------
// AccessControlEntry — entrada de lista blanca (ACL)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlEntry {
    pub binary_path: String,
    pub allowed_capabilities: Vec<CapabilityType>,
}

// ---------------------------------------------------------------------------
// Account — struct principal de cuenta
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub display_name: String,
    pub provider_type: String,
    pub capabilities: HashMap<CapabilityType, Value>,
    pub acl: Vec<AccessControlEntry>,
}

impl Account {
    pub fn new(
        display_name: &str,
        provider_type: &str,
        capabilities: HashMap<CapabilityType, Value>,
    ) -> Self {
        Account {
            id: uuid::Uuid::new_v4().to_string(),
            display_name: display_name.to_string(),
            provider_type: provider_type.to_string(),
            capabilities,
            acl: Vec::new(),
        }
    }

    pub fn add_acl_entry(&mut self, entry: AccessControlEntry) {
        self.acl.push(entry);
    }
}

// ---------------------------------------------------------------------------
// StorageError
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Keyring(keyring::Error),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Io(e) => write!(f, "IO error: {}", e),
            StorageError::Json(e) => write!(f, "JSON error: {}", e),
            StorageError::Keyring(e) => write!(f, "Keyring error: {}", e),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StorageError::Io(e) => Some(e),
            StorageError::Json(e) => Some(e),
            StorageError::Keyring(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self { StorageError::Io(e) }
}

impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self { StorageError::Json(e) }
}

impl From<keyring::Error> for StorageError {
    fn from(e: keyring::Error) -> Self { StorageError::Keyring(e) }
}

// ---------------------------------------------------------------------------
// AccountDatabase — contenedor con persistencia JSON
// ---------------------------------------------------------------------------

pub struct AccountDatabase {
    path: PathBuf,
    pub accounts: Vec<Account>,
}

impl AccountDatabase {
    const DIR_NAME: &'static str = "vasakos";
    const FILE_NAME: &'static str = "accounts.json";

    pub fn new() -> Result<Self, StorageError> {
        Self::with_override(None)
    }

    fn with_override(base: Option<PathBuf>) -> Result<Self, StorageError> {
        let path = base
            .unwrap_or_else(|| {
                dirs::config_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(Self::DIR_NAME)
                    .join(Self::FILE_NAME)
            });

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        Ok(AccountDatabase {
            path,
            accounts: Vec::new(),
        })
    }

    /// Lee `accounts.json` y carga las cuentas en memoria.
    /// Si el archivo no existe, deja la lista vacía.
    pub fn load(&mut self) -> Result<(), StorageError> {
        if !self.path.exists() {
            self.accounts.clear();
            return Ok(());
        }
        let data = std::fs::read_to_string(&self.path)?;
        self.accounts = serde_json::from_str(&data)?;
        Ok(())
    }

    /// Persiste el estado actual de `accounts` a `accounts.json`.
    pub fn save(&self) -> Result<(), StorageError> {
        let data = serde_json::to_string_pretty(&self.accounts)?;
        std::fs::write(&self.path, data)?;
        Ok(())
    }

    /// Agrega una cuenta, persiste y retorna el ID asignado.
    pub fn add(&mut self, account: Account) -> Result<String, StorageError> {
        let id = account.id.clone();
        self.accounts.push(account);
        self.save()?;
        Ok(id)
    }

    pub fn all(&self) -> &[Account] {
        &self.accounts
    }

    pub fn get(&self, id: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.id == id)
    }

    pub fn update_account(&mut self, updated: Account) -> Result<(), StorageError> {
        let id = updated.id.clone();
        let pos = self
            .accounts
            .iter()
            .position(|a| a.id == id)
            .ok_or_else(|| {
                StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Account '{}' not found for update", id),
                ))
            })?;
        self.accounts[pos] = updated;
        self.save()?;
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> Result<bool, StorageError> {
        let len = self.accounts.len();
        self.accounts.retain(|a| a.id != id);
        if self.accounts.len() != len {
            self.save()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }
}

// ---------------------------------------------------------------------------
// SecureKeyringManager — llavero del sistema (Secret Service)
// ---------------------------------------------------------------------------

const KEYRING_SERVICE: &str = "vasakos-account-manager";

pub struct SecureKeyringManager;

impl SecureKeyringManager {
    /// Guarda un token OAuth2 / contraseña en el Secret Service de Linux.
    pub fn store_token(account_id: &str, token: &str) -> Result<(), StorageError> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, account_id)?;
        entry.set_password(token)?;
        Ok(())
    }

    /// Recupera un token previamente guardado.
    pub fn get_token(account_id: &str) -> Result<String, StorageError> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, account_id)?;
        let password = entry.get_password()?;
        Ok(password)
    }

    /// Elimina un token del llavero.
    pub fn delete_token(account_id: &str) -> Result<(), StorageError> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, account_id)?;
        entry.delete_credential()?;
        Ok(())
    }

    /// Guarda un secreto identificado por una clave adicional
    /// (ej. "refresh", "client_secret") en el llavero.
    pub fn store_secret(account_id: &str, key: &str, secret: &str) -> Result<(), StorageError> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, &format!("{}:{}", account_id, key))?;
        entry.set_password(secret)?;
        Ok(())
    }

    /// Lee un secreto previamente guardado con `store_secret`.
    pub fn get_secret(account_id: &str, key: &str) -> Result<String, StorageError> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, &format!("{}:{}", account_id, key))?;
        Ok(entry.get_password()?)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_account() -> Account {
        let mut caps = HashMap::new();
        caps.insert(
            CapabilityType::Email,
            json!({
                "address": "alice@gmail.com",
                "imap_host": "imap.gmail.com",
                "imap_port": 993,
            }),
        );
        caps.insert(
            CapabilityType::Drive,
            json!({
                "root_folder": "/",
                "max_storage_gb": 15,
            }),
        );
        let mut account = Account::new("Alice Google", "google", caps);
        account.acl = vec![
            AccessControlEntry {
                binary_path: "/usr/bin/thunderbird".into(),
                allowed_capabilities: vec![CapabilityType::Email],
            },
            AccessControlEntry {
                binary_path: "/usr/bin/rclone".into(),
                allowed_capabilities: vec![CapabilityType::Drive, CapabilityType::Tasks],
            },
        ];
        account
    }

    #[test]
    fn test_account_serde_roundtrip() {
        let account = sample_account();

        let json = serde_json::to_string_pretty(&account).unwrap();
        let deserialized: Account = serde_json::from_str(&json).unwrap();

        assert_eq!(account.id, deserialized.id);
        assert_eq!(account.display_name, deserialized.display_name);
        assert_eq!(account.provider_type, deserialized.provider_type);
        assert_eq!(
            account.capabilities.get(&CapabilityType::Email),
            deserialized.capabilities.get(&CapabilityType::Email),
        );
    }

    #[test]
    fn test_acl_serde_roundtrip() {
        let account = sample_account();
        assert_eq!(account.acl.len(), 2);

        let json = serde_json::to_string_pretty(&account).unwrap();
        let deserialized: Account = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.acl.len(), 2);
        assert_eq!(deserialized.acl[0].binary_path, "/usr/bin/thunderbird");
        assert_eq!(deserialized.acl[1].allowed_capabilities, vec![CapabilityType::Drive, CapabilityType::Tasks]);
    }

    #[test]
    fn test_update_account() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::with_override(Some(dir.clone())).unwrap();
        db.load().unwrap();
        let id = db.add(sample_account()).unwrap();

        let mut updated = db.get(&id).unwrap().clone();
        updated.display_name = "Updated Name".into();
        db.update_account(updated).unwrap();

        let reloaded = db.get(&id).unwrap();
        assert_eq!(reloaded.display_name, "Updated Name");

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    #[test]
    fn test_add_acl_entry_helper() {
        let mut account = Account::new("Test", "local", HashMap::new());
        assert!(account.acl.is_empty());
        account.add_acl_entry(AccessControlEntry {
            binary_path: "/usr/bin/foo".into(),
            allowed_capabilities: vec![CapabilityType::Email],
        });
        assert_eq!(account.acl.len(), 1);
    }

    #[test]
    fn test_capability_type_snake_case() {
        let json = serde_json::to_string(&CapabilityType::Email).unwrap();
        assert_eq!(json, "\"email\"");

        let json = serde_json::to_string(&CapabilityType::Calendar).unwrap();
        assert_eq!(json, "\"calendar\"");

        let json = serde_json::to_string(&CapabilityType::Contacts).unwrap();
        assert_eq!(json, "\"contacts\"");
    }

    #[test]
    fn test_database_load_save_roundtrip() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());

        let mut db = AccountDatabase::with_override(Some(dir.clone())).unwrap();
        db.load().unwrap();
        assert!(db.is_empty());

        db.add(sample_account()).unwrap();
        assert_eq!(db.len(), 1);

        let mut db2 = AccountDatabase::with_override(Some(dir.clone())).unwrap();
        db2.load().unwrap();
        assert_eq!(db2.len(), 1);
        assert_eq!(db2.get(&db.accounts[0].id).unwrap().display_name, "Alice Google");

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }
}
