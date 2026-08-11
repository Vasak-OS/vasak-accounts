use std::collections::HashMap;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
// Account — struct principal de cuenta
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub display_name: String,
    pub provider_type: String,
    pub capabilities: HashMap<CapabilityType, Value>,
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
        }
    }

}

// ---------------------------------------------------------------------------
// StorageError
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum StorageError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Io(e) => write!(f, "IO error: {}", e),
            StorageError::Json(e) => write!(f, "JSON error: {}", e),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StorageError::Io(e) => Some(e),
            StorageError::Json(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self { StorageError::Io(e) }
}

impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self { StorageError::Json(e) }
}

// ---------------------------------------------------------------------------
// AccountDatabase — contenedor con persistencia JSON
// ---------------------------------------------------------------------------

pub struct AccountDatabase {
    path: PathBuf,
    pub accounts: Vec<Account>,
}

impl AccountDatabase {
    /// Root-owned, one directory per user.
    ///
    /// This used to live in the user's own configuration directory, which meant
    /// the tokens beside it were reachable by anything running as that user.
    /// Now the daemon is the only way in, and the permission service decides
    /// who gets through.
    const ROOT: &'static str = "/var/lib/vasak-accounts";
    const FILE_NAME: &'static str = "accounts.json";

    /// Where one user's data lives. Nothing outside this directory is ever
    /// touched on their behalf, so one person's request cannot reach another
    /// person's accounts.
    pub fn directory_for(uid: u32) -> PathBuf {
        Self::root().join(uid.to_string())
    }

    fn root() -> PathBuf {
        // Development override, debug builds only: the released daemon has no
        // way to be pointed at a directory somebody else can write.
        #[cfg(debug_assertions)]
        if let Some(root) = std::env::var_os("VASAK_ACCOUNTS_TEST_ROOT") {
            return PathBuf::from(root);
        }
        PathBuf::from(Self::ROOT)
    }

    pub fn for_user(uid: u32) -> Result<Self, StorageError> {
        Self::in_directory(Self::directory_for(uid))
    }

    /// Opens a database in a specific directory. The per-user path resolves to
    /// this; tests use it directly so they do not have to share a process-wide
    /// setting and can run alongside each other.
    pub fn in_directory(directory: PathBuf) -> Result<Self, StorageError> {
        std::fs::create_dir_all(&directory)?;
        // 0700: the listing alone says which accounts exist.
        let _ = std::fs::set_permissions(&directory, PermissionsExt::from_mode(0o700));

        Ok(AccountDatabase {
            path: directory.join(Self::FILE_NAME),
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
        write_private(&self.path, data.as_bytes())?;
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

    pub fn get_mut(&mut self, id: &str) -> Option<&mut Account> {
        self.accounts.iter_mut().find(|a| a.id == id)
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
// SecretStore — tokens del lado de root
// ---------------------------------------------------------------------------

/// Where the tokens live now.
///
/// They used to be in the user's own keyring, which meant the permission check
/// in front of this daemon protected nothing: any program running as that user
/// could ask the keyring for the token directly and skip the question
/// entirely. Root-owned files make the daemon the only way to reach them.
///
/// The files are not encrypted on top of that, deliberately. A key the daemon
/// can read unattended has to sit next to what it protects, which buys nothing
/// against anyone who can already read the file — the same reasoning that has
/// NetworkManager keep Wi-Fi passwords as root-owned plain text. Protection
/// against a stolen disk is full-disk encryption's job, not this file's.
pub struct SecretStore;

impl SecretStore {
    const FILE_NAME: &'static str = "secrets.json";

    /// account id → (secret name → value).
    fn load(directory: &std::path::Path) -> Result<HashMap<String, HashMap<String, String>>, StorageError> {
        let path = directory.join(Self::FILE_NAME);
        if !path.exists() {
            return Ok(HashMap::new());
        }
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }

    fn persist(
        directory: &std::path::Path,
        secrets: &HashMap<String, HashMap<String, String>>,
    ) -> Result<(), StorageError> {
        std::fs::create_dir_all(directory)?;
        let _ = std::fs::set_permissions(directory, PermissionsExt::from_mode(0o700));

        write_private(
            &directory.join(Self::FILE_NAME),
            serde_json::to_string(secrets)?.as_bytes(),
        )
    }

    pub fn store_secret(
        uid: u32,
        account_id: &str,
        key: &str,
        secret: &str,
    ) -> Result<(), StorageError> {
        Self::store_secret_in(&AccountDatabase::directory_for(uid), account_id, key, secret)
    }

    /// The per-user calls resolve to these; tests use them directly rather than
    /// sharing a process-wide setting.
    pub fn store_secret_in(
        directory: &std::path::Path,
        account_id: &str,
        key: &str,
        secret: &str,
    ) -> Result<(), StorageError> {
        let mut secrets = Self::load(directory)?;
        secrets
            .entry(account_id.to_string())
            .or_default()
            .insert(key.to_string(), secret.to_string());
        Self::persist(directory, &secrets)
    }

    pub fn get_secret(uid: u32, account_id: &str, key: &str) -> Result<String, StorageError> {
        Self::get_secret_in(&AccountDatabase::directory_for(uid), account_id, key)
    }

    pub fn get_secret_in(
        directory: &std::path::Path,
        account_id: &str,
        key: &str,
    ) -> Result<String, StorageError> {
        Self::load(directory)?
            .get(account_id)
            .and_then(|entry| entry.get(key))
            .cloned()
            .ok_or_else(|| {
                StorageError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no hay '{key}' guardado para la cuenta '{account_id}'"),
                ))
            })
    }

    /// The access token, which is the secret asked for most often.
    pub fn store_token(uid: u32, account_id: &str, token: &str) -> Result<(), StorageError> {
        Self::store_secret(uid, account_id, "access", token)
    }

    pub fn get_token(uid: u32, account_id: &str) -> Result<String, StorageError> {
        Self::get_secret(uid, account_id, "access")
    }

    /// Removes everything held for one account.
    ///
    /// Called when the account is deleted: leaving the tokens behind would keep
    /// a live credential on disk for something the user believes is gone.
    pub fn forget_account(uid: u32, account_id: &str) -> Result<(), StorageError> {
        Self::forget_account_in(&AccountDatabase::directory_for(uid), account_id)
    }

    pub fn forget_account_in(
        directory: &std::path::Path,
        account_id: &str,
    ) -> Result<(), StorageError> {
        let mut secrets = Self::load(directory)?;
        if secrets.remove(account_id).is_some() {
            Self::persist(directory, &secrets)?;
        }
        Ok(())
    }
}

/// Writes a file only its owner can read, replacing it in one step.
///
/// Created 0600 from the start rather than fixed up afterwards, so a token is
/// never briefly world-readable; and renamed into place so an interrupted write
/// cannot leave a half-written file where the credentials used to be.
fn write_private(path: &std::path::Path, data: &[u8]) -> Result<(), StorageError> {
    use std::io::Write;

    let temp = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)?;

    let written = file.write_all(data).and_then(|_| file.sync_all());
    drop(file);

    match written.and_then(|_| std::fs::rename(&temp, path)) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&temp);
            Err(StorageError::Io(error))
        }
    }
}

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
        Account::new("Alice Google", "google", caps)
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
    fn test_update_account() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
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

        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        assert!(db.is_empty());

        db.add(sample_account()).unwrap();
        assert_eq!(db.len(), 1);

        let mut db2 = AccountDatabase::in_directory(dir.clone()).unwrap();
        db2.load().unwrap();
        assert_eq!(db2.len(), 1);
        assert_eq!(db2.get(&db.accounts[0].id).unwrap().display_name, "Alice Google");

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    fn temp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_secret_survives_being_written_and_read_back() {
        let dir = temp_dir();

        SecretStore::store_secret_in(&dir, "acct-1", "access", "token-abc").unwrap();
        SecretStore::store_secret_in(&dir, "acct-1", "refresh", "refresh-xyz").unwrap();

        assert_eq!(
            SecretStore::get_secret_in(&dir, "acct-1", "access").unwrap(),
            "token-abc"
        );
        assert_eq!(
            SecretStore::get_secret_in(&dir, "acct-1", "refresh").unwrap(),
            "refresh-xyz"
        );

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    /// The file holds live credentials, so nobody but its owner may read it.
    /// This is the whole point of moving them out of the user's keyring.
    #[test]
    fn the_secret_file_is_readable_only_by_its_owner() {
        let dir = temp_dir();
        SecretStore::store_secret_in(&dir, "acct-1", "access", "token").unwrap();

        let mode = std::fs::metadata(dir.join("secrets.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert!(
            !dir.join("secrets.tmp").exists(),
            "no temporary file should be left holding a token"
        );

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    #[test]
    fn accounts_do_not_see_each_others_secrets() {
        let dir = temp_dir();
        SecretStore::store_secret_in(&dir, "acct-1", "access", "one").unwrap();
        SecretStore::store_secret_in(&dir, "acct-2", "access", "two").unwrap();

        assert_eq!(SecretStore::get_secret_in(&dir, "acct-1", "access").unwrap(), "one");
        assert_eq!(SecretStore::get_secret_in(&dir, "acct-2", "access").unwrap(), "two");

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    /// Deleting an account has to take its credentials with it, or a working
    /// token stays on disk for something the user believes is gone.
    #[test]
    fn deleting_an_account_removes_its_secrets() {
        let dir = temp_dir();
        SecretStore::store_secret_in(&dir, "acct-1", "access", "one").unwrap();
        SecretStore::store_secret_in(&dir, "acct-2", "access", "two").unwrap();

        SecretStore::forget_account_in(&dir, "acct-1").unwrap();

        assert!(SecretStore::get_secret_in(&dir, "acct-1", "access").is_err());
        assert_eq!(
            SecretStore::get_secret_in(&dir, "acct-2", "access").unwrap(),
            "two",
            "the other account must be untouched"
        );

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    #[test]
    fn a_secret_that_was_never_stored_is_an_error_not_an_empty_string() {
        let dir = temp_dir();
        assert!(SecretStore::get_secret_in(&dir, "missing", "access").is_err());
        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    /// One person's request must never reach another person's directory.
    #[test]
    fn each_user_gets_their_own_directory() {
        assert_ne!(
            AccountDatabase::directory_for(1000),
            AccountDatabase::directory_for(1001)
        );
        assert!(AccountDatabase::directory_for(1000)
            .to_string_lossy()
            .ends_with("/1000"));
    }
}
