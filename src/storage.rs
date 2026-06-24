use std::path::PathBuf;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Tipos de datos
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountMetadata {
    pub id: String,
    pub provider: String,
    pub username: String,
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Error propio del módulo
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
    fn from(e: std::io::Error) -> Self {
        StorageError::Io(e)
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self {
        StorageError::Json(e)
    }
}

impl From<keyring::Error> for StorageError {
    fn from(e: keyring::Error) -> Self {
        StorageError::Keyring(e)
    }
}

// ---------------------------------------------------------------------------
// Almacenamiento
// ---------------------------------------------------------------------------

const SERVICE_NAME: &str = "vasakos-account-manager";

pub struct Storage {
    accounts_path: PathBuf,
}

impl Storage {
    /// Crea una instancia, asegurando que el directorio de configuración
    /// `~/.config/vasakos/` exista.
    pub fn new() -> Result<Self, StorageError> {
        let config_dir = dirs::config_dir().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "config directory not found")
        })?;

        let accounts_dir = config_dir.join("vasakos");
        let accounts_path = accounts_dir.join("accounts.json");

        std::fs::create_dir_all(&accounts_dir)?;

        Ok(Storage { accounts_path })
    }

    /// Retorna la lista completa de cuentas desde el archivo JSON.
    /// Si el archivo no existe, retorna una lista vacía.
    pub fn load_accounts(&self) -> Result<Vec<AccountMetadata>, StorageError> {
        if !self.accounts_path.exists() {
            return Ok(Vec::new());
        }
        let data = std::fs::read_to_string(&self.accounts_path)?;
        let accounts: Vec<AccountMetadata> = serde_json::from_str(&data)?;
        Ok(accounts)
    }

    /// Sobrescribe el archivo JSON con la lista de cuentas provista.
    pub fn save_accounts(&self, accounts: &[AccountMetadata]) -> Result<(), StorageError> {
        let data = serde_json::to_string_pretty(accounts)?;
        std::fs::write(&self.accounts_path, data)?;
        Ok(())
    }

    /// Agrega una cuenta a la lista existente y persiste los cambios.
    pub fn add_account(&self, account: &AccountMetadata) -> Result<(), StorageError> {
        let mut accounts = self.load_accounts()?;
        accounts.push(account.clone());
        self.save_accounts(&accounts)
    }

    // -----------------------------------------------------------------------
    // Llavero del sistema (Secret Service de Linux)
    // -----------------------------------------------------------------------

    /// Guarda un token secreto en el llavero del sistema.
    /// El secreto se asocia al servicio `vasakos-account-manager` y se
    /// indexa con `account_id` como credencial/usuario del llavero.
    pub fn store_secret(&self, account_id: &str, token: &str) -> Result<(), StorageError> {
        let entry = keyring::Entry::new(SERVICE_NAME, account_id)?;
        entry.set_password(token)?;
        Ok(())
    }

    /// Recupera un token secreto previamente guardado.
    pub fn get_secret(&self, account_id: &str) -> Result<String, StorageError> {
        let entry = keyring::Entry::new(SERVICE_NAME, account_id)?;
        let password = entry.get_password()?;
        Ok(password)
    }

    /// Elimina un secreto del llavero.
    pub fn delete_secret(&self, account_id: &str) -> Result<(), StorageError> {
        let entry = keyring::Entry::new(SERVICE_NAME, account_id)?;
        entry.delete_credential()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_metadata_roundtrip() {
        let account = AccountMetadata {
            id: uuid::Uuid::new_v4().to_string(),
            provider: "nextcloud".into(),
            username: "user@example.com".into(),
            enabled: true,
        };

        let json = serde_json::to_string_pretty(&account).unwrap();
        let deserialized: AccountMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(account.id, deserialized.id);
        assert_eq!(account.provider, deserialized.provider);
        assert_eq!(account.username, deserialized.username);
        assert_eq!(account.enabled, deserialized.enabled);
    }

    #[test]
    fn test_json_file_roundtrip() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("accounts.json");

        let storage = Storage { accounts_path: path.clone() };

        let accounts = vec![
            AccountMetadata {
                id: "a1".into(),
                provider: "google".into(),
                username: "alice@gmail.com".into(),
                enabled: true,
            },
            AccountMetadata {
                id: "a2".into(),
                provider: "nextcloud".into(),
                username: "bob@example.com".into(),
                enabled: false,
            },
        ];

        storage.save_accounts(&accounts).unwrap();
        let loaded = storage.load_accounts().unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].username, "alice@gmail.com");
        assert_eq!(loaded[1].enabled, false);

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }
}
