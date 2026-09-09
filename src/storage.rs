use std::collections::HashMap;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// CapabilityType — enum polimórfico snake_case
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityType {
    Email,
    Calendar,
    Contacts,
    Chat,
    Drive,
    Tasks,
}

impl CapabilityType {
    /// Todas, en el orden en que se muestran.
    ///
    /// Existe para que la lista de capacidades esté escrita **una vez**: estaba
    /// en el `match` de `permissions.rs` y en el `rename_all` de serde, y una
    /// séptima capacidad habría tenido que agregarse en los dos lugares sin que
    /// nada avisara si se olvidaba uno.
    pub const ALL: [CapabilityType; 6] = [
        CapabilityType::Email,
        CapabilityType::Calendar,
        CapabilityType::Contacts,
        CapabilityType::Chat,
        CapabilityType::Drive,
        CapabilityType::Tasks,
    ];

    /// El nombre con el que viaja por D-Bus, se guarda en `accounts.json` y lo
    /// espera el servicio de permisos. Un test comprueba que coincida con lo
    /// que serializa serde, que es la otra mitad de la misma verdad.
    pub fn as_id(&self) -> &'static str {
        match self {
            CapabilityType::Email => "email",
            CapabilityType::Calendar => "calendar",
            CapabilityType::Contacts => "contacts",
            CapabilityType::Chat => "chat",
            CapabilityType::Drive => "drive",
            CapabilityType::Tasks => "tasks",
        }
    }
}

/// Lo que devuelve un nombre de capacidad que no existe.
///
/// Nombra las válidas: el mensaje termina en el error de D-Bus que ve quien
/// llamó, y «capability inválida» a secas no le dice qué escribir.
#[derive(Debug, PartialEq, Eq)]
pub struct UnknownCapability(pub String);

impl std::fmt::Display for UnknownCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let validas: Vec<&str> = CapabilityType::ALL.iter().map(|c| c.as_id()).collect();
        write!(
            f,
            "capacidad '{}' desconocida; las válidas son: {}",
            self.0,
            validas.join(", "),
        )
    }
}

impl std::error::Error for UnknownCapability {}

/// Convierte el nombre que llegó por D-Bus en una capacidad.
///
/// Antes esto se hacía metiendo el texto recibido dentro de comillas y pasándolo
/// por `serde_json`. Funcionaba de casualidad: un nombre con una comilla o una
/// barra invertida producía JSON inválido, y la persona recibía un error de
/// sintaxis JSON por haber escrito mal «calendar».
impl std::str::FromStr for CapabilityType {
    type Err = UnknownCapability;

    fn from_str(nombre: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|capacidad| capacidad.as_id() == nombre)
            .ok_or_else(|| UnknownCapability(nombre.to_string()))
    }
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

    /// El proveedor dejó de aceptar el refresh_token y hay que volver a
    /// autorizar.
    ///
    /// Pasa cuando la persona revoca el acceso desde la web del proveedor, o
    /// cambia la contraseña, o el token caduca por no usarse. Sin esta marca la
    /// cuenta queda zombi: sigue en la lista, y cada intento de usarla falla
    /// con un error de red que no dice qué hacer.
    ///
    /// `default` porque los archivos escritos antes de que esto existiera no la
    /// tienen, y una cuenta sin la marca es una cuenta que anda.
    #[serde(default)]
    pub needs_reauth: bool,
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
            needs_reauth: false,
        }
    }

    /// Lo que se le cuenta a cualquiera que pregunte qué cuentas hay.
    pub fn summary(&self) -> AccountSummary {
        let mut capabilities: Vec<&'static str> = CapabilityType::ALL
            .into_iter()
            .filter(|c| self.capabilities.contains_key(c))
            .map(|c| c.as_id())
            .collect();
        capabilities.sort();

        AccountSummary {
            id: self.id.clone(),
            display_name: self.display_name.clone(),
            provider_type: self.provider_type.clone(),
            capabilities,
            needs_reauth: self.needs_reauth,
        }
    }
}

/// La versión de una cuenta que `ListAccounts` entrega.
///
/// Es un resumen y no la cuenta entera por una razón concreta. Listar no pide
/// permiso —tiene que poder abrirse la pantalla de cuentas sin que aparezca un
/// diálogo por cada una—, así que lo que sale por ahí lo ve cualquier programa
/// del usuario. La configuración completa de una capacidad incluye a qué
/// servidor se habla, con qué `client_id` y con qué alcances, y eso sólo sale
/// por `GetAccountData`, que sí pregunta.
///
/// Lo que queda acá es lo que una aplicación necesita para dibujar una lista y
/// saber a qué cuenta pedirle permiso después.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AccountSummary {
    pub id: String,
    pub display_name: String,
    pub provider_type: String,
    pub capabilities: Vec<&'static str>,
    pub needs_reauth: bool,
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


    /// Sólo para los tests: la aplicación nunca pregunta cuántas cuentas hay.
    ///
    /// Con `#[cfg(test)]` en lugar de un `allow(dead_code)`: así no viaja en el
    /// binario y el aviso de código muerto sigue sirviendo para lo que de verdad
    /// no se usa.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
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

    /// Marca —o desmarca— que una cuenta necesita volver a autorizarse.
    ///
    /// Devuelve si la marca **cambió**: quien llama usa eso para avisar por la
    /// señal sólo cuando hay algo nuevo, y no en cada refresco fallido de una
    /// cuenta que ya estaba marcada.
    pub fn set_needs_reauth(&mut self, id: &str, needs: bool) -> Result<bool, StorageError> {
        let Some(cuenta) = self.accounts.iter_mut().find(|a| a.id == id) else {
            return Ok(false);
        };
        if cuenta.needs_reauth == needs {
            return Ok(false);
        }
        cuenta.needs_reauth = needs;
        self.save()?;
        Ok(true)
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






    /// Las dos mitades de la misma verdad: `as_id()` es lo que se le manda al
    /// servicio de permisos y `Serialize` es lo que se escribe en
    /// `accounts.json`. Si se separan, un permiso concedido deja de encontrar
    /// la cuenta a la que corresponde y nadie se enteraría.
    #[test]
    fn el_nombre_de_la_capacidad_es_el_mismo_para_serde_y_para_los_permisos() {
        for capacidad in CapabilityType::ALL {
            let por_serde = serde_json::to_string(&capacidad).unwrap();
            assert_eq!(
                por_serde,
                format!("\"{}\"", capacidad.as_id()),
                "{capacidad:?} se serializa distinto de su as_id()",
            );
        }
    }

    #[test]
    fn se_reconocen_las_seis_capacidades_por_su_nombre() {
        for capacidad in CapabilityType::ALL {
            assert_eq!(capacidad.as_id().parse::<CapabilityType>(), Ok(capacidad));
        }
    }

    /// Antes el nombre recibido por D-Bus se metía entre comillas y se pasaba
    /// por `serde_json`, así que una comilla o una barra invertida producían
    /// JSON inválido y la persona recibía un error de sintaxis JSON. Ahora
    /// cualquier nombre que no esté en la lista da el mismo error claro.
    #[test]
    fn un_nombre_con_comillas_o_barras_es_un_nombre_desconocido_y_nada_mas() {
        for entrada in ["email\"", "\"email\"", "email\\", "e\"mail", "\\", "\""] {
            assert_eq!(
                entrada.parse::<CapabilityType>(),
                Err(UnknownCapability(entrada.to_string())),
                "{entrada:?} debía rechazarse como desconocido",
            );
        }
    }

    #[test]
    fn los_nombres_que_no_existen_se_rechazan() {
        // "Email" incluido: los identificadores son en minúscula y aceptar la
        // variante en mayúscula grabaría permisos contra un nombre que después
        // nadie vuelve a encontrar.
        for entrada in ["", "Email", "EMAIL", "emial", "correo", "account.email"] {
            assert!(
                entrada.parse::<CapabilityType>().is_err(),
                "{entrada:?} no debía aceptarse",
            );
        }
    }

    /// El mensaje va a parar al error de D-Bus que ve quien llamó, así que
    /// tiene que decirle qué escribir.
    #[test]
    fn el_error_nombra_las_capacidades_validas() {
        let mensaje = "emial".parse::<CapabilityType>().unwrap_err().to_string();
        assert!(mensaje.contains("emial"), "falta lo que se escribió: {mensaje}");
        for capacidad in CapabilityType::ALL {
            assert!(
                mensaje.contains(capacidad.as_id()),
                "el mensaje no nombra '{}': {mensaje}",
                capacidad.as_id(),
            );
        }
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

    /// Borrar algo que ya no está no es un error, pero tampoco puede decir que
    /// borró: el llamante usa ese `bool` para avisarle a la persona.
    #[test]
    fn borrar_una_cuenta_que_no_existe_devuelve_false() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        let id = db.add(sample_account()).unwrap();

        assert!(!db.remove("no-existe").unwrap());
        assert!(db.get(&id).is_some(), "la otra cuenta tenía que quedar");
        assert!(db.remove(&id).unwrap());
        assert!(db.get(&id).is_none());

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    /// Actualizar una cuenta que no está tiene que fallar y no agregarla en
    /// silencio: sería una cuenta nueva que nadie pidió.
    #[test]
    fn actualizar_una_cuenta_que_no_existe_falla() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();

        let huerfana = sample_account();
        assert!(db.update_account(huerfana).is_err());
        assert!(db.is_empty(), "no tenía que quedar ninguna cuenta");

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    /// Un `accounts.json` ilegible tiene que dar error y **no** dejar la lista
    /// vacía: con una lista vacía el daemon diría que la persona no tiene
    /// cuentas, y el primer `save()` encima pisaría el archivo dañado con `[]`.
    #[test]
    fn un_accounts_json_corrupto_da_error_en_vez_de_lista_vacia() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        db.add(sample_account()).unwrap();

        std::fs::write(dir.join("accounts.json"), "{ esto no es json").unwrap();

        let mut otra = AccountDatabase::in_directory(dir.clone()).unwrap();
        assert!(matches!(otra.load(), Err(StorageError::Json(_))));

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    /// Un directorio sin `accounts.json` es una cuenta nueva, no un fallo: es
    /// lo que se encuentra en el primer arranque.
    #[test]
    fn un_directorio_vacio_carga_sin_cuentas_y_sin_error() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        assert!(db.is_empty());
        assert!(db.get("cualquiera").is_none());

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    /// El directorio guarda los tokens de una persona: que otra pueda listarlo
    /// ya dice qué cuentas tiene.
    #[test]
    fn el_directorio_de_la_base_es_solo_para_su_dueno() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        AccountDatabase::in_directory(dir.clone()).unwrap();

        let modo = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(modo, 0o700);

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    /// Lo que sale por `ListAccounts`, que no pide permiso: tiene que alcanzar
    /// para dibujar una lista y **no** incluir la configuración de la cuenta.
    #[test]
    fn el_resumen_no_lleva_la_configuracion_de_la_cuenta() {
        let cuenta = sample_account();
        let resumen = cuenta.summary();

        assert_eq!(resumen.display_name, "Alice Google");
        assert_eq!(resumen.provider_type, "google");
        assert_eq!(resumen.capabilities, vec!["drive", "email"]);
        assert!(!resumen.needs_reauth);

        // El servidor de correo, el client_id y los alcances quedan detrás de
        // GetAccountData, que sí pregunta. Que no se filtren por acá es el
        // motivo de que el resumen exista.
        let json = serde_json::to_string(&resumen).unwrap();
        for secreto in ["imap.gmail.com", "alice@gmail.com", "max_storage_gb"] {
            assert!(
                !json.contains(secreto),
                "el resumen filtró '{secreto}': {json}"
            );
        }
    }

    /// Las capacidades del resumen van ordenadas y sin depender del recorrido de
    /// un HashMap, o la lista de la pantalla se reordenaría sola entre lecturas.
    #[test]
    fn las_capacidades_del_resumen_van_ordenadas() {
        let mut caps = HashMap::new();
        for capacidad in CapabilityType::ALL {
            caps.insert(capacidad, json!({}));
        }
        let resumen = Account::new("Todas", "prueba", caps).summary();

        let mut esperado = resumen.capabilities.clone();
        esperado.sort();
        assert_eq!(resumen.capabilities, esperado);
        assert_eq!(resumen.capabilities.len(), 6);
    }

    #[test]
    fn marcar_reauth_solo_avisa_cuando_cambia() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        let id = db.add(sample_account()).unwrap();

        assert!(db.set_needs_reauth(&id, true).unwrap(), "el primer cambio avisa");
        // Y el segundo no: si no, cada refresco fallido de una cuenta ya marcada
        // emitiría una señal y despertaría a todas las aplicaciones.
        assert!(!db.set_needs_reauth(&id, true).unwrap());
        assert!(db.get(&id).unwrap().needs_reauth);

        assert!(db.set_needs_reauth(&id, false).unwrap(), "volver a andar avisa");
        assert!(!db.get(&id).unwrap().needs_reauth);

        // Y una cuenta que no existe no es un error: puede haberse borrado
        // mientras se hablaba con el proveedor.
        assert!(!db.set_needs_reauth("no-existe", true).unwrap());

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    /// La marca tiene que sobrevivir al disco, o la pantalla diría que todo
    /// está bien después de reiniciar el servicio.
    #[test]
    fn la_marca_de_reauth_se_persiste() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut db = AccountDatabase::in_directory(dir.clone()).unwrap();
        db.load().unwrap();
        let id = db.add(sample_account()).unwrap();
        db.set_needs_reauth(&id, true).unwrap();

        let mut otra = AccountDatabase::in_directory(dir.clone()).unwrap();
        otra.load().unwrap();
        assert!(otra.get(&id).unwrap().needs_reauth);

        std::fs::remove_dir_all(dir).unwrap_or_default();
    }

    /// Los archivos escritos antes de que la marca existiera no la tienen, y una
    /// cuenta sin marca es una cuenta que anda. Sin el `default` de serde, el
    /// servicio no podría leer ningún accounts.json anterior.
    #[test]
    fn una_cuenta_sin_la_marca_se_lee_como_que_anda() {
        let viejo = r#"[{
            "id": "abc",
            "display_name": "Vieja",
            "provider_type": "custom",
            "capabilities": {}
        }]"#;

        let cuentas: Vec<Account> = serde_json::from_str(viejo).unwrap();
        assert!(!cuentas[0].needs_reauth);
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
