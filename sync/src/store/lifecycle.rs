//! Cuándo se crea, se abre, se cierra y se borra cada base.
//!
//! La tabla entera, en el orden en que se mira:
//!
//! | llavero | clave | base | qué se hace |
//! |---|---|---|---|
//! | bloqueado | — | — | nada; el correo sigue en modo memoria |
//! | desbloqueado | no está | no está | crear primero la clave y después la base |
//! | desbloqueado | está | no está | crear la base con esa clave |
//! | desbloqueado | no está | está | clave perdida: borrar y rehacer, anotar en `sync_log` y avisar en el estado |
//! | desbloqueado | está | no abre | igual que la anterior |
//! | pasa a bloqueado | — | abierta | cerrar la base y soltar la clave |
//!
//! Y alrededor de la tabla:
//!
//! - **Encendido por omisión.** Lo que la persona decide por cuenta vive en
//!   `stores.json`; un archivo o una cuenta ausentes quieren decir encendido.
//! - **Apagar y vaciar** borran primero la clave del llavero y después los
//!   archivos. Borrar la clave primero es lo que hace inútil cualquier copia
//!   que haya quedado —una copia de seguridad, un `-wal` recuperado del disco—.
//!   Con el llavero bloqueado se borran los archivos, y la clave queda anotada
//!   para borrarse en el primer desbloqueo; hasta entonces esa cuenta no vuelve
//!   a tener base, para no rehacerla con la clave vieja.
//! - **Una cuenta vaciada o apagada no vuelve a usar nunca la clave que
//!   encuentre.** Queda en `pending_key_deletions` aunque el `Delete` haya
//!   contestado bien —un `Ok` no prueba que la clave se fue: el llavero pudo
//!   bloquearse a mitad, o mentir—, y sale de ahí recién cuando una clave
//!   **nueva** quedó guardada y releída. Mientras tanto, lo que `find` devuelva
//!   para esa cuenta se descarta.
//! - **Al desconectar una cuenta** se borra la base de toda cuenta que no esté
//!   en `ListAccounts`, **sólo si `ListAccounts` respondió bien**, y comparando
//!   contra todas las cuentas: una que pide reautenticarse sigue siendo de la
//!   persona y conserva su base.
//!
//! Lo que **nunca** lleva a borrar: un error del disco, un error del llavero, un
//! esquema más nuevo que este programa. Sólo una clave que no está —leída con el
//! llavero desbloqueado— o una que no abre.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::key::{KeyError, KeySource, StoreKey};
use super::paths::{self, StorePaths};
use super::{LogLevel, Store, StoreError};

/// Las capacidades de una cuenta que van a tener lugar en el almacén.
pub const STORE_AREAS: [&str; 3] = ["email", "calendar", "contacts"];

/// En qué está la base de una cuenta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreState {
    /// El llavero está bloqueado: no hay base abierta, y se espera.
    Locked,
    /// Abierta y lista.
    Open,
    /// Abierta, pero rehecha vacía en esta sesión porque la clave se había
    /// perdido o no abría. Lo que había se vuelve a traer del servidor.
    Rebuilt,
    /// La persona la apagó.
    Disabled,
    /// No se pudo: sin llavero, sin directorio, un error del disco. `detail`
    /// dice cuál.
    Unavailable,
}

/// En qué está el llavero, visto desde acá.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyringState {
    /// Todavía no se le preguntó.
    #[default]
    Unknown,
    Locked,
    Unlocked,
    Unavailable,
}

/// El estado de la base de una cuenta, como lo contesta `GetStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountStatus {
    pub account_id: String,
    pub state: StoreState,
    /// Vacío si no hay nada que explicar.
    pub detail: String,
    /// Cuánto ocupa en el disco, con el `-wal` y el `-shm`.
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Status {
    pub keyring: KeyringState,
    pub accounts: Vec<AccountStatus>,
}

/// Una cuenta tal como la listó el servicio de cuentas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedAccount {
    pub id: String,
    pub capabilities: Vec<String>,
}

impl ListedAccount {
    /// Si la cuenta tiene algo que guardar: correo, calendario o contactos.
    ///
    /// `needs_reauth` no entra: una cuenta que pide reautenticarse sigue
    /// siendo de la persona, y su base se conserva.
    fn wants_store(&self) -> bool {
        self.capabilities
            .iter()
            .any(|c| STORE_AREAS.contains(&c.as_str()))
    }
}

/// Cómo terminó el último `ListAccounts`.
///
/// Un tipo y no un `Option` para que «falló» se tenga que escribir: es el caso
/// en el que **no se borra nada**, y no puede confundirse con «no hay cuentas».
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountListing {
    Failed,
    Listed(Vec<ListedAccount>),
}

/// Lo que la persona decidió, por cuenta. Vive en `stores.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreSettings {
    #[serde(default)]
    pub accounts: BTreeMap<String, AccountSettings>,
    /// Cuentas cuya clave del llavero no se vuelve a usar: se vaciaron o se
    /// apagaron. Se intenta borrarla en cada vuelta con el llavero
    /// desbloqueado, y la cuenta sale de acá recién cuando tiene una clave
    /// nueva guardada. Una cuenta apagada, o que ya no está, se queda: son unos
    /// bytes, y sacarla sin una clave nueva es justo lo que esta lista evita.
    #[serde(default)]
    pub pending_key_deletions: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSettings {
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
}

fn enabled_by_default() -> bool {
    true
}

impl StoreSettings {
    /// Si la base de una cuenta está encendida. Una cuenta que no figura, lo
    /// está.
    pub fn is_enabled(&self, account_id: &str) -> bool {
        self.accounts
            .get(account_id)
            .is_none_or(|settings| settings.enabled)
    }

    /// Lee el archivo. Que no exista es lo normal: todo encendido.
    ///
    /// Que exista y no se entienda **es un error**, y no «todo encendido»: la
    /// persona pudo haber apagado una base, y leer basura como «nada apagado»
    /// la volvería a encender sin que nadie lo pidiera.
    pub fn load(path: &Path) -> Result<Self, StoreError> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
                StoreError::Settings(format!("{} no se entiende: {e}", path.display()))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(StoreError::Settings(format!(
                "no se pudo leer {}: {e}",
                path.display()
            ))),
        }
    }

    /// Escribe el archivo entero, a un temporal y renombrado: o queda el de
    /// antes o el de ahora, nunca uno a medias.
    pub fn save(&self, path: &Path) -> Result<(), StoreError> {
        use std::io::Write;

        let dir = path
            .parent()
            .ok_or_else(|| StoreError::Settings("la ruta no tiene carpeta".into()))?;
        paths::create_private_dir(dir)?;
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| StoreError::Settings(format!("no se pudo serializar: {e}")))?;

        let temporary = dir.join(".stores.json.tmp");
        let write = || -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&json)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)
        };
        write().map_err(|e| {
            StoreError::Settings(format!("no se pudo guardar {}: {e}", path.display()))
        })
    }
}

/// Dónde viven las bases y lo decidido por cuenta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locations {
    pub stores: PathBuf,
    pub settings: PathBuf,
}

impl Locations {
    pub fn from_environment() -> Result<Self, StoreError> {
        Ok(Self {
            stores: paths::stores_root()?,
            settings: paths::settings_file()?,
        })
    }
}

/// La base de una cuenta, y lo que se sabe de ella.
struct Entry {
    store: Option<Store>,
    state: StoreState,
    detail: String,
}

impl Entry {
    fn new() -> Self {
        Self {
            store: None,
            state: StoreState::Locked,
            detail: String::new(),
        }
    }

    /// Cierra la base, si estaba abierta.
    ///
    /// Soltar la conexión es cerrar la base, y SQLCipher borra su copia de la
    /// clave al cerrar. La otra copia —la de este lado— ya no existe: vivió en
    /// `Zeroizing` lo que duró abrir.
    fn close(&mut self) {
        self.store = None;
    }

    fn set(&mut self, state: StoreState, detail: impl Into<String>) {
        self.state = state;
        self.detail = detail.into();
    }
}

#[derive(Default)]
struct Inner {
    keyring: KeyringState,
    /// Todas las cuentas del último `ListAccounts` que respondió bien, o nada
    /// si todavía no respondió ninguno.
    listed: Option<BTreeSet<String>>,
    /// Las que tienen algo que guardar.
    wanted: BTreeSet<String>,
    entries: BTreeMap<String, Entry>,
}

impl Inner {
    fn entry(&mut self, account_id: &str) -> &mut Entry {
        self.entries
            .entry(account_id.to_string())
            .or_insert_with(Entry::new)
    }

    /// Lo que cambia el estado que se publica, para saber si avisar.
    fn snapshot(&self) -> (KeyringState, Vec<(String, StoreState, String)>) {
        (
            self.keyring,
            self.entries
                .iter()
                .map(|(id, e)| (id.clone(), e.state, e.detail.clone()))
                .collect(),
        )
    }
}

/// El dueño de todas las bases.
///
/// Una sola cerradura para todo: los cambios de una base —abrir, vaciar,
/// borrar— van de a uno, y así «vaciar» no se cruza nunca con «abrir» sobre la
/// misma cuenta. Son pocas cuentas y cada paso tarda milisegundos; lo que
/// escribe en serio llega con los datos, y va a tener su propio hilo por cuenta.
pub struct StoreManager<K: KeySource> {
    keys: K,
    locations: Result<Locations, String>,
    inner: Mutex<Inner>,
}

impl<K: KeySource> StoreManager<K> {
    pub fn new(keys: K, locations: Result<Locations, StoreError>) -> Self {
        Self {
            keys,
            locations: locations.map_err(|e| e.to_string()),
            inner: Mutex::new(Inner::default()),
        }
    }

    pub fn keys(&self) -> &K {
        &self.keys
    }

    fn locations(&self) -> Result<&Locations, StoreError> {
        self.locations
            .as_ref()
            .map_err(|detail| StoreError::Io(detail.clone()))
    }

    /// El estado de todas las bases.
    pub async fn status(&self) -> Status {
        let inner = self.inner.lock().await;
        let root = self.locations.as_ref().ok().map(|l| l.stores.clone());
        let accounts = inner
            .wanted
            .iter()
            .map(|id| {
                let (state, detail) = inner.entries.get(id).map_or(
                    (StoreState::Unavailable, "todavía no se revisó".to_string()),
                    |e| (e.state, e.detail.clone()),
                );
                let size_bytes = root
                    .as_deref()
                    .and_then(|root| StorePaths::new(root, id).ok())
                    .map_or(0, |p| p.size_bytes());
                AccountStatus {
                    account_id: id.clone(),
                    state,
                    detail,
                    size_bytes,
                }
            })
            .collect();
        Status {
            keyring: inner.keyring,
            accounts,
        }
    }

    /// Lo que hay que hacer cada vez que se leen las cuentas. Devuelve si
    /// cambió el estado que se publica.
    ///
    /// **Con `Failed` no se hace nada**, y en particular no se borra nada: un
    /// servicio de cuentas que no contesta no quiere decir que la persona no
    /// tenga cuentas.
    pub async fn accounts_listed(&self, listing: AccountListing) -> bool {
        let AccountListing::Listed(accounts) = listing else {
            return false;
        };

        let mut inner = self.inner.lock().await;
        let before = inner.snapshot();

        let listed: BTreeSet<String> = accounts.iter().map(|a| a.id.clone()).collect();
        let wanted: BTreeSet<String> = accounts
            .iter()
            .filter(|a| a.wants_store())
            .filter(|a| {
                let valid = paths::validate_account_id(&a.id).is_ok();
                if !valid {
                    tracing::warn!(
                        "la cuenta «{}» no puede tener almacén: identificador inválido",
                        a.id
                    );
                }
                valid
            })
            .map(|a| a.id.clone())
            .collect();

        // Las que ya no tienen nada que guardar se cierran.
        inner.entries.retain(|id, _| wanted.contains(id));
        inner.listed = Some(listed.clone());
        inner.wanted = wanted;

        self.run(&mut inner, None).await;
        let unlocked = inner.keyring == KeyringState::Unlocked;
        self.prune(unlocked, &listed).await;

        before != inner.snapshot()
    }

    /// Vuelve a pasar la tabla por todas las cuentas: al cambiar el llavero, y
    /// cada tanto por las dudas. Devuelve si cambió el estado que se publica.
    pub async fn refresh(&self) -> bool {
        let mut inner = self.inner.lock().await;
        let before = inner.snapshot();
        self.run(&mut inner, None).await;
        before != inner.snapshot()
    }

    /// `RequestSync`: se asegura de que la base de la cuenta esté lista.
    ///
    /// En este punto no hay nada que traer todavía; lo que hace es pasar la
    /// tabla por esa cuenta, que es lo que va a necesitar cualquier
    /// sincronización antes de empezar.
    pub async fn request_sync(&self, account_id: &str) -> Result<(), StoreError> {
        paths::validate_account_id(account_id)?;
        let mut inner = self.inner.lock().await;
        if !inner.wanted.contains(account_id) {
            return Err(StoreError::UnknownAccount(account_id.to_string()));
        }
        self.run(&mut inner, Some(account_id)).await;
        Ok(())
    }

    /// `SetStoreEnabled`: enciende o apaga la base de una cuenta.
    ///
    /// Apagar la borra —clave y archivos—: una base apagada que sigue en el
    /// disco no es una base apagada.
    pub async fn set_enabled(&self, account_id: &str, enabled: bool) -> Result<(), StoreError> {
        paths::validate_account_id(account_id)?;
        let locations = self.locations()?;
        let mut inner = self.inner.lock().await;

        let mut settings = StoreSettings::load(&locations.settings)?;
        settings
            .accounts
            .insert(account_id.to_string(), AccountSettings { enabled });
        settings.save(&locations.settings)?;

        if enabled {
            self.run(&mut inner, Some(account_id)).await;
            return Ok(());
        }

        inner.entry(account_id).close();
        let unlocked = matches!(self.keys.is_locked().await, Ok(false));
        let removed = self
            .remove_store(locations, &mut settings, account_id, unlocked)
            .await;
        inner.entry(account_id).set(StoreState::Disabled, "");
        removed
    }

    /// `ClearStore`: borra la base de una cuenta —clave y archivos— y, si está
    /// encendida, la vuelve a crear vacía con una clave nueva.
    pub async fn clear(&self, account_id: &str) -> Result<(), StoreError> {
        paths::validate_account_id(account_id)?;
        let locations = self.locations()?;
        let mut inner = self.inner.lock().await;

        let mut settings = StoreSettings::load(&locations.settings)?;
        inner.entry(account_id).close();
        let unlocked = matches!(self.keys.is_locked().await, Ok(false));
        self.remove_store(locations, &mut settings, account_id, unlocked)
            .await?;

        if inner.wanted.contains(account_id) {
            self.run(&mut inner, Some(account_id)).await;
        }
        Ok(())
    }

    /// Pasa la tabla por las cuentas: todas, o una.
    async fn run(&self, inner: &mut Inner, only: Option<&str>) {
        let targets: Vec<String> = inner
            .wanted
            .iter()
            .filter(|id| only.is_none_or(|o| o == id.as_str()))
            .cloned()
            .collect();

        let locations = match &self.locations {
            Ok(locations) => locations,
            Err(detail) => {
                for id in &targets {
                    let entry = inner.entry(id);
                    entry.close();
                    entry.set(StoreState::Unavailable, detail.clone());
                }
                return;
            }
        };

        let mut settings = match StoreSettings::load(&locations.settings) {
            Ok(settings) => settings,
            Err(e) => {
                // Ni encender ni borrar: no se sabe qué decidió la persona.
                tracing::warn!("{e}");
                for id in &targets {
                    let entry = inner.entry(id);
                    entry.close();
                    entry.set(StoreState::Unavailable, e.to_string());
                }
                return;
            }
        };

        let locked = match self.keys.is_locked().await {
            Ok(locked) => locked,
            Err(e) => {
                // Sin saber si el llavero está abierto, la clave no se usa: se
                // cierra todo y se espera.
                inner.keyring = KeyringState::Unavailable;
                for (id, entry) in inner.entries.iter_mut() {
                    entry.close();
                    if settings.is_enabled(id) {
                        entry.set(StoreState::Unavailable, e.to_string());
                    } else {
                        entry.set(StoreState::Disabled, "");
                    }
                }
                for id in &targets {
                    if !inner.entries.contains_key(id) {
                        let state = if settings.is_enabled(id) {
                            StoreState::Unavailable
                        } else {
                            StoreState::Disabled
                        };
                        inner.entry(id).set(state, e.to_string());
                    }
                }
                return;
            }
        };

        if locked {
            // Fila 1 y fila 6: nada nuevo, y lo abierto se cierra.
            inner.keyring = KeyringState::Locked;
            for id in inner.wanted.clone() {
                let enabled = settings.is_enabled(&id);
                let entry = inner.entry(&id);
                entry.close();
                if enabled {
                    entry.set(StoreState::Locked, "");
                } else {
                    entry.set(StoreState::Disabled, "");
                }
            }
            // Una base apagada que quedó en el disco se puede borrar igual:
            // borrar archivos no necesita la clave. La clave queda anotada.
            for id in &targets {
                if !settings.is_enabled(id) && self.has_files(locations, id) {
                    let _ = self.remove_store(locations, &mut settings, id, false).await;
                }
            }
            return;
        }

        inner.keyring = KeyringState::Unlocked;
        let cleared = self.flush_pending_deletions(&settings).await;
        if let Some(listed) = &inner.listed {
            self.sweep_orphan_keys(listed).await;
        }

        for id in targets {
            self.bring_account(inner, locations, &mut settings, &cleared, &id)
                .await;
        }
    }

    /// Una cuenta, con el llavero desbloqueado.
    async fn bring_account(
        &self,
        inner: &mut Inner,
        locations: &Locations,
        settings: &mut StoreSettings,
        cleared: &BTreeSet<String>,
        account_id: &str,
    ) {
        if !settings.is_enabled(account_id) {
            inner.entry(account_id).close();
            if self.has_files(locations, account_id) {
                if let Err(e) = self
                    .remove_store(locations, settings, account_id, true)
                    .await
                {
                    tracing::warn!("no se pudo borrar la base apagada de «{account_id}»: {e}");
                }
            }
            inner.entry(account_id).set(StoreState::Disabled, "");
            return;
        }

        let pending = settings.pending_key_deletions.contains(account_id);
        if pending && !cleared.contains(account_id) {
            // No se rehace con la clave vieja: primero tiene que irse.
            let entry = inner.entry(account_id);
            entry.close();
            entry.set(
                StoreState::Unavailable,
                "la clave anterior todavía no se pudo borrar del llavero",
            );
            return;
        }

        if inner.entry(account_id).store.is_some() {
            return;
        }

        let result = self.bring_up(&locations.stores, account_id, pending).await;
        if pending && result.is_ok() {
            // Recién ahora: hay una clave nueva guardada y releída, que
            // reemplazó a la vieja en el llavero.
            settings.pending_key_deletions.remove(account_id);
            if let Err(e) = settings.save(&locations.settings) {
                tracing::warn!("{e}");
            }
        }
        if matches!(result, Err(StoreError::Key(KeyError::Locked))) {
            inner.keyring = KeyringState::Locked;
        }
        let entry = inner.entry(account_id);
        match result {
            Ok((store, false)) => {
                entry.store = Some(store);
                entry.set(StoreState::Open, "");
            }
            Ok((store, true)) => {
                entry.store = Some(store);
                entry.set(
                    StoreState::Rebuilt,
                    "la clave de la base se perdió o no abría: se rehízo vacía",
                );
            }
            Err(StoreError::Key(KeyError::Locked)) => entry.set(StoreState::Locked, ""),
            Err(e) => {
                tracing::warn!("la base de «{account_id}» no está disponible: {e}");
                entry.set(StoreState::Unavailable, e.to_string());
            }
        }
    }

    /// Las filas 2 a 5 de la tabla. Devuelve la base abierta y si se rehízo.
    ///
    /// Con `discard_found_key`, lo que haya en el llavero para esta cuenta no se
    /// usa: es una cuenta vaciada o apagada, y una clave que aparece ahí es la
    /// vieja —un `Delete` que contestó bien y no borró—. Se sigue como si no
    /// hubiera clave, y la nueva la reemplaza.
    async fn bring_up(
        &self,
        root: &Path,
        account_id: &str,
        discard_found_key: bool,
    ) -> Result<(Store, bool), StoreError> {
        let paths = StorePaths::new(root, account_id)?;

        let key = if discard_found_key {
            None
        } else {
            match self.keys.find(account_id).await {
                Ok(key) => key,
                // Lo guardado no es una clave: es lo mismo que una que no abre.
                Err(KeyError::Malformed) => {
                    self.ensure_unlocked().await?;
                    self.keys.delete(account_id).await?;
                    None
                }
                // Cualquier otro error **no** es «no hay clave».
                Err(e) => return Err(e.into()),
            }
        };

        // Un error del disco al mirar si hay base no es «no hay base»: se corta
        // acá, antes de crear —que barre la carpeta— o de rehacer.
        let db_exists = paths.db_exists()?;
        match (key, db_exists) {
            (Some(key), true) => {
                let (key, opened) = blocking({
                    let paths = paths.clone();
                    move || {
                        let opened = Store::open(&paths, &key);
                        (key, opened)
                    }
                })
                .await?;
                match opened {
                    Ok(store) => Ok((store, false)),
                    Err(StoreError::WrongKey) => self
                        .rebuild(
                            &paths,
                            account_id,
                            Some(key),
                            "la clave del llavero no abre la base",
                            false,
                        )
                        .await
                        .map(|store| (store, true)),
                    Err(e) => Err(e),
                }
            }
            (Some(key), false) => Ok((create_fresh(paths, key).await?, false)),
            (None, false) => {
                let key = self.new_key(account_id).await?;
                Ok((create_fresh(paths, key).await?, false))
            }
            (None, true) => self
                .rebuild(
                    &paths,
                    account_id,
                    None,
                    if discard_found_key {
                        "la base se había vaciado o apagado y quedaban archivos"
                    } else {
                        "la clave de la base no estaba en el llavero"
                    },
                    // Una cuenta vaciada no vuelve a buscar: lo que encuentre
                    // es la clave vieja.
                    !discard_found_key,
                )
                .await
                .map(|store| (store, true)),
        }
    }

    /// Borra una base que no se puede abrir y la vuelve a crear vacía.
    ///
    /// **El orden es lo que salva a la fila 4.** `vasak-keyring` puede
    /// contestar `Locked == false` y un `SearchItems` vacío a la vez —una
    /// contraseña que no descifró, la escritura bloqueada, un
    /// `VASAK_KEYRING_PASSWORD` equivocado—, y ahí «no hay clave» es mentira.
    /// Así que, antes de destruir: se vuelve a leer `Locked`; con
    /// `recheck_missing_key`, se vuelve a buscar la clave y si ahora aparece no
    /// se rehace nada; y la clave nueva se guarda y se relee **antes** de tocar
    /// un archivo. Si el llavero no deja guardar, la base buena se queda.
    async fn rebuild(
        &self,
        paths: &StorePaths,
        account_id: &str,
        key: Option<StoreKey>,
        reason: &str,
        recheck_missing_key: bool,
    ) -> Result<Store, StoreError> {
        // Otra vez, justo antes de destruir: si el llavero se bloqueó entre la
        // búsqueda y acá, el vacío de la búsqueda no quería decir nada.
        self.ensure_unlocked().await?;
        if key.is_none() && recheck_missing_key && self.keys.find(account_id).await?.is_some() {
            return Err(StoreError::Key(KeyError::Failed(
                "la clave apareció al volver a buscarla: no se rehace la base, se vuelve a \
                 intentar en la próxima vuelta"
                    .into(),
            )));
        }
        tracing::warn!("'{account_id}': {reason}; se rehace la base vacía");

        let key = match key {
            Some(key) => key,
            None => self.new_key(account_id).await?,
        };
        let store = create_fresh(paths.clone(), key).await?;
        store.log(
            LogLevel::Warn,
            None,
            &format!("{reason}: se rehízo vacía; lo que había se vuelve a traer del servidor"),
        )?;
        Ok(store)
    }

    /// Una clave nueva, guardada y comprobada.
    ///
    /// Se relee después de guardar: una base creada con una clave que el
    /// llavero no retuvo es una base que no abre en el próximo arranque.
    async fn new_key(&self, account_id: &str) -> Result<StoreKey, StoreError> {
        self.ensure_unlocked().await?;
        let key = StoreKey::generate()?;
        self.keys.store(account_id, &key).await?;
        match self.keys.find(account_id).await? {
            Some(stored) if stored == key => Ok(key),
            _ => Err(StoreError::Key(KeyError::Failed(
                "la clave nueva no quedó guardada en el llavero".into(),
            ))),
        }
    }

    /// Falla si el llavero no está desbloqueado **ahora**.
    async fn ensure_unlocked(&self) -> Result<(), StoreError> {
        match self.keys.is_locked().await? {
            false => Ok(()),
            true => Err(StoreError::Key(KeyError::Locked)),
        }
    }

    fn has_files(&self, locations: &Locations, account_id: &str) -> bool {
        StorePaths::new(&locations.stores, account_id).is_ok_and(|p| p.dir.exists())
    }

    /// Borra la base de una cuenta: primero la clave, después los archivos.
    ///
    /// La cuenta queda anotada en `pending_key_deletions` **siempre**, también
    /// si el `Delete` contestó bien: un `Ok` no prueba que la clave se fue, y
    /// rehacer la base con la clave vieja sería deshacer el «vaciar». Sale de
    /// la lista cuando tiene una clave nueva (ver `bring_account`). Los
    /// archivos se borran igual.
    async fn remove_store(
        &self,
        locations: &Locations,
        settings: &mut StoreSettings,
        account_id: &str,
        unlocked: bool,
    ) -> Result<(), StoreError> {
        let paths = StorePaths::new(&locations.stores, account_id)?;

        if unlocked {
            if let Err(e) = self.keys.delete(account_id).await {
                tracing::warn!("'{account_id}': la clave se borra después: {e}");
            }
        }
        if settings
            .pending_key_deletions
            .insert(account_id.to_string())
        {
            if let Err(e) = settings.save(&locations.settings) {
                tracing::warn!("{e}");
            }
        }

        blocking(move || paths.remove()).await?
    }

    /// Intenta borrar las claves anotadas. Devuelve las cuentas cuyo `Delete`
    /// contestó bien en esta vuelta, que son las únicas que pueden volver a
    /// tener base ahora; siguen en la lista hasta tener una clave nueva.
    async fn flush_pending_deletions(&self, settings: &StoreSettings) -> BTreeSet<String> {
        let mut cleared = BTreeSet::new();
        for account_id in &settings.pending_key_deletions {
            match self.keys.delete(account_id).await {
                Ok(()) => {
                    cleared.insert(account_id.clone());
                }
                Err(e) => tracing::warn!("'{account_id}': la clave vieja sigue en el llavero: {e}"),
            }
        }
        cleared
    }

    /// Borra las claves de cuentas que ya no están: las de una cuenta quitada
    /// con el llavero bloqueado, o mientras este servicio no corría.
    async fn sweep_orphan_keys(&self, listed: &BTreeSet<String>) {
        let Ok(with_keys) = self.keys.key_accounts().await else {
            return;
        };
        for account_id in with_keys.iter().filter(|id| !listed.contains(*id)) {
            match self.keys.delete(account_id).await {
                Ok(()) => tracing::info!("se borró la clave huérfana de «{account_id}»"),
                Err(e) => tracing::warn!("'{account_id}': la clave huérfana sigue: {e}"),
            }
        }
    }

    /// Borra la base de toda cuenta que ya no está en `ListAccounts`.
    ///
    /// Todo relativo a un descriptor de `stores/` abierto sin seguir enlaces:
    /// si `stores/` o `vasak-accounts-sync/` son un enlace, no se borra nada. Y
    /// sólo carpetas que parecen una base; lo demás que haya ahí no es de este
    /// servicio. Ver [`paths::StoresRoot`].
    async fn prune(&self, unlocked: bool, listed: &BTreeSet<String>) {
        let Ok(locations) = &self.locations else {
            return;
        };

        let stores = locations.stores.clone();
        let opened = blocking(move || {
            let root = paths::StoresRoot::open(&stores)?;
            let ids = match &root {
                Some(root) => root.store_ids()?,
                None => Vec::new(),
            };
            Ok::<_, StoreError>((root.map(Arc::new), ids))
        })
        .await
        .and_then(|result| result);

        match opened {
            Ok((Some(root), ids)) => {
                for account_id in ids.into_iter().filter(|id| !listed.contains(id)) {
                    // La clave primero, si se puede. Si no, la barre
                    // `sweep_orphan_keys` en el próximo desbloqueo.
                    if unlocked {
                        if let Err(e) = self.keys.delete(&account_id).await {
                            tracing::warn!("'{account_id}': la clave se borra después: {e}");
                        }
                    }
                    let root = Arc::clone(&root);
                    let id = account_id.clone();
                    match blocking(move || root.remove(&id)).await {
                        Ok(Ok(())) => {
                            tracing::info!(
                                "se borró la base de «{account_id}», que ya no es una cuenta"
                            )
                        }
                        Ok(Err(e)) | Err(e) => {
                            tracing::warn!("no se pudo borrar la base de «{account_id}»: {e}")
                        }
                    }
                }
            }
            Ok((None, _)) => {}
            Err(e) => tracing::warn!("no se pudieron leer las bases: {e}"),
        }

        // Y lo decidido para cuentas que ya no existen.
        if let Ok(mut settings) = StoreSettings::load(&locations.settings) {
            let before = settings.accounts.len();
            settings.accounts.retain(|id, _| listed.contains(id));
            if settings.accounts.len() != before {
                if let Err(e) = settings.save(&locations.settings) {
                    tracing::warn!("{e}");
                }
            }
        }
    }

    #[cfg(test)]
    async fn is_open(&self, account_id: &str) -> bool {
        self.inner
            .lock()
            .await
            .entries
            .get(account_id)
            .is_some_and(|e| e.store.is_some())
    }
}

/// Crea una base nueva, borrando antes cualquier resto que haya en su carpeta.
///
/// Un `-wal` suelto de una base anterior se aplicaría sobre la nueva al
/// abrirla, cifrado con otra clave. Sólo se llama cuando no hay base o cuando
/// se decidió rehacerla.
async fn create_fresh(paths: StorePaths, key: StoreKey) -> Result<Store, StoreError> {
    blocking(move || {
        paths.remove()?;
        Store::create(&paths, &key)
    })
    .await?
}

/// Corre algo que toca el disco fuera del hilo del bucle de eventos.
async fn blocking<T, F>(work: F) -> Result<T, StoreError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| StoreError::Io(format!("la tarea del disco se cayó: {e}")))
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::super::key::fake::FakeKeys;
    use super::super::paths::tests::TempDir;
    use super::*;

    struct Fixture {
        temp: TempDir,
        keys: FakeKeys,
        manager: StoreManager<FakeKeys>,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let temp = TempDir::new(label);
            let keys = FakeKeys::default();
            let manager = StoreManager::new(keys.clone(), Ok(Self::locations_in(&temp)));
            Self {
                temp,
                keys,
                manager,
            }
        }

        fn locations_in(temp: &TempDir) -> Locations {
            Locations {
                stores: temp.0.join("data/stores"),
                settings: temp.0.join("config/stores.json"),
            }
        }

        fn locations(&self) -> Locations {
            Self::locations_in(&self.temp)
        }

        fn paths(&self, account_id: &str) -> StorePaths {
            StorePaths::new(&self.locations().stores, account_id).unwrap()
        }

        fn key(&self, account_id: &str) -> Option<StoreKey> {
            self.keys
                .state()
                .keys
                .get(account_id)
                .map(|hex| StoreKey::from_secret(Zeroizing::new(hex.as_bytes().to_vec())).unwrap())
        }

        async fn state(&self, account_id: &str) -> StoreState {
            self.manager
                .status()
                .await
                .accounts
                .into_iter()
                .find(|a| a.account_id == account_id)
                .map(|a| a.state)
                .expect("la cuenta no figura en el estado")
        }

        fn settings(&self) -> StoreSettings {
            StoreSettings::load(&self.locations().settings).unwrap()
        }
    }

    fn account(id: &str, capabilities: &[&str]) -> ListedAccount {
        ListedAccount {
            id: id.into(),
            capabilities: capabilities.iter().map(|c| c.to_string()).collect(),
        }
    }

    fn listing(ids: &[&str]) -> AccountListing {
        AccountListing::Listed(ids.iter().map(|id| account(id, &["email"])).collect())
    }

    fn fixed_key(c: u8) -> StoreKey {
        StoreKey::from_secret(Zeroizing::new(vec![c; 64])).unwrap()
    }

    fn log_lines(fixture: &Fixture, account_id: &str) -> Vec<(String, String)> {
        let key = fixture.key(account_id).unwrap();
        let store = Store::open(&fixture.paths(account_id), &key).unwrap();
        let mut statement = store
            .connection()
            .prepare("SELECT level, message FROM sync_log ORDER BY id")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    // ── La tabla, fila por fila ─────────────────────────────────────────────

    /// Fila 1, y la regla que más importa: **llavero bloqueado, ni clave ni
    /// base**. Antes del desbloqueo el llavero contesta vacío, y tomar eso por
    /// «no hay clave» es lo que deja ilegible una base buena.
    #[tokio::test]
    async fn fila_1_con_el_llavero_bloqueado_no_hay_ni_clave_ni_base() {
        let f = Fixture::new("fila1");
        f.keys.state().locked = true;

        f.manager.accounts_listed(listing(&["cuenta"])).await;

        {
            let state = f.keys.state();
            assert!(
                state.stored.is_empty(),
                "no se tenía que guardar ninguna clave"
            );
            assert_eq!(state.stored_while_locked, 0);
        }
        assert!(
            !f.paths("cuenta").dir.exists(),
            "no tenía que aparecer ningún archivo"
        );
        assert!(!f.locations().stores.exists());
        assert_eq!(f.state("cuenta").await, StoreState::Locked);
        assert_eq!(f.manager.status().await.keyring, KeyringState::Locked);
    }

    /// Fila 1 también cuando ya hay una base: bloqueado no la toca.
    #[tokio::test]
    async fn fila_1_una_base_que_ya_estaba_no_se_toca_con_el_llavero_bloqueado() {
        let f = Fixture::new("fila1b");
        drop(Store::create(&f.paths("cuenta"), &fixed_key(b'a')).unwrap());
        let before = std::fs::read(&f.paths("cuenta").db).unwrap();
        f.keys.state().locked = true;

        f.manager.accounts_listed(listing(&["cuenta"])).await;

        assert_eq!(std::fs::read(&f.paths("cuenta").db).unwrap(), before);
        assert!(f.keys.state().stored.is_empty());
    }

    /// Fila 2: sin clave ni base, primero la clave y después la base.
    #[tokio::test]
    async fn fila_2_sin_clave_ni_base_se_crea_la_clave_y_despues_la_base() {
        let f = Fixture::new("fila2");
        f.manager.accounts_listed(listing(&["cuenta"])).await;

        assert_eq!(f.keys.state().stored, vec!["cuenta".to_string()]);
        assert!(f.paths("cuenta").db_exists().unwrap());
        assert_eq!(f.state("cuenta").await, StoreState::Open);
        assert!(f.manager.is_open("cuenta").await);
        // Y la base abre con la clave que quedó en el llavero.
        assert!(Store::open(&f.paths("cuenta"), &f.key("cuenta").unwrap()).is_ok());
    }

    /// Fila 2, el orden: si la clave no quedó en el llavero, **no hay base**.
    /// Una base con una clave que el llavero no retuvo no abre en el próximo
    /// arranque.
    #[tokio::test]
    async fn fila_2_si_la_clave_no_queda_guardada_no_se_crea_la_base() {
        let f = Fixture::new("fila2b");
        f.keys.state().lose_stores = true;

        f.manager.accounts_listed(listing(&["cuenta"])).await;

        assert!(!f.paths("cuenta").db_exists().unwrap());
        assert_eq!(f.state("cuenta").await, StoreState::Unavailable);
    }

    /// Fila 3: con clave y sin base, la base se crea con esa clave.
    #[tokio::test]
    async fn fila_3_con_clave_y_sin_base_se_usa_esa_clave() {
        let f = Fixture::new("fila3");
        f.keys
            .state()
            .keys
            .insert("cuenta".into(), fixed_key(b'3').hex().into());

        f.manager.accounts_listed(listing(&["cuenta"])).await;

        assert!(
            f.keys.state().stored.is_empty(),
            "no hacía falta otra clave"
        );
        assert_eq!(f.state("cuenta").await, StoreState::Open);
        assert!(Store::open(&f.paths("cuenta"), &fixed_key(b'3')).is_ok());
    }

    /// Fila 3 con restos: un `-wal` suelto de otra base no se aplica sobre la
    /// nueva.
    #[tokio::test]
    async fn fila_3_los_restos_de_una_base_anterior_se_barren() {
        let f = Fixture::new("fila3b");
        let paths = f.paths("cuenta");
        paths.prepare_dir().unwrap();
        std::fs::write(&paths.wal, vec![0x42; 4096]).unwrap();
        f.keys
            .state()
            .keys
            .insert("cuenta".into(), fixed_key(b'3').hex().into());

        f.manager.accounts_listed(listing(&["cuenta"])).await;

        assert_eq!(f.state("cuenta").await, StoreState::Open);
    }

    /// Fila 4: sin clave y con base. Se rehace, se anota y se avisa.
    #[tokio::test]
    async fn fila_4_sin_clave_y_con_base_se_rehace_y_queda_anotado() {
        let f = Fixture::new("fila4");
        drop(Store::create(&f.paths("cuenta"), &fixed_key(b'a')).unwrap());

        f.manager.accounts_listed(listing(&["cuenta"])).await;

        assert_eq!(f.state("cuenta").await, StoreState::Rebuilt);
        let status = f.manager.status().await;
        assert!(
            !status.accounts[0].detail.is_empty(),
            "el estado tiene que decir por qué"
        );
        // Con otra clave, que es la que quedó en el llavero.
        let new_key = f.key("cuenta").unwrap();
        assert_ne!(new_key, fixed_key(b'a'));
        assert!(Store::open(&f.paths("cuenta"), &fixed_key(b'a')).is_err());
        let lines = log_lines(&f, "cuenta");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].0, "warn");
        assert!(lines[0].1.contains("no estaba en el llavero"));
    }

    /// Fila 4 con un llavero que dice «desbloqueado», no ve la clave y no deja
    /// guardar otra —`vasak-keyring` con la base sin descifrar—: la base buena
    /// sobrevive, porque la clave nueva se pide **antes** de borrar. Fija ese
    /// orden.
    #[tokio::test]
    async fn fila_4_sin_poder_guardar_la_clave_nueva_no_se_borra_la_base() {
        let f = Fixture::new("fila4-sin-guardar");
        drop(Store::create(&f.paths("cuenta"), &fixed_key(b'a')).unwrap());
        f.keys.state().reject_stores = true;

        f.manager.accounts_listed(listing(&["cuenta"])).await;

        assert_eq!(f.state("cuenta").await, StoreState::Unavailable);
        assert!(
            Store::open(&f.paths("cuenta"), &fixed_key(b'a')).is_ok(),
            "la base buena se tenía que quedar"
        );
    }

    /// Fila 4 con un vacío que no valía: la primera búsqueda no ve la clave y
    /// la segunda sí. No se rehace nada, y en la próxima vuelta la base abre
    /// con la clave de siempre.
    #[tokio::test]
    async fn fila_4_si_la_clave_aparece_al_volver_a_buscarla_no_se_rehace() {
        let f = Fixture::new("fila4-reaparece");
        drop(Store::create(&f.paths("cuenta"), &fixed_key(b'a')).unwrap());
        {
            let mut state = f.keys.state();
            state
                .keys
                .insert("cuenta".into(), fixed_key(b'a').hex().into());
            state.blind_finds = 1;
        }

        f.manager.accounts_listed(listing(&["cuenta"])).await;

        assert_ne!(f.state("cuenta").await, StoreState::Rebuilt);
        assert!(
            f.keys.state().stored.is_empty(),
            "no hacía falta otra clave"
        );
        assert!(Store::open(&f.paths("cuenta"), &fixed_key(b'a')).is_ok());

        f.manager.refresh().await;
        assert_eq!(f.state("cuenta").await, StoreState::Open);
        assert!(log_lines(&f, "cuenta").is_empty());
    }

    /// Fila 5: la clave está y no abre. Lo mismo que la anterior, con la clave
    /// que ya había.
    #[tokio::test]
    async fn fila_5_una_clave_que_no_abre_rehace_la_base() {
        let f = Fixture::new("fila5");
        drop(Store::create(&f.paths("cuenta"), &fixed_key(b'a')).unwrap());
        f.keys
            .state()
            .keys
            .insert("cuenta".into(), fixed_key(b'b').hex().into());

        f.manager.accounts_listed(listing(&["cuenta"])).await;

        assert_eq!(f.state("cuenta").await, StoreState::Rebuilt);
        assert!(Store::open(&f.paths("cuenta"), &fixed_key(b'b')).is_ok());
        let lines = log_lines(&f, "cuenta");
        assert!(lines[0].1.contains("no abre"));
    }

    /// Fila 5 también cuando lo guardado ni siquiera es una clave.
    #[tokio::test]
    async fn fila_5_un_secreto_que_no_es_clave_se_reemplaza() {
        let f = Fixture::new("fila5b");
        drop(Store::create(&f.paths("cuenta"), &fixed_key(b'a')).unwrap());
        f.keys.state().malformed.insert("cuenta".into());

        f.manager.accounts_listed(listing(&["cuenta"])).await;

        assert_eq!(f.state("cuenta").await, StoreState::Rebuilt);
        assert_eq!(f.keys.state().deleted, vec!["cuenta".to_string()]);
        assert!(f.key("cuenta").is_some());
    }

    /// Fila 6: al bloquearse, la base abierta se cierra. Y al desbloquear vuelve.
    #[tokio::test]
    async fn fila_6_al_bloquearse_se_cierra_la_base_y_al_desbloquear_se_abre() {
        let f = Fixture::new("fila6");
        f.manager.accounts_listed(listing(&["cuenta"])).await;
        assert!(f.manager.is_open("cuenta").await);

        f.keys.state().locked = true;
        assert!(f.manager.refresh().await, "tenía que avisar el cambio");
        assert!(!f.manager.is_open("cuenta").await);
        assert_eq!(f.state("cuenta").await, StoreState::Locked);

        f.keys.state().locked = false;
        f.manager.refresh().await;
        assert!(f.manager.is_open("cuenta").await);
        assert_eq!(f.state("cuenta").await, StoreState::Open);
        // La misma clave: no se generó otra.
        assert_eq!(f.keys.state().stored.len(), 1);
    }

    /// Si el llavero se bloquea entre la búsqueda y la creación, el vacío de la
    /// búsqueda no vale: ni clave ni base, y la que había queda como estaba.
    #[tokio::test]
    async fn un_bloqueo_a_mitad_de_camino_no_genera_ni_borra() {
        let f = Fixture::new("carrera");
        drop(Store::create(&f.paths("cuenta"), &fixed_key(b'a')).unwrap());
        let before = std::fs::read(&f.paths("cuenta").db).unwrap();
        f.keys.state().lock_after_find = true;

        f.manager.accounts_listed(listing(&["cuenta"])).await;

        assert_eq!(f.keys.state().stored_while_locked, 0);
        assert!(f.keys.state().stored.is_empty());
        assert_eq!(std::fs::read(&f.paths("cuenta").db).unwrap(), before);
        assert_eq!(f.state("cuenta").await, StoreState::Locked);
    }

    /// Un error del llavero no es «no hay clave»: la base se queda.
    #[tokio::test]
    async fn un_error_del_llavero_no_borra_la_base() {
        let f = Fixture::new("error");
        drop(Store::create(&f.paths("cuenta"), &fixed_key(b'a')).unwrap());
        f.keys.state().fail_find = true;

        f.manager.accounts_listed(listing(&["cuenta"])).await;

        assert!(Store::open(&f.paths("cuenta"), &fixed_key(b'a')).is_ok());
        assert_eq!(f.state("cuenta").await, StoreState::Unavailable);
        assert!(f.keys.state().stored.is_empty());
    }

    /// Un error del disco al mirar si hay base no es «no hay base»: ni se
    /// genera una clave ni se barre nada. Acá el error es un `ENOTDIR`, porque
    /// donde va la carpeta de la cuenta hay un archivo.
    #[tokio::test]
    async fn un_error_del_disco_al_mirar_la_base_no_genera_ni_borra() {
        let f = Fixture::new("error-disco");
        let stores = f.locations().stores;
        std::fs::create_dir_all(&stores).unwrap();
        std::fs::write(stores.join("cuenta"), "de la persona").unwrap();

        f.manager.accounts_listed(listing(&["cuenta"])).await;

        assert_eq!(f.state("cuenta").await, StoreState::Unavailable);
        assert!(
            f.keys.state().stored.is_empty(),
            "no se tenía que generar ninguna clave"
        );
        assert_eq!(
            std::fs::read_to_string(stores.join("cuenta")).unwrap(),
            "de la persona"
        );
    }

    #[tokio::test]
    async fn sin_llavero_se_informa_no_disponible_y_no_se_toca_nada() {
        let f = Fixture::new("sin-llavero");
        f.manager.accounts_listed(listing(&["cuenta"])).await;
        assert!(f.manager.is_open("cuenta").await);

        f.keys.state().unavailable = true;
        f.manager.refresh().await;

        assert!(!f.manager.is_open("cuenta").await);
        assert_eq!(f.state("cuenta").await, StoreState::Unavailable);
        assert_eq!(f.manager.status().await.keyring, KeyringState::Unavailable);
        assert!(f.paths("cuenta").db_exists().unwrap());
    }

    #[tokio::test]
    async fn sin_directorio_de_datos_todo_queda_no_disponible() {
        let keys = FakeKeys::default();
        let manager = StoreManager::new(keys.clone(), Err(StoreError::NoBaseDir));
        manager.accounts_listed(listing(&["cuenta"])).await;
        let status = manager.status().await;
        assert_eq!(status.accounts[0].state, StoreState::Unavailable);
        assert!(keys.state().stored.is_empty());
        assert!(manager.set_enabled("cuenta", false).await.is_err());
    }

    // ── Las cuentas que se van ──────────────────────────────────────────────

    /// Un `ListAccounts` que falló no dice que la persona no tenga cuentas.
    #[tokio::test]
    async fn si_list_accounts_falla_no_se_borra_nada() {
        let f = Fixture::new("falla");
        f.manager.accounts_listed(listing(&["a", "b"])).await;
        assert!(f.paths("a").db_exists().unwrap() && f.paths("b").db_exists().unwrap());

        assert!(!f.manager.accounts_listed(AccountListing::Failed).await);

        assert!(f.paths("a").db_exists().unwrap());
        assert!(f.paths("b").db_exists().unwrap());
        assert!(f.keys.state().deleted.is_empty());
    }

    /// Bien respondido, se van sólo las bases de las cuentas que no están. Una
    /// que pide reautenticarse, o que ya no tiene nada que guardar, sigue siendo
    /// una cuenta y conserva la suya. La clave se borra antes que los archivos.
    #[tokio::test]
    async fn si_list_accounts_responde_se_borran_solo_las_cuentas_que_no_estan() {
        let f = Fixture::new("prune");
        f.manager.accounts_listed(listing(&["a", "b", "c"])).await;
        // Algo que no puso este servicio: no se toca.
        std::fs::create_dir_all(f.locations().stores.join("no.es.cuenta")).unwrap();

        f.manager
            .accounts_listed(AccountListing::Listed(vec![
                account("a", &["email"]),
                // Pide reautenticarse: para el servicio de cuentas sigue ahí.
                account("b", &["email"]),
                // Ya no tiene correo, calendario ni contactos, pero existe.
                account("c", &["files"]),
                account("d", &["contacts"]),
            ]))
            .await;
        assert!(f.paths("a").db_exists().unwrap());
        assert!(f.paths("b").db_exists().unwrap());
        assert!(f.paths("c").db_exists().unwrap());
        assert!(f.paths("d").db_exists().unwrap());

        f.manager.accounts_listed(listing(&["a", "d"])).await;

        assert!(f.paths("a").db_exists().unwrap());
        assert!(f.paths("d").db_exists().unwrap());
        assert!(!f.paths("b").dir.exists());
        assert!(!f.paths("c").dir.exists());
        assert!(f.locations().stores.join("no.es.cuenta").exists());
        let state = f.keys.state();
        assert!(state.deleted.contains(&"b".to_string()));
        assert!(state.deleted.contains(&"c".to_string()));
        assert!(!state.keys.contains_key("b"));
    }

    /// Si `stores/` es un enlace a la carpeta de la persona, la poda no lo
    /// sigue: ni lee lo que hay del otro lado ni borra nada.
    #[tokio::test]
    async fn la_poda_no_sigue_un_stores_enlazado_ni_borra_carpetas_ajenas() {
        let temp = TempDir::new("poda-enlace");
        let docs = temp.0.join("Documentos");
        for dir in ["Fotos", "Trabajo", "2024", "vacia"] {
            std::fs::create_dir_all(docs.join(dir)).unwrap();
        }
        for dir in ["Fotos", "Trabajo", "2024"] {
            std::fs::write(docs.join(dir).join("importante.txt"), "x").unwrap();
        }
        std::fs::create_dir_all(temp.0.join("data")).unwrap();
        std::os::unix::fs::symlink(&docs, temp.0.join("data/stores")).unwrap();
        let manager = StoreManager::new(
            FakeKeys::default(),
            Ok(Locations {
                stores: temp.0.join("data/stores"),
                settings: temp.0.join("config/stores.json"),
            }),
        );

        manager.accounts_listed(listing(&[])).await;

        for dir in ["Fotos", "Trabajo", "2024"] {
            assert!(
                docs.join(dir).join("importante.txt").exists(),
                "{dir} se tenía que quedar"
            );
        }
        // Ni siquiera una carpeta vacía: del otro lado del enlace nada es suyo.
        assert!(docs.join("vacia").exists());
    }

    /// Lo mismo si el enlace es `vasak-accounts-sync/`, un nivel más arriba.
    #[tokio::test]
    async fn la_poda_no_sigue_la_carpeta_del_servicio_enlazada() {
        let temp = TempDir::new("poda-enlace-servicio");
        let docs = temp.0.join("Documentos");
        std::fs::create_dir_all(docs.join("stores/Fotos")).unwrap();
        std::fs::create_dir_all(docs.join("stores/vacia")).unwrap();
        std::fs::write(docs.join("stores/Fotos/store.db"), "x").unwrap();
        std::fs::create_dir_all(temp.0.join("data")).unwrap();
        std::os::unix::fs::symlink(&docs, temp.0.join("data/vasak-accounts-sync")).unwrap();
        let manager = StoreManager::new(
            FakeKeys::default(),
            Ok(Locations {
                stores: temp.0.join("data/vasak-accounts-sync/stores"),
                settings: temp.0.join("config/stores.json"),
            }),
        );

        manager.accounts_listed(listing(&[])).await;

        assert!(docs.join("stores/Fotos/store.db").exists());
        assert!(docs.join("stores/vacia").exists());
    }

    /// En un `stores/` de verdad, una carpeta con nombre de cuenta que no es una
    /// base —sin `store.db`, o con una subcarpeta— no se toca. Una vacía, o con
    /// sólo restos de una base, sí se va.
    #[tokio::test]
    async fn la_poda_solo_borra_carpetas_que_son_una_base() {
        let f = Fixture::new("poda-ajenas");
        let stores = f.locations().stores;
        std::fs::create_dir_all(stores.join("Fotos")).unwrap();
        std::fs::write(stores.join("Fotos/importante.txt"), "x").unwrap();
        std::fs::create_dir_all(stores.join("Trabajo/sub")).unwrap();
        std::fs::write(stores.join("Trabajo/store.db"), "x").unwrap();
        std::fs::create_dir_all(stores.join("vacia")).unwrap();
        std::fs::create_dir_all(stores.join("restos")).unwrap();
        std::fs::write(stores.join("restos/store.db-wal"), "x").unwrap();

        f.manager.accounts_listed(listing(&[])).await;

        assert!(stores.join("Fotos/importante.txt").exists());
        assert!(stores.join("Trabajo/sub").exists());
        assert!(stores.join("Trabajo/store.db").exists());
        assert!(!stores.join("vacia").exists());
        assert!(!stores.join("restos").exists());
    }

    /// Una cuenta quitada con el llavero bloqueado deja su clave: se barre en
    /// el primer desbloqueo.
    #[tokio::test]
    async fn la_clave_de_una_cuenta_quitada_se_barre_al_desbloquear() {
        let f = Fixture::new("huerfana");
        f.manager.accounts_listed(listing(&["a", "b"])).await;

        f.keys.state().locked = true;
        f.manager.accounts_listed(listing(&["a"])).await;
        assert!(!f.paths("b").dir.exists(), "los archivos se van igual");
        assert!(f.keys.state().keys.contains_key("b"), "la clave espera");

        f.keys.state().locked = false;
        f.manager.refresh().await;
        assert!(!f.keys.state().keys.contains_key("b"));
        assert!(f.keys.state().keys.contains_key("a"));
    }

    // ── Apagar, vaciar ──────────────────────────────────────────────────────

    #[test]
    fn sin_stores_json_todo_esta_encendido() {
        let temp = TempDir::new("sin-archivo");
        let settings = StoreSettings::load(&temp.0.join("stores.json")).unwrap();
        assert!(settings.is_enabled("cualquiera"));

        // Y una cuenta que no figura en un archivo que sí existe, también.
        let path = temp.0.join("otro.json");
        std::fs::write(&path, r#"{"accounts":{"a":{"enabled":false}}}"#).unwrap();
        let settings = StoreSettings::load(&path).unwrap();
        assert!(!settings.is_enabled("a"));
        assert!(settings.is_enabled("b"));
    }

    #[tokio::test]
    async fn apagar_persiste_y_borra_la_clave_y_los_archivos() {
        let f = Fixture::new("apagar");
        f.manager.accounts_listed(listing(&["cuenta"])).await;

        f.manager.set_enabled("cuenta", false).await.unwrap();

        assert!(!f.settings().is_enabled("cuenta"));
        assert!(f.key("cuenta").is_none(), "la clave se tenía que ir");
        assert!(!f.paths("cuenta").dir.exists(), "y los archivos también");
        assert_eq!(f.state("cuenta").await, StoreState::Disabled);
        let mode = std::fs::metadata(f.locations().settings).unwrap();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode.permissions()) & 0o777,
            0o600
        );

        // Y no vuelve sola.
        f.manager.refresh().await;
        f.manager.accounts_listed(listing(&["cuenta"])).await;
        assert!(!f.paths("cuenta").dir.exists());
        assert_eq!(f.state("cuenta").await, StoreState::Disabled);

        // Encender la vuelve a crear, con otra clave.
        f.manager.set_enabled("cuenta", true).await.unwrap();
        assert_eq!(f.state("cuenta").await, StoreState::Open);
        assert!(f.settings().is_enabled("cuenta"));
    }

    #[tokio::test]
    async fn vaciar_borra_y_vuelve_a_crear_con_otra_clave() {
        let f = Fixture::new("vaciar");
        f.manager.accounts_listed(listing(&["cuenta"])).await;
        let old_key = f.key("cuenta").unwrap();
        f.manager.request_sync("cuenta").await.unwrap();

        f.manager.clear("cuenta").await.unwrap();

        // Se borra al vaciar, y otra vez antes de crear la nueva: la cuenta
        // sigue anotada hasta tener clave nueva.
        let deleted = f.keys.state().deleted.clone();
        assert!(!deleted.is_empty() && deleted.iter().all(|id| id == "cuenta"));
        assert!(f.settings().pending_key_deletions.is_empty());
        let new_key = f.key("cuenta").unwrap();
        assert_ne!(new_key, old_key);
        assert_eq!(f.state("cuenta").await, StoreState::Open);
        assert!(Store::open(&f.paths("cuenta"), &old_key).is_err());
        assert!(log_lines(&f, "cuenta").is_empty());
    }

    /// Vaciar con el llavero bloqueado: los archivos se van ya, la clave en el
    /// primer desbloqueo, y **recién después** hay base nueva, con otra clave.
    #[tokio::test]
    async fn vaciar_con_el_llavero_bloqueado_borra_la_clave_al_desbloquear() {
        let f = Fixture::new("vaciar-bloqueado");
        f.manager.accounts_listed(listing(&["cuenta"])).await;
        let old_key = f.key("cuenta").unwrap();

        f.keys.state().locked = true;
        f.manager.clear("cuenta").await.unwrap();
        assert!(!f.paths("cuenta").dir.exists());
        assert!(
            f.key("cuenta").is_some(),
            "con el llavero bloqueado la clave espera"
        );
        assert!(f.settings().pending_key_deletions.contains("cuenta"));

        f.keys.state().locked = false;
        f.manager.refresh().await;

        assert_eq!(f.keys.state().deleted, vec!["cuenta".to_string()]);
        assert!(f.settings().pending_key_deletions.is_empty());
        assert_ne!(f.key("cuenta").unwrap(), old_key);
        assert_eq!(f.state("cuenta").await, StoreState::Open);
    }

    /// El llavero se bloquea entre el `is_locked` y el `Delete` de «vaciar», y
    /// el `Delete` contesta bien sin borrar —lo que hacía el cliente antes,
    /// con un `SearchItems` vacío—. La cuenta queda anotada igual, y al
    /// desbloquear la base nueva lleva **otra** clave: la vieja no se reusa.
    #[tokio::test]
    async fn vaciar_con_bloqueo_a_mitad_no_reusa_la_clave_vieja() {
        let f = Fixture::new("vaciar-carrera");
        f.manager.accounts_listed(listing(&["cuenta"])).await;
        let old_key = f.key("cuenta").unwrap();
        {
            let mut state = f.keys.state();
            state.lose_deletes = true;
            state.lock_after_is_locked = true;
        }

        f.manager.clear("cuenta").await.unwrap();
        assert!(
            f.settings().pending_key_deletions.contains("cuenta"),
            "la cuenta tenía que quedar anotada"
        );

        f.keys.state().locked = false;
        f.manager.refresh().await;
        assert_eq!(f.state("cuenta").await, StoreState::Open);
        assert_ne!(
            f.key("cuenta").unwrap(),
            old_key,
            "la clave vieja no se vuelve a usar"
        );
        assert!(Store::open(&f.paths("cuenta"), &old_key).is_err());
        assert!(f.settings().pending_key_deletions.is_empty());
    }

    /// Lo mismo sin bloqueo: un `Delete` que contesta bien y no borra no hace
    /// que apagar y volver a encender reuse la clave vieja.
    #[tokio::test]
    async fn apagar_y_encender_con_un_delete_que_no_borra_no_reusa_la_clave_vieja() {
        let f = Fixture::new("delete-mentiroso");
        f.manager.accounts_listed(listing(&["cuenta"])).await;
        let old_key = f.key("cuenta").unwrap();
        f.keys.state().lose_deletes = true;

        f.manager.set_enabled("cuenta", false).await.unwrap();
        assert!(f.settings().pending_key_deletions.contains("cuenta"));
        // Apagada sigue anotada: no tiene clave nueva.
        f.manager.refresh().await;
        assert!(f.settings().pending_key_deletions.contains("cuenta"));

        f.manager.set_enabled("cuenta", true).await.unwrap();
        assert_eq!(f.state("cuenta").await, StoreState::Open);
        assert_ne!(f.key("cuenta").unwrap(), old_key);
        assert!(f.settings().pending_key_deletions.is_empty());
    }

    /// Si la clave vieja no se puede borrar, la cuenta no vuelve a tener base:
    /// rehacerla con esa clave sería deshacer el «vaciar».
    #[tokio::test]
    async fn sin_poder_borrar_la_clave_vieja_no_se_rehace_la_base() {
        let f = Fixture::new("clave-que-no-se-va");
        f.manager.accounts_listed(listing(&["cuenta"])).await;
        f.keys.state().fail_delete = true;

        f.manager.clear("cuenta").await.unwrap();

        assert!(!f.paths("cuenta").dir.exists());
        assert_eq!(f.state("cuenta").await, StoreState::Unavailable);
        assert!(f.settings().pending_key_deletions.contains("cuenta"));

        f.keys.state().fail_delete = false;
        f.manager.refresh().await;
        assert_eq!(f.state("cuenta").await, StoreState::Open);
        assert!(f.settings().pending_key_deletions.is_empty());
    }

    /// Un `stores.json` que no se entiende no enciende ni borra nada.
    #[tokio::test]
    async fn un_stores_json_ilegible_no_enciende_ni_borra() {
        let f = Fixture::new("ilegible");
        f.manager.accounts_listed(listing(&["cuenta"])).await;
        let settings = f.locations().settings;
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(&settings, "{ esto no es json").unwrap();

        f.manager.refresh().await;
        assert_eq!(f.state("cuenta").await, StoreState::Unavailable);
        assert!(f.paths("cuenta").db_exists().unwrap());
        assert!(matches!(
            f.manager.set_enabled("cuenta", false).await,
            Err(StoreError::Settings(_))
        ));
        assert!(f.paths("cuenta").db_exists().unwrap());
        assert!(f.key("cuenta").is_some());
    }

    #[tokio::test]
    async fn los_comandos_rechazan_un_identificador_invalido() {
        let f = Fixture::new("invalido");
        for bad in ["", "a/b", "../x", ".."] {
            assert!(matches!(
                f.manager.set_enabled(bad, false).await,
                Err(StoreError::InvalidAccountId(_))
            ));
            assert!(matches!(
                f.manager.clear(bad).await,
                Err(StoreError::InvalidAccountId(_))
            ));
            assert!(matches!(
                f.manager.request_sync(bad).await,
                Err(StoreError::InvalidAccountId(_))
            ));
        }
        assert!(matches!(
            f.manager.request_sync("desconocida").await,
            Err(StoreError::UnknownAccount(_))
        ));
        assert!(!f.locations().settings.exists());
    }

    /// Lo que contesta `GetStatus`, en JSON.
    #[tokio::test]
    async fn el_estado_trae_el_llavero_y_cada_cuenta_con_su_tamano() {
        let f = Fixture::new("estado");
        f.manager.accounts_listed(listing(&["b", "a"])).await;

        let status = f.manager.status().await;
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["keyring"], "unlocked");
        assert_eq!(json["accounts"][0]["account_id"], "a");
        assert_eq!(json["accounts"][0]["state"], "open");
        assert!(json["accounts"][0]["size_bytes"].as_u64().unwrap() > 0);
        assert_eq!(json["accounts"][1]["account_id"], "b");
    }
}
