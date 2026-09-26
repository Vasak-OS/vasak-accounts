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
//! **La última fila no es inmediata.** `vasak-keyring` avisa al desbloquear y
//! no al bloquear, así que el bloqueo lo nota la revisión por reloj del bucle
//! principal: hasta 300 segundos después, y mientras tanto la base sigue
//! abierta, con la clave de sus páginas en la memoria de SQLCipher.
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
//! - **Al desconectar una cuenta** se borra su base —archivos y clave— y lo
//!   decidido para ella en `stores.json`, pero **sólo cuando la ausencia está
//!   confirmada**: la cuenta falta en dos `ListAccounts` que respondieron bien,
//!   y el segundo llegó por lo menos [`PRUNE_CONFIRMATION`] —una vuelta del
//!   bucle principal— después del primero en que faltó. Un listado que falló
//!   no cuenta ni a favor ni en contra, y una cuenta que reaparece en cualquier
//!   listado bueno deja de estar bajo sospecha. Se compara contra todas las
//!   cuentas: una que pide reautenticarse sigue siendo de la persona y conserva
//!   su base. Ver [`Listings`].
//!
//! - **La colección del llavero se fija una vez por vuelta** y se anota cuál
//!   guarda la clave de cada base (`key_collections` en `stores.json`). Si en
//!   una vuelta la colección no es la anotada —el alias `default` apunta a otra,
//!   que `SetAlias` lo puede cambiar cualquier proceso de la sesión, o el
//!   llavero es otro—, que la clave «no esté» no quiere decir que se perdió: la
//!   base **no se rehace**, queda no disponible con el motivo, y abre como
//!   estaba en cuanto vuelve la colección. Vaciarla es la salida si el cambio
//!   fue a propósito.
//!   Y como un llavero que se reinicia puede servir otra colección en la ruta
//!   fijada, antes de rehacer una base se vuelve a identificar la colección
//!   —ruta, `Created` y dueño en el bus—: si ya no es la de la vuelta, no se
//!   borra nada.
//!
//! Lo que **nunca** lleva a borrar: un error del disco, un error del llavero, un
//! esquema más nuevo que este programa, una colección que cambió. Sólo una clave
//! que no está —leída con el llavero desbloqueado, en la colección donde se
//! guardó— o una que no abre.
//!
//! ── Las áreas, y quién escribe ──────────────────────────────────────────────
//!
//! Un área de una cuenta —los contactos o el calendario ([`SYNCED_AREAS`])—
//! **se enciende la primera vez que alguien la pide con permiso** (una lectura
//! o un `RequestSync`) y queda anotada en `stores.json` (`active_areas`), así
//! que después de reiniciar sigue sola. Su estado se ve en `GetStatus`, al lado
//! del de la base. Todo lo de un área —encenderla, a qué cuentas les toca, su
//! estado— es lo mismo para las dos, con el área como argumento.
//!
//! **Un solo escritor por base**: todo lo que toca una base abierta pasa por
//! [`StoreManager::with_store`], con la cerradura del administrador tomada y el
//! llavero releído en ese momento. Con el llavero bloqueado no se escribe nada
//! —se pasa la tabla, que cierra la base— y la sincronización se corta ahí.
//!
//! **Y dos lectores**, que no pasan por esa cerradura: [`StoreManager::read`]
//! toma una de las conexiones de sólo lectura de la base ([`ReadPool`]) y lee
//! en WAL lo último que se confirmó, sin esperar a que termine un lote. El
//! diseño pedía un actor por cuenta —un hilo dueño de la conexión, con órdenes
//! por canal—; no hace falta: el único escritor ya lo garantiza la cerradura
//! (un lote por vez, de a lo sumo 500 filas), y los lectores no pueden
//! escribir —`SQLITE_OPEN_READONLY` y `query_only`—, así que no hay un segundo
//! escritor posible aunque lean en paralelo. Un actor sumaría un hilo por
//! cuenta para ordenar algo que ya está en orden.
//!
//! **Cada lote que cambia algo se anuncia**: lo que la base anotó que cambió
//! ([`Store::take_changes`]) sale por [`StoreManager::subscribe_changes`] al
//! terminar el lote, una vez por área, y de ahí a la señal `Changed`.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use super::key::{KeyError, KeySource, StoreKey};
use super::paths::{self, StorePaths};
use super::readers::ReadPool;
use super::{LogLevel, Store, StoreError};

/// Las capacidades de una cuenta que van a tener lugar en el almacén.
pub const STORE_AREAS: [&str; 3] = ["email", "calendar", "contacts"];

/// El nombre del área de contactos, en la capacidad de la cuenta y en
/// `active_areas` de `stores.json`.
pub const CONTACTS_AREA: &str = "contacts";

/// El nombre del área de calendario, en la capacidad de la cuenta y en
/// `active_areas` de `stores.json`. Lleva los eventos y las tareas de CalDAV
/// (supuesto 8 de `vasak-accounts#23`).
pub const CALENDAR_AREA: &str = "calendar";

/// Las áreas que se sincronizan por DAV y se encienden la primera vez que
/// alguien las pide con permiso. El correo llega después.
pub const SYNCED_AREAS: [&str; 2] = [CONTACTS_AREA, CALENDAR_AREA];

/// Cuánto tiene que haber entre el primer listado bueno en que falta una
/// cuenta y el que confirma que se fue, antes de borrar nada suyo.
///
/// Una vuelta del bucle principal, que es el que lee las cuentas. **Dos
/// listados y una vuelta, las dos cosas**, y no una sola:
///
/// - Un listado solo no alcanza. El servicio de cuentas contesta bien y vacío
///   cuando le falta `accounts.json` (`AccountDatabase::load` en el demonio),
///   y una sola respuesta así borraba todas las bases.
/// - Dos listados solos tampoco: una ráfaga de `AccountsChanged` dispara dos
///   en el mismo segundo, y los dos salen del mismo estado roto del servicio.
/// - Y una gracia sola —«falta desde hace cinco minutos»— borraría con la
///   vuelta del llavero o del reloj, sin que el servicio de cuentas haya vuelto
///   a decir nada: la segunda respuesta es la evidencia, el tiempo es lo que la
///   hace independiente de la primera.
///
/// La sospecha vive en memoria y no se guarda: después de reiniciar el sync
/// hace falta confirmar de nuevo, que es lo conservador.
pub const PRUNE_CONFIRMATION: Duration = crate::POLL_INTERVAL;

/// Lo que dijeron los `ListAccounts` que respondieron bien desde que arrancó
/// el proceso: el último listado, y desde cuándo falta cada cuenta que dejó de
/// figurar.
///
/// Es la única fuente de «esta cuenta se fue». Todo lo que se borra porque una
/// cuenta ya no está —la base, la clave huérfana, lo decidido en
/// `stores.json`, la entrada de `pending_key_deletions`— pregunta acá, con
/// [`Self::is_confirmed_gone`].
#[derive(Debug, Clone)]
struct Listings {
    /// El primer listado bueno. Una cuenta que no figuró en ninguno falta
    /// desde ahí.
    first_at: Instant,
    /// El último listado bueno. La confirmación se mide hasta acá y no hasta
    /// «ahora»: el tiempo que pasa sin que el servicio conteste no confirma
    /// nada.
    last_at: Instant,
    /// Todas las cuentas del último listado bueno.
    listed: BTreeSet<String>,
    /// Las que figuraban y dejaron de figurar: el primer listado bueno en que
    /// faltaron. Una que reaparece sale de acá.
    missing_since: BTreeMap<String, Instant>,
}

impl Listings {
    fn first(listed: BTreeSet<String>, now: Instant) -> Self {
        Self {
            first_at: now,
            last_at: now,
            listed,
            missing_since: BTreeMap::new(),
        }
    }

    /// Suma un listado bueno. Devuelve `false`, sin cambiar nada, si es más
    /// viejo que el último que ya se sumó: cada listado se atiende en una tarea
    /// propia, y dos seguidas pueden tomar la cerradura en otro orden.
    fn observe(&mut self, listed: BTreeSet<String>, now: Instant) -> bool {
        if now < self.last_at {
            return false;
        }
        for gone in self.listed.difference(&listed) {
            self.missing_since.insert(gone.clone(), now);
        }
        // La sospecha se olvida en cuanto la cuenta vuelve a figurar.
        self.missing_since.retain(|id, _| !listed.contains(id));
        self.last_at = now;
        self.listed = listed;
        true
    }

    fn is_listed(&self, account_id: &str) -> bool {
        self.listed.contains(account_id)
    }

    /// Si la cuenta faltó en todos los listados buenos desde uno que llegó por
    /// lo menos [`PRUNE_CONFIRMATION`] antes del último. Como la confirmación
    /// no es cero, eso son siempre dos listados distintos.
    fn is_confirmed_gone(&self, account_id: &str) -> bool {
        if self.is_listed(account_id) {
            return false;
        }
        let since = self
            .missing_since
            .get(account_id)
            .copied()
            .unwrap_or(self.first_at);
        self.last_at.saturating_duration_since(since) >= PRUNE_CONFIRMATION
    }
}

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

/// En qué está un área —los contactos, el calendario— de una cuenta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AreaState {
    /// Nadie la pidió todavía: no se sincroniza.
    Off,
    /// Encendida, esperando su vuelta o que se abra la base.
    Pending,
    Syncing,
    /// La última vuelta terminó bien.
    Synced,
    /// No se puede: el servicio de cuentas no da permiso. No se reintenta
    /// hasta la próxima vuelta o un `RequestSync`.
    Unavailable,
    /// La última vuelta falló: el servidor, la red. `detail` dice qué.
    Failed,
}

/// El estado de un área, como lo contesta `GetStatus`. **Sin datos de
/// contactos ni direcciones**: sólo en qué está y un texto fijo que lo explica.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AreaStatus {
    pub state: AreaState,
    /// Vacío si no hay nada que explicar.
    pub detail: String,
    /// Cuándo terminó bien la última vuelta, en esta sesión del servicio.
    pub last_synced_at: Option<String>,
}

impl AreaStatus {
    fn new(state: AreaState) -> Self {
        Self {
            state,
            detail: String::new(),
            last_synced_at: None,
        }
    }
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
    /// El área de contactos, sólo en las cuentas que tienen contactos.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<AreaStatus>,
    /// El área de calendario, sólo en las cuentas que tienen calendario.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calendar: Option<AreaStatus>,
    /// Si la cuenta tiene la capacidad de contactos, aunque no se sincronice.
    /// No se publica: decide quién ve el detalle.
    #[serde(skip)]
    pub has_contacts: bool,
    /// Lo mismo, del calendario.
    #[serde(skip)]
    pub has_calendar: bool,
}

impl AccountStatus {
    /// El estado de un área, si la cuenta la tiene.
    pub fn area(&self, area: &str) -> Option<&AreaStatus> {
        match area {
            CONTACTS_AREA => self.contacts.as_ref(),
            CALENDAR_AREA => self.calendar.as_ref(),
            _ => None,
        }
    }

    /// Si la cuenta tiene la capacidad de un área, aunque no se sincronice.
    pub fn has_area(&self, area: &str) -> bool {
        match area {
            CONTACTS_AREA => self.has_contacts,
            CALENDAR_AREA => self.has_calendar,
            _ => false,
        }
    }
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
    /// Cómo la llama la persona. Va al diálogo de permiso: de qué cuenta se
    /// trata.
    pub display_name: String,
    pub capabilities: Vec<String>,
    /// La base se conserva igual; lo que no se hace es sincronizarla: pedirle
    /// el token daría error en cada vuelta.
    pub needs_reauth: bool,
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

    /// Si tiene la capacidad de un área.
    fn has_area(&self, area: &str) -> bool {
        self.capabilities.iter().any(|c| c == area)
    }

    /// Si hay algo de un área que sincronizar.
    fn has_area_to_sync(&self, area: &str) -> bool {
        !self.needs_reauth && self.has_area(area)
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
    /// nueva guardada. Una cuenta apagada se queda: sacarla sin una clave
    /// nueva es justo lo que esta lista evita.
    ///
    /// La única otra salida es la de una cuenta **que ya no está**, confirmada
    /// como para podar su base (ver [`PRUNE_CONFIRMATION`]), cuyo `Delete`
    /// contestó bien y cuya clave ya no aparece al volver a buscarla con el
    /// llavero desbloqueado. Con el llavero bloqueado no sale nunca: sin poder
    /// releer, «la clave no está» no se sabe.
    #[serde(default)]
    pub pending_key_deletions: BTreeSet<String>,
    /// En qué colección del llavero está la clave de cada base: la identidad
    /// que dio [`KeySource::pin_collection`] cuando se guardó, o cuando se la
    /// encontró y abrió la base por primera vez.
    ///
    /// Es lo que separa «se perdió la clave» de «el llavero es otro». Si la
    /// colección de ahora no es la anotada —el alias `default` apunta a otra, o
    /// el llavero se reemplazó—, la clave no «falta»: está en otra parte, y la
    /// base **no se rehace**. Queda no disponible y el estado lo dice, hasta
    /// que vuelva la colección o la persona la vacíe.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub key_collections: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSettings {
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// Las áreas que alguien pidió alguna vez y que desde ahí se sincronizan
    /// solas. Texto y no un tipo cerrado: un área que llegue en una versión
    /// posterior no puede volver ilegible el archivo al volver a esta.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub active_areas: BTreeSet<String>,
}

impl Default for AccountSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            active_areas: BTreeSet::new(),
        }
    }
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

    /// Si alguien pidió alguna vez esta área de esta cuenta.
    pub fn is_active(&self, account_id: &str, area: &str) -> bool {
        self.accounts
            .get(account_id)
            .is_some_and(|settings| settings.active_areas.contains(area))
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
    ///
    /// El temporal tiene un nombre propio de esta escritura y se crea **nuevo**
    /// (`O_CREAT|O_EXCL`) y con `O_NOFOLLOW`: un enlace plantado con ese nombre,
    /// o un archivo que ya estaba, hacen fallar la escritura en vez de pisar lo
    /// que apunten. Si algo falla después de crearlo, se borra.
    pub fn save(&self, path: &Path) -> Result<(), StoreError> {
        let dir = path
            .parent()
            .ok_or_else(|| StoreError::Settings("la ruta no tiene carpeta".into()))?;
        paths::create_private_dir(dir)?;
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| StoreError::Settings(format!("no se pudo serializar: {e}")))?;

        let temporary = dir.join(temporary_name());
        write_new_private(&temporary, &json)
            .and_then(|()| {
                std::fs::rename(&temporary, path).inspect_err(|_| {
                    let _ = std::fs::remove_file(&temporary);
                })
            })
            .map_err(|e| {
                StoreError::Settings(format!("no se pudo guardar {}: {e}", path.display()))
            })
    }
}

/// Un nombre de temporal que no usa ninguna otra escritura: el proceso, un
/// contador y la hora. No hace falta que sea impredecible —el temporal se crea
/// con `O_EXCL`, así que adivinarlo sólo hace fallar la escritura—, sólo que
/// dos escrituras no se pisen.
fn temporary_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!(
        ".stores.json.{}.{}.{nanos}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// Escribe `bytes` en un archivo **nuevo**, 0600, sin seguir un enlace, y lo
/// lleva al disco. Si falla después de crearlo, lo borra: es de esta escritura.
fn write_new_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .inspect_err(|_| {
            let _ = std::fs::remove_file(path);
        })
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
    /// El estado de cada área, desde que alguien la tocó en esta sesión.
    areas: BTreeMap<&'static str, AreaStatus>,
}

impl Entry {
    fn new() -> Self {
        Self {
            store: None,
            state: StoreState::Locked,
            detail: String::new(),
            areas: BTreeMap::new(),
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
    /// Lo que dijeron los `ListAccounts` que respondieron bien, o nada si
    /// todavía no respondió ninguno.
    listings: Option<Listings>,
    /// Las que tienen algo que guardar.
    wanted: BTreeSet<String>,
    /// Por área, las que tienen algo de esa área que sincronizar.
    syncable: BTreeMap<&'static str, BTreeSet<String>>,
    /// Por área, las que tienen almacén y la capacidad de esa área —también
    /// las que piden reautenticarse: lo guardado se puede leer igual—, con el
    /// nombre que les puso la persona.
    area_accounts: BTreeMap<&'static str, BTreeMap<String, String>>,
    entries: BTreeMap<String, Entry>,
}

impl Inner {
    fn is_syncable(&self, area: &str, account_id: &str) -> bool {
        self.syncable
            .get(area)
            .is_some_and(|ids| ids.contains(account_id))
    }

    fn has_area(&self, area: &str, account_id: &str) -> bool {
        self.area_accounts
            .get(area)
            .is_some_and(|ids| ids.contains_key(account_id))
    }

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
    locations: Result<Locations, StoreError>,
    inner: Mutex<Inner>,
    /// Las conexiones de lectura de cada base abierta. Aparte de `inner` para
    /// que leer no espere a la cerradura que tiene tomada un lote de escritura.
    /// Una base que se cierra cierra su grupo, y el que queda acá no sirve más
    /// ([`ReadPool::is_closed`]) hasta que otra apertura lo reemplace.
    readers: std::sync::Mutex<BTreeMap<String, Arc<ReadPool>>>,
    /// Por dónde sale cada cambio, si alguien escucha.
    changes: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<StoreChange>>>,
}

/// Si quien pide encender un área dio su permiso para leerla
/// ([`StoreManager::activate_area`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consent {
    /// Se le preguntó `store.<área>` y dijo que sí.
    Granted,
    /// No se le preguntó: un área apagada no se enciende.
    NotAsked,
}

/// Lo que [`StoreManager::area_account`] sabe de una cuenta con un área.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AreaAccount {
    pub display_name: String,
    /// Si alguien ya la pidió y se sincroniza sola.
    pub active: bool,
    /// Si se puede sincronizar: no pide reautenticarse.
    pub syncable: bool,
}

/// Un lote que cambió lo guardado de un área de una cuenta. Es lo que lleva la
/// señal `Changed`: **cuándo**, no **qué**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreChange {
    pub area: &'static str,
    pub account_id: String,
    pub generation: u64,
}

impl<K: KeySource> StoreManager<K> {
    pub fn new(keys: K, locations: Result<Locations, StoreError>) -> Self {
        Self {
            keys,
            locations,
            inner: Mutex::new(Inner::default()),
            readers: std::sync::Mutex::new(BTreeMap::new()),
            changes: std::sync::Mutex::new(None),
        }
    }

    /// Los cambios, de acá en adelante, en orden. Hay un solo oyente: uno nuevo
    /// reemplaza al anterior.
    pub fn subscribe_changes(&self) -> tokio::sync::mpsc::UnboundedReceiver<StoreChange> {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        *self.changes.lock().unwrap_or_else(|p| p.into_inner()) = Some(sender);
        receiver
    }

    fn announce(&self, account_id: &str, changes: Vec<(&'static str, u64)>) {
        if changes.is_empty() {
            return;
        }
        let sink = self.changes.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(sink) = sink.as_ref() {
            for (area, generation) in changes {
                let _ = sink.send(StoreChange {
                    area,
                    account_id: account_id.to_string(),
                    generation,
                });
            }
        }
    }

    /// Anota el grupo de lectura de una base recién abierta. De paso se van los
    /// que ya se cerraron.
    fn register_readers(&self, account_id: &str, store: &Store) {
        let mut readers = self.readers.lock().unwrap_or_else(|p| p.into_inner());
        readers.retain(|_, pool| !pool.is_closed());
        readers.insert(account_id.to_string(), store.readers());
    }

    fn reader_pool(&self, account_id: &str) -> Option<Arc<ReadPool>> {
        self.readers
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(account_id)
            .filter(|pool| !pool.is_closed())
            .cloned()
    }

    /// Lee algo de la base abierta de una cuenta, por una de sus conexiones de
    /// sólo lectura. **No toma la cerradura del administrador**: un lote de
    /// escritura largo no la hace esperar, y ve lo último que se confirmó.
    ///
    /// Con la base cerrada, `Err(Missing)`. Con el llavero bloqueado —o sin
    /// poder saberlo—, `Err(Key(Locked))` y nada leído: el llavero se relee en
    /// cada lectura, igual que antes de cada lote, porque `vasak-keyring` no
    /// avisa al bloquearse. Las conexiones de lectura se cierran en el acto, y
    /// la de escritura con la tabla —ya, si el escritor no está ocupado; si
    /// no, lo hace él antes de su próximo lote—.
    pub async fn read<T, F>(&self, account_id: &str, work: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&rusqlite::Connection) -> Result<T, StoreError> + Send + 'static,
    {
        let pool = self.open_readers(account_id).await?;
        blocking(move || pool.read(work)).await?
    }

    /// Como [`Self::read`], pero con el grupo de lectura entero, para una
    /// lectura **de a partes**: cada parte toma una conexión y la suelta, y lo
    /// que hay entre una y otra —la expansión en el momento del calendario, que
    /// es CPU— corre sin ninguna. Cada parte vuelve a mirar si el grupo se
    /// cerró: con el llavero bloqueado a mitad, la siguiente da
    /// `Err(Missing)`.
    pub async fn read_in_parts<T, F>(&self, account_id: &str, work: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&ReadPool) -> Result<T, StoreError> + Send + 'static,
    {
        let pool = self.open_readers(account_id).await?;
        blocking(move || work(&pool)).await?
    }

    /// El grupo de lectura de una base abierta, con el llavero releído.
    async fn open_readers(&self, account_id: &str) -> Result<Arc<ReadPool>, StoreError> {
        let pool = self.reader_pool(account_id).ok_or(StoreError::Missing)?;
        if !matches!(self.keys.is_locked().await, Ok(false)) {
            pool.close();
            if let Ok(mut inner) = self.inner.try_lock() {
                self.run(&mut inner, Some(account_id)).await;
            }
            return Err(StoreError::Key(KeyError::Locked));
        }
        Ok(pool)
    }

    pub fn keys(&self) -> &K {
        &self.keys
    }

    fn locations(&self) -> Result<&Locations, StoreError> {
        self.locations.as_ref().map_err(Clone::clone)
    }

    /// El estado de todas las bases.
    pub async fn status(&self) -> Status {
        let inner = self.inner.lock().await;
        let root = self.locations.as_ref().ok().map(|l| l.stores.clone());
        let settings = self
            .locations
            .as_ref()
            .ok()
            .and_then(|l| StoreSettings::load(&l.settings).ok())
            .unwrap_or_default();
        let accounts = inner
            .wanted
            .iter()
            .map(|id| {
                let area = |area: &'static str| {
                    inner.is_syncable(area, id).then(|| {
                        inner
                            .entries
                            .get(id)
                            .and_then(|e| e.areas.get(area).cloned())
                            .unwrap_or_else(|| {
                                AreaStatus::new(if settings.is_active(id, area) {
                                    AreaState::Pending
                                } else {
                                    AreaState::Off
                                })
                            })
                    })
                };
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
                    contacts: area(CONTACTS_AREA),
                    calendar: area(CALENDAR_AREA),
                    has_contacts: inner.has_area(CONTACTS_AREA, id),
                    has_calendar: inner.has_area(CALENDAR_AREA, id),
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
    /// `now` es cuándo llegó la respuesta; se pasa y no se lee acá para poder
    /// probar la confirmación sin esperar una vuelta entera.
    ///
    /// **Con `Failed` no se hace nada**, y en particular no se borra nada ni se
    /// cuenta para confirmar una ausencia: un servicio de cuentas que no
    /// contesta no quiere decir que la persona no tenga cuentas. Una respuesta
    /// buena tampoco borra sola lo de una cuenta que no figura: hace falta la
    /// confirmación de [`Listings::is_confirmed_gone`].
    pub async fn accounts_listed(&self, listing: AccountListing, now: Instant) -> bool {
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

        match &mut inner.listings {
            Some(listings) => {
                if !listings.observe(listed, now) {
                    tracing::debug!("se descartó un listado de cuentas más viejo que el último");
                    return false;
                }
            }
            None => inner.listings = Some(Listings::first(listed, now)),
        }

        inner.syncable = SYNCED_AREAS
            .iter()
            .map(|area| {
                let ids = accounts
                    .iter()
                    .filter(|a| a.has_area_to_sync(area) && wanted.contains(&a.id))
                    .map(|a| a.id.clone())
                    .collect();
                (*area, ids)
            })
            .collect();
        inner.area_accounts = SYNCED_AREAS
            .iter()
            .map(|area| {
                let ids = accounts
                    .iter()
                    .filter(|a| wanted.contains(&a.id) && a.has_area(area))
                    .map(|a| (a.id.clone(), a.display_name.clone()))
                    .collect();
                (*area, ids)
            })
            .collect();

        // Las que ya no tienen nada que guardar se cierran. Cerrar no es
        // borrar: una que reaparece en el próximo listado se vuelve a abrir con
        // su clave.
        inner.entries.retain(|id, _| wanted.contains(id));
        inner.wanted = wanted;

        self.run(&mut inner, None).await;
        let unlocked = inner.keyring == KeyringState::Unlocked;
        if let Some(listings) = &inner.listings {
            self.prune(unlocked, listings).await;
        }

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
    ///
    /// Sólo para una cuenta del último `ListAccounts` bueno (ver
    /// [`Self::require_listed`]).
    pub async fn set_enabled(&self, account_id: &str, enabled: bool) -> Result<(), StoreError> {
        paths::validate_account_id(account_id)?;
        let mut inner = self.inner.lock().await;
        Self::require_listed(&inner, account_id)?;
        let locations = self.locations()?;

        let mut settings = StoreSettings::load(&locations.settings)?;
        // Lo demás que se decidió para la cuenta —las áreas encendidas— se
        // conserva: apagar la base no es olvidar que alguien pidió sus contactos.
        settings
            .accounts
            .entry(account_id.to_string())
            .or_default()
            .enabled = enabled;
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
    ///
    /// Sólo para una cuenta del último `ListAccounts` bueno (ver
    /// [`Self::require_listed`]).
    pub async fn clear(&self, account_id: &str) -> Result<(), StoreError> {
        paths::validate_account_id(account_id)?;
        let mut inner = self.inner.lock().await;
        Self::require_listed(&inner, account_id)?;
        let locations = self.locations()?;

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

    /// Enciende un área de una cuenta, si tiene algo de esa área que
    /// sincronizar. Queda anotado en `stores.json`, así que sigue encendida
    /// después de reiniciar. Devuelve si hay algo que sincronizar con el área
    /// encendida.
    ///
    /// **Encender pide `consent`**: sólo con [`Consent::Granted`] —quien llama
    /// preguntó `store.<área>` y le dijeron que sí— un área apagada se
    /// enciende. Con [`Consent::NotAsked`], una encendida sigue y una apagada
    /// queda así. La decisión se toma acá, con la misma cerradura con que se
    /// enciende: `RequestSync` miraba primero si hacía falta preguntar y
    /// encendía después, y un `ListAccounts` en el medio —la cuenta que deja
    /// de pedir reautenticarse, o que suma contactos— la encendía sin que
    /// nadie hubiera preguntado.
    ///
    /// Una cuenta sin esa área no enciende nada y tampoco es un error.
    pub async fn activate_area(
        &self,
        area: &'static str,
        account_id: &str,
        consent: Consent,
    ) -> Result<bool, StoreError> {
        paths::validate_account_id(account_id)?;
        let inner = self.inner.lock().await;
        Self::require_listed(&inner, account_id)?;
        if !inner.is_syncable(area, account_id) {
            return Ok(false);
        }
        let locations = self.locations()?;
        let mut settings = StoreSettings::load(&locations.settings)?;
        if settings.is_active(account_id, area) {
            return Ok(true);
        }
        if consent != Consent::Granted {
            return Ok(false);
        }
        settings
            .accounts
            .entry(account_id.to_string())
            .or_default()
            .active_areas
            .insert(area.to_string());
        settings.save(&locations.settings)?;
        Ok(true)
    }

    /// Una cuenta del último listado bueno, para los comandos que la nombran.
    pub async fn is_known(&self, account_id: &str) -> bool {
        Self::require_listed(&*self.inner.lock().await, account_id).is_ok()
    }

    /// Lo que hace falta saber para leer un área de una cuenta: cómo se llama
    /// —para el diálogo de permiso— y si su área ya está encendida.
    ///
    /// `UnknownAccount` si la cuenta no está en el último listado, no tiene
    /// almacén o no tiene esa área.
    pub async fn area_account(
        &self,
        area: &'static str,
        account_id: &str,
    ) -> Result<AreaAccount, StoreError> {
        paths::validate_account_id(account_id)?;
        let inner = self.inner.lock().await;
        Self::require_listed(&inner, account_id)?;
        let Some(display_name) = inner
            .area_accounts
            .get(area)
            .and_then(|ids| ids.get(account_id))
        else {
            return Err(StoreError::UnknownAccount(account_id.to_string()));
        };
        let active = self
            .locations()
            .ok()
            .and_then(|l| StoreSettings::load(&l.settings).ok())
            .is_some_and(|s| s.is_active(account_id, area));
        Ok(AreaAccount {
            display_name: display_name.clone(),
            active,
            syncable: inner.is_syncable(area, account_id),
        })
    }

    /// Todas las cuentas que tienen un área, en orden de identificador, con lo
    /// mismo que [`Self::area_account`]. Es lo que leen las lecturas que
    /// juntan todas las cuentas —el calendario de un widget—.
    pub async fn area_accounts(&self, area: &'static str) -> Vec<(String, AreaAccount)> {
        let inner = self.inner.lock().await;
        let settings = self
            .locations()
            .ok()
            .and_then(|l| StoreSettings::load(&l.settings).ok())
            .unwrap_or_default();
        inner
            .area_accounts
            .get(area)
            .into_iter()
            .flatten()
            .map(|(id, display_name)| {
                (
                    id.clone(),
                    AreaAccount {
                        display_name: display_name.clone(),
                        active: settings.is_active(id, area),
                        syncable: inner.is_syncable(area, id),
                    },
                )
            })
            .collect()
    }

    /// Después de vaciar una base con alguna área encendida: sube la
    /// generación de cada una en la base nueva, y eso sale como `Changed`.
    /// Quien tenía una lista leída se entera de que ya no vale sin esperar a
    /// la sincronización.
    pub async fn announce_cleared(&self, account_id: &str) {
        for area in SYNCED_AREAS {
            match self.area_account(area, account_id).await {
                Ok(account) if account.active => {}
                _ => continue,
            }
            if let Err(e) = self
                .with_store(account_id, move |store| store.touch(area).map(|_| ()))
                .await
            {
                tracing::debug!("no se pudo anunciar la base vaciada de «{account_id}»: {e}");
            }
        }
    }

    /// Las cuentas a las que hay que sincronizarles un área: con esa área, con
    /// la base encendida y con el área encendida.
    pub async fn area_targets(&self, area: &'static str) -> Vec<String> {
        let inner = self.inner.lock().await;
        let Ok(locations) = self.locations() else {
            return Vec::new();
        };
        let Ok(settings) = StoreSettings::load(&locations.settings) else {
            return Vec::new();
        };
        inner
            .syncable
            .get(area)
            .into_iter()
            .flatten()
            .filter(|id| settings.is_enabled(id) && settings.is_active(id, area))
            .cloned()
            .collect()
    }

    /// Antes de pedir nada a la red: pasa la tabla por la cuenta —releyendo el
    /// llavero **ahora**— y dice si su base quedó abierta. Con el llavero
    /// bloqueado, sin llavero, con la base cerrada o sin nada del área que
    /// sincronizar, `false`, y no se pide nada.
    pub async fn prepare_for_sync(&self, area: &'static str, account_id: &str) -> bool {
        let mut inner = self.inner.lock().await;
        if !inner.is_syncable(area, account_id) {
            return false;
        }
        self.run(&mut inner, Some(account_id)).await;
        inner
            .entries
            .get(account_id)
            .is_some_and(|e| e.store.is_some())
    }

    /// Hace algo con la base abierta de una cuenta. **El único camino para
    /// escribir en una base**: con la cerradura tomada, así que no hay dos
    /// escritores, y con el llavero releído en este momento.
    ///
    /// Con el llavero bloqueado —o sin poder saberlo— no se hace nada: se pasa
    /// la tabla, que cierra lo abierto, y vuelve `Err(Key(Locked))`. Con la
    /// base cerrada, `Err(Missing)`.
    ///
    /// El trabajo corre fuera del hilo del bucle de eventos, con la base
    /// prestada, y vuelve a su lugar al terminar. Quien llama lo corta en lotes
    /// chicos (ver `store::contacts::WRITE_BATCH_ROWS`): mientras corre, nadie
    /// más llega al almacén.
    pub async fn with_store<T, F>(&self, account_id: &str, work: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Store) -> Result<T, StoreError> + Send + 'static,
    {
        let mut inner = self.inner.lock().await;
        if !matches!(self.keys.is_locked().await, Ok(false)) {
            self.run(&mut inner, Some(account_id)).await;
            return Err(StoreError::Key(KeyError::Locked));
        }
        let Some(mut store) = inner
            .entries
            .get_mut(account_id)
            .and_then(|e| e.store.take())
        else {
            return Err(StoreError::Missing);
        };
        match blocking(move || {
            let result = work(&mut store);
            let changes = store.take_changes();
            (store, result, changes)
        })
        .await
        {
            Ok((store, result, changes)) => {
                inner.entry(account_id).store = Some(store);
                // Lo confirmado se anuncia aunque el trabajo haya terminado
                // con un error después: ya está en la base.
                self.announce(account_id, changes);
                result
            }
            Err(e) => {
                // La tarea se cayó con la base adentro: se cerró al soltarse.
                inner
                    .entry(account_id)
                    .set(StoreState::Unavailable, e.public_detail());
                Err(e)
            }
        }
    }

    /// Anota en qué está un área de una cuenta. Devuelve si cambió lo que se
    /// publica.
    pub async fn set_area_status(
        &self,
        area: &'static str,
        account_id: &str,
        state: AreaState,
        detail: &str,
    ) -> bool {
        let mut inner = self.inner.lock().await;
        if !inner.wanted.contains(account_id) {
            return false;
        }
        let entry = inner.entry(account_id);
        let previous = entry.areas.get(area).cloned();
        let mut status = previous
            .clone()
            .unwrap_or_else(|| AreaStatus::new(AreaState::Off));
        status.state = state;
        status.detail = detail.to_string();
        if state == AreaState::Synced {
            status.last_synced_at = Some(chrono::Utc::now().to_rfc3339());
        }
        let changed = previous.as_ref() != Some(&status);
        entry.areas.insert(area, status);
        changed
    }

    /// Falla con `UnknownAccount` —lo mismo que `RequestSync`— si la cuenta
    /// no está en el último `ListAccounts` que respondió bien.
    ///
    /// Los identificadores llegan por D-Bus de cualquier proceso de la sesión,
    /// y cada uno aceptado deja una entrada en `stores.json`, en memoria y en
    /// `pending_key_deletions`: sin esto crecerían sin tope con nombres
    /// inventados. **Antes del primer `ListAccounts` bueno se rechaza todo**:
    /// todavía no se sabe qué cuentas hay, y la ventana que llama las sacó de
    /// ese mismo listado, así que un reintento después del arranque alcanza.
    fn require_listed(inner: &Inner, account_id: &str) -> Result<(), StoreError> {
        match &inner.listings {
            Some(listings) if listings.is_listed(account_id) => Ok(()),
            _ => Err(StoreError::UnknownAccount(account_id.to_string())),
        }
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
            Err(e) => {
                for id in &targets {
                    let entry = inner.entry(id);
                    entry.close();
                    entry.set(StoreState::Unavailable, e.public_detail());
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
                    entry.set(StoreState::Unavailable, e.public_detail());
                }
                return;
            }
        };

        // La colección, una vez por vuelta: lo que sigue la usa fijada.
        let mut collection = String::new();
        let locked = match self.keys.pin_collection().await {
            Ok(identity) => {
                collection = identity;
                self.keys.is_locked().await
            }
            Err(e) => Err(e),
        };
        let locked = match locked {
            Ok(locked) => locked,
            Err(e) => {
                tracing::info!("el llavero no contesta: {e}");
                let e = StoreError::Key(e);
                // Sin saber si el llavero está abierto, la clave no se usa: se
                // cierra todo y se espera.
                inner.keyring = KeyringState::Unavailable;
                for (id, entry) in inner.entries.iter_mut() {
                    entry.close();
                    if settings.is_enabled(id) {
                        entry.set(StoreState::Unavailable, e.public_detail());
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
                        inner.entry(id).set(state, e.public_detail());
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
        if let Some(listings) = &inner.listings {
            self.sweep_orphan_keys(listings).await;
            self.forget_gone_accounts(locations, &mut settings, listings, &cleared)
                .await;
        }

        for id in targets {
            self.bring_account(inner, locations, &mut settings, &cleared, &collection, &id)
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
        collection: &str,
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
            if !settings.key_collections.contains_key(account_id) {
                self.adopt_collection(locations, settings, collection, account_id)
                    .await;
            }
            return;
        }

        let moved = settings
            .key_collections
            .get(account_id)
            .is_some_and(|recorded| recorded != collection);
        let result = self
            .bring_up(&locations.stores, account_id, pending, moved)
            .await;
        if result.is_ok()
            && settings.key_collections.get(account_id).map(String::as_str) != Some(collection)
        {
            // La clave con la que abrió está en esta colección —la guardó
            // recién, o la encontró ahí—, **si la colección sigue siendo la
            // del principio de la vuelta**. Un llavero que cambió de colección
            // entre que se fijó y que se guardó la clave nueva la dejó en la
            // nueva: anotar la de antes ataba la base a una colección donde su
            // clave no está, y después de reiniciar quedaba `unavailable` por
            // `CollectionChanged` hasta vaciarla. Si cambió, no se anota nada
            // y la base queda abierta: la vuelta siguiente, con la colección
            // nueva fijada, la adopta ([`Self::adopt_collection`]), y un
            // reinicio antes de eso la encuentra en la nueva como a una base
            // de antes.
            match self.keys.pinned_is_unchanged().await {
                Ok(true) => {
                    settings
                        .key_collections
                        .insert(account_id.to_string(), collection.to_string());
                    if let Err(e) = settings.save(&locations.settings) {
                        tracing::warn!("{e}");
                    }
                }
                Ok(false) | Err(_) => tracing::info!(
                    "'{account_id}': la colección del llavero cambió mientras se abría la base;                      se anota en la vuelta siguiente"
                ),
            }
        }
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
        if let Ok((store, _)) = &result {
            self.register_readers(account_id, store);
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
                entry.set(StoreState::Unavailable, e.public_detail());
            }
        }
    }

    /// Una base abierta sin colección anotada —porque la colección cambió en la
    /// vuelta en que se abrió— adopta la de esta vuelta, **si su clave está
    /// ahí y es la que la abre**: la clave se busca en la colección fijada y se
    /// prueba contra el archivo. Si no está, o es otra, no se anota nada y la
    /// base sigue abierta como estaba; nada se borra.
    async fn adopt_collection(
        &self,
        locations: &Locations,
        settings: &mut StoreSettings,
        collection: &str,
        account_id: &str,
    ) {
        let Ok(Some(key)) = self.keys.find(account_id).await else {
            return;
        };
        let Ok(paths) = StorePaths::new(&locations.stores, account_id) else {
            return;
        };
        let opens = blocking(move || Store::key_opens(&paths, &key))
            .await
            .unwrap_or(false);
        if !opens || !matches!(self.keys.pinned_is_unchanged().await, Ok(true)) {
            return;
        }
        settings
            .key_collections
            .insert(account_id.to_string(), collection.to_string());
        if let Err(e) = settings.save(&locations.settings) {
            tracing::warn!("{e}");
        }
    }

    /// Las filas 2 a 5 de la tabla. Devuelve la base abierta y si se rehízo.
    ///
    /// Con `discard_found_key`, lo que haya en el llavero para esta cuenta no se
    /// usa: es una cuenta vaciada o apagada, y una clave que aparece ahí es la
    /// vieja —un `Delete` que contestó bien y no borró—. Se sigue como si no
    /// hubiera clave, y la nueva la reemplaza.
    ///
    /// Con `collection_moved`, la clave de esta cuenta se guardó en otra
    /// colección que la de esta vuelta. Si hay base, **no se toca**: ni se
    /// busca la clave —lo que haya en esta colección no es la suya—, ni se
    /// rehace. Sin base no hay nada que perder, y se sigue como siempre.
    async fn bring_up(
        &self,
        root: &Path,
        account_id: &str,
        discard_found_key: bool,
        collection_moved: bool,
    ) -> Result<(Store, bool), StoreError> {
        let paths = StorePaths::new(root, account_id)?;
        if collection_moved && paths.db_exists()? {
            return Err(StoreError::CollectionChanged);
        }

        let key = if discard_found_key {
            None
        } else {
            match self.keys.find(account_id).await {
                Ok(key) => key,
                // Lo guardado no es una clave: es lo mismo que una que no abre.
                Err(KeyError::Malformed) => {
                    self.ensure_unlocked().await?;
                    self.ensure_same_collection().await?;
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
    ///
    /// **Y la colección se vuelve a identificar**, al entrar y otra vez justo
    /// antes de borrar. `moved` se calculó con la identidad del principio de la
    /// vuelta, y la ruta fijada puede servir, después de un reinicio del
    /// llavero, otra colección: ahí la clave «falta» porque la colección es
    /// otra. Si cambió, no se borra nada y la cuenta queda no disponible; la
    /// vuelta siguiente fija la nueva, ve que no es la anotada y la base queda
    /// como estaba.
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
        self.ensure_same_collection().await?;
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
        // La última, después de las idas y vueltas de la clave nueva: lo que
        // sigue es lo que borra.
        self.ensure_same_collection().await?;
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

    /// Falla si la colección fijada en esta vuelta ya no es **ahora** la misma
    /// (ver [`KeySource::pinned_is_unchanged`]).
    async fn ensure_same_collection(&self) -> Result<(), StoreError> {
        match self.keys.pinned_is_unchanged().await? {
            true => Ok(()),
            false => Err(StoreError::CollectionChanged),
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
        // La colección anotada se olvida: la base que venga después se hace
        // con una clave nueva, en la colección de ese momento.
        let forgot = settings.key_collections.remove(account_id).is_some();
        if settings
            .pending_key_deletions
            .insert(account_id.to_string())
            || forgot
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
    ///
    /// Sólo las de una ausencia confirmada, igual que la poda de la base: una
    /// clave borrada por un listado vacío suelto deja ilegible una base buena.
    async fn sweep_orphan_keys(&self, listings: &Listings) {
        let Ok(with_keys) = self.keys.key_accounts().await else {
            return;
        };
        for account_id in with_keys.iter().filter(|id| listings.is_confirmed_gone(id)) {
            match self.keys.delete(account_id).await {
                Ok(()) => tracing::info!("se borró la clave huérfana de «{account_id}»"),
                Err(e) => tracing::warn!("'{account_id}': la clave huérfana sigue: {e}"),
            }
        }
    }

    /// Saca de `stores.json` lo que queda de las cuentas que ya no están: su
    /// entrada en `pending_key_deletions` y lo decidido para ellas.
    ///
    /// Sin esto, una cuenta vaciada o apagada y después quitada quedaba anotada
    /// para siempre: nunca iba a tener la clave nueva que la saca de la lista.
    ///
    /// Sale sólo una cuenta con la ausencia confirmada, cuyo `Delete` de esta
    /// vuelta contestó bien (`cleared`), cuya clave **no aparece al volver a
    /// buscarla**, y con `Locked == false` releído después de esa búsqueda. Un
    /// `Delete` que contesta bien no prueba nada solo, y con el llavero
    /// bloqueado no se llega hasta acá.
    async fn forget_gone_accounts(
        &self,
        locations: &Locations,
        settings: &mut StoreSettings,
        listings: &Listings,
        cleared: &BTreeSet<String>,
    ) {
        let candidates: Vec<String> = settings
            .pending_key_deletions
            .iter()
            .filter(|id| cleared.contains(*id) && listings.is_confirmed_gone(id))
            .cloned()
            .collect();

        let mut changed = false;
        for account_id in candidates {
            if !matches!(self.keys.find(&account_id).await, Ok(None)) {
                continue;
            }
            if !matches!(self.keys.is_locked().await, Ok(false)) {
                continue;
            }
            settings.pending_key_deletions.remove(&account_id);
            settings.accounts.remove(&account_id);
            settings.key_collections.remove(&account_id);
            changed = true;
            tracing::info!(
                "se olvidó la clave pendiente de «{account_id}», que ya no es una cuenta"
            );
        }
        if changed {
            if let Err(e) = settings.save(&locations.settings) {
                tracing::warn!("{e}");
            }
        }
    }

    /// Borra la base de toda cuenta cuya ausencia está confirmada (ver
    /// [`Listings::is_confirmed_gone`]).
    ///
    /// Todo relativo a un descriptor de `stores/` abierto sin seguir enlaces:
    /// si `stores/` o `vasak-accounts-sync/` son un enlace, no se borra nada. Y
    /// sólo carpetas que parecen una base; lo demás que haya ahí no es de este
    /// servicio. Ver [`paths::StoresRoot`].
    async fn prune(&self, unlocked: bool, listings: &Listings) {
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
                for account_id in ids.into_iter().filter(|id| listings.is_confirmed_gone(id)) {
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

        // Y lo decidido para cuentas que ya no existen. `pending_key_deletions`
        // no: ésa necesita el llavero, y la vacía `forget_gone_accounts`.
        if let Ok(mut settings) = StoreSettings::load(&locations.settings) {
            let before = (settings.accounts.len(), settings.key_collections.len());
            settings
                .accounts
                .retain(|id, _| !listings.is_confirmed_gone(id));
            settings
                .key_collections
                .retain(|id, _| !listings.is_confirmed_gone(id));
            if (settings.accounts.len(), settings.key_collections.len()) != before {
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
        /// El reloj de los listados: sólo avanza cuando la prueba lo pide.
        clock: std::sync::Mutex<Instant>,
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
                clock: std::sync::Mutex::new(Instant::now()),
            }
        }

        /// Un listado que llega ahora, según el reloj de la prueba.
        async fn list(&self, listing: AccountListing) -> bool {
            let now = *self.clock.lock().unwrap();
            self.manager.accounts_listed(listing, now).await
        }

        fn advance(&self, by: Duration) {
            *self.clock.lock().unwrap() += by;
        }

        /// Un listado que llega una vuelta después del anterior.
        async fn list_after_a_round(&self, listing: AccountListing) -> bool {
            self.advance(PRUNE_CONFIRMATION);
            self.list(listing).await
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
            display_name: format!("Cuenta {id}"),
            capabilities: capabilities.iter().map(|c| c.to_string()).collect(),
            needs_reauth: false,
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
        log_lines_with(fixture, account_id, &key)
    }

    /// El `sync_log` de una base abierta con una clave dada: para cuando la
    /// del llavero no es la de la base.
    fn log_lines_with(
        fixture: &Fixture,
        account_id: &str,
        key: &StoreKey,
    ) -> Vec<(String, String)> {
        let store = Store::open(&fixture.paths(account_id), key).unwrap();
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

        f.list(listing(&["cuenta"])).await;

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

        f.list(listing(&["cuenta"])).await;

        assert_eq!(std::fs::read(&f.paths("cuenta").db).unwrap(), before);
        assert!(f.keys.state().stored.is_empty());
    }

    /// Fila 2: sin clave ni base, primero la clave y después la base.
    #[tokio::test]
    async fn fila_2_sin_clave_ni_base_se_crea_la_clave_y_despues_la_base() {
        let f = Fixture::new("fila2");
        f.list(listing(&["cuenta"])).await;

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

        f.list(listing(&["cuenta"])).await;

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

        f.list(listing(&["cuenta"])).await;

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

        f.list(listing(&["cuenta"])).await;

        assert_eq!(f.state("cuenta").await, StoreState::Open);
    }

    /// Fila 4: sin clave y con base. Se rehace, se anota y se avisa.
    #[tokio::test]
    async fn fila_4_sin_clave_y_con_base_se_rehace_y_queda_anotado() {
        let f = Fixture::new("fila4");
        drop(Store::create(&f.paths("cuenta"), &fixed_key(b'a')).unwrap());

        f.list(listing(&["cuenta"])).await;

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

        f.list(listing(&["cuenta"])).await;

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

        f.list(listing(&["cuenta"])).await;

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

        f.list(listing(&["cuenta"])).await;

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

        f.list(listing(&["cuenta"])).await;

        assert_eq!(f.state("cuenta").await, StoreState::Rebuilt);
        assert_eq!(f.keys.state().deleted, vec!["cuenta".to_string()]);
        assert!(f.key("cuenta").is_some());
    }

    /// Fila 6: al bloquearse, la base abierta se cierra. Y al desbloquear vuelve.
    #[tokio::test]
    async fn fila_6_al_bloquearse_se_cierra_la_base_y_al_desbloquear_se_abre() {
        let f = Fixture::new("fila6");
        f.list(listing(&["cuenta"])).await;
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

    // ── La colección del llavero ────────────────────────────────────────────

    /// Si la identidad de la colección no se pudo leer, la vuelta no crea ni
    /// adopta nada y no anota ninguna colección: la siguiente lo hace con la
    /// identidad de verdad, y la base no queda atada a una que no existe.
    #[tokio::test]
    async fn sin_la_identidad_de_la_coleccion_no_se_anota_nada() {
        let f = Fixture::new("coleccion-sin-identidad");
        f.keys.state().fail_pins = 1;
        f.list(listing(&["a"])).await;
        assert!(f.settings().key_collections.is_empty());
        assert!(f.keys.state().stored.is_empty(), "no se creó ninguna clave");
        assert!(!f.manager.is_open("a").await);

        f.manager.refresh().await;
        assert_eq!(
            f.settings().key_collections.get("a").map(String::as_str),
            Some("coleccion-a")
        );
        assert!(f.manager.is_open("a").await);
    }

    /// El alias `default` que pasa a otra colección —o un llavero que se
    /// reemplazó— hace que ninguna clave «esté». Eso no es una clave perdida:
    /// **no se rehace ninguna base**, el estado lo dice, y al volver la
    /// colección todo abre como estaba.
    #[tokio::test]
    async fn la_coleccion_del_llavero_que_cambia_no_rehace_ninguna_base() {
        let f = Fixture::new("coleccion");
        f.list(listing(&["a", "b"])).await;
        assert_eq!(
            f.settings().key_collections.get("a").map(String::as_str),
            Some("coleccion-a")
        );
        assert_eq!(f.keys.state().pins, 1, "una vez por vuelta, no por cuenta");
        let keys_before = f.keys.state().keys.clone();
        let stored_before = f.keys.state().stored.len();

        // Se bloquea —se cierran— y vuelve con otra colección, vacía.
        f.keys.state().locked = true;
        f.manager.refresh().await;
        {
            let mut state = f.keys.state();
            state.locked = false;
            state.collection = "coleccion-b".into();
            state.keys.clear();
        }
        f.manager.refresh().await;

        for id in ["a", "b"] {
            assert_eq!(f.state(id).await, StoreState::Unavailable);
            assert!(!f.manager.is_open(id).await);
        }
        let status = f.manager.status().await;
        assert_eq!(
            status.accounts[0].detail,
            StoreError::CollectionChanged.to_string()
        );
        assert_eq!(
            f.keys.state().stored.len(),
            stored_before,
            "no se tenía que generar ninguna clave"
        );
        assert!(f.keys.state().deleted.is_empty(), "ni borrar ninguna");

        // Vuelve la colección de antes: abren las mismas, sin rehacer nada.
        {
            let mut state = f.keys.state();
            state.collection = "coleccion-a".into();
            state.keys = keys_before;
        }
        f.manager.refresh().await;
        for id in ["a", "b"] {
            assert_eq!(f.state(id).await, StoreState::Open);
            assert!(log_lines(&f, id).is_empty(), "no se rehízo");
        }
    }

    /// El llavero se reinicia **después** de que la vuelta fijó la colección, y
    /// en la misma ruta sirve otra, vacía. `moved` se calculó con la identidad
    /// de antes, así que la clave «falta» y la cuenta llega a rehacerse: sin
    /// volver a identificar la colección antes de borrar, la base buena se iba.
    /// Tiene que quedar intacta, no disponible y sin clave nueva; y en la vuelta
    /// siguiente la colección nueva no es la anotada, y la base sigue igual.
    #[tokio::test]
    async fn un_llavero_que_cambia_de_coleccion_a_mitad_de_la_vuelta_no_rehace_la_base() {
        let f = Fixture::new("coleccion-a-mitad");
        f.list(listing(&["cuenta"])).await;
        let key = f.key("cuenta").unwrap();
        let keys_before = f.keys.state().keys.clone();
        f.keys.state().locked = true;
        f.manager.refresh().await;
        let stored_before = f.keys.state().stored.len();

        {
            let mut state = f.keys.state();
            state.locked = false;
            state.replace_after_pin = Some("coleccion-b".into());
        }
        f.manager.refresh().await;

        assert_eq!(f.state("cuenta").await, StoreState::Unavailable);
        assert_eq!(
            f.manager.status().await.accounts[0].detail,
            StoreError::CollectionChanged.to_string()
        );
        assert_eq!(
            f.keys.state().stored.len(),
            stored_before,
            "no se tenía que guardar ninguna clave en la colección nueva"
        );
        assert!(
            Store::open(&f.paths("cuenta"), &key).is_ok(),
            "la base buena se tenía que quedar"
        );
        assert!(
            log_lines_with(&f, "cuenta", &key).is_empty(),
            "no se rehízo"
        );
        assert_eq!(
            f.settings()
                .key_collections
                .get("cuenta")
                .map(String::as_str),
            Some("coleccion-a"),
            "la colección anotada sigue siendo la de la clave"
        );

        // La vuelta siguiente fija la nueva y ve que no es la anotada.
        f.manager.refresh().await;
        assert_eq!(f.state("cuenta").await, StoreState::Unavailable);
        assert!(Store::open(&f.paths("cuenta"), &key).is_ok());

        // Y al volver la de antes, abre como estaba.
        {
            let mut state = f.keys.state();
            state.collection = "coleccion-a".into();
            state.keys = keys_before;
        }
        f.manager.refresh().await;
        assert_eq!(f.state("cuenta").await, StoreState::Open);
        assert!(log_lines(&f, "cuenta").is_empty());
    }

    /// El mismo reinicio, pero después de la primera comprobación: entre la
    /// segunda búsqueda y el guardado de la clave nueva, que queda en la
    /// colección nueva y se relee bien. Lo que salva a la base es la
    /// comprobación de justo antes de borrar.
    #[tokio::test]
    async fn un_llavero_que_cambia_de_coleccion_al_guardar_la_clave_nueva_no_rehace_la_base() {
        let f = Fixture::new("coleccion-al-guardar");
        f.list(listing(&["cuenta"])).await;
        let key = f.key("cuenta").unwrap();
        f.keys.state().locked = true;
        f.manager.refresh().await;

        {
            let mut state = f.keys.state();
            state.locked = false;
            // La clave no está en la colección de siempre: fila 4.
            state.keys.clear();
            state.replace_before_store = Some("coleccion-b".into());
        }
        f.manager.refresh().await;

        assert_eq!(f.state("cuenta").await, StoreState::Unavailable);
        assert!(
            Store::open(&f.paths("cuenta"), &key).is_ok(),
            "la base buena se tenía que quedar"
        );
        assert!(
            log_lines_with(&f, "cuenta", &key).is_empty(),
            "no se rehízo"
        );
        assert_eq!(
            f.settings()
                .key_collections
                .get("cuenta")
                .map(String::as_str),
            Some("coleccion-a")
        );
    }

    /// **La colección que cambia al crear una base nueva** (fila 2, sin base
    /// previa): la clave nueva queda en la colección nueva. Anotar la del
    /// principio de la vuelta ataba la base a la colección vieja, y después de
    /// reiniciar quedaba `unavailable` por `CollectionChanged` hasta vaciarla
    /// (lo que dejó anotado el #53). Ahora no se anota; la vuelta siguiente
    /// adopta la nueva, y un reinicio antes de eso abre la misma base, sin
    /// rehacer ni borrar nada.
    #[tokio::test]
    async fn la_coleccion_que_cambia_al_crear_la_base_no_la_ata_a_la_vieja() {
        let f = Fixture::new("coleccion-al-crear");
        f.keys.state().replace_before_store = Some("coleccion-b".into());
        f.list(listing(&["cuenta"])).await;
        assert_eq!(f.state("cuenta").await, StoreState::Open);
        let key = f.key("cuenta").unwrap();
        assert_ne!(
            f.settings()
                .key_collections
                .get("cuenta")
                .map(String::as_str),
            Some("coleccion-a"),
            "se anotó la colección donde la clave no está"
        );

        // Un reinicio antes de la vuelta siguiente: la misma base, abierta.
        let restarted = StoreManager::new(f.keys.clone(), Ok(f.locations()));
        restarted
            .accounts_listed(listing(&["cuenta"]), Instant::now())
            .await;
        let state = restarted.status().await.accounts[0].state;
        assert_eq!(state, StoreState::Open, "la base quedó atada a la vieja");
        assert!(
            log_lines_with(&f, "cuenta", &key).is_empty(),
            "no se rehízo"
        );

        // Y la vuelta siguiente del que no se reinició la adopta.
        f.manager.refresh().await;
        assert_eq!(
            f.settings()
                .key_collections
                .get("cuenta")
                .map(String::as_str),
            Some("coleccion-b")
        );
        assert!(Store::open(&f.paths("cuenta"), &key).is_ok());
    }

    /// Una base abierta sin colección anotada no adopta una colección donde su
    /// clave no está, ni una donde hay otra clave para la cuenta.
    #[tokio::test]
    async fn una_base_abierta_no_adopta_una_coleccion_con_otra_clave() {
        let f = Fixture::new("coleccion-no-adopta");
        f.keys.state().replace_before_store = Some("coleccion-b".into());
        f.list(listing(&["cuenta"])).await;
        {
            let mut state = f.keys.state();
            state.collection = "coleccion-c".into();
            state.keys.insert("cuenta".into(), "c".repeat(64));
        }
        f.manager.refresh().await;
        assert!(!f.settings().key_collections.contains_key("cuenta"));
        assert!(f.manager.is_open("cuenta").await, "la base sigue abierta");
        assert!(f.keys.state().deleted.is_empty(), "no se borró nada");
    }

    /// Vaciar es la salida cuando la colección cambió a propósito: la base
    /// vuelve, vacía, con una clave en la colección nueva.
    #[tokio::test]
    async fn vaciar_con_la_coleccion_cambiada_la_rehace_en_la_nueva() {
        let f = Fixture::new("coleccion-vaciar");
        f.list(listing(&["cuenta"])).await;
        f.keys.state().locked = true;
        f.manager.refresh().await;
        {
            let mut state = f.keys.state();
            state.locked = false;
            state.collection = "coleccion-b".into();
            state.keys.clear();
        }
        f.manager.refresh().await;
        assert_eq!(f.state("cuenta").await, StoreState::Unavailable);

        f.manager.clear("cuenta").await.unwrap();
        assert_eq!(f.state("cuenta").await, StoreState::Open);
        assert_eq!(
            f.settings()
                .key_collections
                .get("cuenta")
                .map(String::as_str),
            Some("coleccion-b")
        );
    }

    /// Una base de antes de anotar colecciones adopta la de la vuelta en que
    /// su clave la abre, y desde ahí queda protegida.
    #[tokio::test]
    async fn una_base_sin_coleccion_anotada_adopta_la_de_la_vuelta() {
        let f = Fixture::new("coleccion-adopta");
        f.list(listing(&["cuenta"])).await;
        let mut settings = f.settings();
        settings.key_collections.clear();
        settings.save(&f.locations().settings).unwrap();

        f.keys.state().locked = true;
        f.manager.refresh().await;
        f.keys.state().locked = false;
        f.manager.refresh().await;

        assert_eq!(f.state("cuenta").await, StoreState::Open);
        assert_eq!(
            f.settings()
                .key_collections
                .get("cuenta")
                .map(String::as_str),
            Some("coleccion-a")
        );
    }

    /// Si el llavero se bloquea entre la búsqueda y la creación, el vacío de la
    /// búsqueda no vale: ni clave ni base, y la que había queda como estaba.
    #[tokio::test]
    async fn un_bloqueo_a_mitad_de_camino_no_genera_ni_borra() {
        let f = Fixture::new("carrera");
        drop(Store::create(&f.paths("cuenta"), &fixed_key(b'a')).unwrap());
        let before = std::fs::read(&f.paths("cuenta").db).unwrap();
        f.keys.state().lock_after_find = true;

        f.list(listing(&["cuenta"])).await;

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

        f.list(listing(&["cuenta"])).await;

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

        f.list(listing(&["cuenta"])).await;

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
        f.list(listing(&["cuenta"])).await;
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
        manager
            .accounts_listed(listing(&["cuenta"]), Instant::now())
            .await;
        let status = manager.status().await;
        assert_eq!(status.accounts[0].state, StoreState::Unavailable);
        assert!(keys.state().stored.is_empty());
        assert!(manager.set_enabled("cuenta", false).await.is_err());
    }

    // ── Las cuentas que se van ──────────────────────────────────────────────

    /// Un `ListAccounts` que falló no dice que la persona no tenga cuentas,
    /// ni una vez ni varias separadas por una vuelta.
    #[tokio::test]
    async fn si_list_accounts_falla_no_se_borra_nada() {
        let f = Fixture::new("falla");
        f.list(listing(&["a", "b"])).await;
        assert!(f.paths("a").db_exists().unwrap() && f.paths("b").db_exists().unwrap());

        assert!(!f.list(AccountListing::Failed).await);
        assert!(!f.list_after_a_round(AccountListing::Failed).await);

        assert!(f.paths("a").db_exists().unwrap());
        assert!(f.paths("b").db_exists().unwrap());
        assert!(f.keys.state().deleted.is_empty());
    }

    /// Bien respondido y confirmado, se van sólo las bases de las cuentas que
    /// no están. Una que pide reautenticarse, o que ya no tiene nada que
    /// guardar, sigue siendo una cuenta y conserva la suya. La clave se borra
    /// antes que los archivos.
    #[tokio::test]
    async fn si_list_accounts_responde_se_borran_solo_las_cuentas_que_no_estan() {
        let f = Fixture::new("prune");
        f.list(listing(&["a", "b", "c"])).await;
        // Algo que no puso este servicio: no se toca.
        std::fs::create_dir_all(f.locations().stores.join("no.es.cuenta")).unwrap();

        let still_accounts = || {
            AccountListing::Listed(vec![
                account("a", &["email"]),
                // Pide reautenticarse: para el servicio de cuentas sigue ahí.
                account("b", &["email"]),
                // Ya no tiene correo, calendario ni contactos, pero existe.
                account("c", &["files"]),
                account("d", &["contacts"]),
            ])
        };
        f.list(still_accounts()).await;
        f.list_after_a_round(still_accounts()).await;
        assert!(f.paths("a").db_exists().unwrap());
        assert!(f.paths("b").db_exists().unwrap());
        assert!(f.paths("c").db_exists().unwrap());
        assert!(f.paths("d").db_exists().unwrap());

        f.list_after_a_round(listing(&["a", "d"])).await;
        f.list_after_a_round(listing(&["a", "d"])).await;

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

        // Confirmado: dos listados vacíos separados por una vuelta.
        let t0 = Instant::now();
        manager.accounts_listed(listing(&[]), t0).await;
        manager
            .accounts_listed(listing(&[]), t0 + PRUNE_CONFIRMATION)
            .await;

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

        // Confirmado: dos listados vacíos separados por una vuelta.
        let t0 = Instant::now();
        manager.accounts_listed(listing(&[]), t0).await;
        manager
            .accounts_listed(listing(&[]), t0 + PRUNE_CONFIRMATION)
            .await;

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

        f.list(listing(&[])).await;
        f.list_after_a_round(listing(&[])).await;

        assert!(stores.join("Fotos/importante.txt").exists());
        assert!(stores.join("Trabajo/sub").exists());
        assert!(stores.join("Trabajo/store.db").exists());
        assert!(!stores.join("vacia").exists());
        assert!(!stores.join("restos").exists());
    }

    /// Una cuenta quitada con el llavero bloqueado deja su clave: se barre en
    /// el primer desbloqueo. Los archivos se van con la confirmación aunque
    /// el llavero siga bloqueado: borrarlos no necesita la clave.
    #[tokio::test]
    async fn la_clave_de_una_cuenta_quitada_se_barre_al_desbloquear() {
        let f = Fixture::new("huerfana");
        f.list(listing(&["a", "b"])).await;

        f.keys.state().locked = true;
        f.list(listing(&["a"])).await;
        assert!(
            f.paths("b").db_exists().unwrap(),
            "falta una vez: se espera"
        );
        f.list_after_a_round(listing(&["a"])).await;
        assert!(!f.paths("b").dir.exists(), "los archivos se van igual");
        assert!(f.keys.state().keys.contains_key("b"), "la clave espera");

        f.keys.state().locked = false;
        f.manager.refresh().await;
        assert!(!f.keys.state().keys.contains_key("b"));
        assert!(f.keys.state().keys.contains_key("a"));
    }

    // ── La confirmación de que una cuenta se fue ────────────────────────────

    /// Lo que se ve de una cuenta en el disco, en el llavero y en
    /// `stores.json`, para comparar antes y después.
    fn footprint(f: &Fixture, account_id: &str) -> (bool, bool, bool) {
        (
            f.paths(account_id).db_exists().unwrap(),
            f.keys.state().keys.contains_key(account_id),
            f.settings().accounts.contains_key(account_id),
        )
    }

    #[test]
    fn la_confirmacion_es_una_vuelta_del_bucle_y_nunca_cero() {
        assert_eq!(PRUNE_CONFIRMATION, crate::POLL_INTERVAL);
        // Con cero, un solo listado se confirmaría a sí mismo.
        assert!(PRUNE_CONFIRMATION > Duration::ZERO);
    }

    /// El caso que motivó todo: el servicio de cuentas contesta bien y vacío
    /// —le falta `accounts.json`— una vez. No se va nada: ni archivos, ni
    /// claves, ni lo decidido en `stores.json`. Tampoco cuando el llavero avisa
    /// después y se vuelve a pasar la tabla sin un listado nuevo.
    #[tokio::test]
    async fn un_listado_vacio_aislado_no_borra_nada() {
        let f = Fixture::new("vacio-aislado");
        f.list(listing(&["a", "b"])).await;
        f.manager.set_enabled("a", true).await.unwrap();
        assert_eq!(footprint(&f, "a"), (true, true, true));

        f.list(listing(&[])).await;
        f.advance(PRUNE_CONFIRMATION * 3);
        f.manager.refresh().await;

        assert_eq!(footprint(&f, "a"), (true, true, true));
        assert_eq!(footprint(&f, "b"), (true, true, false));
        assert!(
            f.keys.state().deleted.is_empty(),
            "no se borró ninguna clave"
        );

        // Y cuando el servicio se recupera, todo sigue donde estaba.
        f.list(listing(&["a", "b"])).await;
        assert_eq!(f.state("a").await, StoreState::Open);
        assert_eq!(f.state("b").await, StoreState::Open);
        assert_eq!(f.keys.state().stored.len(), 2, "no se generó otra clave");
    }

    /// Dos listados vacíos en el mismo instante —una ráfaga de
    /// `AccountsChanged`— salen del mismo estado del servicio, y tampoco
    /// alcanzan. Ni un tercero apenas antes de cumplirse la vuelta.
    #[tokio::test]
    async fn dos_listados_vacios_seguidos_en_menos_de_una_vuelta_no_borran_nada() {
        let f = Fixture::new("vacios-rafaga");
        f.list(listing(&["a"])).await;

        f.list(listing(&[])).await;
        f.list(listing(&[])).await;
        f.advance(PRUNE_CONFIRMATION - Duration::from_secs(1));
        f.list(listing(&[])).await;

        assert_eq!(footprint(&f, "a"), (true, true, false));
        assert!(f.keys.state().deleted.is_empty());
    }

    /// La desconexión de verdad sí se lleva la base: la cuenta falta en dos
    /// listados buenos separados por una vuelta, y se van los archivos y la
    /// clave. La que sigue en la lista no se toca.
    #[tokio::test]
    async fn la_desconexion_real_se_lleva_la_base_y_la_clave() {
        let f = Fixture::new("desconexion");
        f.list(listing(&["a", "b"])).await;
        f.manager.set_enabled("b", true).await.unwrap();

        f.list(listing(&["a"])).await;
        assert_eq!(footprint(&f, "b"), (true, true, true), "falta una vez");

        f.list_after_a_round(listing(&["a"])).await;
        assert!(!f.paths("b").dir.exists());
        assert!(!f.keys.state().keys.contains_key("b"));
        assert!(!f.settings().accounts.contains_key("b"));
        assert_eq!(footprint(&f, "a"), (true, true, false));
        assert_eq!(f.state("a").await, StoreState::Open);
    }

    /// Una cuenta que falta una vez y reaparece conserva su base, y la
    /// sospecha se olvida: la ausencia siguiente vuelve a empezar la cuenta, y
    /// no se confirma con la vuelta medida desde la primera.
    #[tokio::test]
    async fn una_cuenta_que_falta_y_reaparece_conserva_la_base_y_se_olvida_la_sospecha() {
        let f = Fixture::new("reaparece");
        f.list(listing(&["a", "b"])).await;
        let key = f.key("b").unwrap();

        // Falta en t0 y reaparece una vuelta después.
        f.list(listing(&["a"])).await;
        f.list_after_a_round(listing(&["a", "b"])).await;
        assert_eq!(f.state("b").await, StoreState::Open);
        assert_eq!(f.key("b").unwrap(), key, "la misma clave");

        // Vuelve a faltar un segundo después: la sospecha empieza de nuevo acá.
        f.advance(Duration::from_secs(1));
        f.list(listing(&["a"])).await;
        // Dos vueltas desde la primera ausencia, pero menos de una desde ésta.
        f.advance(PRUNE_CONFIRMATION - Duration::from_secs(1));
        f.list(listing(&["a"])).await;
        assert!(
            f.paths("b").db_exists().unwrap(),
            "la ausencia vieja no cuenta"
        );
        assert!(f.keys.state().keys.contains_key("b"));

        // Una vuelta entera desde la segunda ausencia, sí.
        f.advance(Duration::from_secs(1));
        f.list(listing(&["a"])).await;
        assert!(!f.paths("b").dir.exists());
    }

    /// Un listado fallido en el medio no confirma —aunque llegue una vuelta
    /// después— ni reinicia la cuenta: el siguiente bueno confirma midiendo
    /// desde la primera ausencia.
    #[tokio::test]
    async fn un_listado_fallido_en_el_medio_ni_confirma_ni_reinicia() {
        let f = Fixture::new("fallido-en-el-medio");
        f.list(listing(&["a", "b"])).await;

        f.list(listing(&["a"])).await;
        f.list_after_a_round(AccountListing::Failed).await;
        assert_eq!(footprint(&f, "b"), (true, true, false), "no confirma");

        // En el mismo instante que el fallido: si lo hubiera reiniciado,
        // faltaría otra vuelta.
        f.list(listing(&["a"])).await;
        assert!(!f.paths("b").dir.exists());
        assert!(!f.keys.state().keys.contains_key("b"));
    }

    /// Cada listado se atiende en una tarea propia, y dos pueden tomar la
    /// cerradura al revés. Uno más viejo que el último no cuenta: ni para
    /// empezar una ausencia ni para confirmarla.
    #[tokio::test]
    async fn un_listado_mas_viejo_que_el_ultimo_no_cuenta() {
        let f = Fixture::new("listado-viejo");
        let start = *f.clock.lock().unwrap();
        f.list(listing(&["a", "b"])).await;
        f.list_after_a_round(listing(&["a", "b"])).await;

        assert!(
            !f.manager.accounts_listed(listing(&["a"]), start).await,
            "un listado viejo no cambia nada"
        );
        f.list_after_a_round(listing(&["a"])).await;

        assert!(
            f.paths("b").db_exists().unwrap(),
            "la ausencia empieza recién en el último listado"
        );
        assert!(f.manager.set_enabled("a", true).await.is_ok());
    }

    /// La sospecha vive en memoria: un sync que arranca no sabe desde cuándo
    /// falta nada, y vuelve a hacer falta la confirmación entera.
    #[tokio::test]
    async fn despues_de_reiniciar_hay_que_volver_a_confirmar() {
        let f = Fixture::new("reinicio");
        f.list(listing(&["a", "b"])).await;
        f.list(listing(&["a"])).await;

        let restarted = StoreManager::new(f.keys.clone(), Ok(f.locations()));
        f.advance(PRUNE_CONFIRMATION);
        let now = *f.clock.lock().unwrap();
        restarted.accounts_listed(listing(&["a"]), now).await;
        assert_eq!(footprint(&f, "b"), (true, true, false));

        restarted
            .accounts_listed(listing(&["a"]), now + PRUNE_CONFIRMATION)
            .await;
        assert!(!f.paths("b").dir.exists());
    }

    /// Una cuenta apagada queda en `pending_key_deletions` hasta tener clave
    /// nueva. Si en cambio se quita, sale de ahí —y de lo decidido para ella—
    /// con la confirmación y el llavero desbloqueado, recién después de
    /// comprobar que su clave ya no está.
    #[tokio::test]
    async fn la_clave_pendiente_de_una_cuenta_quitada_se_olvida_al_confirmar() {
        let f = Fixture::new("pendiente-quitada");
        f.list(listing(&["a", "b"])).await;
        f.manager.set_enabled("b", false).await.unwrap();
        assert!(f.settings().pending_key_deletions.contains("b"));

        f.list(listing(&["a"])).await;
        assert!(
            f.settings().pending_key_deletions.contains("b"),
            "falta una vez: se queda"
        );
        assert!(f.settings().accounts.contains_key("b"));

        f.list_after_a_round(listing(&["a"])).await;
        let settings = f.settings();
        assert!(settings.pending_key_deletions.is_empty());
        assert!(!settings.accounts.contains_key("b"));
        assert!(!f.keys.state().keys.contains_key("b"));
    }

    /// Con el llavero bloqueado no se saca nada de `pending_key_deletions`,
    /// aunque la ausencia esté confirmada: sin poder releer, «la clave no está»
    /// no se sabe. Sale en el primer desbloqueo.
    #[tokio::test]
    async fn con_el_llavero_bloqueado_la_clave_pendiente_no_se_olvida() {
        let f = Fixture::new("pendiente-bloqueado");
        f.list(listing(&["a", "b"])).await;
        f.keys.state().locked = true;
        f.manager.clear("b").await.unwrap();
        assert!(f.settings().pending_key_deletions.contains("b"));

        f.list(listing(&["a"])).await;
        f.list_after_a_round(listing(&["a"])).await;
        f.manager.refresh().await;
        assert!(
            f.settings().pending_key_deletions.contains("b"),
            "con el llavero bloqueado se queda"
        );
        assert!(f.keys.state().keys.contains_key("b"));

        f.keys.state().locked = false;
        f.manager.refresh().await;
        assert!(f.settings().pending_key_deletions.is_empty());
        assert!(!f.keys.state().keys.contains_key("b"));
    }

    /// Un `Delete` que contesta bien y no borra no alcanza: la clave sigue
    /// apareciendo al volver a buscarla, y la cuenta sigue anotada.
    #[tokio::test]
    async fn una_clave_pendiente_que_no_se_va_no_se_olvida() {
        let f = Fixture::new("pendiente-mentiroso");
        f.list(listing(&["a", "b"])).await;
        f.keys.state().lose_deletes = true;
        f.manager.set_enabled("b", false).await.unwrap();

        f.list(listing(&["a"])).await;
        f.list_after_a_round(listing(&["a"])).await;

        assert!(f.keys.state().keys.contains_key("b"));
        assert!(f.settings().pending_key_deletions.contains("b"));
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
        f.list(listing(&["cuenta"])).await;

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
        f.list(listing(&["cuenta"])).await;
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
        f.list(listing(&["cuenta"])).await;
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
        f.list(listing(&["cuenta"])).await;
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
        f.list(listing(&["cuenta"])).await;
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
        f.list(listing(&["cuenta"])).await;
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
        f.list(listing(&["cuenta"])).await;
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

    /// El temporal de `stores.json` no sigue un enlace: el que estaba plantado
    /// con el nombre fijo de antes queda como estaba, y lo apuntado también.
    #[tokio::test]
    async fn el_temporal_de_stores_json_no_sigue_enlaces() {
        let f = Fixture::new("temporal-enlace");
        f.list(listing(&["cuenta"])).await;
        let victim = f.temp.0.join("victima.txt");
        std::fs::write(&victim, "contenido de la persona").unwrap();
        let dir = f.locations().settings.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(&victim, dir.join(".stores.json.tmp")).unwrap();

        f.manager.set_enabled("cuenta", false).await.unwrap();

        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "contenido de la persona"
        );
        assert!(!f.settings().is_enabled("cuenta"));
    }

    /// Crear el temporal no pisa nada: ni lo que apunta un enlace con ese
    /// nombre ni un archivo que ya estaba.
    #[test]
    fn el_temporal_se_crea_nuevo_y_sin_seguir_enlaces() {
        let temp = TempDir::new("temporal-nuevo");
        let victim = temp.0.join("victima.txt");
        std::fs::write(&victim, "de la persona").unwrap();
        let link = temp.0.join("enlace");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(write_new_private(&link, b"{}").is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "de la persona");

        let dangling = temp.0.join("colgado");
        std::os::unix::fs::symlink(temp.0.join("no-existe"), &dangling).unwrap();
        assert!(write_new_private(&dangling, b"{}").is_err());
        assert!(!temp.0.join("no-existe").exists());

        assert!(write_new_private(&victim, b"{}").is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "de la persona");

        let fresh = temp.0.join("nuevo");
        write_new_private(&fresh, b"{}").unwrap();
        let mode = std::fs::metadata(&fresh).unwrap();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode.permissions()) & 0o777,
            0o600
        );
        assert_ne!(temporary_name(), temporary_name());
    }

    /// Si guardar falla después de crear el temporal, el temporal no queda.
    #[test]
    fn si_guardar_falla_no_queda_el_temporal() {
        let temp = TempDir::new("temporal-fallido");
        let path = temp.0.join("config/stores.json");
        // `stores.json` es una carpeta con algo adentro: el `rename` falla.
        std::fs::create_dir_all(path.join("algo")).unwrap();

        assert!(StoreSettings::default().save(&path).is_err());

        let leftovers: Vec<_> = std::fs::read_dir(temp.0.join("config"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .filter(|name| name.to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "quedaron temporales: {leftovers:?}");
    }

    /// Un `stores.json` que no se entiende no enciende ni borra nada.
    #[tokio::test]
    async fn un_stores_json_ilegible_no_enciende_ni_borra() {
        let f = Fixture::new("ilegible");
        f.list(listing(&["cuenta"])).await;
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

    /// Apagar y vaciar sólo aceptan cuentas del último `ListAccounts` bueno.
    /// Con identificadores inventados, `stores.json` y lo que se guarda en
    /// memoria crecían sin tope desde el bus. Y antes del primer listado bueno
    /// no hay cuentas conocidas: se rechaza todo.
    #[tokio::test]
    async fn apagar_o_vaciar_una_cuenta_que_no_esta_se_rechaza() {
        let f = Fixture::new("desconocidas");
        assert!(matches!(
            f.manager.set_enabled("cuenta", false).await,
            Err(StoreError::UnknownAccount(_))
        ));
        assert!(matches!(
            f.manager.clear("cuenta").await,
            Err(StoreError::UnknownAccount(_))
        ));
        assert!(!f.locations().settings.exists());

        // Un listado que falló tampoco da cuentas conocidas.
        f.list(AccountListing::Failed).await;
        assert!(matches!(
            f.manager.set_enabled("cuenta", false).await,
            Err(StoreError::UnknownAccount(_))
        ));

        f.list(listing(&["cuenta"])).await;
        for i in 0..300 {
            let invented = format!("inventada{i}");
            assert!(matches!(
                f.manager.set_enabled(&invented, false).await,
                Err(StoreError::UnknownAccount(_))
            ));
            assert!(matches!(
                f.manager.clear(&invented).await,
                Err(StoreError::UnknownAccount(_))
            ));
        }
        let settings = StoreSettings::load(&f.locations().settings).unwrap();
        assert!(settings.accounts.is_empty());
        assert!(settings.pending_key_deletions.is_empty());
        assert_eq!(f.manager.inner.lock().await.entries.len(), 1);

        // Una cuenta listada sí, aunque no tenga nada que guardar.
        f.list(AccountListing::Listed(vec![
            account("cuenta", &["email"]),
            account("archivos", &["files"]),
        ]))
        .await;
        f.manager.set_enabled("cuenta", false).await.unwrap();
        f.manager.set_enabled("archivos", false).await.unwrap();
        assert_eq!(f.settings().accounts.len(), 2);
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
        f.list(listing(&["b", "a"])).await;

        let status = f.manager.status().await;
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["keyring"], "unlocked");
        assert_eq!(json["accounts"][0]["account_id"], "a");
        assert_eq!(json["accounts"][0]["state"], "open");
        assert!(json["accounts"][0]["size_bytes"].as_u64().unwrap() > 0);
        assert_eq!(json["accounts"][1]["account_id"], "b");
    }

    // ── Las áreas ───────────────────────────────────────────────────────────

    fn with_contacts(ids: &[&str]) -> AccountListing {
        AccountListing::Listed(
            ids.iter()
                .map(|id| account(id, &["email", "contacts"]))
                .collect(),
        )
    }

    /// El área de contactos se enciende la primera vez que alguien la pide, y
    /// queda en `stores.json`: después de reiniciar sigue encendida.
    #[tokio::test]
    async fn el_area_de_contactos_se_enciende_al_pedirla_y_sigue_despues_de_reiniciar() {
        let f = Fixture::new("area-encendida");
        f.list(with_contacts(&["cuenta"])).await;
        assert!(
            f.manager.area_targets(CONTACTS_AREA).await.is_empty(),
            "nadie la pidió"
        );
        let status = serde_json::to_value(f.manager.status().await).unwrap();
        assert_eq!(status["accounts"][0]["contacts"]["state"], "off");

        assert!(f
            .manager
            .activate_area(CONTACTS_AREA, "cuenta", Consent::Granted)
            .await
            .unwrap());
        assert_eq!(f.manager.area_targets(CONTACTS_AREA).await, vec!["cuenta"]);
        assert!(f.settings().is_active("cuenta", CONTACTS_AREA));
        let status = serde_json::to_value(f.manager.status().await).unwrap();
        assert_eq!(status["accounts"][0]["contacts"]["state"], "pending");

        // Otro proceso, la misma configuración.
        let again = StoreManager::new(f.keys.clone(), Ok(f.locations()));
        again
            .accounts_listed(with_contacts(&["cuenta"]), Instant::now())
            .await;
        assert_eq!(again.area_targets(CONTACTS_AREA).await, vec!["cuenta"]);
    }

    /// **Cada área por su lado**: encender los contactos no enciende el
    /// calendario, cada una tiene sus cuentas y su estado, y una cuenta con
    /// las dos las muestra a las dos en `GetStatus`.
    #[tokio::test]
    async fn cada_area_se_enciende_por_su_lado() {
        let f = Fixture::new("areas-por-su-lado");
        f.list(AccountListing::Listed(vec![
            account("ambas", &["contacts", "calendar"]),
            account("agenda", &["calendar"]),
        ]))
        .await;
        f.manager
            .activate_area(CONTACTS_AREA, "ambas", Consent::Granted)
            .await
            .unwrap();
        assert_eq!(f.manager.area_targets(CONTACTS_AREA).await, vec!["ambas"]);
        assert!(f.manager.area_targets(CALENDAR_AREA).await.is_empty());
        assert!(!f.settings().is_active("ambas", CALENDAR_AREA));

        assert!(f
            .manager
            .activate_area(CALENDAR_AREA, "agenda", Consent::Granted)
            .await
            .unwrap());
        assert!(!f
            .manager
            .activate_area(CONTACTS_AREA, "agenda", Consent::Granted)
            .await
            .unwrap());
        assert_eq!(f.manager.area_targets(CALENDAR_AREA).await, vec!["agenda"]);
        f.manager
            .set_area_status(CALENDAR_AREA, "agenda", AreaState::Synced, "")
            .await;

        let status = serde_json::to_value(f.manager.status().await).unwrap();
        let by_id = |id: &str| {
            status["accounts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|a| a["account_id"] == id)
                .unwrap()
                .clone()
        };
        assert_eq!(by_id("ambas")["contacts"]["state"], "pending");
        assert_eq!(by_id("ambas")["calendar"]["state"], "off");
        assert_eq!(by_id("agenda")["calendar"]["state"], "synced");
        assert!(by_id("agenda").get("contacts").is_none());
        assert!(f.manager.prepare_for_sync(CALENDAR_AREA, "agenda").await);
        assert!(!f.manager.prepare_for_sync(CONTACTS_AREA, "agenda").await);
    }

    /// Sin permiso, un área apagada no se enciende aunque la cuenta tenga
    /// contactos que sincronizar; una que ya estaba encendida sigue, y dice
    /// que hay contactos.
    #[tokio::test]
    async fn encender_sin_permiso_no_enciende_aunque_la_cuenta_cambie() {
        let f = Fixture::new("area-sin-permiso");
        let mut stale = account("cuenta", &["contacts"]);
        stale.needs_reauth = true;
        f.list(AccountListing::Listed(vec![stale])).await;
        // La cuenta deja de pedir reautenticarse: ahora sí se encendería.
        f.list(with_contacts(&["cuenta"])).await;

        assert!(!f
            .manager
            .activate_area(CONTACTS_AREA, "cuenta", Consent::NotAsked)
            .await
            .unwrap());
        assert!(!f.settings().is_active("cuenta", CONTACTS_AREA));
        assert!(f.manager.area_targets(CONTACTS_AREA).await.is_empty());

        assert!(f
            .manager
            .activate_area(CONTACTS_AREA, "cuenta", Consent::Granted)
            .await
            .unwrap());
        assert!(
            f.manager
                .activate_area(CONTACTS_AREA, "cuenta", Consent::NotAsked)
                .await
                .unwrap(),
            "encendida, sigue encendida sin volver a preguntar"
        );
    }

    /// Una cuenta sin contactos no enciende nada ni es un error, y en el estado
    /// no aparece el área.
    #[tokio::test]
    async fn una_cuenta_sin_contactos_no_enciende_nada() {
        let f = Fixture::new("area-sin-contactos");
        f.list(listing(&["cuenta"])).await;
        assert!(!f
            .manager
            .activate_area(CONTACTS_AREA, "cuenta", Consent::Granted)
            .await
            .unwrap());
        assert!(!f.settings().is_active("cuenta", CONTACTS_AREA));
        let status = serde_json::to_value(f.manager.status().await).unwrap();
        assert!(status["accounts"][0].get("contacts").is_none());
        assert!(f
            .manager
            .activate_area(CONTACTS_AREA, "otra", Consent::Granted)
            .await
            .is_err());
    }

    /// Una cuenta que pide reautenticarse conserva su base, pero sus contactos
    /// no se sincronizan: pedirle el token daría error en cada vuelta.
    #[tokio::test]
    async fn una_cuenta_que_pide_reautenticarse_no_sincroniza_contactos() {
        let f = Fixture::new("area-reautenticar");
        f.list(with_contacts(&["cuenta"])).await;
        f.manager
            .activate_area(CONTACTS_AREA, "cuenta", Consent::Granted)
            .await
            .unwrap();
        let mut stale = account("cuenta", &["contacts"]);
        stale.needs_reauth = true;
        f.list(AccountListing::Listed(vec![stale])).await;

        assert!(f.manager.area_targets(CONTACTS_AREA).await.is_empty());
        assert!(!f.manager.prepare_for_sync(CONTACTS_AREA, "cuenta").await);
        assert!(
            f.paths("cuenta").db_exists().unwrap(),
            "la base se conserva"
        );
    }

    /// Apagar la base no olvida que alguien pidió los contactos, pero mientras
    /// está apagada no hay nada que sincronizar.
    #[tokio::test]
    async fn apagar_la_base_no_olvida_el_area() {
        let f = Fixture::new("area-apagada");
        f.list(with_contacts(&["cuenta"])).await;
        f.manager
            .activate_area(CONTACTS_AREA, "cuenta", Consent::Granted)
            .await
            .unwrap();

        f.manager.set_enabled("cuenta", false).await.unwrap();
        assert!(f.settings().is_active("cuenta", CONTACTS_AREA));
        assert!(f.manager.area_targets(CONTACTS_AREA).await.is_empty());
        assert!(!f.manager.prepare_for_sync(CONTACTS_AREA, "cuenta").await);

        f.manager.set_enabled("cuenta", true).await.unwrap();
        assert_eq!(f.manager.area_targets(CONTACTS_AREA).await, vec!["cuenta"]);
    }

    /// **Un solo camino para escribir, y con el llavero releído**: bloqueado,
    /// no se corre nada y la base se cierra.
    #[tokio::test]
    async fn con_el_llavero_bloqueado_no_se_llega_a_la_base() {
        let f = Fixture::new("area-escritor");
        f.list(with_contacts(&["cuenta"])).await;
        assert!(f.manager.prepare_for_sync(CONTACTS_AREA, "cuenta").await);
        assert!(f
            .manager
            .with_store("cuenta", |s| s.log(LogLevel::Warn, None, "hola"))
            .await
            .is_ok());

        f.keys.state().locked = true;
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&ran);
        let result = f
            .manager
            .with_store("cuenta", move |_| {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            })
            .await;
        assert_eq!(result, Err(StoreError::Key(KeyError::Locked)));
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!f.manager.is_open("cuenta").await, "la base se cerró");
        assert_eq!(f.state("cuenta").await, StoreState::Locked);
    }

    // ── Las lecturas ────────────────────────────────────────────────────────

    /// Leer no toma la cerradura del administrador ni espera a un lote: con un
    /// lote de escritura a medias —la transacción abierta y la cerradura
    /// tomada—, una lectura contesta enseguida con lo último confirmado.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn leer_no_espera_a_un_lote_de_escritura_largo() {
        let f = Arc::new(Fixture::new("leer-mientras-escribe"));
        f.list(listing(&["cuenta"])).await;

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let writer = {
            let f = Arc::clone(&f);
            tokio::spawn(async move {
                f.manager
                    .with_store("cuenta", move |store| {
                        let tx = store
                            .connection
                            .unchecked_transaction()
                            .map_err(super::super::classify)?;
                        tx.execute(
                            "INSERT INTO store_meta (key, value) VALUES ('a-medias', '1')",
                            [],
                        )
                        .map_err(super::super::classify)?;
                        let _ = started_tx.send(());
                        let _ = release_rx.recv_timeout(Duration::from_secs(10));
                        tx.commit().map_err(super::super::classify)
                    })
                    .await
            })
        };
        started_rx.await.unwrap();

        let count = |f: Arc<Fixture>| async move {
            f.manager
                .read("cuenta", |c| {
                    c.query_row(
                        "SELECT count(*) FROM store_meta WHERE key = 'a-medias'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(super::super::classify)
                })
                .await
        };
        let during = tokio::time::timeout(Duration::from_secs(5), count(Arc::clone(&f)))
            .await
            .expect("la lectura esperó al lote");
        assert_eq!(during, Ok(0), "lo que no se confirmó no se ve");

        release_tx.send(()).unwrap();
        writer.await.unwrap().unwrap();
        assert_eq!(count(Arc::clone(&f)).await, Ok(1));
    }

    /// Con el llavero bloqueado, leer no da nada: error claro, y los lectores
    /// y la base se cierran en el acto, sin esperar a la revisión.
    #[tokio::test]
    async fn leer_con_el_llavero_bloqueado_no_da_nada_y_cierra_todo() {
        let f = Fixture::new("leer-bloqueado");
        f.list(listing(&["cuenta"])).await;
        let pool = f.manager.reader_pool("cuenta").unwrap();
        assert_eq!(pool.open_connections(), 2);

        f.keys.state().locked = true;
        let read = f
            .manager
            .read("cuenta", |c| {
                c.query_row("SELECT count(*) FROM store_meta", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(super::super::classify)
            })
            .await;
        assert_eq!(read, Err(StoreError::Key(KeyError::Locked)));
        assert!(pool.is_closed());
        assert_eq!(pool.open_connections(), 0);
        assert!(!f.manager.is_open("cuenta").await);

        // Y al desbloquear, lectores nuevos.
        f.keys.state().locked = false;
        f.manager.refresh().await;
        let again = f.manager.reader_pool("cuenta").unwrap();
        assert!(!again.is_closed());
        assert!(!Arc::ptr_eq(&pool, &again));
    }

    /// Una base cerrada —bloqueo, apagado— no se puede leer, y lo que se
    /// cierra cierra también sus lectores.
    #[tokio::test]
    async fn apagar_la_base_cierra_sus_lectores() {
        let f = Fixture::new("leer-apagada");
        f.list(listing(&["cuenta"])).await;
        let pool = f.manager.reader_pool("cuenta").unwrap();
        f.manager.set_enabled("cuenta", false).await.unwrap();
        assert!(pool.is_closed());
        assert_eq!(
            f.manager.read("cuenta", |_| Ok(())).await,
            Err(StoreError::Missing)
        );
    }

    /// `with_store` anuncia lo que cambió al terminar cada lote: una vez por
    /// área aunque el lote haya cambiado varias cosas, y nada si no cambió
    /// nada.
    #[tokio::test]
    async fn cada_lote_se_anuncia_una_vez_y_el_que_no_cambia_nada_no() {
        let f = Fixture::new("anuncios");
        f.list(listing(&["cuenta"])).await;
        let mut changes = f.manager.subscribe_changes();

        f.manager
            .with_store("cuenta", |store| {
                let book = store
                    .upsert_address_books(&[("https://x/a/".into(), "A".into())])?
                    .remove(0);
                store.apply_contacts(
                    &book,
                    &[super::super::contacts::ContactOp::Upsert(
                        super::super::contacts::tests::row("https://x/a/1.vcf", "Ana", "a@x.com"),
                    )],
                    None,
                    u64::MAX,
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let change = changes.try_recv().unwrap();
        assert_eq!(change.area, CONTACTS_AREA);
        assert_eq!(change.account_id, "cuenta");
        assert!(
            changes.try_recv().is_err(),
            "una vez por lote, no por escritura"
        );

        f.manager
            .with_store("cuenta", |store| {
                store.upsert_address_books(&[("https://x/a/".into(), "A".into())])?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(changes.try_recv().is_err(), "sin cambios, sin aviso");
    }
}
