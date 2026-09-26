//! `ar.net.vasak.os.AccountsStore` — el almacén local, por D-Bus.
//!
//! Una interfaz aparte y no métodos nuevos en `AccountsSync`: lo que se lee del
//! almacén pide permiso por área, y `AccountsSync` no lo pide a propósito.
//! Mezclarlas obligaría a que cada método explique cuál de los dos regímenes le
//! toca.
//!
//! Vive en el mismo nombre de bus que el resto del servicio
//! (`ar.net.vasak.os.AccountsSync`), en `/ar/net/vasak/os/AccountsStore`.
//! Respuestas en JSON, como `AccountsSync`.
//!
//! ── Qué hay ─────────────────────────────────────────────────────────────────
//!
//! - **Lecturas de contactos**, con el permiso `store.contacts` de quien llama
//!   (ver `access.rs`): `ListAddressBooks`, `ListContacts`, `SearchContacts`,
//!   `GetContact`. Sin permiso contestan `AccessDenied` y **ningún dato**. La
//!   primera lectura de una cuenta **enciende** su área de contactos —después
//!   de que el permiso dijo que sí—, y desde ahí se sincroniza sola.
//! - **Estado**: `GetStatus` y la señal `StatusChanged`. Lo ve cualquiera de la
//!   sesión, recortado (ver [`visible_status`]).
//! - **Control**: `SetStoreEnabled`, `ClearStore`, `RequestSync`, con un límite
//!   por llamante ([`crate::access::CallerLimits`]). `RequestSync` que
//!   encendería el área de contactos pide además `store.contacts`.
//! - **La señal `Changed(area, account_id, generation)`**: un lote de la
//!   sincronización cambió lo guardado de un área. Dice **cuándo**, no
//!   **qué**; `generation` sólo crece, así que quien la recibe dos veces o
//!   fuera de orden sabe cuál es la última.
//!
//! **Las lecturas pueden tardar**: la primera de cada aplicación puede abrir un
//! diálogo de `vasak-permissions`, y la respuesta llega cuando la persona lo
//! cierra. Quien llama tiene que esperar con un tiempo largo —minutos, no los
//! 25 s por omisión de libdbus o GDBus— o su llamada vence antes.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use zbus::interface;
use zbus::message::Header;
use zbus::object_server::SignalContext;

use crate::access::{self, Access, CONTACTS_RESOURCE};
use crate::broker::{self, BrokerError};
use crate::contacts_sync::{BrokerCredentials, ContactsScheduler, ContactsSync};
use crate::dav::webdav::{HttpPolicy, Limits};
use crate::store::contacts_read::{self, Cursor, InvalidArgument};
use crate::store::key::{self, KeyError, KeySource, SecretServiceKeys};
use crate::store::lifecycle::{
    AccountListing, ListedAccount, Locations, Status, StoreManager, CONTACTS_AREA,
};
use crate::store::{paths, StoreError};

/// Dónde se publica la interfaz.
pub const PATH: &str = "/ar/net/vasak/os/AccountsStore";

/// Cuánto se espera para volver a escuchar al llavero, o al bus, si se cortó.
const RETRY: Duration = Duration::from_secs(15);

/// Cuánto se espera después de un aviso del llavero antes de pasar la tabla.
///
/// Junta en una sola vuelta los avisos que llegan de a varios —uno por
/// colección, o un desbloqueo seguido de otro cambio— y pone un techo a cuántas
/// veces por segundo el sync le vuelve a preguntar al llavero, aunque alguien
/// le mande señales sin parar.
const SETTLE: Duration = Duration::from_secs(1);

/// Cuántos `RequestSync` pueden esperar su vuelta. Uno de más se descarta: la
/// cuenta ya tiene uno en la fila, o la revisión de siempre la va a alcanzar.
const PENDING_REQUESTS: usize = 16;

/// El objeto de D-Bus.
pub struct StoreApi<K: KeySource> {
    manager: Arc<StoreManager<K>>,
    /// Por donde se le pide a la sincronización de contactos que atienda una
    /// cuenta ya.
    contacts: Option<mpsc::Sender<String>>,
    /// El permiso de quien llama, y el límite de los comandos.
    access: Arc<Access>,
}

#[interface(name = "ar.net.vasak.os.AccountsStore")]
impl<K: KeySource> StoreApi<K> {
    /// El estado del almacén, **recortado según quién pregunta**.
    ///
    /// Cualquiera de la sesión ve el estado del llavero y, por cuenta, en qué
    /// está su base (`locked`, `open`, `rebuilt`, `disabled`, `unavailable`) y
    /// en qué está su área de contactos (`off`, `pending`, `syncing`,
    /// `synced`, `unavailable`, `failed`): códigos fijos, nada más. El texto
    /// que explica cada uno, cuánto ocupa la base (`size_bytes`) y cuándo
    /// terminó bien la última vuelta (`last_synced_at`) los ve sólo quien tiene
    /// `store.contacts` concedido, y sólo en las cuentas con contactos. **No
    /// abre ningún diálogo**: mira la respuesta que quedó guardada de una
    /// lectura de los últimos 30 s; sin ella, se ve la parte pública. Ver
    /// [`visible_status`].
    async fn get_status(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<String> {
        let status = self.manager.status().await;
        let sender = sender_of(&header);
        let contacts_allowed =
            self.access.cached(sender.as_deref(), CONTACTS_RESOURCE) == Some(true);
        serde_json::to_string(&visible_status(&status, contacts_allowed))
            .map_err(|e| zbus::fdo::Error::Failed(format!("no se pudo serializar: {e}")))
    }

    /// Enciende o apaga la base de una cuenta. Apagarla la borra: la clave del
    /// llavero primero, después los archivos.
    ///
    /// Sólo para una cuenta del último `ListAccounts` bueno; con otra —o antes
    /// del primero— contesta `InvalidArgs`. Con el límite por llamante.
    async fn set_store_enabled(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(signal_context)] emitter: SignalContext<'_>,
        account_id: String,
        enabled: bool,
    ) -> zbus::fdo::Result<()> {
        self.admit_control(&header, &account_id).await?;
        let result = self.manager.set_enabled(&account_id, enabled).await;
        let _ = Self::status_changed(&emitter).await;
        result.map_err(to_fdo)
    }

    /// Vacía la base de una cuenta: la borra —clave y archivos— y, si está
    /// encendida, la vuelve a crear vacía con una clave nueva.
    ///
    /// **Lo que había se pierde** y se vuelve a traer del servidor, ahí mismo
    /// si los contactos estaban encendidos. Quien llama tiene que preguntar
    /// antes; acá no hay cómo. Sale un `Changed` de contactos: lo que alguien
    /// tenía leído ya no está.
    ///
    /// Sólo para una cuenta del último `ListAccounts` bueno. Con el límite por
    /// llamante.
    async fn clear_store(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(signal_context)] emitter: SignalContext<'_>,
        account_id: String,
    ) -> zbus::fdo::Result<()> {
        self.admit_control(&header, &account_id).await?;
        let result = self.manager.clear(&account_id).await;
        if result.is_ok() {
            self.manager.announce_cleared(&account_id).await;
            if matches!(self.manager.contacts_account(&account_id).await, Ok(a) if a.active && a.syncable)
            {
                self.ask_for_sync(&account_id);
            }
        }
        let _ = Self::status_changed(&emitter).await;
        result.map_err(to_fdo)
    }

    /// Pide que la base de una cuenta se ponga al día. Lo llama una aplicación
    /// al abrirse.
    ///
    /// Pasa la tabla del ciclo de vida por esa cuenta y, si tiene contactos,
    /// les pide una vuelta ya. **Si el área de contactos todavía no estaba
    /// encendida, encenderla pide `store.contacts`** a quien llama: encender es
    /// empezar a guardar, y sólo lo puede pedir quien después lo va a poder
    /// leer. Sin permiso, `AccessDenied` y no se enciende nada.
    ///
    /// No espera a que la vuelta termine: el resultado se ve en `GetStatus`,
    /// con `StatusChanged`. Con el límite por llamante.
    async fn request_sync(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(signal_context)] emitter: SignalContext<'_>,
        account_id: String,
    ) -> zbus::fdo::Result<()> {
        self.admit_control(&header, &account_id).await?;
        if let Ok(account) = self.manager.contacts_account(&account_id).await {
            if account.syncable && !account.active {
                self.authorize(&header, &account.display_name).await?;
            }
        }
        let result = self.manager.request_sync(&account_id).await;
        if result.is_ok() {
            match self.manager.activate_contacts(&account_id).await {
                Ok(true) => self.ask_for_sync(&account_id),
                Ok(false) => {}
                Err(e) => tracing::warn!("no se pudo encender el área de contactos: {e}"),
            }
        }
        let _ = Self::status_changed(&emitter).await;
        result.map_err(to_fdo)
    }

    /// Las libretas de una cuenta: `[{id, display_name, contacts}]`, con
    /// cuántos contactos se ven en cada una.
    ///
    /// Pide `store.contacts`.
    async fn list_address_books(
        &self,
        #[zbus(header)] header: Header<'_>,
        account_id: String,
    ) -> zbus::fdo::Result<String> {
        self.authorize_contacts(&header, &account_id).await?;
        let books = self
            .manager
            .read(&account_id, contacts_read::list_address_books)
            .await
            .map_err(read_error)?;
        contacts_read::to_capped_json(&books, contacts_read::MAX_PAGE_BYTES).map_err(read_error)
    }

    /// Una página de contactos, por nombre: de todas las libretas
    /// (`address_book_id` vacío) o de una. `{items: [{id, address_book_id,
    /// display_name, email, phone}], next_cursor}`: `next_cursor` es lo que se
    /// pasa como `cursor` para la siguiente —vacío para la primera—, y `null`
    /// cuando no hay más. `limit` 0 pide 100, y nada pasa de 1000.
    ///
    /// Pide `store.contacts`.
    async fn list_contacts(
        &self,
        #[zbus(header)] header: Header<'_>,
        account_id: String,
        address_book_id: String,
        cursor: String,
        limit: u32,
    ) -> zbus::fdo::Result<String> {
        let book = match address_book_id.as_str() {
            "" => None,
            id => Some(contacts_read::parse_id(id).map_err(invalid)?),
        };
        let after = Cursor::decode(&cursor).map_err(invalid)?;
        let limit = contacts_read::page_limit(limit);
        self.authorize_contacts(&header, &account_id).await?;
        let page = self
            .manager
            .read(&account_id, move |c| {
                contacts_read::list_contacts(c, book, after.as_ref(), limit)
            })
            .await
            .map_err(read_error)?;
        contacts_read::to_capped_json(&page, 2 * contacts_read::MAX_PAGE_BYTES).map_err(read_error)
    }

    /// Una página de la búsqueda, con la misma forma y el mismo cursor que
    /// `ListContacts`. Busca por el principio de cada palabra, sin acentos ni
    /// mayúsculas, en el nombre, los correos, los teléfonos y la organización;
    /// todas las palabras tienen que estar. Lo que se escribe es texto, nunca
    /// lenguaje de consulta. Vacía, de más de 256 bytes o de más de 8
    /// palabras: `InvalidArgs`.
    ///
    /// Pide `store.contacts`.
    async fn search_contacts(
        &self,
        #[zbus(header)] header: Header<'_>,
        account_id: String,
        query: String,
        cursor: String,
        limit: u32,
    ) -> zbus::fdo::Result<String> {
        let fts = contacts_read::fts_query(&query).map_err(invalid)?;
        let after = Cursor::decode(&cursor).map_err(invalid)?;
        let limit = contacts_read::page_limit(limit);
        self.authorize_contacts(&header, &account_id).await?;
        let page = match fts {
            Some(fts) => self
                .manager
                .read(&account_id, move |c| {
                    contacts_read::search_contacts(c, &fts, after.as_ref(), limit)
                })
                .await
                .map_err(read_error)?,
            // Sólo signos: nada que buscar. Igual con la base abierta, para
            // que la respuesta no dependa de qué se escribió.
            None => self
                .manager
                .read(&account_id, |_| {
                    Ok(contacts_read::Page::<contacts_read::ContactSummary> {
                        items: Vec::new(),
                        next_cursor: None,
                    })
                })
                .await
                .map_err(read_error)?,
        };
        contacts_read::to_capped_json(&page, 2 * contacts_read::MAX_PAGE_BYTES).map_err(read_error)
    }

    /// Un contacto entero, leído de su tarjeta en el momento: `{id,
    /// address_book_id, uid, display_name, emails, phones, organization,
    /// notes, related}`, cada correo, teléfono o relación como `{label,
    /// value}`. `null` si ya no está. Nunca la tarjeta cruda.
    ///
    /// Pide `store.contacts`.
    async fn get_contact(
        &self,
        #[zbus(header)] header: Header<'_>,
        account_id: String,
        contact_id: String,
    ) -> zbus::fdo::Result<String> {
        let id = contacts_read::parse_id(&contact_id).map_err(invalid)?;
        self.authorize_contacts(&header, &account_id).await?;
        let contact = self
            .manager
            .read(&account_id, move |c| contacts_read::get_contact(c, id))
            .await
            .map_err(read_error)?;
        contacts_read::to_capped_json(&contact, contacts_read::MAX_CONTACT_BYTES)
            .map_err(read_error)
    }

    /// Señal `StatusChanged` — cambió el estado de alguna base.
    ///
    /// Sin detalle: quien la recibe vuelve a leer `GetStatus`.
    #[zbus(signal)]
    async fn status_changed(emitter: &SignalContext<'_>) -> zbus::Result<()>;

    /// Señal `Changed` — un lote cambió lo guardado de un área (`contacts`) de
    /// una cuenta. Una por lote que cambió algo; ninguna por un lote que no.
    #[zbus(signal)]
    async fn changed(
        emitter: &SignalContext<'_>,
        area: &str,
        account_id: &str,
        generation: u64,
    ) -> zbus::Result<()>;
}

impl<K: KeySource> StoreApi<K> {
    /// Lo que pasa antes de un comando de control: la cuenta se conoce, y quien
    /// llama no pasó su límite.
    async fn admit_control(&self, header: &Header<'_>, account_id: &str) -> zbus::fdo::Result<()> {
        paths::validate_account_id(account_id).map_err(to_fdo)?;
        if !self.manager.is_known(account_id).await {
            return Err(to_fdo(StoreError::UnknownAccount(account_id.to_string())));
        }
        let sender = sender_of(header);
        if !self.access.limits().allow(sender.as_deref(), account_id) {
            return Err(zbus::fdo::Error::LimitsExceeded(format!(
                "demasiados pedidos seguidos sobre esta cuenta: como mucho {} cada {} s",
                access::CONTROL_BURST,
                access::CONTROL_WINDOW.as_secs()
            )));
        }
        Ok(())
    }

    /// `store.contacts` de quien llama, o `AccessDenied`.
    async fn authorize(&self, header: &Header<'_>, account_name: &str) -> zbus::fdo::Result<()> {
        let sender = sender_of(header);
        let verdict = self
            .access
            .check(sender.as_deref(), CONTACTS_RESOURCE, account_name)
            .await;
        match verdict {
            access::Verdict::Allowed => Ok(()),
            access::Verdict::Denied => Err(denied()),
            access::Verdict::Failed(reason) => {
                tracing::info!("no se pudo preguntar por el permiso de los contactos: {reason}");
                Err(denied())
            }
        }
    }

    /// Todo lo que va antes de leer contactos, en este orden: la cuenta existe
    /// y tiene contactos, quien llama tiene `store.contacts`, y —recién
    /// entonces— el área se enciende si no lo estaba.
    async fn authorize_contacts(
        &self,
        header: &Header<'_>,
        account_id: &str,
    ) -> zbus::fdo::Result<()> {
        let account = self
            .manager
            .contacts_account(account_id)
            .await
            .map_err(to_fdo)?;
        self.authorize(header, &account.display_name).await?;
        if !account.active && account.syncable {
            match self.manager.activate_contacts(account_id).await {
                Ok(true) => self.ask_for_sync(account_id),
                Ok(false) => {}
                Err(e) => tracing::warn!("no se pudo encender el área de contactos: {e}"),
            }
        }
        Ok(())
    }

    fn ask_for_sync(&self, account_id: &str) {
        if let Some(contacts) = &self.contacts {
            if contacts.try_send(account_id.to_string()).is_err() {
                tracing::debug!("ya hay bastantes pedidos de sincronización en la fila");
            }
        }
    }
}

/// El nombre único de quien mandó el mensaje. Lo pone el bus; en una conexión
/// punto a punto, lo que diga el otro lado (las pruebas).
fn sender_of(header: &Header<'_>) -> Option<String> {
    header.sender().map(|s| s.to_string())
}

fn denied() -> zbus::fdo::Error {
    zbus::fdo::Error::AccessDenied(
        "sin permiso para leer los contactos guardados (store.contacts)".into(),
    )
}

fn invalid(error: InvalidArgument) -> zbus::fdo::Error {
    zbus::fdo::Error::InvalidArgs(error.to_string())
}

/// El error de una lectura, con texto fijo: nada de rutas ni de lo que dijo
/// SQLite.
fn read_error(error: StoreError) -> zbus::fdo::Error {
    match &error {
        StoreError::Key(KeyError::Locked) => zbus::fdo::Error::Failed(
            "el almacén de esta cuenta está cerrado: el llavero está bloqueado".into(),
        ),
        StoreError::Missing => zbus::fdo::Error::Failed(
            "el almacén de esta cuenta no está abierto; GetStatus dice por qué".into(),
        ),
        other => {
            tracing::warn!("no se pudo leer del almacén: {other}");
            zbus::fdo::Error::Failed(other.public_detail().into())
        }
    }
}

fn to_fdo(error: StoreError) -> zbus::fdo::Error {
    match error {
        StoreError::InvalidAccountId(_) | StoreError::UnknownAccount(_) => {
            zbus::fdo::Error::InvalidArgs(error.to_string())
        }
        other => zbus::fdo::Error::Failed(other.to_string()),
    }
}

/// Lo que ve de `GetStatus` quien pregunta.
///
/// **Cualquiera**: el llavero, y por cuenta su identificador —que
/// `ListAccounts` del servicio de cuentas ya da a cualquiera—, el estado de la
/// base y el del área de contactos, como códigos fijos.
///
/// **Con `store.contacts`** (`contacts_allowed`), en las cuentas con
/// contactos, además: el texto de la base (`detail`, siempre fijo), cuánto
/// ocupa (`size_bytes`), y el texto y la última vuelta buena del área
/// (`detail`, `last_synced_at`). Cuánto ocupa la base es cuánto tiene la
/// persona guardado, y cuándo se sincronizó dice cuándo usó la cuenta: no es
/// para cualquiera.
///
/// Ningún texto lleva rutas ni lo que escribió un servidor, en ningún caso:
/// son fijos desde `lifecycle.rs` y `contacts_sync.rs`.
pub fn visible_status(status: &Status, contacts_allowed: bool) -> serde_json::Value {
    let accounts: Vec<serde_json::Value> = status
        .accounts
        .iter()
        .map(|account| {
            let detailed = contacts_allowed && account.has_contacts;
            let mut entry = serde_json::json!({
                "account_id": account.account_id,
                "state": account.state,
            });
            if detailed {
                entry["detail"] = account.detail.clone().into();
                entry["size_bytes"] = account.size_bytes.into();
            }
            if let Some(contacts) = &account.contacts {
                let mut area = serde_json::json!({ "state": contacts.state });
                if detailed {
                    area["detail"] = contacts.detail.clone().into();
                    area["last_synced_at"] = contacts.last_synced_at.clone().into();
                }
                entry[CONTACTS_AREA] = area;
            }
            entry
        })
        .collect();
    serde_json::json!({
        "keyring": status.keyring,
        "accounts": accounts,
    })
}

/// Convierte lo que contestó `ListAccounts` en lo que entiende el ciclo de
/// vida.
///
/// Un error es `Failed` —**no se borra nada**—, y una respuesta buena lleva
/// **todas** las cuentas, también las que piden reautenticarse: siguen siendo
/// de la persona, y su base se conserva.
pub fn listing_from(result: &Result<Vec<broker::Account>, BrokerError>) -> AccountListing {
    match result {
        Ok(accounts) => AccountListing::Listed(
            accounts
                .iter()
                .map(|a| ListedAccount {
                    id: a.id.clone(),
                    display_name: a.display_name.clone(),
                    capabilities: a.capabilities.clone(),
                    needs_reauth: a.needs_reauth,
                })
                .collect(),
        ),
        Err(_) => AccountListing::Failed,
    }
}

/// El almacén andando: la interfaz publicada y el llavero escuchado.
pub struct StoreService<K: KeySource> {
    manager: Arc<StoreManager<K>>,
    emitter: SignalContext<'static>,
}

impl StoreService<SecretServiceKeys> {
    /// Publica la interfaz en la conexión de sesión y empieza a escuchar al
    /// llavero.
    ///
    /// No falla por el almacén: sin directorio de datos o sin llavero la
    /// interfaz se publica igual y cada cuenta se ve «no disponible». Lo que no
    /// esté se tiene que ver como no disponible, nunca como roto.
    pub async fn start(connection: &zbus::Connection) -> zbus::Result<Self> {
        let keys = SecretServiceKeys::on_session_bus(connection.clone());
        let manager = Arc::new(StoreManager::new(keys, Locations::from_environment()));
        let access = Arc::new(Access::new(
            Arc::new(access::DbusPermissions::new(connection.clone())),
            Arc::new(access::SystemClock),
        ));
        let (requests, pending) = mpsc::channel(PENDING_REQUESTS);
        let service = Self::serve(connection, manager, Some(requests), Arc::clone(&access)).await?;
        service.watch_keyring();
        service.watch_departures(connection.clone(), access);
        service.forward_changes();
        service.sync_contacts(pending);
        Ok(service)
    }

    /// Olvida el permiso y el límite de cada nombre único que se va del bus
    /// de sesión. Si la escucha se corta, se vuelve a armar.
    fn watch_departures(&self, connection: zbus::Connection, access: Arc<Access>) {
        tokio::spawn(async move {
            loop {
                if let Err(e) =
                    access::watch_departures(connection.clone(), Arc::clone(&access)).await
                {
                    tracing::info!("no se pueden escuchar los nombres que se van del bus: {e}");
                }
                tokio::time::sleep(RETRY).await;
            }
        });
    }

    /// La sincronización de contactos, en una tarea propia: una revisión cada
    /// cinco minutos, una vuelta por cuenta cada hora, y cada `RequestSync`.
    fn sync_contacts(&self, requests: mpsc::Receiver<String>) {
        let emitter = self.emitter.clone();
        let notify = Arc::new(move || {
            let emitter = emitter.clone();
            tokio::spawn(async move {
                let _ = StoreApi::<SecretServiceKeys>::status_changed(&emitter).await;
            });
        });
        let sync = ContactsSync::new(
            Arc::clone(&self.manager),
            BrokerCredentials,
            Limits::DEFAULT,
            HttpPolicy::default(),
            notify,
        );
        tokio::spawn(Arc::new(ContactsScheduler::new(sync)).run(requests));
    }

    /// Escucha los cambios de `Locked` del llavero y vuelve a pasar la tabla.
    ///
    /// Es lo que abre las bases al iniciar sesión, cuando el llavero se
    /// desbloquea después de que este servicio arrancó. Lo contrario —que se
    /// bloquee— **no es inmediato**: `vasak-keyring` no avisa al bloquear, así
    /// que lo levanta la revisión de cada cinco minutos, y hasta entonces —hasta
    /// 300 segundos— la base sigue abierta con su clave en memoria.
    ///
    /// Sólo cuentan los avisos del dueño de `org.freedesktop.secrets`, y cada
    /// uno espera [`SETTLE`] antes de reaccionar.
    fn watch_keyring(&self) {
        use futures_util::{FutureExt, StreamExt};

        let manager = Arc::clone(&self.manager);
        let emitter = self.emitter.clone();
        tokio::spawn(async move {
            loop {
                match manager.keys().lock_changes().await {
                    Ok(mut changes) => {
                        while let Some(Ok(message)) = changes.next().await {
                            if !key::is_lock_change(&message)
                                || !manager.keys().is_from_keyring(&message).await
                            {
                                continue;
                            }
                            tokio::time::sleep(SETTLE).await;
                            // Lo que llegó mientras tanto queda cubierto por
                            // esta misma vuelta.
                            while let Some(Some(_)) = changes.next().now_or_never() {}
                            if manager.refresh().await {
                                let _ =
                                    StoreApi::<SecretServiceKeys>::status_changed(&emitter).await;
                            }
                        }
                    }
                    Err(e) => tracing::info!("no se puede escuchar al llavero: {e}"),
                }
                tokio::time::sleep(RETRY).await;
            }
        });
    }
}

impl<K: KeySource> StoreService<K> {
    async fn serve(
        connection: &zbus::Connection,
        manager: Arc<StoreManager<K>>,
        contacts: Option<mpsc::Sender<String>>,
        access: Arc<Access>,
    ) -> zbus::Result<Self> {
        connection
            .object_server()
            .at(
                PATH,
                StoreApi {
                    manager: Arc::clone(&manager),
                    contacts,
                    access,
                },
            )
            .await?;
        let emitter = SignalContext::new(connection, PATH)?.to_owned();
        Ok(Self { manager, emitter })
    }

    /// Cada lote que cambió algo, como señal `Changed`, en el orden en que se
    /// escribieron.
    fn forward_changes(&self) {
        let mut changes = self.manager.subscribe_changes();
        let emitter = self.emitter.clone();
        tokio::spawn(async move {
            while let Some(change) = changes.recv().await {
                let _ = StoreApi::<K>::changed(
                    &emitter,
                    change.area,
                    &change.account_id,
                    change.generation,
                )
                .await;
            }
        });
    }

    /// Lo que hay que hacer cada vez que se leen las cuentas.
    ///
    /// En una tarea aparte: el llavero puede tardar en contestar, y el bucle
    /// que atiende el correo no tiene por qué esperarlo. El momento se toma
    /// **acá**, al llegar la respuesta, y no cuando la tarea consigue la
    /// cerradura: es lo que mide la confirmación de una cuenta que se fue, y
    /// una espera por el llavero no puede acortar ni estirar la vuelta.
    pub fn accounts_listed(&self, listing: AccountListing) {
        let manager = Arc::clone(&self.manager);
        let emitter = self.emitter.clone();
        let arrived = Instant::now();
        tokio::spawn(async move {
            if manager.accounts_listed(listing, arrived).await {
                let _ = StoreApi::<K>::status_changed(&emitter).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;

    use super::*;
    use crate::access::tests::{AccessFixture, Answer};
    use crate::store::contacts::tests::row;
    use crate::store::contacts::ContactOp;
    use crate::store::key::fake::FakeKeys;
    use crate::store::lifecycle::StoreSettings;
    use crate::store::paths::tests::TempDir;

    const IFACE: &str = "ar.net.vasak.os.AccountsStore";

    fn account(id: &str, needs_reauth: bool) -> broker::Account {
        broker::Account {
            id: id.into(),
            display_name: id.into(),
            provider_type: "custom".into(),
            capabilities: vec!["email".into(), "calendar".into()],
            needs_reauth,
        }
    }

    fn with_contacts(id: &str) -> broker::Account {
        let mut account = account(id, false);
        account.display_name = "Trabajo".into();
        account.capabilities.push("contacts".into());
        account
    }

    #[test]
    fn un_list_accounts_que_fallo_no_es_una_lista_vacia() {
        let failed: Result<Vec<broker::Account>, BrokerError> =
            Err(BrokerError::Unavailable("no está".into()));
        assert_eq!(listing_from(&failed), AccountListing::Failed);
        assert_eq!(
            listing_from(&Ok(Vec::new())),
            AccountListing::Listed(Vec::new())
        );
    }

    /// Una cuenta que pide reautenticarse entra en la lista igual: sigue
    /// siendo una cuenta, y su base no se borra.
    #[test]
    fn la_lista_lleva_tambien_las_cuentas_que_piden_reautenticarse() {
        let listing = listing_from(&Ok(vec![account("a", false), account("b", true)]));
        let AccountListing::Listed(accounts) = listing else {
            panic!("tenía que ser una lista");
        };
        let ids: Vec<&str> = accounts.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b"]);
        assert_eq!(accounts[1].capabilities, vec!["email", "calendar"]);
    }

    /// La interfaz entera, con el llavero falso y un `vasak-permissions` falso,
    /// por conexiones punto a punto: cada cliente tiene su nombre único, como
    /// en el bus.
    struct Api {
        temp: TempDir,
        keys: FakeKeys,
        manager: Arc<StoreManager<FakeKeys>>,
        access: AccessFixture,
        requests: mpsc::Sender<String>,
        pending: mpsc::Receiver<String>,
        connections: Vec<zbus::Connection>,
    }

    impl Api {
        async fn new(label: &str, accounts: Vec<broker::Account>, answer: Answer) -> Self {
            let temp = TempDir::new(label);
            let keys = FakeKeys::default();
            let manager = Arc::new(StoreManager::new(
                keys.clone(),
                Ok(Locations {
                    stores: temp.0.join("stores"),
                    settings: temp.0.join("stores.json"),
                }),
            ));
            manager
                .accounts_listed(listing_from(&Ok(accounts)), Instant::now())
                .await;
            let (requests, pending) = mpsc::channel(PENDING_REQUESTS);
            Self {
                temp,
                keys,
                manager,
                access: AccessFixture::new(answer).await,
                requests,
                pending,
                connections: Vec::new(),
            }
        }

        /// Un cliente con nombre único `name`, y el servicio del otro lado.
        async fn client(&mut self, name: &str) -> (zbus::Connection, StoreService<FakeKeys>) {
            let (server_end, client_end) = tokio::net::UnixStream::pair().unwrap();
            let server = zbus::connection::Builder::unix_stream(server_end)
                .server(zbus::Guid::generate())
                .unwrap()
                .p2p()
                .build();
            let client = zbus::connection::Builder::unix_stream(client_end)
                .p2p()
                .build();
            let (server, client) = tokio::join!(server, client);
            let (server, client) = (server.unwrap(), client.unwrap());
            // Lo que haría el bus: cada mensaje de este cliente sale con su
            // nombre único como remitente.
            client.set_unique_name(name).unwrap();
            let service = StoreService::serve(
                &server,
                Arc::clone(&self.manager),
                Some(self.requests.clone()),
                Arc::clone(&self.access.access),
            )
            .await
            .unwrap();
            self.connections.push(server);
            (client, service)
        }

        fn settings(&self) -> StoreSettings {
            StoreSettings::load(&self.temp.0.join("stores.json")).unwrap()
        }

        /// Dos contactos en una libreta, escritos como los escribe la
        /// sincronización.
        async fn with_two_contacts(&self) {
            self.manager
                .with_store("cuenta", |store| {
                    let book = store
                        .upsert_address_books(&[("https://x/a/".into(), "Personal".into())])?
                        .remove(0);
                    store.apply_contacts(
                        &book,
                        &[
                            ContactOp::Upsert(row("https://x/a/1.vcf", "Ana Pérez", "ana@x.com")),
                            ContactOp::Upsert(row("https://x/a/2.vcf", "Beto Gómez", "beto@x.com")),
                        ],
                        None,
                        u64::MAX,
                    )?;
                    Ok(())
                })
                .await
                .unwrap();
        }
    }

    async fn call<B>(client: &zbus::Connection, method: &str, body: &B) -> zbus::Result<String>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        client
            .call_method(None::<&str>, PATH, Some(IFACE), method, body)
            .await?
            .body()
            .deserialize::<String>()
    }

    async fn call_unit<B>(client: &zbus::Connection, method: &str, body: &B) -> zbus::Result<()>
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        client
            .call_method(None::<&str>, PATH, Some(IFACE), method, body)
            .await
            .map(|_| ())
    }

    async fn status(client: &zbus::Connection) -> serde_json::Value {
        serde_json::from_str(&call(client, "GetStatus", &()).await.unwrap()).unwrap()
    }

    /// El nombre del error de D-Bus, sin lo que dice: los mensajes de las
    /// pruebas no repiten lo que contestó una lectura.
    fn error_name<T>(result: &zbus::Result<T>) -> String {
        match result {
            Err(zbus::Error::MethodError(name, _, _)) => name.as_str().to_string(),
            Err(_) => "otro error".into(),
            Ok(_) => "ninguno".into(),
        }
    }

    const ACCESS_DENIED: &str = "org.freedesktop.DBus.Error.AccessDenied";
    const INVALID_ARGS: &str = "org.freedesktop.DBus.Error.InvalidArgs";
    const LIMITS_EXCEEDED: &str = "org.freedesktop.DBus.Error.LimitsExceeded";

    #[tokio::test]
    async fn la_interfaz_contesta_en_json_y_avisa_los_cambios() {
        let mut api = Api::new("api", vec![account("cuenta", false)], Answer::Allow).await;
        let (client, _service) = api.client(":1.7").await;

        // Los métodos y las señales, ni uno más.
        let xml: String = client
            .call_method(
                None::<&str>,
                PATH,
                Some("org.freedesktop.DBus.Introspectable"),
                "Introspect",
                &(),
            )
            .await
            .unwrap()
            .body()
            .deserialize()
            .unwrap();
        let start = xml.find(IFACE).unwrap();
        let iface = &xml[start..start + xml[start..].find("</interface>").unwrap()];
        let mut members: Vec<&str> = iface
            .split("name=\"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
            .filter(|name| name.chars().next().is_some_and(char::is_uppercase))
            .collect();
        members.sort();
        assert_eq!(
            members,
            vec![
                "Changed",
                "ClearStore",
                "GetContact",
                "GetStatus",
                "ListAddressBooks",
                "ListContacts",
                "RequestSync",
                "SearchContacts",
                "SetStoreEnabled",
                "StatusChanged"
            ]
        );

        let current = status(&client).await;
        assert_eq!(current["keyring"], "unlocked");
        assert_eq!(current["accounts"][0]["account_id"], "cuenta");
        assert_eq!(current["accounts"][0]["state"], "open");

        // Un identificador con barra, o una cuenta que no está: argumento
        // inválido, y nada se toca.
        for bad in ["../cuenta", "desconocida"] {
            assert_eq!(
                error_name(&call_unit(&client, "ClearStore", &(bad,)).await),
                INVALID_ARGS
            );
        }

        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface(IFACE)
            .unwrap()
            .member("StatusChanged")
            .unwrap()
            .build();
        let mut signals = zbus::MessageStream::for_match_rule(rule, &client, None)
            .await
            .unwrap();

        call_unit(&client, "RequestSync", &("cuenta",))
            .await
            .unwrap();
        // Una cuenta de correo y calendario no tiene contactos: no se enciende
        // nada, no se pide una vuelta ni se pregunta ningún permiso.
        assert!(api.pending.try_recv().is_err());
        assert_eq!(api.access.permissions.calls(), 0);
        call_unit(&client, "SetStoreEnabled", &("cuenta", false))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), signals.next())
            .await
            .expect("no llegó StatusChanged")
            .unwrap()
            .unwrap();

        assert_eq!(status(&client).await["accounts"][0]["state"], "disabled");
        assert!(
            api.keys.state().keys.is_empty(),
            "apagar tenía que borrar la clave"
        );
    }

    /// `RequestSync` que encendería los contactos pide `store.contacts`: sin
    /// permiso no enciende nada; con permiso enciende el área y pide la vuelta.
    #[tokio::test]
    async fn pedir_una_sincronizacion_que_enciende_los_contactos_pide_permiso() {
        let mut api = Api::new("api-contactos", vec![with_contacts("cuenta")], Answer::Deny).await;
        let (denied, _s1) = api.client(":1.7").await;
        assert_eq!(
            status(&denied).await["accounts"][0]["contacts"]["state"],
            "off"
        );

        let result = call_unit(&denied, "RequestSync", &("cuenta",)).await;
        assert_eq!(error_name(&result), ACCESS_DENIED);
        assert!(api.pending.try_recv().is_err());
        assert!(!api.settings().is_active("cuenta", CONTACTS_AREA));
        assert_eq!(
            status(&denied).await["accounts"][0]["contacts"]["state"],
            "off"
        );

        api.access.permissions.set(Answer::Allow);
        let (allowed, _s2) = api.client(":1.8").await;
        call_unit(&allowed, "RequestSync", &("cuenta",))
            .await
            .unwrap();
        assert_eq!(api.pending.try_recv().unwrap(), "cuenta");
        assert!(api.settings().is_active("cuenta", CONTACTS_AREA));
        assert_eq!(
            status(&allowed).await["accounts"][0]["contacts"]["state"],
            "pending"
        );

        // Ya encendida, pedir una vuelta no vuelve a preguntar.
        let asked = api.access.permissions.calls();
        let (other, _s3) = api.client(":1.9").await;
        api.access
            .bus
            .0
            .lock()
            .unwrap()
            .insert(":1.9".into(), std::process::id());
        call_unit(&other, "RequestSync", &("cuenta",))
            .await
            .unwrap();
        assert_eq!(api.access.permissions.calls(), asked);
    }

    /// **Sin permiso, ningún dato**, en las cuatro lecturas: `AccessDenied`, y
    /// el área no se enciende.
    #[tokio::test]
    async fn sin_permiso_ninguna_lectura_devuelve_datos() {
        let mut api = Api::new("api-negado", vec![with_contacts("cuenta")], Answer::Deny).await;
        api.with_two_contacts().await;
        let (client, _service) = api.client(":1.7").await;

        let results = [
            call(&client, "ListAddressBooks", &("cuenta",)).await,
            call(&client, "ListContacts", &("cuenta", "", "", 0u32)).await,
            call(&client, "SearchContacts", &("cuenta", "ana", "", 0u32)).await,
            call(&client, "GetContact", &("cuenta", "1")).await,
        ];
        for result in &results {
            assert_eq!(error_name(result), ACCESS_DENIED);
        }
        assert_eq!(api.access.permissions.calls(), 1, "el «no» quedó guardado");
        assert!(!api.settings().is_active("cuenta", CONTACTS_AREA));
        assert!(api.pending.try_recv().is_err());

        // Un error del servicio de permisos, lo mismo.
        api.access.permissions.set(Answer::Fail);
        let (other, _s) = api.client(":1.8").await;
        assert_eq!(
            error_name(&call(&other, "ListContacts", &("cuenta", "", "", 0u32)).await),
            ACCESS_DENIED
        );
    }

    /// Con permiso: las cuatro lecturas, la paginación por el bus, y el área
    /// que se enciende con la primera lectura. Se pregunta una sola vez.
    #[tokio::test]
    async fn con_permiso_se_leen_los_contactos_y_se_enciende_el_area() {
        let mut api = Api::new("api-lee", vec![with_contacts("cuenta")], Answer::Allow).await;
        api.with_two_contacts().await;
        let (client, _service) = api.client(":1.7").await;

        let books: serde_json::Value = serde_json::from_str(
            &call(&client, "ListAddressBooks", &("cuenta",))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(books[0]["display_name"], "Personal");
        assert_eq!(books[0]["contacts"], 2);
        assert!(api.settings().is_active("cuenta", CONTACTS_AREA));
        assert_eq!(api.pending.try_recv().unwrap(), "cuenta");

        let first: serde_json::Value = serde_json::from_str(
            &call(&client, "ListContacts", &("cuenta", "", "", 1u32))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(first["items"][0]["display_name"], "Ana Pérez");
        assert_eq!(first["items"][0]["email"], "ana@x.com");
        let cursor = first["next_cursor"].as_str().unwrap().to_string();
        let second: serde_json::Value = serde_json::from_str(
            &call(
                &client,
                "ListContacts",
                &("cuenta", "", cursor.as_str(), 1u32),
            )
            .await
            .unwrap(),
        )
        .unwrap();
        assert_eq!(second["items"][0]["display_name"], "Beto Gómez");
        assert!(second["next_cursor"].is_null());

        let book_id = books[0]["id"].as_str().unwrap().to_string();
        let in_book: serde_json::Value = serde_json::from_str(
            &call(
                &client,
                "ListContacts",
                &("cuenta", book_id.as_str(), "", 0u32),
            )
            .await
            .unwrap(),
        )
        .unwrap();
        assert_eq!(in_book["items"].as_array().unwrap().len(), 2);

        let found: serde_json::Value = serde_json::from_str(
            &call(&client, "SearchContacts", &("cuenta", "gomez", "", 0u32))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(found["items"].as_array().unwrap().len(), 1);
        let id = found["items"][0]["id"].as_str().unwrap().to_string();

        let contact: serde_json::Value = serde_json::from_str(
            &call(&client, "GetContact", &("cuenta", id.as_str()))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(contact["display_name"], "Beto Gómez");
        assert_eq!(contact["emails"][0]["value"], "beto@x.com");
        assert!(contact.get("raw_vcard").is_none());
        assert_eq!(
            call(&client, "GetContact", &("cuenta", "999999"))
                .await
                .unwrap(),
            "null"
        );
        assert_eq!(
            api.access.permissions.calls(),
            1,
            "una sola pregunta, guardada"
        );
    }

    /// Un argumento que no se entiende es `InvalidArgs` antes de preguntar
    /// nada: no se abre un diálogo por un pedido mal hecho.
    #[tokio::test]
    async fn un_argumento_invalido_no_llega_a_preguntar() {
        let mut api = Api::new("api-args", vec![with_contacts("cuenta")], Answer::Allow).await;
        let (client, _service) = api.client(":1.7").await;
        let results = [
            call(
                &client,
                "ListContacts",
                &("cuenta", "", "no-es-un-cursor", 0u32),
            )
            .await,
            call(&client, "ListContacts", &("cuenta", "x", "", 0u32)).await,
            call(&client, "SearchContacts", &("cuenta", "   ", "", 0u32)).await,
            call(
                &client,
                "SearchContacts",
                &("cuenta", "a b c d e f g h i", "", 0u32),
            )
            .await,
            call(&client, "GetContact", &("cuenta", "abc")).await,
            call(&client, "ListAddressBooks", &("../cuenta",)).await,
            call(&client, "ListAddressBooks", &("desconocida",)).await,
        ];
        for result in &results {
            assert_eq!(error_name(result), INVALID_ARGS);
        }
        assert_eq!(api.access.permissions.calls(), 0);
    }

    /// Con el llavero bloqueado, leer da un error que lo dice, y ningún dato.
    #[tokio::test]
    async fn leer_con_el_llavero_bloqueado_da_un_error_claro_y_ningun_dato() {
        let mut api = Api::new(
            "api-bloqueado",
            vec![with_contacts("cuenta")],
            Answer::Allow,
        )
        .await;
        api.with_two_contacts().await;
        let (client, _service) = api.client(":1.7").await;
        api.keys.state().locked = true;

        let result = call(&client, "ListContacts", &("cuenta", "", "", 0u32)).await;
        match &result {
            Err(zbus::Error::MethodError(name, Some(text), _)) => {
                assert!(name.as_str().ends_with(".Failed"));
                assert!(text.contains("llavero está bloqueado"));
            }
            other => panic!("tenía que ser un error del almacén: {}", error_name(other)),
        }
    }

    /// Lo que ve cualquiera de `GetStatus` son códigos: ni cuánto ocupa la
    /// base, ni cuándo se sincronizó, ni ningún texto. Quien tiene
    /// `store.contacts` —una lectura concedida hace menos de 30 s— ve el resto.
    #[tokio::test]
    async fn get_status_sin_permiso_no_lleva_tamano_ni_detalle() {
        let mut api = Api::new("api-estado", vec![with_contacts("cuenta")], Answer::Allow).await;
        let (reader, _s1) = api.client(":1.7").await;
        let (stranger, _s2) = api.client(":1.8").await;
        api.manager
            .set_contacts_status("cuenta", crate::store::lifecycle::AreaState::Synced, "")
            .await;

        let public = status(&stranger).await;
        let account = &public["accounts"][0];
        assert_eq!(account["state"], "open");
        assert_eq!(account["contacts"]["state"], "synced");
        for hidden in ["size_bytes", "detail"] {
            assert!(account.get(hidden).is_none(), "{hidden} no es público");
        }
        for hidden in ["detail", "last_synced_at"] {
            assert!(
                account["contacts"].get(hidden).is_none(),
                "{hidden} no es público"
            );
        }

        call(&reader, "ListAddressBooks", &("cuenta",))
            .await
            .unwrap();
        let full = status(&reader).await;
        assert!(full["accounts"][0]["size_bytes"].as_u64().unwrap() > 0);
        assert!(full["accounts"][0]["contacts"]["last_synced_at"].is_string());
        // El otro sigue viendo lo público.
        assert!(status(&stranger).await["accounts"][0]
            .get("size_bytes")
            .is_none());
        // Y mirar el estado no abrió ningún diálogo.
        assert_eq!(api.access.permissions.calls(), 1);
    }

    /// El límite por llamante: la llamada de control que pasa el cupo contesta
    /// `LimitsExceeded`; otro nombre tiene el suyo.
    #[tokio::test]
    async fn el_limite_por_llamante_corta_la_llamada_siguiente() {
        let mut api = Api::new("api-limite", vec![account("cuenta", false)], Answer::Allow).await;
        let (client, _s1) = api.client(":1.7").await;
        for _ in 0..access::CONTROL_BURST {
            call_unit(&client, "ClearStore", &("cuenta",))
                .await
                .unwrap();
        }
        assert_eq!(
            error_name(&call_unit(&client, "ClearStore", &("cuenta",)).await),
            LIMITS_EXCEEDED
        );
        assert_eq!(
            error_name(&call_unit(&client, "RequestSync", &("cuenta",)).await),
            LIMITS_EXCEEDED
        );
        let (other, _s2) = api.client(":1.8").await;
        call_unit(&other, "ClearStore", &("cuenta",)).await.unwrap();
    }

    async fn next_changed(signals: &mut zbus::MessageStream) -> (String, String, u64) {
        let message = tokio::time::timeout(Duration::from_secs(5), signals.next())
            .await
            .expect("no llegó Changed")
            .unwrap()
            .unwrap();
        message
            .body()
            .deserialize::<(String, String, u64)>()
            .unwrap()
    }

    /// Cada lote que cambió algo sale como `Changed` por el bus, con el área,
    /// la cuenta y la generación; un lote que no cambió nada no sale. Vaciar la
    /// base con los contactos encendidos también avisa.
    #[tokio::test]
    async fn changed_sale_por_el_bus_una_vez_por_lote() {
        let mut api = Api::new("api-changed", vec![with_contacts("cuenta")], Answer::Allow).await;
        let (client, service) = api.client(":1.7").await;
        service.forward_changes();
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface(IFACE)
            .unwrap()
            .member("Changed")
            .unwrap()
            .build();
        let mut signals = zbus::MessageStream::for_match_rule(rule, &client, None)
            .await
            .unwrap();
        api.with_two_contacts().await;
        let (area, account_id, first) = next_changed(&mut signals).await;
        assert_eq!((area.as_str(), account_id.as_str()), ("contacts", "cuenta"));

        // Nada cambió: nada sale.
        api.manager
            .with_store("cuenta", |store| {
                store.upsert_address_books(&[("https://x/a/".into(), "Personal".into())])?;
                Ok(())
            })
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), signals.next())
                .await
                .is_err(),
            "un lote sin cambios no avisa"
        );

        // Vaciar, con los contactos encendidos.
        call(&client, "ListAddressBooks", &("cuenta",))
            .await
            .unwrap();
        call_unit(&client, "ClearStore", &("cuenta",))
            .await
            .unwrap();
        let (_, _, after_clear) = next_changed(&mut signals).await;
        assert!(after_clear > first, "la base nueva empieza más arriba");
    }
}
