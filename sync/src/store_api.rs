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
//! - **Lecturas del calendario**, con `store.calendar`: `ListCalendars`,
//!   `ListOccurrences`, `GetEvent`, `ListTasks`. Igual que los contactos, salvo
//!   que **juntan todas las cuentas** con calendario —el permiso es por
//!   aplicación y no por cuenta, y un widget quiere la semana entera—, con
//!   identificadores globales (`"<cuenta>/<número>"`). La primera lectura
//!   enciende el calendario de todas las cuentas que lo tienen.
//! - **Estado**: `GetStatus` y la señal `StatusChanged`. Lo ve cualquiera de la
//!   sesión, recortado (ver [`visible_status`]).
//! - **Control**: `SetStoreEnabled`, `ClearStore`, `RequestSync`, con un límite
//!   por llamante ([`crate::access::CallerLimits`]). `RequestSync` que
//!   encendería un área pide además su permiso (`store.contacts`,
//!   `store.calendar`).
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

use serde::Serialize;

use crate::access::{self, Access, ControlAction, Refusal, CALENDAR_RESOURCE, CONTACTS_RESOURCE};
use crate::broker::{self, BrokerError};
use crate::calendar_sync::{CalendarScheduler, CalendarSync, CALENDAR_TICK};
use crate::contacts_sync::{BrokerCredentials, ContactsScheduler, ContactsSync, CONTACTS_TICK};
use crate::dav::webdav::{HttpPolicy, Limits};
use crate::ical::recurrence::ExpansionLimits;
use crate::store::calendar_read::{self, GlobalId, ListCursor, Range};
use crate::store::contacts_read::{self, Cursor, InvalidArgument};
use crate::store::key::{self, KeyError, KeySource, SecretServiceKeys};
use crate::store::lifecycle::{
    AccountListing, AreaAccount, Consent, ListedAccount, Locations, Status, StoreManager,
    CALENDAR_AREA, CONTACTS_AREA, SYNCED_AREAS,
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

/// Cada área y el recurso de su permiso.
const AREA_RESOURCES: [(&str, &str); 2] = [
    (CONTACTS_AREA, CONTACTS_RESOURCE),
    (CALENDAR_AREA, CALENDAR_RESOURCE),
];

/// Hasta cuánto del nombre de las cuentas va al diálogo de permiso de una
/// lectura que junta todas.
const MAX_DIALOG_DETAIL: usize = 256;

/// El objeto de D-Bus.
pub struct StoreApi<K: KeySource> {
    manager: Arc<StoreManager<K>>,
    /// Por donde se le pide a la sincronización de contactos que atienda una
    /// cuenta ya.
    contacts: Option<mpsc::Sender<String>>,
    /// Lo mismo, a la del calendario.
    calendar: Option<mpsc::Sender<String>>,
    /// El permiso de quien llama, y el límite de los comandos.
    access: Arc<Access>,
}

#[interface(name = "ar.net.vasak.os.AccountsStore")]
impl<K: KeySource> StoreApi<K> {
    /// El estado del almacén, **recortado según quién pregunta**.
    ///
    /// Cualquiera de la sesión ve el estado del llavero y, por cuenta, en qué
    /// está su base (`locked`, `open`, `rebuilt`, `disabled`, `unavailable`) y
    /// en qué está cada área —contactos, calendario— (`off`, `pending`,
    /// `syncing`, `synced`, `unavailable`, `failed`): códigos fijos, nada más.
    /// El texto que explica la base y cuánto ocupa (`detail`, `size_bytes`) los
    /// ve quien tiene concedido el permiso de **alguna** de las áreas de esa
    /// cuenta; el texto de un área y cuándo terminó bien su última vuelta
    /// (`last_synced_at`), quien tiene el permiso de **esa** área. **No abre
    /// ningún diálogo**: mira la respuesta que quedó guardada de una lectura de
    /// los últimos 30 s; sin ella, se ve la parte pública. Ver
    /// [`visible_status`].
    async fn get_status(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<String> {
        let status = self.manager.status().await;
        let sender = sender_of(&header);
        let allowed: Vec<&str> = AREA_RESOURCES
            .into_iter()
            .filter(|(_, resource)| self.access.cached(sender.as_deref(), resource) == Some(true))
            .map(|(area, _)| area)
            .collect();
        serde_json::to_string(&visible_status(&status, &allowed))
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
        let action = if enabled {
            ControlAction::Enable
        } else {
            ControlAction::Disable
        };
        self.admit_control(&header, &account_id, action).await?;
        let result = self.manager.set_enabled(&account_id, enabled).await;
        let _ = Self::status_changed(&emitter).await;
        result.map_err(to_fdo)
    }

    /// Vacía la base de una cuenta: la borra —clave y archivos— y, si está
    /// encendida, la vuelve a crear vacía con una clave nueva.
    ///
    /// **Lo que había se pierde** y se vuelve a traer del servidor, ahí mismo
    /// en cada área encendida. Quien llama tiene que preguntar antes; acá no
    /// hay cómo. Sale un `Changed` por área encendida: lo que alguien tenía
    /// leído ya no está.
    ///
    /// Sólo para una cuenta del último `ListAccounts` bueno. Con el límite por
    /// llamante.
    async fn clear_store(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(signal_context)] emitter: SignalContext<'_>,
        account_id: String,
    ) -> zbus::fdo::Result<()> {
        self.admit_control(&header, &account_id, ControlAction::Clear)
            .await?;
        let result = self.manager.clear(&account_id).await;
        if result.is_ok() {
            self.manager.announce_cleared(&account_id).await;
            for area in SYNCED_AREAS {
                if matches!(self.manager.area_account(area, &account_id).await, Ok(a) if a.active && a.syncable)
                {
                    self.ask_for_sync(area, &account_id);
                }
            }
        }
        let _ = Self::status_changed(&emitter).await;
        result.map_err(to_fdo)
    }

    /// Pide que la base de una cuenta se ponga al día. Lo llama una aplicación
    /// al abrirse.
    ///
    /// Pasa la tabla del ciclo de vida por esa cuenta y le pide una vuelta ya
    /// a cada área que tenga. **Si un área todavía no estaba encendida,
    /// encenderla pide su permiso** (`store.contacts`, `store.calendar`) a
    /// quien llama: encender es empezar a guardar, y sólo lo puede pedir quien
    /// después lo va a poder leer. Un área cuyo permiso dice que no queda
    /// apagada; si se preguntó por alguna y ninguna dijo que sí, y no había
    /// ninguna encendida, `AccessDenied`.
    ///
    /// No espera a que la vuelta termine: el resultado se ve en `GetStatus`,
    /// con `StatusChanged`. Con el límite por llamante, y uno por cuenta cada
    /// [`access::SYNC_FLOOR`] de cualquier llamante.
    async fn request_sync(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(signal_context)] emitter: SignalContext<'_>,
        account_id: String,
    ) -> zbus::fdo::Result<()> {
        self.admit_control(&header, &account_id, ControlAction::Sync)
            .await?;
        // Si hace falta preguntar se mira acá, pero **encender lo decide
        // `activate_area`** con lo que haya en ese momento, y sin un «sí»
        // no enciende: si la cuenta cambia en el medio —un `ListAccounts`
        // mientras se pasa la tabla—, no se enciende nada sin permiso, y el
        // próximo `RequestSync` pregunta.
        let mut consents = Vec::new();
        let mut refused = None;
        let mut asked_granted = false;
        let mut active = false;
        for (area, resource) in AREA_RESOURCES {
            let mut consent = Consent::NotAsked;
            if let Ok(account) = self.manager.area_account(area, &account_id).await {
                active |= account.active;
                if account.syncable && !account.active {
                    match self
                        .authorize(&header, resource, &account.display_name)
                        .await
                    {
                        Ok(()) => {
                            consent = Consent::Granted;
                            asked_granted = true;
                        }
                        Err(e) => {
                            refused.get_or_insert(e);
                        }
                    }
                }
            }
            consents.push((area, consent));
        }
        if let Some(refusal) = refused {
            if !asked_granted && !active {
                let _ = Self::status_changed(&emitter).await;
                return Err(refusal);
            }
        }
        let result = self.manager.request_sync(&account_id).await;
        if result.is_ok() {
            for (area, consent) in consents {
                match self.manager.activate_area(area, &account_id, consent).await {
                    Ok(true) => self.ask_for_sync(area, &account_id),
                    Ok(false) => {}
                    Err(e) => tracing::warn!("no se pudo encender un área: {e}"),
                }
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
    /// cuando no hay más. **El final es `next_cursor == null`**, no una página
    /// vacía: si todas las filas de una página se saltearon porque solas no
    /// entraban, vuelve sin ninguna y con cursor, y la siguiente trae lo que
    /// sigue. `limit` 0 pide 100, y nada pasa de 1000.
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
        contacts_read::to_capped_json(&page, contacts_read::MAX_PAGE_REPLY_BYTES)
            .map_err(read_error)
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
        contacts_read::to_capped_json(&page, contacts_read::MAX_PAGE_REPLY_BYTES)
            .map_err(read_error)
    }

    /// Un contacto entero, leído de su tarjeta en el momento: `{id,
    /// address_book_id, uid, display_name, emails, phones, organization,
    /// notes, related, truncated}`, cada correo, teléfono o relación como
    /// `{label, value}`. `null` si ya no está. Nunca la tarjeta cruda. Uno que
    /// no entra en 1 MiB llega recortado —sin sus últimas relaciones,
    /// teléfonos y correos— y con `truncated: true`.
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

    /// Los calendarios de **todas las cuentas** con calendario:
    /// `[{id, account_id, display_name, color, components}]`, con `id` global
    /// (`"<cuenta>/<número>"`) y `components` entre `VEVENT` y `VTODO`.
    ///
    /// Pide `store.calendar`.
    async fn list_calendars(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> zbus::fdo::Result<String> {
        let accounts = self.authorize_calendar_accounts(&header).await?;
        let mut calendars = Vec::new();
        for account_id in accounts {
            let id = account_id.clone();
            match self
                .manager
                .read(&account_id, move |c| calendar_read::list_calendars(c, &id))
                .await
            {
                Ok(items) => calendars.extend(items),
                Err(StoreError::Missing) => {}
                Err(e) => return Err(read_error(e)),
            }
        }
        contacts_read::to_capped_json(&calendars, contacts_read::MAX_PAGE_BYTES).map_err(read_error)
    }

    /// **Lo que muestra un widget**: las veces de los eventos de todas las
    /// cuentas con calendario que se ven en `[from, to)` (RFC 3339, como mucho
    /// 400 días), de los calendarios de `calendar_ids` (vacío: todos), por
    /// comienzo. `{items: [{event_id, occurrence_id, calendar_id, title, start,
    /// end, all_day, floating, color}], next_cursor, truncated}`: `start` y
    /// `end` en UTC —un día completo, a medianoche UTC y con `all_day`—,
    /// `floating` si la hora es la de quien mira. Fuera de la ventana del
    /// almacén se expande en el momento, con topes: `truncated` dice que algo
    /// quedó afuera. El cursor y los topes son los de `ListContacts`: `limit` 0
    /// pide 100, nada pasa de 1000, y **el final es `next_cursor == null`**.
    ///
    /// Pide `store.calendar`.
    async fn list_occurrences(
        &self,
        #[zbus(header)] header: Header<'_>,
        from: String,
        to: String,
        calendar_ids: Vec<String>,
        cursor: String,
        limit: u32,
    ) -> zbus::fdo::Result<String> {
        let range = Range::parse(&from, &to).map_err(invalid)?;
        let calendars = calendar_read::parse_calendar_ids(&calendar_ids).map_err(invalid)?;
        let after = ListCursor::decode(&cursor).map_err(invalid)?;
        let limit = contacts_read::page_limit(limit);
        let accounts = self.authorize_calendar_accounts(&header).await?;
        let mut rows = Vec::new();
        let mut truncated = false;
        for account_id in accounts {
            let Some(filter) = filter_for(&calendars, &account_id) else {
                continue;
            };
            let (id, after) = (account_id.clone(), after.clone());
            match self
                .manager
                .read_in_parts(&account_id, move |pool| {
                    calendar_read::account_occurrences(
                        pool,
                        &id,
                        range,
                        filter.as_deref(),
                        after.as_ref(),
                        limit,
                        &ExpansionLimits::DEFAULT,
                    )
                })
                .await
            {
                Ok(found) => {
                    truncated |= found.truncated;
                    rows.extend(found.rows);
                }
                Err(StoreError::Missing) => {}
                Err(e) => return Err(read_error(e)),
            }
        }
        let (items, next_cursor) = paginate(rows, limit);
        contacts_read::to_capped_json(
            &OccurrencePage {
                items,
                next_cursor,
                truncated,
            },
            contacts_read::MAX_PAGE_REPLY_BYTES,
        )
        .map_err(read_error)
    }

    /// Un evento entero, leído de su iCalendar en el momento: `{event_id,
    /// occurrence_id, calendar_id, uid, title, description, location, start,
    /// end, all_day, timezone, timezone_unknown, floating, status, recurrence,
    /// alarms, organizer, attendees, truncated}`. Con `occurrence_id` vacío, el
    /// evento; con el de una vez, esa vez —la excepción, si la tiene—. `null`
    /// si no está. Nunca el iCalendar crudo ni la dirección en el servidor. Uno
    /// que no entra en 1 MiB llega recortado, con `truncated: true`.
    ///
    /// Pide `store.calendar`.
    async fn get_event(
        &self,
        #[zbus(header)] header: Header<'_>,
        event_id: String,
        occurrence_id: String,
    ) -> zbus::fdo::Result<String> {
        let id = GlobalId::parse(&event_id).map_err(invalid)?;
        let occurrence = calendar_read::parse_occurrence_id(&occurrence_id).map_err(invalid)?;
        let account = self
            .manager
            .area_account(CALENDAR_AREA, &id.account_id)
            .await
            .map_err(to_fdo)?;
        self.authorize(&header, CALENDAR_RESOURCE, &account.display_name)
            .await?;
        self.activate_after_read(CALENDAR_AREA, &id.account_id, &account)
            .await;
        let account_id = id.account_id.clone();
        let event = self
            .manager
            .read_in_parts(&id.account_id, move |pool| {
                calendar_read::get_event(
                    pool,
                    &account_id,
                    id.id,
                    occurrence,
                    &ExpansionLimits::DEFAULT,
                )
            })
            .await
            .map_err(read_error)?;
        contacts_read::to_capped_json(&event, calendar_read::MAX_EVENT_BYTES).map_err(read_error)
    }

    /// Las tareas (`VTODO`) de todas las cuentas con calendario, de los
    /// calendarios de `calendar_ids` (vacío: todas), por vencimiento —las que
    /// no tienen, al final—, y sin las hechas salvo con `include_completed`.
    /// `{items: [{task_id, calendar_id, title, due, all_day, status, priority,
    /// completed, done, color}], next_cursor}`, con el cursor y los topes de
    /// `ListOccurrences`.
    ///
    /// Pide `store.calendar`.
    async fn list_tasks(
        &self,
        #[zbus(header)] header: Header<'_>,
        calendar_ids: Vec<String>,
        include_completed: bool,
        cursor: String,
        limit: u32,
    ) -> zbus::fdo::Result<String> {
        let calendars = calendar_read::parse_calendar_ids(&calendar_ids).map_err(invalid)?;
        let after = ListCursor::decode(&cursor).map_err(invalid)?;
        let limit = contacts_read::page_limit(limit);
        let accounts = self.authorize_calendar_accounts(&header).await?;
        let mut rows = Vec::new();
        for account_id in accounts {
            let Some(filter) = filter_for(&calendars, &account_id) else {
                continue;
            };
            let (id, after) = (account_id.clone(), after.clone());
            match self
                .manager
                .read(&account_id, move |c| {
                    calendar_read::account_tasks(
                        c,
                        &id,
                        filter.as_deref(),
                        include_completed,
                        after.as_ref(),
                        limit,
                    )
                })
                .await
            {
                Ok(found) => rows.extend(found.rows),
                Err(StoreError::Missing) => {}
                Err(e) => return Err(read_error(e)),
            }
        }
        let (items, next_cursor) = paginate(rows, limit);
        contacts_read::to_capped_json(
            &contacts_read::Page { items, next_cursor },
            contacts_read::MAX_PAGE_REPLY_BYTES,
        )
        .map_err(read_error)
    }

    /// Señal `StatusChanged` — cambió el estado de alguna base.
    ///
    /// Sin detalle: quien la recibe vuelve a leer `GetStatus`.
    #[zbus(signal)]
    async fn status_changed(emitter: &SignalContext<'_>) -> zbus::Result<()>;

    /// Señal `Changed` — un lote cambió lo guardado de un área (`contacts`,
    /// `calendar`) de una cuenta. Una por lote que cambió algo; ninguna por un
    /// lote que no. Correr la ventana del calendario, una vez por día, también
    /// sale, si cambió lo que se ve.
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
    async fn admit_control(
        &self,
        header: &Header<'_>,
        account_id: &str,
        action: ControlAction,
    ) -> zbus::fdo::Result<()> {
        paths::validate_account_id(account_id).map_err(to_fdo)?;
        if !self.manager.is_known(account_id).await {
            return Err(to_fdo(StoreError::UnknownAccount(account_id.to_string())));
        }
        let sender = sender_of(header);
        match self
            .access
            .limits()
            .admit(sender.as_deref(), account_id, action)
        {
            Ok(()) => Ok(()),
            Err(Refusal::Caller) => Err(zbus::fdo::Error::LimitsExceeded(format!(
                "demasiados pedidos seguidos sobre esta cuenta: como mucho {} cada {} s",
                access::CONTROL_BURST,
                access::CONTROL_WINDOW.as_secs()
            ))),
            Err(Refusal::Account) => Err(zbus::fdo::Error::LimitsExceeded(format!(
                "esta cuenta recibió el mismo pedido hace menos de {} s",
                action.floor().as_secs()
            ))),
            Err(Refusal::Full) => Err(zbus::fdo::Error::LimitsExceeded(format!(
                "demasiados pedidos de control en el último minuto: como mucho {}",
                access::MAX_TRACKED_CALLS
            ))),
        }
    }

    /// El permiso `resource` de quien llama, o `AccessDenied`. `detail` va al
    /// diálogo: de qué cuenta —o cuentas— se trata.
    async fn authorize(
        &self,
        header: &Header<'_>,
        resource: &'static str,
        detail: &str,
    ) -> zbus::fdo::Result<()> {
        let sender = sender_of(header);
        let verdict = self.access.check(sender.as_deref(), resource, detail).await;
        match verdict {
            access::Verdict::Allowed => Ok(()),
            access::Verdict::Denied => Err(denied(resource)),
            access::Verdict::Failed(reason) => {
                tracing::info!("no se pudo preguntar por el permiso {resource}: {reason}");
                Err(denied(resource))
            }
        }
    }

    /// Después de que el permiso dijo que sí: el área se enciende si no lo
    /// estaba, y se le pide una vuelta.
    async fn activate_after_read(
        &self,
        area: &'static str,
        account_id: &str,
        account: &AreaAccount,
    ) {
        if account.active || !account.syncable {
            return;
        }
        match self
            .manager
            .activate_area(area, account_id, Consent::Granted)
            .await
        {
            Ok(true) => self.ask_for_sync(area, account_id),
            Ok(false) => {}
            Err(e) => tracing::warn!("no se pudo encender un área: {e}"),
        }
    }

    /// Lo que va antes de una lectura del calendario que junta todas las
    /// cuentas: las cuentas con calendario, `store.calendar` de quien llama
    /// —una sola pregunta, con sus nombres en el diálogo— y, recién entonces,
    /// el calendario de cada una encendido. Sin ninguna cuenta con calendario
    /// no se pregunta nada: no hay nada que leer ni que encender.
    async fn authorize_calendar_accounts(
        &self,
        header: &Header<'_>,
    ) -> zbus::fdo::Result<Vec<String>> {
        let accounts = self.manager.area_accounts(CALENDAR_AREA).await;
        if accounts.is_empty() {
            return Ok(Vec::new());
        }
        let names: Vec<&str> = accounts
            .iter()
            .map(|(_, account)| account.display_name.as_str())
            .collect();
        let detail = crate::ical::clipped(&names.join(", "), MAX_DIALOG_DETAIL);
        self.authorize(header, CALENDAR_RESOURCE, &detail).await?;
        for (account_id, account) in &accounts {
            self.activate_after_read(CALENDAR_AREA, account_id, account)
                .await;
        }
        Ok(accounts.into_iter().map(|(id, _)| id).collect())
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
            .area_account(CONTACTS_AREA, account_id)
            .await
            .map_err(to_fdo)?;
        self.authorize(header, CONTACTS_RESOURCE, &account.display_name)
            .await?;
        self.activate_after_read(CONTACTS_AREA, account_id, &account)
            .await;
        Ok(())
    }

    /// Le pide una vuelta ya a la sincronización de un área.
    fn ask_for_sync(&self, area: &str, account_id: &str) {
        let queue = match area {
            CONTACTS_AREA => &self.contacts,
            CALENDAR_AREA => &self.calendar,
            _ => &None,
        };
        if let Some(queue) = queue {
            if queue.try_send(account_id.to_string()).is_err() {
                tracing::debug!("ya hay bastantes pedidos de sincronización en la fila");
            }
        }
    }
}

/// Una página de `ListOccurrences`: como las de los contactos, y si algo de lo
/// que se expandió en el momento quedó afuera por un tope.
#[derive(Debug, Serialize)]
struct OccurrencePage {
    items: Vec<calendar_read::OccurrenceItem>,
    next_cursor: Option<String>,
    truncated: bool,
}

/// El filtro de calendarios de una cuenta: `Some(None)` si no hay filtro,
/// `Some(Some(números))` con los de esa cuenta, y `None` si el filtro nombra
/// calendarios y ninguno es de esa cuenta —no se lee—.
fn filter_for(calendars: &[GlobalId], account_id: &str) -> Option<Option<Vec<i64>>> {
    if calendars.is_empty() {
        return Some(None);
    }
    let mine: Vec<i64> = calendars
        .iter()
        .filter(|c| c.account_id == account_id)
        .map(|c| c.id)
        .collect();
    (!mine.is_empty()).then_some(Some(mine))
}

/// Junta las filas de todas las cuentas en una página: en orden, hasta
/// `limit` y hasta [`contacts_read::MAX_PAGE_BYTES`] de JSON **medido como se
/// manda**, con el cursor en la última que entró. Una fila que sola no entra
/// se saltea, y la lista sigue después de ella; el final es `next_cursor ==
/// null`.
fn paginate<T: Serialize>(
    mut rows: Vec<(ListCursor, T)>,
    limit: usize,
) -> (Vec<T>, Option<String>) {
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let mut items = Vec::new();
    let mut last: Option<ListCursor> = None;
    let mut bytes = 0usize;
    let mut more = false;
    let total = rows.len();
    for (seen, (position, item)) in rows.into_iter().enumerate() {
        let size = serde_json::to_string(&item)
            .map_or(usize::MAX, |json| json.len())
            .saturating_add(1);
        if items.len() == limit
            || (!items.is_empty() && bytes.saturating_add(size) > contacts_read::MAX_PAGE_BYTES)
        {
            more = true;
            break;
        }
        if size > contacts_read::MAX_PAGE_BYTES {
            tracing::warn!("una fila no entra en una página ({size} bytes) y no se lista");
            last = Some(position);
            more = seen + 1 < total;
            continue;
        }
        bytes += size;
        last = Some(position);
        items.push(item);
    }
    (items, if more { last.map(|c| c.encode()) } else { None })
}

/// El nombre único de quien mandó el mensaje. Lo pone el bus; en una conexión
/// punto a punto, lo que diga el otro lado (las pruebas).
fn sender_of(header: &Header<'_>) -> Option<String> {
    header.sender().map(|s| s.to_string())
}

fn denied(resource: &str) -> zbus::fdo::Error {
    let what = match resource {
        CALENDAR_RESOURCE => "el calendario guardado",
        _ => "los contactos guardados",
    };
    zbus::fdo::Error::AccessDenied(format!("sin permiso para leer {what} ({resource})"))
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

/// El error de un comando de control, **con texto fijo**, como el de una
/// lectura.
///
/// Los comandos de control no piden permiso, así que lo que contestan lo ve
/// cualquier proceso de la sesión. El texto entero de `Io`, `Settings` o del
/// llavero lleva rutas bajo `$HOME` y lo que dijo el llavero: va sólo al
/// diario, y por el bus sale [`StoreError::public_detail`].
fn to_fdo(error: StoreError) -> zbus::fdo::Error {
    match &error {
        StoreError::InvalidAccountId(_) | StoreError::UnknownAccount(_) => {
            zbus::fdo::Error::InvalidArgs(error.public_detail().into())
        }
        other => {
            tracing::warn!("un comando del almacén falló: {other}");
            zbus::fdo::Error::Failed(other.public_detail().into())
        }
    }
}

/// Lo que ve de `GetStatus` quien pregunta.
///
/// **Cualquiera**: el llavero, y por cuenta su identificador —que
/// `ListAccounts` del servicio de cuentas ya da a cualquiera—, el estado de la
/// base y el de cada área (contactos, calendario), como códigos fijos.
///
/// **Con el permiso de alguna de las áreas de una cuenta** (`allowed`: las
/// áreas cuyo `store.<área>` está concedido en la caché), en esa cuenta,
/// además: el texto de la base (`detail`, siempre fijo) y cuánto ocupa
/// (`size_bytes`). Y **en cada área cuyo permiso tiene**, su texto y su última
/// vuelta buena (`detail`, `last_synced_at`). Cuánto ocupa la base es cuánto
/// tiene la persona guardado, y cuándo se sincronizó dice cuándo usó la
/// cuenta: no es para cualquiera.
///
/// Ningún texto lleva rutas ni lo que escribió un servidor, en ningún caso:
/// son fijos desde `lifecycle.rs` y las sincronizaciones.
pub fn visible_status(status: &Status, allowed: &[&str]) -> serde_json::Value {
    let accounts: Vec<serde_json::Value> = status
        .accounts
        .iter()
        .map(|account| {
            let detailed = allowed.iter().any(|area| account.has_area(area));
            let mut entry = serde_json::json!({
                "account_id": account.account_id,
                "state": account.state,
            });
            if detailed {
                entry["detail"] = account.detail.clone().into();
                entry["size_bytes"] = account.size_bytes.into();
            }
            for area in SYNCED_AREAS {
                let Some(state) = account.area(area) else {
                    continue;
                };
                let mut shown = serde_json::json!({ "state": state.state });
                if allowed.contains(&area) && account.has_area(area) {
                    shown["detail"] = state.detail.clone().into();
                    shown["last_synced_at"] = state.last_synced_at.clone().into();
                }
                entry[area] = shown;
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
        let (contacts, contacts_pending) = mpsc::channel(PENDING_REQUESTS);
        let (calendar, calendar_pending) = mpsc::channel(PENDING_REQUESTS);
        let service = Self::serve(
            connection,
            manager,
            Some(contacts),
            Some(calendar),
            Arc::clone(&access),
        )
        .await?;
        service.watch_keyring();
        service.watch_departures(connection.clone(), access);
        service.forward_changes();
        service.sync_contacts(contacts_pending);
        service.sync_calendar(calendar_pending);
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
        tokio::spawn(Arc::new(ContactsScheduler::new(sync)).run(CONTACTS_TICK, requests));
    }

    /// La sincronización del calendario, en otra tarea: una revisión cada
    /// cinco minutos —que además corre la ventana si cambió el día—, una
    /// vuelta por cuenta cada quince, y cada `RequestSync`.
    fn sync_calendar(&self, requests: mpsc::Receiver<String>) {
        let emitter = self.emitter.clone();
        let notify = Arc::new(move || {
            let emitter = emitter.clone();
            tokio::spawn(async move {
                let _ = StoreApi::<SecretServiceKeys>::status_changed(&emitter).await;
            });
        });
        let sync = CalendarSync::new(
            Arc::clone(&self.manager),
            BrokerCredentials,
            Limits::DEFAULT,
            HttpPolicy::default(),
            notify,
        );
        tokio::spawn(Arc::new(CalendarScheduler::new(sync)).run(CALENDAR_TICK, requests));
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
        calendar: Option<mpsc::Sender<String>>,
        access: Arc<Access>,
    ) -> zbus::Result<Self> {
        connection
            .object_server()
            .at(
                PATH,
                StoreApi {
                    manager: Arc::clone(&manager),
                    contacts,
                    calendar,
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
    use crate::store::calendar::tests::{calendar, object, weekly, window};
    use crate::store::calendar::ObjectOp;
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
            capabilities: vec!["email".into()],
            needs_reauth,
        }
    }

    fn with_contacts(id: &str) -> broker::Account {
        let mut account = account(id, false);
        account.display_name = "Trabajo".into();
        account.capabilities.push("contacts".into());
        account
    }

    fn with_calendar(id: &str, name: &str) -> broker::Account {
        let mut account = account(id, false);
        account.display_name = name.into();
        account.capabilities.push("calendar".into());
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
        assert_eq!(accounts[1].capabilities, vec!["email"]);
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
        calendar_requests: mpsc::Sender<String>,
        calendar_pending: mpsc::Receiver<String>,
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
            let (calendar_requests, calendar_pending) = mpsc::channel(PENDING_REQUESTS);
            Self {
                temp,
                keys,
                manager,
                access: AccessFixture::new(answer).await,
                requests,
                pending,
                calendar_requests,
                calendar_pending,
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
                Some(self.calendar_requests.clone()),
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

        /// Un calendario con una reunión semanal, un evento suelto y dos
        /// tareas en una cuenta, escritos como los escribe la sincronización.
        async fn with_calendar_data(&self, account_id: &str, prefix: &str) {
            let prefix = prefix.to_string();
            self.manager
                .with_store(account_id, move |store| {
                    let cal = calendar(store, &format!("https://x/{prefix}/"));
                    let w = window();
                    let single = format!(
                        "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:{prefix}-a\r\n\
                         SUMMARY:Suelto {prefix}\r\nDTSTART:20260915T120000Z\r\n\
                         DURATION:PT1H\r\nLOCATION:Aula 3\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
                    );
                    let todo = |uid: &str, due: &str| {
                        format!(
                            "BEGIN:VCALENDAR\r\nBEGIN:VTODO\r\nUID:{uid}\r\nSUMMARY:{uid}\r\n\
                             DUE:{due}\r\nEND:VTODO\r\nEND:VCALENDAR\r\n"
                        )
                    };
                    store.apply_calendar_objects(
                        &cal,
                        &[
                            ObjectOp::Upsert(object(
                                &format!("https://x/{prefix}/s.ics"),
                                &weekly(&format!("{prefix}-s"), "20260907T090000Z"),
                                w,
                            )),
                            ObjectOp::Upsert(object(
                                &format!("https://x/{prefix}/a.ics"),
                                &single,
                                w,
                            )),
                            ObjectOp::Upsert(object(
                                &format!("https://x/{prefix}/t1.ics"),
                                &todo(&format!("{prefix}-pronto"), "20261001T100000Z"),
                                w,
                            )),
                            ObjectOp::Upsert(object(
                                &format!("https://x/{prefix}/t2.ics"),
                                &todo(&format!("{prefix}-tarde"), "20261201T100000Z"),
                                w,
                            )),
                        ],
                        w,
                        None,
                        crate::store::calendar::CalendarRoom::UNLIMITED,
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
                "GetEvent",
                "GetStatus",
                "ListAddressBooks",
                "ListCalendars",
                "ListContacts",
                "ListOccurrences",
                "ListTasks",
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
        // Una cuenta de sólo correo no tiene ningún área: no se enciende nada,
        // no se pide una vuelta ni se pregunta ningún permiso.
        assert!(api.pending.try_recv().is_err());
        assert!(api.calendar_pending.try_recv().is_err());
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

        // Un rechazo también ocupa el piso de `RequestSync` de la cuenta.
        api.access.permissions.set(Answer::Allow);
        api.access.clock.advance(access::SYNC_FLOOR);
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
        api.access.clock.advance(access::SYNC_FLOOR);
        call_unit(&other, "RequestSync", &("cuenta",))
            .await
            .unwrap();
        assert_eq!(api.access.permissions.calls(), asked);
    }

    /// La carrera de `RequestSync`: decide si pregunta con una mirada —la
    /// cuenta pide reautenticarse, así que no se encendería y no pregunta— y
    /// mientras pasa la tabla llega un `ListAccounts` en que ya no lo pide.
    /// Encender lo decide recién `activate_area`, y sin un «sí» no
    /// enciende: el área queda apagada y nadie preguntó nada.
    #[tokio::test]
    async fn pedir_una_vuelta_no_enciende_los_contactos_si_la_cuenta_cambia_en_el_medio() {
        let mut stale = with_contacts("cuenta");
        stale.needs_reauth = true;
        let mut api = Api::new("api-carrera", vec![stale], Answer::Allow).await;
        let (client, _service) = api.client(":1.7").await;
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        api.keys.state().pin_gate = Some(Arc::clone(&gate));

        let request = tokio::spawn({
            let client = client.clone();
            async move { call_unit(&client, "RequestSync", &("cuenta",)).await }
        });
        // La vuelta de `RequestSync` quedó detenida con la cerradura tomada.
        tokio::time::timeout(Duration::from_secs(5), async {
            while api.keys.state().pins_waiting == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("la vuelta no llegó al llavero");
        // Llega el listado nuevo y espera su turno, antes que el encendido.
        let relist = tokio::spawn({
            let manager = Arc::clone(&api.manager);
            async move {
                manager
                    .accounts_listed(
                        listing_from(&Ok(vec![with_contacts("cuenta")])),
                        Instant::now(),
                    )
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        gate.add_permits(100);

        request.await.unwrap().unwrap();
        relist.await.unwrap();
        assert!(
            api.manager
                .area_account(CONTACTS_AREA, "cuenta")
                .await
                .is_ok_and(|a| a.syncable),
            "la cuenta ya se podía sincronizar cuando se encendía"
        );
        assert!(
            !api.settings().is_active("cuenta", CONTACTS_AREA),
            "se encendió sin preguntar"
        );
        assert_eq!(api.access.permissions.calls(), 0);
        assert!(api.pending.try_recv().is_err());
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
            .set_area_status(
                CONTACTS_AREA,
                "cuenta",
                crate::store::lifecycle::AreaState::Synced,
                "",
            )
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

    /// Lo que contesta un comando de control que falló es un texto fijo: sin
    /// la ruta de `stores.json` ni nada bajo `$HOME`, que lo leería cualquier
    /// proceso de la sesión.
    #[tokio::test]
    async fn un_error_de_un_comando_no_lleva_rutas() {
        let mut api = Api::new("api-ruta", vec![account("cuenta", false)], Answer::Allow).await;
        let (client, _service) = api.client(":1.7").await;
        // Un directorio donde tendría que estar `stores.json`: leerlo falla, y
        // el error del disco lleva la ruta.
        let settings = api.temp.0.join("stores.json");
        let _ = std::fs::remove_file(&settings);
        std::fs::create_dir_all(settings.join("adentro")).unwrap();

        let result = call_unit(&client, "SetStoreEnabled", &("cuenta", false)).await;
        match &result {
            Err(zbus::Error::MethodError(name, Some(text), _)) => {
                assert!(name.as_str().ends_with(".Failed"));
                let root = api.temp.0.to_string_lossy().to_string();
                assert!(!text.contains(&root), "el texto lleva la ruta del almacén");
                assert!(!text.contains('/'), "el texto lleva una ruta");
            }
            other => panic!("tenía que fallar con Failed: {}", error_name(other)),
        }
    }

    /// El límite por llamante: la llamada de control que pasa el cupo contesta
    /// `LimitsExceeded`; otro nombre tiene el suyo.
    #[tokio::test]
    async fn el_limite_por_llamante_corta_la_llamada_siguiente() {
        let mut api = Api::new("api-limite", vec![account("cuenta", false)], Answer::Allow).await;
        let (client, _s1) = api.client(":1.7").await;
        // Separadas por el piso de la cuenta, para que corte el cupo.
        for _ in 0..access::CONTROL_BURST {
            call_unit(&client, "RequestSync", &("cuenta",))
                .await
                .unwrap();
            api.access.clock.advance(access::SYNC_FLOOR);
        }
        assert_eq!(
            error_name(&call_unit(&client, "RequestSync", &("cuenta",)).await),
            LIMITS_EXCEEDED
        );
        assert_eq!(
            error_name(&call_unit(&client, "ClearStore", &("cuenta",)).await),
            LIMITS_EXCEEDED
        );
        let (other, _s2) = api.client(":1.8").await;
        call_unit(&other, "ClearStore", &("cuenta",)).await.unwrap();
    }

    /// El piso por cuenta, por el bus: un segundo `ClearStore` de otra conexión
    /// dentro de los 10 s contesta `LimitsExceeded`; pasado el piso, entra.
    #[tokio::test]
    async fn vaciar_desde_otra_conexion_respeta_el_piso_por_cuenta() {
        let mut api = Api::new("api-piso", vec![account("cuenta", false)], Answer::Allow).await;
        let (first, _s1) = api.client(":1.7").await;
        let (second, _s2) = api.client(":1.8").await;
        call_unit(&first, "ClearStore", &("cuenta",)).await.unwrap();
        assert_eq!(
            error_name(&call_unit(&second, "ClearStore", &("cuenta",)).await),
            LIMITS_EXCEEDED
        );
        api.access.clock.advance(access::ACCOUNT_FLOOR);
        call_unit(&second, "ClearStore", &("cuenta",))
            .await
            .unwrap();
    }

    /// El piso de `RequestSync`, por el bus: otra conexión que pide una vuelta
    /// de la misma cuenta dentro de los 5 s contesta `LimitsExceeded`, y
    /// pasado el piso entra.
    #[tokio::test]
    async fn pedir_una_vuelta_desde_otra_conexion_respeta_el_piso_de_la_cuenta() {
        let mut api = Api::new(
            "api-piso-vuelta",
            vec![account("cuenta", false)],
            Answer::Allow,
        )
        .await;
        let (first, _s1) = api.client(":1.7").await;
        let (second, _s2) = api.client(":1.8").await;
        call_unit(&first, "RequestSync", &("cuenta",))
            .await
            .unwrap();
        assert_eq!(
            error_name(&call_unit(&second, "RequestSync", &("cuenta",)).await),
            LIMITS_EXCEEDED
        );
        api.access.clock.advance(access::SYNC_FLOOR);
        call_unit(&second, "RequestSync", &("cuenta",))
            .await
            .unwrap();
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

    // ── El calendario ───────────────────────────────────────────────────────

    type Occurrences = (String, String, Vec<String>, String, u32);

    fn occurrences(
        from: &str,
        to: &str,
        calendars: &[&str],
        cursor: &str,
        limit: u32,
    ) -> Occurrences {
        (
            from.into(),
            to.into(),
            calendars.iter().map(|c| c.to_string()).collect(),
            cursor.into(),
            limit,
        )
    }

    fn json(text: &str) -> serde_json::Value {
        serde_json::from_str(text).unwrap()
    }

    /// **Sin permiso, ningún dato del calendario**, en las cuatro lecturas:
    /// `AccessDenied`, el área no se enciende, y se pregunta una sola vez.
    #[tokio::test]
    async fn sin_permiso_ninguna_lectura_del_calendario_devuelve_datos() {
        let mut api = Api::new(
            "api-calendario-negado",
            vec![with_calendar("cuenta", "Trabajo")],
            Answer::Deny,
        )
        .await;
        api.with_calendar_data("cuenta", "c").await;
        let (client, _service) = api.client(":1.7").await;

        let results = [
            call(&client, "ListCalendars", &()).await,
            call(
                &client,
                "ListOccurrences",
                &occurrences("2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z", &[], "", 0),
            )
            .await,
            call(&client, "GetEvent", &("cuenta/1", "")).await,
            call(
                &client,
                "ListTasks",
                &(Vec::<String>::new(), true, "", 0u32),
            )
            .await,
        ];
        for result in &results {
            assert_eq!(error_name(result), ACCESS_DENIED);
        }
        assert_eq!(api.access.permissions.calls(), 1, "el «no» quedó guardado");
        assert!(!api.settings().is_active("cuenta", CALENDAR_AREA));
        assert!(api.calendar_pending.try_recv().is_err());
    }

    /// Con permiso: las cuatro lecturas del calendario, la paginación por el
    /// bus y el área encendida con la primera lectura. Una sola pregunta.
    #[tokio::test]
    async fn con_permiso_se_lee_el_calendario_y_se_enciende_el_area() {
        let mut api = Api::new(
            "api-calendario-lee",
            vec![with_calendar("cuenta", "Trabajo")],
            Answer::Allow,
        )
        .await;
        api.with_calendar_data("cuenta", "c").await;
        let (client, _service) = api.client(":1.7").await;

        let calendars = json(&call(&client, "ListCalendars", &()).await.unwrap());
        assert_eq!(calendars[0]["id"], "cuenta/1");
        assert_eq!(calendars[0]["account_id"], "cuenta");
        assert_eq!(calendars[0]["color"], "#FF0000");
        assert_eq!(
            calendars[0]["components"],
            serde_json::json!(["VEVENT", "VTODO"])
        );
        assert!(api.settings().is_active("cuenta", CALENDAR_AREA));
        assert_eq!(api.calendar_pending.try_recv().unwrap(), "cuenta");

        let range = ("2026-09-14T00:00:00Z", "2026-09-22T00:00:00Z");
        let first = json(
            &call(
                &client,
                "ListOccurrences",
                &occurrences(range.0, range.1, &[], "", 1),
            )
            .await
            .unwrap(),
        );
        assert_eq!(first["items"][0]["title"], "Semanal c-s");
        assert_eq!(first["items"][0]["start"], "2026-09-14T09:00:00+00:00");
        assert_eq!(first["items"][0]["calendar_id"], "cuenta/1");
        assert_eq!(first["truncated"], false);
        let mut titles = vec![first["items"][0]["title"].as_str().unwrap().to_string()];
        let mut cursor = first["next_cursor"].as_str().unwrap().to_string();
        loop {
            let page = json(
                &call(
                    &client,
                    "ListOccurrences",
                    &occurrences(range.0, range.1, &[], &cursor, 1),
                )
                .await
                .unwrap(),
            );
            titles.extend(
                page["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|i| i["title"].as_str().unwrap().to_string()),
            );
            match page["next_cursor"].as_str() {
                Some(next) => cursor = next.to_string(),
                None => break,
            }
        }
        assert_eq!(titles, vec!["Semanal c-s", "Suelto c", "Semanal c-s"]);

        let whole = json(
            &call(
                &client,
                "ListOccurrences",
                &occurrences(range.0, range.1, &[], "", 0),
            )
            .await
            .unwrap(),
        );
        let event_id = whole["items"][1]["event_id"].as_str().unwrap().to_string();
        let event = json(
            &call(&client, "GetEvent", &(event_id.as_str(), ""))
                .await
                .unwrap(),
        );
        assert_eq!(event["title"], "Suelto c");
        assert_eq!(event["location"], "Aula 3");
        assert!(event.get("raw_ical").is_none());
        assert!(!event.to_string().contains("https://x/"));

        let weekly_id = whole["items"][0]["event_id"].as_str().unwrap().to_string();
        let occurrence = whole["items"][2]["occurrence_id"]
            .as_str()
            .unwrap()
            .to_string();
        let instance = json(
            &call(
                &client,
                "GetEvent",
                &(weekly_id.as_str(), occurrence.as_str()),
            )
            .await
            .unwrap(),
        );
        assert_eq!(instance["start"], "2026-09-21T09:00:00+00:00");
        assert_eq!(instance["recurrence"]["frequency"], "weekly");
        assert_eq!(
            call(&client, "GetEvent", &("cuenta/999", ""))
                .await
                .unwrap(),
            "null"
        );

        let tasks = json(
            &call(
                &client,
                "ListTasks",
                &(Vec::<String>::new(), false, "", 0u32),
            )
            .await
            .unwrap(),
        );
        let names: Vec<&str> = tasks["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["title"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["c-pronto", "c-tarde"]);
        assert_eq!(tasks["items"][0]["due"], "2026-10-01T10:00:00+00:00");
        assert!(tasks["next_cursor"].is_null());

        assert_eq!(
            api.access.permissions.calls(),
            1,
            "una sola pregunta, guardada"
        );
    }

    /// `ListOccurrences` **junta todas las cuentas** con calendario, en orden,
    /// y el filtro por calendario nombra calendarios de cualquiera.
    #[tokio::test]
    async fn las_ocurrencias_juntan_todas_las_cuentas() {
        let mut api = Api::new(
            "api-calendario-cuentas",
            vec![
                with_calendar("cuenta", "Trabajo"),
                with_calendar("otra", "Casa"),
            ],
            Answer::Allow,
        )
        .await;
        api.with_calendar_data("cuenta", "c").await;
        api.with_calendar_data("otra", "o").await;
        let (client, _service) = api.client(":1.7").await;
        let range = ("2026-09-14T00:00:00Z", "2026-09-16T00:00:00Z");

        let all = json(
            &call(
                &client,
                "ListOccurrences",
                &occurrences(range.0, range.1, &[], "", 0),
            )
            .await
            .unwrap(),
        );
        let seen: Vec<(String, String)> = all["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| {
                (
                    i["start"].as_str().unwrap().to_string(),
                    i["event_id"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            vec![
                ("2026-09-14T09:00:00+00:00".into(), "cuenta/1".into()),
                ("2026-09-14T09:00:00+00:00".into(), "otra/1".into()),
                ("2026-09-15T12:00:00+00:00".into(), "cuenta/2".into()),
                ("2026-09-15T12:00:00+00:00".into(), "otra/2".into()),
            ]
        );
        // El detalle del diálogo nombra las dos cuentas.
        assert!(api.settings().is_active("otra", CALENDAR_AREA));

        let only = json(
            &call(
                &client,
                "ListOccurrences",
                &occurrences(range.0, range.1, &["otra/1"], "", 0),
            )
            .await
            .unwrap(),
        );
        assert_eq!(only["items"].as_array().unwrap().len(), 2);
        assert!(only["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["calendar_id"] == "otra/1"));
    }

    /// Un argumento del calendario que no se entiende es `InvalidArgs` antes
    /// de preguntar nada.
    #[tokio::test]
    async fn un_argumento_invalido_del_calendario_no_llega_a_preguntar() {
        let mut api = Api::new(
            "api-calendario-args",
            vec![with_calendar("cuenta", "Trabajo")],
            Answer::Allow,
        )
        .await;
        let (client, _service) = api.client(":1.7").await;
        let many: Vec<String> = (1..=101).map(|i| format!("cuenta/{i}")).collect();
        let results = [
            call(
                &client,
                "ListOccurrences",
                &occurrences("ayer", "hoy", &[], "", 0),
            )
            .await,
            call(
                &client,
                "ListOccurrences",
                &occurrences("2026-10-01T00:00:00Z", "2026-09-01T00:00:00Z", &[], "", 0),
            )
            .await,
            call(
                &client,
                "ListOccurrences",
                &occurrences("2026-01-01T00:00:00Z", "2027-06-01T00:00:00Z", &[], "", 0),
            )
            .await,
            call(
                &client,
                "ListOccurrences",
                &occurrences(
                    "2026-09-01T00:00:00Z",
                    "2026-10-01T00:00:00Z",
                    &["1"],
                    "",
                    0,
                ),
            )
            .await,
            call(
                &client,
                "ListOccurrences",
                &occurrences(
                    "2026-09-01T00:00:00Z",
                    "2026-10-01T00:00:00Z",
                    &[],
                    "basura",
                    0,
                ),
            )
            .await,
            call(
                &client,
                "ListOccurrences",
                &(
                    "2026-09-01T00:00:00Z".to_string(),
                    "2026-10-01T00:00:00Z".to_string(),
                    many,
                    String::new(),
                    0u32,
                ),
            )
            .await,
            call(&client, "GetEvent", &("1", "")).await,
            call(&client, "GetEvent", &("cuenta/1", "mañana")).await,
            call(&client, "GetEvent", &("desconocida/1", "")).await,
            call(
                &client,
                "ListTasks",
                &(vec!["../x/1".to_string()], false, "", 0u32),
            )
            .await,
            call(
                &client,
                "ListTasks",
                &(Vec::<String>::new(), false, "x", 0u32),
            )
            .await,
        ];
        for result in &results {
            assert_eq!(error_name(result), INVALID_ARGS);
        }
        assert_eq!(api.access.permissions.calls(), 0);
    }

    /// Sin ninguna cuenta con calendario no se pregunta nada: no hay nada que
    /// leer ni que encender.
    #[tokio::test]
    async fn sin_cuentas_con_calendario_no_se_pregunta_nada() {
        let mut api = Api::new(
            "api-calendario-vacio",
            vec![account("cuenta", false)],
            Answer::Deny,
        )
        .await;
        let (client, _service) = api.client(":1.7").await;
        assert_eq!(call(&client, "ListCalendars", &()).await.unwrap(), "[]");
        let empty = json(
            &call(
                &client,
                "ListOccurrences",
                &occurrences("2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z", &[], "", 0),
            )
            .await
            .unwrap(),
        );
        assert!(empty["items"].as_array().unwrap().is_empty());
        assert_eq!(api.access.permissions.calls(), 0);
    }

    /// Con el llavero bloqueado, leer el calendario da un error que lo dice.
    #[tokio::test]
    async fn leer_el_calendario_con_el_llavero_bloqueado_da_un_error_claro() {
        let mut api = Api::new(
            "api-calendario-bloqueado",
            vec![with_calendar("cuenta", "Trabajo")],
            Answer::Allow,
        )
        .await;
        api.with_calendar_data("cuenta", "c").await;
        let (client, _service) = api.client(":1.7").await;
        api.keys.state().locked = true;
        let result = call(
            &client,
            "ListOccurrences",
            &occurrences("2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z", &[], "", 0),
        )
        .await;
        match &result {
            Err(zbus::Error::MethodError(name, Some(text), _)) => {
                assert!(name.as_str().ends_with(".Failed"));
                assert!(text.contains("llavero está bloqueado"));
            }
            other => panic!("tenía que ser un error del almacén: {}", error_name(other)),
        }
    }

    /// **`GetStatus` con sólo `store.calendar`** muestra el detalle de la
    /// cuenta y el del calendario —no el de los contactos—; sin nada, la parte
    /// pública.
    #[tokio::test]
    async fn get_status_con_solo_el_calendario_muestra_el_detalle_de_la_cuenta() {
        let mut both = with_calendar("cuenta", "Trabajo");
        both.capabilities.push("contacts".into());
        let mut api = Api::new("api-estado-calendario", vec![both], Answer::Allow).await;
        let (reader, _s1) = api.client(":1.7").await;
        let (stranger, _s2) = api.client(":1.8").await;
        for area in SYNCED_AREAS {
            api.manager
                .set_area_status(
                    area,
                    "cuenta",
                    crate::store::lifecycle::AreaState::Synced,
                    "",
                )
                .await;
        }

        let public = status(&stranger).await;
        let account = &public["accounts"][0];
        assert_eq!(account["calendar"]["state"], "synced");
        assert!(account.get("size_bytes").is_none());
        assert!(account["calendar"].get("last_synced_at").is_none());

        call(&reader, "ListCalendars", &()).await.unwrap();
        let full = status(&reader).await;
        let account = &full["accounts"][0];
        assert!(account["size_bytes"].as_u64().unwrap() > 0);
        assert_eq!(account["detail"], "");
        assert!(account["calendar"]["last_synced_at"].is_string());
        assert!(
            account["contacts"].get("last_synced_at").is_none(),
            "el de los contactos pide store.contacts"
        );
        assert!(status(&stranger).await["accounts"][0]
            .get("size_bytes")
            .is_none());
        assert_eq!(api.access.permissions.calls(), 1);
    }

    /// `RequestSync` que encendería el calendario pide `store.calendar`: sin
    /// permiso no enciende nada; con permiso, lo enciende y pide la vuelta.
    #[tokio::test]
    async fn pedir_una_sincronizacion_que_enciende_el_calendario_pide_permiso() {
        let mut api = Api::new(
            "api-calendario-vuelta",
            vec![with_calendar("cuenta", "Trabajo")],
            Answer::Deny,
        )
        .await;
        let (denied, _s1) = api.client(":1.7").await;
        assert_eq!(
            error_name(&call_unit(&denied, "RequestSync", &("cuenta",)).await),
            ACCESS_DENIED
        );
        assert!(!api.settings().is_active("cuenta", CALENDAR_AREA));
        assert!(api.calendar_pending.try_recv().is_err());

        api.access.permissions.set(Answer::Allow);
        api.access.clock.advance(access::SYNC_FLOOR);
        let (allowed, _s2) = api.client(":1.8").await;
        call_unit(&allowed, "RequestSync", &("cuenta",))
            .await
            .unwrap();
        assert_eq!(api.calendar_pending.try_recv().unwrap(), "cuenta");
        assert!(api.settings().is_active("cuenta", CALENDAR_AREA));
        assert!(api.pending.try_recv().is_err(), "no tiene contactos");
    }

    /// Una cuenta con las dos áreas: si el permiso de una dice que no y el de
    /// la otra que sí, se enciende la que dijo que sí y no es un error.
    #[tokio::test]
    async fn pedir_una_vuelta_enciende_solo_el_area_que_tiene_permiso() {
        let mut both = with_calendar("cuenta", "Trabajo");
        both.capabilities.push("contacts".into());
        let mut api = Api::new("api-dos-areas", vec![both], Answer::Allow).await;
        api.access
            .permissions
            .set_for(CONTACTS_RESOURCE, Answer::Deny);
        let (client, _s) = api.client(":1.7").await;
        call_unit(&client, "RequestSync", &("cuenta",))
            .await
            .unwrap();
        assert!(api.settings().is_active("cuenta", CALENDAR_AREA));
        assert!(!api.settings().is_active("cuenta", CONTACTS_AREA));
        assert_eq!(api.calendar_pending.try_recv().unwrap(), "cuenta");
        assert!(api.pending.try_recv().is_err());
    }

    /// Un lote del calendario sale como `Changed` con el área `calendar`.
    #[tokio::test]
    async fn changed_del_calendario_sale_por_el_bus() {
        let mut api = Api::new(
            "api-calendario-changed",
            vec![with_calendar("cuenta", "Trabajo")],
            Answer::Allow,
        )
        .await;
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
        api.with_calendar_data("cuenta", "c").await;
        let (area, account_id, _) = next_changed(&mut signals).await;
        assert_eq!((area.as_str(), account_id.as_str()), ("calendar", "cuenta"));
    }
}
