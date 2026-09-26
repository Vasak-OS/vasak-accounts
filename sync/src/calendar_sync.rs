//! Mantener al día el calendario de cada cuenta en el almacén local: los
//! eventos (`VEVENT`) y las tareas (`VTODO`) de CalDAV, de sólo lectura hacia
//! el servidor.
//!
//! ── Cuándo ──────────────────────────────────────────────────────────────────
//!
//! Como los contactos (supuestos 1 y 2 de `vasak-accounts#23`): el área de
//! calendario de una cuenta **se enciende la primera vez que alguien la pide
//! con permiso** —una lectura de `AccountsStore`, o un `RequestSync` que la
//! encendería, con `store.calendar`— y desde ahí sigue sola, también después de
//! reiniciar. Cada cuenta encendida se sincroniza **cada
//! [`CALENDAR_INTERVAL`]** (quince minutos) y con cada `RequestSync`; la
//! revisión corre cada [`CALENDAR_TICK`], y con el llavero bloqueado no cuenta
//! como intento. Las tareas van con el calendario, con la misma capacidad y el
//! mismo permiso (supuesto 8).
//!
//! ── Cómo ────────────────────────────────────────────────────────────────────
//!
//! Lo mismo que los contactos, con las piezas de `dav_sync.rs`: la base abierta
//! o nada; la credencial con la capacidad `calendar`; los calendarios por
//! `PROPFIND` (los que ya no están se borran de a tandas, salvo que el listado
//! haya traído alguno de otro origen); por calendario, nada si su `getctag` no
//! cambió, y si no `sync-collection` desde el token —o `PROPFIND` de los ETag—,
//! `calendar-multiget` de a tandas, y **lotes de [`WRITE_BATCH_ROWS`] objetos
//! por transacción con el token en el último**. Cada escritura relee el
//! llavero.
//!
//! Lo que cambia es **qué se escribe**: cada objeto llega a la transacción con
//! sus ocurrencias ya expandidas en la ventana del almacén
//! ([`crate::store::calendar::Window`]), derivadas fuera del bucle de eventos
//! y fuera de la cerradura ([`derive_with_occurrences`], con los topes de
//! `ical/recurrence.rs`). La ventana es la que tiene la base; la primera vez, la
//! de hoy.
//!
//! ── La ventana que se corre ─────────────────────────────────────────────────
//!
//! En cada revisión, antes de las vueltas, cada cuenta encendida mira si la
//! ventana de su base es la de hoy ([`CalendarSync::shift_window`]). Si no —
//! una vez por día—, las series se vuelven a expandir desde `raw_ical`, sin
//! volver a la red: de a [`SHIFT_BATCH_ROWS`], la expansión fuera de la
//! cerradura y la escritura en una transacción por lote, y la ventana nueva
//! queda en la base con el último. Si eso cambió lo que se ve, sale `Changed`.
//!
//! ── Los topes de cada vuelta ────────────────────────────────────────────────
//!
//! Los de los contactos, adaptados ([`Limits`]): calendarios por cuenta,
//! objetos por calendario (mirado antes de escribir), el tamaño de un objeto,
//! los bytes de iCalendar crudo, las ocurrencias y los recordatorios guardados
//! de la cuenta —por el cambio neto de cada lote, medido en su transacción— y
//! el plazo de la vuelta. Pasar uno de la cuenta corta la vuelta sin guardar el token.

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::dav::caldav::{self, CalendarCollection, CalendarResource};
use crate::dav::webdav::{self, href_key, DavClient, DavCredential, DavError, HttpPolicy, Limits};
use crate::dav_sync::{
    self, AreaSync, CollectionCap, CredentialError, CredentialSource, ListedCollection, Plan,
    RoundError,
};
use crate::ical::recurrence::ExpansionLimits;
use crate::store::calendar::{
    derive_with_occurrences, shift_series, CalendarApplied, CalendarListing, CalendarProgress,
    CalendarRoom, ExpansionState, ObjectOp, ObjectRow, SeriesShift, StaleSeries, StoredCalendar,
    Window, SHIFT_BATCH_ROWS, WRITE_BATCH_ALARMS, WRITE_BATCH_BYTES, WRITE_BATCH_OCCURRENCES,
    WRITE_BATCH_ROWS,
};
use crate::store::key::{KeyError, KeySource};
use crate::store::lifecycle::{AreaState, StoreManager, CALENDAR_AREA};
use crate::store::{LogLevel, Store, StoreError};

/// Cada cuánto se sincroniza el calendario de una cuenta encendida (supuesto
/// 1 de `vasak-accounts#23`).
pub const CALENDAR_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Cada cuánto se mira qué cuentas toca sincronizar, y si la ventana se corrió.
pub const CALENDAR_TICK: Duration = crate::POLL_INTERVAL;

/// Lo que se ve en el estado cuando el servicio de cuentas dice que no.
const DENIED_DETAIL: &str = "el servicio de cuentas no le da al sincronizador permiso para el \
     calendario de esta cuenta: hace falta vasak-permissions 0.15.0 o posterior, y que la persona \
     lo permita en Configuración → Privacidad y seguridad";

/// Lo que se ve cuando la base no está abierta.
const CLOSED_DETAIL: &str =
    "la base no está abierta: se sincroniza cuando se desbloquee el llavero";

/// El reloj de la ventana. Uno inyectado en las pruebas.
pub type Clock = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// Lo que hizo una vuelta, para el diario y las pruebas.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CalendarReport {
    pub calendars: usize,
    /// Calendarios que no se tocaron porque su `getctag` no cambió.
    pub unchanged_calendars: usize,
    pub fetched: usize,
    pub removed: usize,
    /// Transacciones escritas.
    pub batches: usize,
    /// Tokens vencidos que llevaron a una sincronización completa.
    pub full_resyncs: usize,
    /// Calendarios que fueron por ETag porque el servidor no sabe
    /// `sync-collection`.
    pub etag_calendars: usize,
    /// Objetos que no se guardaron por pasar el tope de tamaño.
    pub too_large: usize,
    /// Direcciones de otro origen que se descartaron.
    pub foreign: usize,
    /// Objetos que vinieron en un `multiget` sin haberlos pedido.
    pub unrequested: usize,
    /// Objetos guardados cuya expansión pasó un tope o no se entendió: se
    /// guardaron con las ocurrencias que entraron, y quedan marcados.
    pub capped_series: usize,
}

/// Cómo terminó una vuelta de una cuenta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalendarOutcome {
    /// La base no estaba abierta: no se pidió nada. No cuenta como intento.
    StoreClosed,
    /// El servicio de cuentas no da permiso.
    Denied,
    Synced(CalendarReport),
    /// Con el texto que va al estado, sin direcciones ni datos.
    Failed(String),
}

/// Lo que puede cortar una vuelta.
#[derive(Debug)]
enum SyncError {
    Dav(DavError),
    Store(StoreError),
    Timeout,
    /// La cuenta pasaría el tope de bytes o de ocurrencias.
    AccountTooLarge,
    /// La ventana de la base cambió mientras se expandía un lote.
    WindowMoved,
}

impl From<DavError> for SyncError {
    fn from(error: DavError) -> Self {
        SyncError::Dav(error)
    }
}

impl From<StoreError> for SyncError {
    fn from(error: StoreError) -> Self {
        SyncError::Store(error)
    }
}

impl From<RoundError> for SyncError {
    fn from(error: RoundError) -> Self {
        match error {
            RoundError::Dav(e) => SyncError::Dav(e),
            RoundError::Timeout => SyncError::Timeout,
        }
    }
}

/// Lo que lleva una vuelta de una cuenta de calendario en calendario.
struct Round {
    report: CalendarReport,
    deadline: tokio::time::Instant,
    /// Los bytes de iCalendar crudo de la cuenta, con el cambio neto de cada
    /// lote.
    stored_bytes: u64,
    /// Las ocurrencias guardadas de la cuenta, igual.
    stored_occurrences: u64,
    /// Y los recordatorios.
    stored_alarms: u64,
    /// La ventana con la que se expande todo lo de esta vuelta.
    window: Window,
}

impl Round {
    fn check_deadline(&self) -> Result<(), SyncError> {
        Ok(dav_sync::check_deadline(self.deadline)?)
    }

    async fn net<T>(
        &self,
        request: impl Future<Output = Result<T, DavError>>,
    ) -> Result<T, SyncError> {
        Ok(dav_sync::net(self.deadline, request).await?)
    }
}

/// La sincronización del calendario de todas las cuentas.
pub struct CalendarSync<K: KeySource, C: CredentialSource> {
    manager: Arc<StoreManager<K>>,
    credentials: C,
    limits: Limits,
    expansion: ExpansionLimits,
    policy: HttpPolicy,
    notify: Arc<dyn Fn() + Send + Sync>,
    clock: Clock,
}

impl<K: KeySource, C: CredentialSource> CalendarSync<K, C> {
    pub fn new(
        manager: Arc<StoreManager<K>>,
        credentials: C,
        limits: Limits,
        policy: HttpPolicy,
        notify: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            manager,
            credentials,
            limits,
            expansion: ExpansionLimits::DEFAULT,
            policy,
            notify,
            clock: Arc::new(Utc::now),
        }
    }

    /// Con otro reloj para la ventana.
    #[cfg(test)]
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Con otros topes para la expansión.
    #[cfg(test)]
    pub fn with_expansion(mut self, expansion: ExpansionLimits) -> Self {
        self.expansion = expansion;
        self
    }

    async fn set_status(&self, account_id: &str, state: AreaState, detail: &str) {
        if self
            .manager
            .set_area_status(CALENDAR_AREA, account_id, state, detail)
            .await
        {
            (self.notify)();
        }
    }

    async fn store<T, F>(&self, account_id: &str, work: F) -> Result<T, SyncError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Store) -> Result<T, StoreError> + Send + 'static,
    {
        Ok(self.manager.with_store(account_id, work).await?)
    }

    /// Una vuelta de una cuenta, de punta a punta, con su estado.
    pub async fn sync_account(&self, account_id: &str) -> CalendarOutcome {
        // Antes de nada, y releyendo el llavero: con la base cerrada no se le
        // pide nada ni al servicio de cuentas ni al servidor.
        if !self
            .manager
            .prepare_for_sync(CALENDAR_AREA, account_id)
            .await
        {
            self.set_status(account_id, AreaState::Pending, CLOSED_DETAIL)
                .await;
            return CalendarOutcome::StoreClosed;
        }
        self.set_status(account_id, AreaState::Syncing, "").await;

        let credential = match self.credentials.credential(account_id, CALENDAR_AREA).await {
            Ok(credential) => credential,
            Err(CredentialError::Denied) => {
                tracing::info!("'{account_id}': sin permiso para el calendario");
                self.set_status(account_id, AreaState::Unavailable, DENIED_DETAIL)
                    .await;
                return CalendarOutcome::Denied;
            }
            Err(CredentialError::Failed(detail)) => {
                tracing::warn!(
                    "'{account_id}': no se obtuvo la credencial del calendario: {detail}"
                );
                let shown = "no se obtuvo la credencial de la cuenta del servicio de cuentas";
                self.set_status(account_id, AreaState::Failed, shown).await;
                return CalendarOutcome::Failed(shown.into());
            }
        };

        let outcome = match self.run(account_id, &credential).await {
            Ok(report) => {
                tracing::info!("'{account_id}': calendario al día: {report:?}");
                self.set_status(account_id, AreaState::Synced, "").await;
                CalendarOutcome::Synced(report)
            }
            Err(SyncError::Store(StoreError::Key(KeyError::Locked)))
            | Err(SyncError::Store(StoreError::Missing))
            | Err(SyncError::WindowMoved) => {
                tracing::info!("'{account_id}': la base se cerró a mitad de la sincronización");
                self.set_status(account_id, AreaState::Pending, CLOSED_DETAIL)
                    .await;
                CalendarOutcome::StoreClosed
            }
            Err(SyncError::Store(e)) => {
                tracing::warn!("'{account_id}': no se pudo guardar el calendario: {e}");
                let shown = "no se pudo guardar el calendario en el almacén";
                self.set_status(account_id, AreaState::Failed, shown).await;
                CalendarOutcome::Failed(shown.into())
            }
            Err(SyncError::Timeout) => {
                let minutes = self.limits.max_round.as_secs().div_ceil(60);
                tracing::warn!("'{account_id}': la vuelta pasó los {minutes} minutos y se cortó");
                let shown = format!(
                    "la sincronización del calendario tardó más de {minutes} minutos y se cortó; \
                     sigue en la próxima vuelta"
                );
                self.set_status(account_id, AreaState::Failed, &shown).await;
                CalendarOutcome::Failed(shown)
            }
            Err(SyncError::AccountTooLarge) => {
                let (bytes, occurrences, alarms) = (
                    self.limits.max_account_ical_bytes,
                    self.limits.max_account_occurrences,
                    self.limits.max_account_alarms,
                );
                tracing::warn!(
                    "'{account_id}': el calendario pasaría los {bytes} bytes, las {occurrences} \
                     ocurrencias o los {alarms} recordatorios"
                );
                let shown = format!(
                    "el calendario de la cuenta pasa lo que se guarda ({bytes} bytes, \
                     {occurrences} ocurrencias o {alarms} recordatorios); no se guardó lo que \
                     faltaba"
                );
                self.set_status(account_id, AreaState::Failed, &shown).await;
                CalendarOutcome::Failed(shown)
            }
            Err(SyncError::Dav(e)) => {
                tracing::warn!(
                    "'{account_id}': no se pudo sincronizar el calendario: {}",
                    e.log_text()
                );
                let shown = e.to_string();
                self.set_status(account_id, AreaState::Failed, &shown).await;
                CalendarOutcome::Failed(shown)
            }
        };
        drop(credential);
        outcome
    }

    async fn run(
        &self,
        account_id: &str,
        credential: &DavCredential,
    ) -> Result<CalendarReport, SyncError> {
        let client = DavClient::new(credential, self.limits, self.policy)?;
        let today = Window::around((self.clock)());
        let window = self
            .store(account_id, |s| s.calendar_window())
            .await?
            .unwrap_or(today);
        let mut round = Round {
            report: CalendarReport::default(),
            deadline: tokio::time::Instant::now() + self.limits.max_round,
            stored_bytes: 0,
            stored_occurrences: 0,
            stored_alarms: 0,
            window,
        };

        let mut seen = BTreeSet::new();
        let (calendars, foreign) = round.net(caldav::list_calendars(&client)).await?;
        round.report.foreign += foreign;
        let calendars: Vec<CalendarCollection> = calendars
            .into_iter()
            // Un calendario que el servidor nombra dos veces es uno.
            .filter(|c| seen.insert(href_key(&c.href)))
            .collect();
        round.report.calendars = calendars.len();
        let listed: Vec<CalendarListing> = calendars
            .iter()
            .map(|c| CalendarListing {
                href: href_key(&c.href),
                display_name: c.display_name.clone(),
                color: c.color.clone(),
                components: c.components.clone(),
            })
            .collect();

        // Los que ya no están, de a tandas, salvo que el listado haya traído
        // alguno de otro origen (como las libretas).
        let before = self.store(account_id, |s| s.calendars()).await?;
        if foreign > 0 {
            tracing::warn!(
                "'{account_id}': el listado trajo {foreign} calendarios de otro origen; no se \
                 borra ninguno en esta vuelta"
            );
        }
        for gone in before
            .iter()
            .filter(|_| foreign == 0)
            .filter(|c| !listed.iter().any(|l| l.href == c.href))
        {
            let id = gone.id;
            loop {
                round.check_deadline()?;
                let removed = self
                    .store(account_id, move |s| s.remove_calendar_chunk(id))
                    .await?;
                round.report.batches += 1;
                round.report.removed += removed;
                if removed == 0 {
                    break;
                }
            }
        }

        let stored = self
            .store(account_id, move |s| s.upsert_calendars(&listed))
            .await?;
        (
            round.stored_bytes,
            round.stored_occurrences,
            round.stored_alarms,
        ) = self
            .store(account_id, |s| {
                Ok((
                    s.calendar_raw_bytes()?,
                    s.occurrence_count()?,
                    s.alarm_count()?,
                ))
            })
            .await?;

        let mut first_error = None;
        for (calendar, stored) in calendars.iter().zip(stored) {
            match self
                .sync_calendar(account_id, &client, calendar, &stored, &mut round)
                .await
            {
                Ok(()) => {}
                Err(SyncError::Dav(e)) => {
                    tracing::warn!(
                        "'{account_id}': un calendario no se pudo sincronizar: {}",
                        e.log_text()
                    );
                    first_error.get_or_insert(e);
                }
                Err(other) => return Err(other),
            }
        }
        if round.report.capped_series > 0 {
            let message = format!(
                "{} objetos pasaron los topes de la expansión y se guardaron con las ocurrencias \
                 que entraron",
                round.report.capped_series
            );
            tracing::warn!("'{account_id}': {message}");
            let _ = self
                .store(account_id, move |s| {
                    s.log(LogLevel::Warn, Some(CALENDAR_AREA), &message)
                })
                .await;
        }
        match first_error {
            Some(e) => Err(SyncError::Dav(e)),
            None => Ok(round.report),
        }
    }

    async fn sync_calendar(
        &self,
        account_id: &str,
        client: &DavClient,
        calendar: &CalendarCollection,
        stored: &StoredCalendar,
        round: &mut Round,
    ) -> Result<(), SyncError> {
        if calendar.ctag.is_some() && calendar.ctag == stored.ctag {
            round.report.unchanged_calendars += 1;
            return Ok(());
        }

        let href = stored.href.clone();
        let calendar_id = stored.id;
        let (token, local) = self
            .store(account_id, move |s| {
                Ok((
                    s.calendar_sync_token(&href)?,
                    s.calendar_object_etags(calendar_id)?,
                ))
            })
            .await?;

        let mut counters = dav_sync::PlanCounters::default();
        let plan = dav_sync::plan_collection(
            client,
            ListedCollection {
                href: &calendar.href,
                ctag: calendar.ctag.as_deref(),
                sync_collection: calendar.sync_collection,
            },
            token,
            &local,
            CollectionCap {
                max: self.limits.max_objects_per_calendar,
                error: DavError::TooManyObjects,
            },
            &self.limits,
            round.deadline,
            &mut counters,
        )
        .await;
        round.report.full_resyncs += counters.full_resyncs;
        round.report.foreign += counters.foreign;
        round.report.etag_calendars += usize::from(counters.by_etag);
        let plan = plan?;

        self.execute(account_id, client, calendar, stored, plan, round)
            .await
    }

    /// Trae lo que hay que traer y escribe de a lotes; el último lleva el token.
    async fn execute(
        &self,
        account_id: &str,
        client: &DavClient,
        calendar: &CalendarCollection,
        stored: &StoredCalendar,
        plan: Plan,
        round: &mut Round,
    ) -> Result<(), SyncError> {
        let mut batch = Batch::default();
        round.report.removed += plan.delete.len();
        for href in plan.delete {
            batch.push(ObjectOp::Delete(href));
            if batch.full() {
                self.write(account_id, stored, &mut batch, None, round)
                    .await?;
            }
        }

        for chunk in plan.fetch.chunks(self.limits.multiget_batch.max(1)) {
            let objects = self.fetch_objects(client, calendar, chunk, round).await?;
            // Leer y expandir es CPU, y un objeto armado a propósito tarda:
            // fuera del bucle de eventos y fuera de la cerradura del almacén.
            // Y el plazo de la vuelta se mira entre objeto y objeto: una
            // tanda son cincuenta, y cada uno puede gastar su plazo entero.
            let (max_bytes, window, expansion, deadline) = (
                self.limits.max_ical_bytes,
                round.window,
                self.expansion,
                round.deadline.into_std(),
            );
            let (rows, too_large) = webdav::off_runtime(move || {
                Ok(rows_from(objects, max_bytes, window, &expansion, deadline))
            })
            .await?;
            // Si se pasó mientras derivaba, lo derivado a medias no se escribe.
            round.check_deadline()?;
            round.report.too_large += too_large;
            for row in rows {
                round.report.fetched += 1;
                if row.index.expansion != ExpansionState::Complete {
                    round.report.capped_series += 1;
                }
                batch.push(ObjectOp::Upsert(Box::new(row)));
                if batch.full() {
                    self.write(account_id, stored, &mut batch, None, round)
                        .await?;
                }
            }
        }

        // El último lote, aunque esté vacío: es el que guarda el token.
        let progress = CalendarProgress {
            token: plan.token,
            ctag: plan.ctag,
        };
        self.write(account_id, stored, &mut batch, Some(progress), round)
            .await
    }

    async fn write(
        &self,
        account_id: &str,
        stored: &StoredCalendar,
        batch: &mut Batch,
        finish: Option<CalendarProgress>,
        round: &mut Round,
    ) -> Result<(), SyncError> {
        round.check_deadline()?;
        let ops = batch.take();
        let room = CalendarRoom {
            bytes: self
                .limits
                .max_account_ical_bytes
                .saturating_sub(round.stored_bytes),
            occurrences: self
                .limits
                .max_account_occurrences
                .saturating_sub(round.stored_occurrences),
            alarms: self
                .limits
                .max_account_alarms
                .saturating_sub(round.stored_alarms),
        };
        let calendar = stored.clone();
        let window = round.window;
        let applied = self
            .store(account_id, move |s| {
                s.apply_calendar_objects(&calendar, &ops, window, finish.as_ref(), room)
            })
            .await?;
        match applied {
            CalendarApplied::Written {
                net_bytes,
                net_occurrences,
                net_alarms,
            } => {
                round.stored_bytes = round.stored_bytes.saturating_add_signed(net_bytes);
                round.stored_occurrences = round
                    .stored_occurrences
                    .saturating_add_signed(net_occurrences);
                round.stored_alarms = round.stored_alarms.saturating_add_signed(net_alarms);
            }
            CalendarApplied::OverCap => return Err(SyncError::AccountTooLarge),
            CalendarApplied::WindowMoved => return Err(SyncError::WindowMoved),
        }
        round.report.batches += 1;
        Ok(())
    }

    /// Una tanda de `multiget`. Si la respuesta pasa el tope, se parte en dos
    /// hasta llegar a un objeto solo, y ése se saltea.
    async fn fetch_objects(
        &self,
        client: &DavClient,
        calendar: &CalendarCollection,
        hrefs: &[url::Url],
        round: &mut Round,
    ) -> Result<Vec<CalendarResource>, SyncError> {
        let mut objects = Vec::new();
        let mut parts = vec![hrefs.to_vec()];
        while let Some(part) = parts.pop() {
            match round
                .net(caldav::multiget(client, &calendar.href, &part))
                .await
            {
                Ok(fetched) => {
                    round.report.unrequested += fetched.unrequested;
                    // Lo que pasaba el tope ya se descartó al leer la
                    // respuesta: acá no llega.
                    round.report.too_large += fetched.too_large;
                    objects.extend(fetched.items);
                }
                Err(SyncError::Dav(DavError::BodyTooLarge(_))) if part.len() > 1 => {
                    let (first, second) = part.split_at(part.len() / 2);
                    parts.push(second.to_vec());
                    parts.push(first.to_vec());
                }
                Err(SyncError::Dav(DavError::BodyTooLarge(_))) => round.report.too_large += 1,
                Err(e) => return Err(e),
            }
        }
        Ok(objects)
    }

    /// Corre la ventana de una cuenta si no es la de hoy: vuelve a expandir
    /// las series desde `raw_ical`, de a lotes, sin volver a la red. Devuelve
    /// si hizo algo. Con la base cerrada, o sin nada del calendario guardado,
    /// no hace nada.
    pub async fn shift_window(&self, account_id: &str) -> bool {
        let target = Window::around((self.clock)());
        let current = match self.store(account_id, |s| s.calendar_window()).await {
            Ok(Some(current)) => current,
            Ok(None) | Err(_) => return false,
        };
        if current == target {
            return false;
        }
        let deadline = tokio::time::Instant::now() + self.limits.max_round;
        let mut room = match self
            .store(account_id, |s| {
                Ok((s.occurrence_count()?, s.alarm_count()?))
            })
            .await
        {
            // Correr la ventana no cambia el crudo: los bytes no se miden.
            Ok((occurrences, alarms)) => CalendarRoom {
                occurrences: self
                    .limits
                    .max_account_occurrences
                    .saturating_sub(occurrences),
                alarms: self.limits.max_account_alarms.saturating_sub(alarms),
                ..CalendarRoom::UNLIMITED
            },
            Err(_) => return false,
        };
        let mut after = 0;
        loop {
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!("'{account_id}': correr la ventana tardó demasiado; sigue después");
                return true;
            }
            let stale = match self
                .store(account_id, move |s| {
                    s.stale_series(target, after, SHIFT_BATCH_ROWS)
                })
                .await
            {
                Ok(stale) => stale,
                Err(e) => {
                    tracing::info!("'{account_id}': la ventana no se pudo correr: {e:?}");
                    return true;
                }
            };
            let last = stale.len() < SHIFT_BATCH_ROWS;
            after = stale.last().map_or(after, |s| s.id);
            let expansion = self.expansion;
            let until = deadline.into_std();
            let shifts: Vec<SeriesShift> = match webdav::off_runtime(move || {
                Ok(shifts_until(&stale, target, &expansion, until))
            })
            .await
            {
                Ok(Some(shifts)) => shifts,
                Ok(None) => {
                    tracing::warn!(
                        "'{account_id}': correr la ventana tardó demasiado; sigue después"
                    );
                    return true;
                }
                Err(_) => return true,
            };
            let expansion = self.expansion;
            match self
                .store(account_id, move |s| {
                    s.apply_window_shift(target, &shifts, last, room, &expansion)
                })
                .await
            {
                Ok(CalendarApplied::Written {
                    net_occurrences,
                    net_alarms,
                    ..
                }) => {
                    room.occurrences = room.occurrences.saturating_add_signed(-net_occurrences);
                    room.alarms = room.alarms.saturating_add_signed(-net_alarms);
                }
                Ok(_) => {
                    tracing::warn!(
                        "'{account_id}': correr la ventana pasaría el tope de ocurrencias o de \
                         recordatorios"
                    );
                    return true;
                }
                Err(e) => {
                    tracing::info!("'{account_id}': la ventana no se pudo correr: {e:?}");
                    return true;
                }
            }
            if last {
                return true;
            }
        }
    }
}

/// Lo que se va juntando para el próximo lote.
#[derive(Default)]
struct Batch {
    ops: Vec<ObjectOp>,
    bytes: usize,
    occurrences: usize,
    alarms: usize,
}

impl Batch {
    fn push(&mut self, op: ObjectOp) {
        self.occurrences += op.occurrences();
        self.alarms += op.alarms();
        self.bytes += match &op {
            ObjectOp::Upsert(row) => row.raw_ical.len(),
            ObjectOp::Delete(href) => href.len(),
        };
        self.ops.push(op);
    }

    fn full(&self) -> bool {
        self.ops.len() >= WRITE_BATCH_ROWS
            || self.bytes >= WRITE_BATCH_BYTES
            || self.occurrences >= WRITE_BATCH_OCCURRENCES
            || self.alarms >= WRITE_BATCH_ALARMS
    }

    fn take(&mut self) -> Vec<ObjectOp> {
        self.bytes = 0;
        self.occurrences = 0;
        self.alarms = 0;
        std::mem::take(&mut self.ops)
    }
}

/// Lo que hay que escribir de unas series para la ventana nueva, o `None` si
/// el plazo pasó antes de terminar: cada una puede gastar el plazo de su
/// expansión, y una tanda son cien.
fn shifts_until(
    stale: &[StaleSeries],
    target: Window,
    expansion: &ExpansionLimits,
    deadline: std::time::Instant,
) -> Option<Vec<SeriesShift>> {
    let mut shifts = Vec::with_capacity(stale.len());
    for series in stale {
        if std::time::Instant::now() >= deadline {
            return None;
        }
        shifts.push(shift_series(series, target, expansion));
    }
    Some(shifts)
}

/// Lo que se guarda de unos objetos, y cuántos no, por pasar el tope. Deja de
/// derivar cuando pasa `deadline`: lo que queda no se deriva, y quien llama
/// corta la vuelta.
///
/// El tope ya se miró al leer cada respuesta del `multiget` (N8): lo que lo
/// pasa no llega hasta acá. Se vuelve a mirar por si alguien arma objetos por
/// otro camino.
fn rows_from(
    objects: Vec<CalendarResource>,
    max_bytes: usize,
    window: Window,
    expansion: &ExpansionLimits,
    deadline: std::time::Instant,
) -> (Vec<ObjectRow>, usize) {
    let mut too_large = 0;
    let rows = objects
        .into_iter()
        .take_while(|_| std::time::Instant::now() < deadline)
        .filter_map(|object| {
            if object.data.len() > max_bytes {
                too_large += 1;
                return None;
            }
            let (index, occurrences) = derive_with_occurrences(&object.data, window, expansion);
            Some(ObjectRow {
                // Se guarda por su clave, que es con la que lo comparan el
                // listado y el `multiget` de la vuelta siguiente.
                href: href_key(&object.href),
                etag: object.etag,
                raw_ical: object.data,
                index,
                occurrences,
            })
        })
        .collect();
    (rows, too_large)
}

// ---------------------------------------------------------------------------
// Cuándo
// ---------------------------------------------------------------------------

/// Decide cuándo le toca a cada cuenta: el de `dav_sync.rs`, con el
/// calendario.
pub type CalendarScheduler<K, C> = dav_sync::DavScheduler<CalendarSync<K, C>>;

impl<K: KeySource, C: CredentialSource> AreaSync for CalendarSync<K, C> {
    fn interval(&self) -> Duration {
        CALENDAR_INTERVAL
    }

    async fn targets(&self) -> Vec<String> {
        self.manager.area_targets(CALENDAR_AREA).await
    }

    async fn attempt(&self, account_id: &str) -> bool {
        self.sync_account(account_id).await != CalendarOutcome::StoreClosed
    }

    /// La ventana de cada cuenta encendida, si el día cambió.
    async fn maintain(&self) {
        for account_id in self.manager.area_targets(CALENDAR_AREA).await {
            self.shift_window(&account_id).await;
        }
    }
}

#[cfg(test)]
mod tests;
