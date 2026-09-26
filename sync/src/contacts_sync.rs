//! Mantener al día los contactos de cada cuenta en el almacén local.
//!
//! ── Cuándo ──────────────────────────────────────────────────────────────────
//!
//! El área de contactos de una cuenta **se enciende la primera vez que alguien
//! la pide** —`RequestSync(account_id)` de `AccountsStore`— y desde ahí sigue
//! sola, también después de reiniciar (queda en `stores.json`). Sólo cuentas con
//! la capacidad `contacts` y que no piden reautenticarse.
//!
//! Cada cuenta encendida se sincroniza **cada [`CONTACTS_INTERVAL`]** (una
//! hora), y además cada vez que llega un `RequestSync`. La revisión corre cada
//! [`CONTACTS_TICK`], pero sólo cuenta como intento lo que llegó a pedir algo:
//! con el llavero bloqueado no se pide nada, y apenas se desbloquea la cuenta
//! entra en la próxima revisión. Un `AccessDenied` sí cuenta: se ve
//! `unavailable` y **no se vuelve a preguntar hasta la hora siguiente** o un
//! `RequestSync` (y dos `RequestSync` seguidos de la misma cuenta, con menos de
//! [`crate::dav_sync::REQUEST_COOLDOWN`] entre ellos, son uno).
//!
//! ── Cómo ────────────────────────────────────────────────────────────────────
//!
//! 1. **La base tiene que estar abierta.** Se pasa la tabla del ciclo de vida
//!    releyendo el llavero; si quedó cerrada, no se pide nada a nadie.
//! 2. La credencial, al servicio de cuentas, con la capacidad `contacts`
//!    (`GetAccessToken` y `GetAccountData`), como cualquier aplicación.
//! 3. Las libretas por `PROPFIND`. Las que ya no están se borran de a tandas.
//! 4. Por libreta, si su `getctag` no cambió desde la última vuelta completa,
//!    nada. Si no, **`sync-collection`** (RFC 6578) desde el token guardado —sin
//!    token es la carga inicial—: lo que vino con `404` se borra, lo que cambió
//!    de ETag se trae con `addressbook-multiget` de a tandas. Un token vencido
//!    se tira y se hace la sincronización completa. Si el servidor no sabe
//!    `sync-collection`, `PROPFIND` de los ETag y se compara con lo guardado.
//! 5. Todo se escribe **de a [`WRITE_BATCH_ROWS`] contactos por transacción**, y
//!    el token nuevo va en la misma transacción que el último lote. Si algo se
//!    corta a mitad, el token es el de antes y la próxima vuelta repite.
//!
//! Cada escritura vuelve a mirar el llavero: si se bloqueó a mitad de camino,
//! no se escribe nada más y la vuelta se corta.
//!
//! Y cada vuelta tiene dos topes que la cortan entera, como fallida y sin
//! guardar el token: un plazo ([`Limits::max_round`], diez minutos), para que
//! un servidor lento no deje esperando a las otras cuentas, y los bytes de
//! tarjetas crudas de la cuenta ([`Limits::max_account_vcard_bytes`], un
//! gigabyte), con el cambio neto de cada lote medido antes de guardarlo: una
//! tarjeta reescrita cuenta la diferencia y una borrada resta.

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use crate::dav::carddav::{self, AddressBook, CardResource};
use crate::dav::webdav::{self, href_key, DavClient, DavCredential, DavError, HttpPolicy, Limits};
use crate::dav_sync::{self, AreaSync, CollectionCap, ListedCollection, Plan, RoundError};
// La credencial y cuándo le toca a cada cuenta son de las dos
// sincronizaciones: viven en `dav_sync.rs`.
pub use crate::dav_sync::{BrokerCredentials, CredentialError, CredentialSource};
use crate::store::contacts::{
    Applied, BookProgress, ContactOp, ContactRow, StoredAddressBook, WRITE_BATCH_BYTES,
    WRITE_BATCH_ROWS,
};
use crate::store::key::{KeyError, KeySource};
use crate::store::lifecycle::{AreaState, StoreManager, CONTACTS_AREA};
use crate::store::{Store, StoreError};
use crate::vcard;

/// Cada cuánto se sincronizan los contactos de una cuenta encendida (supuesto
/// 1 de `vasak-accounts#23`).
pub const CONTACTS_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Cada cuánto se mira qué cuentas toca sincronizar.
pub const CONTACTS_TICK: Duration = crate::POLL_INTERVAL;

/// Lo que se ve en el estado cuando el servicio de cuentas dice que no.
const DENIED_DETAIL: &str = "el servicio de cuentas no le da al sincronizador permiso para los \
     contactos de esta cuenta: hace falta vasak-permissions 0.15.0 o posterior, y que la persona \
     lo permita en Configuración → Privacidad y seguridad";

/// Lo que se ve cuando la base no está abierta.
const CLOSED_DETAIL: &str =
    "la base no está abierta: se sincroniza cuando se desbloquee el llavero";

// ---------------------------------------------------------------------------
// Una vuelta
// ---------------------------------------------------------------------------

/// Lo que hizo una vuelta, para el diario y las pruebas.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub books: usize,
    /// Libretas que no se tocaron porque su `getctag` no cambió.
    pub unchanged_books: usize,
    pub fetched: usize,
    pub removed: usize,
    /// Transacciones escritas.
    pub batches: usize,
    /// Tokens vencidos que llevaron a una sincronización completa.
    pub full_resyncs: usize,
    /// Libretas que fueron por ETag porque el servidor no sabe
    /// `sync-collection`.
    pub etag_books: usize,
    /// Tarjetas que no se guardaron por pasar el tope de tamaño.
    pub too_large: usize,
    /// Direcciones de otro origen que se descartaron.
    pub foreign: usize,
    /// Tarjetas que vinieron en un `multiget` sin haberlas pedido, o
    /// repetidas: no se guardan.
    pub unrequested: usize,
}

/// Cómo terminó una vuelta de una cuenta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// La base no estaba abierta: no se pidió nada. No cuenta como intento.
    StoreClosed,
    /// El servicio de cuentas no da permiso.
    Denied,
    Synced(SyncReport),
    /// Con el texto que va al estado, sin direcciones ni datos.
    Failed(String),
}

/// Lo que puede cortar una vuelta.
#[derive(Debug)]
enum SyncError {
    Dav(DavError),
    Store(StoreError),
    /// La vuelta pasó [`Limits::max_round`]. Corta la vuelta entera.
    Timeout,
    /// Las tarjetas de la cuenta pasarían [`Limits::max_account_vcard_bytes`].
    /// Corta la vuelta entera: las otras libretas suman al mismo tope.
    AccountTooLarge,
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

/// Lo que lleva una vuelta de una cuenta de libreta en libreta.
struct Round {
    report: SyncReport,
    /// Hasta cuándo puede seguir: cada pedido a la red espera como mucho hasta
    /// acá, y después de esto no se escribe nada más.
    ///
    /// Un plazo que se mira en cada paso y no un `timeout` sobre la vuelta
    /// entera: cortar desde afuera suelta el futuro de `with_store` a mitad de
    /// un lote, con la base prestada al hilo que escribe, y el lote —el último
    /// lleva el token— se termina de escribir igual. Así, lo que se corta es
    /// un pedido a la red o un lote que todavía no empezó.
    deadline: tokio::time::Instant,
    /// Los bytes de tarjetas crudas de la cuenta: los guardados después de
    /// borrar las libretas que ya no están, más el cambio neto de cada lote de
    /// esta vuelta, que mide el almacén dentro de la misma transacción (ver
    /// `Store::apply_contacts`). Una tarjeta reescrita cuenta la diferencia y
    /// una borrada resta: contarla dos veces hacía que la carga completa de una
    /// cuenta por encima de la mitad del tope fallara siempre.
    stored_bytes: u64,
}

impl Round {
    fn check_deadline(&self) -> Result<(), SyncError> {
        Ok(dav_sync::check_deadline(self.deadline)?)
    }

    /// Un pedido a la red, con lo que le queda de plazo a la vuelta.
    async fn net<T>(
        &self,
        request: impl Future<Output = Result<T, DavError>>,
    ) -> Result<T, SyncError> {
        Ok(dav_sync::net(self.deadline, request).await?)
    }
}

/// La sincronización de contactos de todas las cuentas.
pub struct ContactsSync<K: KeySource, C: CredentialSource> {
    manager: Arc<StoreManager<K>>,
    credentials: C,
    limits: Limits,
    policy: HttpPolicy,
    /// Lo que se llama cuando cambia el estado que se publica: la señal
    /// `StatusChanged`.
    notify: Arc<dyn Fn() + Send + Sync>,
}

impl<K: KeySource, C: CredentialSource> ContactsSync<K, C> {
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
            policy,
            notify,
        }
    }

    async fn set_status(&self, account_id: &str, state: AreaState, detail: &str) {
        if self
            .manager
            .set_area_status(CONTACTS_AREA, account_id, state, detail)
            .await
        {
            (self.notify)();
        }
    }

    /// Una vuelta de una cuenta, de punta a punta, con su estado.
    pub async fn sync_account(&self, account_id: &str) -> SyncOutcome {
        // Antes de nada, y releyendo el llavero: con la base cerrada no se le
        // pide nada ni al servicio de cuentas ni al servidor.
        if !self
            .manager
            .prepare_for_sync(CONTACTS_AREA, account_id)
            .await
        {
            self.set_status(account_id, AreaState::Pending, CLOSED_DETAIL)
                .await;
            return SyncOutcome::StoreClosed;
        }
        self.set_status(account_id, AreaState::Syncing, "").await;

        let credential = match self.credentials.credential(account_id, CONTACTS_AREA).await {
            Ok(credential) => credential,
            Err(CredentialError::Denied) => {
                tracing::info!("'{account_id}': sin permiso para los contactos");
                self.set_status(account_id, AreaState::Unavailable, DENIED_DETAIL)
                    .await;
                return SyncOutcome::Denied;
            }
            Err(CredentialError::Failed(detail)) => {
                tracing::warn!(
                    "'{account_id}': no se obtuvo la credencial de los contactos: {detail}"
                );
                let shown = "no se obtuvo la credencial de la cuenta del servicio de cuentas";
                self.set_status(account_id, AreaState::Failed, shown).await;
                return SyncOutcome::Failed(shown.into());
            }
        };

        let outcome = match self.run(account_id, &credential).await {
            Ok(report) => {
                tracing::info!("'{account_id}': contactos al día: {report:?}");
                self.set_status(account_id, AreaState::Synced, "").await;
                SyncOutcome::Synced(report)
            }
            Err(SyncError::Store(StoreError::Key(KeyError::Locked)))
            | Err(SyncError::Store(StoreError::Missing)) => {
                tracing::info!("'{account_id}': la base se cerró a mitad de la sincronización");
                self.set_status(account_id, AreaState::Pending, CLOSED_DETAIL)
                    .await;
                SyncOutcome::StoreClosed
            }
            Err(SyncError::Store(e)) => {
                tracing::warn!("'{account_id}': no se pudieron guardar los contactos: {e}");
                let shown = "no se pudieron guardar los contactos en el almacén";
                self.set_status(account_id, AreaState::Failed, shown).await;
                SyncOutcome::Failed(shown.into())
            }
            Err(SyncError::Timeout) => {
                let minutes = self.limits.max_round.as_secs().div_ceil(60);
                tracing::warn!("'{account_id}': la vuelta pasó los {minutes} minutos y se cortó");
                let shown = format!(
                    "la sincronización de los contactos tardó más de {minutes} minutos y se cortó; \
                     sigue en la próxima vuelta"
                );
                self.set_status(account_id, AreaState::Failed, &shown).await;
                SyncOutcome::Failed(shown)
            }
            Err(SyncError::AccountTooLarge) => {
                let cap = self.limits.max_account_vcard_bytes;
                tracing::warn!(
                    "'{account_id}': las tarjetas de la cuenta pasarían los {cap} bytes"
                );
                let shown = format!(
                    "los contactos de la cuenta pasan los {cap} bytes que se guardan; no se \
                     guardaron los que faltaban"
                );
                self.set_status(account_id, AreaState::Failed, &shown).await;
                SyncOutcome::Failed(shown)
            }
            Err(SyncError::Dav(e)) => {
                tracing::warn!(
                    "'{account_id}': no se pudieron sincronizar los contactos: {}",
                    e.log_text()
                );
                // El texto de `DavError` es fijo, sin direcciones ni nada del
                // servidor: se puede mostrar. El detalle se quedó en el diario.
                let shown = e.to_string();
                self.set_status(account_id, AreaState::Failed, &shown).await;
                SyncOutcome::Failed(shown)
            }
        };
        drop(credential);
        outcome
    }

    async fn store<T, F>(&self, account_id: &str, work: F) -> Result<T, SyncError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Store) -> Result<T, StoreError> + Send + 'static,
    {
        Ok(self.manager.with_store(account_id, work).await?)
    }

    async fn run(
        &self,
        account_id: &str,
        credential: &DavCredential,
    ) -> Result<SyncReport, SyncError> {
        let client = DavClient::new(credential, self.limits, self.policy)?;
        let mut round = Round {
            report: SyncReport::default(),
            deadline: tokio::time::Instant::now() + self.limits.max_round,
            stored_bytes: 0,
        };

        let mut seen = BTreeSet::new();
        let (books, foreign) = round.net(carddav::list_address_books(&client)).await?;
        round.report.foreign += foreign;
        let books: Vec<AddressBook> = books
            .into_iter()
            // Una libreta que el servidor nombra dos veces es una.
            .filter(|b| seen.insert(href_key(&b.href)))
            .collect();
        round.report.books = books.len();
        let listed: Vec<(String, String)> = books
            .iter()
            .map(|b| (href_key(&b.href), b.display_name.clone()))
            .collect();

        // Las libretas que ya no están, de a tandas. **Salvo que el listado haya
        // traído alguna de otro origen**: un servidor que pasa a contestar con
        // URLs absolutas de otro nombre de máquina —un alias, `www.`, un proxy
        // mal configurado— haría que todas «ya no estén», y se irían con sus
        // contactos mientras dure el error. Esa vuelta no borra ninguna.
        let before = self.store(account_id, |s| s.address_books()).await?;
        if foreign > 0 {
            tracing::warn!(
                "'{account_id}': el listado trajo {foreign} libretas de otro origen; no se borra \
                 ninguna en esta vuelta"
            );
        }
        for gone in before
            .iter()
            .filter(|_| foreign == 0)
            .filter(|b| !listed.iter().any(|(href, _)| href == &b.href))
        {
            let id = gone.id;
            loop {
                round.check_deadline()?;
                let removed = self
                    .store(account_id, move |s| s.remove_address_book_chunk(id))
                    .await?;
                round.report.batches += 1;
                round.report.removed += removed;
                if removed == 0 {
                    break;
                }
            }
        }

        let stored = self
            .store(account_id, move |s| s.upsert_address_books(&listed))
            .await?;
        // Después de borrar las libretas que se fueron: lo suyo ya no ocupa.
        round.stored_bytes = self.store(account_id, |s| s.contacts_raw_bytes()).await?;

        // Una libreta que falla no frena a las otras; la vuelta se da por
        // fallida con el primer error del servidor. Uno del almacén sí corta:
        // es la base cerrada o el disco, y las otras van a dar lo mismo.
        let mut first_error = None;
        for (book, stored) in books.iter().zip(stored) {
            match self
                .sync_book(account_id, &client, book, &stored, &mut round)
                .await
            {
                Ok(()) => {}
                Err(SyncError::Dav(e)) => {
                    tracing::warn!(
                        "'{account_id}': una libreta no se pudo sincronizar: {}",
                        e.log_text()
                    );
                    first_error.get_or_insert(e);
                }
                Err(store) => return Err(store),
            }
        }
        match first_error {
            Some(e) => Err(SyncError::Dav(e)),
            None => Ok(round.report),
        }
    }

    async fn sync_book(
        &self,
        account_id: &str,
        client: &DavClient,
        book: &AddressBook,
        stored: &StoredAddressBook,
        round: &mut Round,
    ) -> Result<(), SyncError> {
        if book.ctag.is_some() && book.ctag == stored.ctag {
            round.report.unchanged_books += 1;
            return Ok(());
        }

        let href = stored.href.clone();
        let book_id = stored.id;
        let (token, local) = self
            .store(account_id, move |s| {
                Ok((s.contacts_sync_token(&href)?, s.contact_etags(book_id)?))
            })
            .await?;

        let mut counters = dav_sync::PlanCounters::default();
        let plan = dav_sync::plan_collection(
            client,
            ListedCollection {
                href: &book.href,
                ctag: book.ctag.as_deref(),
                sync_collection: book.sync_collection,
            },
            token,
            &local,
            CollectionCap {
                max: self.limits.max_cards_per_book,
                error: DavError::TooManyCards,
            },
            &self.limits,
            round.deadline,
            &mut counters,
        )
        .await;
        round.report.full_resyncs += counters.full_resyncs;
        round.report.foreign += counters.foreign;
        round.report.etag_books += usize::from(counters.by_etag);
        let plan = plan?;

        self.execute(account_id, client, book, stored, plan, round)
            .await
    }

    /// Trae lo que hay que traer y escribe de a lotes; el último lleva el token.
    async fn execute(
        &self,
        account_id: &str,
        client: &DavClient,
        book: &AddressBook,
        stored: &StoredAddressBook,
        plan: Plan,
        round: &mut Round,
    ) -> Result<(), SyncError> {
        let mut pending: Vec<ContactOp> = Vec::new();
        let mut pending_bytes = 0;
        round.report.removed += plan.delete.len();
        for href in plan.delete {
            pending_bytes += href.len();
            pending.push(ContactOp::Delete(href));
            if pending.len() >= WRITE_BATCH_ROWS {
                self.write(account_id, stored, &mut pending, None, round)
                    .await?;
                pending_bytes = 0;
            }
        }

        for chunk in plan.fetch.chunks(self.limits.multiget_batch.max(1)) {
            let cards = self.fetch_cards(client, book, chunk, round).await?;
            // Desarmar las tarjetas es CPU, y una armada a propósito tarda: fuera
            // del bucle de eventos.
            let max_vcard_bytes = self.limits.max_vcard_bytes;
            let (rows, too_large) =
                webdav::off_runtime(move || Ok(rows_from(cards, max_vcard_bytes))).await?;
            round.report.too_large += too_large;
            for row in rows {
                round.report.fetched += 1;
                pending_bytes += row.raw_vcard.len();
                pending.push(ContactOp::Upsert(Box::new(row)));
                if pending.len() >= WRITE_BATCH_ROWS || pending_bytes >= WRITE_BATCH_BYTES {
                    self.write(account_id, stored, &mut pending, None, round)
                        .await?;
                    pending_bytes = 0;
                }
            }
        }

        // El último lote, aunque esté vacío: es el que guarda el token.
        let progress = BookProgress {
            token: plan.token,
            ctag: plan.ctag,
        };
        self.write(account_id, stored, &mut pending, Some(progress), round)
            .await
    }

    async fn write(
        &self,
        account_id: &str,
        stored: &StoredAddressBook,
        pending: &mut Vec<ContactOp>,
        finish: Option<BookProgress>,
        round: &mut Round,
    ) -> Result<(), SyncError> {
        round.check_deadline()?;
        let ops = std::mem::take(pending);
        // El almacén mide el cambio neto del lote en la misma transacción: si
        // pasa el tope, no escribe nada, y el token —que va con el último— no
        // se guarda.
        let room = self
            .limits
            .max_account_vcard_bytes
            .saturating_sub(round.stored_bytes);
        let book = stored.clone();
        let applied = self
            .store(account_id, move |s| {
                s.apply_contacts(&book, &ops, finish.as_ref(), room)
            })
            .await?;
        match applied {
            Applied::Written { net_bytes } => {
                round.stored_bytes = round.stored_bytes.saturating_add_signed(net_bytes);
            }
            Applied::OverCap => return Err(SyncError::AccountTooLarge),
        }
        round.report.batches += 1;
        Ok(())
    }

    /// Una tanda de `multiget`. Si la respuesta pasa el tope, se parte en dos
    /// hasta llegar a una tarjeta sola, y ésa se saltea: una tarjeta enorme no
    /// puede trabar la libreta entera para siempre.
    async fn fetch_cards(
        &self,
        client: &DavClient,
        book: &AddressBook,
        hrefs: &[url::Url],
        round: &mut Round,
    ) -> Result<Vec<CardResource>, SyncError> {
        let mut cards = Vec::new();
        let mut parts = vec![hrefs.to_vec()];
        while let Some(part) = parts.pop() {
            match round
                .net(carddav::multiget(client, &book.href, &part))
                .await
            {
                Ok(fetched) => {
                    round.report.unrequested += fetched.unrequested;
                    // Lo que pasaba el tope ya se descartó al leer la
                    // respuesta: acá no llega.
                    round.report.too_large += fetched.too_large;
                    cards.extend(fetched.items);
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
        Ok(cards)
    }
}

/// Lo que se guarda de unas tarjetas, y cuántas no, por pasar el tope. El tope
/// ya se miró al leer cada respuesta del `multiget` (N8): se vuelve a mirar por
/// si alguien arma tarjetas por otro camino.
fn rows_from(cards: Vec<CardResource>, max_vcard_bytes: usize) -> (Vec<ContactRow>, usize) {
    let mut too_large = 0;
    let rows = cards
        .into_iter()
        .filter_map(|card| {
            if card.data.len() > max_vcard_bytes {
                too_large += 1;
                return None;
            }
            row_from(card)
        })
        .collect();
    (rows, too_large)
}

/// Lo que se guarda de una tarjeta, o nada si no es una.
fn row_from(card: CardResource) -> Option<ContactRow> {
    // Un recurso de CardDAV es una tarjeta. Si trae varias pegadas, lo que se
    // indexa es la primera; lo crudo se guarda entero.
    let first = vcard::split_cards(&card.data).into_iter().next()?;
    // Se guarda por su clave ([`href_key`]), que es con la que la comparan el
    // listado y el `multiget` de la vuelta siguiente.
    let href = href_key(&card.href);
    let contact = vcard::contact_from(&first, &href).unwrap_or_default();
    Some(ContactRow {
        href,
        etag: card.etag,
        raw_vcard: card.data,
        contact,
    })
}

// ---------------------------------------------------------------------------
// Cuándo
// ---------------------------------------------------------------------------

/// Decide cuándo le toca a cada cuenta: el de `dav_sync.rs`, con los
/// contactos.
pub type ContactsScheduler<K, C> = dav_sync::DavScheduler<ContactsSync<K, C>>;

impl<K: KeySource, C: CredentialSource> AreaSync for ContactsSync<K, C> {
    fn interval(&self) -> Duration {
        CONTACTS_INTERVAL
    }

    async fn targets(&self) -> Vec<String> {
        self.manager.area_targets(CONTACTS_AREA).await
    }

    async fn attempt(&self, account_id: &str) -> bool {
        self.sync_account(account_id).await != SyncOutcome::StoreClosed
    }
}

#[cfg(test)]
mod tests;
