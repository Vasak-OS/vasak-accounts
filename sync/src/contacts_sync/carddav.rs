//! Backend CardDAV para sincronización de contactos.
//!
//! Es la implementación existente, extraída a un módulo para el backend CardDAV.

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use super::SyncReport;
use crate::contacts_sync::backend::{SyncContext, SyncResult};
use crate::dav::carddav::{self, AddressBook, CardResource};
use crate::dav::webdav::{self, href_key, DavClient, DavCredential, DavError, HttpPolicy, Limits};
use crate::dav_sync::{
    self, BrokerCredentials, CollectionCap, CredentialError, ListedCollection, MissingStreaks,
    Plan, RoundError, Settled, MISSING_ROUNDS,
};
use crate::store::contacts::{
    Applied, BookProgress, ContactOp, ContactRow, StoredAddressBook, WRITE_BATCH_BYTES,
    WRITE_BATCH_ROWS,
};
use crate::store::key::KeySource;
use crate::store::lifecycle::{AreaState, StoreManager, CONTACTS_AREA};
use crate::store::{LogLevel, Store, StoreError};
use crate::vcard;

/// Cada cuánto se sincronizan los contactos de una cuenta encendida.
const CONTACTS_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Lo que se ve en el estado cuando el servicio de cuentas dice que no.
const DENIED_DETAIL: &str = "el servicio de cuentas no le da al sincronizador permiso para los \
     contactos de esta cuenta: hace falta vasak-permissions 0.15.0 o posterior, y que la persona \
     lo permita en Configuración → Privacidad y seguridad";

/// Lo que se ve cuando la base no está abierta.
const CLOSED_DETAIL: &str =
    "la base no está abierta: se sincroniza cuando se desbloquee el llavero";

/// Lo que puede cortar una vuelta.
#[derive(Debug)]
enum SyncError {
    Dav(DavError),
    Store(StoreError),
    /// La vuelta pasó [`Limits::max_round`].
    Timeout,
    /// Las tarjetas de la cuenta pasarían [`Limits::max_account_vcard_bytes`].
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

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::Dav(e) => write!(f, "error DAV: {e}"),
            SyncError::Store(e) => write!(f, "error de almacén: {e}"),
            SyncError::Timeout => write!(f, "tiempo agotado"),
            SyncError::AccountTooLarge => write!(f, "cuenta demasiado grande"),
        }
    }
}

/// Lo que lleva una vuelta de una cuenta de libreta en libreta.
struct Round {
    report: SyncReport,
    deadline: tokio::time::Instant,
    stored_bytes: u64,
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

/// Backend CardDAV.
pub struct CardDavBackend;

impl CardDavBackend {
    /// Sincroniza los contactos usando CardDAV.
    pub async fn sync<K: KeySource>(
        &self,
        ctx: SyncContext<'_, K>,
        credential: &DavCredential,
        http_policy: HttpPolicy,
    ) -> SyncResult {
        let manager = ctx.manager;
        let account_id = ctx.account_id;
        let notify = ctx.notify;

        let set_status: Arc<
            dyn Fn(AreaState, &str) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>>
                + Send
                + Sync,
        > = {
            let manager = manager.clone();
            let account_id = account_id.to_string();
            let notify = notify.clone();
            Arc::new(
                move |state: AreaState,
                      detail: &str|
                      -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> {
                    let manager = manager.clone();
                    let account_id = account_id.clone();
                    let detail = detail.to_string();
                    let notify = notify.clone();
                    Box::pin(async move {
                        if manager
                            .set_area_status(CONTACTS_AREA, &account_id, state, &detail)
                            .await
                        {
                            (notify)();
                        }
                    })
                },
            )
        };

        // Antes de nada, y releyendo el llavero: con la base cerrada no se le
        // pide nada ni al servicio de cuentas ni al servidor.
        if !manager.prepare_for_sync(CONTACTS_AREA, account_id).await {
            set_status(AreaState::Pending, CLOSED_DETAIL).await;
            return SyncResult::StoreClosed;
        }
        set_status(AreaState::Syncing, "").await;

        let client = match DavClient::new(credential, Limits::DEFAULT, http_policy) {
            Ok(c) => c,
            Err(e) => {
                set_status(AreaState::Failed, &e.to_string()).await;
                return SyncResult::Failed(e.to_string());
            }
        };

        let mut round = Round {
            report: SyncReport::default(),
            deadline: tokio::time::Instant::now() + Limits::DEFAULT.max_round,
            stored_bytes: 0,
        };

        let mut seen = BTreeSet::new();
        let (books, foreign) = match round.net(carddav::list_address_books(&client)).await {
            Ok(r) => r,
            Err(e) => {
                set_status(AreaState::Failed, &e.to_string()).await;
                return SyncResult::Failed(e.to_string());
            }
        };
        round.report.foreign += foreign;
        let books: Vec<AddressBook> = books
            .into_iter()
            .filter(|b| seen.insert(href_key(&b.href)))
            .collect();
        round.report.books = books.len();
        let listed: Vec<(String, String)> = books
            .iter()
            .map(|b| (href_key(&b.href), b.display_name.clone()))
            .collect();

        let before = match manager.with_store(account_id, |s| s.address_books()).await {
            Ok(b) => b,
            Err(e) => {
                set_status(AreaState::Failed, "no se pudieron leer las libretas").await;
                return SyncResult::Failed(e.to_string());
            }
        };
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
                if round.check_deadline().is_err() {
                    set_status(
                        AreaState::Failed,
                        "la vuelta pasó el tiempo máximo y se cortó",
                    )
                    .await;
                    return SyncResult::Failed("timeout".into());
                }
                let removed = match manager
                    .with_store(account_id, move |s| s.remove_address_book_chunk(id))
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        set_status(AreaState::Failed, "no se pudo borrar la libreta").await;
                        return SyncResult::Failed(e.to_string());
                    }
                };
                round.report.batches += 1;
                round.report.removed += removed;
                if removed == 0 {
                    break;
                }
            }
        }

        let stored = match manager
            .with_store(account_id, move |s| s.upsert_address_books(&listed))
            .await
        {
            Ok(s) => s,
            Err(e) => {
                set_status(AreaState::Failed, "no se pudieron guardar las libretas").await;
                return SyncResult::Failed(e.to_string());
            }
        };
        round.stored_bytes = match manager
            .with_store(account_id, |s| s.contacts_raw_bytes())
            .await
        {
            Ok(b) => b,
            Err(e) => {
                set_status(AreaState::Failed, "no se pudieron leer los bytes guardados").await;
                return SyncResult::Failed(e.to_string());
            }
        };

        let mut first_error = None;
        for (book, stored_book) in books.iter().zip(stored) {
            if let Err(e) = Self::sync_book(
                account_id,
                &client,
                book,
                &stored_book,
                &mut round,
                manager,
                Arc::clone(&set_status),
            )
            .await
            {
                match e {
                    SyncError::Dav(dav_err) => {
                        first_error.get_or_insert(dav_err);
                    }
                    store_err => {
                        set_status(AreaState::Failed, &store_err.to_string()).await;
                        return SyncResult::Failed(store_err.to_string());
                    }
                }
            }
        }

        match first_error {
            Some(e) => {
                set_status(AreaState::Failed, &e.to_string()).await;
                SyncResult::Failed(e.to_string())
            }
            None => {
                set_status(AreaState::Synced, "").await;
                SyncResult::Synced(round.report)
            }
        }
    }

    /// Sincroniza una libreta.
    async fn sync_book<K: KeySource>(
        account_id: &str,
        client: &DavClient,
        book: &AddressBook,
        stored: &StoredAddressBook,
        round: &mut Round,
        manager: &Arc<StoreManager<K>>,
        set_status: Arc<
            dyn Fn(AreaState, &str) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>>
                + Send
                + Sync,
        >,
    ) -> Result<(), SyncError> {
        if book.ctag.is_some() && book.ctag == stored.ctag {
            round.report.unchanged_books += 1;
            return Ok(());
        }

        let href = stored.href.clone();
        let book_id = stored.id;
        let (token, local) = manager
            .with_store(account_id, move |s| {
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
                max: Limits::DEFAULT.max_cards_per_book,
                error: DavError::TooManyCards,
            },
            &Limits::DEFAULT,
            round.deadline,
            &mut counters,
        )
        .await;
        round.report.full_resyncs += counters.full_resyncs;
        round.report.foreign += counters.foreign;
        round.report.etag_books += usize::from(counters.by_etag);
        let plan = plan?;

        Self::execute(
            account_id, client, book, stored, plan, round, manager, set_status,
        )
        .await
    }

    /// Trae lo que hay que traer y escribe de a lotes; el último lleva el token.
    async fn execute<K: KeySource>(
        account_id: &str,
        client: &DavClient,
        book: &AddressBook,
        stored: &StoredAddressBook,
        plan: Plan,
        round: &mut Round,
        manager: &Arc<StoreManager<K>>,
        _set_status: Arc<
            dyn Fn(AreaState, &str) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>>
                + Send
                + Sync,
        >,
    ) -> Result<(), SyncError> {
        let settles = plan.settles();
        let mut pending: Vec<ContactOp> = Vec::new();
        let mut pending_bytes = 0;
        round.report.removed += plan.delete.len();
        for href in plan.delete {
            pending_bytes += href.len();
            pending.push(ContactOp::Delete(href));
            if pending.len() >= WRITE_BATCH_ROWS {
                Self::write(account_id, stored, &mut pending, None, round, manager).await?;
                pending_bytes = 0;
            }
        }

        let mut missing = 0;
        for chunk in plan.fetch.chunks(Limits::DEFAULT.multiget_batch.max(1)) {
            let (cards, lost) = Self::fetch_cards(client, book, chunk, round).await?;
            missing += lost;
            let max_vcard_bytes = Limits::DEFAULT.max_vcard_bytes;
            let (rows, too_large) =
                webdav::off_runtime(move || Ok(rows_from(cards, max_vcard_bytes))).await?;
            round.report.too_large += too_large;
            for row in rows {
                round.report.fetched += 1;
                pending_bytes += row.raw_vcard.len();
                pending.push(ContactOp::Upsert(Box::new(row)));
                if pending.len() >= WRITE_BATCH_ROWS || pending_bytes >= WRITE_BATCH_BYTES {
                    Self::write(account_id, stored, &mut pending, None, round, manager).await?;
                    pending_bytes = 0;
                }
            }
        }

        // El último lote, aunque esté vacío: es el que guarda el token.
        let settled = MissingStreaks::default().settle(account_id, &stored.href, missing);
        let settles = settles && !matches!(settled, Settled::Retry(_));
        let progress = settles.then_some(BookProgress {
            token: plan.token,
            ctag: plan.ctag,
        });
        Self::write(account_id, stored, &mut pending, progress, round, manager).await?;
        match settled {
            Settled::Complete => Ok(()),
            Settled::Retry(count) => {
                tracing::warn!(
                    "'{account_id}': {count} tarjetas pedidas no volvieron; la libreta no se da \
                     por al día y se vuelven a pedir"
                );
                Err(SyncError::Dav(DavError::MissingResources(count)))
            }
            Settled::GaveUp(count) => {
                round.report.missing += count;
                let message = format!(
                    "{count} tarjetas pedidas no volvieron en {MISSING_ROUNDS} vueltas seguidas: \
                     la libreta se dio por al día sin ellas, y llegan cuando cambien en el \
                     servidor"
                );
                tracing::warn!("'{account_id}': {message}");
                let _ = manager
                    .with_store(account_id, move |s| {
                        s.log(LogLevel::Warn, Some(CONTACTS_AREA), &message)
                    })
                    .await;
                Ok(())
            }
        }
    }

    async fn write<K: KeySource>(
        account_id: &str,
        stored: &StoredAddressBook,
        pending: &mut Vec<ContactOp>,
        finish: Option<BookProgress>,
        round: &mut Round,
        manager: &Arc<StoreManager<K>>,
    ) -> Result<(), SyncError> {
        round.check_deadline()?;
        let ops = std::mem::take(pending);
        let room = Limits::DEFAULT
            .max_account_vcard_bytes
            .saturating_sub(round.stored_bytes);
        let book = stored.clone();
        let applied = manager
            .with_store(account_id, move |s| {
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
    /// puede trabar la libreta entera para siempre. Devuelve también cuántas
    /// de las pedidas no volvieron.
    async fn fetch_cards(
        client: &DavClient,
        book: &AddressBook,
        hrefs: &[url::Url],
        round: &mut Round,
    ) -> Result<(Vec<CardResource>, usize), SyncError> {
        let mut cards = Vec::new();
        let mut missing = 0;
        let mut parts = vec![hrefs.to_vec()];
        while let Some(part) = parts.pop() {
            match round
                .net(carddav::multiget(client, &book.href, &part))
                .await
            {
                Ok(fetched) => {
                    round.report.unrequested += fetched.unrequested;
                    round.report.too_large += fetched.too_large;
                    missing += fetched.missing.len();
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
        Ok((cards, missing))
    }
}

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

fn row_from(card: CardResource) -> Option<ContactRow> {
    let first = vcard::split_cards(&card.data).into_iter().next()?;
    let href = href_key(&card.href);
    let contact = vcard::contact_from(&first, &href).unwrap_or_default();
    Some(ContactRow {
        href,
        etag: card.etag,
        raw_vcard: card.data,
        contact,
    })
}
