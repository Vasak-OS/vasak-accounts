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
//! [`REQUEST_COOLDOWN`] entre ellos, son uno).
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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::broker::{Broker, BrokerError};
use crate::dav::carddav::{self, AddressBook, CardResource};
use crate::dav::webdav::{self, href_key, DavClient, DavCredential, DavError, HttpPolicy, Limits};
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

/// Cuánto tiene que pasar entre dos `RequestSync` de la misma cuenta para que
/// el segundo vuelva a sincronizar. Una aplicación que se abre dos veces
/// seguidas no tiene por qué pedir todo dos veces.
pub const REQUEST_COOLDOWN: Duration = Duration::from_secs(30);

/// Lo que se ve en el estado cuando el servicio de cuentas dice que no.
const DENIED_DETAIL: &str = "el servicio de cuentas no le da al sincronizador permiso para los \
     contactos de esta cuenta: hace falta vasak-permissions 0.15.0 o posterior, y que la persona \
     lo permita en Configuración → Privacidad y seguridad";

/// Lo que se ve cuando la base no está abierta.
const CLOSED_DETAIL: &str =
    "la base no está abierta: se sincroniza cuando se desbloquee el llavero";

// ---------------------------------------------------------------------------
// La credencial
// ---------------------------------------------------------------------------

/// Por qué no hay credencial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    /// El servicio de cuentas dijo que no (`AccessDenied`). No se reintenta.
    Denied,
    /// No contesta, o contestó otra cosa.
    Failed(String),
}

/// De dónde sale la credencial de los contactos de una cuenta.
///
/// Un rasgo para poder probar la sincronización sin el bus del sistema.
pub trait CredentialSource: Send + Sync + 'static {
    fn contacts_credential(
        &self,
        account_id: &str,
    ) -> impl Future<Output = Result<DavCredential, CredentialError>> + Send;
}

/// La de verdad: el servicio de cuentas, por la puerta de permisos como
/// cualquier otra aplicación.
///
/// La capacidad es `contacts`: el servicio la convierte en el recurso
/// `account.contacts` al preguntarle a `vasak-permissions`. El token primero,
/// porque es lo que dispara el permiso; si dice que no, no tiene sentido haber
/// pedido el resto.
pub struct BrokerCredentials;

impl CredentialSource for BrokerCredentials {
    async fn contacts_credential(
        &self,
        account_id: &str,
    ) -> Result<DavCredential, CredentialError> {
        let classify = |e: BrokerError| match e {
            BrokerError::Denied(_) => CredentialError::Denied,
            other => CredentialError::Failed(other.to_string()),
        };
        let broker = Broker::connect().await.map_err(classify)?;
        let secret = Zeroizing::new(
            broker
                .access_token(account_id, CONTACTS_AREA)
                .await
                .map_err(classify)?,
        );
        let data = broker
            .account_data(account_id, CONTACTS_AREA)
            .await
            .map_err(classify)?;
        // La configuración viene envuelta: el servicio devuelve la cuenta
        // entera con la capacidad adentro.
        let config = data.get("config").unwrap_or(&data);
        webdav::credential_from(config, secret).map_err(CredentialError::Failed)
    }
}

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
        if tokio::time::Instant::now() >= self.deadline {
            return Err(SyncError::Timeout);
        }
        Ok(())
    }

    /// Un pedido a la red, con lo que le queda de plazo a la vuelta.
    async fn net<T>(
        &self,
        request: impl Future<Output = Result<T, DavError>>,
    ) -> Result<T, SyncError> {
        match tokio::time::timeout_at(self.deadline, request).await {
            Ok(result) => Ok(result?),
            Err(_) => Err(SyncError::Timeout),
        }
    }
}

/// Qué hay que hacer con una libreta.
struct Plan {
    fetch: Vec<url::Url>,
    delete: Vec<String>,
    progress: BookProgress,
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

        let credential = match self.credentials.contacts_credential(account_id).await {
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

        let plan = match book.sync_collection {
            Some(false) => None,
            _ => {
                self.plan_by_token(client, book, token, &local, round)
                    .await?
            }
        };
        let plan = match plan {
            Some(plan) => plan,
            None => {
                round.report.etag_books += 1;
                self.plan_by_etag(client, book, &local, round).await?
            }
        };

        self.execute(account_id, client, book, stored, plan, round)
            .await
    }

    /// El camino de `sync-collection`. `None` si el servidor no lo sabe.
    async fn plan_by_token(
        &self,
        client: &DavClient,
        book: &AddressBook,
        mut token: Option<String>,
        local: &HashMap<String, Option<String>>,
        round: &mut Round,
    ) -> Result<Option<Plan>, SyncError> {
        let mut full = token.is_none();
        let mut changed: BTreeMap<String, (url::Url, Option<String>)> = BTreeMap::new();
        let mut removed: BTreeSet<String> = BTreeSet::new();
        let mut rounds = 0;

        loop {
            rounds += 1;
            if rounds > self.limits.max_sync_rounds {
                return Err(DavError::Status(507).into());
            }
            match round
                .net(webdav::sync_collection(
                    client,
                    &book.href,
                    token.as_deref(),
                ))
                .await?
            {
                webdav::SyncCollection::NotSupported => return Ok(None),
                webdav::SyncCollection::InvalidToken => {
                    if token.is_none() {
                        // Sin token no hay nada que tirar: el servidor no sabe
                        // lo que dice. Por ETag.
                        return Ok(None);
                    }
                    tracing::info!("el token de una libreta venció: sincronización completa");
                    round.report.full_resyncs += 1;
                    token = None;
                    full = true;
                    changed.clear();
                    removed.clear();
                }
                webdav::SyncCollection::Delta(delta) => {
                    round.report.foreign += delta.foreign;
                    merge_delta(
                        &mut changed,
                        &mut removed,
                        delta.changed,
                        delta.removed,
                        local,
                    );
                    if changed.len() > self.limits.max_cards_per_book {
                        return Err(DavError::TooManyCards(self.limits.max_cards_per_book).into());
                    }
                    let advanced = delta.token.is_some() && delta.token != token;
                    token = delta.token;
                    match (delta.truncated, advanced) {
                        (false, _) => break,
                        (true, true) => continue,
                        // Truncado y sin token nuevo: pedir de nuevo daría lo
                        // mismo, y tomarlo como completo borraría todo lo que
                        // no llegó en la parte cortada. Error, sin escribir
                        // nada ni mover el token.
                        (true, false) => return Err(DavError::Status(507).into()),
                    }
                }
            }
        }

        let mut delete: Vec<String> = removed
            .into_iter()
            .filter(|href| local.contains_key(href))
            .collect();
        if full {
            // La carga completa trae todo lo que hay: lo guardado que no vino,
            // ya no está.
            delete.extend(
                local
                    .keys()
                    .filter(|href| !changed.contains_key(*href))
                    .cloned(),
            );
        }
        let fetch = to_fetch(changed.into_values(), local);
        self.check_total(local, &delete, &fetch)?;

        let token = token.filter(|t| t.len() <= webdav::MAX_TOKEN_BYTES);
        Ok(Some(Plan {
            fetch,
            delete,
            progress: BookProgress {
                token,
                ctag: book.ctag.clone(),
            },
        }))
    }

    /// El camino por ETag, para el servidor que no sabe `sync-collection`.
    async fn plan_by_etag(
        &self,
        client: &DavClient,
        book: &AddressBook,
        local: &HashMap<String, Option<String>>,
        round: &Round,
    ) -> Result<Plan, SyncError> {
        let mut listed = round.net(carddav::list_etags(client, &book.href)).await?;
        if listed.len() > self.limits.max_cards_per_book {
            return Err(DavError::TooManyCards(self.limits.max_cards_per_book).into());
        }
        // Una tarjeta que el listado nombra dos veces —con escapes distintos—
        // es una.
        let mut present = BTreeSet::new();
        listed.retain(|(u, _)| present.insert(href_key(u)));
        let delete: Vec<String> = local
            .keys()
            .filter(|href| !present.contains(*href))
            .cloned()
            .collect();
        let fetch = to_fetch(listed, local);
        self.check_total(local, &delete, &fetch)?;
        Ok(Plan {
            fetch,
            delete,
            progress: BookProgress {
                token: None,
                ctag: book.ctag.clone(),
            },
        })
    }

    /// Que la libreta no pase el tope de tarjetas después de aplicar el plan.
    fn check_total(
        &self,
        local: &HashMap<String, Option<String>>,
        delete: &[String],
        fetch: &[url::Url],
    ) -> Result<(), SyncError> {
        let new = fetch
            .iter()
            .filter(|u| !local.contains_key(&href_key(u)))
            .count();
        let total = (local.len() + new).saturating_sub(delete.len());
        if total > self.limits.max_cards_per_book {
            return Err(DavError::TooManyCards(self.limits.max_cards_per_book).into());
        }
        Ok(())
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
        self.write(account_id, stored, &mut pending, Some(plan.progress), round)
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
                Ok((fetched, unrequested)) => {
                    round.report.unrequested += unrequested;
                    cards.extend(fetched);
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

/// Lo que se guarda de unas tarjetas, y cuántas no, por pasar el tope.
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

/// Suma una tanda de `sync-collection` a lo acumulado de las anteriores.
///
/// Lo que se borró sólo se anota **si está guardado**: con cincuenta tandas
/// de dieciséis megas de `404` de direcciones que nadie tiene, la lista crecía
/// hasta gigabytes antes de filtrarla al final. Así no pasa de lo guardado,
/// que tiene tope. Lo que cambió y después se borró deja de pedirse igual.
fn merge_delta(
    changed: &mut BTreeMap<String, (url::Url, Option<String>)>,
    removed: &mut BTreeSet<String>,
    delta_changed: Vec<(url::Url, Option<String>)>,
    delta_removed: Vec<url::Url>,
    local: &HashMap<String, Option<String>>,
) {
    for url in delta_removed {
        let key = href_key(&url);
        changed.remove(&key);
        if local.contains_key(&key) {
            removed.insert(key);
        }
    }
    for (url, etag) in delta_changed {
        let key = href_key(&url);
        removed.remove(&key);
        changed.insert(key, (url, etag));
    }
}

/// Lo que hay que traer: lo nuevo y lo que cambió de ETag. Sin ETag no hay
/// cómo saber, y se trae.
fn to_fetch(
    listed: impl IntoIterator<Item = (url::Url, Option<String>)>,
    local: &HashMap<String, Option<String>>,
) -> Vec<url::Url> {
    listed
        .into_iter()
        .filter(|(url, etag)| match (local.get(&href_key(url)), etag) {
            (Some(Some(stored)), Some(etag)) => stored != etag,
            _ => true,
        })
        .map(|(url, _)| url)
        .collect()
}

// ---------------------------------------------------------------------------
// Cuándo
// ---------------------------------------------------------------------------

/// Decide cuándo le toca a cada cuenta.
pub struct ContactsScheduler<K: KeySource, C: CredentialSource> {
    sync: ContactsSync<K, C>,
    /// El último intento que llegó a pedir algo, por cuenta.
    last_attempt: Mutex<HashMap<String, Instant>>,
    /// El último `RequestSync` atendido, por cuenta.
    last_request: Mutex<HashMap<String, Instant>>,
}

impl<K: KeySource, C: CredentialSource> ContactsScheduler<K, C> {
    pub fn new(sync: ContactsSync<K, C>) -> Self {
        Self {
            sync,
            last_attempt: Mutex::new(HashMap::new()),
            last_request: Mutex::new(HashMap::new()),
        }
    }

    /// Las cuentas a las que les toca, una por una.
    pub async fn run_due(&self, now: Instant) {
        for account_id in self.sync.manager.area_targets(CONTACTS_AREA).await {
            let due = self
                .last_attempt
                .lock()
                .await
                .get(&account_id)
                .is_none_or(|last| now.saturating_duration_since(*last) >= CONTACTS_INTERVAL);
            if due {
                self.sync_one(&account_id, now).await;
            }
        }
    }

    /// Un `RequestSync`: ya, salvo que la misma cuenta haya pedido hace muy
    /// poco.
    pub async fn run_requested(&self, account_id: &str, now: Instant) {
        {
            let mut requests = self.last_request.lock().await;
            if requests
                .get(account_id)
                .is_some_and(|last| now.saturating_duration_since(*last) < REQUEST_COOLDOWN)
            {
                return;
            }
            requests.insert(account_id.to_string(), now);
        }
        if self
            .sync
            .manager
            .area_targets(CONTACTS_AREA)
            .await
            .iter()
            .any(|id| id == account_id)
        {
            self.sync_one(account_id, now).await;
        }
    }

    async fn sync_one(&self, account_id: &str, now: Instant) {
        let outcome = self.sync.sync_account(account_id).await;
        // Una base cerrada no pidió nada: no cuenta, y se vuelve a mirar en la
        // próxima revisión.
        if outcome != SyncOutcome::StoreClosed {
            self.last_attempt
                .lock()
                .await
                .insert(account_id.to_string(), now);
        }
    }

    /// El bucle: una revisión cada [`CONTACTS_TICK`] y cada `RequestSync` que
    /// llega por `requests`. De a una cuenta por vez.
    pub async fn run(self: Arc<Self>, mut requests: tokio::sync::mpsc::Receiver<String>) {
        let mut tick = tokio::time::interval(CONTACTS_TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = tick.tick() => self.run_due(Instant::now()).await,
                request = requests.recv() => match request {
                    Some(account_id) => self.run_requested(&account_id, Instant::now()).await,
                    None => return,
                },
            }
        }
    }
}

#[cfg(test)]
mod tests;
