//! Lo que comparten las sincronizaciones por DAV: los contactos
//! (`contacts_sync.rs`) y el calendario (`calendar_sync.rs`).
//!
//! Las dos hacen lo mismo con otro espacio de nombres: pedir la credencial al
//! servicio de cuentas, listar las colecciones, decidir por colección qué
//! traer y qué borrar —por `sync-collection` o por ETag—, traerlo de a tandas
//! y escribirlo de a lotes con el token en el último, con un plazo por vuelta.
//! Acá vive lo que no depende de qué se guarda:
//!
//! - la credencial ([`CredentialSource`]), por capacidad;
//! - el plazo de la vuelta ([`net`], [`check_deadline`]);
//! - **el plan de una colección** ([`plan_collection`]): `sync-collection`
//!   desde el token —sin token, la carga inicial; vencido, la completa; un
//!   `507` que no avanza, error—, o `PROPFIND` de los ETag si el servidor no
//!   lo sabe, con el tope de recursos por colección mirado antes de escribir;
//! - y cuándo le toca a cada cuenta ([`DavScheduler`]).
//!
//! Salió de `contacts_sync.rs` sin cambiar lo que hace: las pruebas de los
//! contactos son las mismas.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::broker::{Broker, BrokerError};
use crate::dav::webdav::{self, href_key, DavClient, DavCredential, DavError, Limits};

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

/// De dónde sale la credencial de un área de una cuenta.
///
/// Un rasgo para poder probar la sincronización sin el bus del sistema.
pub trait CredentialSource: Send + Sync + 'static {
    /// La credencial de `capability` —`contacts`, `calendar`— de una cuenta.
    fn credential(
        &self,
        account_id: &str,
        capability: &'static str,
    ) -> impl Future<Output = Result<DavCredential, CredentialError>> + Send;
}

/// La de verdad: el servicio de cuentas, por la puerta de permisos como
/// cualquier otra aplicación.
///
/// La capacidad es el nombre del área —`contacts`, `calendar`—: el servicio la
/// convierte en el recurso `account.<capacidad>` al preguntarle a
/// `vasak-permissions`. El token primero, porque es lo que dispara el permiso;
/// si dice que no, no tiene sentido haber pedido el resto.
pub struct BrokerCredentials;

impl CredentialSource for BrokerCredentials {
    async fn credential(
        &self,
        account_id: &str,
        capability: &'static str,
    ) -> Result<DavCredential, CredentialError> {
        let classify = |e: BrokerError| match e {
            BrokerError::Denied(_) => CredentialError::Denied,
            other => CredentialError::Failed(other.to_string()),
        };
        let broker = Broker::connect().await.map_err(classify)?;
        let secret = Zeroizing::new(
            broker
                .access_token(account_id, capability)
                .await
                .map_err(classify)?,
        );
        let data = broker
            .account_data(account_id, capability)
            .await
            .map_err(classify)?;
        // La configuración viene envuelta: el servicio devuelve la cuenta
        // entera con la capacidad adentro.
        let config = data.get("config").unwrap_or(&data);
        webdav::credential_from(config, secret).map_err(CredentialError::Failed)
    }
}

// ---------------------------------------------------------------------------
// El plazo de una vuelta
// ---------------------------------------------------------------------------

/// Lo que corta el plan de una colección.
#[derive(Debug)]
pub enum RoundError {
    Dav(DavError),
    /// La vuelta pasó su plazo ([`Limits::max_round`]).
    Timeout,
}

impl From<DavError> for RoundError {
    fn from(error: DavError) -> Self {
        RoundError::Dav(error)
    }
}

/// Falla si la vuelta ya pasó su plazo.
///
/// Un plazo que se mira en cada paso y no un `timeout` sobre la vuelta entera:
/// cortar desde afuera suelta el futuro de `with_store` a mitad de un lote, con
/// la base prestada al hilo que escribe, y el lote —el último lleva el token—
/// se termina de escribir igual. Así, lo que se corta es un pedido a la red o
/// un lote que todavía no empezó.
pub fn check_deadline(deadline: tokio::time::Instant) -> Result<(), RoundError> {
    if tokio::time::Instant::now() >= deadline {
        return Err(RoundError::Timeout);
    }
    Ok(())
}

/// Un pedido a la red, con lo que le queda de plazo a la vuelta.
pub async fn net<T>(
    deadline: tokio::time::Instant,
    request: impl Future<Output = Result<T, DavError>>,
) -> Result<T, RoundError> {
    match tokio::time::timeout_at(deadline, request).await {
        Ok(result) => Ok(result?),
        Err(_) => Err(RoundError::Timeout),
    }
}

// ---------------------------------------------------------------------------
// El plan de una colección
// ---------------------------------------------------------------------------

/// Una colección —una libreta, un calendario— tal como la listó el servidor.
#[derive(Debug, Clone, Copy)]
pub struct ListedCollection<'a> {
    pub href: &'a url::Url,
    pub ctag: Option<&'a str>,
    /// Si sabe `sync-collection`, según su `supported-report-set`.
    pub sync_collection: Option<bool>,
}

/// Cuántos recursos puede tener una colección, y el error de pasarlo.
#[derive(Debug, Clone, Copy)]
pub struct CollectionCap {
    pub max: usize,
    pub error: fn(usize) -> DavError,
}

impl CollectionCap {
    fn exceeded(&self) -> RoundError {
        RoundError::Dav((self.error)(self.max))
    }
}

/// Qué hay que hacer con una colección.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Lo nuevo y lo que cambió de ETag, para pedirlo con un `multiget`.
    pub fetch: Vec<url::Url>,
    /// Lo guardado que ya no está, por su clave ([`href_key`]).
    pub delete: Vec<String>,
    /// El token para la próxima vez, si hay uno que se pueda guardar. `None`
    /// en el camino por ETag: la próxima vuelta vuelve a mirar todo.
    pub token: Option<String>,
    /// El `getctag` con que se termina la colección.
    pub ctag: Option<String>,
}

/// Lo que hizo el plan, para el informe de la vuelta.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlanCounters {
    /// Tokens vencidos que llevaron a una sincronización completa.
    pub full_resyncs: usize,
    /// Si fue por ETag porque el servidor no sabe `sync-collection`.
    pub by_etag: bool,
    /// Direcciones de otro origen que se descartaron.
    pub foreign: usize,
}

/// Decide qué traer y qué borrar de una colección: `sync-collection` desde el
/// token guardado —o la carga inicial, sin token—, y si el servidor no lo
/// sabe, `PROPFIND` de los ETag contra lo guardado. `local` es lo guardado de
/// la colección, por clave, con su ETag.
#[allow(clippy::too_many_arguments)]
pub async fn plan_collection(
    client: &DavClient,
    collection: ListedCollection<'_>,
    token: Option<String>,
    local: &HashMap<String, Option<String>>,
    cap: CollectionCap,
    limits: &Limits,
    deadline: tokio::time::Instant,
    counters: &mut PlanCounters,
) -> Result<Plan, RoundError> {
    let plan = match collection.sync_collection {
        Some(false) => None,
        _ => {
            plan_by_token(
                client, collection, token, local, cap, limits, deadline, counters,
            )
            .await?
        }
    };
    match plan {
        Some(plan) => Ok(plan),
        None => {
            counters.by_etag = true;
            plan_by_etag(client, collection, local, cap, deadline).await
        }
    }
}

/// El camino de `sync-collection`. `None` si el servidor no lo sabe.
#[allow(clippy::too_many_arguments)]
async fn plan_by_token(
    client: &DavClient,
    collection: ListedCollection<'_>,
    mut token: Option<String>,
    local: &HashMap<String, Option<String>>,
    cap: CollectionCap,
    limits: &Limits,
    deadline: tokio::time::Instant,
    counters: &mut PlanCounters,
) -> Result<Option<Plan>, RoundError> {
    let mut full = token.is_none();
    let mut changed: BTreeMap<String, (url::Url, Option<String>)> = BTreeMap::new();
    let mut removed: BTreeSet<String> = BTreeSet::new();
    let mut rounds = 0;

    loop {
        rounds += 1;
        if rounds > limits.max_sync_rounds {
            return Err(DavError::Status(507).into());
        }
        match net(
            deadline,
            webdav::sync_collection(client, collection.href, token.as_deref()),
        )
        .await?
        {
            webdav::SyncCollection::NotSupported => return Ok(None),
            webdav::SyncCollection::InvalidToken => {
                if token.is_none() {
                    // Sin token no hay nada que tirar: el servidor no sabe lo
                    // que dice. Por ETag.
                    return Ok(None);
                }
                tracing::info!("el token de una colección venció: sincronización completa");
                counters.full_resyncs += 1;
                token = None;
                full = true;
                changed.clear();
                removed.clear();
            }
            webdav::SyncCollection::Delta(delta) => {
                counters.foreign += delta.foreign;
                merge_delta(
                    &mut changed,
                    &mut removed,
                    delta.changed,
                    delta.removed,
                    local,
                );
                if changed.len() > cap.max {
                    return Err(cap.exceeded());
                }
                let advanced = delta.token.is_some() && delta.token != token;
                token = delta.token;
                match (delta.truncated, advanced) {
                    (false, _) => break,
                    (true, true) => continue,
                    // Truncado y sin token nuevo: pedir de nuevo daría lo
                    // mismo, y tomarlo como completo borraría todo lo que no
                    // llegó en la parte cortada. Error, sin escribir nada ni
                    // mover el token.
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
        // La carga completa trae todo lo que hay: lo guardado que no vino, ya
        // no está.
        delete.extend(
            local
                .keys()
                .filter(|href| !changed.contains_key(*href))
                .cloned(),
        );
    }
    let fetch = to_fetch(changed.into_values(), local);
    check_total(local, &delete, &fetch, cap)?;

    let token = token.filter(|t| t.len() <= webdav::MAX_TOKEN_BYTES);
    Ok(Some(Plan {
        fetch,
        delete,
        token,
        ctag: collection.ctag.map(str::to_string),
    }))
}

/// El camino por ETag, para el servidor que no sabe `sync-collection`.
async fn plan_by_etag(
    client: &DavClient,
    collection: ListedCollection<'_>,
    local: &HashMap<String, Option<String>>,
    cap: CollectionCap,
    deadline: tokio::time::Instant,
) -> Result<Plan, RoundError> {
    let mut listed = net(deadline, webdav::list_etags(client, collection.href)).await?;
    if listed.len() > cap.max {
        return Err(cap.exceeded());
    }
    // Un recurso que el listado nombra dos veces —con escapes distintos— es
    // uno.
    let mut present = BTreeSet::new();
    listed.retain(|(u, _)| present.insert(href_key(u)));
    let delete: Vec<String> = local
        .keys()
        .filter(|href| !present.contains(*href))
        .cloned()
        .collect();
    let fetch = to_fetch(listed, local);
    check_total(local, &delete, &fetch, cap)?;
    Ok(Plan {
        fetch,
        delete,
        token: None,
        ctag: collection.ctag.map(str::to_string),
    })
}

/// Que la colección no pase el tope de recursos después de aplicar el plan.
fn check_total(
    local: &HashMap<String, Option<String>>,
    delete: &[String],
    fetch: &[url::Url],
    cap: CollectionCap,
) -> Result<(), RoundError> {
    let new = fetch
        .iter()
        .filter(|u| !local.contains_key(&href_key(u)))
        .count();
    let total = (local.len() + new).saturating_sub(delete.len());
    if total > cap.max {
        return Err(cap.exceeded());
    }
    Ok(())
}

/// Suma una tanda de `sync-collection` a lo acumulado de las anteriores.
///
/// Lo que se borró sólo se anota **si está guardado**: con cincuenta tandas
/// de dieciséis megas de `404` de direcciones que nadie tiene, la lista crecía
/// hasta gigabytes antes de filtrarla al final. Así no pasa de lo guardado,
/// que tiene tope. Lo que cambió y después se borró deja de pedirse igual.
pub fn merge_delta(
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
pub fn to_fetch(
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

/// Cuánto tiene que pasar entre dos `RequestSync` de la misma cuenta para que
/// el segundo vuelva a sincronizar. Una aplicación que se abre dos veces
/// seguidas no tiene por qué pedir todo dos veces.
pub const REQUEST_COOLDOWN: Duration = Duration::from_secs(30);

/// Un área que se sincroniza por cuenta, para [`DavScheduler`].
pub trait AreaSync: Send + Sync + 'static {
    /// Cada cuánto le toca a cada cuenta.
    fn interval(&self) -> Duration;

    /// Las cuentas a las que les toca el área.
    fn targets(&self) -> impl Future<Output = Vec<String>> + Send;

    /// Una vuelta de una cuenta. `false` si no llegó a pedir nada —la base
    /// estaba cerrada—: no cuenta como intento, y la cuenta entra en la
    /// revisión siguiente.
    fn attempt(&self, account_id: &str) -> impl Future<Output = bool> + Send;

    /// Lo que se hace en cada revisión, antes de las vueltas: correr la
    /// ventana del calendario, por ejemplo. Nada, si el área no tiene.
    fn maintain(&self) -> impl Future<Output = ()> + Send {
        async {}
    }
}

/// Decide cuándo le toca a cada cuenta de un área.
pub struct DavScheduler<S: AreaSync> {
    sync: S,
    /// El último intento que llegó a pedir algo, por cuenta.
    last_attempt: Mutex<HashMap<String, Instant>>,
    /// El último `RequestSync` atendido, por cuenta.
    last_request: Mutex<HashMap<String, Instant>>,
}

impl<S: AreaSync> DavScheduler<S> {
    pub fn new(sync: S) -> Self {
        Self {
            sync,
            last_attempt: Mutex::new(HashMap::new()),
            last_request: Mutex::new(HashMap::new()),
        }
    }

    /// Las cuentas a las que les toca, una por una.
    pub async fn run_due(&self, now: Instant) {
        self.sync.maintain().await;
        let interval = self.sync.interval();
        for account_id in self.sync.targets().await {
            let due = self
                .last_attempt
                .lock()
                .await
                .get(&account_id)
                .is_none_or(|last| now.saturating_duration_since(*last) >= interval);
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
        if self.sync.targets().await.iter().any(|id| id == account_id) {
            self.sync_one(account_id, now).await;
        }
    }

    async fn sync_one(&self, account_id: &str, now: Instant) {
        // Una base cerrada no pidió nada: no cuenta, y se vuelve a mirar en la
        // próxima revisión.
        if self.sync.attempt(account_id).await {
            self.last_attempt
                .lock()
                .await
                .insert(account_id.to_string(), now);
        }
    }

    /// El bucle: una revisión cada `tick` y cada `RequestSync` que llega por
    /// `requests`. De a una cuenta por vez.
    pub async fn run(
        self: Arc<Self>,
        tick: Duration,
        mut requests: tokio::sync::mpsc::Receiver<String>,
    ) {
        let mut tick = tokio::time::interval(tick);
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
