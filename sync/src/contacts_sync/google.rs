//! Backend Google para sincronización de contactos: CardDAV **más** una pasada
//! de enriquecimiento por la People API (`vasak-accounts#111`, hito P5).
//!
//! Google sincroniza la agenda por **CardDAV** genérico (como cualquier cuenta
//! `oauth2` con CardDAV); la People API (`people.googleapis.com`) la **enriquece**,
//! no la reemplaza. El alcance de este PR es **sólo la foto**: el CardDAV de
//! Google no suele traer la `PHOTO` embebida y la People API sí. Grupos,
//! etiquetas y «destacado» quedan fuera (los difiere el usuario).
//!
//! ── Dónde vive la foto ───────────────────────────────────────────────────────
//!
//! **Nunca en el `raw_vcard`.** Meterla en el crudo chocaría con la escritura
//! conservadora (decisión 3 del taller) y con el replay: reescribir el crudo de
//! un contacto con una edición local sin confirmar la pisaría. La foto vive en la
//! tabla `contact_enrichment` (columnas `photo`/`photo_media_type`, migración V8)
//! y la lectura (`contacts_read::cards_page`) la inyecta al vCard de salida. La
//! pasada respeta `pending_op` igual que `apply_contacts`: un contacto con una op
//! pendiente no se enriquece (lo deja fuera `Store::contact_ids_by_email`).
//!
//! ── Matching e incrementalidad ───────────────────────────────────────────────
//!
//! No hay clave estable compartida entre el UID de vCard del CardDAV de Google y
//! el `resourceName` `people/c<id>` de la People API, así que se **casa por
//! email** (decisión de #111). Al casar se persiste `resourceName` + `etag` de la
//! persona y el `photo_etag` (la propia url de la foto, que cambia cuando cambia
//! la foto). Las corridas siguientes son incrementales: si la persona casa con el
//! mismo `resourceName` y la misma url de foto, **no se re-baja**. Los contactos
//! sin email se pierden en el casamiento: es el trade-off aceptado en #111.
//!
//! ── Seguridad ────────────────────────────────────────────────────────────────
//!
//! - **La paginación de People es un paginador propio y acotado** ([`fetch_connections`]):
//!   el `nextPageToken` es un parámetro **opaco** que se pega a *nuestra* url base
//!   (`people.googleapis.com`), nunca una url que venga en la respuesta —el riesgo
//!   de host-no-confiable de `@odata.nextLink` no aplica—. Igual se acota: tope de
//!   páginas, tope de ítems, deduplicado del token, plazo por pedido y tope de
//!   tamaño de respuesta. No se reusa `graph::fetch_all_pages` (atado a OData).
//! - **La descarga de la foto es SSRF**: People no da los bytes, da una *url* de
//!   la foto (en `googleusercontent.com`). Seguir esa url es exactamente el vector
//!   que evita el resto del subsistema, así que se baja con el fetcher anti-SSRF
//!   que ya existe ([`crate::images::fetch`]) —rechaza loopback/privadas/metadata,
//!   no sigue redirecciones, no manda token ni cookies, y acota los bytes—, más
//!   un allowlist del host de Google como defensa en profundidad y un tope duro de
//!   tamaño antes de guardar. El token OAuth **no** viaja a googleusercontent: las
//!   fotos de People son públicas, así que la descarga va pelada.
//! - Todo lo que entra al vCard (la foto en base64) pasa por
//!   `vcard::escape_vcard_public` en [`crate::vcard::embed_photo`].

use std::collections::HashSet;
use std::sync::Arc;

use base64::Engine;
use serde::Deserialize;

use crate::contacts_sync::backend::{SyncContext, SyncResult};
use crate::contacts_sync::carddav::CardDavBackend;
use crate::dav::webdav::{AuthKind, DavCredential, HttpPolicy};
use crate::graph;
use crate::store::contacts::ContactEnrichment;
use crate::store::key::KeySource;
use crate::store::lifecycle::{StoreManager, CONTACTS_AREA};
use crate::store::{LogLevel, StoreError};

/// Raíz de la People API en producción. Las pruebas la cambian por el endpoint
/// falso en `127.0.0.1`.
const PEOPLE_BASE_URL: &str = "https://people.googleapis.com/v1";

/// Tope duro del tamaño de una foto antes de guardarla. Las fotos de People son
/// chicas; mejor sin foto que un blob sin límite. (El fetcher de `images` ya
/// acota la descarga a 5 MB; esto es el tope propio, más ajustado, antes de
/// guardar.)
const PHOTO_MAX_BYTES: usize = 2 * 1024 * 1024;

/// Las cotas de la paginación de People. Parametrizadas para que las pruebas las
/// pongan chicas y lleguen al tope sin miles de páginas, al estilo de
/// `dav::webdav::Limits`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PeopleLimits {
    /// Tope de páginas: un servidor que no corta es un bucle o un intento de
    /// agotar memoria.
    pub max_pages: usize,
    /// Tope de personas acumuladas, cota de memoria independiente del de páginas.
    pub max_people: usize,
    /// Cuántas personas se piden por página (`pageSize`).
    pub page_size: usize,
    /// Tope del cuerpo de una respuesta, contado mientras llega.
    pub max_response_bytes: usize,
}

impl PeopleLimits {
    pub const DEFAULT: Self = Self {
        max_pages: 1_000,
        max_people: 50_000,
        page_size: 200,
        max_response_bytes: 16 * 1024 * 1024,
    };
}

/// Una página de `people/me/connections`.
///
/// Todo opcional y con `default`: es dato de red, así que un campo que no venga
/// queda vacío y nunca hace fallar el parseo.
#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct PeopleConnections {
    connections: Vec<Person>,
    next_page_token: Option<String>,
}

/// Una persona de la People API.
#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Person {
    /// `people/c<id>`: con el que se la vuelve a pedir y que se persiste al casar.
    resource_name: String,
    /// El testigo de concurrencia de la persona.
    etag: Option<String>,
    email_addresses: Vec<PersonEmail>,
    photos: Vec<PersonPhoto>,
}

/// Un correo de una persona de People.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PersonEmail {
    value: Option<String>,
}

/// Una foto de una persona de People.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct PersonPhoto {
    /// La url de la foto, en `googleusercontent.com`. Es dato de red: no se sigue
    /// a ciegas (ver [`fetch_photo`]).
    url: Option<String>,
    /// `true` cuando es el monograma que Google genera solo, no una foto de
    /// verdad: ésas no se bajan.
    #[serde(rename = "default")]
    is_default: bool,
}

/// Lo que puede fallar la pasada de enriquecimiento. Ninguna variante vuelca el
/// token ni el cuerpo crudo de la respuesta.
#[derive(Debug)]
pub(crate) enum PeopleError {
    Network(String),
    Parse,
    Http(reqwest::StatusCode),
    MalformedUrl,
    /// El servidor repitió un `pageToken` ya visto: paginación en bucle.
    PaginationLoop,
    TooManyPages,
    TooManyItems,
    /// El cuerpo de una respuesta pasó el tope de tamaño.
    TooLarge,
    Timeout,
    Store(StoreError),
}

impl std::fmt::Display for PeopleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeopleError::Network(e) => write!(f, "error de red con People API: {e}"),
            PeopleError::Parse => write!(f, "no se pudo parsear la respuesta de People API"),
            PeopleError::Http(status) => write!(f, "People API respondió con error {status}"),
            PeopleError::MalformedUrl => write!(f, "URL inválida al paginar People API"),
            PeopleError::PaginationLoop => {
                write!(f, "People API repitió un token de paginación; se abortó")
            }
            PeopleError::TooManyPages => write!(f, "demasiadas páginas de People API; se abortó"),
            PeopleError::TooManyItems => write!(f, "demasiadas personas de People API; se abortó"),
            PeopleError::TooLarge => {
                write!(f, "una respuesta de People API pasó el tope de tamaño")
            }
            PeopleError::Timeout => write!(f, "se agotó el tiempo de espera de People API"),
            PeopleError::Store(e) => write!(f, "error de almacén al enriquecer: {e}"),
        }
    }
}

/// Backend Google.
pub struct GoogleBackend;

impl GoogleBackend {
    /// Sincroniza los contactos de una cuenta Google: primero el sync CardDAV
    /// existente, después la pasada de enriquecimiento por la People API.
    ///
    /// El enriquecimiento es **mejor esfuerzo**: si falla, los contactos ya
    /// sincronizados por CardDAV quedan igual y la vuelta sigue siendo `Synced`
    /// (decisión 2 del taller: lo que no está disponible se ve no disponible,
    /// nunca roto). `people_base_url` es `None` en producción
    /// ([`PEOPLE_BASE_URL`]); las pruebas lo apuntan al endpoint falso.
    pub async fn sync<K: KeySource>(
        &self,
        ctx: SyncContext<'_, K>,
        credential: &DavCredential,
        http_policy: HttpPolicy,
        people_base_url: Option<&str>,
    ) -> SyncResult {
        let manager = ctx.manager;
        let account_id = ctx.account_id;
        let notify = ctx.notify.clone();

        // 1. La base: el mismo sync CardDAV que cualquier cuenta genérica.
        let carddav_ctx = SyncContext {
            manager,
            account_id,
            notify: notify.clone(),
        };
        let mut report = match CardDavBackend
            .sync(carddav_ctx, credential, http_policy)
            .await
        {
            SyncResult::Synced(report) => report,
            // Si la base no sincronizó, no tiene sentido enriquecer: se propaga
            // tal cual (StoreClosed / Denied / Failed).
            other => return other,
        };

        // 2. El enriquecimiento por People API. Reusa la credencial CardDAV: para
        //    Google el secreto ES el token OAuth en `Bearer`, así que no se pide
        //    una segunda vez (y no se dispara un refresco concurrente).
        if credential.auth != AuthKind::Token {
            tracing::warn!(
                "'{account_id}': la cuenta Google no trae token OAuth; sin enriquecimiento de fotos"
            );
            return SyncResult::Synced(report);
        }
        let base_url = people_base_url.unwrap_or(PEOPLE_BASE_URL);
        let token = credential.secret.as_str();

        match enrich_photos(
            manager,
            account_id,
            token,
            base_url,
            PeopleLimits::DEFAULT,
            |url| async move { fetch_photo(&url).await },
        )
        .await
        {
            Ok((fetched, unchanged)) => {
                report.photos_fetched = fetched;
                report.photos_unchanged = unchanged;
            }
            Err(e) => {
                let message =
                    format!("el enriquecimiento de fotos por People API no se completó: {e}");
                tracing::warn!("'{account_id}': {message}");
                let _ = manager
                    .with_store(account_id, move |s| {
                        s.log(LogLevel::Warn, Some(CONTACTS_AREA), &message)
                    })
                    .await;
            }
        }

        SyncResult::Synced(report)
    }
}

/// La pasada de enriquecimiento: lista las personas de People, las casa por email
/// con los contactos locales y baja la foto de las que cambiaron.
///
/// Devuelve `(bajadas, sin_cambio)`. El `fetch_photo` se recibe como parámetro
/// para que las pruebas puedan sustituir la descarga (que en producción va por
/// `images::fetch`, que rechaza el loopback del endpoint falso).
pub(crate) async fn enrich_photos<K, F, Fut>(
    manager: &Arc<StoreManager<K>>,
    account_id: &str,
    token: &str,
    base_url: &str,
    limits: PeopleLimits,
    fetch_photo: F,
) -> Result<(usize, usize), PeopleError>
where
    K: KeySource,
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<(Vec<u8>, String), String>>,
{
    let client = graph::http_client().map_err(|e| PeopleError::Network(e.to_string()))?;
    let people = fetch_connections(&client, token, base_url, &limits).await?;

    // El mapa de email → contacto, sólo contactos sin op pendiente: así una
    // edición local sin confirmar no se enriquece (se respeta `pending_op` igual
    // que `apply_contacts`).
    let email_map = manager
        .with_store(account_id, |s| s.contact_ids_by_email())
        .await
        .map_err(PeopleError::Store)?;

    let mut fetched = 0usize;
    let mut unchanged = 0usize;
    for person in people {
        if person.resource_name.is_empty() {
            continue;
        }
        // Casar por email: el primer correo de la persona que exista en la agenda
        // local decide a qué contacto enriquece.
        let Some(contact_id) = person
            .email_addresses
            .iter()
            .filter_map(|e| e.value.as_deref())
            .filter(|v| !v.is_empty())
            .find_map(|v| email_map.get(&v.to_ascii_lowercase()).copied())
        else {
            continue; // sin email que case: el trade-off aceptado en #111.
        };

        // La primera foto de verdad (no el monograma generado).
        let Some(photo_url) = person
            .photos
            .iter()
            .filter(|p| !p.is_default)
            .filter_map(|p| p.url.as_deref())
            .find(|u| !u.is_empty())
        else {
            continue;
        };
        let photo_url = photo_url.to_string();

        // Incrementalidad: misma persona y misma foto que la corrida anterior → no
        // se re-baja.
        let existing = manager
            .with_store(account_id, move |s| s.contact_enrichment(contact_id))
            .await
            .map_err(PeopleError::Store)?;
        if let Some(link) = &existing {
            if link.resource_name == person.resource_name
                && link.photo_etag.as_deref() == Some(photo_url.as_str())
            {
                unchanged += 1;
                continue;
            }
        }

        match fetch_photo(photo_url.clone()).await {
            Ok((bytes, media_type)) => {
                let link = ContactEnrichment {
                    contact_id,
                    resource_name: person.resource_name.clone(),
                    etag: person.etag.clone(),
                    photo_etag: Some(photo_url),
                };
                manager
                    .with_store(account_id, move |s| {
                        // El enlace (resourceName/etag/photo_etag) primero, que crea
                        // la fila; después los bytes, que la actualizan.
                        s.upsert_contact_enrichment(&link)?;
                        s.set_contact_photo(contact_id, &bytes, &media_type)
                    })
                    .await
                    .map_err(PeopleError::Store)?;
                fetched += 1;
            }
            Err(detail) => {
                tracing::warn!(
                    "'{account_id}': no se bajó la foto de {}: {detail}",
                    person.resource_name
                );
            }
        }
    }
    Ok((fetched, unchanged))
}

/// Trae todas las personas de `people/me/connections` paginando por
/// `nextPageToken`.
///
/// **El `nextPageToken` es opaco y se pega a NUESTRA url base**, nunca se sigue
/// una url que venga en la respuesta. Acota: tope de páginas, tope de personas,
/// deduplicado del token (bucle), plazo por pedido y tope de tamaño del cuerpo.
async fn fetch_connections(
    client: &reqwest::Client,
    token: &str,
    base_url: &str,
    limits: &PeopleLimits,
) -> Result<Vec<Person>, PeopleError> {
    let base = url::Url::parse(base_url).map_err(|_| PeopleError::MalformedUrl)?;
    let mut all: Vec<Person> = Vec::new();
    // Los `pageToken` ya pedidos, para cortar un servidor que repite el mismo en
    // bucle.
    let mut seen: HashSet<String> = HashSet::new();
    let mut page_token: Option<String> = None;

    for _page in 0..limits.max_pages {
        let mut url = base.clone();
        {
            let mut seg = url
                .path_segments_mut()
                .map_err(|_| PeopleError::MalformedUrl)?;
            seg.pop_if_empty();
            for s in ["people", "me", "connections"] {
                seg.push(s);
            }
        }
        url.query_pairs_mut()
            .append_pair("personFields", "emailAddresses,photos")
            .append_pair("pageSize", &limits.page_size.to_string());
        if let Some(token) = &page_token {
            url.query_pairs_mut().append_pair("pageToken", token);
        }

        let deadline = tokio::time::Instant::now() + graph::REQUEST_TIMEOUT;
        let request = client
            .get(url.as_str())
            .bearer_auth(token)
            .header("Accept", "application/json");
        let max_bytes = limits.max_response_bytes;
        let fetch = async move {
            let response = request
                .send()
                .await
                .map_err(|e| PeopleError::Network(e.to_string()))?;
            if !response.status().is_success() {
                return Err(PeopleError::Http(response.status()));
            }
            let body = read_capped(response, max_bytes).await?;
            serde_json::from_slice::<PeopleConnections>(&body).map_err(|_| PeopleError::Parse)
        };
        let data = match tokio::time::timeout_at(deadline, fetch).await {
            Ok(result) => result?,
            Err(_) => return Err(PeopleError::Timeout),
        };

        all.extend(data.connections);
        if all.len() > limits.max_people {
            return Err(PeopleError::TooManyItems);
        }

        match data.next_page_token {
            None => return Ok(all),
            Some(token) if token.is_empty() => return Ok(all),
            Some(token) => {
                if !seen.insert(token.clone()) {
                    return Err(PeopleError::PaginationLoop);
                }
                page_token = Some(token);
            }
        }
    }

    Err(PeopleError::TooManyPages)
}

/// Lee el cuerpo de una respuesta sin pasarse del tope, contando mientras llega
/// (un `Content-Length` es una promesa, no un límite).
async fn read_capped(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, PeopleError> {
    use futures_util::StreamExt;

    let mut received: Vec<u8> = Vec::new();
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(|e| PeopleError::Network(e.to_string()))?;
        if received.len() + chunk.len() > max_bytes {
            return Err(PeopleError::TooLarge);
        }
        received.extend_from_slice(&chunk);
    }
    Ok(received)
}

/// Baja los bytes de una foto de People, con el guard anti-SSRF de `images` más
/// un allowlist del host de Google y un tope duro de tamaño.
///
/// People da una *url* (en `googleusercontent.com`), no los bytes: seguirla es el
/// vector SSRF que el resto del subsistema evita. `images::fetch` ya rechaza
/// loopback/privadas/metadata, no sigue redirecciones, no manda token ni cookies
/// y acota la descarga; acá se suma que el host tiene que ser de Google (ya
/// sabemos a dónde tiene que apuntar) y un tope propio antes de guardar.
async fn fetch_photo(url: &str) -> Result<(Vec<u8>, String), String> {
    let parsed = url::Url::parse(url).map_err(|_| "la URL de la foto no es válida".to_string())?;
    let host = parsed.host_str().unwrap_or_default();
    if !is_google_photo_host(host) {
        return Err(format!("la foto no apunta a un host de Google: {host}"));
    }

    let image = crate::images::fetch(url).await?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(image.base64.as_bytes())
        .map_err(|_| "la foto no se pudo decodificar".to_string())?;
    if !check_photo_size(&bytes) {
        return Err(format!("la foto pasa el tope de {PHOTO_MAX_BYTES} bytes"));
    }
    Ok((bytes, image.content_type))
}

/// Si los bytes de una foto entran en el tope [`PHOTO_MAX_BYTES`] (2 MB). Pura y
/// con costura para la prueba: el tope vivía embebido en `fetch_photo` sin nada
/// que lo cubra, así que borrarlo no ponía nada rojo.
fn check_photo_size(bytes: &[u8]) -> bool {
    bytes.len() <= PHOTO_MAX_BYTES
}

/// Si el host de una url de foto es de Google (`googleusercontent.com` o un
/// subdominio suyo).
fn is_google_photo_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "googleusercontent.com" || host.ends_with(".googleusercontent.com")
}

#[cfg(test)]
mod tests;
