//! La etapa de empuje **por Microsoft Graph**: drena la cola de escrituras de una
//! cuenta Graph hacia `/me/events` y `/me/contacts`.
//!
//! Es el espejo de [`crate::replay`] para el camino Graph. La cola
//! (`store::queue`) es la misma —el mismo modelo de op, estado y conflicto—, pero
//! el alambre no: DAV habla `If-Match`/ETag de DAV con `PUT`/`DELETE` del crudo
//! (iCal/vCard), y Graph habla JSON con su propio `@odata.etag` y
//! `POST`/`PATCH`/`DELETE`. Por eso Graph necesita **su propia etapa** y no se
//! fuerza por el camino DAV (`vasak-accounts#97`).
//!
//! El despacho ya está separado aguas arriba: una cuenta Graph llega por
//! `GraphApiBackend::sync` (calendario y contactos), que llama a
//! [`replay_graph_area`] antes de la bajada, igual que el camino CardDAV llama a
//! `replay::replay_area` en su `push_pending`.
//!
//! Qué se hace con cada op, calcado de `replay` salvo donde Graph difiere:
//!
//! - **`Put` sin `base_etag`** → **crear**: `POST /me/{segmento}`. El contrato de
//!   la superficie D-Bus es que `if_match` vacío es crear (ver `store_api`), así
//!   que un `base_etag` nulo es siempre una creación, nunca una edición sin ETag.
//!   Graph asigna el `id` y el `@odata.etag`; con ellos se **re-basa el `href`**
//!   de la fila local al que usará la próxima bajada
//!   ([`Store::complete_create`]), para que no quede un duplicado. Los eventos
//!   llevan `transactionId` (idempotencia nativa de Graph): un `POST`
//!   reintentado tras una respuesta perdida no crea un segundo evento.
//! - **`Put` con `base_etag`** → **editar**: `PATCH /me/{segmento}/{id}` con
//!   `If-Match: @odata.etag`. Sólo se mandan los campos del subconjunto
//!   conservador (decisión 3); `PATCH` fusiona, así que lo que no modelamos no se
//!   pisa.
//! - **`Delete`** → `DELETE /me/{segmento}/{id}` con `If-Match`. Un `404` es
//!   éxito idempotente: el recurso ya no está, que es lo que se buscaba. Sin
//!   `base_etag` nunca hubo recurso en el servidor: se cierra sin tocar la red.
//! - **`412`/`409`** → la op queda en `conflict` (**no se pisa el local**), como
//!   en DAV, y además se **trae la copia del servidor** por un `GET` propio de Graph
//!   (`/me/events/{id}`, `/me/contacts/{id}`, no el `multiget` DAV): se guarda en
//!   `server_etag`/`server_raw` de la op para que `GetConflict` muestre «la mía vs la
//!   del servidor» y `ResolveConflict` (`keep_local`/`take_server`) funcione —la
//!   maquinaria de resolución del store es la misma de DAV; sólo la captura es propia
//!   de Graph—. La traída respeta el plazo y, si no entra o falla, el conflicto queda
//!   sin copia y se reintenta la próxima vuelta, acotado por [`MAX_REPLAY_ATTEMPTS`].
//! - **Red, `429`, `5xx`** → reintentable, con tope [`MAX_REPLAY_ATTEMPTS`].
//! - **Cualquier otro error** (credencial, `4xx` firme) → permanente: escala a
//!   `conflict` para no trabar la colección (disponibilidad), como en `replay`.
//!
//! **Seguridad:** el token viaja sólo en `Authorization` y nunca se loguea (la
//! credencial tacha su `Debug`); todas las URLs se construyen sobre
//! `credential.base_url` con [`graph::build_url`] (que percent-codifica cada
//! segmento) —**nunca** se sigue una URL de la respuesta para escribir—; el
//! cuerpo sale del crudo local serializado a JSON por `serde_json`, que escapa
//! solo (no hay inyección de línea posible como en los formatos de texto); y la
//! lectura de la respuesta está acotada en tamaño ([`MAX_WRITE_RESPONSE`]) y en
//! plazo (el de la vuelta).

use std::sync::Arc;

use crate::calendar_sync::graph as calendar_graph;
use crate::contacts_sync::graph as contacts_graph;
use crate::graph::{self, GraphCredential};
use crate::replay::ReplayReport;
use crate::store::key::KeySource;
use crate::store::lifecycle::{StoreManager, CALENDAR_AREA};
use crate::store::queue::{PendingKind, PendingOp, PendingState};
use crate::store::StoreError;

/// Cuántos intentos reintentables aguanta una op antes de escalar a `conflict`,
/// igual que en [`crate::replay`]: un recurso que falla por red una y otra vez no
/// puede trabar la colección para siempre.
const MAX_REPLAY_ATTEMPTS: i64 = 10;

/// Tope del cuerpo de la respuesta de una escritura que se lee (el recurso recién
/// creado o editado, para sacarle el `id` y el `@odata.etag`). Un evento o un
/// contacto es chico; más que esto es un servidor roto o adversario y se corta.
const MAX_WRITE_RESPONSE: usize = 256 * 1024;

/// Drena la cola de escrituras de un área de una cuenta Graph. Devuelve el
/// informe; sólo falla con un [`StoreError`] si la base se cerró a mitad (el
/// llavero se bloqueó), que corta la vuelta como cualquier otra escritura.
pub async fn replay_graph_area<K: KeySource>(
    manager: &Arc<StoreManager<K>>,
    account_id: &str,
    area: &'static str,
    client: &reqwest::Client,
    credential: &GraphCredential,
    deadline: tokio::time::Instant,
) -> Result<ReplayReport, StoreError> {
    let ops = manager
        .with_store(account_id, move |store| store.pending_ops(area))
        .await?;

    let mut report = ReplayReport::default();
    for op in ops {
        if tokio::time::Instant::now() >= deadline {
            tracing::info!(
                "'{account_id}': el empuje Graph pasó el plazo de la vuelta; sigue después"
            );
            break;
        }
        // Una op ya en conflicto no se reintenta sola: la resuelve la superficie de
        // conflicto. Pero si quedó **sin la copia del servidor** de una vuelta
        // anterior (la traída falló o no entró en el plazo), se vuelve a intentar
        // traerla ahora —acotado por [`MAX_REPLAY_ATTEMPTS`], igual que el camino
        // DAV—: es lo único que se reintenta de una op en conflicto, y no toca el
        // crudo local ni reintenta la escritura.
        if op.state == PendingState::Conflict {
            if op.server_etag.is_none()
                && op.server_raw.is_none()
                && op.attempts < MAX_REPLAY_ATTEMPTS
            {
                capture_server_copy(
                    manager,
                    account_id,
                    client,
                    credential,
                    deadline,
                    &op.area,
                    op.id,
                    op.revision,
                    &op.object_href,
                )
                .await?;
            }
            continue;
        }
        resolve_op(
            manager,
            account_id,
            client,
            credential,
            area,
            deadline,
            op,
            &mut report,
        )
        .await?;
    }

    report.remaining = manager
        .with_store(account_id, move |store| store.pending_count(area))
        .await? as usize;
    Ok(report)
}

/// El segmento de colección de cada área en la ruta de Graph.
fn segment(area: &str) -> &'static str {
    if area == CALENDAR_AREA {
        "events"
    } else {
        "contacts"
    }
}

/// Resuelve una op: un pedido a Graph y, con la respuesta, un cierre en la base.
#[allow(clippy::too_many_arguments)]
async fn resolve_op<K: KeySource>(
    manager: &Arc<StoreManager<K>>,
    account_id: &str,
    client: &reqwest::Client,
    credential: &GraphCredential,
    area: &'static str,
    deadline: tokio::time::Instant,
    op: PendingOp,
    report: &mut ReplayReport,
) -> Result<(), StoreError> {
    // La identidad de la op, por si un `412`/`409` pide traer la copia del servidor
    // después de cerrar el conflicto: `op` se consume al armar la decisión, así que se
    // guarda acá lo barato (sin el `payload`).
    let (op_id, op_revision) = (op.id, op.revision);
    let object_href = op.object_href.clone();
    let mut server_conflict = false;

    let decision = match op.kind {
        PendingKind::Put => {
            let body = match op.payload.as_deref().map(std::str::from_utf8) {
                Some(Ok(raw)) => raw.to_string(),
                _ => {
                    // Sin cuerpo, o un cuerpo que no es UTF-8: reintentar no lo
                    // arregla. A conflicto, sin perder el local.
                    report.conflicts += 1;
                    let detail = "el cuerpo guardado no es UTF-8".into();
                    return close(manager, account_id, Close::Conflict(op, detail)).await;
                }
            };
            match op.base_etag.clone() {
                // Crear: `if_match` vacío es crear por contrato de la superficie
                // D-Bus, así que un `base_etag` nulo es siempre una creación.
                None => {
                    // El `transactionId` sale del `object_href` local, estable
                    // entre reintentos del mismo objeto: idempotencia nativa de
                    // Graph para los eventos (los contactos no lo soportan).
                    let json = match build_body(area, &body, Some(&op.object_href)) {
                        Some(json) => json,
                        None => {
                            report.conflicts += 1;
                            let detail = "no se pudo serializar el objeto para Graph".into();
                            return close(manager, account_id, Close::Conflict(op, detail)).await;
                        }
                    };
                    let request = create(client, credential, segment(area), &json);
                    match tokio::time::timeout_at(deadline, request).await {
                        // Pasó el plazo de la vuelta: se reintenta.
                        Err(_) => retry_or_escalate(op, "plazo de la vuelta".into(), report),
                        Ok(Ok(created)) => {
                            report.pushed += 1;
                            let new_href = href_for_id(area, &created.id);
                            Close::Create(op, new_href, created.etag)
                        }
                        Ok(Err(e)) => {
                            server_conflict = e == GraphWriteError::Conflict;
                            on_error(op, e, report)
                        }
                    }
                }
                // Editar: `PATCH` con `If-Match`.
                Some(etag) => {
                    let json = match build_body(area, &body, None) {
                        Some(json) => json,
                        None => {
                            report.conflicts += 1;
                            let detail = "no se pudo serializar el objeto para Graph".into();
                            return close(manager, account_id, Close::Conflict(op, detail)).await;
                        }
                    };
                    let id = id_from_href(area, &op.object_href);
                    let request = update(client, credential, segment(area), &id, &etag, &json);
                    match tokio::time::timeout_at(deadline, request).await {
                        Err(_) => retry_or_escalate(op, "plazo de la vuelta".into(), report),
                        Ok(Ok(new_etag)) => {
                            report.pushed += 1;
                            Close::Put(op, new_etag)
                        }
                        Ok(Err(e)) => {
                            server_conflict = e == GraphWriteError::Conflict;
                            on_error(op, e, report)
                        }
                    }
                }
            }
        }
        PendingKind::Delete => {
            let Some(etag) = op.base_etag.clone() else {
                // Sin ETag nunca hubo recurso en el servidor (se creó y se borró
                // local sin subir): se cierra el borrado sin tocar la red.
                report.pushed += 1;
                return close(manager, account_id, Close::Delete(op)).await;
            };
            let id = id_from_href(area, &op.object_href);
            let request = delete(client, credential, segment(area), &id, &etag);
            match tokio::time::timeout_at(deadline, request).await {
                Err(_) => retry_or_escalate(op, "plazo de la vuelta".into(), report),
                // El `404` idempotente lo mapea `classify` a `Ok(())`.
                Ok(Ok(())) => {
                    report.pushed += 1;
                    Close::Delete(op)
                }
                Ok(Err(e)) => {
                    server_conflict = e == GraphWriteError::Conflict;
                    on_error(op, e, report)
                }
            }
        }
    };
    close(manager, account_id, decision).await?;

    // Un `412`/`409` genuino: además de dejar el conflicto, se trae la versión del
    // servidor para que `GetConflict` muestre «local vs. servidor» y
    // `ResolveConflict` pueda aplicar `take_server`/`keep_local`. Va **después** de
    // cerrar el conflicto (el guardado es condicional al estado `conflict`), respeta
    // el plazo y, si falla o no entra, deja el conflicto sin copia (se reintenta la
    // próxima vuelta). Sólo en un conflicto genuino: un error firme que también escala
    // a `conflict` no tiene una versión del servidor que mostrar.
    if server_conflict {
        capture_server_copy(
            manager,
            account_id,
            client,
            credential,
            deadline,
            area,
            op_id,
            op_revision,
            &object_href,
        )
        .await?;
    }
    Ok(())
}

/// Arma el cuerpo JSON de Graph desde el crudo local del área. `transaction_id`
/// sólo se usa al crear un evento (idempotencia); en una edición va `None`.
fn build_body(area: &str, raw: &str, transaction_id: Option<&str>) -> Option<serde_json::Value> {
    if area == CALENDAR_AREA {
        calendar_graph::event_body_from_ical(raw, transaction_id)
    } else {
        Some(contacts_graph::contact_body_from_vcard(raw))
    }
}

/// El `href` que la fila guardada usa para un `id` del servidor, con la **misma
/// escapada que la bajada de cada área** (`escape_text` en calendario,
/// `escape_vcard_public` en contactos): así un `POST` recién creado se re-basa a la
/// fila que la próxima bajada haría upsert, sin duplicar. Único lugar donde vive la
/// escapada del lado escritura, para que no se separe entre las dos áreas.
pub(crate) fn href_for_id(area: &str, id: &str) -> String {
    if area == CALENDAR_AREA {
        crate::serialize::escape_text(id)
    } else {
        crate::vcard::escape_vcard_public(id)
    }
}

/// El `id` del servidor a partir del `href` guardado: el inverso de
/// [`href_for_id`], para interpolarlo en la ruta de `PATCH`/`DELETE`. Para un `id`
/// real de Graph es la identidad; deshace la escapada sólo si el `id` trajera
/// `;`, `,` o `\`.
pub(crate) fn id_from_href(area: &str, href: &str) -> String {
    if area == CALENDAR_AREA {
        crate::ical::unescape_text(href)
    } else {
        crate::vcard::unescape_text(href)
    }
}

/// Lo que puede fallar al escribir en Graph. Tipado como lo clasifica el empuje:
/// cada variante decide reintento vs. conflicto, igual que `DavError` del lado
/// DAV. Ninguna lleva el cuerpo crudo de la respuesta de Graph.
#[derive(Debug, PartialEq, Eq)]
enum GraphWriteError {
    /// `412`/`409`, o un `PATCH`/`DELETE` que dio `404` (el recurso cambió o
    /// desapareció en el servidor): conflicto, no se pisa el local.
    Conflict,
    /// Red, `429`, `5xx`: se reintenta mientras no pase el tope.
    Retryable(String),
    /// Firme (credencial, `4xx` que no es `412`/`409`/`404`, respuesta ilegible):
    /// escala a conflicto para no trabar la colección.
    Permanent(String),
}

impl GraphWriteError {
    fn detail(&self) -> String {
        match self {
            GraphWriteError::Conflict => "el recurso cambió en el servidor".into(),
            GraphWriteError::Retryable(e) => e.clone(),
            GraphWriteError::Permanent(e) => e.clone(),
        }
    }
}

/// El recurso recién creado, tal como lo necesita el cierre.
#[derive(Debug)]
struct Created {
    /// El `id` que asignó el servidor: para re-basar el `href` local.
    id: String,
    /// El `@odata.etag` del recurso, si vino: se guarda para no re-bajarlo.
    etag: Option<String>,
}

/// Lo que se saca del cuerpo de una respuesta de escritura: `id` y `@odata.etag`.
/// Todo opcional: es dato de red.
#[derive(serde::Deserialize)]
struct WriteResponse {
    #[serde(default)]
    id: Option<String>,
    #[serde(rename = "@odata.etag", default)]
    etag: Option<String>,
}

/// `POST /users/{user}/{segmento}`: crea el recurso y devuelve su `id` y ETag.
async fn create(
    client: &reqwest::Client,
    credential: &GraphCredential,
    segment: &str,
    body: &serde_json::Value,
) -> Result<Created, GraphWriteError> {
    let url = graph_url(credential, &["users", &credential.user_id, segment])?;
    let response = send_write(
        client,
        credential,
        reqwest::Method::POST,
        url,
        None,
        Some(body),
    )
    .await?;
    let parsed = read_response(response).await?;
    match parsed.id {
        Some(id) if !id.is_empty() => Ok(Created {
            id,
            etag: parsed.etag,
        }),
        // Un `201` sin `id` no se puede cerrar (no hay a qué re-basar el `href`):
        // es firme, va a conflicto en vez de reintentar un `POST` que duplicaría.
        _ => Err(GraphWriteError::Permanent(
            "Graph creó el objeto pero no devolvió su id".into(),
        )),
    }
}

/// `PATCH /users/{user}/{segmento}/{id}` con `If-Match`. Devuelve el `@odata.etag`
/// nuevo si vino; si no, `None` y la bajada traerá el suyo.
async fn update(
    client: &reqwest::Client,
    credential: &GraphCredential,
    segment: &str,
    id: &str,
    etag: &str,
    body: &serde_json::Value,
) -> Result<Option<String>, GraphWriteError> {
    let url = object_url(credential, segment, id)?;
    let response = send_write(
        client,
        credential,
        reqwest::Method::PATCH,
        url,
        Some(etag),
        Some(body),
    )
    .await?;
    Ok(read_response(response).await?.etag)
}

/// `DELETE /users/{user}/{segmento}/{id}` con `If-Match`. Un `404` es éxito
/// idempotente (lo mapea [`classify`]).
async fn delete(
    client: &reqwest::Client,
    credential: &GraphCredential,
    segment: &str,
    id: &str,
    etag: &str,
) -> Result<(), GraphWriteError> {
    let url = object_url(credential, segment, id)?;
    send_write(
        client,
        credential,
        reqwest::Method::DELETE,
        url,
        Some(etag),
        None,
    )
    .await
    .map(|_| ())
}

/// Manda un pedido de escritura y clasifica su estado. Lo común a crear, editar y
/// borrar: el token en `Authorization`, el `Accept` cuando hay respuesta que leer,
/// el `If-Match` de precondición si lo hay, y el cuerpo JSON si lo hay. Un error de
/// red es reintentable. El `is_delete` de [`classify`] sale de si el método es
/// `DELETE` (es el único que trata un `404` como éxito idempotente).
async fn send_write(
    client: &reqwest::Client,
    credential: &GraphCredential,
    method: reqwest::Method,
    url: url::Url,
    if_match: Option<&str>,
    body: Option<&serde_json::Value>,
) -> Result<reqwest::Response, GraphWriteError> {
    let is_delete = method == reqwest::Method::DELETE;
    let mut request = client
        .request(method, url)
        .bearer_auth(credential.access_token.as_str());
    // El `DELETE` no lee cuerpo de respuesta; los demás sí.
    if !is_delete {
        request = request.header("Accept", "application/json");
    }
    if let Some(etag) = if_match {
        request = request.header("If-Match", etag);
    }
    if let Some(body) = body {
        request = request.json(body);
    }
    let response = request
        .send()
        .await
        // `without_url()`: el `Display` de `reqwest::Error` incluye la URL —con el
        // `user_id` (que puede ser un UPN/correo) y el id del objeto—, y esto termina
        // en `pending_dav_ops.last_error` y la superficie de conflicto. Se tacha,
        // como el camino DAV.
        .map_err(|e| GraphWriteError::Retryable(e.without_url().to_string()))?;
    classify(response.status(), is_delete)?;
    Ok(response)
}

/// Una URL de Graph construida **sobre la base de la credencial** —el único origen
/// al que viaja el token— a partir de los segmentos de ruta. [`graph::build_url`]
/// percent-codifica cada segmento, así que un `id` con `/`, `?` o `#` no puede
/// alterar la ruta ni colar una query; el `?` que deja la query vacía se limpia.
fn graph_url(credential: &GraphCredential, segments: &[&str]) -> Result<url::Url, GraphWriteError> {
    let mut url = graph::build_url(&credential.base_url, segments, "")
        .map_err(|e| GraphWriteError::Permanent(e.to_string()))?;
    url.set_query(None);
    Ok(url)
}

/// La URL de un objeto (`/users/{user}/{segmento}/{id}`), sobre [`graph_url`].
fn object_url(
    credential: &GraphCredential,
    segment: &str,
    id: &str,
) -> Result<url::Url, GraphWriteError> {
    graph_url(credential, &["users", &credential.user_id, segment, id])
}

/// Clasifica el estado HTTP de una escritura. `is_delete` cambia qué se hace con
/// un `404`: en un `DELETE` es éxito idempotente; en un `PATCH` es que el recurso
/// desapareció → conflicto.
fn classify(status: reqwest::StatusCode, is_delete: bool) -> Result<(), GraphWriteError> {
    if status.is_success() {
        return Ok(());
    }
    match status.as_u16() {
        404 if is_delete => Ok(()),
        404 => Err(GraphWriteError::Conflict),
        409 | 412 => Err(GraphWriteError::Conflict),
        // 429 y 5xx: transitorios. Sólo el código, nunca el cuerpo.
        429 => Err(GraphWriteError::Retryable(format!(
            "Graph respondió {status}"
        ))),
        s if (500..=599).contains(&s) => Err(GraphWriteError::Retryable(format!(
            "Graph respondió {status}"
        ))),
        _ => Err(GraphWriteError::Permanent(format!(
            "Graph respondió {status}"
        ))),
    }
}

/// Lee el cuerpo de una respuesta de escritura, **acotado en tamaño**
/// ([`MAX_WRITE_RESPONSE`]), y le saca `id`/`@odata.etag`. Un cuerpo vacío
/// —`204 No Content` de un `PATCH`— devuelve todo en `None`, que es válido.
async fn read_response(response: reqwest::Response) -> Result<WriteResponse, GraphWriteError> {
    let bytes = response
        .bytes()
        .await
        // `without_url()`: no filtrar la URL (con el `user_id`) al diario de errores.
        .map_err(|e| GraphWriteError::Retryable(e.without_url().to_string()))?;
    if bytes.len() > MAX_WRITE_RESPONSE {
        return Err(GraphWriteError::Permanent(
            "la respuesta de Graph supera el tope de tamaño".into(),
        ));
    }
    if bytes.is_empty() {
        return Ok(WriteResponse {
            id: None,
            etag: None,
        });
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| GraphWriteError::Permanent("respuesta de Graph ilegible".into()))
}

/// Decide qué hacer con el error de una escritura, y cuenta en el informe. Mismo
/// criterio que [`crate::replay`]: conflicto se marca, reintentable se reintenta
/// hasta el tope, y lo firme escala a conflicto para no trabar la colección.
fn on_error(op: PendingOp, error: GraphWriteError, report: &mut ReplayReport) -> Close {
    match error {
        GraphWriteError::Conflict => {
            report.conflicts += 1;
            Close::Conflict(op, error.detail())
        }
        GraphWriteError::Retryable(_) => retry_or_escalate(op, error.detail(), report),
        GraphWriteError::Permanent(_) => {
            report.conflicts += 1;
            Close::Conflict(op, error.detail())
        }
    }
}

/// Reintenta mientras la op no haya pasado [`MAX_REPLAY_ATTEMPTS`]; si los pasó,
/// escala a conflicto, como en [`crate::replay`].
fn retry_or_escalate(op: PendingOp, detail: String, report: &mut ReplayReport) -> Close {
    if op.attempts + 1 < MAX_REPLAY_ATTEMPTS {
        report.retried += 1;
        Close::Retry(op, detail)
    } else {
        report.conflicts += 1;
        Close::Conflict(op, detail)
    }
}

/// Cómo se cierra una op en la base.
enum Close {
    /// `POST` de creación cerrado: se re-basa el `href` al id del servidor y se
    /// guarda el ETag.
    Create(PendingOp, String, Option<String>),
    /// `PATCH` cerrado, con el ETag nuevo si vino.
    Put(PendingOp, Option<String>),
    /// `DELETE` cerrado.
    Delete(PendingOp),
    /// Conflicto o error firme: se conserva el local, la op queda en `conflict`.
    Conflict(PendingOp, String),
    /// Para reintentar.
    Retry(PendingOp, String),
}

/// Aplica el cierre en la base, en una llamada a `with_store`.
async fn close<K: KeySource>(
    manager: &Arc<StoreManager<K>>,
    account_id: &str,
    close: Close,
) -> Result<(), StoreError> {
    manager
        .with_store(account_id, move |store| match close {
            Close::Create(op, href, etag) => store.complete_create(&op, &href, etag.as_deref()),
            Close::Put(op, etag) => store.complete_put(&op, etag.as_deref()),
            Close::Delete(op) => store.complete_delete(&op),
            Close::Conflict(op, detail) => store.mark_conflict(&op, &detail),
            Close::Retry(op, detail) => store.retry_later(&op, &detail),
        })
        .await
}

/// Trae la versión del servidor de un recurso Graph en conflicto y la guarda cifrada
/// en la op, **condicionada al `id` y la `revision`** (ver `Store::store_server_copy`).
/// Es el equivalente Graph de `replay::capture_server_copy`: en vez del `multiget` DAV,
/// un `GET` propio de Graph por área ([`fetch_server_copy`]).
///
/// Respeta el plazo de la vuelta: si la traída no entra, si falla, o si el recurso ya
/// no está (`Ok(None)`), **se deja el conflicto sin copia** y se le suma un intento
/// (`Store::count_conflict_fetch_attempt`), así la re-traída queda acotada por
/// [`MAX_REPLAY_ATTEMPTS`]. El detalle del error no se registra: el crudo del servidor
/// es dato privado y no tiene por qué terminar en el diario.
#[allow(clippy::too_many_arguments)]
async fn capture_server_copy<K: KeySource>(
    manager: &Arc<StoreManager<K>>,
    account_id: &str,
    client: &reqwest::Client,
    credential: &GraphCredential,
    deadline: tokio::time::Instant,
    area: &str,
    id: i64,
    revision: i64,
    object_href: &str,
) -> Result<(), StoreError> {
    // El `id` del servidor sale del `href` guardado (su inverso de `href_for_id`), y
    // la URL del `GET` la arma `fetch_server_copy` sobre `credential.base_url`.
    let server_id = id_from_href(area, object_href);
    let stored = match tokio::time::timeout_at(
        deadline,
        fetch_server_copy(area, client, credential, &server_id),
    )
    .await
    {
        Err(_) => {
            tracing::info!(
                "'{account_id}': la copia del servidor del conflicto Graph no entró en el plazo; \
                 se trae la próxima vuelta"
            );
            false
        }
        // El recurso no volvió (se borró en el servidor): no hay copia que guardar.
        Ok(Ok(None)) => false,
        Ok(Err(_)) => {
            // Sin el detalle: puede venir del servidor y el crudo es privado.
            tracing::info!(
                "'{account_id}': no se pudo traer la copia del servidor del conflicto Graph; \
                 se reintenta la próxima vuelta"
            );
            false
        }
        Ok(Ok(Some((server_etag, server_raw)))) => {
            manager
                .with_store(account_id, move |store| {
                    store.store_server_copy(id, revision, server_etag.as_deref(), &server_raw)
                })
                .await?
        }
    };

    if !stored {
        manager
            .with_store(account_id, move |store| {
                store.count_conflict_fetch_attempt(id, revision)
            })
            .await?;
    }
    Ok(())
}

/// Despacha la traída de la copia del servidor al `GET` del área: el del calendario
/// o el de contactos, cada uno sobre su struct y su conversión de la bajada (para que
/// el `server_raw` salga en el mismo formato iCal/vCard que un objeto DAV).
async fn fetch_server_copy(
    area: &str,
    client: &reqwest::Client,
    credential: &GraphCredential,
    id: &str,
) -> Result<Option<(Option<String>, Vec<u8>)>, graph::GraphFetchError> {
    if area == CALENDAR_AREA {
        calendar_graph::fetch_server_copy(client, credential, id).await
    } else {
        contacts_graph::fetch_server_copy(client, credential, id).await
    }
}

#[cfg(test)]
mod tests;
