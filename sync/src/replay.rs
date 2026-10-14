//! La etapa de empuje: drena la cola de escrituras hacia el servidor.
//!
//! En cada vuelta de sincronización, **antes de dar la bajada por al día**, se
//! drena `pending_dav_ops` de la cuenta (ver `store::queue`): por cada op se
//! arma el `PUT` o el `DELETE` con la precondición de ETag que corresponda y, según
//! lo que conteste el servidor, se cierra la op, se la deja en conflicto o se la
//! deja para reintentar. Reusa la **misma credencial** del área —no pide una
//! nueva— y el mismo plazo de la vuelta.
//!
//! El trabajo con la base y los pedidos a la red van **intercalados, nunca
//! juntos**: se lee la cola con la base prestada, se suelta, se habla con el
//! servidor, y recién con la respuesta se vuelve a tomar la base para cerrar la
//! op. Así no se sostiene la cerradura del almacén a través de un `.await`, como
//! en el resto del sincronizador.
//!
//! Qué se hace con cada resultado:
//!
//! - **`PUT`/`DELETE` que salió bien** → se cierra la op. En un `put` con ETag,
//!   se guarda el del recurso recién escrito; sin ETag (`NeedsRefetch`), se deja
//!   el ETag local en `NULL` para que la bajada traiga el suyo. En un `delete`,
//!   se borra la fila guardada. Un `DELETE` con `404` es éxito idempotente (lo
//!   mapea el cliente): el recurso ya no está, que es lo que se buscaba.
//! - **`412 Conflict`** → el recurso cambió en el servidor desde `base_etag`
//!   (o un `Create` chocó con algo que ya está en ese `href`). **No se pisa
//!   nada**: se conserva el crudo local y la op queda en `conflict` para que M3
//!   la resuelva de cara a la persona. No se intenta adivinar «es mi creación
//!   que ya llegó» vs. «hay otro recurso ahí»: adivinar mal pisaría la creación
//!   local con contenido ajeno en la próxima bajada. **Además de marcar el
//!   conflicto, se trae la versión del servidor** del recurso —su ETag y su
//!   crudo— por el mismo camino de lectura de un recurso del cliente DAV (un
//!   `multiget` por `href`), y se guarda cifrada en la op
//!   ([`capture_server_copy`]) para que M3 muestre «local vs. servidor». La
//!   traída respeta el plazo de la vuelta y se guarda **condicionada al `id` y la
//!   `revision`** de la op (como los demás cierres), para no resucitar una foto
//!   vieja sobre una edición concurrente. Si la traída falla o no entra en el
//!   plazo, el conflicto queda sin copia y se reintenta la próxima vuelta: una op
//!   en `conflict` sin copia del servidor se vuelve a intentar al drenar.
//! - **Red, `423`, `507` (reintentables, [`DavError::is_retryable`])** → la op
//!   se deja, con un reintento más y el detalle en `last_error`. Vuelve a
//!   intentarse en la próxima vuelta, respetando el plazo. Tras
//!   [`MAX_REPLAY_ATTEMPTS`] intentos escala a `conflict`, para no reintentar
//!   para siempre y trabar el token de la colección.
//! - **Cualquier otro error** (credencial, estado inesperado, redirección,
//!   origen ajeno, precondición inservible) → es **permanente**: reintentarlo da
//!   lo mismo. Escala a `conflict` (lo resuelve M3) en vez de quedar en `ready`
//!   trabando la colección para siempre (disponibilidad).
//!
//! **Idempotencia**: un `delete` reejecutado sobre algo que ya no está vuelve
//! con `404`, que el cliente mapea a éxito. Un `Create` reintentado que el
//! servidor ya tenía vuelve con `412` y va a `conflict`: la creación local se
//! conserva y M3 decide, en vez de arriesgarse a pisarla con lo que haya en ese
//! `href`.

use crate::dav::webdav::{DavClient, DavError, Precondition, PutOutcome};
use crate::store::key::KeySource;
use crate::store::lifecycle::{StoreManager, CALENDAR_AREA};
use crate::store::queue::{PendingKind, PendingOp, PendingState};
use crate::store::StoreError;

/// El `Content-Type` del cuerpo de un `PUT` de cada área.
pub const CALENDAR_CONTENT_TYPE: &str = "text/calendar; charset=utf-8";
pub const CONTACTS_CONTENT_TYPE: &str = "text/vcard; charset=utf-8";

/// Lo que hizo una etapa de empuje, para el informe de la vuelta.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayReport {
    /// Ops cerradas con éxito (escritas o borradas en el servidor).
    pub pushed: usize,
    /// Ops que quedaron en conflicto (`412`): las resuelve M3.
    pub conflicts: usize,
    /// Ops que quedaron para reintentar (red, `423`, `507`, otros).
    pub retried: usize,
    /// Ops que siguen pendientes al terminar, en cualquier estado.
    pub remaining: usize,
}

/// Cuántos intentos reintentables aguanta una op antes de escalar a `conflict`.
/// Un recurso que falla por red una y otra vez no puede trabar el token de su
/// colección para siempre: tras esto lo resuelve M3.
const MAX_REPLAY_ATTEMPTS: i64 = 10;

/// Drena la cola de un área contra el servidor. Devuelve el informe; sólo falla
/// con un [`StoreError`] si la base se cerró a mitad (el llavero se bloqueó),
/// que corta la vuelta como cualquier otra escritura.
pub async fn replay_area<K: KeySource>(
    manager: &StoreManager<K>,
    account_id: &str,
    area: &'static str,
    client: &DavClient,
    content_type: &str,
    deadline: tokio::time::Instant,
) -> Result<ReplayReport, StoreError> {
    let ops = manager
        .with_store(account_id, move |store| store.pending_ops(area))
        .await?;

    let mut report = ReplayReport::default();
    for op in ops {
        if tokio::time::Instant::now() >= deadline {
            tracing::info!("'{account_id}': el empuje pasó el plazo de la vuelta; sigue después");
            break;
        }
        // Una op en conflicto no se reintenta sola: la resuelve M3. Pero si
        // quedó sin la copia del servidor de una vuelta anterior (la traída
        // falló o no entró en el plazo), se vuelve a intentar traerla ahora: es
        // lo único que se reintenta de una op en conflicto, y no toca el crudo
        // local ni reintenta la escritura.
        if op.state == PendingState::Conflict {
            if op.server_etag.is_none() && op.server_raw.is_none() {
                if let Ok(object) = url::Url::parse(&op.object_href) {
                    capture_server_copy(
                        manager,
                        account_id,
                        client,
                        deadline,
                        &op.area,
                        op.id,
                        op.revision,
                        &op.collection_href,
                        &object,
                    )
                    .await?;
                }
            }
            continue;
        }
        resolve_op(
            manager,
            account_id,
            client,
            content_type,
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

/// Resuelve una op: un pedido a la red y, con la respuesta, un cierre en la base.
async fn resolve_op<K: KeySource>(
    manager: &StoreManager<K>,
    account_id: &str,
    client: &DavClient,
    content_type: &str,
    deadline: tokio::time::Instant,
    op: PendingOp,
    report: &mut ReplayReport,
) -> Result<(), StoreError> {
    let url = match url::Url::parse(&op.object_href) {
        Ok(url) => url,
        Err(_) => {
            // La dirección guardada no se puede volver a parsear: raro, porque se
            // guardó desde una URL válida. Es permanente: a conflicto, no a
            // reintentar para siempre.
            report.conflicts += 1;
            return close(
                manager,
                account_id,
                Close::Conflict(op, "dirección inválida".into()),
            )
            .await;
        }
    };

    // La identidad de la op, por si un `412` pide traer la copia del servidor
    // después de cerrar el conflicto: `op` se consume al armar el cierre, así que
    // se guarda acá lo barato (sin el `payload`).
    let (id, revision) = (op.id, op.revision);
    let area = op.area.clone();
    let collection_href = op.collection_href.clone();
    let mut server_conflict = false;

    let decision = match op.kind {
        PendingKind::Put => {
            let body = match String::from_utf8(op.payload.clone().unwrap_or_default()) {
                Ok(body) => body,
                Err(_) => {
                    // Un cuerpo que no es UTF-8 no va a mejorar reintentando: a
                    // conflicto.
                    report.conflicts += 1;
                    let detail = "el cuerpo guardado no es UTF-8".into();
                    return close(manager, account_id, Close::Conflict(op, detail)).await;
                }
            };
            let precondition = match op.base_etag.clone() {
                Some(etag) => Precondition::Replace(etag),
                None => Precondition::Create,
            };
            match run(deadline, client.put(&url, body, precondition, content_type)).await {
                Timed::Elapsed => retry_or_escalate(op, "plazo de la vuelta".into(), report),
                Timed::Done(Ok(PutOutcome::Etag(etag))) => {
                    report.pushed += 1;
                    Close::Put(op, Some(etag))
                }
                Timed::Done(Ok(PutOutcome::NeedsRefetch)) => {
                    report.pushed += 1;
                    Close::Put(op, None)
                }
                Timed::Done(Err(e)) => {
                    server_conflict = e == DavError::Conflict;
                    on_error(op, e, report)
                }
            }
        }
        PendingKind::Delete => {
            let Some(etag) = op.base_etag.clone() else {
                // Sin ETag no hubo nunca recurso en el servidor (se creó y se
                // borró local sin subir): se cierra el borrado sin tocar la red.
                report.pushed += 1;
                return close(manager, account_id, Close::Delete(op)).await;
            };
            match run(deadline, client.delete(&url, &etag)).await {
                Timed::Elapsed => retry_or_escalate(op, "plazo de la vuelta".into(), report),
                // Éxito, y el `404` idempotente, los mapea el cliente a `Ok(())`.
                Timed::Done(Ok(())) => {
                    report.pushed += 1;
                    Close::Delete(op)
                }
                Timed::Done(Err(e)) => {
                    server_conflict = e == DavError::Conflict;
                    on_error(op, e, report)
                }
            }
        }
    };
    close(manager, account_id, decision).await?;

    // Un `412` genuino: además de dejar el conflicto, se trae la versión del
    // servidor para que M3 muestre «local vs. servidor». Va **después** de cerrar
    // el conflicto —el guardado es condicional al estado `conflict`—, respeta el
    // plazo y, si falla o no entra, deja el conflicto sin copia (se reintenta la
    // próxima vuelta). Sólo en un `412`: un error permanente que también escala a
    // `conflict` no tiene una versión del servidor que mostrar.
    if server_conflict {
        capture_server_copy(
            manager,
            account_id,
            client,
            deadline,
            &area,
            id,
            revision,
            &collection_href,
            &url,
        )
        .await?;
    }
    Ok(())
}

/// Decide qué hacer con el error de una escritura, y cuenta en el informe.
///
/// Un `412` es siempre conflicto: el recurso cambió, o un `Create` chocó con
/// algo que ya está en ese `href` (no se adivina «es mi creación»). Un error
/// **reintentable** ([`DavError::is_retryable`]) se reintenta mientras no pase
/// el tope; **cualquier otro** —credencial, estado inesperado, redirección,
/// origen ajeno, precondición inservible— es permanente y va a conflicto, para
/// no quedar en `ready` trabando el token de la colección para siempre.
fn on_error(op: PendingOp, error: DavError, report: &mut ReplayReport) -> Close {
    if error == DavError::Conflict {
        report.conflicts += 1;
        return Close::Conflict(op, "el recurso cambió en el servidor".into());
    }
    if error.is_retryable() {
        return retry_or_escalate(op, error.log_text(), report);
    }
    report.conflicts += 1;
    Close::Conflict(op, error.log_text())
}

/// Reintenta mientras la op no haya pasado [`MAX_REPLAY_ATTEMPTS`]; si los pasó,
/// escala a conflicto para que M3 lo resuelva y la colección pueda asentar su
/// token.
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
    /// `put` cerrado con éxito, con el ETag del servidor si vino.
    Put(PendingOp, Option<String>),
    /// `delete` cerrado con éxito.
    Delete(PendingOp),
    /// Conflicto o error permanente: se conserva lo local, la op queda en
    /// `conflict` con el detalle.
    Conflict(PendingOp, String),
    /// Para reintentar, con el detalle.
    Retry(PendingOp, String),
}

/// Aplica el cierre en la base, en una llamada a `with_store`.
async fn close<K: KeySource>(
    manager: &StoreManager<K>,
    account_id: &str,
    close: Close,
) -> Result<(), StoreError> {
    manager
        .with_store(account_id, move |store| match close {
            Close::Put(op, etag) => store.complete_put(&op, etag.as_deref()),
            Close::Delete(op) => store.complete_delete(&op),
            Close::Conflict(op, detail) => store.mark_conflict(&op, &detail),
            Close::Retry(op, detail) => store.retry_later(&op, &detail),
        })
        .await
}

/// El resultado de un pedido con el plazo de la vuelta encima.
enum Timed<T> {
    Done(T),
    Elapsed,
}

/// Corre un pedido a la red cortándolo si pasa el plazo de la vuelta.
async fn run<T>(
    deadline: tokio::time::Instant,
    request: impl std::future::Future<Output = T>,
) -> Timed<T> {
    match tokio::time::timeout_at(deadline, request).await {
        Ok(value) => Timed::Done(value),
        Err(_) => Timed::Elapsed,
    }
}

/// Trae del servidor la versión actual de un recurso —su ETag y su crudo— por el
/// mismo camino de lectura de un recurso del cliente DAV: un `calendar-multiget`
/// o un `addressbook-multiget` por `href`, según el área. Reusa la **misma
/// credencial** del cliente, como el resto del empuje; no pide una nueva.
///
/// `Ok(None)` es que el recurso **no volvió**: el servidor lo omitió, lo contestó
/// con un estado de error o ya no está. Ahí no hay copia que guardar, y el
/// conflicto queda sin ella (se reintenta la próxima vuelta).
async fn fetch_server_copy(
    area: &str,
    client: &DavClient,
    collection: &url::Url,
    object: &url::Url,
) -> Result<Option<(Option<String>, Vec<u8>)>, DavError> {
    let hrefs = [object.clone()];
    let copy = if area == CALENDAR_AREA {
        crate::dav::caldav::multiget(client, collection, &hrefs)
            .await?
            .items
            .into_iter()
            .next()
            .map(|o| (o.etag, o.data.into_bytes()))
    } else {
        crate::dav::carddav::multiget(client, collection, &hrefs)
            .await?
            .items
            .into_iter()
            .next()
            .map(|c| (c.etag, c.data.into_bytes()))
    };
    Ok(copy)
}

/// Trae la versión del servidor de un recurso en conflicto y la guarda cifrada en
/// la op, **condicionada al `id` y la `revision`** (ver `Store::store_server_copy`).
///
/// Respeta el plazo de la vuelta: si la traída no entra, si falla, o si el
/// recurso no volvió, **se deja el conflicto sin copia** y se reintenta la
/// próxima vuelta —nunca se bloquea ni se pierde el conflicto—. El detalle del
/// error no se registra: el crudo del servidor es dato privado y no tiene por qué
/// terminar en el diario.
#[allow(clippy::too_many_arguments)]
async fn capture_server_copy<K: KeySource>(
    manager: &StoreManager<K>,
    account_id: &str,
    client: &DavClient,
    deadline: tokio::time::Instant,
    area: &str,
    id: i64,
    revision: i64,
    collection_href: &str,
    object: &url::Url,
) -> Result<(), StoreError> {
    let Ok(collection) = url::Url::parse(collection_href) else {
        // La dirección de la colección no se puede parsear: sin ella no hay a
        // quién pedirle la copia. Raro, porque se guardó desde una URL válida.
        return Ok(());
    };
    let copy = match run(
        deadline,
        fetch_server_copy(area, client, &collection, object),
    )
    .await
    {
        Timed::Elapsed => {
            tracing::info!(
                "'{account_id}': la copia del servidor del conflicto no entró en el plazo; \
                 se trae la próxima vuelta"
            );
            return Ok(());
        }
        Timed::Done(Ok(Some(copy))) => copy,
        Timed::Done(Ok(None)) => return Ok(()),
        Timed::Done(Err(_)) => {
            // Sin el detalle: puede venir del servidor y el crudo es privado.
            tracing::info!(
                "'{account_id}': no se pudo traer la copia del servidor del conflicto; \
                 se reintenta la próxima vuelta"
            );
            return Ok(());
        }
    };

    let (server_etag, server_raw) = copy;
    manager
        .with_store(account_id, move |store| {
            store.store_server_copy(id, revision, server_etag.as_deref(), &server_raw)?;
            Ok(())
        })
        .await
}

#[cfg(test)]
mod tests;
