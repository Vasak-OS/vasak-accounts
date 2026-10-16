//! Backend Microsoft Graph API para sincronización de **calendario**.
//!
//! Lee los eventos del calendario del usuario (`/me/events`) con paginación por
//! `@odata.nextLink`, los convierte a `VEVENT` y hace upsert en el almacén de
//! calendario. Es el hermano del backend de contactos
//! ([`crate::contacts_sync::graph`]) y comparte con él toda la maquinaria de
//! Graph —credencial, errores, paginación con validación de mismo-origen— que
//! vive en [`crate::graph`].
//!
//! Es **de sólo lectura**: no escribe nada contra Graph. La escritura por Graph
//! (`Calendars.ReadWrite`) es fase 2 (Vasak-OS/vasak-accounts#97).
//!
//! ── Por qué en UTC ───────────────────────────────────────────────────────────
//!
//! Cada pedido lleva `Prefer: outlook.timezone="UTC"`, así Graph devuelve las
//! fechas en UTC en vez de en nombres de zona de Windows («Pacific Standard
//! Time»), que habría que traducir a IANA. Con eso cada `DTSTART`/`DTEND` sale
//! en UTC (`...Z`) y no hace falta emitir ningún `VTIMEZONE`.

use std::sync::Arc;

use chrono::NaiveDateTime;

use crate::calendar_sync::{CalendarOutcome, CalendarReport, CLOSED_DETAIL};
use crate::graph::{self, GraphCredential, GraphFetchError};
use crate::ical::recurrence::ExpansionLimits;
use crate::serialize::escape_text;
use crate::store::calendar::{
    derive_with_occurrences, CalendarApplied, CalendarListing, CalendarProgress, CalendarRoom,
    ObjectOp, ObjectRow, Window, WRITE_BATCH_ROWS,
};
use crate::store::key::{KeyError, KeySource};
use crate::store::lifecycle::{AreaState, StoreManager, CALENDAR_AREA};
use crate::store::StoreError;

/// Tope de eventos acumulados. Cota de memoria independiente del tope de
/// páginas de [`crate::graph`], por si un servidor devuelve páginas enormes.
const MAX_EVENTS: usize = 100_000;

/// El `href` y el nombre de la libreta por defecto donde se guardan los eventos
/// de Graph: una sola colección, como la de contactos (`graph://default`).
const DEFAULT_CALENDAR_HREF: &str = "graph://default";
const DEFAULT_CALENDAR_NAME: &str = "Graph Calendar";

/// Los campos del evento que se piden con `$select`: sólo lo que se convierte a
/// `VEVENT`, para no traer de más.
const EVENTS_SELECT: &str = "$top=100&$select=id,iCalUId,subject,bodyPreview,start,end,isAllDay,\
     location,organizer,attendees,recurrence,categories,importance,lastModifiedDateTime,isCancelled";

/// Los mismos campos que [`EVENTS_SELECT`] pero **sin `$top`**: para el `GET` de una
/// sola entidad (la copia del servidor de un conflicto). `$top` es un parámetro de
/// listado y no va en el `GET` de un objeto.
const EVENTS_SELECT_ITEM: &str = "$select=id,iCalUId,subject,bodyPreview,start,end,isAllDay,\
     location,organizer,attendees,recurrence,categories,importance,lastModifiedDateTime,isCancelled";

/// Pedir las fechas en UTC en vez de en nombres de zona de Windows.
const PREFER_UTC: (&str, &str) = ("Prefer", "outlook.timezone=\"UTC\"");

/// Un evento del calendario de Microsoft Graph.
///
/// Todo opcional y con `default`: es dato de red, así que un campo que no venga
/// queda vacío y nunca hace fallar el parseo.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct GraphEvent {
    id: String,
    /// El testigo de concurrencia de Graph. Se captura en la lectura para que la
    /// escritura (`#97`) pueda mandar `If-Match: @odata.etag`: sin él la
    /// precondición no tiene nada que enviar y el `412` nunca se dispara.
    #[serde(rename = "@odata.etag")]
    odata_etag: Option<String>,
    #[serde(rename = "iCalUId")]
    i_cal_uid: String,
    subject: Option<String>,
    body_preview: Option<String>,
    start: Option<GraphDateTime>,
    end: Option<GraphDateTime>,
    is_all_day: bool,
    is_cancelled: bool,
    location: Option<GraphLocation>,
    organizer: Option<GraphRecipient>,
    attendees: Vec<GraphAttendee>,
    recurrence: Option<GraphRecurrence>,
    categories: Vec<String>,
    importance: Option<String>,
    last_modified_date_time: Option<String>,
}

/// La fecha-hora de Graph: `dateTime` sin zona (ya en UTC por el `Prefer`).
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct GraphDateTime {
    date_time: Option<String>,
    time_zone: Option<String>,
}

/// El lugar de un evento.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct GraphLocation {
    display_name: Option<String>,
}

/// Un destinatario (organizador o asistente) de Graph.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct GraphRecipient {
    email_address: Option<GraphEmailAddress>,
}

/// La dirección de correo de un destinatario.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct GraphEmailAddress {
    name: Option<String>,
    address: Option<String>,
}

/// Un asistente: su dirección y su respuesta.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct GraphAttendee {
    email_address: Option<GraphEmailAddress>,
    status: Option<GraphResponseStatus>,
}

/// La respuesta de un asistente (`none`, `accepted`, `declined`, …).
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct GraphResponseStatus {
    response: Option<String>,
}

/// La recurrencia de Graph: patrón más rango.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct GraphRecurrence {
    pattern: Option<GraphRecurrencePattern>,
    range: Option<GraphRecurrenceRange>,
}

/// El patrón de repetición de Graph.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct GraphRecurrencePattern {
    /// `daily`, `weekly`, `absoluteMonthly`, `relativeMonthly`,
    /// `absoluteYearly`, `relativeYearly`.
    r#type: Option<String>,
    interval: Option<u32>,
    days_of_week: Vec<String>,
    day_of_month: Option<u32>,
    /// `first`, `second`, `third`, `fourth`, `last`.
    index: Option<String>,
    month: Option<u32>,
}

/// El rango de la repetición de Graph.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct GraphRecurrenceRange {
    /// `endDate`, `noEnd`, `numbered`.
    r#type: Option<String>,
    end_date: Option<String>,
    number_of_occurrences: Option<u32>,
}

/// Lo que un backend de calendario necesita para una vuelta de Graph.
///
/// Espejo del `SyncContext` de contactos, con lo que el calendario suma: la
/// ventana en la que se expanden las ocurrencias y los topes de la expansión.
pub struct GraphSyncContext<'a, K: KeySource> {
    pub manager: &'a Arc<StoreManager<K>>,
    pub account_id: &'a str,
    pub notify: Arc<dyn Fn() + Send + Sync>,
    /// La ventana con la que se expanden las series; la de la base, o la de hoy
    /// la primera vez.
    pub window: Window,
    pub expansion: ExpansionLimits,
}

// ── Escritura por Graph (`#97`) ──────────────────────────────────────────────
//
// El lado de vuelta del backend: el empuje de `crate::graph_write` convierte el
// crudo iCal de la cola a JSON de Graph. La escapada del `href` (`escape_text`, la
// misma de la lectura) vive con su inversa en `graph_write::href_for_id`, un solo
// lugar para las dos áreas.

/// Convierte el crudo iCal de un evento al cuerpo JSON de Graph (`/me/events`),
/// subconjunto conservador (decisión 3): `subject`, `body` (texto), `start`/`end`
/// en UTC, `isAllDay` y `location`. Lo que no modelamos no se manda, y como
/// `PATCH` fusiona, no se pisa en el servidor.
///
/// `transaction_id` sólo al **crear** (`POST`): es la idempotencia nativa de Graph
/// para eventos —un `POST` reintentado con el mismo `transactionId` no crea un
/// segundo evento—. En una edición va `None`.
///
/// `None` si el crudo no trae un `VEVENT` (p. ej. un `VTODO`, que no va a
/// `/me/events`): el empuje lo manda a conflicto en vez de crear algo torcido.
///
/// **Sin inyección**: el cuerpo lo arma `serde_json`, que escapa los valores solo;
/// no hay forma de partir una línea como en los formatos de texto.
pub(crate) fn event_body_from_ical(
    raw_ical: &str,
    transaction_id: Option<&str>,
) -> Option<serde_json::Value> {
    use serde_json::json;
    let document = crate::ical::parse_document(raw_ical);
    let vevent = document.components.iter().find(|c| c.name == "VEVENT")?;

    let text = |name: &str| {
        vevent
            .first(name)
            .map(|p| crate::ical::unescape_text(&p.value))
    };

    let mut body = serde_json::Map::new();
    if let Some(subject) = text("SUMMARY") {
        body.insert("subject".into(), json!(subject));
    }
    if let Some(content) = text("DESCRIPTION") {
        body.insert(
            "body".into(),
            json!({ "contentType": "text", "content": content }),
        );
    }
    if let Some(location) = text("LOCATION") {
        body.insert("location".into(), json!({ "displayName": location }));
    }

    let dtstart = vevent.first("DTSTART");
    let dtend = vevent.first("DTEND");
    let all_day = dtstart.map(is_date_only).unwrap_or(false);
    // Un `DTSTART`/`DTEND` que existe pero no se puede convertir (flotante, `TZID`
    // desconocido, hora inexistente o ambigua) **aborta todo el cuerpo** con `None`,
    // no se omite la fecha. `resolve_op` lleva ese `None` a conflicto: el crudo local
    // queda intacto y la persona lo resuelve. Mandar el `PATCH` sin la fecha la
    // borraría en el servidor en silencio, y la bajada siguiente pisaría con la vieja
    // (pérdida de dato). Un evento sin `DTSTART` en el crudo —si existe— se deja pasar
    // como está.
    if let Some(dtstart) = dtstart {
        body.insert("start".into(), graph_datetime(dtstart)?);
    }
    if let Some(dtend) = dtend {
        body.insert("end".into(), graph_datetime(dtend)?);
    }
    body.insert("isAllDay".into(), json!(all_day));

    if let Some(id) = transaction_id {
        body.insert("transactionId".into(), json!(id));
    }
    Some(serde_json::Value::Object(body))
}

/// Si una propiedad de fecha es de día completo (`VALUE=DATE`).
fn is_date_only(property: &crate::ical::Property) -> bool {
    property
        .params
        .iter()
        .any(|p| p.eq_ignore_ascii_case("VALUE=DATE"))
}

/// Un valor de fecha-hora iCal (`20260915T140000Z`, `20260915T140000` o, de día
/// completo, `20260915`) al `dateTime` de Graph (`2026-09-15T14:00:00`), siempre
/// en UTC —la lectura las pide así (`Prefer: outlook.timezone="UTC"`)—. `None` si
/// el valor no tiene al menos una fecha de ocho dígitos.
fn graph_datetime(property: &crate::ical::Property) -> Option<serde_json::Value> {
    use chrono::TimeZone;
    use serde_json::json;

    let value = property.value.as_str();
    let bytes = value.as_bytes();
    if bytes.len() < 8 || !bytes[..8].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let date = format!("{}-{}-{}", &value[0..4], &value[4..6], &value[6..8]);

    // Sólo fecha (día completo, `VALUE=DATE`): medianoche UTC. El `isAllDay` lo marca
    // aparte quien llama.
    let has_time =
        bytes.len() >= 15 && bytes[8] == b'T' && bytes[9..15].iter().all(u8::is_ascii_digit);
    if !has_time {
        return Some(json!({ "dateTime": format!("{date}T00:00:00"), "timeZone": "UTC" }));
    }
    let time = format!("{}:{}:{}", &value[9..11], &value[11..13], &value[13..15]);

    // Con hora y sufijo `Z`: ya es UTC.
    if value.ends_with('Z') {
        return Some(json!({ "dateTime": format!("{date}T{time}"), "timeZone": "UTC" }));
    }

    // Con hora y `TZID=`: se interpreta en esa zona y se convierte a UTC. Una zona
    // desconocida, o una hora que en esa zona no existe o es ambigua (cambio de
    // horario), devuelve `None`: mejor rutear la op a conflicto que mandar —y que la
    // bajada persista— una hora corrida.
    // `Property::param` compara el nombre del parámetro sin distinguir mayúsculas
    // (los nombres de parámetro iCal son case-insensitive: `TZID=` o `tzid=`) y le
    // saca las comillas a un `TZID="America/…"`; se reusa en vez de un `strip_prefix`
    // propio, que se comía los dos casos.
    if let Some(tzid) = property.param("TZID") {
        let zone: chrono_tz::Tz = tzid.parse().ok()?;
        let naive =
            NaiveDateTime::parse_from_str(&format!("{date}T{time}"), "%Y-%m-%dT%H:%M:%S").ok()?;
        let utc = zone
            .from_local_datetime(&naive)
            .single()?
            .with_timezone(&chrono::Utc);
        return Some(json!({
            "dateTime": utc.format("%Y-%m-%dT%H:%M:%S").to_string(),
            "timeZone": "UTC"
        }));
    }

    // Hora flotante (ni `Z` ni `TZID`): no se adivina la zona. `None` → conflicto.
    None
}

/// Trae la versión actual de un evento del servidor
/// (`GET /users/{user}/events/{id}`) como `(su @odata.etag, su crudo iCal)`, para la
/// **copia del servidor** de un conflicto (`#97`, equivalente Graph del `multiget`
/// DAV de `replay`). Devuelve el iCal con la **misma conversión que la bajada**
/// ([`GraphApiBackend::event_to_ical`]) y las fechas en UTC ([`PREFER_UTC`]), así
/// `GetConflict` muestra la copia del servidor en el mismo formato que para un objeto
/// DAV, y `take_server` adopta un crudo válido.
///
/// `Ok(None)` si el evento ya no está (`404`): el recurso se borró en el servidor, no
/// hay copia que guardar. La URL se arma sobre `credential.base_url` con el `id`
/// percent-codificado; **nunca** se sigue una URL de la respuesta.
pub(crate) async fn fetch_server_copy(
    client: &reqwest::Client,
    credential: &GraphCredential,
    id: &str,
) -> Result<Option<(Option<String>, Vec<u8>)>, GraphFetchError> {
    let url = graph::build_url(
        &credential.base_url,
        &["users", &credential.user_id, "events", id],
        EVENTS_SELECT_ITEM,
    )?;
    let Some(event) =
        graph::fetch_one::<GraphEvent>(client, credential, url, &[PREFER_UTC]).await?
    else {
        return Ok(None);
    };
    let raw = GraphApiBackend::event_to_ical(&event);
    Ok(Some((event.odata_etag.clone(), raw.into_bytes())))
}

/// Backend Microsoft Graph API para calendario.
///
/// Sincroniza los eventos del calendario del usuario (`/me/events`) contra el
/// almacén local. Convierte cada evento a `VEVENT` y hace upsert en el
/// calendario «Graph Calendar». De sólo lectura.
pub struct GraphApiBackend;

impl GraphApiBackend {
    /// Sincroniza el calendario usando `/me/events` de Microsoft Graph.
    pub async fn sync<K: KeySource>(
        &self,
        ctx: GraphSyncContext<'_, K>,
        credential: &GraphCredential,
    ) -> CalendarOutcome {
        let manager = ctx.manager;
        let account_id = ctx.account_id;
        let notify = ctx.notify;

        let set_status = |state: AreaState, detail: &str| {
            let manager = manager.clone();
            let account_id = account_id.to_string();
            let detail = detail.to_string();
            let notify = notify.clone();
            async move {
                if manager
                    .set_area_status(CALENDAR_AREA, &account_id, state, &detail)
                    .await
                {
                    (notify)();
                }
            }
        };

        if !manager.prepare_for_sync(CALENDAR_AREA, account_id).await {
            set_status(AreaState::Pending, CLOSED_DETAIL).await;
            return CalendarOutcome::StoreClosed;
        }
        set_status(AreaState::Syncing, "").await;

        let client = match graph::http_client() {
            Ok(c) => c,
            Err(e) => {
                set_status(AreaState::Failed, "no se pudo preparar el cliente HTTP").await;
                return CalendarOutcome::Failed(e.to_string());
            }
        };

        // El empuje primero: se drena la cola de escrituras por Graph antes de la
        // bajada, igual que el camino CardDAV drena la suya antes de bajar. El
        // plazo de la vuelta es el mismo que usa el resto del servicio.
        let deadline = tokio::time::Instant::now() + crate::dav::webdav::Limits::DEFAULT.max_round;
        let push = match crate::graph_write::replay_graph_area(
            manager,
            account_id,
            CALENDAR_AREA,
            &client,
            credential,
            deadline,
        )
        .await
        {
            Ok(report) => report,
            // El llavero cerrado a mitad corta la vuelta como cualquier otra
            // escritura: se pide desbloquearlo.
            Err(StoreError::Key(KeyError::Locked)) | Err(StoreError::Missing) => {
                set_status(AreaState::Pending, CLOSED_DETAIL).await;
                return CalendarOutcome::StoreClosed;
            }
            // Cualquier otro error de almacén (un `Sqlite`/`Io` persistente) no es
            // «desbloqueá el llavero»: se reporta como falla, como el camino CalDAV,
            // para no reintentarlo cada vuelta en vano.
            Err(e) => {
                let shown = e.public_detail();
                set_status(AreaState::Failed, shown).await;
                return CalendarOutcome::Failed(shown.into());
            }
        };

        // Traer los eventos completos (sin delta sync por ahora).
        let events = match Self::fetch_all_events(&client, credential).await {
            Ok(events) => events,
            Err(e) => {
                set_status(AreaState::Failed, &e.to_string()).await;
                return CalendarOutcome::Failed(e.to_string());
            }
        };

        // Crear la libreta por defecto para Graph.
        let listing = CalendarListing {
            href: DEFAULT_CALENDAR_HREF.to_string(),
            display_name: DEFAULT_CALENDAR_NAME.to_string(),
            color: None,
            components: vec!["VEVENT".to_string()],
        };
        let stored = match manager
            .with_store(account_id, move |s| s.upsert_calendars(&[listing]))
            .await
        {
            Ok(mut calendars) => match calendars.pop() {
                Some(calendar) => calendar,
                None => {
                    set_status(AreaState::Failed, "no se creó el calendario Graph").await;
                    return CalendarOutcome::Failed("no se creó el calendario Graph".into());
                }
            },
            Err(e) => {
                set_status(AreaState::Failed, "no se pudo crear el calendario Graph").await;
                return CalendarOutcome::Failed(e.to_string());
            }
        };

        // Convertir a filas, derivando las ocurrencias en la ventana. Es CPU: un
        // evento sin `id` o que no deja ni un `VEVENT` válido se descarta.
        let mut rows = Vec::new();
        for event in events {
            if let Some(row) = Self::event_to_row(&event, ctx.window, &ctx.expansion) {
                rows.push(row);
            }
        }

        let mut report = CalendarReport {
            calendars: 1,
            pushed: push.pushed,
            conflicts: push.conflicts,
            pending: push.remaining,
            ..CalendarReport::default()
        };

        // Escribir de a lotes de [`WRITE_BATCH_ROWS`] objetos por transacción.
        // El tope de cantidad ya lo puso la bajada (MAX_EVENTS); acá no se vuelve
        // a acotar por cuenta, así que [`CalendarRoom::UNLIMITED`].
        let total_batches = rows.len().div_ceil(WRITE_BATCH_ROWS);
        for (index, chunk) in rows.chunks(WRITE_BATCH_ROWS).enumerate() {
            let ops: Vec<ObjectOp> = chunk
                .iter()
                .cloned()
                .map(|row| ObjectOp::Upsert(Box::new(row)))
                .collect();
            let fetched = ops.len();
            let calendar = stored.clone();
            let window = ctx.window;
            // El último lote guarda que el calendario quedó al día. Graph no da
            // ctag ni token de sincronización, así que van en `None`: cada
            // vuelta vuelve a bajar todo (sin delta sync todavía).
            let finish = (index + 1 == total_batches).then_some(CalendarProgress {
                token: None,
                ctag: None,
            });
            let applied = manager
                .with_store(account_id, move |s| {
                    s.apply_calendar_objects(
                        &calendar,
                        &ops,
                        window,
                        finish.as_ref(),
                        CalendarRoom::UNLIMITED,
                    )
                })
                .await;
            match applied {
                Ok(CalendarApplied::Written { .. }) => {
                    report.fetched += fetched;
                    report.batches += 1;
                }
                Ok(CalendarApplied::WindowMoved) => {
                    set_status(
                        AreaState::Pending,
                        "la ventana del calendario se corrió a mitad de la sincronización",
                    )
                    .await;
                    return CalendarOutcome::WindowMoved;
                }
                Ok(CalendarApplied::OverCap) => {
                    set_status(AreaState::Failed, "no se pudo guardar el calendario").await;
                    return CalendarOutcome::Failed("el calendario pasó el tope".into());
                }
                Err(e) => {
                    set_status(AreaState::Failed, "no se pudieron guardar los eventos").await;
                    return CalendarOutcome::Failed(e.to_string());
                }
            }
        }

        set_status(AreaState::Synced, "").await;
        CalendarOutcome::Synced(report)
    }

    /// Trae todos los eventos del calendario con paginación.
    ///
    /// Arma la URL inicial de `/users/{user_id}/events` sobre la base de la
    /// credencial y delega en [`crate::graph::fetch_all_pages`] —donde vive la
    /// defensa del token y las cotas de paginación—, pidiendo las fechas en UTC.
    async fn fetch_all_events(
        client: &reqwest::Client,
        credential: &GraphCredential,
    ) -> Result<Vec<GraphEvent>, GraphFetchError> {
        let url = graph::build_url(
            &credential.base_url,
            &["users", &credential.user_id, "events"],
            EVENTS_SELECT,
        )?;
        graph::fetch_all_pages(client, credential, url, MAX_EVENTS, &[PREFER_UTC]).await
    }

    /// Convierte un `GraphEvent` a [`ObjectRow`], derivando sus ocurrencias en
    /// la ventana.
    ///
    /// Un evento sin `id` se descarta: el `id` es el `href`, y sin él no hay
    /// forma estable de hacer upsert. Un evento que no deja un `VEVENT` con
    /// `UID` tampoco se guarda.
    fn event_to_row(
        event: &GraphEvent,
        window: Window,
        expansion: &ExpansionLimits,
    ) -> Option<ObjectRow> {
        if event.id.is_empty() {
            return None;
        }
        // El `id` es dato de red: se escapa igual que cualquier otro campo antes
        // de usarlo como `href`, por si se vuelca a un formato por líneas.
        let href = escape_text(&event.id);
        let ical = Self::event_to_ical(event);
        let (index, occurrences) = derive_with_occurrences(&ical, window, expansion);
        // Sin `UID` no hay serie: el evento no se entendió, no se guarda.
        if index.uid.is_empty() {
            return None;
        }
        Some(ObjectRow {
            href,
            // El `@odata.etag` capturado: la fila guardada lo lleva para que la
            // escritura por Graph (`#97`) pueda condicionar `PATCH`/`DELETE`.
            etag: event.odata_etag.clone(),
            raw_ical: ical,
            index,
            occurrences,
        })
    }

    /// Convierte un `GraphEvent` a un documento iCalendar con un `VEVENT`.
    ///
    /// **Todo campo de red se escapa** con [`escape_text`] (RFC 5545 §3.3.11):
    /// la barra primero, luego `;` `,` y el salto como `\n`, y el `\r` se
    /// descarta. Así ni el `UID`/`iCalUId` ni ningún otro valor puede fabricar
    /// una propiedad nueva ni partir el `VEVENT` con un `\r\n` incrustado. Las
    /// fechas se reformatean a un patrón numérico fijo: si no parsean, se
    /// omiten. Un campo ausente se omite; nunca hace fallar la conversión.
    fn event_to_ical(event: &GraphEvent) -> String {
        let mut out = String::new();
        out.push_str("BEGIN:VCALENDAR\r\n");
        out.push_str("VERSION:2.0\r\n");
        out.push_str("PRODID:-//VasakOS//vasak-accounts Graph//ES\r\n");
        out.push_str("BEGIN:VEVENT\r\n");

        // UID: el iCalUId del evento, que es su identidad iCalendar estable; si
        // no vino, el id. Es un valor TEXT, así que se escapa.
        let uid = if event.i_cal_uid.is_empty() {
            event.id.as_str()
        } else {
            event.i_cal_uid.as_str()
        };
        out.push_str(&format!("UID:{}\r\n", escape_text(uid)));

        // DTSTAMP: obligatorio. La última modificación si vino, o ahora.
        let dtstamp = event
            .last_modified_date_time
            .as_deref()
            .and_then(format_utc_datetime)
            .unwrap_or_else(now_utc_datetime);
        out.push_str(&format!("DTSTAMP:{dtstamp}\r\n"));
        if let Some(modified) = event
            .last_modified_date_time
            .as_deref()
            .and_then(format_utc_datetime)
        {
            out.push_str(&format!("LAST-MODIFIED:{modified}\r\n"));
        }

        // DTSTART/DTEND. Un evento de día completo va con `VALUE=DATE` (sin
        // hora): Graph lo da con el fin exclusivo, como iCalendar.
        push_datetime(&mut out, "DTSTART", event.start.as_ref(), event.is_all_day);
        push_datetime(&mut out, "DTEND", event.end.as_ref(), event.is_all_day);

        if let Some(subject) = non_empty(&event.subject) {
            out.push_str(&format!("SUMMARY:{}\r\n", escape_text(subject)));
        }
        if let Some(body) = non_empty(&event.body_preview) {
            out.push_str(&format!("DESCRIPTION:{}\r\n", escape_text(body)));
        }
        if let Some(location) = event
            .location
            .as_ref()
            .and_then(|l| non_empty(&l.display_name))
        {
            out.push_str(&format!("LOCATION:{}\r\n", escape_text(location)));
        }

        if let Some(line) = event
            .organizer
            .as_ref()
            .and_then(|o| o.email_address.as_ref())
            .and_then(|e| cal_address_line("ORGANIZER", e, None))
        {
            out.push_str(&line);
        }
        for attendee in &event.attendees {
            if let Some(email) = attendee.email_address.as_ref() {
                let partstat = attendee
                    .status
                    .as_ref()
                    .and_then(|s| s.response.as_deref())
                    .and_then(partstat_of);
                if let Some(line) = cal_address_line("ATTENDEE", email, partstat) {
                    out.push_str(&line);
                }
            }
        }

        if let Some(rrule) = event.recurrence.as_ref().and_then(recurrence_to_rrule) {
            out.push_str(&format!("RRULE:{rrule}\r\n"));
        }

        if !event.categories.is_empty() {
            // CATEGORIES es una lista separada por comas: cada valor se escapa
            // (su coma interna queda `\,`) y se juntan con comas sin escapar.
            let joined = event
                .categories
                .iter()
                .map(|c| escape_text(c))
                .collect::<Vec<_>>()
                .join(",");
            out.push_str(&format!("CATEGORIES:{joined}\r\n"));
        }

        if let Some(priority) = event.importance.as_deref().and_then(priority_of) {
            out.push_str(&format!("PRIORITY:{priority}\r\n"));
        }
        if event.is_cancelled {
            out.push_str("STATUS:CANCELLED\r\n");
        }

        out.push_str("END:VEVENT\r\n");
        out.push_str("END:VCALENDAR\r\n");
        out
    }
}

/// `Some(valor)` si el campo vino y no está vacío.
fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|s| !s.is_empty())
}

/// Saca de un valor todo lo que no puede ir en una línea de contenido: el `\r`
/// y el `\n` (que partirían la línea) y la comilla doble (que rompería un
/// parámetro entrecomillado). Es para los valores que **no** son TEXT —una
/// dirección de correo, un nombre dentro de un parámetro `CN`—, donde no
/// corresponde el escape de TEXT pero sí hay que impedir la inyección por salto
/// de línea.
fn clean_param_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| *c != '\r' && *c != '\n' && *c != '"')
        .collect()
}

/// Arma una línea `ORGANIZER`/`ATTENDEE` con su `CAL-ADDRESS`.
///
/// `CN` va entrecomillado y saneado; la dirección va como `mailto:` saneada.
/// Sin dirección no se emite la línea.
fn cal_address_line(
    property: &str,
    email: &GraphEmailAddress,
    partstat: Option<&str>,
) -> Option<String> {
    let address = non_empty(&email.address)?;
    let address = clean_param_value(address);
    if address.is_empty() {
        return None;
    }
    let mut params = String::new();
    if let Some(name) = non_empty(&email.name) {
        let name = clean_param_value(name);
        if !name.is_empty() {
            params.push_str(&format!(";CN=\"{name}\""));
        }
    }
    if let Some(partstat) = partstat {
        params.push_str(&format!(";PARTSTAT={partstat}"));
    }
    Some(format!("{property}{params}:mailto:{address}\r\n"))
}

/// Mapea la respuesta de un asistente de Graph al `PARTSTAT` de iCalendar.
fn partstat_of(response: &str) -> Option<&'static str> {
    match response.to_ascii_lowercase().as_str() {
        "accepted" | "organizer" => Some("ACCEPTED"),
        "declined" => Some("DECLINED"),
        "tentativelyaccepted" => Some("TENTATIVE"),
        "notresponded" | "none" => Some("NEEDS-ACTION"),
        _ => None,
    }
}

/// Mapea `importance` de Graph a `PRIORITY` de iCalendar (1 alta … 9 baja).
fn priority_of(importance: &str) -> Option<u8> {
    match importance.to_ascii_lowercase().as_str() {
        "high" => Some(1),
        "normal" => Some(5),
        "low" => Some(9),
        _ => None,
    }
}

/// Agrega un `DTSTART`/`DTEND` a partir de una fecha-hora de Graph.
///
/// En un evento de día completo va `;VALUE=DATE` con la fecha sola; si no, el
/// instante en UTC (`...Z`). Si la fecha no parsea, no se emite nada.
fn push_datetime(out: &mut String, property: &str, value: Option<&GraphDateTime>, all_day: bool) {
    let Some(raw) = value.and_then(|v| v.date_time.as_deref()) else {
        return;
    };
    if all_day {
        if let Some(date) = format_utc_date(raw) {
            out.push_str(&format!("{property};VALUE=DATE:{date}\r\n"));
        }
    } else if let Some(moment) = format_utc_datetime(raw) {
        out.push_str(&format!("{property}:{moment}\r\n"));
    }
}

/// El patrón con el que Graph entrega una fecha-hora: ISO sin zona, con hasta
/// siete decimales de segundo.
const GRAPH_DATETIME_FORMATS: [&str; 2] = ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"];

/// Parsea una fecha-hora de Graph (ya en UTC) y la formatea como
/// `YYYYMMDDTHHMMSSZ`. `None` si no parsea.
fn format_utc_datetime(raw: &str) -> Option<String> {
    parse_graph_datetime(raw).map(|dt| dt.format("%Y%m%dT%H%M%SZ").to_string())
}

/// Lo mismo, como fecha sola `YYYYMMDD`, para los eventos de día completo.
fn format_utc_date(raw: &str) -> Option<String> {
    parse_graph_datetime(raw).map(|dt| dt.format("%Y%m%d").to_string())
}

fn parse_graph_datetime(raw: &str) -> Option<NaiveDateTime> {
    GRAPH_DATETIME_FORMATS
        .iter()
        .find_map(|fmt| NaiveDateTime::parse_from_str(raw, fmt).ok())
}

/// `DTSTAMP` cuando no vino la última modificación.
fn now_utc_datetime() -> String {
    chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

/// Traduce la recurrencia de Graph a una `RRULE`.
///
/// Cubre los patrones documentados de Graph (diario, semanal, mensual y anual,
/// absolutos y relativos) y el rango (`endDate` → `UNTIL`, `numbered` →
/// `COUNT`). Un patrón que no se entiende devuelve `None`: el evento se guarda
/// como una sola ocurrencia, nunca roto (decisión 2 de `vasak-accounts#24`).
fn recurrence_to_rrule(recurrence: &GraphRecurrence) -> Option<String> {
    let pattern = recurrence.pattern.as_ref()?;
    let interval = pattern.interval.unwrap_or(1).max(1);
    let days = pattern
        .days_of_week
        .iter()
        .filter_map(|d| weekday_of(d))
        .collect::<Vec<_>>();

    let mut parts: Vec<String> = Vec::new();
    match pattern.r#type.as_deref()?.to_ascii_lowercase().as_str() {
        "daily" => parts.push("FREQ=DAILY".into()),
        "weekly" => {
            parts.push("FREQ=WEEKLY".into());
            if !days.is_empty() {
                parts.push(format!("BYDAY={}", days.join(",")));
            }
        }
        "absolutemonthly" => {
            parts.push("FREQ=MONTHLY".into());
            if let Some(day) = pattern.day_of_month {
                parts.push(format!("BYMONTHDAY={day}"));
            }
        }
        "relativemonthly" => {
            parts.push("FREQ=MONTHLY".into());
            push_relative(&mut parts, &days, pattern.index.as_deref())?;
        }
        "absoluteyearly" => {
            parts.push("FREQ=YEARLY".into());
            if let Some(month) = pattern.month {
                parts.push(format!("BYMONTH={month}"));
            }
            if let Some(day) = pattern.day_of_month {
                parts.push(format!("BYMONTHDAY={day}"));
            }
        }
        "relativeyearly" => {
            parts.push("FREQ=YEARLY".into());
            if let Some(month) = pattern.month {
                parts.push(format!("BYMONTH={month}"));
            }
            push_relative(&mut parts, &days, pattern.index.as_deref())?;
        }
        _ => return None,
    }

    if interval > 1 {
        parts.push(format!("INTERVAL={interval}"));
    }

    if let Some(range) = recurrence.range.as_ref() {
        match range.r#type.as_deref().map(|s| s.to_ascii_lowercase()) {
            Some(ref t) if t == "enddate" => {
                if let Some(until) = range.end_date.as_deref().and_then(end_date_until) {
                    parts.push(format!("UNTIL={until}"));
                }
            }
            Some(ref t) if t == "numbered" => {
                if let Some(count) = range.number_of_occurrences.filter(|n| *n > 0) {
                    parts.push(format!("COUNT={count}"));
                }
            }
            _ => {}
        }
    }

    Some(parts.join(";"))
}

/// Agrega `BYDAY` (con los días) y `BYSETPOS` (el `index`) a un patrón
/// relativo. Devuelve `None` si no hay ni un día entendido: un relativo sin día
/// no se puede expresar.
fn push_relative(parts: &mut Vec<String>, days: &[&str], index: Option<&str>) -> Option<()> {
    if days.is_empty() {
        return None;
    }
    parts.push(format!("BYDAY={}", days.join(",")));
    if let Some(pos) = index.and_then(setpos_of) {
        parts.push(format!("BYSETPOS={pos}"));
    }
    Some(())
}

/// El día de la semana de Graph (`monday`, …) en el código de iCalendar
/// (`MO`, …).
fn weekday_of(day: &str) -> Option<&'static str> {
    match day.to_ascii_lowercase().as_str() {
        "sunday" => Some("SU"),
        "monday" => Some("MO"),
        "tuesday" => Some("TU"),
        "wednesday" => Some("WE"),
        "thursday" => Some("TH"),
        "friday" => Some("FR"),
        "saturday" => Some("SA"),
        _ => None,
    }
}

/// El `index` de un patrón relativo de Graph como `BYSETPOS`.
fn setpos_of(index: &str) -> Option<i8> {
    match index.to_ascii_lowercase().as_str() {
        "first" => Some(1),
        "second" => Some(2),
        "third" => Some(3),
        "fourth" => Some(4),
        "last" => Some(-1),
        _ => None,
    }
}

/// El `UNTIL` a partir del `endDate` de Graph (`YYYY-MM-DD`): el final del día
/// en UTC, para que el último día también cuente. `None` si no parsea.
fn end_date_until(end_date: &str) -> Option<String> {
    let date = chrono::NaiveDate::parse_from_str(end_date, "%Y-%m-%d").ok()?;
    Some(date.format("%Y%m%dT235959Z").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pruebas mínimas de la conversión de un evento de Graph a `VEVENT`. Las
    // definitivas —endpoint falso, paginación y hallazgos de seguridad— las
    // escribe qa, reusando la maquinaria de `contacts_sync::graph`.

    fn event_from(json: &str) -> GraphEvent {
        serde_json::from_str(json).expect("JSON de evento válido")
    }

    #[test]
    fn un_evento_completo_se_convierte_a_vevent() {
        let event = event_from(
            r#"{
                "id": "AAA-1",
                "iCalUId": "040000008200",
                "subject": "Reunión de equipo",
                "bodyPreview": "Repaso semanal",
                "start": { "dateTime": "2026-01-05T14:00:00.0000000", "timeZone": "UTC" },
                "end": { "dateTime": "2026-01-05T15:00:00.0000000", "timeZone": "UTC" },
                "isAllDay": false,
                "location": { "displayName": "Sala 3" },
                "organizer": { "emailAddress": { "name": "Ada", "address": "ada@example.com" } },
                "attendees": [
                    { "emailAddress": { "name": "Bob", "address": "bob@example.com" },
                      "status": { "response": "accepted" } }
                ],
                "categories": ["Trabajo", "Importante"],
                "importance": "high",
                "lastModifiedDateTime": "2026-01-01T10:00:00.0000000"
            }"#,
        );
        let ical = GraphApiBackend::event_to_ical(&event);

        assert!(ical.contains("UID:040000008200\r\n"));
        assert!(ical.contains("SUMMARY:Reunión de equipo\r\n"));
        assert!(ical.contains("DESCRIPTION:Repaso semanal\r\n"));
        assert!(ical.contains("DTSTART:20260105T140000Z\r\n"));
        assert!(ical.contains("DTEND:20260105T150000Z\r\n"));
        assert!(ical.contains("LOCATION:Sala 3\r\n"));
        assert!(ical.contains("ORGANIZER;CN=\"Ada\":mailto:ada@example.com\r\n"));
        assert!(ical.contains("ATTENDEE;CN=\"Bob\";PARTSTAT=ACCEPTED:mailto:bob@example.com\r\n"));
        assert!(ical.contains("CATEGORIES:Trabajo,Importante\r\n"));
        assert!(ical.contains("PRIORITY:1\r\n"));
        assert!(ical.contains("LAST-MODIFIED:20260101T100000Z\r\n"));
        assert!(ical.contains("BEGIN:VEVENT\r\n"));
        assert!(ical.contains("END:VEVENT\r\n"));
    }

    #[test]
    fn un_evento_de_dia_completo_va_con_value_date() {
        let event = event_from(
            r#"{
                "id": "AAA-2",
                "iCalUId": "diacompleto",
                "subject": "Feriado",
                "start": { "dateTime": "2026-02-10T00:00:00.0000000", "timeZone": "UTC" },
                "end": { "dateTime": "2026-02-11T00:00:00.0000000", "timeZone": "UTC" },
                "isAllDay": true
            }"#,
        );
        let ical = GraphApiBackend::event_to_ical(&event);
        assert!(ical.contains("DTSTART;VALUE=DATE:20260210\r\n"));
        assert!(ical.contains("DTEND;VALUE=DATE:20260211\r\n"));
    }

    #[test]
    fn un_evento_sin_campos_no_rompe_y_omite_lo_ausente() {
        let event = event_from(r#"{ "id": "solo-id", "iCalUId": "u" }"#);
        let ical = GraphApiBackend::event_to_ical(&event);
        assert!(ical.contains("UID:u\r\n"));
        assert!(ical.contains("DTSTAMP:"));
        // Nada de lo que no vino se emite.
        assert!(!ical.contains("\r\nSUMMARY:"));
        assert!(!ical.contains("\r\nDTSTART"));
        assert!(!ical.contains("\r\nATTENDEE"));
        assert!(!ical.contains("\r\nRRULE:"));
    }

    #[test]
    fn un_uid_con_salto_de_linea_no_inyecta_propiedades() {
        // El id/iCalUId trae CR y LF de verdad (el JSON los produce de los
        // escapes). No debe fabricar una línea nueva ni un segundo UID.
        let event =
            event_from(r#"{ "id": "x", "iCalUId": "AAA\r\nSUMMARY:INYECTADO\r\nUID:BBB" }"#);
        let ical = GraphApiBackend::event_to_ical(&event);
        let lineas: Vec<&str> = ical.split("\r\n").collect();
        assert_eq!(
            lineas.iter().filter(|l| l.starts_with("UID:")).count(),
            1,
            "el UID partido no debe fabricar un segundo UID: {ical:?}"
        );
        assert!(
            !ical.contains("\r\nSUMMARY:INYECTADO"),
            "el SUMMARY inyectado no debe quedar como línea propia: {ical:?}"
        );
        // El salto queda escapado como `\n` dentro del valor del UID.
        assert!(ical.contains("UID:AAA\\nSUMMARY"));
    }

    #[test]
    fn una_direccion_con_salto_de_linea_no_parte_la_linea() {
        let event = event_from(
            r#"{ "id": "x", "iCalUId": "u",
                 "organizer": { "emailAddress": {
                    "name": "Ma\r\nSUMMARY:X", "address": "a@b.com\r\nDESCRIPTION:Y" } } }"#,
        );
        let ical = GraphApiBackend::event_to_ical(&event);
        assert!(
            !ical.contains("\r\nSUMMARY:X"),
            "el nombre con salto no fabrica una propiedad: {ical:?}"
        );
        assert!(
            !ical.contains("\r\nDESCRIPTION:Y"),
            "la dirección con salto no fabrica una propiedad: {ical:?}"
        );
    }

    #[test]
    fn una_recurrencia_semanal_se_traduce_a_rrule() {
        let recurrence: GraphRecurrence = serde_json::from_str(
            r#"{
                "pattern": { "type": "weekly", "interval": 2,
                             "daysOfWeek": ["monday", "wednesday"] },
                "range": { "type": "numbered", "numberOfOccurrences": 10 }
            }"#,
        )
        .expect("recurrencia válida");
        let rrule = recurrence_to_rrule(&recurrence).expect("hay RRULE");
        assert!(rrule.contains("FREQ=WEEKLY"));
        assert!(rrule.contains("BYDAY=MO,WE"));
        assert!(rrule.contains("INTERVAL=2"));
        assert!(rrule.contains("COUNT=10"));
    }

    #[test]
    fn una_recurrencia_mensual_relativa_usa_bysetpos() {
        let recurrence: GraphRecurrence = serde_json::from_str(
            r#"{
                "pattern": { "type": "relativeMonthly", "interval": 1,
                             "daysOfWeek": ["friday"], "index": "last" },
                "range": { "type": "endDate", "endDate": "2026-12-31" }
            }"#,
        )
        .expect("recurrencia válida");
        let rrule = recurrence_to_rrule(&recurrence).expect("hay RRULE");
        assert!(rrule.contains("FREQ=MONTHLY"));
        assert!(rrule.contains("BYDAY=FR"));
        assert!(rrule.contains("BYSETPOS=-1"));
        assert!(rrule.contains("UNTIL=20261231T235959Z"));
    }

    #[test]
    fn una_recurrencia_desconocida_no_da_rrule() {
        let recurrence: GraphRecurrence =
            serde_json::from_str(r#"{ "pattern": { "type": "loco" } }"#).expect("válida");
        assert!(recurrence_to_rrule(&recurrence).is_none());
    }

    #[test]
    fn un_evento_sin_id_se_descarta() {
        let event = event_from(r#"{ "iCalUId": "u", "subject": "sin id" }"#);
        assert!(GraphApiBackend::event_to_row(
            &event,
            Window::around(chrono::Utc::now()),
            &ExpansionLimits::DEFAULT
        )
        .is_none());
    }

    // ── Pruebas definitivas: endpoint falso, paginación y hallazgos de
    // seguridad. Escritas por qa, reusando la maquinaria de `crate::graph::fake`
    // —la misma que usan las pruebas de contactos—. ──────────────────────────

    use std::sync::Arc;
    use std::time::Instant;

    use chrono::TimeZone;

    use crate::graph::fake::{client, credential_for, FakeGraph, TOKEN};
    use crate::store::key::fake::FakeKeys;
    use crate::store::lifecycle::{AccountListing, Consent, ListedAccount, Locations};
    use crate::store::paths::tests::TempDir;

    const ACCOUNT: &str = "cuenta";
    /// Mediodía UTC del 26 de septiembre de 2026, como en las pruebas de CalDAV:
    /// la ventana de expansión se arma alrededor de este instante, y los eventos
    /// de las pruebas caen dentro de ella.
    const TODAY: i64 = 1_790_424_000;

    fn test_window() -> Window {
        Window::around(chrono::Utc.timestamp_opt(TODAY, 0).unwrap())
    }

    /// Un evento completo, con todos los campos que se convierten a `VEVENT`,
    /// para comprobar la conversión de punta a punta pasando por el endpoint
    /// falso y el almacén.
    fn evento_completo_json() -> &'static str {
        r#"{
            "id": "AAA-1",
            "iCalUId": "uid-full",
            "subject": "Reunión de equipo",
            "bodyPreview": "Repaso semanal",
            "start": { "dateTime": "2026-09-28T14:00:00.0000000", "timeZone": "UTC" },
            "end": { "dateTime": "2026-09-28T15:00:00.0000000", "timeZone": "UTC" },
            "isAllDay": false,
            "location": { "displayName": "Sala 3" },
            "organizer": { "emailAddress": { "name": "Ada", "address": "ada@example.com" } },
            "attendees": [
                { "emailAddress": { "name": "Bob", "address": "bob@example.com" },
                  "status": { "response": "accepted" } }
            ],
            "categories": ["Trabajo", "Importante"],
            "importance": "high",
            "lastModifiedDateTime": "2026-09-01T10:00:00.0000000"
        }"#
    }

    /// El almacén local y el gestor, con la cuenta lista y el área de calendario
    /// activada, para correr `GraphApiBackend::sync` de punta a punta.
    struct Fixture {
        _temp: TempDir,
        manager: Arc<StoreManager<FakeKeys>>,
        server: FakeGraph,
    }

    impl Fixture {
        async fn new(label: &str) -> Self {
            let temp = TempDir::new(label);
            let keys = FakeKeys::default();
            let manager = Arc::new(StoreManager::new(
                keys,
                Ok(Locations {
                    stores: temp.0.join("data/stores"),
                    settings: temp.0.join("config/stores.json"),
                }),
            ));
            manager
                .accounts_listed(
                    AccountListing::Listed(vec![ListedAccount {
                        id: ACCOUNT.into(),
                        display_name: "Trabajo".into(),
                        capabilities: vec!["calendar".into()],
                        needs_reauth: false,
                    }]),
                    Instant::now(),
                )
                .await;
            assert!(manager
                .activate_area(CALENDAR_AREA, ACCOUNT, Consent::Granted)
                .await
                .unwrap());
            let server = FakeGraph::start().await;
            Self {
                _temp: temp,
                manager,
                server,
            }
        }

        async fn sync(&self) -> CalendarOutcome {
            let ctx = GraphSyncContext {
                manager: &self.manager,
                account_id: ACCOUNT,
                notify: Arc::new(|| {}),
                window: test_window(),
                expansion: ExpansionLimits::DEFAULT,
            };
            GraphApiBackend
                .sync(ctx, &credential_for(&self.server))
                .await
        }

        async fn synced(&self) -> CalendarReport {
            match self.sync().await {
                CalendarOutcome::Synced(report) => report,
                other => panic!("la vuelta no terminó bien: {other:?}"),
            }
        }

        async fn calendar_names(&self) -> Vec<String> {
            self.manager
                .with_store(ACCOUNT, |store| {
                    let c = store.connection();
                    Ok(
                        c.prepare("SELECT display_name FROM calendars ORDER BY display_name")
                            .unwrap()
                            .query_map([], |row| row.get::<_, String>(0))
                            .unwrap()
                            .collect::<Result<Vec<_>, _>>()
                            .unwrap(),
                    )
                })
                .await
                .expect("la base tenía que estar abierta")
        }

        /// El iCalendar crudo guardado para un UID.
        async fn raw_for(&self, uid: &'static str) -> String {
            self.manager
                .with_store(ACCOUNT, move |store| {
                    Ok(store
                        .connection()
                        .query_row(
                            "SELECT raw_ical FROM calendar_objects WHERE uid = ?1",
                            [uid],
                            |r| r.get::<_, String>(0),
                        )
                        .unwrap())
                })
                .await
                .expect("la base tenía que estar abierta")
        }

        async fn count(&self, sql: &'static str) -> i64 {
            self.manager
                .with_store(ACCOUNT, move |store| {
                    Ok(store.connection().query_row(sql, [], |r| r.get(0)).unwrap())
                })
                .await
                .expect("la base tenía que estar abierta")
        }
    }

    /// (1) Paginación: dos páginas con `nextLink` al **mismo host** se siguen,
    /// todos los eventos se upsertan en «Graph Calendar», cada pedido lleva el
    /// token y pide las fechas en UTC, y los `VEVENT` salen con los campos
    /// correctos —incluido un evento de día completo y uno recurrente—.
    #[tokio::test]
    async fn la_paginacion_del_mismo_host_trae_y_convierte_todos_los_eventos() {
        let f = Fixture::new("graph-cal-paginacion").await;
        let origin = f.server.origin();
        // Página 1: el completo y un evento de día completo, con nextLink al
        // mismo host.
        f.server.push(format!(
            "{{\"value\":[{completo},{{\
               \"id\":\"AAA-2\",\"iCalUId\":\"uid-allday\",\"subject\":\"Feriado\",\
               \"isAllDay\":true,\
               \"start\":{{\"dateTime\":\"2026-10-01T00:00:00.0000000\",\"timeZone\":\"UTC\"}},\
               \"end\":{{\"dateTime\":\"2026-10-02T00:00:00.0000000\",\"timeZone\":\"UTC\"}}}}],\
             \"@odata.nextLink\":\"{origin}/v1.0/me/events?$skip=100\"}}",
            completo = evento_completo_json()
        ));
        // Página 2: un evento recurrente semanal, sin nextLink.
        f.server.push(
            r#"{"value":[{
                "id": "AAA-3", "iCalUId": "uid-weekly", "subject": "Semanal",
                "start": { "dateTime": "2026-09-28T09:00:00.0000000", "timeZone": "UTC" },
                "end": { "dateTime": "2026-09-28T09:30:00.0000000", "timeZone": "UTC" },
                "recurrence": {
                    "pattern": { "type": "weekly", "interval": 1, "daysOfWeek": ["monday"] },
                    "range": { "type": "numbered", "numberOfOccurrences": 5 }
                }
            }]}"#,
        );

        let report = f.synced().await;
        assert_eq!(report.fetched, 3, "tres eventos entre las dos páginas");
        assert_eq!(
            f.count("SELECT count(*) FROM calendar_objects").await,
            3,
            "los tres se guardaron"
        );
        assert_eq!(f.calendar_names().await, vec!["Graph Calendar".to_string()]);

        // Se pidieron las dos páginas; cada pedido llevó el token (la base_url es
        // el único origen al que se adjunta) y pidió las fechas en UTC.
        let requests = f.server.requests();
        assert_eq!(requests.len(), 2, "se siguió el nextLink del mismo host");
        for r in &requests {
            assert_eq!(r.authorization, format!("Bearer {TOKEN}"));
            assert_eq!(
                r.prefer, "outlook.timezone=\"UTC\"",
                "cada pedido pide las fechas en UTC"
            );
        }
        assert!(
            requests[0].path.starts_with("/v1.0/users/me/events"),
            "la URL inicial sale de la base_url: {}",
            requests[0].path
        );

        // El completo: UID desde iCalUId, fechas con TZ (UTC), SUMMARY, LOCATION,
        // ORGANIZER, ATTENDEE con PARTSTAT, CATEGORIES y PRIORITY.
        let completo = f.raw_for("uid-full").await;
        assert!(completo.contains("UID:uid-full\r\n"), "{completo:?}");
        assert!(completo.contains("SUMMARY:Reunión de equipo\r\n"));
        assert!(completo.contains("DESCRIPTION:Repaso semanal\r\n"));
        assert!(completo.contains("DTSTART:20260928T140000Z\r\n"));
        assert!(completo.contains("DTEND:20260928T150000Z\r\n"));
        assert!(completo.contains("LOCATION:Sala 3\r\n"));
        assert!(completo.contains("ORGANIZER;CN=\"Ada\":mailto:ada@example.com\r\n"));
        assert!(
            completo.contains("ATTENDEE;CN=\"Bob\";PARTSTAT=ACCEPTED:mailto:bob@example.com\r\n")
        );
        assert!(completo.contains("CATEGORIES:Trabajo,Importante\r\n"));
        assert!(completo.contains("PRIORITY:1\r\n"));

        // El de día completo va con `VALUE=DATE`.
        let allday = f.raw_for("uid-allday").await;
        assert!(
            allday.contains("DTSTART;VALUE=DATE:20261001\r\n"),
            "{allday:?}"
        );
        assert!(
            allday.contains("DTEND;VALUE=DATE:20261002\r\n"),
            "{allday:?}"
        );

        // El recurrente lleva su RRULE.
        let weekly = f.raw_for("uid-weekly").await;
        assert!(weekly.contains("RRULE:FREQ=WEEKLY"), "{weekly:?}");
        assert!(weekly.contains("BYDAY=MO"), "{weekly:?}");
        assert!(weekly.contains("COUNT=5"), "{weekly:?}");
    }

    /// (2 · módulo compartido) Un `nextLink` a **otro host** aborta la
    /// sincronización con `UntrustedNextLink` y **no** le manda el token a ese
    /// host: no hay una segunda petición al atacante. El mismo host sí se sigue.
    ///
    /// Es la defensa que vive en `crate::graph::fetch_all_pages`, compartida con
    /// contactos; esta prueba la ejercita por el camino del calendario.
    /// Rojo-sin-arreglo: si se quita la validación `same_origin`, el
    /// sincronizador sigue el enlace, el atacante recibe el token y esta prueba
    /// falla.
    #[tokio::test]
    async fn un_next_link_a_otro_host_aborta_sin_mandar_el_token() {
        let victima = FakeGraph::start().await;
        let atacante = FakeGraph::start().await;
        victima.push(format!(
            "{{\"value\":[{{\"id\":\"AAA\",\"iCalUId\":\"u\"}}],\
             \"@odata.nextLink\":\"{}/v1.0/me/events?$skip=100\"}}",
            atacante.origin()
        ));

        let result = GraphApiBackend::fetch_all_events(&client(), &credential_for(&victima)).await;
        assert!(
            matches!(result, Err(GraphFetchError::UntrustedNextLink)),
            "un nextLink a otro host tiene que abortar con UntrustedNextLink, dio {result:?}"
        );

        let de_la_victima = victima.requests();
        assert_eq!(de_la_victima.len(), 1);
        assert_eq!(de_la_victima[0].authorization, format!("Bearer {TOKEN}"));
        assert!(
            atacante.requests().is_empty(),
            "el token no debe viajar al host del nextLink no confiable"
        );
    }

    /// (2 · módulo compartido) El contrapunto: un `nextLink` al **mismo host** sí
    /// se sigue, y los eventos de las dos páginas vuelven.
    #[tokio::test]
    async fn un_next_link_del_mismo_host_se_sigue() {
        let server = FakeGraph::start().await;
        let origin = server.origin();
        server.push(format!(
            "{{\"value\":[{{\"id\":\"A\",\"iCalUId\":\"a\"}}],\
             \"@odata.nextLink\":\"{origin}/v1.0/me/events?$skip=100\"}}"
        ));
        server.push(r#"{"value":[{"id":"B","iCalUId":"b"}]}"#);

        let result = GraphApiBackend::fetch_all_events(&client(), &credential_for(&server)).await;
        let events = result.expect("el nextLink del mismo host se sigue");
        assert_eq!(events.len(), 2);
        assert_eq!(server.requests().len(), 2);
    }

    /// (3 · inyección por UID/iCalUId) Un `iCalUId` con `\r\n` —y una `VALARM` o
    /// un `ATTENDEE` enteros incrustados— **no** fabrica propiedades nuevas ni
    /// parte/cierra el `VEVENT`: el salto queda escapado como `\n` dentro del
    /// valor del UID. El UID es el campo que se olvidó en contactos; acá se
    /// cubre explícito.
    ///
    /// Rojo-sin-arreglo: si el `UID:` vuelve a emitir el valor crudo
    /// (`format!("UID:{uid}\r\n")` sin `escape_text`), el `\r\n` abre líneas
    /// reales y un segundo `UID`, y esta prueba falla.
    #[test]
    fn un_ical_uid_con_salto_no_fabrica_propiedades_ni_parte_el_vevent() {
        for payload in [
            r#"X\r\nBEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT5M\r\nEND:VALARM\r\nUID:Y"#,
            r#"X\r\nATTENDEE:mailto:evil@example.com"#,
        ] {
            let event = event_from(&format!(r#"{{ "id": "x", "iCalUId": "{payload}" }}"#));
            let ical = GraphApiBackend::event_to_ical(&event);
            let lineas: Vec<&str> = ical.split("\r\n").collect();

            assert_eq!(
                lineas.iter().filter(|l| l.starts_with("UID:")).count(),
                1,
                "el UID partido no debe fabricar un segundo UID (payload={payload}): {ical:?}"
            );
            assert_eq!(
                lineas
                    .iter()
                    .filter(|l| l.trim_start() == "BEGIN:VALARM")
                    .count(),
                0,
                "no debe fabricarse una VALARM (payload={payload}): {ical:?}"
            );
            assert!(
                !ical.contains("\r\nACTION:DISPLAY"),
                "la VALARM inyectada no debe quedar como línea (payload={payload}): {ical:?}"
            );
            assert!(
                !ical.contains("\r\nATTENDEE:mailto:evil"),
                "el ATTENDEE inyectado no debe quedar como línea (payload={payload}): {ical:?}"
            );
        }

        // El salto queda escapado como `\n` dentro del valor del UID.
        let event =
            event_from(r#"{ "id": "x", "iCalUId": "X\r\nBEGIN:VALARM\r\nEND:VALARM\r\nUID:Y" }"#);
        let ical = GraphApiBackend::event_to_ical(&event);
        assert!(ical.contains("UID:X\\nBEGIN:VALARM"), "{ical:?}");
    }

    /// (4 · inyección por otros campos de texto) `location` y `categories` con
    /// `;`, `,`, `\` y `\r\n` quedan escapados: ni fabrican una propiedad nueva
    /// ni parten el `VEVENT`. `location` es un valor TEXT y `categories` una
    /// lista de valores TEXT (cada uno escapado, juntados con comas sin escapar).
    ///
    /// Rojo-sin-arreglo: si alguno de los dos se emite sin `escape_text`, el
    /// `\r\n` abre una línea real (un `SUMMARY`, un segundo `UID`) y esta prueba
    /// falla.
    #[test]
    fn location_y_categories_con_metacaracteres_quedan_escapados() {
        let event = event_from(
            r#"{ "id": "x", "iCalUId": "u",
                 "location": { "displayName": "Sala;3,b\\c\r\nSUMMARY:X" },
                 "categories": ["a,b", "c;d", "e\\f", "g\r\nUID:Z"] }"#,
        );
        let ical = GraphApiBackend::event_to_ical(&event);

        // Ningún salto real: no se fabrica un SUMMARY ni un segundo UID.
        assert!(!ical.contains("\r\nSUMMARY:X"), "{ical:?}");
        let lineas: Vec<&str> = ical.split("\r\n").collect();
        assert_eq!(
            lineas.iter().filter(|l| l.starts_with("UID:")).count(),
            1,
            "categories no debe fabricar un segundo UID: {ical:?}"
        );

        // `location` escapada: `;` `,` `\` escapados y el salto como `\n`.
        assert!(
            ical.contains(r"LOCATION:Sala\;3\,b\\c\nSUMMARY:X"),
            "{ical:?}"
        );
        // `categories`: cada valor escapa su `;` `,` `\` y su salto; se juntan
        // con comas sin escapar (que sí separan).
        assert!(
            ical.contains(r"CATEGORIES:a\,b,c\;d,e\\f,g\nUID:Z"),
            "{ical:?}"
        );
    }

    /// (5 · cotas de paginación) Un `nextLink` que se repite corta con
    /// `PaginationLoop` sin colgarse.
    #[tokio::test]
    async fn un_next_link_repetido_corta_el_bucle() {
        let server = FakeGraph::start().await;
        let origin = server.origin();
        let bucle = format!("{origin}/v1.0/me/events?$skip=100");
        server.push(format!("{{\"value\":[],\"@odata.nextLink\":\"{bucle}\"}}"));
        server.push(format!("{{\"value\":[],\"@odata.nextLink\":\"{bucle}\"}}"));

        let result = GraphApiBackend::fetch_all_events(&client(), &credential_for(&server)).await;
        assert!(
            matches!(result, Err(GraphFetchError::PaginationLoop)),
            "un nextLink repetido corta con PaginationLoop, dio {result:?}"
        );
    }

    /// (5 · cotas de paginación) Superar el tope de páginas da `TooManyPages` sin
    /// agotar memoria: el servidor genera páginas únicas sin fin.
    #[tokio::test]
    async fn superar_el_tope_de_paginas_aborta() {
        let server = FakeGraph::start().await;
        server.auto_paginate();

        let result = GraphApiBackend::fetch_all_events(&client(), &credential_for(&server)).await;
        assert!(
            matches!(result, Err(GraphFetchError::TooManyPages)),
            "pasado el tope de páginas se aborta con TooManyPages, dio {result:?}"
        );
        assert_eq!(
            server.requests().len(),
            graph::MAX_PAGES,
            "se pidieron exactamente MAX_PAGES páginas antes de cortar"
        );
    }

    /// (6 · bordes) Un HTTP de error devuelve un error tipado **sin** el cuerpo
    /// crudo de Graph.
    #[tokio::test]
    async fn un_http_de_error_no_vuelca_el_cuerpo_crudo() {
        let server = FakeGraph::start().await;
        server.push_status(500, "cuerpo-secreto-crudo-de-graph");

        let result = GraphApiBackend::fetch_all_events(&client(), &credential_for(&server)).await;
        let err = result.expect_err("un 500 tiene que ser Err");
        assert!(
            matches!(err, GraphFetchError::Http(s) if s == reqwest::StatusCode::INTERNAL_SERVER_ERROR)
        );
        assert!(
            !err.to_string().contains("cuerpo-secreto-crudo-de-graph"),
            "el cuerpo crudo del error no se muestra: {err}"
        );
    }

    /// (6 · bordes) Un JSON inválido da `Parse`, no un pánico.
    #[tokio::test]
    async fn un_json_invalido_da_error_de_parseo() {
        let server = FakeGraph::start().await;
        server.push("esto no es json {{{");

        let result = GraphApiBackend::fetch_all_events(&client(), &credential_for(&server)).await;
        assert!(
            matches!(result, Err(GraphFetchError::Parse)),
            "dio {result:?}"
        );
    }

    /// (6 · bordes, de punta a punta) Un evento sin `id` se descarta; uno sin
    /// `iCalUId` usa el `id` como UID y se guarda. Sin pánico.
    #[tokio::test]
    async fn un_evento_sin_id_se_descarta_y_uno_sin_ical_uid_usa_el_id() {
        let f = Fixture::new("graph-cal-bordes").await;
        f.server.push(
            r#"{"value":[{"id":"","subject":"Fantasma"},{"id":"keep","subject":"Sin iCalUId"}]}"#,
        );

        let report = f.synced().await;
        assert_eq!(report.fetched, 1, "el evento sin id no se guarda");
        assert_eq!(f.count("SELECT count(*) FROM calendar_objects").await, 1);

        let raw = f.raw_for("keep").await;
        assert!(raw.contains("UID:keep\r\n"), "{raw:?}");
        assert!(raw.contains("SUMMARY:Sin iCalUId\r\n"), "{raw:?}");
    }

    // ── `graph_datetime`: zonas, flotantes y horas que no existen (`#97`) ─────

    fn dtstart(params: &[&str], value: &str) -> crate::ical::Property {
        crate::ical::Property {
            name: "DTSTART".into(),
            params: params.iter().map(|p| p.to_string()).collect(),
            value: value.into(),
        }
    }

    fn utc(value: Option<serde_json::Value>) -> Option<String> {
        value.map(|v| {
            assert_eq!(v["timeZone"], "UTC", "siempre sale en UTC");
            v["dateTime"].as_str().unwrap().to_string()
        })
    }

    /// Con `TZID` la hora se interpreta en esa zona y **se convierte a UTC**:
    /// Buenos Aires es UTC-3, así que las 14:00 locales son las 17:00 UTC. Sin la
    /// conversión (la versión vieja ponía la hora tal cual en UTC) el evento caería
    /// tres horas antes.
    #[test]
    fn una_hora_con_tzid_se_convierte_a_utc() {
        let p = dtstart(&["TZID=America/Argentina/Buenos_Aires"], "20260915T140000");
        assert_eq!(
            utc(graph_datetime(&p)).as_deref(),
            Some("2026-09-15T17:00:00")
        );
    }

    /// Una hora con sufijo `Z` ya es UTC: sale sin cambio.
    #[test]
    fn una_hora_con_z_ya_es_utc() {
        let p = dtstart(&[], "20260915T140000Z");
        assert_eq!(
            utc(graph_datetime(&p)).as_deref(),
            Some("2026-09-15T14:00:00")
        );
    }

    /// Un día completo (sólo fecha) sale a medianoche UTC.
    #[test]
    fn una_fecha_sin_hora_sale_a_medianoche() {
        let p = dtstart(&["VALUE=DATE"], "20260915");
        assert_eq!(
            utc(graph_datetime(&p)).as_deref(),
            Some("2026-09-15T00:00:00")
        );
    }

    /// Una zona que no se conoce no se adivina: `None`.
    #[test]
    fn un_tzid_desconocido_da_none() {
        let p = dtstart(&["TZID=Mars/Olympus_Mons"], "20260915T140000");
        assert!(graph_datetime(&p).is_none());
    }

    /// Una hora flotante (ni `Z` ni `TZID`) no se adivina: `None`.
    #[test]
    fn una_hora_flotante_da_none() {
        let p = dtstart(&[], "20260915T140000");
        assert!(graph_datetime(&p).is_none());
    }

    /// Una hora que en su zona **no existe** (el salto adelante del cambio de
    /// horario) o es **ambigua** (el retroceso la repite) da `None`, no una hora
    /// corrida.
    #[test]
    fn una_hora_inexistente_o_ambigua_por_cambio_de_horario_da_none() {
        // 2026-03-08 02:30 en Nueva York: el reloj salta de 02:00 a 03:00.
        let inexistente = dtstart(&["TZID=America/New_York"], "20260308T023000");
        assert!(graph_datetime(&inexistente).is_none(), "inexistente");
        // 2026-11-01 01:30 en Nueva York: ocurre dos veces.
        let ambigua = dtstart(&["TZID=America/New_York"], "20261101T013000");
        assert!(graph_datetime(&ambigua).is_none(), "ambigua");
        // Y una hora normal de la misma zona sí se convierte (EDT, UTC-4).
        let normal = dtstart(&["TZID=America/New_York"], "20260915T140000");
        assert_eq!(
            utc(graph_datetime(&normal)).as_deref(),
            Some("2026-09-15T18:00:00")
        );
    }

    /// De punta a punta por el cuerpo: un evento con `TZID` sale con `start` y
    /// `end` ya en UTC.
    #[test]
    fn el_cuerpo_de_un_evento_con_tzid_sale_en_utc() {
        let ical = "BEGIN:VEVENT\r\nUID:u\r\nSUMMARY:x\r\n\
            DTSTART;TZID=America/Argentina/Buenos_Aires:20260915T140000\r\n\
            DTEND;TZID=America/Argentina/Buenos_Aires:20260915T150000\r\n\
            END:VEVENT\r\n";
        let body = event_body_from_ical(ical, None).expect("es un VEVENT");
        assert_eq!(body["start"]["dateTime"], "2026-09-15T17:00:00");
        assert_eq!(body["end"]["dateTime"], "2026-09-15T18:00:00");
    }

    // ── Mapeo de errores de almacén del empuje (`#97`) ────────────────────────

    /// Un error de almacén que **no** es «llavero bloqueado» (acá, la tabla de la
    /// cola rota: `Sqlite`) es una **falla** de la vuelta, no «desbloqueá el
    /// llavero»: se reporta `Failed` y no se baja nada. Con el mapeo viejo (todo a
    /// `StoreClosed`) la persona vería un pedido de desbloqueo que no arregla nada.
    #[tokio::test]
    async fn un_error_de_almacen_que_no_es_el_llavero_da_failed() {
        let f = Fixture::new("graph_cal_store_failed").await;
        f.manager
            .prepare_for_sync(CALENDAR_AREA, ACCOUNT)
            .await
            .then_some(())
            .expect("la base tenía que quedar abierta");
        f.manager
            .with_store(ACCOUNT, |store| {
                store
                    .connection()
                    .execute_batch("DROP TABLE pending_dav_ops")
                    .map_err(|e| StoreError::Sqlite(e.to_string()))
            })
            .await
            .unwrap();

        let outcome = f.sync().await;

        assert!(
            matches!(outcome, CalendarOutcome::Failed(_)),
            "un Sqlite no es StoreClosed: {outcome:?}"
        );
        assert!(
            f.server.requests().is_empty(),
            "no se bajó nada tras la falla del empuje"
        );
    }

    /// El llavero que se bloquea justo después de abrir la base sí es
    /// `StoreClosed`: se pide desbloquearlo.
    #[tokio::test]
    async fn el_llavero_bloqueado_a_mitad_da_store_closed() {
        let f = Fixture::new("graph_cal_store_locked").await;
        f.manager.keys().state().lock_after_is_locked = true;

        let outcome = f.sync().await;

        assert!(
            matches!(outcome, CalendarOutcome::StoreClosed),
            "llavero bloqueado: {outcome:?}"
        );
        assert!(f.server.requests().is_empty());
    }

    /// El nombre del parámetro `TZID` no distingue mayúsculas (`tzid=`), y el valor
    /// puede venir entre comillas: las dos formas se convierten igual que la
    /// canónica.
    #[test]
    fn el_tzid_no_distingue_mayusculas_ni_comillas() {
        for param in [
            "tzid=America/Argentina/Buenos_Aires",
            "TZID=\"America/Argentina/Buenos_Aires\"",
        ] {
            let p = dtstart(&[param], "20260915T140000");
            assert_eq!(
                utc(graph_datetime(&p)).as_deref(),
                Some("2026-09-15T17:00:00"),
                "{param}"
            );
        }
    }
}
