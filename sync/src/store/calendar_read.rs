//! Lo que leen las aplicaciones del calendario: los calendarios, las veces que
//! ocurre cada evento en un rango, un evento entero y las tareas.
//!
//! Todo corre sobre una conexión de **sólo lectura** ([`super::readers`]), una
//! cuenta por vez, y nada de acá escribe. Quién puede llegar hasta acá lo
//! decide `access.rs`, antes. Juntar las cuentas —un widget quiere la semana de
//! todas— lo hace `store_api.rs` con lo que devuelve cada una de acá.
//!
//! ── Los identificadores ─────────────────────────────────────────────────────
//!
//! **Globales**: `"<cuenta>/<número>"` para un calendario, un evento o una
//! tarea ([`GlobalId`]). El permiso es por aplicación y no por cuenta, y las
//! lecturas juntan todas las cuentas: un número solo no diría de cuál. Una vez
//! de un evento se identifica por su `occurrence_id`: el comienzo que tenía en
//! la serie, en segundos UTC, como texto.
//!
//! ── Un rango ────────────────────────────────────────────────────────────────
//!
//! [`account_occurrences`] da lo que se superpone con `[from, to)`: lo guardado
//! —las series en su ventana, lo que no se repite entero— por el índice de
//! `occurrences`, y **lo que cae fuera de la ventana de cada serie, expandido
//! en el momento** desde `raw_ical`, con los mismos topes que al guardar más
//! uno por consulta ([`MAX_SERIES_ON_THE_FLY`], [`ON_THE_FLY_BUDGET`]). Lo que
//! pasa un tope vuelve con `truncated`. El rango no pasa de
//! [`MAX_RANGE_SECONDS`].
//!
//! **El orden es `(comienzo, cuenta, evento, vez)`**, con el cursor en esa
//! posición: si entre una página y la siguiente entra o se va una vez, no se
//! repite ni se saltea ninguna de las que ya estaban. Un evento que se
//! reescribe conserva su número, y una vez su `occurrence_id`, así que
//! volver a expandir no mueve nada.

use base64::Engine;
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;

use super::contacts_read::{InvalidArgument, MAX_CURSOR_BYTES};
use super::{classify, paths, StoreError};
use crate::ical::recurrence::{EventSeries, ExpansionLimits, Trigger};
use crate::ical::{self, Component, DateValue, MAX_DESCRIPTION, MAX_TEXT};

/// El rango más largo que se puede pedir de una vez: un año con margen, que es
/// lo que muestra la vista más ancha de un calendario.
pub const MAX_RANGE_SECONDS: i64 = 400 * 86_400;

/// Desde cuánto una vez es **larga**: la consulta por rango mira hacia atrás
/// lo que dura la vez más larga de la cuenta, pero no más que esto, y las que
/// duran más las busca aparte, en `occurrences_long` (un índice con sólo
/// ésas). Sin este tope, un solo evento del año 1 al 9999 llevaba el piso de
/// **toda** consulta al año 1, y cada página recorría el índice entero. El
/// número está también en la migración v3, en la condición del índice.
pub const LONG_OCCURRENCE_SECONDS: i64 = 400 * 86_400;

/// Cuántos calendarios se pueden nombrar en un filtro.
pub const MAX_CALENDAR_IDS: usize = 100;

/// Cuántas series se expanden en el momento por cuenta y por consulta. Más
/// que eso vuelve con `truncated`.
pub const MAX_SERIES_ON_THE_FLY: usize = 2000;

/// Cuánto puede tardar lo que se expande en el momento, por cuenta y por
/// consulta.
pub const ON_THE_FLY_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

/// El tope de la respuesta de un evento entero. Se puede llegar —cien
/// asistentes y una descripción larga—: el que no entra vuelve recortado.
pub const MAX_EVENT_BYTES: usize = 1024 * 1024;

/// Cuántos asistentes se devuelven de un evento.
pub const MAX_ATTENDEES: usize = 100;

/// Un identificador de calendario, evento o tarea: la cuenta y el número.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GlobalId {
    pub account_id: String,
    pub id: i64,
}

impl GlobalId {
    pub fn encode(&self) -> String {
        format!("{}/{}", self.account_id, self.id)
    }

    /// `"<cuenta>/<número>"`, con la cuenta como la valida el almacén y el
    /// número positivo.
    pub fn parse(text: &str) -> Result<Self, InvalidArgument> {
        const BAD: InvalidArgument = InvalidArgument("el identificador no es válido");
        let (account_id, id) = text.split_once('/').ok_or(BAD)?;
        paths::validate_account_id(account_id).map_err(|_| BAD)?;
        let id = super::contacts_read::parse_id(id).map_err(|_| BAD)?;
        Ok(Self {
            account_id: account_id.to_string(),
            id,
        })
    }
}

/// Los calendarios de un filtro, por cuenta. Vacío es «todos».
pub fn parse_calendar_ids(ids: &[String]) -> Result<Vec<GlobalId>, InvalidArgument> {
    if ids.len() > MAX_CALENDAR_IDS {
        return Err(InvalidArgument("demasiados calendarios en el filtro"));
    }
    let mut parsed: Vec<GlobalId> = ids
        .iter()
        .map(|id| GlobalId::parse(id))
        .collect::<Result<_, _>>()?;
    parsed.sort();
    parsed.dedup();
    Ok(parsed)
}

/// Un instante en RFC 3339, en segundos UTC. Años de cuatro cifras.
pub fn parse_instant(text: &str) -> Result<i64, InvalidArgument> {
    const BAD: InvalidArgument = InvalidArgument("la fecha no es RFC 3339");
    if text.len() > 64 {
        return Err(BAD);
    }
    let moment = chrono::DateTime::parse_from_rfc3339(text.trim()).map_err(|_| BAD)?;
    let year = chrono::Datelike::year(&moment.naive_utc());
    if !(1..=9999).contains(&year) {
        return Err(BAD);
    }
    Ok(moment.timestamp())
}

/// El rango de una consulta, validado: `from < to` y no más largo que
/// [`MAX_RANGE_SECONDS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub from: i64,
    pub to: i64,
}

impl Range {
    pub fn parse(from: &str, to: &str) -> Result<Self, InvalidArgument> {
        let (from, to) = (parse_instant(from)?, parse_instant(to)?);
        if from >= to {
            return Err(InvalidArgument("el rango está vacío o al revés"));
        }
        if to - from > MAX_RANGE_SECONDS {
            return Err(InvalidArgument(
                "el rango es demasiado largo: como mucho 400 días",
            ));
        }
        Ok(Self { from, to })
    }
}

/// Una vez que se identifica: vacía es «el evento», un número es una vez.
pub fn parse_occurrence_id(text: &str) -> Result<Option<i64>, InvalidArgument> {
    const BAD: InvalidArgument = InvalidArgument("el identificador de la ocurrencia no es válido");
    if text.is_empty() {
        return Ok(None);
    }
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty() || digits.len() > 18 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BAD);
    }
    text.parse().map(Some).map_err(|_| BAD)
}

/// Dónde quedó una página: la posición de la última fila que entregó, en el
/// orden de la lista entera —de todas las cuentas—.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ListCursor {
    /// El comienzo, en una lista de ocurrencias; el vencimiento, en una de
    /// tareas.
    pub key: i64,
    pub account_id: String,
    pub id: i64,
    /// La vez, en una lista de ocurrencias; cero en una de tareas.
    pub occurrence: i64,
}

impl ListCursor {
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(&(self.key, &self.account_id, self.id, self.occurrence))
            .unwrap_or_default();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
    }

    pub fn decode(text: &str) -> Result<Option<Self>, InvalidArgument> {
        const BAD: InvalidArgument = InvalidArgument("el cursor no es válido");
        if text.is_empty() {
            return Ok(None);
        }
        if text.len() > MAX_CURSOR_BYTES {
            return Err(BAD);
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| BAD)?;
        let (key, account_id, id, occurrence): (i64, String, i64, i64) =
            serde_json::from_slice(&bytes).map_err(|_| BAD)?;
        paths::validate_account_id(&account_id).map_err(|_| BAD)?;
        if id <= 0 {
            return Err(BAD);
        }
        Ok(Some(Self {
            key,
            account_id,
            id,
            occurrence,
        }))
    }

    /// La condición del cursor para las filas de una cuenta, como SQL sobre
    /// `(clave, id, vez)`: todo lo que va **después** de la posición en el
    /// orden global.
    fn condition(&self, account_id: &str) -> (&'static str, Vec<i64>) {
        use std::cmp::Ordering;
        match account_id.cmp(self.account_id.as_str()) {
            Ordering::Greater => ("{key} >= ?", vec![self.key]),
            Ordering::Less => ("{key} > ?", vec![self.key]),
            Ordering::Equal => (
                "({key}, {id}, {occurrence}) > (?, ?, ?)",
                vec![self.key, self.id, self.occurrence],
            ),
        }
    }

    /// Si una posición va después del cursor.
    pub fn is_before(&self, position: &ListCursor) -> bool {
        self < position
    }
}

/// Un calendario, para `ListCalendars`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CalendarItem {
    pub id: String,
    pub account_id: String,
    pub display_name: String,
    pub color: Option<String>,
    pub components: Vec<String>,
}

/// Una vez de un evento: lo que dibuja un widget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OccurrenceItem {
    pub event_id: String,
    pub occurrence_id: String,
    pub calendar_id: String,
    pub title: String,
    pub start: String,
    pub end: String,
    pub all_day: bool,
    /// Si la hora es la de quien mira: sin zona, o con una que no se pudo
    /// resolver.
    pub floating: bool,
    pub color: Option<String>,
}

/// Una tarea, para `ListTasks`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaskItem {
    pub task_id: String,
    pub calendar_id: String,
    pub title: String,
    pub due: Option<String>,
    pub all_day: bool,
    /// `needs-action`, `in-process`, `completed`, `cancelled`, o vacío.
    pub status: String,
    /// De 1 (la más alta) a 9, o nada.
    pub priority: Option<i64>,
    pub completed: Option<String>,
    pub done: bool,
    pub color: Option<String>,
}

/// Lo que dio una cuenta para una página: las filas con su posición, y si
/// algo de lo expandido en el momento pasó un tope.
#[derive(Debug)]
pub struct AccountRows<T> {
    pub rows: Vec<(ListCursor, T)>,
    pub truncated: bool,
}

impl<T> Default for AccountRows<T> {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            truncated: false,
        }
    }
}

/// Los calendarios de una cuenta, por nombre.
pub fn list_calendars(
    connection: &Connection,
    account_id: &str,
) -> Result<Vec<CalendarItem>, StoreError> {
    let mut statement = connection
        .prepare(
            "SELECT id, display_name, color, components FROM calendars
              ORDER BY display_name, id",
        )
        .map_err(classify)?;
    let rows = statement
        .query_map([], |row| {
            let components: String = row.get(3)?;
            Ok(CalendarItem {
                id: GlobalId {
                    account_id: account_id.to_string(),
                    id: row.get(0)?,
                }
                .encode(),
                account_id: account_id.to_string(),
                display_name: row.get(1)?,
                color: row.get(2)?,
                components: components
                    .split(',')
                    .filter(|c| !c.is_empty())
                    .map(str::to_string)
                    .collect(),
            })
        })
        .map_err(classify)?;
    rows.collect::<Result<_, _>>().map_err(classify)
}

/// Lo que va después de `WHERE` para filtrar por calendario, con sus números.
fn calendar_filter(column: &str, calendars: Option<&[i64]>) -> String {
    match calendars {
        None => String::new(),
        Some(ids) => format!(
            " AND {column} IN ({})",
            ids.iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Qué parte de lo guardado se lee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredPart {
    /// Lo que empieza desde el piso ([`scan_floor`]): por
    /// `occurrences_by_start`.
    FromFloor,
    /// Las veces largas que empiezan antes del piso: por `occurrences_long`.
    Long,
}

/// La consulta de las ocurrencias guardadas de un rango: por el índice de
/// comienzo, con la superposición, el calendario y el cursor adentro de él.
/// Los parámetros: el piso, `to`, `from`, `from`, los del cursor y el límite.
/// Aparte para que una prueba mire su plan.
pub fn occurrences_sql(
    part: StoredPart,
    calendars: Option<&[i64]>,
    cursor: Option<&str>,
) -> String {
    let cursor = cursor
        .map(|c| {
            format!(
                " AND {}",
                c.replace("{key}", "o.starts_at")
                    .replace("{id}", "o.object_id")
                    .replace("{occurrence}", "o.recurrence_id")
            )
        })
        .unwrap_or_default();
    // La condición del índice parcial va escrita igual que en la migración,
    // con el número y no con un parámetro: si no, SQLite no puede usarlo.
    let (index, starts) = match part {
        StoredPart::FromFloor => (
            "occurrences_by_start",
            "o.starts_at >= ? AND o.starts_at < ?",
        ),
        StoredPart::Long => (
            "occurrences_long",
            "o.starts_at < ? AND o.starts_at < ? AND o.ends_at - o.starts_at > 34560000",
        ),
    };
    format!(
        "SELECT o.starts_at, o.object_id, o.recurrence_id, o.ends_at, o.all_day,
                coalesce(t.summary, c.summary), o.calendar_id, k.color, c.zone
           FROM occurrences o INDEXED BY {index}
           JOIN calendar_objects c ON c.id = o.object_id
           JOIN calendars k ON k.id = o.calendar_id
           LEFT JOIN object_titles t ON t.object_id = o.object_id AND t.position = o.title
          WHERE {starts}
            AND (o.ends_at > ? OR (o.ends_at <= o.starts_at AND o.starts_at >= ?)){}{}
          ORDER BY o.starts_at, o.object_id, o.recurrence_id
          LIMIT ?",
        calendar_filter("o.calendar_id", calendars),
        cursor
    )
}

/// Desde dónde se leen las ocurrencias guardadas de un rango que empieza en
/// `from`: lo que dura la vez más larga de la cuenta hacia atrás, pero no más
/// que [`LONG_OCCURRENCE_SECONDS`]. Lo que dura más se lee aparte
/// ([`StoredPart::Long`]).
pub fn scan_floor(connection: &Connection, from: i64) -> Result<i64, StoreError> {
    let max_span: i64 = connection
        .query_row(
            "SELECT coalesce(max(span), 0) FROM calendar_objects",
            [],
            |row| row.get(0),
        )
        .map_err(classify)?;
    Ok(from.saturating_sub(max_span.clamp(0, LONG_OCCURRENCE_SECONDS)))
}

fn floating(zone: &str) -> bool {
    matches!(zone, "floating" | "unknown")
}

/// Las veces de los eventos de una cuenta que se ven en `range`, después de
/// `after`, en orden, como mucho `limit + 1` —una más, para saber si hay otra
/// página—.
pub fn account_occurrences(
    connection: &Connection,
    account_id: &str,
    range: Range,
    calendars: Option<&[i64]>,
    after: Option<&ListCursor>,
    limit: usize,
    limits: &ExpansionLimits,
) -> Result<AccountRows<OccurrenceItem>, StoreError> {
    let mut result = AccountRows::default();
    let position = |start: i64, object: i64, rid: i64| ListCursor {
        key: start,
        account_id: account_id.to_string(),
        id: object,
        occurrence: rid,
    };
    let item = |start: i64,
                object: i64,
                rid: i64,
                end: i64,
                all_day: bool,
                title: String,
                calendar: i64,
                color: Option<String>,
                zone: &str| OccurrenceItem {
        event_id: GlobalId {
            account_id: account_id.to_string(),
            id: object,
        }
        .encode(),
        occurrence_id: rid.to_string(),
        calendar_id: GlobalId {
            account_id: account_id.to_string(),
            id: calendar,
        }
        .encode(),
        title,
        start: ical::rfc3339(start),
        end: ical::rfc3339(end),
        all_day,
        floating: floating(zone),
        color,
    };

    // Lo guardado: lo que empieza desde el piso, y las veces largas que
    // empiezan antes.
    let floor = scan_floor(connection, range.from)?;
    let condition = after.map(|a| a.condition(account_id));
    for part in [StoredPart::FromFloor, StoredPart::Long] {
        let sql = occurrences_sql(part, calendars, condition.as_ref().map(|(c, _)| *c));
        let mut params: Vec<i64> = vec![floor, range.to, range.from, range.from];
        if let Some((_, values)) = &condition {
            params.extend(values);
        }
        params.push((limit + 1) as i64);
        let mut statement = connection.prepare(&sql).map_err(classify)?;
        let mut rows = statement
            .query(rusqlite::params_from_iter(params))
            .map_err(classify)?;
        while let Some(row) = rows.next().map_err(classify)? {
            let (start, object, rid): (i64, i64, i64) = (
                row.get(0).map_err(classify)?,
                row.get(1).map_err(classify)?,
                row.get(2).map_err(classify)?,
            );
            let zone: String = row.get(8).map_err(classify)?;
            result.rows.push((
                position(start, object, rid),
                item(
                    start,
                    object,
                    rid,
                    row.get(3).map_err(classify)?,
                    row.get(4).map_err(classify)?,
                    row.get(5).map_err(classify)?,
                    row.get(6).map_err(classify)?,
                    row.get(7).map_err(classify)?,
                    &zone,
                ),
            ));
        }
    }

    // Lo que cae fuera de la ventana de cada serie, en el momento.
    let mut statement = connection
        .prepare(&format!(
            "SELECT c.id, c.calendar_id, c.raw_ical, c.expanded_from, c.expanded_to, c.span,
                    c.summary, c.zone, k.color
               FROM calendar_objects c
               JOIN calendars k ON k.id = c.calendar_id
              WHERE c.recurring = 1 AND c.component = 'VEVENT'
                AND (c.starts_at IS NULL OR c.starts_at < ?1)
                AND NOT (c.expanded_from IS NOT NULL AND c.expanded_from <= ?2 - c.span
                         AND c.expanded_to >= ?1){}
              ORDER BY c.id
              LIMIT ?3",
            calendar_filter("c.calendar_id", calendars)
        ))
        .map_err(classify)?;
    let mut series = statement
        .query(rusqlite::params![
            range.to,
            range.from,
            (MAX_SERIES_ON_THE_FLY + 1) as i64
        ])
        .map_err(classify)?;
    let deadline = std::time::Instant::now() + ON_THE_FLY_BUDGET;
    let mut expanded = 0usize;
    while let Some(row) = series.next().map_err(classify)? {
        expanded += 1;
        if expanded > MAX_SERIES_ON_THE_FLY || std::time::Instant::now() >= deadline {
            result.truncated = true;
            break;
        }
        let object: i64 = row.get(0).map_err(classify)?;
        let calendar: i64 = row.get(1).map_err(classify)?;
        let raw: String = row.get(2).map_err(classify)?;
        let skip: Option<(i64, i64)> = row
            .get::<_, Option<i64>>(3)
            .map_err(classify)?
            .zip(row.get::<_, Option<i64>>(4).map_err(classify)?);
        let summary: String = row.get(6).map_err(classify)?;
        let zone: String = row.get(7).map_err(classify)?;
        let color: Option<String> = row.get(8).map_err(classify)?;
        let document = ical::parse_document(&raw);
        let Some(parsed) = EventSeries::from_document(&document, limits) else {
            continue;
        };
        let expansion = parsed.between(range.from, range.to, skip, limits);
        result.truncated |= expansion.truncated;
        for occurrence in expansion.occurrences {
            let at = position(occurrence.start, object, occurrence.recurrence_id);
            if after.is_some_and(|a| !a.is_before(&at)) {
                continue;
            }
            result.rows.push((
                at,
                item(
                    occurrence.start,
                    object,
                    occurrence.recurrence_id,
                    occurrence.end,
                    occurrence.all_day,
                    parsed
                        .title_of(&occurrence)
                        .map_or_else(|| summary.clone(), str::to_string),
                    calendar,
                    color.clone(),
                    &zone,
                ),
            ));
        }
    }

    result.rows.sort_by(|a, b| a.0.cmp(&b.0));
    result.rows.dedup_by(|a, b| a.0 == b.0);
    result.rows.truncate(limit + 1);
    Ok(result)
}

/// Las tareas de una cuenta, por vencimiento —las sin vencimiento al final—,
/// después de `after`, como mucho `limit + 1`.
pub fn account_tasks(
    connection: &Connection,
    account_id: &str,
    calendars: Option<&[i64]>,
    include_done: bool,
    after: Option<&ListCursor>,
    limit: usize,
) -> Result<AccountRows<TaskItem>, StoreError> {
    let condition = after.map(|a| a.condition(account_id));
    let cursor = condition
        .as_ref()
        .map(|(c, _)| {
            format!(
                " AND {}",
                c.replace("{key}", "c.sort_key")
                    .replace("{id}", "c.id")
                    .replace("{occurrence}", "0")
            )
        })
        .unwrap_or_default();
    let sql = format!(
        "SELECT c.id, c.calendar_id, c.summary, c.ends_at, c.all_day, c.status, c.priority,
                c.completed_at, c.done, c.sort_key, k.color
           FROM calendar_objects c
           JOIN calendars k ON k.id = c.calendar_id
          WHERE c.component = 'VTODO'{}{}{}
          ORDER BY c.sort_key, c.id
          LIMIT ?",
        if include_done { "" } else { " AND c.done = 0" },
        calendar_filter("c.calendar_id", calendars),
        cursor
    );
    let mut params: Vec<i64> = condition.map(|(_, v)| v).unwrap_or_default();
    params.push((limit + 1) as i64);
    let mut statement = connection.prepare(&sql).map_err(classify)?;
    let mut rows = statement
        .query(rusqlite::params_from_iter(params))
        .map_err(classify)?;
    let mut result = AccountRows::default();
    while let Some(row) = rows.next().map_err(classify)? {
        let id: i64 = row.get(0).map_err(classify)?;
        let calendar: i64 = row.get(1).map_err(classify)?;
        let sort_key: i64 = row.get(9).map_err(classify)?;
        let due: Option<i64> = row.get(3).map_err(classify)?;
        let completed: Option<i64> = row.get(7).map_err(classify)?;
        result.rows.push((
            ListCursor {
                key: sort_key,
                account_id: account_id.to_string(),
                id,
                occurrence: 0,
            },
            TaskItem {
                task_id: GlobalId {
                    account_id: account_id.to_string(),
                    id,
                }
                .encode(),
                calendar_id: GlobalId {
                    account_id: account_id.to_string(),
                    id: calendar,
                }
                .encode(),
                title: row.get(2).map_err(classify)?,
                due: due.map(ical::rfc3339),
                all_day: row.get(4).map_err(classify)?,
                status: row.get(5).map_err(classify)?,
                priority: row.get(6).map_err(classify)?,
                completed: completed.map(ical::rfc3339),
                done: row.get(8).map_err(classify)?,
                color: row.get(10).map_err(classify)?,
            },
        ));
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Un evento entero
// ---------------------------------------------------------------------------

/// Una persona de un evento: el organizador o un asistente.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Person {
    pub name: String,
    pub email: String,
    /// La respuesta de un asistente (`accepted`, `declined`, …), o vacío.
    pub status: String,
}

/// La regla de repetición, en partes para que la aplicación la diga en su
/// idioma, y el texto de la regla tal cual.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Recurrence {
    pub rule: String,
    /// `daily`, `weekly`, …, o vacío si no se entiende.
    pub frequency: String,
    pub interval: u32,
    pub count: Option<u32>,
    pub until: Option<String>,
    /// `MO`, `-1FR`, … tal como los trae `BYDAY`.
    pub by_day: Vec<String>,
    /// Si además tiene fechas sueltas (`RDATE`) o sacadas (`EXDATE`).
    pub has_extra_dates: bool,
}

/// Un recordatorio de un evento.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AlarmItem {
    pub action: String,
    /// Tanto antes (negativo) o después, en segundos.
    pub offset_seconds: Option<i64>,
    /// `start` o `end`: de dónde se cuenta.
    pub related: Option<String>,
    /// Un disparo fijo, en RFC 3339.
    pub at: Option<String>,
}

/// Un evento entero, interpretado desde `raw_ical` en el momento.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventDetail {
    pub event_id: String,
    /// La vez que se pidió, o `null` si se pidió el evento.
    pub occurrence_id: Option<String>,
    pub calendar_id: String,
    pub uid: String,
    pub title: String,
    pub description: String,
    pub location: String,
    pub start: String,
    pub end: String,
    pub all_day: bool,
    /// El nombre de la zona en que lo escribieron, o vacío.
    pub timezone: String,
    /// Si esa zona no se pudo resolver y se tomó como hora flotante.
    pub timezone_unknown: bool,
    pub floating: bool,
    /// `confirmed`, `tentative`, `cancelled`, o vacío.
    pub status: String,
    pub recurrence: Option<Recurrence>,
    pub alarms: Vec<AlarmItem>,
    pub organizer: Option<Person>,
    pub attendees: Vec<Person>,
    /// Si no entraba en [`MAX_EVENT_BYTES`] y se le sacaron asistentes o se
    /// recortó la descripción.
    pub truncated: bool,
}

fn person(property: &ical::Property) -> Person {
    let value = property.value.trim();
    let email = value
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("mailto:"))
        .map_or(value, |_| &value[7..]);
    Person {
        name: property
            .param("CN")
            .map(|n| ical::visible(n, MAX_TEXT))
            .unwrap_or_default(),
        email: ical::visible(email, MAX_TEXT),
        status: property
            .param("PARTSTAT")
            .map(|s| ical::visible(s, 32).to_ascii_lowercase())
            .unwrap_or_default(),
    }
}

fn recurrence_of(master: &Component) -> Option<Recurrence> {
    let rule = master.value("RRULE").map(|r| ical::visible(r, 1024));
    let extra = master.first("RDATE").is_some() || master.first("EXDATE").is_some();
    if rule.is_none() && master.first("RDATE").is_none() {
        return None;
    }
    let rule = rule.unwrap_or_default();
    let mut recurrence = Recurrence {
        rule: rule.clone(),
        frequency: String::new(),
        interval: 1,
        count: None,
        until: None,
        by_day: Vec::new(),
        has_extra_dates: extra,
    };
    for part in rule.split(';') {
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        match name.trim().to_ascii_uppercase().as_str() {
            "FREQ" => {
                recurrence.frequency = match value.trim().to_ascii_uppercase().as_str() {
                    f @ ("SECONDLY" | "MINUTELY" | "HOURLY" | "DAILY" | "WEEKLY" | "MONTHLY"
                    | "YEARLY") => f.to_ascii_lowercase(),
                    _ => String::new(),
                }
            }
            "INTERVAL" => recurrence.interval = value.trim().parse().unwrap_or(1).max(1),
            "COUNT" => recurrence.count = value.trim().parse().ok(),
            "UNTIL" => {
                recurrence.until = DateValue::parse(value, &[])
                    .and_then(|d| d.resolve(&Default::default()))
                    .map(|(m, _)| m.to_rfc3339())
            }
            "BYDAY" => {
                recurrence.by_day = value
                    .split(',')
                    .map(|d| d.trim().to_ascii_uppercase())
                    .filter(|d| !d.is_empty() && d.len() <= 5)
                    .take(64)
                    .collect()
            }
            _ => {}
        }
    }
    Some(recurrence)
}

fn alarms_of(component: &Component, limits: &ExpansionLimits) -> Vec<AlarmItem> {
    component
        .children
        .iter()
        .filter(|c| c.name == "VALARM")
        .take(limits.max_alarms)
        .filter_map(crate::ical::recurrence::alarm_of)
        .map(|alarm| match alarm.trigger {
            Trigger::Relative { seconds, from_end } => AlarmItem {
                action: alarm.action,
                offset_seconds: Some(seconds),
                related: Some(if from_end { "end" } else { "start" }.into()),
                at: None,
            },
            Trigger::Absolute(at) => AlarmItem {
                action: alarm.action,
                offset_seconds: None,
                related: None,
                at: Some(ical::rfc3339(at)),
            },
        })
        .collect()
}

/// Un evento entero, o `None` si no está, no es un evento o no tiene esa vez.
/// Nunca el iCalendar crudo ni la dirección en el servidor.
pub fn get_event(
    connection: &Connection,
    account_id: &str,
    id: i64,
    occurrence: Option<i64>,
    limits: &ExpansionLimits,
) -> Result<Option<EventDetail>, StoreError> {
    let row: Option<(i64, String, String)> = connection
        .query_row(
            "SELECT calendar_id, raw_ical, zone FROM calendar_objects
              WHERE id = ?1 AND component = 'VEVENT'",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(classify)?;
    let Some((calendar, raw, zone)) = row else {
        return Ok(None);
    };
    let document = ical::parse_document(&raw);
    let Some(series) = EventSeries::from_document(&document, limits) else {
        return Ok(None);
    };
    let events: Vec<&Component> = document
        .components
        .iter()
        .filter(|c| c.name == "VEVENT")
        .collect();
    let uid = events
        .first()
        .and_then(|c| c.value("UID"))
        .unwrap_or("")
        .to_string();
    let same: Vec<&Component> = events
        .into_iter()
        .filter(|c| c.value("UID").unwrap_or("") == uid)
        .collect();
    let master = same
        .iter()
        .find(|c| c.first("RECURRENCE-ID").is_none())
        .or(same.first())
        .copied()
        .expect("la serie tiene por lo menos un VEVENT");

    // La vez pedida: la excepción que la reemplaza, si hay, o la serie.
    let (component, times) = match occurrence {
        None => {
            let event = ical::event_of(master, &document.zones);
            let times = event.map(|e| (e.start, e.end, e.all_day));
            (master, times)
        }
        Some(rid) => {
            let Some(instance) = series.instance(rid, limits) else {
                return Ok(None);
            };
            let exception = same.iter().copied().find(|c| {
                c.first("RECURRENCE-ID")
                    .and_then(|p| DateValue::parse(&p.value, &p.params))
                    .and_then(|d| d.resolve(&document.zones))
                    .is_some_and(|(m, _)| m.timestamp() == rid)
            });
            (
                exception.unwrap_or(master),
                Some((
                    ical::rfc3339(instance.start),
                    ical::rfc3339(instance.end),
                    instance.all_day,
                )),
            )
        }
    };
    let (start, end, all_day) = times.unwrap_or_default();
    let detail = EventDetail {
        event_id: GlobalId {
            account_id: account_id.to_string(),
            id,
        }
        .encode(),
        occurrence_id: occurrence.map(|r| r.to_string()),
        calendar_id: GlobalId {
            account_id: account_id.to_string(),
            id: calendar,
        }
        .encode(),
        uid: ical::clipped(&uid, MAX_TEXT),
        title: component.text("SUMMARY", MAX_TEXT).unwrap_or_default(),
        description: component
            .first("DESCRIPTION")
            .map(|p| ical::visible_multiline(&ical::unescape_text(&p.value), MAX_DESCRIPTION))
            .unwrap_or_default(),
        location: component.text("LOCATION", MAX_TEXT).unwrap_or_default(),
        start,
        end,
        all_day,
        timezone: ical::zone_name(component),
        timezone_unknown: zone == "unknown",
        floating: floating(&zone),
        status: component
            .value("STATUS")
            .map(|s| ical::visible(s, 32).to_ascii_lowercase())
            .unwrap_or_default(),
        recurrence: recurrence_of(master),
        alarms: alarms_of(component, limits),
        organizer: component.first("ORGANIZER").map(person),
        attendees: component
            .all("ATTENDEE")
            .take(MAX_ATTENDEES)
            .map(person)
            .collect(),
        truncated: false,
    };
    Ok(Some(fit_event(detail, MAX_EVENT_BYTES)))
}

fn json_len<T: Serialize>(value: &T) -> usize {
    serde_json::to_string(value).map_or(usize::MAX, |json| json.len())
}

/// Un evento que entra en `cap` bytes de JSON: entero si entra; si no, sin
/// sus últimos asistentes y, si todavía no entra, con la descripción
/// recortada.
fn fit_event(mut event: EventDetail, cap: usize) -> EventDetail {
    if json_len(&event) <= cap {
        return event;
    }
    event.truncated = true;
    while json_len(&event) > cap && event.attendees.pop().is_some() {}
    while json_len(&event) > cap && !event.description.is_empty() {
        let half = event.description.len() / 2;
        event.description = ical::clipped(&event.description, half);
    }
    event
}

#[cfg(test)]
mod tests {
    use super::super::calendar::tests::{at, calendar, object, weekly, window};
    use super::super::calendar::{CalendarRoom, ObjectOp};
    use super::super::contacts::tests::open_store;
    use super::super::paths::tests::TempDir;
    use super::super::Store;
    use super::*;

    fn store_with(temp: &TempDir, raws: &[(&str, &str)]) -> Store {
        let mut store = open_store(temp);
        let cal = calendar(&mut store, "https://x/c/");
        let w = window();
        let ops: Vec<ObjectOp> = raws
            .iter()
            .map(|(href, raw)| ObjectOp::Upsert(object(href, raw, w)))
            .collect();
        store
            .apply_calendar_objects(&cal, &ops, w, None, CalendarRoom::UNLIMITED)
            .unwrap();
        store
    }

    fn range(from: &str, to: &str) -> Range {
        Range::parse(from, to).unwrap()
    }

    fn single(uid: &str, start: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nSUMMARY:Suelto {uid}\r\n\
             DTSTART:{start}\r\nDURATION:PT1H\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    }

    fn titles(rows: &AccountRows<OccurrenceItem>) -> Vec<(String, String)> {
        rows.rows
            .iter()
            .map(|(_, i)| (i.start.clone(), i.title.clone()))
            .collect()
    }

    #[test]
    fn los_identificadores_globales_se_validan() {
        assert_eq!(
            GlobalId::parse("cuenta-1/42").unwrap(),
            GlobalId {
                account_id: "cuenta-1".into(),
                id: 42
            }
        );
        for bad in [
            "",
            "42",
            "cuenta/",
            "/42",
            "cu enta/1",
            "c/0",
            "c/-1",
            "c/1/2",
            "../c/1",
        ] {
            assert!(GlobalId::parse(bad).is_err(), "{bad:?}");
        }
        assert!(parse_calendar_ids(&vec!["c/1".to_string(); MAX_CALENDAR_IDS + 1]).is_err());
        assert_eq!(
            parse_calendar_ids(&["c/1".into(), "c/1".into()])
                .unwrap()
                .len(),
            1
        );
    }

    /// El rango se valida antes de todo: sin fechas que no son RFC 3339, al
    /// revés, vacío o de más de 400 días.
    #[test]
    fn el_rango_se_valida() {
        assert!(Range::parse("2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z").is_ok());
        assert!(Range::parse("2026-01-01T00:00:00-03:00", "2027-01-01T00:00:00Z").is_ok());
        for (from, to) in [
            ("2026-10-01T00:00:00Z", "2026-09-01T00:00:00Z"),
            ("2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z"),
            ("2026-01-01T00:00:00Z", "2027-03-01T00:00:00Z"),
            ("ayer", "2026-09-01T00:00:00Z"),
            ("2026-09-01", "2026-10-01"),
            ("+10000-01-01T00:00:00Z", "+10000-02-01T00:00:00Z"),
        ] {
            assert!(Range::parse(from, to).is_err(), "{from} {to}");
        }
    }

    #[test]
    fn el_cursor_se_valida_y_vuelve() {
        let cursor = ListCursor {
            key: -5,
            account_id: "c".into(),
            id: 3,
            occurrence: 99,
        };
        assert_eq!(ListCursor::decode(&cursor.encode()).unwrap(), Some(cursor));
        assert_eq!(ListCursor::decode("").unwrap(), None);
        let raw = |json: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        for bad in [
            "no-es-base64!".to_string(),
            raw("[1,\"c\",0,0]"),
            raw("[1,\"../c\",1,0]"),
            raw("[1,\"c\"]"),
            "a".repeat(MAX_CURSOR_BYTES + 1),
        ] {
            assert!(ListCursor::decode(&bad).is_err(), "{bad:?}");
        }
    }

    /// Lo guardado de un rango: las veces de una serie y un suelto, en orden,
    /// cada uno con su calendario y su color.
    #[test]
    fn un_rango_dentro_de_la_ventana_lee_lo_guardado() {
        let temp = TempDir::new("leer-rango");
        let store = store_with(
            &temp,
            &[
                ("https://x/c/s.ics", &weekly("s", "20260907T090000Z")),
                ("https://x/c/a.ics", &single("a", "20260915T120000Z")),
            ],
        );
        let rows = account_occurrences(
            store.connection(),
            "cuenta",
            range("2026-09-14T00:00:00Z", "2026-09-22T00:00:00Z"),
            None,
            None,
            100,
            &ExpansionLimits::DEFAULT,
        )
        .unwrap();
        assert_eq!(
            titles(&rows),
            vec![
                ("2026-09-14T09:00:00+00:00".into(), "Semanal s".into()),
                ("2026-09-15T12:00:00+00:00".into(), "Suelto a".into()),
                ("2026-09-21T09:00:00+00:00".into(), "Semanal s".into()),
            ]
        );
        let first = &rows.rows[0].1;
        assert_eq!(first.event_id, "cuenta/1");
        assert_eq!(first.calendar_id, "cuenta/1");
        assert_eq!(first.color.as_deref(), Some("#FF0000"));
        assert_eq!(first.occurrence_id, at("2026-09-14T09:00:00Z").to_string());
        assert!(!rows.truncated);
    }

    /// **Fuera de la ventana, en el momento**: una serie se expande desde
    /// `raw_ical` para un rango de 2030, y un suelto de 2010 sale de lo
    /// guardado.
    #[test]
    fn un_rango_fuera_de_la_ventana_se_expande_en_el_momento() {
        let temp = TempDir::new("leer-fuera");
        let store = store_with(
            &temp,
            &[
                ("https://x/c/s.ics", &weekly("s", "20260907T090000Z")),
                ("https://x/c/v.ics", &single("v", "20300105T100000Z")),
            ],
        );
        let rows = account_occurrences(
            store.connection(),
            "cuenta",
            range("2030-01-01T00:00:00Z", "2030-01-15T00:00:00Z"),
            None,
            None,
            100,
            &ExpansionLimits::DEFAULT,
        )
        .unwrap();
        assert_eq!(
            titles(&rows),
            vec![
                ("2030-01-05T10:00:00+00:00".into(), "Suelto v".into()),
                ("2030-01-07T09:00:00+00:00".into(), "Semanal s".into()),
                ("2030-01-14T09:00:00+00:00".into(), "Semanal s".into()),
            ]
        );

        // Y un rango que cruza el borde de la ventana: ni repetidos ni huecos.
        let w = window();
        let from = w.end - 14 * 86_400;
        let across = Range {
            from,
            to: w.end + 14 * 86_400,
        };
        let rows = account_occurrences(
            store.connection(),
            "cuenta",
            across,
            None,
            None,
            100,
            &ExpansionLimits::DEFAULT,
        )
        .unwrap();
        let starts: Vec<i64> = rows.rows.iter().map(|(p, _)| p.key).collect();
        assert_eq!(starts.len(), 4, "cuatro semanas, dos de cada lado");
        assert!(starts.windows(2).all(|w| w[1] - w[0] == 7 * 86_400));
    }

    /// El título de una `THISANDFUTURE` llega a cada vez que le sigue, de lo
    /// guardado —por `object_titles`— y de lo expandido en el momento.
    #[test]
    fn el_titulo_de_una_excepcion_llega_a_la_lista() {
        let temp = TempDir::new("leer-titulo");
        let raw = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:s\r\nSUMMARY:Semanal s\r\n\
                   DTSTART:20260907T090000Z\r\nDURATION:PT1H\r\nRRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\n\
                   BEGIN:VEVENT\r\nUID:s\r\nSUMMARY:Semanal corrida\r\n\
                   RECURRENCE-ID;RANGE=THISANDFUTURE:20260914T090000Z\r\n\
                   DTSTART:20260914T090000Z\r\nDURATION:PT1H\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let store = store_with(&temp, &[("https://x/c/s.ics", raw)]);
        let list = |from: &str, to: &str| {
            titles(
                &account_occurrences(
                    store.connection(),
                    "cuenta",
                    range(from, to),
                    None,
                    None,
                    100,
                    &ExpansionLimits::DEFAULT,
                )
                .unwrap(),
            )
        };
        assert_eq!(
            list("2026-09-01T00:00:00Z", "2026-09-22T00:00:00Z"),
            vec![
                ("2026-09-07T09:00:00+00:00".into(), "Semanal s".into()),
                ("2026-09-14T09:00:00+00:00".into(), "Semanal corrida".into()),
                ("2026-09-21T09:00:00+00:00".into(), "Semanal corrida".into()),
            ]
        );
        assert_eq!(
            list("2030-01-01T00:00:00Z", "2030-01-08T00:00:00Z"),
            vec![("2030-01-07T09:00:00+00:00".into(), "Semanal corrida".into())]
        );
    }

    /// Un suelto del año 1 al 9999 y diez mil veces guardadas, una por día
    /// desde 1999: lo que un servidor puede mandar.
    fn store_with_a_ten_thousand_year_event(temp: &TempDir) -> Store {
        let long = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:largo\r\nSUMMARY:Largo\r\n\
                    DTSTART:00010101T000000Z\r\nDTEND:99991231T000000Z\r\nEND:VEVENT\r\n\
                    END:VCALENDAR\r\n";
        let store = store_with(
            temp,
            &[
                ("https://x/c/largo.ics", long),
                ("https://x/c/v.ics", &single("v", "19990101T100000Z")),
            ],
        );
        let (object, calendar): (i64, i64) = store
            .connection()
            .query_row(
                "SELECT id, calendar_id FROM calendar_objects WHERE uid = 'v'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let first = at("1999-01-01T10:00:00Z");
        store.connection().execute_batch("BEGIN").unwrap();
        for day in 1..10_000i64 {
            let start = first + day * 86_400;
            store
                .connection()
                .execute(
                    "INSERT INTO occurrences
                       (object_id, recurrence_id, calendar_id, starts_at, ends_at, all_day)
                     VALUES (?1, ?2, ?3, ?2, ?2 + 3600, 0)",
                    rusqlite::params![object, start, calendar],
                )
                .unwrap();
        }
        store.connection().execute_batch("COMMIT").unwrap();
        store
    }

    /// **Un evento de diez mil años no saca la consulta del índice.** Con
    /// uno así, `max(span)` llevaba el piso de toda consulta al año 1 y cada
    /// página recorría las diez mil veces; ahora el piso mira hacia atrás
    /// como mucho [`LONG_OCCURRENCE_SECONDS`], y lo que la consulta recorre
    /// —medido en pasos de la máquina de SQLite— es lo de esos 400 días.
    #[test]
    fn un_evento_de_diez_mil_anios_no_saca_la_consulta_del_indice() {
        use rusqlite::StatementStatus;
        let temp = TempDir::new("leer-largo-costo");
        let store = store_with_a_ten_thousand_year_event(&temp);
        let r = range("2026-01-01T00:00:00Z", "2026-01-08T00:00:00Z");
        let floor = scan_floor(store.connection(), r.from).unwrap();
        assert_eq!(floor, r.from - LONG_OCCURRENCE_SECONDS);

        let steps = |floor: i64| {
            let sql = occurrences_sql(StoredPart::FromFloor, None, None);
            let mut statement = store.connection().prepare(&sql).unwrap();
            let mut rows = statement
                .query(rusqlite::params![floor, r.to, r.from, r.from, 1001])
                .unwrap();
            let mut found = 0;
            while rows.next().unwrap().is_some() {
                found += 1;
            }
            drop(rows);
            (found, statement.get_status(StatementStatus::VmStep))
        };
        let (found, capped) = steps(floor);
        let (all, uncapped) = steps(at("0001-01-01T00:00:00Z"));
        assert_eq!(found, 7, "una por día de la semana pedida");
        assert_eq!(all, 8, "y el largo, desde el año 1");
        // Unos 400 días de índice contra diez mil.
        assert!(
            capped * 10 < uncapped,
            "con el piso acotado {capped} pasos, sin acotar {uncapped}"
        );
    }

    /// Y el evento largo **se sigue viendo**, en cualquier año que cubra: lo
    /// trae la consulta de las veces largas, por su índice.
    #[test]
    fn un_evento_de_diez_mil_anios_se_sigue_viendo() {
        let temp = TempDir::new("leer-largo-visto");
        let store = store_with_a_ten_thousand_year_event(&temp);
        for (from, to, others) in [
            ("2026-01-01T00:00:00Z", "2026-01-08T00:00:00Z", 7),
            ("5000-06-01T00:00:00Z", "5000-06-08T00:00:00Z", 0),
            ("0001-01-01T00:00:00Z", "0001-01-02T00:00:00Z", 0),
        ] {
            let rows = account_occurrences(
                store.connection(),
                "cuenta",
                range(from, to),
                None,
                None,
                100,
                &ExpansionLimits::DEFAULT,
            )
            .unwrap();
            let names: Vec<&str> = rows.rows.iter().map(|(_, i)| i.title.as_str()).collect();
            assert_eq!(names.first(), Some(&"Largo"), "{from}");
            assert_eq!(names.len(), others + 1, "{from}");
        }
        // Y con el cursor: después del largo siguen las otras, sin repetirlo.
        let r = range("2026-01-01T00:00:00Z", "2026-01-08T00:00:00Z");
        let first = account_occurrences(
            store.connection(),
            "cuenta",
            r,
            None,
            None,
            1,
            &ExpansionLimits::DEFAULT,
        )
        .unwrap();
        assert_eq!(first.rows[0].1.title, "Largo");
        let rest = account_occurrences(
            store.connection(),
            "cuenta",
            r,
            None,
            Some(&first.rows[0].0),
            100,
            &ExpansionLimits::DEFAULT,
        )
        .unwrap();
        assert_eq!(rest.rows.len(), 7);
        assert!(rest.rows.iter().all(|(_, i)| i.title == "Suelto v"));
    }

    /// **La paginación no repite ni saltea** aunque entre algo entre páginas,
    /// y el cursor funciona también con lo expandido en el momento.
    #[test]
    fn la_paginacion_de_ocurrencias_no_repite_ni_saltea() {
        let temp = TempDir::new("leer-paginas");
        let mut store = store_with(
            &temp,
            &[
                ("https://x/c/s.ics", &weekly("s", "20260907T090000Z")),
                ("https://x/c/t.ics", &weekly("t", "20260907T090000Z")),
            ],
        );
        let r = range("2026-09-01T00:00:00Z", "2026-11-01T00:00:00Z");
        let mut seen = Vec::new();
        let mut cursor: Option<ListCursor> = None;
        let mut page = 0;
        loop {
            let rows = account_occurrences(
                store.connection(),
                "cuenta",
                r,
                None,
                cursor.as_ref(),
                3,
                &ExpansionLimits::DEFAULT,
            )
            .unwrap();
            let more = rows.rows.len() > 3;
            let taken: Vec<_> = rows.rows.into_iter().take(3).collect();
            cursor = taken.last().map(|(p, _)| p.clone());
            seen.extend(taken.into_iter().map(|(p, _)| p));
            page += 1;
            if page == 1 {
                // Entre la primera y la segunda página entra un suelto
                // antes del cursor y otro después.
                let cal = calendar(&mut store, "https://x/c/");
                let w = window();
                store
                    .apply_calendar_objects(
                        &cal,
                        &[
                            ObjectOp::Upsert(object(
                                "https://x/c/antes.ics",
                                &single("antes", "20260902T000000Z"),
                                w,
                            )),
                            ObjectOp::Upsert(object(
                                "https://x/c/despues.ics",
                                &single("despues", "20261020T000000Z"),
                                w,
                            )),
                        ],
                        w,
                        None,
                        CalendarRoom::UNLIMITED,
                    )
                    .unwrap();
            }
            if !more {
                break;
            }
        }
        let mut sorted = seen.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted, seen, "en orden y sin repetidos");
        // 8 semanas de cada serie más el que entró después del cursor.
        assert_eq!(seen.len(), 8 * 2 + 1);
        assert!(!seen.iter().any(|p| p.key == at("2026-09-02T00:00:00Z")));
    }

    /// El cursor de otra cuenta ordena por cuenta en el mismo comienzo.
    #[test]
    fn el_cursor_de_otra_cuenta_corta_por_comienzo() {
        let temp = TempDir::new("leer-otra-cuenta");
        let store = store_with(
            &temp,
            &[("https://x/c/a.ics", &single("a", "20260915T120000Z"))],
        );
        let at_start = at("2026-09-15T12:00:00Z");
        let r = range("2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z");
        let read = |account: &str| {
            account_occurrences(
                store.connection(),
                "cuenta",
                r,
                None,
                Some(&ListCursor {
                    key: at_start,
                    account_id: account.into(),
                    id: 1,
                    occurrence: 0,
                }),
                10,
                &ExpansionLimits::DEFAULT,
            )
            .unwrap()
            .rows
            .len()
        };
        // Una cuenta anterior en el mismo comienzo: ésta viene después.
        assert_eq!(read("antes"), 1);
        // Una posterior: ésta ya pasó.
        assert_eq!(read("zzz"), 0);
    }

    /// El filtro por calendario.
    #[test]
    fn el_filtro_por_calendario_deja_solo_esos() {
        let temp = TempDir::new("leer-filtro");
        let store = store_with(
            &temp,
            &[("https://x/c/a.ics", &single("a", "20260915T120000Z"))],
        );
        let r = range("2026-09-01T00:00:00Z", "2026-10-01T00:00:00Z");
        for (filter, expected) in [(Some(vec![1]), 1), (Some(vec![2]), 0), (None, 1)] {
            let rows = account_occurrences(
                store.connection(),
                "cuenta",
                r,
                filter.as_deref(),
                None,
                10,
                &ExpansionLimits::DEFAULT,
            )
            .unwrap();
            assert_eq!(rows.rows.len(), expected);
        }
    }

    /// El plan de la consulta de verdad —con sus uniones, el filtro y el
    /// cursor— usa el índice de comienzo y no ordena en memoria.
    #[test]
    fn la_consulta_de_un_rango_usa_el_indice() {
        let temp = TempDir::new("leer-plan");
        let store = open_store(&temp);
        for (part, index) in [
            (StoredPart::FromFloor, "occurrences_by_start"),
            (StoredPart::Long, "occurrences_long"),
        ] {
            let sql = occurrences_sql(
                part,
                Some(&[1, 2]),
                Some("({key}, {id}, {occurrence}) > (?, ?, ?)"),
            )
            .replace("{key}", "o.starts_at")
            .replace("{id}", "o.object_id")
            .replace("{occurrence}", "o.recurrence_id");
            let mut statement = store
                .connection()
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap();
            let plan: Vec<String> = statement
                .query_map([1, 2, 3, 4, 5, 6, 7, 8], |row| row.get::<_, String>(3))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            let plan = plan.join(" | ");
            assert!(plan.contains(&format!("INDEX {index} ")), "{plan}");
            assert!(!plan.contains("TEMP B-TREE"), "{plan}");
        }
        // La condición del índice parcial es la de la consulta, con el mismo
        // número.
        assert!(
            occurrences_sql(StoredPart::Long, None, None).contains(&format!(
                "ends_at - o.starts_at > {LONG_OCCURRENCE_SECONDS}"
            ))
        );
    }

    /// Un evento entero, con la repetición en partes, los recordatorios, el
    /// organizador y los asistentes; nunca el crudo. Y una vez movida trae lo
    /// de su excepción.
    #[test]
    fn un_evento_se_devuelve_interpretado() {
        let raw = "BEGIN:VCALENDAR\r\n\
            BEGIN:VEVENT\r\nUID:s\r\nSUMMARY:Clase\r\nDESCRIPTION:Traer\\nla carpeta\r\n\
            LOCATION:Aula 3\r\nDTSTART;TZID=Europe/Madrid:20260907T090000\r\nDURATION:PT1H\r\n\
            RRULE:FREQ=WEEKLY;BYDAY=MO,WE;COUNT=10\r\n\
            ORGANIZER;CN=Ana:mailto:ana@x.com\r\n\
            ATTENDEE;CN=\"Pérez; Beto\";PARTSTAT=ACCEPTED:mailto:beto@x.com\r\n\
            BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\n\
            END:VEVENT\r\n\
            BEGIN:VEVENT\r\nUID:s\r\nSUMMARY:Clase movida\r\n\
            RECURRENCE-ID;TZID=Europe/Madrid:20260909T090000\r\n\
            DTSTART;TZID=Europe/Madrid:20260910T180000\r\nDURATION:PT2H\r\nEND:VEVENT\r\n\
            END:VCALENDAR\r\n";
        let temp = TempDir::new("leer-evento");
        let store = store_with(&temp, &[("https://x/c/s.ics", raw)]);
        let event = get_event(
            store.connection(),
            "cuenta",
            1,
            None,
            &ExpansionLimits::DEFAULT,
        )
        .unwrap()
        .unwrap();
        assert_eq!(event.title, "Clase");
        assert_eq!(event.description, "Traer\nla carpeta");
        assert_eq!(event.location, "Aula 3");
        assert_eq!(event.start, "2026-09-07T07:00:00+00:00");
        assert_eq!(event.timezone, "Europe/Madrid");
        let recurrence = event.recurrence.as_ref().unwrap();
        assert_eq!(recurrence.frequency, "weekly");
        assert_eq!(recurrence.by_day, vec!["MO", "WE"]);
        assert_eq!(recurrence.count, Some(10));
        assert_eq!(event.alarms[0].offset_seconds, Some(-900));
        assert_eq!(event.organizer.as_ref().unwrap().email, "ana@x.com");
        assert_eq!(event.attendees[0].name, "Pérez; Beto");
        assert_eq!(event.attendees[0].status, "accepted");
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("BEGIN:VCALENDAR") && !json.contains("https://x/"));

        let moved = at("2026-09-09T07:00:00Z");
        let instance = get_event(
            store.connection(),
            "cuenta",
            1,
            Some(moved),
            &ExpansionLimits::DEFAULT,
        )
        .unwrap()
        .unwrap();
        assert_eq!(instance.title, "Clase movida");
        assert_eq!(instance.start, "2026-09-10T16:00:00+00:00");
        assert_eq!(instance.end, "2026-09-10T18:00:00+00:00");
        assert_eq!(instance.occurrence_id, Some(moved.to_string()));

        // Una vez que no existe, y un evento que no está: nada.
        assert_eq!(
            get_event(
                store.connection(),
                "cuenta",
                1,
                Some(12345),
                &ExpansionLimits::DEFAULT
            )
            .unwrap(),
            None
        );
        assert_eq!(
            get_event(
                store.connection(),
                "cuenta",
                99,
                None,
                &ExpansionLimits::DEFAULT
            )
            .unwrap(),
            None
        );
    }

    /// Un evento que no entra en un mega vuelve recortado, nunca como error.
    #[test]
    fn un_evento_que_no_entra_se_devuelve_recortado() {
        let attendees: String = (0..100)
            .map(|i| format!("ATTENDEE;CN={}:mailto:p{i}@x.com\r\n", "x".repeat(1000)))
            .collect();
        let raw = format!(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:g\r\nSUMMARY:Grande\r\n\
             DTSTART:20260915T120000Z\r\nDESCRIPTION:{}\r\n{attendees}END:VEVENT\r\nEND:VCALENDAR\r\n",
            "\\\\".repeat(30_000)
        );
        let temp = TempDir::new("leer-grande");
        let store = store_with(&temp, &[("https://x/c/g.ics", &raw)]);
        let event = get_event(
            store.connection(),
            "cuenta",
            1,
            None,
            &ExpansionLimits::DEFAULT,
        )
        .unwrap()
        .unwrap();
        let fitted = fit_event(event, 50_000);
        assert!(fitted.truncated);
        assert!(json_len(&fitted) <= 50_000);
        assert_eq!(fitted.title, "Grande");
    }

    /// Las tareas: por vencimiento, las sin vencimiento al final, sin las
    /// hechas salvo que se pidan.
    #[test]
    fn las_tareas_se_listan_por_vencimiento() {
        let todo = |uid: &str, extra: &str| {
            format!(
                "BEGIN:VCALENDAR\r\nBEGIN:VTODO\r\nUID:{uid}\r\nSUMMARY:{uid}\r\n{extra}\
                 END:VTODO\r\nEND:VCALENDAR\r\n"
            )
        };
        let temp = TempDir::new("leer-tareas");
        let store = store_with(
            &temp,
            &[
                (
                    "https://x/c/1.ics",
                    &todo("tarde", "DUE:20261201T100000Z\r\n"),
                ),
                ("https://x/c/2.ics", &todo("sin-fecha", "")),
                (
                    "https://x/c/3.ics",
                    &todo("pronto", "DUE:20261001T100000Z\r\nPRIORITY:1\r\n"),
                ),
                (
                    "https://x/c/4.ics",
                    &todo("hecha", "DUE:20260901T100000Z\r\nSTATUS:COMPLETED\r\n"),
                ),
            ],
        );
        let names = |include: bool| -> Vec<String> {
            account_tasks(store.connection(), "cuenta", None, include, None, 10)
                .unwrap()
                .rows
                .into_iter()
                .map(|(_, t)| t.title)
                .collect()
        };
        assert_eq!(names(false), vec!["pronto", "tarde", "sin-fecha"]);
        assert_eq!(names(true), vec!["hecha", "pronto", "tarde", "sin-fecha"]);
        let first = &account_tasks(store.connection(), "cuenta", None, false, None, 1)
            .unwrap()
            .rows[0];
        assert_eq!(first.1.priority, Some(1));
        assert_eq!(first.1.due.as_deref(), Some("2026-10-01T10:00:00+00:00"));
        // Con el cursor de la primera, sigue la segunda.
        let next =
            account_tasks(store.connection(), "cuenta", None, false, Some(&first.0), 1).unwrap();
        assert_eq!(next.rows[0].1.title, "tarde");
    }

    /// Un rango que pide más de lo que se expande en el momento vuelve marcado.
    #[test]
    fn lo_expandido_en_el_momento_tiene_tope() {
        let temp = TempDir::new("leer-tope");
        let store = store_with(
            &temp,
            &[(
                "https://x/c/s.ics",
                "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:s\r\nSUMMARY:Cada minuto\r\n\
                 DTSTART:20260101T000000Z\r\nRRULE:FREQ=MINUTELY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
            )],
        );
        let rows = account_occurrences(
            store.connection(),
            "cuenta",
            range("2030-01-01T00:00:00Z", "2030-12-01T00:00:00Z"),
            None,
            None,
            100,
            &ExpansionLimits::DEFAULT,
        )
        .unwrap();
        assert!(rows.truncated);
        assert_eq!(rows.rows.len(), 101);
    }
}
