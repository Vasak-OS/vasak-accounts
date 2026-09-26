//! El calendario en la base: lo que escribe la sincronización.
//!
//! Sólo escritura, lo que la sincronización necesita leer para decidir qué
//! pedir (los ETag y el token de cada calendario) y la ventana. Listar para las
//! aplicaciones vive en `calendar_read.rs`, sobre las conexiones de lectura.
//!
//! ── Lo que se guarda de cada objeto ─────────────────────────────────────────
//!
//! **El iCalendar crudo**, que es la fuente de verdad (decisión 3 del taller), y
//! derivado de él: lo que hace falta para listar ([`ObjectIndex`]) y, si es un
//! evento, **sus ocurrencias** ya expandidas, con sus recordatorios. Derivar es
//! CPU —leer el archivo, expandir la serie— y lo hace [`derive_object`], que
//! quien escribe llama fuera del bucle de eventos y fuera de la cerradura del
//! almacén: el lote llega a la transacción ya armado.
//!
//! ── La ventana ──────────────────────────────────────────────────────────────
//!
//! Supuesto 3 del diseño: se guardan todos los objetos, y las ocurrencias de
//! las **series** se expanden en `[hoy − 12 meses, hoy + 24 meses]`
//! ([`Window::around`]). Un evento que no se repite se guarda entero, esté
//! donde esté. La ventana vive en `store_meta` (`calendar.window`), y cada
//! serie anota qué rango cubren sus ocurrencias (`expanded_from`,
//! `expanded_to`): lo que se lee fuera de ese rango se expande en el momento
//! desde `raw_ical`.
//!
//! **Una vez por día la ventana se corre** ([`Store::stale_series`] y
//! [`Store::apply_window_shift`]), sin volver a la red: de cada serie se borra
//! lo que quedó afuera y se expande lo que entró, de a lotes, cada uno en su
//! transacción. Una serie recortada por un tope se vuelve a expandir entera.
//! Un lote que escribe con una ventana que ya no es la de la base no escribe
//! nada ([`CalendarApplied::WindowMoved`]).
//!
//! ── Los lotes ───────────────────────────────────────────────────────────────
//!
//! Como en los contactos: una transacción lleva como mucho
//! [`WRITE_BATCH_ROWS`] objetos —y [`WRITE_BATCH_OCCURRENCES`] ocurrencias—,
//! el token va con el último lote de cada calendario, y cada lote que cambia
//! algo sube la generación del área `calendar` en su misma transacción.

use std::collections::HashMap;

use chrono::{DateTime, Months, TimeZone, Utc};
use rusqlite::OptionalExtension;

use super::lifecycle::CALENDAR_AREA;
use super::{bump_generation, classify, Store, StoreError};
use crate::ical::recurrence::{EventSeries, ExpansionLimits, Occurrence};
use crate::ical::{self, Component, DateValue, ZoneKind, MAX_TEXT};

/// Cuántos objetos entran en una transacción, como mucho.
pub const WRITE_BATCH_ROWS: usize = 500;

/// Cuánto iCalendar crudo entra en un lote.
pub const WRITE_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// Cuántas ocurrencias entran en un lote: quinientas series de a mil veces
/// serían medio millón de filas en una transacción.
pub const WRITE_BATCH_OCCURRENCES: usize = 20_000;

/// Cuántas series se vuelven a expandir por lote al correr la ventana.
pub const SHIFT_BATCH_ROWS: usize = 100;

/// La clave de `store_meta` donde vive la ventana.
const WINDOW_KEY: &str = "calendar.window";

/// El rango de las ocurrencias guardadas de las series, en segundos UTC:
/// `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub start: i64,
    pub end: i64,
}

impl Window {
    /// La ventana de un día: desde la medianoche UTC de hace doce meses hasta
    /// la de dentro de veinticuatro. Cambia una vez por día.
    pub fn around(now: DateTime<Utc>) -> Self {
        let today = now.date_naive();
        let start = today
            .checked_sub_months(Months::new(12))
            .unwrap_or(today)
            .and_hms_opt(0, 0, 0)
            .expect("la medianoche existe");
        let end = today
            .checked_add_months(Months::new(24))
            .unwrap_or(today)
            .and_hms_opt(0, 0, 0)
            .expect("la medianoche existe");
        Self {
            start: Utc.from_utc_datetime(&start).timestamp(),
            end: Utc.from_utc_datetime(&end).timestamp(),
        }
    }

    fn encode(self) -> String {
        format!("{},{}", self.start, self.end)
    }

    fn decode(text: &str) -> Option<Self> {
        let (start, end) = text.split_once(',')?;
        let window = Self {
            start: start.parse().ok()?,
            end: end.parse().ok()?,
        };
        (window.start < window.end).then_some(window)
    }
}

/// Un calendario tal como está en la base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCalendar {
    pub id: i64,
    pub href: String,
    pub ctag: Option<String>,
}

/// Un calendario como lo listó el servidor, para darlo de alta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarListing {
    pub href: String,
    pub display_name: String,
    pub color: Option<String>,
    pub components: Vec<String>,
}

/// Cómo terminó la expansión de un objeto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpansionState {
    Complete,
    /// Pasó un tope: se guardaron las ocurrencias que entraron.
    Truncated,
    /// La regla no se entendió: quedaron la primera vez y las `RDATE`.
    Invalid,
}

impl ExpansionState {
    fn as_str(self) -> &'static str {
        match self {
            ExpansionState::Complete => "complete",
            ExpansionState::Truncated => "truncated",
            ExpansionState::Invalid => "invalid",
        }
    }
}

/// Lo que se deriva de un objeto para listarlo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectIndex {
    pub uid: String,
    /// `VEVENT`, `VTODO`, o vacío si no es ninguno de los dos.
    pub component: &'static str,
    pub summary: String,
    /// El comienzo; en una tarea, su `DTSTART` si tiene.
    pub starts_at: Option<i64>,
    /// El fin; en una tarea, **el vencimiento** (`DUE`).
    pub ends_at: Option<i64>,
    pub all_day: bool,
    pub recurring: bool,
    pub zone: ZoneKind,
    /// `STATUS` en minúsculas, o vacío.
    pub status: String,
    /// `PRIORITY` de 1 a 9; 0 —«sin definir»— es `None`.
    pub priority: Option<i64>,
    pub completed_at: Option<i64>,
    /// Si la tarea está hecha: `COMPLETED`, `STATUS:COMPLETED` o el cien por
    /// ciento.
    pub done: bool,
    /// Para ordenar las tareas: el vencimiento, y las que no tienen, al final.
    pub sort_key: i64,
    /// La vez más larga, en segundos.
    pub span: i64,
    pub expansion: ExpansionState,
    /// El rango que cubren las ocurrencias guardadas, si es una serie.
    pub expanded: Option<Window>,
}

/// Un objeto para guardar: el crudo, lo derivado y sus ocurrencias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRow {
    pub href: String,
    pub etag: Option<String>,
    pub raw_ical: String,
    pub index: ObjectIndex,
    pub occurrences: Vec<Occurrence>,
}

/// Lo que se hace con un objeto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectOp {
    Upsert(Box<ObjectRow>),
    Delete(String),
}

impl ObjectOp {
    /// Cuántas ocurrencias lleva.
    pub fn occurrences(&self) -> usize {
        match self {
            ObjectOp::Upsert(row) => row.occurrences.len(),
            ObjectOp::Delete(_) => 0,
        }
    }
}

/// Dónde quedó un calendario al terminar: va con el último lote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarProgress {
    pub token: Option<String>,
    pub ctag: Option<String>,
}

/// Cómo quedó un lote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalendarApplied {
    /// Escrito: cuánto cambiaron los bytes de iCalendar crudo y las
    /// ocurrencias de la cuenta.
    Written {
        net_bytes: i64,
        net_occurrences: i64,
    },
    /// No se escribió nada: la cuenta crecería más de lo que había lugar.
    OverCap,
    /// No se escribió nada: la ventana de la base ya no es con la que se
    /// expandió el lote.
    WindowMoved,
}

fn now_text() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn instant(date: Option<DateValue>, zones: &ical::timezones::Zones) -> Option<i64> {
    date.and_then(|d| d.resolve(zones))
        .map(|(moment, _)| moment.timestamp())
}

/// Deriva lo que se guarda de un objeto: lo que se lista y, si es un evento,
/// sus ocurrencias en la ventana. **Es CPU**: se llama fuera del bucle de
/// eventos.
///
/// Un recurso de CalDAV lleva un solo tipo de componente; si trae eventos y
/// tareas mezclados, vale el primero. Un evento **cancelado entero**
/// (`STATUS:CANCELLED` en la serie) se guarda sin ocurrencias: no ocupa lugar
/// en el día de nadie. Un recurso que no es ni evento ni tarea se guarda con lo
/// derivado vacío, para que su ETag no lo vuelva a pedir.
pub fn derive_object(raw: &str, window: Window, limits: &ExpansionLimits) -> ObjectIndex {
    derive_with_occurrences(raw, window, limits).0
}

/// Lo mismo que [`derive_object`], con las ocurrencias.
pub fn derive_with_occurrences(
    raw: &str,
    window: Window,
    limits: &ExpansionLimits,
) -> (ObjectIndex, Vec<Occurrence>) {
    let document = ical::parse_document(raw);
    let first = document
        .components
        .iter()
        .find(|c| c.name == "VEVENT" || c.name == "VTODO");
    match first.map(|c| c.name.as_str()) {
        Some("VEVENT") => derive_event(&document, window, limits),
        Some("VTODO") => (derive_task(first.expect("hay uno"), &document), Vec::new()),
        _ => (empty_index(), Vec::new()),
    }
}

fn empty_index() -> ObjectIndex {
    ObjectIndex {
        uid: String::new(),
        component: "",
        summary: String::new(),
        starts_at: None,
        ends_at: None,
        all_day: false,
        recurring: false,
        zone: ZoneKind::Utc,
        status: String::new(),
        priority: None,
        completed_at: None,
        done: false,
        sort_key: i64::MAX,
        span: 0,
        expansion: ExpansionState::Complete,
        expanded: None,
    }
}

fn status_of(component: &Component) -> String {
    component
        .value("STATUS")
        .map(|s| ical::visible(s, 32).to_ascii_lowercase())
        .unwrap_or_default()
}

fn derive_event(
    document: &ical::Document,
    window: Window,
    limits: &ExpansionLimits,
) -> (ObjectIndex, Vec<Occurrence>) {
    let Some(series) = EventSeries::from_document(document, limits) else {
        return (empty_index(), Vec::new());
    };
    // Lo que se lista sale de la serie, o de la primera excepción si el
    // recurso sólo trae excepciones.
    let uid = document
        .components
        .iter()
        .find(|c| c.name == "VEVENT")
        .and_then(|c| c.value("UID"))
        .unwrap_or("")
        .to_string();
    let head = document
        .components
        .iter()
        .filter(|c| c.name == "VEVENT" && c.value("UID").unwrap_or("") == uid)
        .min_by_key(|c| c.first("RECURRENCE-ID").is_some())
        .expect("la serie existe, así que hay un VEVENT");
    let event = ical::event_of(head, &document.zones);
    let cancelled = head.first("RECURRENCE-ID").is_none()
        && head
            .value("STATUS")
            .is_some_and(|s| s.eq_ignore_ascii_case("CANCELLED"));

    let recurring = series.is_recurring();
    let expansion = if cancelled {
        Default::default()
    } else {
        series.materialize(window.start, window.end, limits)
    };
    let state = if expansion.invalid_rule {
        ExpansionState::Invalid
    } else if expansion.truncated {
        ExpansionState::Truncated
    } else {
        ExpansionState::Complete
    };
    let span = expansion
        .occurrences
        .iter()
        .map(|o| o.end.saturating_sub(o.start))
        .chain([series.max_span()])
        .max()
        .unwrap_or(0)
        .max(0);
    let starts_at = event
        .as_ref()
        .and_then(|e| chrono::DateTime::parse_from_rfc3339(&e.start).ok())
        .map(|m| m.timestamp());
    let ends_at = event
        .as_ref()
        .and_then(|e| chrono::DateTime::parse_from_rfc3339(&e.end).ok())
        .map(|m| m.timestamp());
    let index = ObjectIndex {
        uid: ical::clipped(&uid, MAX_TEXT),
        component: "VEVENT",
        summary: event.as_ref().map(|e| e.title.clone()).unwrap_or_default(),
        starts_at,
        ends_at,
        all_day: event.as_ref().is_some_and(|e| e.all_day),
        recurring,
        zone: series.zone_kind(),
        status: status_of(head),
        priority: None,
        completed_at: None,
        done: false,
        sort_key: starts_at.unwrap_or(i64::MAX),
        span,
        expansion: state,
        expanded: recurring.then_some(window),
    };
    (index, expansion.occurrences)
}

fn derive_task(task: &Component, document: &ical::Document) -> ObjectIndex {
    let due = task.date("DUE");
    let start = task.date("DTSTART");
    let zone = due
        .as_ref()
        .or(start.as_ref())
        .map_or(ZoneKind::Utc, |d| d.zone(&document.zones).1);
    let all_day = due
        .as_ref()
        .or(start.as_ref())
        .is_some_and(DateValue::is_date);
    let ends_at = instant(due, &document.zones);
    let status = status_of(task);
    let completed_at = instant(task.date("COMPLETED"), &document.zones);
    let percent = task
        .value("PERCENT-COMPLETE")
        .and_then(|p| p.parse::<u32>().ok());
    ObjectIndex {
        uid: ical::clipped(task.value("UID").unwrap_or(""), MAX_TEXT),
        component: "VTODO",
        summary: task.text("SUMMARY", MAX_TEXT).unwrap_or_default(),
        starts_at: instant(start, &document.zones),
        ends_at,
        all_day,
        recurring: task.first("RRULE").is_some(),
        zone,
        done: status == "completed" || completed_at.is_some() || percent == Some(100),
        status,
        priority: task
            .value("PRIORITY")
            .and_then(|p| p.parse::<i64>().ok())
            .filter(|p| (1..=9).contains(p)),
        completed_at,
        sort_key: ends_at.unwrap_or(i64::MAX),
        span: 0,
        expansion: ExpansionState::Complete,
        expanded: None,
    }
}

/// Una serie que hay que volver a expandir porque la ventana se corrió.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleSeries {
    pub id: i64,
    pub calendar_id: i64,
    pub raw_ical: String,
    /// El rango que cubren hoy sus ocurrencias guardadas.
    pub expanded: Option<Window>,
    pub truncated: bool,
}

/// Lo que se escribe de una serie al correr la ventana.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeriesShift {
    pub id: i64,
    pub calendar_id: i64,
    /// El rango que se esperaba encontrar: si el objeto cambió mientras se
    /// expandía —lo reescribió la sincronización—, no se toca.
    pub expected: Option<Window>,
    /// Si se reemplazan todas sus ocurrencias; si no, se borran sólo las que
    /// quedaron fuera de la ventana nueva.
    pub replace_all: bool,
    pub added: Vec<Occurrence>,
    pub expansion: ExpansionState,
    pub span: i64,
}

/// Lo que hay que escribir de una serie para la ventana nueva: todo, si nunca
/// se expandió, si quedó recortada o si la ventana vieja no toca la nueva; si
/// no, sólo lo que entró.
pub fn shift_series(stale: &StaleSeries, target: Window, limits: &ExpansionLimits) -> SeriesShift {
    let document = ical::parse_document(&stale.raw_ical);
    let series = EventSeries::from_document(&document, limits);
    let full = |series: &EventSeries| series.materialize(target.start, target.end, limits);
    let (replace_all, occurrences, truncated, invalid) = match (&series, stale.expanded) {
        (None, _) => (true, Vec::new(), false, false),
        (Some(series), Some(old))
            if !stale.truncated && old.start < target.end && target.start < old.end =>
        {
            let mut added = Vec::new();
            let mut truncated = false;
            let mut invalid = false;
            for (from, to) in [
                (target.start, old.start.min(target.end)),
                (old.end.max(target.start), target.end),
            ] {
                if from < to {
                    let part = series.materialize(from, to, limits);
                    truncated |= part.truncated;
                    invalid |= part.invalid_rule;
                    added.extend(part.occurrences);
                }
            }
            (false, added, truncated, invalid)
        }
        (Some(series), _) => {
            let expansion = full(series);
            (
                true,
                expansion.occurrences,
                expansion.truncated,
                expansion.invalid_rule,
            )
        }
    };
    let span = occurrences
        .iter()
        .map(|o| o.end.saturating_sub(o.start))
        .chain(series.as_ref().map(EventSeries::max_span))
        .max()
        .unwrap_or(0)
        .max(0);
    SeriesShift {
        id: stale.id,
        calendar_id: stale.calendar_id,
        expected: stale.expanded,
        replace_all,
        added: occurrences,
        expansion: if invalid {
            ExpansionState::Invalid
        } else if truncated {
            ExpansionState::Truncated
        } else {
            ExpansionState::Complete
        },
        span,
    }
}

impl Store {
    /// Los calendarios guardados.
    pub fn calendars(&self) -> Result<Vec<StoredCalendar>, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT id, href, ctag FROM calendars ORDER BY id")
            .map_err(classify)?;
        let rows = statement
            .query_map([], |row| {
                Ok(StoredCalendar {
                    id: row.get(0)?,
                    href: row.get(1)?,
                    ctag: row.get(2)?,
                })
            })
            .map_err(classify)?;
        rows.collect::<Result<_, _>>().map_err(classify)
    }

    /// Da de alta los calendarios que listó el servidor, o les actualiza el
    /// nombre, el color y los componentes. No toca el `getctag`, que cambia
    /// recién al terminar cada uno. No borra los que faltan: eso va por
    /// [`Self::remove_calendar_chunk`].
    pub fn upsert_calendars(
        &mut self,
        calendars: &[CalendarListing],
    ) -> Result<Vec<StoredCalendar>, StoreError> {
        let transaction = self.connection.transaction().map_err(classify)?;
        let mut stored = Vec::with_capacity(calendars.len());
        let mut changed = false;
        {
            let mut current = transaction
                .prepare_cached(
                    "SELECT display_name, color, components FROM calendars WHERE href = ?1",
                )
                .map_err(classify)?;
            let mut upsert = transaction
                .prepare_cached(
                    "INSERT INTO calendars (href, display_name, color, components, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT (href) DO UPDATE SET
                       display_name = excluded.display_name, color = excluded.color,
                       components = excluded.components
                     RETURNING id, href, ctag",
                )
                .map_err(classify)?;
            for calendar in calendars {
                let components = calendar.components.join(",");
                let before: Option<(String, Option<String>, String)> = current
                    .query_row([&calendar.href], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                    })
                    .optional()
                    .map_err(classify)?;
                changed |= before
                    != Some((
                        calendar.display_name.clone(),
                        calendar.color.clone(),
                        components.clone(),
                    ));
                stored.push(
                    upsert
                        .query_row(
                            rusqlite::params![
                                calendar.href,
                                calendar.display_name,
                                calendar.color,
                                components,
                                now_text()
                            ],
                            |row| {
                                Ok(StoredCalendar {
                                    id: row.get(0)?,
                                    href: row.get(1)?,
                                    ctag: row.get(2)?,
                                })
                            },
                        )
                        .map_err(classify)?,
                );
            }
        }
        let generation = if changed {
            Some(bump_generation(&transaction, CALENDAR_AREA)?)
        } else {
            None
        };
        transaction.commit().map_err(classify)?;
        if let Some(generation) = generation {
            self.note_change(CALENDAR_AREA, generation);
        }
        Ok(stored)
    }

    /// Borra una tanda de los objetos de un calendario que ya no está —con sus
    /// ocurrencias y recordatorios, por la cascada— y el calendario mismo
    /// cuando no le queda ninguno. Devuelve cuántos objetos se borraron: se
    /// llama hasta que devuelve cero.
    pub fn remove_calendar_chunk(&mut self, calendar_id: i64) -> Result<usize, StoreError> {
        let transaction = self.connection.transaction().map_err(classify)?;
        let removed = transaction
            .execute(
                "DELETE FROM calendar_objects WHERE id IN
                   (SELECT id FROM calendar_objects WHERE calendar_id = ?1 LIMIT ?2)",
                rusqlite::params![calendar_id, WRITE_BATCH_ROWS as i64],
            )
            .map_err(classify)?;
        let mut changed = removed > 0;
        if removed == 0 {
            changed |= transaction
                .execute("DELETE FROM calendars WHERE id = ?1", [calendar_id])
                .map_err(classify)?
                > 0;
        }
        let generation = if changed {
            Some(bump_generation(&transaction, CALENDAR_AREA)?)
        } else {
            None
        };
        transaction.commit().map_err(classify)?;
        if let Some(generation) = generation {
            self.note_change(CALENDAR_AREA, generation);
        }
        Ok(removed)
    }

    /// El `sync-token` guardado de un calendario.
    pub fn calendar_sync_token(&self, href: &str) -> Result<Option<String>, StoreError> {
        self.connection
            .query_row(
                "SELECT token FROM sync_state WHERE area = 'calendar' AND collection = ?1",
                [href],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map(Option::flatten)
            .map_err(classify)
    }

    /// El ETag de cada objeto guardado de un calendario, por dirección.
    pub fn calendar_object_etags(
        &self,
        calendar_id: i64,
    ) -> Result<HashMap<String, Option<String>>, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT href, etag FROM calendar_objects WHERE calendar_id = ?1")
            .map_err(classify)?;
        let rows = statement
            .query_map([calendar_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(classify)?;
        rows.collect::<Result<_, _>>().map_err(classify)
    }

    /// Cuántos bytes ocupa el iCalendar crudo de toda la cuenta.
    pub fn calendar_raw_bytes(&self) -> Result<u64, StoreError> {
        self.connection
            .query_row(
                "SELECT coalesce(sum(octet_length(raw_ical)), 0) FROM calendar_objects",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map(|bytes| bytes.max(0) as u64)
            .map_err(classify)
    }

    /// Cuántas ocurrencias hay guardadas en la cuenta.
    pub fn occurrence_count(&self) -> Result<u64, StoreError> {
        self.connection
            .query_row("SELECT count(*) FROM occurrences", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|count| count.max(0) as u64)
            .map_err(classify)
    }

    /// La ventana de la base, si ya se escribió algo del calendario.
    pub fn calendar_window(&self) -> Result<Option<Window>, StoreError> {
        read_window(&self.connection)
    }

    /// Escribe un lote en **una** transacción, y con el último, dónde quedó el
    /// calendario. Como `apply_contacts`: el calendario tiene que estar en esta
    /// base con el mismo `id` y dirección (si no, `Err(Missing)`), un objeto
    /// que ya estaba se reescribe en su lugar —mismo `id`—, y el lote se mide
    /// contra lo que le queda a la cuenta: `room_bytes` de iCalendar crudo y
    /// `room_occurrences` de ocurrencias, por el cambio neto.
    ///
    /// **La ventana**: si la base no tiene, queda `window`, la del lote; si
    /// tiene otra, no se escribe nada ([`CalendarApplied::WindowMoved`]).
    pub fn apply_calendar_objects(
        &mut self,
        calendar: &StoredCalendar,
        ops: &[ObjectOp],
        window: Window,
        finish: Option<&CalendarProgress>,
        room_bytes: u64,
        room_occurrences: u64,
    ) -> Result<CalendarApplied, StoreError> {
        if ops.len() > WRITE_BATCH_ROWS {
            return Err(StoreError::Sqlite(format!(
                "un lote de {} objetos pasa el tope de {WRITE_BATCH_ROWS}",
                ops.len()
            )));
        }
        let transaction = self.connection.transaction().map_err(classify)?;
        let exists: bool = transaction
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM calendars WHERE id = ?1 AND href = ?2)",
                rusqlite::params![calendar.id, calendar.href],
                |row| row.get(0),
            )
            .map_err(classify)?;
        if !exists {
            return Err(StoreError::Missing);
        }
        match read_window(&transaction)? {
            Some(stored) if stored != window => return Ok(CalendarApplied::WindowMoved),
            Some(_) => {}
            None => write_window(&transaction, window)?,
        }

        let at = now_text();
        let mut net_bytes: i64 = 0;
        let mut net_occurrences: i64 = 0;
        let mut changed = false;
        for op in ops {
            match op {
                ObjectOp::Delete(href) => {
                    let gone: Option<(i64, i64)> = transaction
                        .prepare_cached(
                            "SELECT id, octet_length(raw_ical) FROM calendar_objects
                              WHERE calendar_id = ?1 AND href = ?2",
                        )
                        .and_then(|mut s| {
                            s.query_row(rusqlite::params![calendar.id, href], |r| {
                                Ok((r.get(0)?, r.get(1)?))
                            })
                            .optional()
                        })
                        .map_err(classify)?;
                    if let Some((id, bytes)) = gone {
                        net_occurrences -= occurrences_of(&transaction, id)?;
                        transaction
                            .prepare_cached("DELETE FROM calendar_objects WHERE id = ?1")
                            .and_then(|mut s| s.execute([id]))
                            .map_err(classify)?;
                        net_bytes -= bytes;
                        changed = true;
                    }
                }
                ObjectOp::Upsert(row) => {
                    let before: Option<(i64, i64)> = transaction
                        .prepare_cached(
                            "SELECT id, octet_length(raw_ical) FROM calendar_objects
                              WHERE calendar_id = ?1 AND href = ?2",
                        )
                        .and_then(|mut s| {
                            s.query_row(rusqlite::params![calendar.id, row.href], |r| {
                                Ok((r.get(0)?, r.get(1)?))
                            })
                            .optional()
                        })
                        .map_err(classify)?;
                    if let Some((id, bytes)) = before {
                        net_bytes -= bytes;
                        net_occurrences -= occurrences_of(&transaction, id)?;
                    }
                    net_bytes += row.raw_ical.len() as i64;
                    net_occurrences += row.occurrences.len() as i64;
                    upsert_object(&transaction, calendar.id, row, &at)?;
                    changed = true;
                }
            }
        }
        if (net_bytes > 0 && net_bytes as u64 > room_bytes)
            || (net_occurrences > 0 && net_occurrences as u64 > room_occurrences)
        {
            // Sin `commit`: al soltarse, la transacción se deshace entera.
            return Ok(CalendarApplied::OverCap);
        }

        if let Some(finish) = finish {
            match &finish.token {
                Some(token) => transaction.execute(
                    "INSERT INTO sync_state (area, collection, token, updated_at)
                     VALUES ('calendar', ?1, ?2, ?3)
                     ON CONFLICT (area, collection) DO UPDATE SET
                       token = excluded.token, updated_at = excluded.updated_at",
                    rusqlite::params![calendar.href, token, at],
                ),
                None => transaction.execute(
                    "DELETE FROM sync_state WHERE area = 'calendar' AND collection = ?1",
                    [&calendar.href],
                ),
            }
            .map_err(classify)?;
            transaction
                .execute(
                    "UPDATE calendars SET ctag = ?1, updated_at = ?2 WHERE id = ?3",
                    rusqlite::params![finish.ctag, at, calendar.id],
                )
                .map_err(classify)?;
        }

        let generation = if changed {
            Some(bump_generation(&transaction, CALENDAR_AREA)?)
        } else {
            None
        };
        transaction.commit().map_err(classify)?;
        if let Some(generation) = generation {
            self.note_change(CALENDAR_AREA, generation);
        }
        Ok(CalendarApplied::Written {
            net_bytes,
            net_occurrences,
        })
    }

    /// Las series cuyas ocurrencias guardadas no cubren `target`: las que hay
    /// que volver a expandir al correr la ventana. De a `limit`, por `id`,
    /// después de `after`.
    pub fn stale_series(
        &self,
        target: Window,
        after: i64,
        limit: usize,
    ) -> Result<Vec<StaleSeries>, StoreError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, calendar_id, raw_ical, expanded_from, expanded_to, expansion
                   FROM calendar_objects
                  WHERE recurring = 1 AND component = 'VEVENT' AND id > ?1
                    AND (expanded_from IS NOT ?2 OR expanded_to IS NOT ?3)
                  ORDER BY id LIMIT ?4",
            )
            .map_err(classify)?;
        let rows = statement
            .query_map(
                rusqlite::params![after, target.start, target.end, limit as i64],
                |row| {
                    let from: Option<i64> = row.get(3)?;
                    let to: Option<i64> = row.get(4)?;
                    Ok(StaleSeries {
                        id: row.get(0)?,
                        calendar_id: row.get(1)?,
                        raw_ical: row.get(2)?,
                        expanded: from.zip(to).map(|(start, end)| Window { start, end }),
                        truncated: row.get::<_, String>(5)? == "truncated",
                    })
                },
            )
            .map_err(classify)?;
        rows.collect::<Result<_, _>>().map_err(classify)
    }

    /// Escribe un lote de series con la ventana `target` y, con `last`, deja
    /// esa ventana en la base. Devuelve cuántas ocurrencias sumó (o restó) a la
    /// cuenta, u `OverCap` sin escribir nada si no entran en `room`.
    ///
    /// Una serie que no está como se la leyó —la reescribió la sincronización,
    /// o se borró— no se toca. Sube la generación sólo si cambió alguna fila.
    pub fn apply_window_shift(
        &mut self,
        target: Window,
        shifts: &[SeriesShift],
        last: bool,
        room: u64,
        limits: &ExpansionLimits,
    ) -> Result<CalendarApplied, StoreError> {
        let transaction = self.connection.transaction().map_err(classify)?;
        let mut net: i64 = 0;
        let mut changed = false;
        for shift in shifts {
            let current: Option<(Option<i64>, Option<i64>)> = transaction
                .prepare_cached(
                    "SELECT expanded_from, expanded_to FROM calendar_objects
                      WHERE id = ?1 AND recurring = 1",
                )
                .and_then(|mut s| {
                    s.query_row([shift.id], |r| Ok((r.get(0)?, r.get(1)?)))
                        .optional()
                })
                .map_err(classify)?;
            let expected = shift.expected.map(|w| (Some(w.start), Some(w.end)));
            if current.is_none() || current != Some(expected.unwrap_or((None, None))) {
                continue;
            }
            let removed = if shift.replace_all {
                transaction
                    .prepare_cached("DELETE FROM occurrences WHERE object_id = ?1")
                    .and_then(|mut s| s.execute([shift.id]))
            } else {
                transaction
                    .prepare_cached(
                        "DELETE FROM occurrences WHERE object_id = ?1
                            AND (starts_at < ?2 OR starts_at >= ?3)",
                    )
                    .and_then(|mut s| {
                        s.execute(rusqlite::params![shift.id, target.start, target.end])
                    })
            }
            .map_err(classify)?;
            net -= removed as i64;
            changed |= removed > 0;
            // Lo que quedó de antes más lo nuevo no pasa el tope por objeto:
            // lo que sobra no entra, y la serie queda recortada.
            let kept = occurrences_of(&transaction, shift.id)? as usize;
            let room_here = limits.max_occurrences.saturating_sub(kept);
            let expansion = if shift.added.len() > room_here {
                ExpansionState::Truncated
            } else {
                shift.expansion
            };
            for occurrence in shift.added.iter().take(room_here) {
                insert_occurrence(&transaction, shift.id, shift.calendar_id, occurrence)?;
                net += 1;
                changed = true;
            }
            transaction
                .prepare_cached(
                    "UPDATE calendar_objects SET expanded_from = ?2, expanded_to = ?3,
                            expansion = ?4, span = max(span, ?5)
                      WHERE id = ?1",
                )
                .and_then(|mut s| {
                    s.execute(rusqlite::params![
                        shift.id,
                        target.start,
                        target.end,
                        expansion.as_str(),
                        shift.span
                    ])
                })
                .map_err(classify)?;
        }
        if net > 0 && net as u64 > room {
            return Ok(CalendarApplied::OverCap);
        }
        if last {
            write_window(&transaction, target)?;
        }
        let generation = if changed {
            Some(bump_generation(&transaction, CALENDAR_AREA)?)
        } else {
            None
        };
        transaction.commit().map_err(classify)?;
        if let Some(generation) = generation {
            self.note_change(CALENDAR_AREA, generation);
        }
        Ok(CalendarApplied::Written {
            net_bytes: 0,
            net_occurrences: net,
        })
    }
}

fn read_window(connection: &rusqlite::Connection) -> Result<Option<Window>, StoreError> {
    let value: Option<String> = connection
        .query_row(
            "SELECT value FROM store_meta WHERE key = ?1",
            [WINDOW_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(classify)?;
    Ok(value.as_deref().and_then(Window::decode))
}

fn write_window(connection: &rusqlite::Connection, window: Window) -> Result<(), StoreError> {
    connection
        .execute(
            "INSERT INTO store_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            rusqlite::params![WINDOW_KEY, window.encode()],
        )
        .map(|_| ())
        .map_err(classify)
}

fn occurrences_of(transaction: &rusqlite::Transaction<'_>, id: i64) -> Result<i64, StoreError> {
    transaction
        .prepare_cached("SELECT count(*) FROM occurrences WHERE object_id = ?1")
        .and_then(|mut s| s.query_row([id], |r| r.get(0)))
        .map_err(classify)
}

fn insert_occurrence(
    transaction: &rusqlite::Transaction<'_>,
    object_id: i64,
    calendar_id: i64,
    occurrence: &Occurrence,
) -> Result<(), StoreError> {
    transaction
        .prepare_cached(
            "INSERT INTO occurrences
               (object_id, recurrence_id, calendar_id, starts_at, ends_at, all_day, summary)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (object_id, recurrence_id) DO NOTHING",
        )
        .and_then(|mut s| {
            s.execute(rusqlite::params![
                object_id,
                occurrence.recurrence_id,
                calendar_id,
                occurrence.start,
                occurrence.end,
                occurrence.all_day,
                occurrence.summary
            ])
        })
        .map_err(classify)?;
    for alarm in &occurrence.alarms {
        transaction
            .prepare_cached(
                "INSERT INTO alarms (object_id, recurrence_id, position, fires_at, action)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (object_id, recurrence_id, position) DO NOTHING",
            )
            .and_then(|mut s| {
                s.execute(rusqlite::params![
                    object_id,
                    occurrence.recurrence_id,
                    alarm.position,
                    alarm.at,
                    alarm.action
                ])
            })
            .map_err(classify)?;
    }
    Ok(())
}

fn upsert_object(
    transaction: &rusqlite::Transaction<'_>,
    calendar_id: i64,
    row: &ObjectRow,
    at: &str,
) -> Result<(), StoreError> {
    let index = &row.index;
    let id: i64 = transaction
        .prepare_cached(
            "INSERT INTO calendar_objects
               (calendar_id, href, etag, uid, component, summary, starts_at, ends_at, all_day,
                recurring, zone, status, priority, completed_at, done, sort_key, span,
                expansion, expanded_from, expanded_to, raw_ical, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                     ?17, ?18, ?19, ?20, ?21, ?22)
             ON CONFLICT (calendar_id, href) DO UPDATE SET
               etag = excluded.etag, uid = excluded.uid, component = excluded.component,
               summary = excluded.summary, starts_at = excluded.starts_at,
               ends_at = excluded.ends_at, all_day = excluded.all_day,
               recurring = excluded.recurring, zone = excluded.zone, status = excluded.status,
               priority = excluded.priority, completed_at = excluded.completed_at,
               done = excluded.done, sort_key = excluded.sort_key, span = excluded.span,
               expansion = excluded.expansion, expanded_from = excluded.expanded_from,
               expanded_to = excluded.expanded_to, raw_ical = excluded.raw_ical,
               updated_at = excluded.updated_at
             RETURNING id",
        )
        .and_then(|mut s| {
            s.query_row(
                rusqlite::params![
                    calendar_id,
                    row.href,
                    row.etag,
                    index.uid,
                    index.component,
                    index.summary,
                    index.starts_at,
                    index.ends_at,
                    index.all_day,
                    index.recurring,
                    index.zone.as_str(),
                    index.status,
                    index.priority,
                    index.completed_at,
                    index.done,
                    index.sort_key,
                    index.span,
                    index.expansion.as_str(),
                    index.expanded.map(|w| w.start),
                    index.expanded.map(|w| w.end),
                    row.raw_ical,
                    at
                ],
                |r| r.get(0),
            )
        })
        .map_err(classify)?;
    // Las ocurrencias de antes se van —con sus recordatorios, por la cascada—
    // y se escriben las de ahora.
    transaction
        .prepare_cached("DELETE FROM occurrences WHERE object_id = ?1")
        .and_then(|mut s| s.execute([id]))
        .map_err(classify)?;
    for occurrence in &row.occurrences {
        insert_occurrence(transaction, id, calendar_id, occurrence)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::contacts::tests::open_store;
    use super::super::paths::tests::TempDir;
    use super::*;

    pub(crate) fn at(text: &str) -> i64 {
        chrono::DateTime::parse_from_rfc3339(text)
            .unwrap()
            .timestamp()
    }

    /// La ventana del 26 de septiembre de 2026.
    pub(crate) fn window() -> Window {
        Window::around(Utc.with_ymd_and_hms(2026, 9, 26, 15, 0, 0).unwrap())
    }

    pub(crate) fn object(href: &str, raw: &str, window: Window) -> Box<ObjectRow> {
        let (index, occurrences) = derive_with_occurrences(raw, window, &ExpansionLimits::DEFAULT);
        Box::new(ObjectRow {
            href: href.into(),
            etag: Some("\"1\"".into()),
            raw_ical: raw.into(),
            index,
            occurrences,
        })
    }

    pub(crate) fn weekly(uid: &str, start: &str) -> String {
        format!(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nSUMMARY:Semanal {uid}\r\n\
             DTSTART:{start}\r\nDURATION:PT1H\r\nRRULE:FREQ=WEEKLY\r\n\
             BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT10M\r\nEND:VALARM\r\n\
             END:VEVENT\r\nEND:VCALENDAR\r\n"
        )
    }

    pub(crate) fn calendar(store: &mut Store, href: &str) -> StoredCalendar {
        store
            .upsert_calendars(&[CalendarListing {
                href: href.into(),
                display_name: "Personal".into(),
                color: Some("#FF0000".into()),
                components: vec!["VEVENT".into(), "VTODO".into()],
            }])
            .unwrap()
            .into_iter()
            .find(|c| c.href == href)
            .unwrap()
    }

    fn count(store: &Store, sql: &str) -> i64 {
        store
            .connection()
            .query_row(sql, [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn la_ventana_va_de_doce_meses_atras_a_veinticuatro_adelante() {
        let w = window();
        assert_eq!(crate::ical::rfc3339(w.start), "2025-09-26T00:00:00+00:00");
        assert_eq!(crate::ical::rfc3339(w.end), "2028-09-26T00:00:00+00:00");
        // Todo el día de hoy da la misma.
        assert_eq!(
            Window::around(Utc.with_ymd_and_hms(2026, 9, 26, 0, 0, 1).unwrap()),
            w
        );
        assert_eq!(Window::decode(&w.encode()), Some(w));
        assert_eq!(Window::decode("9,1"), None);
        assert_eq!(Window::decode("basura"), None);
    }

    /// Una serie se guarda con sus ocurrencias **en la ventana**, cada una con
    /// su recordatorio; un evento suelto de hace diez años, entero.
    #[test]
    fn una_serie_se_guarda_expandida_en_la_ventana() {
        let temp = TempDir::new("cal-serie");
        let mut store = open_store(&temp);
        let cal = calendar(&mut store, "https://x/c/");
        let w = window();
        let old = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:viejo\r\nSUMMARY:Viejo\r\n\
                   DTSTART:20160101T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let applied = store
            .apply_calendar_objects(
                &cal,
                &[
                    ObjectOp::Upsert(object(
                        "https://x/c/s.ics",
                        &weekly("s", "20200106T090000Z"),
                        w,
                    )),
                    ObjectOp::Upsert(object("https://x/c/v.ics", old, w)),
                ],
                w,
                None,
                u64::MAX,
                u64::MAX,
            )
            .unwrap();
        let weeks = count(
            &store,
            "SELECT count(*) FROM occurrences WHERE object_id = 1",
        );
        assert!((156..=158).contains(&weeks), "{weeks} semanas en tres años");
        assert_eq!(
            applied,
            CalendarApplied::Written {
                net_bytes: (weekly("s", "20200106T090000Z").len() + old.len()) as i64,
                net_occurrences: weeks + 1
            }
        );
        let (from, to): (i64, i64) = store
            .connection()
            .query_row(
                "SELECT min(starts_at), max(starts_at) FROM occurrences WHERE object_id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(from >= w.start && to < w.end);
        assert_eq!(count(&store, "SELECT count(*) FROM alarms"), weeks);
        assert_eq!(
            count(
                &store,
                "SELECT count(*) FROM occurrences WHERE object_id = 2"
            ),
            1,
            "el suelto se guarda aunque esté fuera de la ventana"
        );
        assert_eq!(store.calendar_window().unwrap(), Some(w));
    }

    /// Reescribir un objeto lo reemplaza en su lugar —mismo `id`— y sus
    /// ocurrencias de antes se van con sus recordatorios.
    #[test]
    fn reescribir_un_objeto_reemplaza_sus_ocurrencias() {
        let temp = TempDir::new("cal-reescribir");
        let mut store = open_store(&temp);
        let cal = calendar(&mut store, "https://x/c/");
        let w = window();
        let href = "https://x/c/s.ics";
        store
            .apply_calendar_objects(
                &cal,
                &[ObjectOp::Upsert(object(
                    href,
                    &weekly("s", "20260105T090000Z"),
                    w,
                ))],
                w,
                None,
                u64::MAX,
                u64::MAX,
            )
            .unwrap();
        let single = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:s\r\nSUMMARY:Una vez\r\n\
                      DTSTART:20261001T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        store
            .apply_calendar_objects(
                &cal,
                &[ObjectOp::Upsert(object(href, single, w))],
                w,
                None,
                u64::MAX,
                u64::MAX,
            )
            .unwrap();
        assert_eq!(count(&store, "SELECT count(*) FROM calendar_objects"), 1);
        assert_eq!(count(&store, "SELECT max(id) FROM calendar_objects"), 1);
        assert_eq!(count(&store, "SELECT count(*) FROM occurrences"), 1);
        assert_eq!(count(&store, "SELECT count(*) FROM alarms"), 0);

        store
            .apply_calendar_objects(
                &cal,
                &[ObjectOp::Delete(href.into())],
                w,
                None,
                u64::MAX,
                u64::MAX,
            )
            .unwrap();
        assert_eq!(count(&store, "SELECT count(*) FROM occurrences"), 0);
    }

    /// Un lote que se expandió con otra ventana no escribe nada; uno que pasa
    /// el tope de ocurrencias de la cuenta, tampoco.
    #[test]
    fn un_lote_con_otra_ventana_o_sin_lugar_no_escribe_nada() {
        let temp = TempDir::new("cal-ventana-lote");
        let mut store = open_store(&temp);
        let cal = calendar(&mut store, "https://x/c/");
        let w = window();
        let other = Window {
            start: w.start + 86_400,
            end: w.end + 86_400,
        };
        store
            .apply_calendar_objects(&cal, &[], w, None, u64::MAX, u64::MAX)
            .unwrap();
        let row = ObjectOp::Upsert(object(
            "https://x/c/s.ics",
            &weekly("s", "20260105T090000Z"),
            other,
        ));
        assert_eq!(
            store
                .apply_calendar_objects(
                    &cal,
                    std::slice::from_ref(&row),
                    other,
                    None,
                    u64::MAX,
                    u64::MAX
                )
                .unwrap(),
            CalendarApplied::WindowMoved
        );
        assert_eq!(
            store
                .apply_calendar_objects(&cal, &[row], w, None, u64::MAX, 10)
                .unwrap(),
            CalendarApplied::OverCap
        );
        assert_eq!(count(&store, "SELECT count(*) FROM calendar_objects"), 0);
    }

    /// Una tarea: el vencimiento, el estado, la prioridad y si está hecha.
    #[test]
    fn una_tarea_se_deriva_con_su_vencimiento_y_su_estado() {
        let raw = "BEGIN:VCALENDAR\r\nBEGIN:VTODO\r\nUID:t\r\nSUMMARY:Comprar pan\r\n\
                   DUE;VALUE=DATE:20261001\r\nSTATUS:COMPLETED\r\nPRIORITY:1\r\n\
                   COMPLETED:20260925T100000Z\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";
        let index = derive_object(raw, window(), &ExpansionLimits::DEFAULT);
        assert_eq!(index.component, "VTODO");
        assert_eq!(index.summary, "Comprar pan");
        assert_eq!(index.ends_at, Some(at("2026-10-01T00:00:00Z")));
        assert!(index.all_day);
        assert_eq!(index.status, "completed");
        assert!(index.done);
        assert_eq!(index.priority, Some(1));
        assert_eq!(index.completed_at, Some(at("2026-09-25T10:00:00Z")));

        let open = "BEGIN:VCALENDAR\r\nBEGIN:VTODO\r\nUID:t\r\nSUMMARY:Algún día\r\n\
                    PRIORITY:0\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";
        let index = derive_object(open, window(), &ExpansionLimits::DEFAULT);
        assert_eq!(index.ends_at, None);
        assert_eq!(index.sort_key, i64::MAX, "sin vencimiento, al final");
        assert_eq!(index.priority, None);
        assert!(!index.done);
    }

    /// Un evento cancelado entero no ocupa ningún día, y un recurso que no es
    /// ni evento ni tarea se guarda vacío.
    #[test]
    fn un_evento_cancelado_no_tiene_ocurrencias() {
        let raw =
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:c\r\nSUMMARY:No va\r\nSTATUS:CANCELLED\r\n\
                   DTSTART:20261001T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let (index, occurrences) =
            derive_with_occurrences(raw, window(), &ExpansionLimits::DEFAULT);
        assert_eq!(index.status, "cancelled");
        assert!(occurrences.is_empty());

        let journal =
            "BEGIN:VCALENDAR\r\nBEGIN:VJOURNAL\r\nUID:j\r\nEND:VJOURNAL\r\nEND:VCALENDAR\r\n";
        assert_eq!(
            derive_object(journal, window(), &ExpansionLimits::DEFAULT).component,
            ""
        );
    }

    /// **La ventana que se corre**, en la base: diez días después, las
    /// ocurrencias de antes del nuevo comienzo se van, las nuevas del final
    /// entran, y la ventana de la base es la nueva. Sin volver a la red: sale
    /// de `raw_ical`.
    #[test]
    fn correr_la_ventana_saca_lo_viejo_y_suma_lo_nuevo() {
        let temp = TempDir::new("cal-correr");
        let mut store = open_store(&temp);
        let cal = calendar(&mut store, "https://x/c/");
        let w = window();
        let daily = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:d\r\nSUMMARY:Diario\r\n\
                     DTSTART:20200101T120000Z\r\nRRULE:FREQ=DAILY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        store
            .apply_calendar_objects(
                &cal,
                &[ObjectOp::Upsert(object("https://x/c/d.ics", daily, w))],
                w,
                None,
                u64::MAX,
                u64::MAX,
            )
            .unwrap();
        let before = count(&store, "SELECT count(*) FROM occurrences");
        store.take_changes();

        let later = Window::around(Utc.with_ymd_and_hms(2026, 10, 6, 15, 0, 0).unwrap());
        let stale = store.stale_series(later, 0, SHIFT_BATCH_ROWS).unwrap();
        assert_eq!(stale.len(), 1);
        let shifts: Vec<SeriesShift> = stale
            .iter()
            .map(|s| shift_series(s, later, &ExpansionLimits::DEFAULT))
            .collect();
        assert!(!shifts[0].replace_all);
        assert_eq!(shifts[0].added.len(), 10);
        store
            .apply_window_shift(later, &shifts, true, u64::MAX, &ExpansionLimits::DEFAULT)
            .unwrap();

        assert_eq!(count(&store, "SELECT count(*) FROM occurrences"), before);
        let (first, last): (i64, i64) = store
            .connection()
            .query_row(
                "SELECT min(starts_at), max(starts_at) FROM occurrences",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(first, at("2025-10-06T12:00:00Z"));
        assert_eq!(last, at("2028-10-05T12:00:00Z"));
        assert_eq!(store.calendar_window().unwrap(), Some(later));
        assert_eq!(store.take_changes().len(), 1, "cambió lo que se ve");
        assert!(store.stale_series(later, 0, 10).unwrap().is_empty());

        // Correrla otra vez a la misma no cambia nada.
        store
            .apply_window_shift(later, &[], true, u64::MAX, &ExpansionLimits::DEFAULT)
            .unwrap();
        assert!(store.take_changes().is_empty());
    }

    /// Una serie que se reescribió mientras se expandía no se toca: la
    /// sincronización ya la dejó con la ventana nueva.
    #[test]
    fn correr_la_ventana_no_pisa_una_serie_que_cambio() {
        let temp = TempDir::new("cal-correr-cambio");
        let mut store = open_store(&temp);
        let cal = calendar(&mut store, "https://x/c/");
        let w = window();
        let href = "https://x/c/s.ics";
        store
            .apply_calendar_objects(
                &cal,
                &[ObjectOp::Upsert(object(
                    href,
                    &weekly("s", "20260105T090000Z"),
                    w,
                ))],
                w,
                None,
                u64::MAX,
                u64::MAX,
            )
            .unwrap();
        let later = Window {
            start: w.start + 7 * 86_400,
            end: w.end + 7 * 86_400,
        };
        let stale = store.stale_series(later, 0, 10).unwrap();
        let shifts: Vec<SeriesShift> = stale
            .iter()
            .map(|s| shift_series(s, later, &ExpansionLimits::DEFAULT))
            .collect();
        // En el medio, la sincronización la reescribe con la ventana nueva.
        store
            .connection
            .execute(
                "UPDATE store_meta SET value = ?1 WHERE key = ?2",
                rusqlite::params![later.encode(), WINDOW_KEY],
            )
            .unwrap();
        store
            .apply_calendar_objects(
                &cal,
                &[ObjectOp::Upsert(object(
                    href,
                    &weekly("s", "20260105T090000Z"),
                    later,
                ))],
                later,
                None,
                u64::MAX,
                u64::MAX,
            )
            .unwrap();
        let before = count(&store, "SELECT count(*) FROM occurrences");
        store
            .apply_window_shift(later, &shifts, true, u64::MAX, &ExpansionLimits::DEFAULT)
            .unwrap();
        assert_eq!(count(&store, "SELECT count(*) FROM occurrences"), before);
    }
}
