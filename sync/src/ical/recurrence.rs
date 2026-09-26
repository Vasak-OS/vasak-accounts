//! Las repeticiones de un evento: de una serie a las veces que ocurre.
//!
//! `vasak-calendar` no las expandía —mostraba una reunión semanal una sola vez,
//! el día que empezaba—. Acá se expanden, con `rrule` para la regla y lo demás
//! a mano: `RDATE`, `EXDATE`, las excepciones (`RECURRENCE-ID`, también con
//! `RANGE=THISANDFUTURE`), `DTEND` o `DURATION`, todo el día, hora flotante y
//! las zonas de [`super::timezones`].
//!
//! ── En qué reloj se repite ──────────────────────────────────────────────────
//!
//! **En el de pared de la zona del evento, y recién después se pasa a UTC.**
//! Una reunión de los lunes a las 9:00 en Madrid es a las 9:00 también después
//! del cambio de hora: en UTC se corre una hora, en el reloj de Madrid no. Por
//! eso a `rrule` se le da la hora de pared como si fuera UTC —un reloj sin
//! saltos—, y cada fecha que devuelve se resuelve con la zona del evento
//! ([`Zone::to_utc`]). Con eso las zonas de un `VTIMEZONE` propio, que `rrule`
//! no conoce, andan igual que las de IANA.
//!
//! ── Que no se dispare ───────────────────────────────────────────────────────
//!
//! La regla la escribe cualquiera: `FREQ=SECONDLY` sin fin, `COUNT=10000000`,
//! miles de `RDATE`. Nada de eso puede colgar el proceso ni llenar la base, y
//! **no se confía sólo en `rrule`**: su propio tope (cien mil vueltas sin
//! encontrar una fecha) no frena una regla que encuentra una por segundo. Los
//! topes son de acá ([`ExpansionLimits`]):
//!
//! - **ocurrencias por objeto** en lo que se pide;
//! - **fechas que se le sacan al iterador**, estén o no en lo que se pide: una
//!   regla que empezó hace años cuenta las de antes;
//! - `RDATE`, `EXDATE` y excepciones por objeto;
//! - **un plazo** por objeto, que se mira en cada fecha que devuelve el
//!   iterador;
//! - **las fechas de un período**, antes de darle la regla a `rrule`
//!   ([`dates_per_period`]).
//!
//! Lo último porque `rrule` arma **un período entero de una vez** antes de
//! devolver la primera fecha: recorre los días del período por las horas, los
//! minutos y los segundos de la regla y los junta en memoria. Una anual con los
//! doce meses, los 31 días, las 24 horas, los 60 minutos y los 60 segundos son
//! 31 millones de fechas en la primera llamada —3 s y 1,5 GB, medido— y ningún
//! tope de acá llega a mirarse. Por eso esa cuenta se hace antes, sobre la
//! regla: si un período puede dar más que el tope, la regla es `invalid`.
//!
//! Lo que pasa un tope no es un error: se devuelve lo que entró, con
//! `truncated`. Una regla que no se entiende tampoco: el evento queda con su
//! primera vez y sus `RDATE`, con `invalid_rule`. Y como esto es CPU, quien lo
//! llama desde el bucle de eventos lo hace fuera de él.
//!
//! **Un salto hacia adelante sin `COUNT`**: si la regla es de período fijo
//! (`SECONDLY` a `WEEKLY`) y empezó mucho antes de lo que se pide, el comienzo
//! se corre de a períodos enteros hasta cerca del principio del rango. Las
//! fechas que da la regla después de ese punto son las mismas —el período y la
//! fase no cambian—, y una reunión diaria desde 1990 no cuesta diez mil
//! vueltas. Con `COUNT` no se puede: hay que contar desde el principio, y el
//! tope de fechas lo frena.
//!
//! ── Lo que no hace ──────────────────────────────────────────────────────────
//!
//! - `EXRULE` (obsoleta desde RFC 5545): se ignora.
//! - Una segunda `RRULE` en el mismo componente (también obsoleta): sólo vale
//!   la primera.
//! - `DURATION` en días de un evento con hora se toma como días de 24 horas, no
//!   como «el mismo reloj al día siguiente».
//! - Los recordatorios con `REPEAT` se guardan una vez, no repetidos.

use std::collections::{BTreeMap, HashSet};
use std::time::{Duration as StdDuration, Instant};

use chrono::{NaiveDate, NaiveDateTime, TimeZone, Utc};

use super::timezones::Zone;
use super::{visible, Component, DateValue, Document, ZoneKind, MAX_TEXT};

/// Los topes de una expansión.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpansionLimits {
    /// Ocurrencias de un objeto en lo que se pide. Una reunión diaria en tres
    /// años son unas 1100; una cada una hora, 26 000, y ésa queda recortada.
    pub max_occurrences: usize,
    /// Fechas que se le sacan al iterador de `rrule` por objeto, contando las
    /// que quedan antes de lo que se pide.
    pub max_iterations: usize,
    /// `RDATE` y `EXDATE` por objeto, cada una.
    pub max_dates: usize,
    /// Excepciones (`RECURRENCE-ID`) por objeto.
    pub max_overrides: usize,
    /// Recordatorios por componente.
    pub max_alarms: usize,
    /// Cuánto puede correrse una serie con `THISANDFUTURE`. Más que esto no se
    /// corre, y queda recortada.
    pub max_shift_seconds: i64,
    /// Cuánto puede tardar la expansión de un objeto.
    pub max_time: StdDuration,
    /// Cuántas fechas puede armar `rrule` para **un** período de la regla —un
    /// año de una anual, un mes de una mensual— antes de devolver la primera.
    /// Una regla que puede pasarlo no se interpreta ([`dates_per_period`]).
    pub max_dates_per_period: u64,
}

impl ExpansionLimits {
    pub const DEFAULT: ExpansionLimits = ExpansionLimits {
        max_occurrences: 5000,
        max_iterations: 100_000,
        max_dates: 1000,
        max_overrides: 500,
        max_alarms: 10,
        max_shift_seconds: 366 * 86_400,
        max_time: StdDuration::from_millis(250),
        max_dates_per_period: 10_000,
    };
}

/// Un día, en segundos.
const DAY: i64 = 86_400;

/// El largo máximo de una `RRULE` que se interpreta.
const MAX_RULE_BYTES: usize = 1024;

/// Cuánto dura cada vez.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Span {
    /// Días enteros: un evento de todo el día.
    Days(i64),
    Seconds(i64),
}

impl Span {
    fn end_of(self, start: i64) -> i64 {
        match self {
            Span::Days(days) => start.saturating_add(days.saturating_mul(DAY)),
            Span::Seconds(seconds) => start.saturating_add(seconds),
        }
    }

    fn seconds(self) -> i64 {
        match self {
            Span::Days(days) => days.saturating_mul(DAY),
            Span::Seconds(seconds) => seconds,
        }
    }
}

/// Qué dispara un recordatorio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// Tanto antes (negativo) o después del comienzo, o del fin.
    Relative { seconds: i64, from_end: bool },
    /// Un instante fijo, en UTC.
    Absolute(i64),
}

/// Un `VALARM`: qué hace y cuándo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlarmSpec {
    /// `DISPLAY`, `AUDIO`, `EMAIL`, en mayúsculas y recortado.
    pub action: String,
    pub trigger: Trigger,
}

/// Un recordatorio de una ocurrencia, ya con su instante.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlarmInstance {
    /// Cuál de los recordatorios del componente es.
    pub position: u32,
    pub at: i64,
    pub action: String,
}

/// Una vez que ocurre un evento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occurrence {
    /// Cuándo empezaba según la serie, en segundos UTC: lo que la identifica,
    /// aunque una excepción la haya movido.
    pub recurrence_id: i64,
    pub start: i64,
    pub end: i64,
    pub all_day: bool,
    /// De qué excepción es el título, cuando no es el de la serie: su lugar
    /// en [`EventSeries::titles`]. No el texto: una `THISANDFUTURE` con otro
    /// título se lo pasa a todas las veces que le siguen, y copiarlo a cada
    /// una multiplicaba el título por las ocurrencias —en la memoria y en la
    /// base—.
    pub title: Option<u32>,
    pub alarms: Vec<AlarmInstance>,
}

/// Lo que dio una expansión.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expansion {
    /// En orden de comienzo.
    pub occurrences: Vec<Occurrence>,
    /// Si se pasó algún tope y faltan ocurrencias.
    pub truncated: bool,
    /// Si la `RRULE` no se entendió: quedan la primera vez y los `RDATE`.
    pub invalid_rule: bool,
}

/// Un `VEVENT`, el de la serie o una excepción, con lo que hace falta para
/// ponerlo en el calendario.
#[derive(Debug, Clone)]
struct Instance {
    start: Option<DateValue>,
    zone: Zone,
    zone_kind: ZoneKind,
    span: Span,
    summary: String,
    cancelled: bool,
    alarms: Vec<AlarmSpec>,
}

#[derive(Debug, Clone)]
struct Override {
    /// El `RECURRENCE-ID`, en segundos UTC.
    rid: i64,
    this_and_future: bool,
    instance: Instance,
    /// Su lugar entre las excepciones, si su título no es el de la serie.
    title: Option<u32>,
}

/// Una fecha que saca `EXDATE`.
#[derive(Debug, Clone, Copy)]
enum Exclusion {
    /// La vez que empieza en ese instante.
    Instant(i64),
    /// Todas las veces de ese día, en el reloj de la serie: una fecha sin hora
    /// en una serie con hora.
    Day(NaiveDate),
}

#[derive(Debug, Clone)]
struct Master {
    instance: Instance,
    rule: Option<String>,
    /// Las `RDATE`, ya resueltas: el instante y la hora de pared.
    rdates: Vec<(i64, NaiveDateTime)>,
    exdates: Vec<Exclusion>,
}

/// Todo lo de un recurso que es un evento: la serie y sus excepciones.
///
/// Un recurso de CalDAV es **un** objeto: la serie y las excepciones de un
/// mismo `UID` viajan juntas, y una excepción reemplaza la vez que nombra su
/// `RECURRENCE-ID`. Un recurso puede traer sólo excepciones —a un invitado se
/// le comparten las veces a las que lo invitaron, no la serie—: cada una es una
/// vez suelta.
#[derive(Debug, Clone)]
pub struct EventSeries {
    master: Option<Master>,
    /// En orden de `RECURRENCE-ID`.
    overrides: Vec<Override>,
    /// Si al leerlo ya se descartó algo por un tope.
    truncated: bool,
}

/// Lee una duración de RFC 5545: `P1D`, `-PT15M`, `P1W`, `PT1H30M`. En
/// segundos, con días de 24 horas.
pub fn parse_duration(value: &str) -> Option<i64> {
    let value = value.trim();
    let (sign, rest) = match value.as_bytes().first()? {
        b'-' => (-1, &value[1..]),
        b'+' => (1, &value[1..]),
        _ => (1, value),
    };
    let rest = rest.strip_prefix(['P', 'p'])?;
    let mut total: i64 = 0;
    let mut number: Option<i64> = None;
    let mut in_time = false;
    let mut any = false;
    for c in rest.chars() {
        match c {
            '0'..='9' => {
                let digit = i64::from(c as u8 - b'0');
                let next = number.unwrap_or(0).checked_mul(10)?.checked_add(digit)?;
                // Diez millones de lo que sea ya es más de lo que dura algo.
                if next > 10_000_000 {
                    return None;
                }
                number = Some(next);
            }
            'T' | 't' if !in_time && number.is_none() => in_time = true,
            unit => {
                let n = number.take()?;
                let factor = match (unit.to_ascii_uppercase(), in_time) {
                    ('W', false) => 7 * DAY,
                    ('D', false) => DAY,
                    ('H', true) => 3600,
                    ('M', true) => 60,
                    ('S', true) => 1,
                    _ => return None,
                };
                total = total.checked_add(n.checked_mul(factor)?)?;
                any = true;
            }
        }
    }
    (any && number.is_none()).then_some(sign * total)
}

/// El recordatorio de un `VALARM`, si se entiende.
pub fn alarm_of(alarm: &Component) -> Option<AlarmSpec> {
    let trigger = alarm.first("TRIGGER")?;
    let action = alarm
        .value("ACTION")
        .map(|a| visible(a, 32).to_ascii_uppercase())
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| "DISPLAY".into());
    let absolute = trigger
        .param("VALUE")
        .is_some_and(|v| v.eq_ignore_ascii_case("DATE-TIME"));
    let trigger = if absolute {
        let at = DateValue::parse(&trigger.value, &trigger.params)?;
        let (moment, _) = at.resolve(&Default::default())?;
        Trigger::Absolute(moment.timestamp())
    } else {
        Trigger::Relative {
            seconds: parse_duration(&trigger.value)?,
            from_end: trigger
                .param("RELATED")
                .is_some_and(|r| r.eq_ignore_ascii_case("END")),
        }
    };
    Some(AlarmSpec { action, trigger })
}

/// Lee un `VEVENT` a lo que hace falta para expandirlo.
fn instance_of(component: &Component, document: &Document, limits: &ExpansionLimits) -> Instance {
    let start = component.date("DTSTART");
    let (zone, zone_kind) = match &start {
        Some(start) => start.zone(&document.zones),
        None => (Zone::Utc, ZoneKind::Utc),
    };
    let all_day = start.as_ref().is_some_and(DateValue::is_date);
    let start_utc = start
        .as_ref()
        .and_then(|s| s.resolve(&document.zones))
        .map(|(moment, _)| moment.timestamp());
    let end = component.date("DTEND");
    let duration = component.value("DURATION").and_then(parse_duration);
    let span = match (all_day, &start, end) {
        (true, Some(DateValue::Date(from)), Some(DateValue::Date(to))) => {
            Span::Days((to - *from).num_days().max(1))
        }
        (true, _, _) => Span::Days(duration.map_or(1, |d| (d / DAY).max(1))),
        (false, _, Some(end)) => {
            let end_utc = end
                .resolve(&document.zones)
                .map(|(moment, _)| moment.timestamp());
            match (start_utc, end_utc) {
                (Some(start), Some(end)) => Span::Seconds(end.saturating_sub(start).max(0)),
                _ => Span::Seconds(duration.unwrap_or(0).max(0)),
            }
        }
        (false, _, None) => Span::Seconds(duration.unwrap_or(0).max(0)),
    };
    Instance {
        start,
        zone,
        zone_kind,
        span,
        summary: component.text("SUMMARY", MAX_TEXT).unwrap_or_default(),
        cancelled: component
            .value("STATUS")
            .is_some_and(|s| s.eq_ignore_ascii_case("CANCELLED")),
        alarms: component
            .children
            .iter()
            .filter(|c| c.name == "VALARM")
            .take(limits.max_alarms)
            .filter_map(alarm_of)
            .collect(),
    }
}

/// Las fechas de las `RDATE` o las `EXDATE` de un componente, con tope. Un
/// período (`20260915T090000Z/PT1H`) vale por su comienzo.
fn dates_of(component: &Component, name: &str, cap: usize, truncated: &mut bool) -> Vec<DateValue> {
    let mut dates = Vec::new();
    for property in component.all(name) {
        for piece in property.value.split(',') {
            if dates.len() >= cap {
                *truncated = true;
                return dates;
            }
            let start = piece.split('/').next().unwrap_or("");
            if let Some(date) = DateValue::parse(start, &property.params) {
                dates.push(date);
            }
        }
    }
    dates
}

/// El instante de una `RDATE` o una `EXDATE`. Sin `TZID` ni `Z` va en la zona
/// del comienzo de la serie, que es lo que quiere decir casi siempre: el cliente
/// la escribió en el mismo reloj.
fn resolve_in(date: &DateValue, zone: &Zone, document: &Document) -> Option<i64> {
    match date {
        DateValue::Local { local, tzid: None } => zone.to_utc(*local),
        other => other.resolve(&document.zones).map(|(moment, _)| moment),
    }
    .map(|moment| moment.timestamp())
}

/// Cuándo se deja de repetir, según `UNTIL`: inclusive.
#[derive(Debug, Clone, Copy)]
enum Until {
    Instant(i64),
    Date(NaiveDate),
    Local(NaiveDateTime),
}

impl Until {
    fn passed(self, local: NaiveDateTime, zone: &Zone) -> bool {
        match self {
            Until::Instant(until) => zone
                .to_utc(local)
                .is_some_and(|moment| moment.timestamp() > until),
            Until::Date(until) => local.date() > until,
            Until::Local(until) => local > until,
        }
    }
}

/// Separa el `UNTIL` del resto de la regla: se aplica acá, contra el instante
/// de cada vez, y no en `rrule`, que quiere el `UNTIL` en la misma zona que el
/// comienzo y acá el comienzo es la hora de pared. `Err` si la regla no se
/// puede interpretar sin riesgo: no es ASCII —`rrule` corta el `BYDAY` por
/// bytes y entra en pánico con un carácter de varios—, es desmedida o trae dos
/// puntos.
fn split_until(rule: &str) -> Result<(String, Option<Until>), ()> {
    let rule = rule.trim();
    if rule.is_empty() || rule.len() > MAX_RULE_BYTES || !rule.is_ascii() || rule.contains(':') {
        return Err(());
    }
    let mut until = None;
    let mut parts = Vec::new();
    for part in rule.split(';').filter(|p| !p.trim().is_empty()) {
        match part.split_once('=') {
            Some((name, value)) if name.trim().eq_ignore_ascii_case("UNTIL") => {
                until = Some(match DateValue::parse(value, &[]).ok_or(())? {
                    DateValue::Date(date) => Until::Date(date),
                    DateValue::Utc(utc) => Until::Instant(Utc.from_utc_datetime(&utc).timestamp()),
                    DateValue::Local { local, .. } => Until::Local(local),
                });
            }
            _ => parts.push(part.trim()),
        }
    }
    Ok((parts.join(";"), until))
}

/// El período de una frecuencia de largo fijo, en segundos de reloj de pared.
fn fixed_period(frequency: rrule::Frequency) -> Option<i64> {
    match frequency {
        rrule::Frequency::Secondly => Some(1),
        rrule::Frequency::Minutely => Some(60),
        rrule::Frequency::Hourly => Some(3600),
        rrule::Frequency::Daily => Some(DAY),
        rrule::Frequency::Weekly => Some(7 * DAY),
        rrule::Frequency::Monthly | rrule::Frequency::Yearly => None,
    }
}

/// Cuántas fechas puede armar `rrule` para **un** período de la regla, como
/// mucho: los días del período que pueden pasar los filtros por los momentos
/// del día.
///
/// `rrule` 0.14 no devuelve de a una: en cada período recorre sus días
/// (`dayset`: el año, el mes, la semana o el día) por el producto `BYHOUR ×
/// BYMINUTE × BYSECOND` (`timeset`), y las junta todas antes de devolver la
/// primera. Lo que se cuenta acá es eso, sobre la regla **ya completada** por
/// `rrule` (una anual sin días toma el día y el mes del comienzo, una semanal
/// el día de la semana, y los momentos que falten, los del comienzo):
///
/// - los días: los del período, acotados por cada filtro que tenga —son todos
///   intersección—: `BYMONTH` (31 por mes), `BYMONTHDAY` (uno por mes),
///   `BYYEARDAY` (uno), `BYWEEKNO` (catorce por semana: la suya y la del año
///   de al lado) y `BYDAY` (53 por día en un año, cinco en un mes, uno en una
///   semana);
/// - los momentos: `BYHOUR × BYMINUTE × BYSECOND` hasta la diaria; en la
///   horaria, `BYMINUTE × BYSECOND`; en la de minutos, `BYSECOND`; en la de
///   segundos, uno;
/// - con `BYSETPOS`, `rrule` arma sólo las posiciones pedidas: como mucho,
///   tantas como posiciones.
///
/// Es una cota por arriba: puede pasarse, nunca quedarse corta.
/// `month_days` son los `BYMONTHDAY` distintos de la regla como vino —`rrule`
/// aparta los negativos y no los muestra—.
fn dates_per_period(rule: &rrule::RRule, month_days: u64) -> u64 {
    use rrule::Frequency;
    let at_least_one = |n: usize| (n as u64).max(1);
    let freq = rule.get_freq();
    let (hours, minutes, seconds) = (
        at_least_one(rule.get_by_hour().len()),
        at_least_one(rule.get_by_minute().len()),
        at_least_one(rule.get_by_second().len()),
    );
    let moments = match freq {
        Frequency::Yearly | Frequency::Monthly | Frequency::Weekly | Frequency::Daily => {
            hours * minutes * seconds
        }
        Frequency::Hourly => minutes * seconds,
        Frequency::Minutely => seconds,
        Frequency::Secondly => 1,
    };
    let month_days = month_days.max(rule.get_by_month_day().len() as u64);
    let months = rule.get_by_month().len() as u64;
    let year_days = rule.get_by_year_day().len() as u64;
    let weeks = rule.get_by_week_no().len() as u64;
    let weekdays = rule.get_by_weekday().len() as u64;
    // Un `BYMONTHDAY` es un día por mes: en un año, por cada mes de `BYMONTH`
    // o por los doce.
    let (full, per_weekday, month_day_factor) = match freq {
        Frequency::Yearly => (366, 53, if months == 0 { 12 } else { months }),
        Frequency::Monthly => (31, 5, 1),
        Frequency::Weekly => (7, 1, 1),
        _ => (1, 1, 1),
    };
    let mut days: u64 = full;
    if months > 0 {
        days = days.min(31 * months);
    }
    if month_days > 0 {
        days = days.min(month_days * month_day_factor);
    }
    if year_days > 0 {
        days = days.min(year_days);
    }
    // Un número de semana puede tocar dos semanas en el mismo año: la suya y
    // la del año de al lado que empieza o termina adentro (la semana 1 del año
    // que viene puede empezar el 29 de diciembre).
    if weeks > 0 {
        days = days.min(14 * weeks);
    }
    if weekdays > 0 {
        days = days.min(per_weekday * weekdays);
    }
    let dates = days.saturating_mul(moments);
    match rule.get_by_set_pos().len() {
        0 => dates,
        positions => dates.min(positions as u64),
    }
}

/// La hora de pared de un instante, leída como si el reloj fuera UTC.
fn wall(seconds: i64) -> NaiveDateTime {
    Utc.timestamp_opt(seconds.clamp(-62_135_596_800, 253_402_300_799), 0)
        .single()
        .map(|moment| moment.naive_utc())
        .unwrap_or_default()
}

/// Lo que da la regla entre `lo` y `hi` (en segundos UTC, con margen), como
/// `(instante, hora de pared)`. `Err` si la regla no se entiende.
#[allow(clippy::too_many_arguments)]
fn rule_instances(
    rule: &str,
    start: NaiveDateTime,
    zone: &Zone,
    lo: i64,
    hi: i64,
    keep: &dyn Fn(i64) -> bool,
    limits: &ExpansionLimits,
    deadline: Instant,
) -> Result<(Vec<(i64, NaiveDateTime)>, bool), ()> {
    let (rule, until) = split_until(rule)?;
    let parsed: rrule::RRule<rrule::Unvalidated> = rule.parse().map_err(|_| ())?;
    // `rrule` acepta `INTERVAL=0` y no da ninguna fecha; RFC 5545 lo prohíbe.
    if parsed.get_interval() == 0 {
        return Err(());
    }
    // El reloj de pared no tiene saltos, pero la zona sí: con dos días de
    // margen a cada lado, lo que se descarta después por su instante.
    let lo_wall = wall(lo.saturating_sub(2 * DAY));
    let hi_wall = wall(hi.saturating_add(2 * DAY));

    let mut from = start;
    if parsed.get_count().is_none() && lo_wall > start {
        if let Some(period) = fixed_period(parsed.get_freq()) {
            let step = period.saturating_mul(i64::from(parsed.get_interval().max(1)));
            let periods = (lo_wall - start).num_seconds() / step;
            if periods > 0 {
                if let Some(moved) = periods
                    .checked_mul(step)
                    .and_then(|s| start.checked_add_signed(chrono::Duration::seconds(s)))
                {
                    from = moved;
                }
            }
        }
    }

    // Los `BYMONTHDAY` como vinieron: `rrule` aparta los negativos al
    // completar la regla y ya no los muestra.
    let mut month_days: Vec<i8> = parsed
        .get_by_month_day()
        .iter()
        .copied()
        .filter(|d| *d != 0)
        .collect();
    month_days.sort_unstable();
    month_days.dedup();
    let dt_start = rrule::Tz::UTC.from_utc_datetime(&from);
    let validated = parsed.validate(dt_start).map_err(|_| ())?;
    // **Antes** de iterar: `rrule` arma el período entero en la primera
    // llamada, y ahí ningún tope de abajo llega a mirarse.
    if dates_per_period(&validated, month_days.len() as u64) > limits.max_dates_per_period {
        return Err(());
    }
    let set = rrule::RRuleSet::new(dt_start).rrule(validated).limit();
    let mut found = Vec::new();
    let mut truncated = false;
    for (iterations, moment) in set.into_iter().enumerate() {
        // El plazo, en cada fecha: una sola vuelta de `rrule` puede recorrer
        // miles de períodos vacíos antes de dar la siguiente.
        if iterations >= limits.max_iterations || Instant::now() >= deadline {
            truncated = true;
            break;
        }
        let local = moment.naive_utc();
        if local > hi_wall || until.is_some_and(|u| u.passed(local, zone)) {
            break;
        }
        if local < lo_wall {
            continue;
        }
        let Some(utc) = zone.to_utc(local).map(|m| m.timestamp()) else {
            continue;
        };
        if utc < lo || utc >= hi || !keep(utc) {
            continue;
        }
        if found.len() >= limits.max_occurrences {
            truncated = true;
            break;
        }
        found.push((utc, local));
    }
    Ok((found, truncated))
}

impl EventSeries {
    /// La serie de un recurso, o `None` si no trae ningún `VEVENT`.
    ///
    /// Vale el `UID` del primer `VEVENT`; los de otro `UID` en el mismo recurso
    /// —CalDAV no los permite— se ignoran.
    pub fn from_document(document: &Document, limits: &ExpansionLimits) -> Option<Self> {
        let events: Vec<&Component> = document
            .components
            .iter()
            .filter(|c| c.name == "VEVENT")
            .collect();
        let uid = events.first()?.value("UID").unwrap_or("").to_string();
        let same = |c: &&&Component| c.value("UID").unwrap_or("") == uid;
        let mut truncated = document.truncated;

        let master = events
            .iter()
            .filter(same)
            .find(|c| c.first("RECURRENCE-ID").is_none())
            .map(|c| {
                let instance = instance_of(c, document, limits);
                let all_day = instance.start.as_ref().is_some_and(DateValue::is_date);
                let rdates = dates_of(c, "RDATE", limits.max_dates, &mut truncated)
                    .iter()
                    .filter_map(|d| {
                        Some((resolve_in(d, &instance.zone, document)?, d.wall_clock()))
                    })
                    .collect();
                let exdates = dates_of(c, "EXDATE", limits.max_dates, &mut truncated)
                    .iter()
                    .filter_map(|d| match d {
                        DateValue::Date(day) if !all_day => Some(Exclusion::Day(*day)),
                        other => {
                            resolve_in(other, &instance.zone, document).map(Exclusion::Instant)
                        }
                    })
                    .collect();
                Master {
                    instance,
                    rule: c.value("RRULE").map(str::to_string),
                    rdates,
                    exdates,
                }
            });

        let mut overrides = Vec::new();
        for component in events
            .iter()
            .filter(same)
            .filter(|c| c.first("RECURRENCE-ID").is_some())
        {
            if overrides.len() >= limits.max_overrides {
                truncated = true;
                break;
            }
            let property = component.first("RECURRENCE-ID").expect("filtrado arriba");
            let Some(rid) = DateValue::parse(&property.value, &property.params)
                .and_then(|d| d.resolve(&document.zones))
                .map(|(moment, _)| moment.timestamp())
            else {
                continue;
            };
            overrides.push(Override {
                rid,
                this_and_future: property
                    .param("RANGE")
                    .is_some_and(|r| r.eq_ignore_ascii_case("THISANDFUTURE")),
                instance: instance_of(component, document, limits),
                title: None,
            });
        }
        overrides.sort_by_key(|o| o.rid);
        // Dos excepciones de la misma vez: vale la primera.
        overrides.dedup_by_key(|o| o.rid);
        let master_summary = master.as_ref().map(|m| m.instance.summary.as_str());
        for (position, o) in overrides.iter_mut().enumerate() {
            o.title =
                (master_summary != Some(o.instance.summary.as_str())).then_some(position as u32);
        }

        Some(Self {
            master,
            overrides,
            truncated,
        })
    }

    /// Los títulos de las excepciones que no llevan el de la serie, por su
    /// lugar: lo que nombra [`Occurrence::title`]. Como mucho uno por
    /// excepción, y cada uno salió del recurso, así que juntos no pesan más que
    /// él.
    pub fn titles(&self) -> Vec<(u32, &str)> {
        self.overrides
            .iter()
            .filter_map(|o| Some((o.title?, o.instance.summary.as_str())))
            .collect()
    }

    /// El título de una vez: el de su excepción, o `None` si es el de la
    /// serie.
    pub fn title_of(&self, occurrence: &Occurrence) -> Option<&str> {
        let position = occurrence.title?;
        self.overrides
            .get(position as usize)
            .filter(|o| o.title == Some(position))
            .map(|o| o.instance.summary.as_str())
    }

    /// Si se repite: tiene regla o fechas sueltas. Una que no se repite tiene
    /// un número fijo de veces —la suya y sus excepciones sueltas—, y se guarda
    /// entera.
    pub fn is_recurring(&self) -> bool {
        self.master
            .as_ref()
            .is_some_and(|m| m.rule.is_some() || !m.rdates.is_empty())
    }

    /// Cómo quedó la zona del comienzo de la serie (o de la primera excepción).
    pub fn zone_kind(&self) -> ZoneKind {
        self.master
            .as_ref()
            .map(|m| &m.instance)
            .or_else(|| self.overrides.first().map(|o| &o.instance))
            .map_or(ZoneKind::Utc, |i| i.zone_kind)
    }

    /// Cuánto puede durar una vez, como mucho: la serie y cada excepción.
    pub fn max_span(&self) -> i64 {
        self.master
            .iter()
            .map(|m| m.instance.span.seconds())
            .chain(self.overrides.iter().map(|o| o.instance.span.seconds()))
            .max()
            .unwrap_or(0)
            .max(0)
    }

    /// Lo que se guarda: en una serie, las veces que **empiezan** en
    /// `[from, to)`; en un evento que no se repite, todas.
    pub fn materialize(&self, from: i64, to: i64, limits: &ExpansionLimits) -> Expansion {
        if self.is_recurring() {
            self.expand(
                from,
                to,
                &|start, _| start >= from && start < to,
                limits,
                true,
            )
        } else {
            self.expand(i64::MIN / 4, i64::MAX / 4, &|_, _| true, limits, true)
        }
    }

    /// Lo que se ve en `[from, to)` —lo que se superpone con el rango—, sin
    /// las veces que empiezan en `skip`: ésas ya están guardadas. Sin los
    /// recordatorios: es para listar, y se guardan sólo los de la ventana.
    pub fn between(
        &self,
        from: i64,
        to: i64,
        skip: Option<(i64, i64)>,
        limits: &ExpansionLimits,
    ) -> Expansion {
        let span = self.max_span();
        let skipped = |start: i64| skip.is_some_and(|(a, b)| start >= a && start < b);
        self.expand(
            from.saturating_sub(span),
            to,
            &|start, end| overlaps(start, end, from, to) && !skipped(start),
            limits,
            false,
        )
    }

    /// Una vez en particular, por su `RECURRENCE-ID`.
    pub fn instance(&self, recurrence_id: i64, limits: &ExpansionLimits) -> Option<Occurrence> {
        self.expand(
            recurrence_id,
            recurrence_id.saturating_add(1),
            &|_, _| true,
            limits,
            false,
        )
        .occurrences
        .into_iter()
        .find(|o| o.recurrence_id == recurrence_id)
        .or_else(|| {
            // Una excepción movida lejos de su lugar original.
            self.overrides
                .iter()
                .find(|o| o.rid == recurrence_id)
                .and_then(|o| self.override_occurrence(o))
        })
    }

    fn override_occurrence(&self, o: &Override) -> Option<Occurrence> {
        if o.instance.cancelled {
            return None;
        }
        let start = o
            .instance
            .start
            .as_ref()
            .and_then(|s| o.instance.zone.to_utc(s.wall_clock()))
            .map_or(o.rid, |m| m.timestamp());
        Some(Occurrence {
            recurrence_id: o.rid,
            start,
            end: o.instance.span.end_of(start),
            all_day: o.instance.start.as_ref().is_some_and(DateValue::is_date),
            title: o.title,
            alarms: Vec::new(),
        })
    }

    /// La expansión: las veces de la serie cuyo comienzo cae en `[lo, hi)`
    /// —corrido lo que pueda correrlas un `THISANDFUTURE`—, con sus
    /// excepciones aplicadas, y de ésas las que pasan `keep`. Con sus
    /// recordatorios sólo si `with_alarms`: son hasta diez por vez.
    fn expand(
        &self,
        lo: i64,
        hi: i64,
        keep: &dyn Fn(i64, i64) -> bool,
        limits: &ExpansionLimits,
        with_alarms: bool,
    ) -> Expansion {
        let deadline = Instant::now() + limits.max_time;
        let mut expansion = Expansion {
            truncated: self.truncated,
            ..Default::default()
        };

        // Cuánto pueden correr la serie sus excepciones hacia adelante: con
        // eso, el rango de lo que se genera se agranda para no perder una vez
        // que cae adentro recién después de correrla.
        let mut shift: i64 = 0;
        for o in self.overrides.iter().filter(|o| o.this_and_future) {
            let delta = self.override_start(o).saturating_sub(o.rid).unsigned_abs();
            if delta > limits.max_shift_seconds.unsigned_abs() {
                expansion.truncated = true;
            } else {
                shift = shift.max(delta as i64);
            }
        }
        let shifting = shift > 0 || self.overrides.iter().any(|o| o.this_and_future);

        // Las veces de la serie: por su comienzo original.
        let mut base: BTreeMap<i64, NaiveDateTime> = BTreeMap::new();
        if let Some(master) = &self.master {
            let instance = &master.instance;
            let span = instance.span;
            let gen_lo = lo.saturating_sub(shift);
            let gen_hi = hi.saturating_add(shift);
            // Con excepciones que corren la serie no se puede filtrar al
            // generar: se filtra al final, con la vez ya corrida.
            let early = |start: i64| shifting || keep(start, span.end_of(start));
            let first = instance
                .start
                .as_ref()
                .and_then(|s| instance.zone.to_utc(s.wall_clock()))
                .map(|m| m.timestamp());

            if let (Some(rule), Some(start)) = (&master.rule, &instance.start) {
                let wall_start = start.wall_clock();
                let zone = instance.zone.clone();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    rule_instances(
                        rule, wall_start, &zone, gen_lo, gen_hi, &early, limits, deadline,
                    )
                }));
                match result {
                    Ok(Ok((found, truncated))) => {
                        expansion.truncated |= truncated;
                        base.extend(found);
                    }
                    Ok(Err(())) | Err(_) => expansion.invalid_rule = true,
                }
            }
            // La primera vez cuenta siempre, la dé o no la regla (RFC 5545,
            // 3.8.5.3).
            if let (Some(first), Some(start)) = (first, &instance.start) {
                if first >= gen_lo && first < gen_hi && early(first) {
                    base.insert(first, start.wall_clock());
                }
            }
            for (utc, wall) in &master.rdates {
                if *utc >= gen_lo && *utc < gen_hi && early(*utc) {
                    base.insert(*utc, *wall);
                }
            }
            // Una fecha sin hora en una serie con hora saca todas las veces de
            // ese día, en el reloj de la serie: todas juntas en una pasada, y
            // no una pasada por fecha —mil `EXDATE` por cinco mil veces—.
            let mut days = HashSet::new();
            for exclusion in &master.exdates {
                match exclusion {
                    Exclusion::Instant(excluded) => {
                        base.remove(excluded);
                    }
                    Exclusion::Day(day) => {
                        days.insert(*day);
                    }
                }
            }
            if !days.is_empty() {
                base.retain(|_, wall| !days.contains(&wall.date()));
            }
        }

        // Cada vez, con su comienzo, su fin, su título y de dónde salen sus
        // recordatorios.
        struct Built<'a> {
            start: i64,
            end: i64,
            all_day: bool,
            title: Option<u32>,
            source: &'a Instance,
        }
        let mut built: BTreeMap<i64, Built<'_>> = BTreeMap::new();
        if let Some(master) = &self.master {
            let all_day = master
                .instance
                .start
                .as_ref()
                .is_some_and(DateValue::is_date);
            for rid in base.keys() {
                built.insert(
                    *rid,
                    Built {
                        start: *rid,
                        end: master.instance.span.end_of(*rid),
                        all_day,
                        title: None,
                        source: &master.instance,
                    },
                );
            }
        }
        // Las excepciones que corren la serie desde una vez en adelante: una
        // posterior manda sobre las veces que siguen a ella, así que a cada
        // vez le toca **la última que empieza en ella o antes**. Se aplica en
        // una sola pasada, con un puntero que avanza, y no una pasada por
        // excepción —quinientas por seis mil veces—. Una cancelada se lleva
        // todas las que siguen, también las que otra posterior habría corrido.
        let this_and_future: Vec<&Override> = self
            .overrides
            .iter()
            .filter(|o| o.this_and_future)
            .collect();
        if let Some(cut) = this_and_future.iter().find(|o| o.instance.cancelled) {
            drop(built.split_off(&cut.rid));
        }
        let mut pending = this_and_future
            .iter()
            .filter(|o| !o.instance.cancelled)
            .peekable();
        let mut current: Option<(&Override, i64)> = None;
        for (rid, occurrence) in built.iter_mut() {
            while let Some(o) = pending.next_if(|o| o.rid <= *rid) {
                let delta = self.override_start(o).saturating_sub(o.rid);
                let delta = if delta.unsigned_abs() > limits.max_shift_seconds.unsigned_abs() {
                    0
                } else {
                    delta
                };
                current = Some((o, delta));
            }
            if let Some((o, delta)) = current {
                occurrence.start = rid.saturating_add(delta);
                occurrence.end = o.instance.span.end_of(occurrence.start);
                occurrence.title = o.title;
                occurrence.source = &o.instance;
            }
        }
        // Y cada excepción reemplaza la vez que nombra.
        for o in &self.overrides {
            built.remove(&o.rid);
            if o.instance.cancelled {
                continue;
            }
            let start = self.override_start(o);
            built.insert(
                o.rid,
                Built {
                    start,
                    end: o.instance.span.end_of(start),
                    all_day: o.instance.start.as_ref().is_some_and(DateValue::is_date),
                    title: o.title,
                    source: &o.instance,
                },
            );
        }

        let mut occurrences: Vec<Occurrence> = built
            .into_iter()
            .filter(|(_, b)| keep(b.start, b.end))
            .map(|(rid, b)| Occurrence {
                recurrence_id: rid,
                start: b.start,
                end: b.end,
                all_day: b.all_day,
                title: b.title,
                alarms: if with_alarms {
                    alarms_for(b.source, b.start, b.end, rid, self.first_rid())
                } else {
                    Vec::new()
                },
            })
            .collect();
        occurrences.sort_by_key(|o| (o.start, o.recurrence_id));
        if occurrences.len() > limits.max_occurrences {
            occurrences.truncate(limits.max_occurrences);
            expansion.truncated = true;
        }
        expansion.occurrences = occurrences;
        expansion
    }

    /// Dónde empieza una excepción: su `DTSTART`, o el lugar que reemplaza.
    fn override_start(&self, o: &Override) -> i64 {
        o.instance
            .start
            .as_ref()
            .and_then(|s| o.instance.zone.to_utc(s.wall_clock()))
            .map_or(o.rid, |m| m.timestamp())
    }

    /// El `RECURRENCE-ID` de la primera vez de la serie.
    fn first_rid(&self) -> Option<i64> {
        let master = self.master.as_ref()?;
        master
            .instance
            .start
            .as_ref()
            .and_then(|s| master.instance.zone.to_utc(s.wall_clock()))
            .map(|m| m.timestamp())
    }
}

/// Los recordatorios de una vez. Uno con instante fijo es de la serie, no de
/// cada vez: va sólo con la primera, o con la excepción que lo trae.
fn alarms_for(
    source: &Instance,
    start: i64,
    end: i64,
    rid: i64,
    first: Option<i64>,
) -> Vec<AlarmInstance> {
    source
        .alarms
        .iter()
        .enumerate()
        .filter_map(|(position, alarm)| {
            let at = match alarm.trigger {
                Trigger::Relative { seconds, from_end } => {
                    (if from_end { end } else { start }).saturating_add(seconds)
                }
                Trigger::Absolute(at) => {
                    if first.is_some_and(|f| f != rid) {
                        return None;
                    }
                    at
                }
            };
            Some(AlarmInstance {
                position: position as u32,
                at,
                action: alarm.action.clone(),
            })
        })
        .collect()
}

/// Si una vez `[start, end)` se ve en `[from, to)`. Una que no dura nada se ve
/// si empieza adentro.
pub fn overlaps(start: i64, end: i64, from: i64, to: i64) -> bool {
    if end <= start {
        start >= from && start < to
    } else {
        start < to && end > from
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Datelike, Timelike};

    use super::super::parse_document;
    use super::*;

    fn at(text: &str) -> i64 {
        chrono::DateTime::parse_from_rfc3339(text)
            .unwrap()
            .timestamp()
    }

    fn series(ical: &str) -> EventSeries {
        EventSeries::from_document(&parse_document(ical), &ExpansionLimits::DEFAULT).unwrap()
    }

    fn event(body: &str) -> String {
        format!("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:s\r\n{body}END:VEVENT\r\nEND:VCALENDAR\r\n")
    }

    fn starts(expansion: &Expansion) -> Vec<String> {
        expansion
            .occurrences
            .iter()
            .map(|o| super::super::rfc3339(o.start))
            .collect()
    }

    /// Corre el trabajo en otro hilo y falla si no termina en el plazo: sin el
    /// arreglo, la prueba cae en vez de colgarse.
    fn finishes_within<T: Send + 'static>(
        limit: StdDuration,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(work());
        });
        receiver
            .recv_timeout(limit)
            .expect("la expansión no terminó a tiempo")
    }

    #[test]
    fn las_duraciones_se_leen() {
        assert_eq!(parse_duration("PT15M"), Some(900));
        assert_eq!(parse_duration("-PT15M"), Some(-900));
        assert_eq!(parse_duration("P1D"), Some(86_400));
        assert_eq!(parse_duration("P1W"), Some(604_800));
        assert_eq!(parse_duration("PT1H30M"), Some(5400));
        assert_eq!(parse_duration("P1DT2H"), Some(93_600));
        for garbage in [
            "",
            "P",
            "PT",
            "1H",
            "P1H",
            "PT1D",
            "P99999999999D",
            "PT15",
            "-",
        ] {
            assert_eq!(parse_duration(garbage), None, "{garbage:?}");
        }
    }

    /// Un semanal con `COUNT` y un `EXDATE`: cuatro de cinco, sin la sacada.
    #[test]
    fn exdate_saca_una_vez_de_la_serie() {
        let s = series(&event(
            "DTSTART:20260105T100000Z\r\nDTEND:20260105T110000Z\r\n\
             RRULE:FREQ=WEEKLY;COUNT=5\r\nEXDATE:20260119T100000Z\r\n",
        ));
        let e = s.materialize(
            at("2026-01-01T00:00:00Z"),
            at("2027-01-01T00:00:00Z"),
            &ExpansionLimits::DEFAULT,
        );
        assert_eq!(
            starts(&e),
            vec![
                "2026-01-05T10:00:00+00:00",
                "2026-01-12T10:00:00+00:00",
                "2026-01-26T10:00:00+00:00",
                "2026-02-02T10:00:00+00:00",
            ]
        );
        assert!(!e.truncated);
        assert_eq!(e.occurrences[0].end - e.occurrences[0].start, 3600);
    }

    /// `UNTIL` es inclusive, y una serie de un evento con `TZID` lo trae en
    /// UTC.
    #[test]
    fn until_corta_la_serie_inclusive() {
        let s = series(&event(
            "DTSTART;TZID=Europe/Madrid:20260105T090000\r\n\
             RRULE:FREQ=DAILY;UNTIL=20260107T080000Z\r\n",
        ));
        let e = s.materialize(
            at("2026-01-01T00:00:00Z"),
            at("2026-02-01T00:00:00Z"),
            &ExpansionLimits::DEFAULT,
        );
        assert_eq!(e.occurrences.len(), 3, "el 5, el 6 y el 7");
    }

    /// Las excepciones: una vez movida de hora y con otro título, y otra
    /// cancelada. La movida reemplaza a la original —no se ven las dos— y la
    /// cancelada desaparece.
    #[test]
    fn recurrence_id_mueve_y_cancela_una_vez() {
        let ical = "BEGIN:VCALENDAR\r\n\
            BEGIN:VEVENT\r\nUID:s\r\nSUMMARY:Reunión\r\n\
            DTSTART:20260105T100000Z\r\nDTEND:20260105T110000Z\r\n\
            RRULE:FREQ=WEEKLY;COUNT=4\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nUID:s\r\nSUMMARY:Reunión movida\r\n\
            RECURRENCE-ID:20260112T100000Z\r\n\
            DTSTART:20260113T150000Z\r\nDTEND:20260113T170000Z\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nUID:s\r\nRECURRENCE-ID:20260119T100000Z\r\n\
            DTSTART:20260119T100000Z\r\nSTATUS:CANCELLED\r\nEND:VEVENT\r\n\
            END:VCALENDAR\r\n";
        let s = series(ical);
        let e = s.materialize(
            at("2026-01-01T00:00:00Z"),
            at("2027-01-01T00:00:00Z"),
            &ExpansionLimits::DEFAULT,
        );
        assert_eq!(
            starts(&e),
            vec![
                "2026-01-05T10:00:00+00:00",
                "2026-01-13T15:00:00+00:00",
                "2026-01-26T10:00:00+00:00",
            ]
        );
        let moved = &e.occurrences[1];
        assert_eq!(moved.recurrence_id, at("2026-01-12T10:00:00Z"));
        assert_eq!(moved.end - moved.start, 7200);
        assert_eq!(s.title_of(moved), Some("Reunión movida"));
        assert_eq!(s.title_of(&e.occurrences[0]), None);
    }

    /// `THISANDFUTURE`: desde esa vez en adelante la serie se corre lo mismo
    /// que se corrió ésa.
    #[test]
    fn thisandfuture_corre_la_serie_desde_esa_vez() {
        let ical = "BEGIN:VCALENDAR\r\n\
            BEGIN:VEVENT\r\nUID:s\r\nSUMMARY:Clase\r\nDTSTART:20260105T100000Z\r\n\
            RRULE:FREQ=WEEKLY;COUNT=4\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nUID:s\r\nSUMMARY:Clase\r\n\
            RECURRENCE-ID;RANGE=THISANDFUTURE:20260119T100000Z\r\n\
            DTSTART:20260119T120000Z\r\nEND:VEVENT\r\n\
            END:VCALENDAR\r\n";
        let e = series(ical).materialize(
            at("2026-01-01T00:00:00Z"),
            at("2027-01-01T00:00:00Z"),
            &ExpansionLimits::DEFAULT,
        );
        assert_eq!(
            starts(&e),
            vec![
                "2026-01-05T10:00:00+00:00",
                "2026-01-12T10:00:00+00:00",
                "2026-01-19T12:00:00+00:00",
                "2026-01-26T12:00:00+00:00",
            ]
        );
    }

    /// **El cambio de hora.** Un semanal a las 9:00 de Madrid sigue a las 9:00
    /// de Madrid del otro lado del cambio: en UTC pasa de las 8 a las 7.
    #[test]
    fn un_semanal_sigue_a_la_misma_hora_local_al_cruzar_el_cambio_de_hora() {
        let s = series(&event(
            "DTSTART;TZID=Europe/Madrid:20260316T090000\r\n\
             DTEND;TZID=Europe/Madrid:20260316T100000\r\nRRULE:FREQ=WEEKLY;COUNT=3\r\n",
        ));
        let e = s.materialize(
            at("2026-03-01T00:00:00Z"),
            at("2026-05-01T00:00:00Z"),
            &ExpansionLimits::DEFAULT,
        );
        assert_eq!(
            starts(&e),
            vec![
                "2026-03-16T08:00:00+00:00",
                "2026-03-23T08:00:00+00:00",
                // El 29 de marzo cambió la hora: 9:00 de Madrid son las 7 UTC.
                "2026-03-30T07:00:00+00:00",
            ]
        );
        for o in &e.occurrences {
            let local = chrono_tz::Europe::Madrid.timestamp_opt(o.start, 0).unwrap();
            assert_eq!((local.hour(), local.minute()), (9, 0));
        }

        // Y lo mismo en Nueva York, que cambia otro día.
        let s = series(&event(
            "DTSTART;TZID=America/New_York:20261026T090000\r\nRRULE:FREQ=WEEKLY;COUNT=2\r\n",
        ));
        let e = s.materialize(
            at("2026-10-01T00:00:00Z"),
            at("2026-12-01T00:00:00Z"),
            &ExpansionLimits::DEFAULT,
        );
        assert_eq!(
            starts(&e),
            vec!["2026-10-26T13:00:00+00:00", "2026-11-02T14:00:00+00:00"]
        );
    }

    /// Todo el día: fechas y no horas, un día de largo, sin zona.
    #[test]
    fn un_evento_de_todo_el_dia_se_repite_por_fechas() {
        let s = series(&event(
            "DTSTART;VALUE=DATE:20261224\r\nDTEND;VALUE=DATE:20261226\r\n\
             RRULE:FREQ=YEARLY;COUNT=3\r\nEXDATE;VALUE=DATE:20271224\r\n",
        ));
        let e = s.materialize(
            at("2026-01-01T00:00:00Z"),
            at("2030-01-01T00:00:00Z"),
            &ExpansionLimits::DEFAULT,
        );
        assert_eq!(
            starts(&e),
            vec!["2026-12-24T00:00:00+00:00", "2028-12-24T00:00:00+00:00"]
        );
        assert!(e.occurrences.iter().all(|o| o.all_day));
        assert_eq!(e.occurrences[0].end - e.occurrences[0].start, 2 * DAY);
        assert_eq!(s.zone_kind(), ZoneKind::Date);
    }

    /// `RDATE` suma veces sueltas, también de un evento que no tiene regla.
    #[test]
    fn rdate_suma_veces_sueltas() {
        let s = series(&event(
            "DTSTART:20260105T100000Z\r\nDURATION:PT30M\r\n\
             RDATE:20260110T100000Z,20260120T150000Z\r\nRDATE;VALUE=PERIOD:20260125T080000Z/PT1H\r\n",
        ));
        assert!(s.is_recurring());
        let e = s.materialize(
            at("2026-01-01T00:00:00Z"),
            at("2026-02-01T00:00:00Z"),
            &ExpansionLimits::DEFAULT,
        );
        assert_eq!(
            starts(&e),
            vec![
                "2026-01-05T10:00:00+00:00",
                "2026-01-10T10:00:00+00:00",
                "2026-01-20T15:00:00+00:00",
                "2026-01-25T08:00:00+00:00",
            ]
        );
        assert!(e.occurrences.iter().all(|o| o.end - o.start == 1800));
    }

    /// `COUNT` cuenta desde la primera vez aunque se pida un rango posterior.
    #[test]
    fn count_cuenta_desde_el_principio() {
        let s = series(&event(
            "DTSTART:20260101T100000Z\r\nRRULE:FREQ=DAILY;COUNT=10\r\n",
        ));
        let e = s.materialize(
            at("2026-01-08T00:00:00Z"),
            at("2026-02-01T00:00:00Z"),
            &ExpansionLimits::DEFAULT,
        );
        assert_eq!(e.occurrences.len(), 3, "el 8, el 9 y el 10");
    }

    /// Una serie diaria desde 1990 no cuesta diez mil vueltas: el comienzo se
    /// corre de a períodos enteros, y las fechas son las mismas.
    #[test]
    fn una_serie_vieja_sin_count_salta_hasta_el_rango() {
        let s = series(&event(
            "DTSTART;TZID=Europe/Madrid:19900103T093000\r\nRRULE:FREQ=DAILY;INTERVAL=3\r\n",
        ));
        let limits = ExpansionLimits {
            max_iterations: 100,
            ..ExpansionLimits::DEFAULT
        };
        let e = s.materialize(
            at("2026-09-01T00:00:00Z"),
            at("2026-09-10T00:00:00Z"),
            &limits,
        );
        assert!(!e.truncated);
        // Cada tres días desde el 3 de enero de 1990: el 3 de septiembre de
        // 2026 es uno (13 392 días después, múltiplo de tres).
        assert_eq!(
            starts(&e),
            vec![
                "2026-09-03T07:30:00+00:00",
                "2026-09-06T07:30:00+00:00",
                "2026-09-09T07:30:00+00:00",
            ]
        );
    }

    /// Una zona desconocida no pierde el evento: queda a la hora de la sesión
    /// y marcado.
    #[test]
    fn una_zona_desconocida_no_pierde_el_evento() {
        let s = series(&event(
            "DTSTART;TZID=Hora de Marte:20260105T100000\r\nRRULE:FREQ=DAILY;COUNT=2\r\n",
        ));
        assert_eq!(s.zone_kind(), ZoneKind::Unknown);
        let e = s.materialize(
            at("2026-01-01T00:00:00Z"),
            at("2026-02-01T00:00:00Z"),
            &ExpansionLimits::DEFAULT,
        );
        assert_eq!(e.occurrences.len(), 2);
        let local = chrono::Local
            .timestamp_opt(e.occurrences[0].start, 0)
            .unwrap();
        assert_eq!((local.day(), local.hour()), (5, 10));
    }

    /// Una regla que no se entiende —o con un `BYDAY` que no es ASCII, que
    /// hace entrar en pánico a `rrule`— deja la primera vez, marcada.
    #[test]
    fn una_regla_que_no_se_entiende_deja_la_primera_vez() {
        for rule in [
            "FREQ=NUNCA",
            "FREQ=WEEKLY;BYDAY=ñM",
            "FREQ=DAILY;INTERVAL=0",
            "BYDAY=MO",
        ] {
            let s = series(&event(&format!(
                "DTSTART:20260105T100000Z\r\nRRULE:{rule}\r\n"
            )));
            let e = s.materialize(
                at("2026-01-01T00:00:00Z"),
                at("2027-01-01T00:00:00Z"),
                &ExpansionLimits::DEFAULT,
            );
            assert!(e.invalid_rule, "{rule}");
            assert_eq!(starts(&e), vec!["2026-01-05T10:00:00+00:00"], "{rule}");
        }
    }

    /// Los recordatorios: relativos al comienzo o al fin, por cada vez; uno
    /// absoluto, sólo con la primera.
    #[test]
    fn los_recordatorios_se_calculan_por_cada_vez() {
        let s = series(&event(
            "DTSTART:20260105T100000Z\r\nDTEND:20260105T110000Z\r\nRRULE:FREQ=DAILY;COUNT=2\r\n\
             BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nEND:VALARM\r\n\
             BEGIN:VALARM\r\nACTION:AUDIO\r\nTRIGGER;RELATED=END:PT0S\r\nEND:VALARM\r\n\
             BEGIN:VALARM\r\nTRIGGER;VALUE=DATE-TIME:20260104T090000Z\r\nEND:VALARM\r\n",
        ));
        let e = s.materialize(
            at("2026-01-01T00:00:00Z"),
            at("2027-01-01T00:00:00Z"),
            &ExpansionLimits::DEFAULT,
        );
        let first: Vec<(u32, i64, &str)> = e.occurrences[0]
            .alarms
            .iter()
            .map(|a| (a.position, a.at, a.action.as_str()))
            .collect();
        assert_eq!(
            first,
            vec![
                (0, at("2026-01-05T09:45:00Z"), "DISPLAY"),
                (1, at("2026-01-05T11:00:00Z"), "AUDIO"),
                (2, at("2026-01-04T09:00:00Z"), "DISPLAY"),
            ]
        );
        assert_eq!(e.occurrences[1].alarms.len(), 2);
    }

    /// Lo que se ve en un rango, sin lo ya guardado: las veces que empiezan
    /// adentro de `skip` no vuelven.
    #[test]
    fn between_no_repite_lo_ya_guardado() {
        let s = series(&event("DTSTART:20260101T100000Z\r\nRRULE:FREQ=DAILY\r\n"));
        let e = s.between(
            at("2026-01-01T00:00:00Z"),
            at("2026-01-06T00:00:00Z"),
            Some((at("2026-01-02T00:00:00Z"), at("2026-01-05T00:00:00Z"))),
            &ExpansionLimits::DEFAULT,
        );
        assert_eq!(
            starts(&e),
            vec!["2026-01-01T10:00:00+00:00", "2026-01-05T10:00:00+00:00"]
        );
    }

    /// **Que no se dispare.** Una regla por segundo sin fin, una con cada
    /// segundo en `BYSECOND`, un `COUNT` de diez millones desde hace años,
    /// miles de `RDATE` y una por minuto: terminan enseguida, con el tope de
    /// ocurrencias, y marcadas.
    #[test]
    fn una_regla_desmedida_no_se_dispara() {
        let seconds: Vec<String> = (0..60).map(|s| s.to_string()).collect();
        let rdates: Vec<String> = (0..20_000)
            .map(|i| {
                super::super::rfc3339(at("2026-01-01T00:00:00Z") + i * 60)
                    .replace(['-', ':'], "")
                    .replace("+0000", "Z")
            })
            .collect();
        let rules = [
            "RRULE:FREQ=SECONDLY".to_string(),
            format!("RRULE:FREQ=MINUTELY;BYSECOND={}", seconds.join(",")),
            "RRULE:FREQ=SECONDLY;COUNT=10000000".to_string(),
            format!("RDATE:{}", rdates.join(",")),
            // Una por minuto: entra en el tope de fechas, y lo que la frena es
            // el de ocurrencias por objeto.
            "RRULE:FREQ=MINUTELY".to_string(),
        ];
        for rule in rules {
            let ical = event(&format!("DTSTART:20240101T000000Z\r\n{rule}\r\n"));
            let e = finishes_within(StdDuration::from_secs(10), move || {
                series(&ical).materialize(
                    at("2025-09-26T00:00:00Z"),
                    at("2028-09-26T00:00:00Z"),
                    &ExpansionLimits::DEFAULT,
                )
            });
            assert!(e.truncated);
            assert!(e.occurrences.len() <= ExpansionLimits::DEFAULT.max_occurrences);
        }
    }

    fn list(from: u32, to: u32) -> String {
        (from..=to)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// **Una regla que llena un período no se expande.** Una anual con los
    /// doce meses, los 31 días, las 24 horas, los 60 minutos y los 60
    /// segundos: `rrule` arma los 31 millones de fechas del año en la primera
    /// llamada —3 s y 1,5 GB en release, medido— antes de que se mire ningún
    /// tope. Se rechaza antes de dársela: queda la primera vez, `invalid`.
    #[test]
    fn una_regla_que_llena_un_periodo_no_se_expande() {
        let rule = format!(
            "FREQ=YEARLY;BYMONTH={};BYMONTHDAY={};BYHOUR={};BYMINUTE={};BYSECOND={}",
            list(1, 12),
            list(1, 31),
            list(0, 23),
            list(0, 59),
            list(0, 59)
        );
        let ical = event(&format!("DTSTART:20260105T100000Z\r\nRRULE:{rule}\r\n"));
        let e = finishes_within(StdDuration::from_secs(2), move || {
            series(&ical).materialize(
                at("2025-09-26T00:00:00Z"),
                at("2028-09-26T00:00:00Z"),
                &ExpansionLimits::DEFAULT,
            )
        });
        assert!(e.invalid_rule);
        assert_eq!(starts(&e), vec!["2026-01-05T10:00:00+00:00"]);
    }

    /// Lo mismo de a una frecuencia por vez: la mensual con todo el día, la
    /// semanal y la diaria con cada segundo pasan el tope; la horaria con cada
    /// minuto y segundo (3600 por hora) y una anual de días hábiles a toda
    /// hora y media no.
    #[test]
    fn el_tope_por_periodo_mira_cada_frecuencia() {
        let day = format!(
            "BYHOUR={};BYMINUTE={};BYSECOND={}",
            list(0, 23),
            list(0, 59),
            list(0, 59)
        );
        for (rule, rejected) in [
            (
                format!("FREQ=MONTHLY;BYMONTHDAY={};{day}", list(1, 31)),
                true,
            ),
            (
                format!("FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR,SA,SU;{day}"),
                true,
            ),
            (format!("FREQ=DAILY;{day}"), true),
            (
                format!(
                    "FREQ=HOURLY;BYMINUTE={};BYSECOND={}",
                    list(0, 59),
                    list(0, 59)
                ),
                false,
            ),
            (
                format!(
                    "FREQ=YEARLY;BYMONTH={};BYDAY=MO,TU,WE,TH,FR;BYHOUR={};BYMINUTE=0,30",
                    list(1, 12),
                    list(8, 18)
                ),
                false,
            ),
            // Con `BYSETPOS`, `rrule` arma sólo las posiciones.
            (
                format!(
                    "FREQ=YEARLY;BYMONTH={};BYMONTHDAY={};{day};BYSETPOS=1,-1",
                    list(1, 12),
                    list(1, 31)
                ),
                false,
            ),
        ] {
            let ical = event(&format!("DTSTART:20260105T100000Z\r\nRRULE:{rule}\r\n"));
            let e = finishes_within(StdDuration::from_secs(10), move || {
                series(&ical).materialize(
                    at("2025-09-26T00:00:00Z"),
                    at("2028-09-26T00:00:00Z"),
                    &ExpansionLimits::DEFAULT,
                )
            });
            assert_eq!(e.invalid_rule, rejected, "{rule}");
        }
    }

    /// **Un evento de verdad sigue expandiendo**: «el primer lunes de cada mes
    /// a las 9 y a las 15».
    #[test]
    fn el_primer_lunes_de_cada_mes_a_las_nueve_y_a_las_quince_se_expande() {
        let s = series(&event(
            "DTSTART:20260105T090000Z\r\nDURATION:PT1H\r\n\
             RRULE:FREQ=MONTHLY;BYDAY=1MO;BYHOUR=9,15;BYMINUTE=0;BYSECOND=0\r\n",
        ));
        let e = s.materialize(
            at("2026-01-01T00:00:00Z"),
            at("2026-04-01T00:00:00Z"),
            &ExpansionLimits::DEFAULT,
        );
        assert!(!e.invalid_rule && !e.truncated);
        assert_eq!(
            starts(&e),
            vec![
                "2026-01-05T09:00:00+00:00",
                "2026-01-05T15:00:00+00:00",
                "2026-02-02T09:00:00+00:00",
                "2026-02-02T15:00:00+00:00",
                "2026-03-02T09:00:00+00:00",
                "2026-03-02T15:00:00+00:00",
            ]
        );
    }

    /// **La cota cubre lo que arma `rrule` de verdad**: para cada regla, las
    /// fechas de cada período —contadas con `rrule` 0.14, por año, mes, semana
    /// o día— no pasan lo que dice [`dates_per_period`].
    #[test]
    fn la_cota_por_periodo_cubre_lo_que_arma_rrule() {
        use chrono::Datelike;
        let rules = [
            "FREQ=YEARLY",
            "FREQ=YEARLY;BYHOUR=9,15",
            "FREQ=YEARLY;BYMONTH=1,2;BYMONTHDAY=1,2,3,-1;BYHOUR=0,12",
            "FREQ=YEARLY;BYDAY=MO,FR;BYMINUTE=0,20,40",
            "FREQ=YEARLY;BYYEARDAY=1,100,200,-1;BYSECOND=0,30",
            "FREQ=YEARLY;BYWEEKNO=1,2,52;BYHOUR=8",
            "FREQ=YEARLY;BYDAY=-1FR;BYMONTH=3,6,9,12",
            "FREQ=MONTHLY;BYMONTHDAY=1,15,-1;BYHOUR=6,18",
            "FREQ=MONTHLY;BYDAY=MO,TU,WE,TH,FR;BYHOUR=9,10,11",
            "FREQ=MONTHLY;BYDAY=1MO,-1FR;BYHOUR=9,15",
            "FREQ=WEEKLY;BYDAY=MO,WE,FR;BYHOUR=9;BYMINUTE=0,15,30,45",
            "FREQ=WEEKLY",
            "FREQ=DAILY;BYHOUR=0,6,12,18;BYMINUTE=0,30",
            "FREQ=HOURLY;BYMINUTE=0,15,30,45;BYSECOND=0,30",
            "FREQ=MINUTELY;BYSECOND=0,10,20,30,40,50",
            "FREQ=YEARLY;BYDAY=1MO,20MO,-1SU",
            "FREQ=YEARLY;BYMONTHDAY=-1,-2;BYHOUR=1",
            "FREQ=YEARLY;BYMONTH=2;BYMONTHDAY=28,29,30,31;BYDAY=SA,SU",
            "FREQ=MONTHLY;BYDAY=MO,TU,WE,TH,FR;BYSETPOS=1,-1",
            "FREQ=YEARLY;BYMONTH=1;BYMONTHDAY=1,2,3;BYHOUR=1,2;BYSETPOS=2,3,4",
        ];
        let start = chrono::NaiveDate::from_ymd_opt(2026, 1, 5)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap();
        for text in rules {
            let parsed: rrule::RRule<rrule::Unvalidated> = text.parse().unwrap();
            let mut month_days: Vec<i8> = parsed.get_by_month_day().to_vec();
            month_days.sort_unstable();
            month_days.dedup();
            let dt = rrule::Tz::UTC.from_utc_datetime(&start);
            let validated = parsed.validate(dt).unwrap();
            let bound = dates_per_period(&validated, month_days.len() as u64);
            let freq = validated.get_freq();
            let mut per_period: BTreeMap<(i32, u32, u32, u32, u32), u64> = BTreeMap::new();
            for moment in rrule::RRuleSet::new(dt)
                .rrule(validated)
                .limit()
                .into_iter()
                .take(20_000)
            {
                let key = match freq {
                    rrule::Frequency::Yearly => (moment.year(), 0, 0, 0, 0),
                    rrule::Frequency::Monthly => (moment.year(), moment.month(), 0, 0, 0),
                    rrule::Frequency::Weekly => {
                        let week = moment.iso_week();
                        (week.year(), week.week(), 0, 0, 0)
                    }
                    rrule::Frequency::Daily => (moment.year(), moment.ordinal(), 0, 0, 0),
                    rrule::Frequency::Hourly => {
                        (moment.year(), moment.ordinal(), moment.hour(), 0, 0)
                    }
                    rrule::Frequency::Minutely | rrule::Frequency::Secondly => (
                        moment.year(),
                        moment.ordinal(),
                        moment.hour(),
                        moment.minute(),
                        0,
                    ),
                };
                *per_period.entry(key).or_default() += 1;
            }
            let most = per_period.values().copied().max().unwrap_or(0);
            assert!(most > 0, "{text}");
            assert!(
                most <= bound,
                "{text}: {most} fechas en un período, la cota dice {bound}"
            );
        }
    }

    /// Una serie por minuto con quinientas excepciones `THISANDFUTURE`, cada
    /// una con otro título de 800 bytes: el objeto pesa unos 470 KB.
    fn many_this_and_future() -> String {
        let start = at("2025-09-27T00:00:00Z");
        let stamp = |t: i64| {
            super::super::rfc3339(t)
                .replace(['-', ':'], "")
                .replace("+0000", "Z")
        };
        let mut ical = format!(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:s\r\nSUMMARY:serie\r\n\
             DTSTART:{}\r\nDURATION:PT1M\r\nRRULE:FREQ=MINUTELY\r\nEND:VEVENT\r\n",
            stamp(start)
        );
        for i in 0..500 {
            let rid = start + i * 60;
            let title: String = format!("t{i:04}").repeat(160);
            ical.push_str(&format!(
                "BEGIN:VEVENT\r\nUID:s\r\nSUMMARY:{title}\r\n\
                 RECURRENCE-ID;RANGE=THISANDFUTURE:{}\r\nDTSTART:{}\r\n\
                 DURATION:PT1M\r\nEND:VEVENT\r\n",
                stamp(rid),
                stamp(rid + 30)
            ));
        }
        ical.push_str("END:VCALENDAR\r\n");
        ical
    }

    /// **Muchas excepciones que corren la serie terminan en plazo.** Cada
    /// `THISANDFUTURE` le copiaba su título a todas las veces que le seguían:
    /// quinientas por seis mil, 0,69 s en release (el doble del plazo) y sin
    /// mirar el plazo. En una pasada es lineal. Y lo que da sigue siendo lo
    /// mismo: la última vez lleva el título y el corrimiento de la última
    /// excepción.
    #[test]
    fn muchas_excepciones_que_corren_la_serie_terminan_en_plazo() {
        let ical = many_this_and_future();
        assert!(ical.len() < 512 * 1024);
        let s = series(&ical);
        let e = finishes_within(StdDuration::from_secs(60), move || {
            let started = Instant::now();
            let e = s.materialize(
                at("2025-09-26T00:00:00Z"),
                at("2028-09-26T00:00:00Z"),
                &ExpansionLimits::DEFAULT,
            );
            (e, started.elapsed())
        });
        let (e, took) = e;
        assert!(
            took < ExpansionLimits::DEFAULT.max_time,
            "la expansión tardó {took:?}"
        );
        let last = e.occurrences.last().unwrap();
        assert_eq!(last.start - last.recurrence_id, 30);
        assert_eq!(
            series(&many_this_and_future()).title_of(last),
            Some(format!("t{:04}", 499).repeat(160).as_str())
        );
        // Una del medio, la de la excepción 200.
        let middle = &e.occurrences[200];
        assert_eq!(middle.title, Some(200));
    }

    /// Una `THISANDFUTURE` cancelada se lleva todas las que siguen, también
    /// las que una posterior habría corrido —queda sólo la vez que esa
    /// posterior nombra, como toda excepción—; y una anterior corre sólo hasta
    /// ella. Lo mismo que daba la pasada por excepción.
    #[test]
    fn una_thisandfuture_cancelada_se_lleva_las_que_siguen() {
        let ical = "BEGIN:VCALENDAR\r\n\
            BEGIN:VEVENT\r\nUID:s\r\nSUMMARY:Clase\r\nDTSTART:20260105T100000Z\r\n\
            RRULE:FREQ=WEEKLY;COUNT=6\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nUID:s\r\nSUMMARY:Clase corrida\r\n\
            RECURRENCE-ID;RANGE=THISANDFUTURE:20260112T100000Z\r\n\
            DTSTART:20260112T110000Z\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nUID:s\r\nRECURRENCE-ID;RANGE=THISANDFUTURE:20260126T100000Z\r\n\
            DTSTART:20260126T100000Z\r\nSTATUS:CANCELLED\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nUID:s\r\nSUMMARY:Otra\r\n\
            RECURRENCE-ID;RANGE=THISANDFUTURE:20260202T100000Z\r\n\
            DTSTART:20260202T120000Z\r\nEND:VEVENT\r\n\
            END:VCALENDAR\r\n";
        let s = series(ical);
        let e = s.materialize(
            at("2026-01-01T00:00:00Z"),
            at("2027-01-01T00:00:00Z"),
            &ExpansionLimits::DEFAULT,
        );
        assert_eq!(
            starts(&e),
            vec![
                "2026-01-05T10:00:00+00:00",
                "2026-01-12T11:00:00+00:00",
                "2026-01-19T11:00:00+00:00",
                "2026-02-02T12:00:00+00:00",
            ]
        );
        assert_eq!(s.title_of(&e.occurrences[0]), None);
        assert_eq!(s.title_of(&e.occurrences[2]), Some("Clase corrida"));
        assert_eq!(s.title_of(&e.occurrences[3]), Some("Otra"));
    }

    /// **Mil `EXDATE` de día no multiplican el costo.** Una fecha sin hora
    /// saca todas las veces de ese día: una pasada por fecha eran mil pasadas
    /// por las cinco mil veces de una serie por minuto (80 ms en release, un
    /// tercio del plazo, sin mirarlo).
    #[test]
    fn mil_exdate_de_dia_no_multiplican_el_costo() {
        let first = chrono::NaiveDate::from_ymd_opt(2025, 10, 7).unwrap();
        let days: Vec<String> = (0..1000)
            .map(|i| {
                (first + chrono::Duration::days(i))
                    .format("%Y%m%d")
                    .to_string()
            })
            .collect();
        let s = series(&event(&format!(
            "DTSTART:20250927T000000Z\r\nDURATION:PT1M\r\nRRULE:FREQ=MINUTELY\r\n\
             EXDATE;VALUE=DATE:{}\r\n",
            days.join(",")
        )));
        let (e, took) = finishes_within(StdDuration::from_secs(60), move || {
            let started = Instant::now();
            let e = s.materialize(
                at("2025-09-26T00:00:00Z"),
                at("2028-09-26T00:00:00Z"),
                &ExpansionLimits::DEFAULT,
            );
            (e, started.elapsed())
        });
        assert!(
            took < ExpansionLimits::DEFAULT.max_time,
            "la expansión tardó {took:?}"
        );
        // Las de los diez primeros días quedan; las de los días sacados, no.
        assert!(!e.occurrences.is_empty());
        assert!(e
            .occurrences
            .iter()
            .all(|o| o.start < at("2025-10-07T00:00:00Z")));
    }

    /// **El plazo se mira en cada fecha.** Una regla diaria que casi nunca da
    /// una —el 29 de febrero que cae lunes— desde el año 1, con `COUNT`, así
    /// que no hay salto: cada vuelta de `rrule` recorre años de días vacíos, y
    /// hasta el rango no llega a dar ni cien fechas. Mirado cada 256, el plazo
    /// no se mira nunca y la expansión corre entera.
    #[test]
    fn el_plazo_se_mira_en_cada_fecha() {
        let ical = event(
            "DTSTART:00010101T000000Z\r\n\
             RRULE:FREQ=DAILY;COUNT=1000000;BYMONTH=2;BYMONTHDAY=29;BYDAY=MO\r\n",
        );
        let limits = ExpansionLimits {
            max_time: StdDuration::from_millis(5),
            ..ExpansionLimits::DEFAULT
        };
        let e = finishes_within(StdDuration::from_secs(20), move || {
            series(&ical).materialize(
                at("2025-09-26T00:00:00Z"),
                at("2028-09-26T00:00:00Z"),
                &limits,
            )
        });
        assert!(e.truncated, "el plazo tenía que cortar la expansión");
    }
}
