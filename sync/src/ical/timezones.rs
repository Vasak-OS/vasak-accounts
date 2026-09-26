//! Resolver la zona horaria de una fecha de iCalendar.
//!
//! Viene de `vasak-calendar` (`src-tauri/src/zonas.rs`), con sus pruebas y los
//! nombres pasados al inglés. Lo que cambió al mudarse: [`Zones::lookup`] dice
//! si un `TZID` se conoce —el almacén marca el evento cuya zona no se pudo
//! resolver, en vez de moverlo a la hora de la sesión sin decir nada—, y las
//! cuentas con fechas se hacen sin pánico en los bordes del calendario.
//!
//! ── Por qué esto existe ─────────────────────────────────────────────────────
//!
//! Una fecha de iCalendar puede venir de tres formas, y sólo una es un instante
//! sin ambigüedad:
//!
//! - `20260915T140000Z` — UTC. Sin vueltas.
//! - `20260915T140000` con `TZID=America/Argentina/Buenos Aires` — las dos de la
//!   tarde **de esa zona**. Para saber qué instante es hay que saber cuánto
//!   estaba corriendo esa zona ese día, que depende del horario de verano.
//! - `20260915T140000` a secas — hora local flotante (RFC 5545 §3.3.5): «las dos
//!   de donde estés». Un despertador, no una reunión.
//!
//! ── De dónde sale la zona ───────────────────────────────────────────────────
//!
//! De cuatro lugares, en este orden, porque no todos los clientes escriben lo
//! mismo:
//!
//! 1. **El `TZID` es un nombre de IANA** (`Europe/Madrid`). Es lo que escriben
//!    Nextcloud, Google, Apple y Evolution, o sea la enorme mayoría. Se resuelve
//!    con la base de datos de zonas y queda exacto, horario de verano incluido.
//! 2. **El `VTIMEZONE` del archivo trae `X-LIC-LOCATION`** con el nombre de
//!    IANA adentro. Es lo que hace libical cuando el `TZID` es un nombre propio.
//! 3. **El `VTIMEZONE` define una sola observancia**: una zona sin horario de
//!    verano. Su `TZOFFSETTO` es el desplazamiento, y es exacto.
//! 4. **El `VTIMEZONE` define las transiciones con reglas anuales**. Es lo que
//!    escribe Outlook, que pone `TZID:Romance Standard Time` —que no es un
//!    nombre de IANA y nunca lo va a ser— y a cambio manda las reglas completas.
//!    Se interpretan acá.
//!
//! Si no se puede con ninguna, se usa el desplazamiento de la observancia
//! estándar. Quedar corrido una hora la mitad del año es mucho mejor que quedar
//! corrido el desplazamiento entero todo el año.
//!
//! **Un nombre de Windows sin su `VTIMEZONE` no se resuelve**: no hay tabla de
//! nombres de Windows a IANA. Cae como zona desconocida (ver [`Zones::lookup`]).
//!
//! ── Qué sigue sin estar bien ────────────────────────────────────────────────
//!
//! **La hora que no existe y la que pasa dos veces.** Cuando adelanta el reloj
//! hay una hora local que no ocurre, y cuando atrasa hay una que ocurre dos
//! veces. Un evento escrito ahí adentro es ambiguo en el formato mismo, no acá.
//! Se elige la primera de las dos y se corre hacia adelante la que no existe;
//! está en [`Zone::to_utc`] con más detalle.
//!
//! **`RDATE` en un `VTIMEZONE`.** Algunas zonas históricas listan sus
//! transiciones una por una en vez de con una regla. No se leen: esas zonas caen
//! al respaldo de la observancia estándar. Es raro y sólo afecta a fechas
//! viejas.

use std::collections::HashMap;

use chrono::{
    DateTime, Datelike, Duration, FixedOffset, LocalResult, NaiveDate, NaiveDateTime, NaiveTime,
    Offset, TimeZone, Utc, Weekday,
};
use chrono_tz::Tz;

use super::{split_line, unfold_lines};

/// Tope de `VTIMEZONE` que se leen de un archivo.
///
/// Un calendario real tiene una zona, o unas pocas. Doscientas es un archivo
/// armado para hacer trabajar al programa.
const MAX_ZONES: usize = 200;

/// Tope de observancias dentro de una zona.
///
/// Dos es lo normal —estándar y verano—; una zona con historia puede tener
/// algunas más.
const MAX_OBSERVANCES: usize = 64;

/// Cómo se convierte una hora local a un instante.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Zone {
    /// La fecha ya venía en UTC.
    Utc,
    /// Una zona con nombre, de la base de datos de IANA.
    Iana(Tz),
    /// Un desplazamiento fijo: una zona sin horario de verano.
    Fixed(FixedOffset),
    /// Las reglas de transición que venían en el `VTIMEZONE` del archivo.
    Rules(Rules),
    /// Hora local flotante: la zona de quien esté mirando.
    Floating,
}

impl Zone {
    /// Pasa una hora local de esta zona al instante que le corresponde.
    ///
    /// ── Las dos horas raras del año ─────────────────────────────────────────
    ///
    /// Cuando el reloj adelanta, una hora local **no existe**: si el salto es a
    /// las 2 y va a las 3, las 2:30 no ocurren. Y cuando atrasa, una hora local
    /// **ocurre dos veces**.
    ///
    /// Un evento escrito ahí adentro es ambiguo en el archivo, no acá: el
    /// formato no da forma de distinguirlas. Se hace lo mismo que hace todo el
    /// mundo, y se elige así porque es lo que menos sorprende:
    ///
    /// - La que ocurre dos veces se toma como **la primera**, que es la que la
    ///   persona quiso decir si escribió el evento antes del cambio.
    /// - La que no existe se corre **hacia adelante** hasta la hora que sí
    ///   existe, que es lo que hace un despertador. Devolver «no se pudo» en
    ///   cambio haría desaparecer el evento del mes, que es peor.
    ///
    /// Fuera de lo que `chrono` puede representar devuelve `None`, sin pánico:
    /// la fecha la escribió quien mandó el archivo.
    pub fn to_utc(&self, local: NaiveDateTime) -> Option<DateTime<Utc>> {
        // Los años que puede escribir iCalendar: cuatro cifras. Afuera de eso
        // no hay evento que mostrar, y las cuentas de abajo se acercan a los
        // bordes de `chrono`.
        if !(1..=9999).contains(&local.year()) {
            return None;
        }
        match self {
            Zone::Utc => Some(Utc.from_utc_datetime(&local)),
            Zone::Iana(tz) => resolve_tolerant(local, |moment| tz.from_local_datetime(moment)),
            Zone::Fixed(offset) => local
                .checked_sub_offset(*offset)
                .map(|utc| Utc.from_utc_datetime(&utc)),
            Zone::Rules(rules) => {
                let offset = rules.offset_at(local);
                local
                    .checked_sub_offset(offset)
                    .map(|utc| Utc.from_utc_datetime(&utc))
            }
            Zone::Floating => {
                resolve_tolerant(local, |moment| chrono::Local.from_local_datetime(moment))
            }
        }
    }
}

/// Resuelve una hora local aguantando las dos horas raras del año.
///
/// Ver la explicación en [`Zone::to_utc`]. Lo único que tiene truco es la hora
/// que **no existe**: para correrla hay que saber cuánto saltó el reloj, y eso
/// se averigua mirando qué desplazamiento corría el día anterior y cuál el día
/// siguiente. La diferencia es el salto.
///
/// Se hace así y no probando de a una hora porque el salto no siempre es de una
/// hora —Lord Howe salta media— y porque correr el evento el tamaño exacto del
/// salto le conserva los minutos: una reunión de las 2:30 pasa a ser de las
/// 3:30, no de las 3 en punto.
fn resolve_tolerant<Z, F>(local: NaiveDateTime, resolve: F) -> Option<DateTime<Utc>>
where
    Z: TimeZone,
    F: Fn(&NaiveDateTime) -> LocalResult<DateTime<Z>>,
{
    // `earliest()` es la primera de las dos cuando la hora ocurre dos veces, y
    // la única cuando ocurre una sola.
    if let Some(moment) = resolve(&local).earliest() {
        return Some(moment.with_timezone(&Utc));
    }

    let one_day = Duration::days(1);
    let before = resolve(&local.checked_sub_signed(one_day)?)
        .earliest()?
        .offset()
        .fix()
        .local_minus_utc();
    let after = resolve(&local.checked_add_signed(one_day)?)
        .earliest()?
        .offset()
        .fix()
        .local_minus_utc();
    let jump = Duration::seconds((after - before).into());

    // Un salto que no es hacia adelante no explica el agujero. No se insiste:
    // devolver algo inventado sería peor que no mostrar la hora.
    if jump <= Duration::zero() {
        return None;
    }
    resolve(&local.checked_add_signed(jump)?)
        .earliest()
        .map(|moment| moment.with_timezone(&Utc))
}

/// Las reglas de transición de un `VTIMEZONE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rules {
    observances: Vec<Observance>,
}

impl Rules {
    /// Qué desplazamiento corría en esta zona a esa hora local.
    ///
    /// ── Cómo se compara ─────────────────────────────────────────────────────
    ///
    /// Cada transición se expresa en el reloj de pared **anterior** al cambio,
    /// que es como la define el formato. Se arman las transiciones de tres años
    /// —el anterior, el de la fecha y el siguiente, porque en el hemisferio sur
    /// el verano cruza el año— y se busca la última que ya pasó.
    ///
    /// Dentro de la hora del cambio esto puede errar por una hora, que es la
    /// misma ambigüedad que describe [`Zone::to_utc`] y que no tiene respuesta
    /// mejor.
    fn offset_at(&self, local: NaiveDateTime) -> FixedOffset {
        let mut transitions: Vec<(NaiveDateTime, FixedOffset, FixedOffset)> = Vec::new();
        for observance in &self.observances {
            for year in [local.year() - 1, local.year(), local.year() + 1] {
                if let Some(when) = observance.transition_in(year) {
                    transitions.push((when, observance.from, observance.to));
                }
            }
        }
        transitions.sort_by_key(|(when, _, _)| *when);

        match transitions.iter().rev().find(|(when, _, _)| *when <= local) {
            Some((_, _, to)) => *to,
            // Antes de la primera transición conocida corría lo que esa
            // transición dejó atrás.
            None => match transitions.first() {
                Some((_, from, _)) => *from,
                None => self.standard_offset(),
            },
        }
    }

    /// El respaldo: el desplazamiento de la observancia estándar.
    ///
    /// Se usa cuando ninguna observancia tiene una regla que se pueda calcular
    /// —una zona definida sólo con `RDATE`, por ejemplo—. Quedar corrido una
    /// hora los meses de verano es mucho mejor que quedar corrido el
    /// desplazamiento entero todo el año.
    fn standard_offset(&self) -> FixedOffset {
        self.observances
            .iter()
            .find(|o| !o.is_daylight)
            .or_else(|| self.observances.first())
            .map(|o| o.to)
            .unwrap_or_else(|| FixedOffset::east_opt(0).expect("cero es un desplazamiento válido"))
    }
}

/// Una observancia de un `VTIMEZONE`: el `STANDARD` o el `DAYLIGHT`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Observance {
    is_daylight: bool,
    /// `TZOFFSETFROM`: lo que corría antes de esta transición.
    from: FixedOffset,
    /// `TZOFFSETTO`: lo que corre después.
    to: FixedOffset,
    /// Desde cuándo vale, y a qué hora del día cae la transición.
    start: NaiveDateTime,
    /// La regla anual, si se pudo entender.
    rule: Option<YearlyRule>,
}

impl Observance {
    /// Cuándo cae esta transición en un año, en el reloj de pared anterior al
    /// cambio.
    fn transition_in(&self, year: i32) -> Option<NaiveDateTime> {
        match &self.rule {
            Some(rule) => rule
                .date_in(year)
                .map(|day| day.and_time(self.start.time())),
            // Sin regla la observancia vale desde su `DTSTART` y no se repite.
            // Sirve igual: una zona de desplazamiento fijo entra por acá.
            None => (self.start.year() == year).then_some(self.start),
        }
    }
}

/// Una regla anual de transición, que es lo único que aparece en un
/// `VTIMEZONE` real.
#[derive(Debug, Clone, PartialEq, Eq)]
enum YearlyRule {
    /// «El último domingo de octubre»: `FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU`.
    Weekday {
        month: u32,
        ordinal: i32,
        day: Weekday,
    },
    /// «El 1 de enero»: `FREQ=YEARLY;BYMONTH=1;BYMONTHDAY=1`.
    MonthDay { month: u32, day: u32 },
}

impl YearlyRule {
    fn date_in(&self, year: i32) -> Option<NaiveDate> {
        match self {
            YearlyRule::MonthDay { month, day } => NaiveDate::from_ymd_opt(year, *month, *day),
            YearlyRule::Weekday {
                month,
                ordinal,
                day,
            } => nth_weekday_of_month(year, *month, *ordinal, *day),
        }
    }
}

/// El *n*-ésimo día de semana de un mes, contando desde el final si *n* es
/// negativo.
///
/// `(-1, domingo)` es «el último domingo», que es como se escribe casi todo
/// cambio de horario del mundo. `(1, domingo)` es el primero.
///
/// Devuelve `None` si ese día no existe —«el quinto domingo» de un mes que tiene
/// cuatro—, en vez de correrlo al mes siguiente.
fn nth_weekday_of_month(year: i32, month: u32, ordinal: i32, day: Weekday) -> Option<NaiveDate> {
    if ordinal == 0 {
        return None;
    }

    if ordinal > 0 {
        let first = NaiveDate::from_ymd_opt(year, month, 1)?;
        let skip = (7 + day.num_days_from_monday() as i64
            - first.weekday().num_days_from_monday() as i64)
            % 7;
        let date = first.checked_add_signed(Duration::days(skip + (ordinal as i64 - 1) * 7))?;
        return (date.month() == month).then_some(date);
    }

    let last = last_day_of_month(year, month)?;
    let back =
        (7 + last.weekday().num_days_from_monday() as i64 - day.num_days_from_monday() as i64) % 7;
    let date = last.checked_sub_signed(Duration::days(back + (-ordinal as i64 - 1) * 7))?;
    (date.month() == month).then_some(date)
}

fn last_day_of_month(year: i32, month: u32) -> Option<NaiveDate> {
    let (next_year, next_month) = if month == 12 {
        (year.checked_add(1)?, 1)
    } else {
        (year, month + 1)
    };
    NaiveDate::from_ymd_opt(next_year, next_month, 1)?.pred_opt()
}

// ---------------------------------------------------------------------------
// Leer los VTIMEZONE del archivo
// ---------------------------------------------------------------------------

/// Las zonas que definía un archivo de iCalendar, por `TZID`.
///
/// Se arma una vez por archivo y se consulta por cada fecha. Vacía es válida y
/// es el caso normal: un `TZID` que sea nombre de IANA no necesita nada de acá.
#[derive(Debug, Clone, Default)]
pub struct Zones(HashMap<String, Zone>);

impl Zones {
    /// Cómo se resuelve una fecha con este `TZID`.
    ///
    /// El orden está explicado arriba, en la cabecera del módulo. Un `TZID` que
    /// no se pueda resolver de ninguna forma cae en [`Zone::Floating`]: mostrar
    /// el evento a la hora local de quien mira es lo más parecido a lo que
    /// quiso decir quien lo escribió, y no lo corre a otro día. Quien necesite
    /// saber que pasó eso pregunta con [`Self::lookup`].
    #[cfg(test)]
    pub fn resolve(&self, tzid: &str) -> Zone {
        self.lookup(tzid).unwrap_or(Zone::Floating)
    }

    /// Como [`Self::resolve`], pero `None` si el `TZID` no es de IANA ni lo
    /// define el archivo. Un `TZID` vacío es flotante, no desconocido.
    pub fn lookup(&self, tzid: &str) -> Option<Zone> {
        let tzid = unquote(tzid.trim());
        if tzid.is_empty() {
            return Some(Zone::Floating);
        }
        if let Ok(tz) = tzid.parse::<Tz>() {
            return Some(Zone::Iana(tz));
        }
        self.0.get(tzid).cloned()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.len()
    }
}

/// Lee los `VTIMEZONE` de un iCalendar.
///
/// En una pasada aparte de la de los eventos, y no en la misma, porque un
/// `VTIMEZONE` puede venir **después** del evento que lo usa: el formato no fija
/// el orden y hay servidores que los ponen al final.
pub fn zones_from(ical: &str) -> Zones {
    let mut zones: HashMap<String, Zone> = HashMap::new();

    let mut tzid: Option<String> = None;
    let mut location: Option<String> = None;
    let mut observances: Vec<Observance> = Vec::new();
    let mut open = false;
    let mut inside: Option<RawObservance> = None;

    for line in unfold_lines(ical) {
        let Some((name, _, value)) = split_line(&line) else {
            continue;
        };
        let value = value.trim();

        match (name.as_str(), value.to_ascii_uppercase().as_str()) {
            ("BEGIN", "VTIMEZONE") => {
                open = true;
                tzid = None;
                location = None;
                observances.clear();
                inside = None;
                continue;
            }
            ("END", "VTIMEZONE") if open => {
                open = false;
                if zones.len() >= MAX_ZONES {
                    continue;
                }
                if let Some(id) = tzid.take() {
                    if let Some(zone) =
                        build_zone(&id, location.take(), std::mem::take(&mut observances))
                    {
                        zones.insert(id, zone);
                    }
                }
                continue;
            }
            ("BEGIN", "STANDARD") | ("BEGIN", "DAYLIGHT") if open => {
                inside = Some(RawObservance {
                    is_daylight: value.eq_ignore_ascii_case("DAYLIGHT"),
                    ..Default::default()
                });
                continue;
            }
            ("END", "STANDARD") | ("END", "DAYLIGHT") if open => {
                if let Some(raw) = inside.take() {
                    if observances.len() < MAX_OBSERVANCES {
                        if let Some(observance) = raw.finish() {
                            observances.push(observance);
                        }
                    }
                }
                continue;
            }
            _ => {}
        }

        if !open {
            continue;
        }

        match inside.as_mut() {
            // Dentro de un STANDARD o un DAYLIGHT.
            Some(raw) => match name.as_str() {
                "TZOFFSETFROM" => raw.from = parse_offset(value),
                "TZOFFSETTO" => raw.to = parse_offset(value),
                "DTSTART" => raw.start = parse_local(value),
                "RRULE" => raw.rule = parse_yearly_rule(value),
                _ => {}
            },
            // Directamente dentro del VTIMEZONE.
            None => match name.as_str() {
                "TZID" => tzid = Some(unquote(value).to_string()),
                // Lo que escribe libical cuando el `TZID` no es de IANA: el
                // nombre de IANA de verdad, adentro.
                "X-LIC-LOCATION" => location = Some(value.to_string()),
                _ => {}
            },
        }
    }

    Zones(zones)
}

/// Decide con qué se resuelve una zona, con los cuatro caminos de la cabecera.
fn build_zone(tzid: &str, location: Option<String>, observances: Vec<Observance>) -> Option<Zone> {
    // El `TZID` mismo, por si el archivo define una zona que además tiene nombre
    // de IANA. La base de datos sabe más que el archivo: tiene la historia
    // completa y el archivo suele traer sólo la regla vigente.
    if let Ok(tz) = tzid.parse::<Tz>() {
        return Some(Zone::Iana(tz));
    }
    if let Some(tz) = location.and_then(|u| u.trim().parse::<Tz>().ok()) {
        return Some(Zone::Iana(tz));
    }
    if observances.is_empty() {
        return None;
    }
    // Una sola observancia es una zona sin horario de verano: su desplazamiento
    // es el desplazamiento, sin más.
    if observances.len() == 1 {
        return Some(Zone::Fixed(observances[0].to));
    }
    Some(Zone::Rules(Rules { observances }))
}

#[derive(Default)]
struct RawObservance {
    is_daylight: bool,
    from: Option<FixedOffset>,
    to: Option<FixedOffset>,
    start: Option<NaiveDateTime>,
    rule: Option<YearlyRule>,
}

impl RawObservance {
    fn finish(self) -> Option<Observance> {
        // Sin `TZOFFSETTO` la observancia no dice nada: es el único campo del
        // que no se puede prescindir.
        let to = self.to?;
        Some(Observance {
            is_daylight: self.is_daylight,
            from: self.from.unwrap_or(to),
            to,
            // Sin `DTSTART` se toma la medianoche del año cero del formato, que
            // es lo que hace que la regla anual mande y la transición caiga a
            // las 00:00.
            start: self.start.unwrap_or_else(|| {
                NaiveDate::from_ymd_opt(1601, 1, 1)
                    .expect("1601-01-01 existe")
                    .and_time(NaiveTime::MIN)
            }),
            rule: self.rule,
        })
    }
}

/// Lee un `TZOFFSETFROM`/`TZOFFSETTO`: `+0200`, `-0330`, `+020000`.
fn parse_offset(value: &str) -> Option<FixedOffset> {
    let value = value.trim();
    let (sign, rest) = match value.chars().next()? {
        '+' => (1, &value[1..]),
        '-' => (-1, &value[1..]),
        // Sin signo no es un desplazamiento válido, y adivinar que es positivo
        // sería adivinar el hemisferio.
        _ => return None,
    };
    if !rest.chars().all(|c| c.is_ascii_digit()) || (rest.len() != 4 && rest.len() != 6) {
        return None;
    }

    let hours: i32 = rest[0..2].parse().ok()?;
    let minutes: i32 = rest[2..4].parse().ok()?;
    let seconds: i32 = if rest.len() == 6 {
        rest[4..6].parse().ok()?
    } else {
        0
    };
    if minutes > 59 || seconds > 59 {
        return None;
    }

    FixedOffset::east_opt(sign * (hours * 3600 + minutes * 60 + seconds))
}

/// Lee el `DTSTART` de una observancia, que siempre es hora local sin zona.
fn parse_local(value: &str) -> Option<NaiveDateTime> {
    super::parse_naive_datetime(value.trim())
}

/// Lee la regla anual de una observancia.
///
/// Sólo el subconjunto que aparece en un `VTIMEZONE`: `FREQ=YEARLY` con un mes y
/// un día de semana, o con un mes y un día del mes. Cualquier otra cosa devuelve
/// `None` y la zona cae al respaldo, que es mejor que interpretarla a medias.
fn parse_yearly_rule(value: &str) -> Option<YearlyRule> {
    let mut yearly = false;
    let mut month = None;
    let mut month_day = None;
    let mut weekday = None;

    for part in value.split(';') {
        // Un punto y coma de más —`BYDAY=-1SU;`— deja un pedazo vacío. No es un
        // pedazo que no se entienda: no hay nada ahí. Descartar la regla entera
        // por eso mandaría una zona perfectamente legible al respaldo.
        if part.trim().is_empty() {
            continue;
        }
        let (name, content) = part.split_once('=')?;
        match name.trim().to_ascii_uppercase().as_str() {
            "FREQ" => yearly = content.trim().eq_ignore_ascii_case("YEARLY"),
            "BYMONTH" => {
                month = content
                    .trim()
                    .parse::<u32>()
                    .ok()
                    .filter(|m| (1..=12).contains(m))
            }
            "BYMONTHDAY" => {
                month_day = content
                    .trim()
                    .parse::<u32>()
                    .ok()
                    .filter(|d| (1..=31).contains(d))
            }
            "BYDAY" => weekday = parse_weekday(content.trim()),
            // `INTERVAL`, `UNTIL` y `COUNT` en un `VTIMEZONE` son rarísimos y
            // cambiarían el resultado, así que se descarta la regla entera en
            // vez de ignorarlos.
            "INTERVAL" | "UNTIL" | "COUNT" => return None,
            _ => {}
        }
    }

    if !yearly {
        return None;
    }
    let month = month?;
    match (weekday, month_day) {
        (Some((ordinal, day)), _) => Some(YearlyRule::Weekday {
            month,
            ordinal,
            day,
        }),
        (None, Some(day)) => Some(YearlyRule::MonthDay { month, day }),
        (None, None) => None,
    }
}

/// Cuántas veces puede aparecer un día de semana en un mes.
///
/// Cinco, y por eso `BYDAY` en una transición sólo admite de -5 a 5 sin el cero.
/// No es una restricción de estilo: sin ella, un `BYDAY=999999999SU` de un
/// archivo cualquiera hace que el cálculo del día **entre en pánico** al sumarle
/// esos años a una fecha, y un archivo lo escribe quien quiera.
const MAX_ORDINAL: i32 = 5;

/// Lee un `BYDAY`: `-1SU`, `2MO`, `SU`.
///
/// Sin número adelante es «todos los domingos del mes», que en una transición
/// no quiere decir nada; se toma como el primero, que es lo que hacen los pocos
/// archivos que lo escriben así.
fn parse_weekday(value: &str) -> Option<(i32, Weekday)> {
    // Una lista —`MO,TU`— no define una transición única. Se descarta.
    if value.contains(',') {
        return None;
    }
    // **Sólo ASCII**, y no por purismo: los dos últimos octetos de un valor con
    // acentos pueden caer en medio de un carácter, y cortar ahí entra en pánico.
    // Un `BYDAY` válido son dos letras y un número, así que nada se pierde.
    if !value.is_ascii() {
        return None;
    }
    let cut = value.len().checked_sub(2)?;
    let (prefix, day) = value.split_at(cut);

    let day = weekday_from_code(day)?;
    let ordinal = if prefix.is_empty() {
        1
    } else {
        prefix.parse::<i32>().ok()?
    };
    // `unsigned_abs` y no `abs`: `-2147483648` se lee, y `i32::MIN.abs()`
    // desborda —en debug, pánico; en release, sigue negativo y pasa el tope—.
    (ordinal != 0 && ordinal.unsigned_abs() <= MAX_ORDINAL.unsigned_abs()).then_some((ordinal, day))
}

/// `MO` → lunes, … `SU` → domingo, sin mirar mayúsculas.
pub fn weekday_from_code(code: &str) -> Option<Weekday> {
    Some(match code.to_ascii_uppercase().as_str() {
        "MO" => Weekday::Mon,
        "TU" => Weekday::Tue,
        "WE" => Weekday::Wed,
        "TH" => Weekday::Thu,
        "FR" => Weekday::Fri,
        "SA" => Weekday::Sat,
        "SU" => Weekday::Sun,
        _ => return None,
    })
}

/// Saca las comillas de un valor de parámetro.
///
/// Un `TZID` con barras o espacios viene entre comillas —`TZID="America/New
/// York"`— y el nombre de la zona es lo de adentro.
pub fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lo que escriben Nextcloud, Google y Apple: el nombre de IANA en el
    /// `TZID`, sin que haga falta mirar el `VTIMEZONE`.
    #[test]
    fn un_tzid_de_iana_se_resuelve_solo() {
        let zones = Zones::default();
        let zone = zones.resolve("America/Argentina/Buenos_Aires");
        assert_eq!(
            zone,
            Zone::Iana(chrono_tz::America::Argentina::Buenos_Aires)
        );

        // Las dos de la tarde en Buenos Aires son las cinco UTC, no las dos.
        let local = NaiveDate::from_ymd_opt(2026, 9, 15)
            .unwrap()
            .and_hms_opt(14, 0, 0)
            .unwrap();
        assert_eq!(
            zone.to_utc(local).unwrap().to_rfc3339(),
            "2026-09-15T17:00:00+00:00"
        );
    }

    /// El mismo `TZID` entre comillas, que es como viene cuando tiene barras.
    #[test]
    fn el_tzid_puede_venir_entre_comillas() {
        let zones = Zones::default();
        assert_eq!(
            zones.resolve(r#""Europe/Madrid""#),
            Zone::Iana(chrono_tz::Europe::Madrid)
        );
    }

    /// El horario de verano cambia el resultado. Madrid corre +1 en invierno y
    /// +2 en verano, así que la misma hora local da dos instantes distintos.
    #[test]
    fn el_horario_de_verano_cambia_el_instante() {
        let zone = Zones::default().resolve("Europe/Madrid");

        let winter = NaiveDate::from_ymd_opt(2026, 1, 15)
            .unwrap()
            .and_hms_opt(9, 0, 0)
            .unwrap();
        assert_eq!(
            zone.to_utc(winter).unwrap().to_rfc3339(),
            "2026-01-15T08:00:00+00:00"
        );

        let summer = NaiveDate::from_ymd_opt(2026, 7, 15)
            .unwrap()
            .and_hms_opt(9, 0, 0)
            .unwrap();
        assert_eq!(
            zone.to_utc(summer).unwrap().to_rfc3339(),
            "2026-07-15T07:00:00+00:00"
        );
    }

    /// Lo que escribe Outlook: un `TZID` que no es de IANA y las reglas
    /// completas al lado.
    pub(crate) const ROMANCE: &str = "BEGIN:VCALENDAR\r\n\
        BEGIN:VTIMEZONE\r\n\
        TZID:Romance Standard Time\r\n\
        BEGIN:STANDARD\r\n\
        DTSTART:16010101T030000\r\n\
        TZOFFSETFROM:+0200\r\n\
        TZOFFSETTO:+0100\r\n\
        RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10\r\n\
        END:STANDARD\r\n\
        BEGIN:DAYLIGHT\r\n\
        DTSTART:16010101T020000\r\n\
        TZOFFSETFROM:+0100\r\n\
        TZOFFSETTO:+0200\r\n\
        RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=3\r\n\
        END:DAYLIGHT\r\n\
        END:VTIMEZONE\r\n\
        END:VCALENDAR\r\n";

    #[test]
    fn las_reglas_de_outlook_se_interpretan() {
        let zones = zones_from(ROMANCE);
        let zone = zones.resolve("Romance Standard Time");
        assert!(matches!(zone, Zone::Rules(_)), "{zone:?}");

        // Invierno: +1. En 2026 el cambio a verano es el 29 de marzo.
        let winter = NaiveDate::from_ymd_opt(2026, 1, 15)
            .unwrap()
            .and_hms_opt(9, 0, 0)
            .unwrap();
        assert_eq!(
            zone.to_utc(winter).unwrap().to_rfc3339(),
            "2026-01-15T08:00:00+00:00"
        );

        // Verano: +2.
        let summer = NaiveDate::from_ymd_opt(2026, 7, 15)
            .unwrap()
            .and_hms_opt(9, 0, 0)
            .unwrap();
        assert_eq!(
            zone.to_utc(summer).unwrap().to_rfc3339(),
            "2026-07-15T07:00:00+00:00"
        );
    }

    /// Y da lo mismo que la zona de IANA equivalente, que es la prueba de que
    /// las reglas se calcularon bien y no de casualidad.
    #[test]
    fn las_reglas_de_outlook_coinciden_con_la_base_de_datos() {
        let from_rules = zones_from(ROMANCE).resolve("Romance Standard Time");
        let from_iana = Zones::default().resolve("Europe/Madrid");

        for (month, day) in [
            (1, 15),
            (3, 28),
            (4, 2),
            (7, 15),
            (10, 24),
            (11, 2),
            (12, 31),
        ] {
            let local = NaiveDate::from_ymd_opt(2026, month, day)
                .unwrap()
                .and_hms_opt(9, 0, 0)
                .unwrap();
            assert_eq!(
                from_rules.to_utc(local),
                from_iana.to_utc(local),
                "el {day}/{month} no coincide"
            );
        }
    }

    /// El hemisferio sur: el verano cruza el año, así que las transiciones del
    /// año anterior tienen que entrar en la cuenta.
    #[test]
    fn una_zona_del_sur_con_verano_a_caballo_del_anio() {
        let ical = "BEGIN:VTIMEZONE\r\n\
            TZID:Zona del sur\r\n\
            BEGIN:STANDARD\r\n\
            DTSTART:16010101T030000\r\n\
            TZOFFSETFROM:-0300\r\n\
            TZOFFSETTO:-0400\r\n\
            RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=4\r\n\
            END:STANDARD\r\n\
            BEGIN:DAYLIGHT\r\n\
            DTSTART:16010101T020000\r\n\
            TZOFFSETFROM:-0400\r\n\
            TZOFFSETTO:-0300\r\n\
            RRULE:FREQ=YEARLY;BYDAY=1SU;BYMONTH=9\r\n\
            END:DAYLIGHT\r\n\
            END:VTIMEZONE\r\n";
        let zone = zones_from(ical).resolve("Zona del sur");

        // Enero está del lado del verano que empezó en septiembre **del año
        // anterior**: -3. Sin mirar el año anterior daría -4.
        let january = NaiveDate::from_ymd_opt(2026, 1, 15)
            .unwrap()
            .and_hms_opt(9, 0, 0)
            .unwrap();
        assert_eq!(
            zone.to_utc(january).unwrap().to_rfc3339(),
            "2026-01-15T12:00:00+00:00"
        );

        // Junio es invierno: -4.
        let june = NaiveDate::from_ymd_opt(2026, 6, 15)
            .unwrap()
            .and_hms_opt(9, 0, 0)
            .unwrap();
        assert_eq!(
            zone.to_utc(june).unwrap().to_rfc3339(),
            "2026-06-15T13:00:00+00:00"
        );
    }

    /// Una zona sin horario de verano: una sola observancia y su desplazamiento.
    #[test]
    fn una_zona_sin_verano_es_un_desplazamiento_fijo() {
        let ical = "BEGIN:VTIMEZONE\r\n\
            TZID:Zona quieta\r\n\
            BEGIN:STANDARD\r\n\
            DTSTART:16010101T000000\r\n\
            TZOFFSETFROM:-0300\r\n\
            TZOFFSETTO:-0300\r\n\
            END:STANDARD\r\n\
            END:VTIMEZONE\r\n";
        let zone = zones_from(ical).resolve("Zona quieta");
        assert_eq!(zone, Zone::Fixed(FixedOffset::east_opt(-3 * 3600).unwrap()));

        let local = NaiveDate::from_ymd_opt(2026, 9, 15)
            .unwrap()
            .and_hms_opt(14, 0, 0)
            .unwrap();
        assert_eq!(
            zone.to_utc(local).unwrap().to_rfc3339(),
            "2026-09-15T17:00:00+00:00"
        );
    }

    /// Lo que escribe libical: nombre propio en el `TZID` y el de IANA adentro.
    #[test]
    fn el_x_lic_location_da_el_nombre_de_iana() {
        let ical = "BEGIN:VTIMEZONE\r\n\
            TZID:/freeassociation.sourceforge.net/Europe/Madrid\r\n\
            X-LIC-LOCATION:Europe/Madrid\r\n\
            BEGIN:STANDARD\r\n\
            TZOFFSETFROM:+0200\r\n\
            TZOFFSETTO:+0100\r\n\
            END:STANDARD\r\n\
            END:VTIMEZONE\r\n";
        let zone = zones_from(ical).resolve("/freeassociation.sourceforge.net/Europe/Madrid");
        assert_eq!(zone, Zone::Iana(chrono_tz::Europe::Madrid));
    }

    /// Un `VTIMEZONE` puede venir después del evento que lo usa. Por eso se lee
    /// en una pasada aparte.
    #[test]
    fn la_zona_se_encuentra_aunque_venga_despues_del_evento() {
        let ical = format!(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:1\r\n\
             DTSTART;TZID=Romance Standard Time:20260715T090000\r\nEND:VEVENT\r\n{}",
            ROMANCE
                .trim_start_matches("BEGIN:VCALENDAR\r\n")
                .trim_end_matches("END:VCALENDAR\r\n")
        );
        assert!(matches!(
            zones_from(&ical).resolve("Romance Standard Time"),
            Zone::Rules(_)
        ));
    }

    /// Un `TZID` que no se conoce y que el archivo no define: se muestra a la
    /// hora local de quien mira, que es lo más parecido a lo que quiso decir
    /// quien lo escribió.
    #[test]
    fn un_tzid_desconocido_queda_flotante() {
        assert_eq!(Zones::default().resolve("Zona Inventada"), Zone::Floating);
        // Y quien pregunta puede saber que no se conocía: el almacén lo marca.
        assert_eq!(Zones::default().lookup("Zona Inventada"), None);
        assert_eq!(Zones::default().lookup(""), Some(Zone::Floating));
    }

    /// Una fecha sin `Z` y sin `TZID` es hora local flotante: «las nueve de
    /// donde estés». Tratarla como UTC la corría el desplazamiento entero.
    ///
    /// La prueba se escribe contra la zona de la máquina a propósito: es la
    /// definición misma de flotante, y así no depende de en qué zona corra.
    #[test]
    fn una_hora_flotante_es_la_de_la_sesion() {
        let local = NaiveDate::from_ymd_opt(2026, 9, 15)
            .unwrap()
            .and_hms_opt(9, 0, 0)
            .unwrap();
        let expected = chrono::Local
            .from_local_datetime(&local)
            .earliest()
            .expect("las 9 de la mañana existen en cualquier zona")
            .with_timezone(&Utc);

        assert_eq!(Zone::Floating.to_utc(local), Some(expected));
    }

    #[test]
    fn los_desplazamientos_se_leen_en_sus_tres_formas() {
        assert_eq!(parse_offset("+0200"), FixedOffset::east_opt(2 * 3600));
        assert_eq!(
            parse_offset("-0330"),
            FixedOffset::east_opt(-(3 * 3600 + 30 * 60))
        );
        assert_eq!(parse_offset("+020000"), FixedOffset::east_opt(2 * 3600));
        assert_eq!(parse_offset("-0000"), FixedOffset::east_opt(0));
    }

    /// Sin signo no es un desplazamiento: adivinar que es positivo sería
    /// adivinar el hemisferio.
    #[test]
    fn un_desplazamiento_roto_no_se_adivina() {
        for garbage in ["0200", "", "+2", "+02:00", "+0270", "hola", "+02000"] {
            assert_eq!(parse_offset(garbage), None, "{garbage:?}");
        }
    }

    #[test]
    fn el_ultimo_domingo_del_mes_se_calcula_bien() {
        // Octubre de 2026 termina un sábado; el último domingo es el 25.
        let last = nth_weekday_of_month(2026, 10, -1, Weekday::Sun).unwrap();
        assert_eq!(last, NaiveDate::from_ymd_opt(2026, 10, 25).unwrap());

        // El primer domingo de marzo de 2026 es el 1.
        let first = nth_weekday_of_month(2026, 3, 1, Weekday::Sun).unwrap();
        assert_eq!(first, NaiveDate::from_ymd_opt(2026, 3, 1).unwrap());

        // El segundo, el 8.
        let second = nth_weekday_of_month(2026, 3, 2, Weekday::Sun).unwrap();
        assert_eq!(second, NaiveDate::from_ymd_opt(2026, 3, 8).unwrap());
    }

    /// «El quinto domingo» de un mes que tiene cuatro no existe, y no se corre
    /// al mes siguiente.
    #[test]
    fn un_dia_de_semana_que_no_existe_no_se_corre_de_mes() {
        assert_eq!(nth_weekday_of_month(2026, 2, 5, Weekday::Sun), None);
        assert_eq!(nth_weekday_of_month(2026, 2, -5, Weekday::Sun), None);
        assert_eq!(nth_weekday_of_month(2026, 3, 0, Weekday::Sun), None);
    }

    #[test]
    fn las_reglas_que_no_se_entienden_se_descartan_enteras() {
        // Una lista de días no define una transición única.
        assert_eq!(parse_yearly_rule("FREQ=YEARLY;BYMONTH=3;BYDAY=MO,TU"), None);
        // Mensual no es anual.
        assert_eq!(parse_yearly_rule("FREQ=MONTHLY;BYMONTH=3;BYDAY=-1SU"), None);
        // Un intervalo cambiaría el resultado y se descarta en vez de ignorarse.
        assert_eq!(
            parse_yearly_rule("FREQ=YEARLY;INTERVAL=2;BYMONTH=3;BYDAY=-1SU"),
            None
        );
        // Sin mes no hay nada que calcular.
        assert_eq!(parse_yearly_rule("FREQ=YEARLY;BYDAY=-1SU"), None);
    }

    /// Un `BYDAY` no ASCII cortaba a la mitad de un carácter y entraba en
    /// pánico. Lo escribe quien mande el archivo.
    #[test]
    fn un_byday_con_acentos_no_rompe_nada() {
        for garbage in ["€", "añSU", "SÜ", "áé", "\u{1f600}"] {
            assert_eq!(parse_weekday(garbage), None, "{garbage:?}");
        }
    }

    /// Un ordinal enorme le sumaba millones de días a una fecha, y eso también
    /// entraba en pánico. Un día de semana aparece cinco veces en un mes como
    /// mucho.
    #[test]
    fn un_ordinal_fuera_de_rango_se_rechaza() {
        assert_eq!(parse_weekday("999999999SU"), None);
        assert_eq!(parse_weekday("-999999999SU"), None);
        assert_eq!(parse_weekday("6SU"), None);
        assert_eq!(parse_weekday("0SU"), None);

        // Y el rango que sí vale sigue valiendo.
        assert_eq!(parse_weekday("5SU"), Some((5, Weekday::Sun)));
        assert_eq!(parse_weekday("-1SU"), Some((-1, Weekday::Sun)));
        assert_eq!(parse_weekday("SU"), Some((1, Weekday::Sun)));
    }

    /// Un punto y coma de más no puede mandar una regla legible al respaldo.
    #[test]
    fn un_punto_y_coma_de_mas_no_descarta_la_regla() {
        assert_eq!(
            parse_yearly_rule("FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU;"),
            Some(YearlyRule::Weekday {
                month: 3,
                ordinal: -1,
                day: Weekday::Sun
            })
        );
        assert_eq!(
            parse_yearly_rule(";;FREQ=YEARLY;;BYMONTH=3;BYDAY=-1SU"),
            Some(YearlyRule::Weekday {
                month: 3,
                ordinal: -1,
                day: Weekday::Sun
            })
        );
        // Un pedazo que **sí** dice algo y no se entiende sigue descartando la
        // regla entera: interpretarla a medias es peor.
        assert_eq!(
            parse_yearly_rule("FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU;basura"),
            None
        );
    }

    /// Una zona definida sólo con fechas sueltas cae al respaldo de la
    /// observancia estándar, que es quedar corrido una hora medio año en vez de
    /// quedar corrido el desplazamiento entero todo el año.
    #[test]
    fn una_zona_sin_reglas_usables_cae_a_la_observancia_estandar() {
        let ical = "BEGIN:VTIMEZONE\r\n\
            TZID:Zona historica\r\n\
            BEGIN:DAYLIGHT\r\n\
            DTSTART:19810329T020000\r\n\
            TZOFFSETFROM:+0100\r\n\
            TZOFFSETTO:+0200\r\n\
            RDATE:19820328T020000\r\n\
            END:DAYLIGHT\r\n\
            BEGIN:STANDARD\r\n\
            DTSTART:19811025T030000\r\n\
            TZOFFSETFROM:+0200\r\n\
            TZOFFSETTO:+0100\r\n\
            END:STANDARD\r\n\
            END:VTIMEZONE\r\n";
        let zone = zones_from(ical).resolve("Zona historica");

        let local = NaiveDate::from_ymd_opt(2026, 7, 15)
            .unwrap()
            .and_hms_opt(9, 0, 0)
            .unwrap();
        assert_eq!(
            zone.to_utc(local).unwrap().to_rfc3339(),
            "2026-07-15T08:00:00+00:00"
        );
    }

    /// La hora que no existe se corre hacia adelante en vez de hacer desaparecer
    /// el evento. En Madrid, el 29 de marzo de 2026 el reloj salta de las 2 a
    /// las 3, así que las 2:30 no ocurren.
    #[test]
    fn la_hora_que_no_existe_se_corre_hacia_adelante() {
        let zone = Zones::default().resolve("Europe/Madrid");
        let missing = NaiveDate::from_ymd_opt(2026, 3, 29)
            .unwrap()
            .and_hms_opt(2, 30, 0)
            .unwrap();

        let moment = zone.to_utc(missing).expect("no puede desaparecer del mes");
        assert_eq!(moment.to_rfc3339(), "2026-03-29T01:30:00+00:00");
    }

    /// La hora que ocurre dos veces se toma como la primera.
    #[test]
    fn la_hora_que_ocurre_dos_veces_se_toma_la_primera() {
        let zone = Zones::default().resolve("Europe/Madrid");
        // El 25 de octubre de 2026 el reloj atrasa de las 3 a las 2.
        let ambiguous = NaiveDate::from_ymd_opt(2026, 10, 25)
            .unwrap()
            .and_hms_opt(2, 30, 0)
            .unwrap();

        // La primera es con +2 todavía puesto: 00:30 UTC.
        assert_eq!(
            zone.to_utc(ambiguous).unwrap().to_rfc3339(),
            "2026-10-25T00:30:00+00:00"
        );
    }

    /// Un archivo con muchísimas zonas no hace crecer la tabla sin freno.
    #[test]
    fn hay_tope_de_zonas() {
        let mut ical = String::new();
        for i in 0..(MAX_ZONES + 50) {
            ical.push_str(&format!(
                "BEGIN:VTIMEZONE\r\nTZID:Zona {i}\r\nBEGIN:STANDARD\r\n\
                 TZOFFSETTO:+0100\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n"
            ));
        }
        assert_eq!(zones_from(&ical).len(), MAX_ZONES);
    }

    /// Un archivo sin ningún `VTIMEZONE` no es un error: es el caso normal.
    #[test]
    fn un_archivo_sin_zonas_da_una_tabla_vacia() {
        let ical = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:1\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert_eq!(zones_from(ical).len(), 0);
    }

    /// **En los bordes del calendario no hay pánico.** La fecha la escribe
    /// quien manda el archivo, y en `vasak-calendar` restar un día a la
    /// primera fecha que sabe `chrono`, o sumárselo a la última, entraba en
    /// pánico (`NaiveDateTime - Duration`). Acá devuelve lo que puede, o
    /// `None`.
    #[test]
    fn en_los_bordes_del_calendario_no_hay_panico() {
        let rules = zones_from(ROMANCE).resolve("Romance Standard Time");
        for zone in [
            Zone::Utc,
            Zone::Floating,
            Zone::Iana(chrono_tz::Europe::Madrid),
            Zone::Fixed(FixedOffset::east_opt(14 * 3600).unwrap()),
            Zone::Fixed(FixedOffset::east_opt(-12 * 3600).unwrap()),
            rules,
        ] {
            for local in [NaiveDateTime::MIN, NaiveDateTime::MAX] {
                let _ = zone.to_utc(local);
            }
        }
        assert_eq!(last_day_of_month(i32::MAX, 12), None);
        assert_eq!(nth_weekday_of_month(262_143, 12, 5, Weekday::Sun), None);
    }

    /// Un `BYDAY` con el mínimo de `i32` no entra en pánico: se descarta. Y
    /// tampoco dentro de un `VTIMEZONE`, que se lee fuera del `catch_unwind`.
    #[test]
    fn un_byday_con_el_minimo_de_i32_no_entra_en_panico() {
        assert_eq!(parse_weekday("-2147483648SU"), None);
        assert_eq!(parse_weekday("2147483647SU"), None);
        assert_eq!(parse_weekday("-6SU"), None);
        assert_eq!(parse_weekday("-5SU"), Some((-5, Weekday::Sun)));
        assert_eq!(parse_weekday("-1SU"), Some((-1, Weekday::Sun)));
        let ical = "BEGIN:VCALENDAR\r\nBEGIN:VTIMEZONE\r\nTZID:Rara\r\n\
            BEGIN:STANDARD\r\nDTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\n\
            TZOFFSETTO:+0100\r\nRRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-2147483648SU\r\n\
            END:STANDARD\r\nEND:VTIMEZONE\r\nEND:VCALENDAR\r\n";
        let document = super::super::parse_document(ical);
        // Leer el documento es lo que entraba en pánico; la zona queda como quede.
        let _ = document.zones.lookup("Rara");
    }
}
