//! Leer iCalendar: los eventos y las tareas de un calendario CalDAV.
//!
//! Viene de `vasak-calendar` (`src-tauri/src/caldav.rs`, la mitad que no habla
//! por la red), con sus pruebas y los nombres pasados al inglés: `unir_lineas`
//! → [`unfold_lines`], `partir_linea` → [`split_line`], `texto_de` →
//! [`unescape_text`], `fecha_de` → [`parse_date`], `tzid_de` → [`tzid_of`],
//! `eventos_de` → [`events_from`], `Evento` → [`Event`]. Las zonas horarias
//! (`zonas.rs`) están en [`timezones`], y la expansión de las repeticiones —que
//! `vasak-calendar` no hacía— en [`recurrence`].
//!
//! Lo que cambió al mudarse: el archivo se lee a un **árbol de componentes**
//! ([`parse_document`]) en vez de una sola pasada que sabía de `VEVENT`, porque
//! el almacén guarda también las tareas (`VTODO`), las excepciones de una serie
//! (`RECURRENCE-ID`) y los recordatorios (`VALARM`); y todo lo que se muestra
//! pierde los caracteres de control, como en `vcard.rs`.
//!
//! ── Sobre interpretar iCalendar ─────────────────────────────────────────────
//!
//! Esto es leer lo que escribió alguien más: el evento lo pudo haber creado
//! cualquier programa, y la invitación pudo haberla mandado cualquiera. Por eso
//! corre como la persona y no como root, fuera del bucle de eventos, y con
//! topes en todo lo que crece con el archivo: componentes, propiedades por
//! componente, anidado, parámetros por línea y largo de lo que se muestra
//! ([`MAX_COMPONENTS`] y los que siguen). Una fecha que no se entiende no se
//! inventa: queda sin fecha.

pub mod recurrence;
pub mod timezones;

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};

use timezones::{Zone, Zones};

/// Componentes que se leen de un recurso, contando los anidados (`VALARM`,
/// `STANDARD`). Una serie con cien excepciones son cien; mil es un archivo
/// armado para hacer trabajar al programa.
pub const MAX_COMPONENTS: usize = 1000;

/// Propiedades de un componente. Un evento con treinta asistentes tiene unas
/// cincuenta.
pub const MAX_PROPERTIES: usize = 1000;

/// Niveles de anidado: `VCALENDAR` › `VEVENT` › `VALARM` son tres.
pub const MAX_DEPTH: usize = 8;

/// Parámetros de una línea. `ATTENDEE` lleva media docena.
pub const MAX_PARAMS: usize = 64;

/// El largo de un texto de una línea que se muestra: el título, el lugar.
pub const MAX_TEXT: usize = 1024;

/// El largo de la descripción que se muestra.
pub const MAX_DESCRIPTION: usize = 32 * 1024;

// ---------------------------------------------------------------------------
// Las líneas
// ---------------------------------------------------------------------------

/// Junta las líneas partidas de un iCalendar.
///
/// El formato corta las líneas largas a 75 octetos y sigue en la siguiente con
/// un espacio o una tabulación adelante. Sin volver a juntarlas, un título largo
/// aparece cortado a la mitad y una fecha partida no se interpreta — y los
/// títulos largos son justamente los que más se cortan.
///
/// Lineal: cada continuación se pega al final de la anterior, sin volver a
/// mirar lo que ya se juntó.
pub fn unfold_lines(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for raw in text.split("\r\n").flat_map(|l| l.split('\n')) {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        match raw.strip_prefix([' ', '\t']) {
            Some(continuation) => {
                if let Some(last) = lines.last_mut() {
                    last.push_str(continuation);
                    continue;
                }
                lines.push(continuation.to_string());
            }
            None => lines.push(raw.to_string()),
        }
    }
    lines
}

/// Separa el nombre y sus parámetros del valor.
///
/// Una línea es `NOMBRE;PARAM=X:valor`, y el valor puede tener dos puntos —una
/// URL, por ejemplo— así que se corta por el **primero** que esté fuera de
/// comillas. Cortar por el último partiría `DESCRIPTION:ver https://x` en el
/// lugar equivocado.
///
/// Los parámetros, como mucho [`MAX_PARAMS`]; los de más se descartan. Un
/// punto y coma entre comillas no separa: `CN="Pérez; Ana"` es uno.
pub fn split_line(line: &str) -> Option<(String, Vec<String>, String)> {
    let mut quoted = false;
    let cut = line.char_indices().find_map(|(i, c)| match c {
        '"' => {
            quoted = !quoted;
            None
        }
        ':' if !quoted => Some(i),
        _ => None,
    })?;

    let (left, right) = line.split_at(cut);
    let value = right[1..].to_string();

    let mut parts = split_params(left).into_iter();
    let name = parts.next()?.trim().to_ascii_uppercase();
    let params: Vec<String> = parts
        .take(MAX_PARAMS)
        .map(|p| p.trim().to_string())
        .collect();

    Some((name, params, value))
}

/// Parte `NOMBRE;A=1;B="x;y"` por los punto y coma que no están entre
/// comillas.
fn split_params(left: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    for (i, c) in left.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ';' if !quoted => {
                parts.push(&left[start..i]);
                start = i + 1;
                if parts.len() > MAX_PARAMS {
                    return parts;
                }
            }
            _ => {}
        }
    }
    parts.push(&left[start..]);
    parts
}

/// Devuelve el texto de un valor `TEXT`, deshaciendo lo escapado.
///
/// En iCalendar una coma, un punto y coma y un salto de línea van escapados. Sin
/// deshacerlo, un título como «Reunión, con Ana» se muestra con la barra a la
/// vista.
pub fn unescape_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') | Some('N') => out.push('\n'),
            Some(',') => out.push(','),
            Some(';') => out.push(';'),
            Some('\\') => out.push('\\'),
            // Una barra que no escapa nada conocido se deja como está: es un
            // dato de alguien y no hay motivo para tragárselo.
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Lo primero de un texto, hasta `cap` bytes y sin partir un carácter.
pub fn clipped(text: &str, cap: usize) -> String {
    if text.len() <= cap {
        return text.to_string();
    }
    let mut cut = cap;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text[..cut].to_string()
}

/// Un texto de una línea para mostrar: sin caracteres de control —los saltos y
/// las tabulaciones pasan a ser un espacio—, recortado y con tope.
pub fn visible(text: &str, cap: usize) -> String {
    let shown: String = text
        .chars()
        .filter_map(|c| match c {
            '\n' | '\r' | '\t' => Some(' '),
            c if c.is_control() => None,
            c => Some(c),
        })
        .collect();
    clipped(shown.trim(), cap)
}

/// Un texto de varias líneas para mostrar —la descripción—: se quedan el salto
/// de línea y la tabulación, y los demás controles se van.
pub fn visible_multiline(text: &str, cap: usize) -> String {
    let shown: String = text
        .chars()
        .filter(|c| matches!(c, '\n' | '\t') || !c.is_control())
        .collect();
    clipped(shown.trim(), cap)
}

// ---------------------------------------------------------------------------
// Las fechas
// ---------------------------------------------------------------------------

/// `20260915` y nada más: ocho dígitos. `chrono` aceptaría años de más cifras
/// y signos, que ningún iCalendar escribe.
pub(crate) fn parse_naive_date(value: &str) -> Option<NaiveDate> {
    if value.len() != 8 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    NaiveDate::parse_from_str(value, "%Y%m%d").ok()
}

/// `20260915T140000` y nada más, sin la `Z`.
pub(crate) fn parse_naive_datetime(value: &str) -> Option<NaiveDateTime> {
    let bytes = value.as_bytes();
    if bytes.len() != 15
        || bytes[8] != b'T'
        || !bytes[..8].iter().chain(&bytes[9..]).all(u8::is_ascii_digit)
    {
        return None;
    }
    NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%S").ok()
}

/// Una fecha de iCalendar tal como vino, antes de resolver su zona.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DateValue {
    /// Todo el día: `20260915`, o con `VALUE=DATE`.
    Date(NaiveDate),
    /// Un instante: `20260915T140000Z`.
    Utc(NaiveDateTime),
    /// Una hora de reloj: con `TZID`, o flotante sin él.
    Local {
        local: NaiveDateTime,
        tzid: Option<String>,
    },
}

/// Cómo quedó la zona de una fecha.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneKind {
    /// Todo el día: no tiene hora, así que no tiene zona.
    Date,
    Utc,
    /// Con un `TZID` que se pudo resolver.
    Zoned,
    /// Sin `TZID`: la hora de quien mira.
    Floating,
    /// Con un `TZID` que no es de IANA ni lo define el archivo. Se trata como
    /// flotante, y queda marcado.
    Unknown,
}

impl ZoneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ZoneKind::Date => "date",
            ZoneKind::Utc => "utc",
            ZoneKind::Zoned => "zoned",
            ZoneKind::Floating => "floating",
            ZoneKind::Unknown => "unknown",
        }
    }

    /// Si la hora depende de dónde esté quien mira.
    #[cfg(test)]
    pub fn is_floating(self) -> bool {
        matches!(self, ZoneKind::Floating | ZoneKind::Unknown)
    }
}

impl DateValue {
    /// Lee el valor con sus parámetros. Cuatro formas, y cada una quiere decir
    /// algo distinto:
    ///
    /// - `20260915`, o con `VALUE=DATE` — **todo el día**. No tiene hora, así
    ///   que no tiene zona: darle una la correría de día para quien esté en
    ///   otra.
    /// - `20260915T140000Z` — **UTC**. Un instante, sin ambigüedad. La `Z`
    ///   manda sobre cualquier `TZID`: una fecha en UTC ya es un instante, y
    ///   un `TZID` al lado es un archivo mal escrito, no otra interpretación.
    /// - `20260915T140000` con `TZID=...` — las dos de la tarde **de esa
    ///   zona** (ver [`timezones`]).
    /// - `20260915T140000` a secas — **hora local flotante**: «las dos de
    ///   donde estés».
    pub fn parse(value: &str, params: &[String]) -> Option<Self> {
        let value = value.trim();
        let date_only = params.iter().any(|p| p.eq_ignore_ascii_case("VALUE=DATE"));
        if date_only || value.len() == 8 {
            return parse_naive_date(value).map(DateValue::Date);
        }
        if let Some(utc) = value.strip_suffix('Z') {
            return parse_naive_datetime(utc).map(DateValue::Utc);
        }
        let local = parse_naive_datetime(value)?;
        Some(DateValue::Local {
            local,
            tzid: tzid_of(params).map(str::to_string),
        })
    }

    /// El reloj de pared: la fecha a medianoche, o la hora tal como vino.
    pub fn wall_clock(&self) -> NaiveDateTime {
        match self {
            DateValue::Date(date) => date.and_time(chrono::NaiveTime::MIN),
            DateValue::Utc(local) | DateValue::Local { local, .. } => *local,
        }
    }

    pub fn is_date(&self) -> bool {
        matches!(self, DateValue::Date(_))
    }

    /// Con qué zona se pasa a un instante, y cómo quedó.
    ///
    /// Un día completo se guarda a medianoche **UTC**, como lo hacía
    /// `vasak-calendar`: no tiene zona, y quien lo muestra lo lee como fecha.
    pub fn zone(&self, zones: &Zones) -> (Zone, ZoneKind) {
        match self {
            DateValue::Date(_) => (Zone::Utc, ZoneKind::Date),
            DateValue::Utc(_) => (Zone::Utc, ZoneKind::Utc),
            DateValue::Local { tzid: None, .. } => (Zone::Floating, ZoneKind::Floating),
            DateValue::Local {
                tzid: Some(tzid), ..
            } => match zones.lookup(tzid) {
                Some(Zone::Floating) => (Zone::Floating, ZoneKind::Floating),
                Some(zone) => (zone, ZoneKind::Zoned),
                None => (Zone::Floating, ZoneKind::Unknown),
            },
        }
    }

    /// El instante, con la zona resuelta contra las del archivo.
    pub fn resolve(&self, zones: &Zones) -> Option<(DateTime<Utc>, ZoneKind)> {
        let (zone, kind) = self.zone(zones);
        zone.to_utc(self.wall_clock()).map(|moment| (moment, kind))
    }
}

/// Interpreta una fecha de iCalendar: el instante y si es de día completo.
///
/// Las formas y lo que quieren decir están en [`DateValue::parse`]. Con `TZID`
/// y con hora flotante se trataban antes como UTC, y eso quería decir que una
/// reunión de las 14:00 en Buenos Aires se mostraba a las 11:00.
///
/// La usan las pruebas que vinieron de `vasak-calendar`; el almacén va por
/// [`DateValue`], que además dice cómo quedó la zona.
#[cfg(test)]
pub fn parse_date(value: &str, params: &[String], zones: &Zones) -> Option<(DateTime<Utc>, bool)> {
    let date = DateValue::parse(value, params)?;
    let all_day = date.is_date();
    date.resolve(zones).map(|(moment, _)| (moment, all_day))
}

/// El `TZID` de los parámetros de una línea, si lo trae, sin comillas.
pub fn tzid_of(params: &[String]) -> Option<&str> {
    param(params, "TZID")
}

/// El valor de un parámetro, sin comillas.
pub fn param<'a>(params: &'a [String], name: &str) -> Option<&'a str> {
    params.iter().find_map(|p| {
        let (key, value) = p.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then(|| timezones::unquote(value.trim()))
    })
}

// ---------------------------------------------------------------------------
// El árbol de componentes
// ---------------------------------------------------------------------------

/// Una línea de contenido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    pub name: String,
    pub params: Vec<String>,
    pub value: String,
}

impl Property {
    pub fn param(&self, name: &str) -> Option<&str> {
        param(&self.params, name)
    }
}

/// Un componente: `VEVENT`, `VTODO`, `VALARM`, …
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub properties: Vec<Property>,
    pub children: Vec<Component>,
}

impl Component {
    /// La primera propiedad con ese nombre.
    pub fn first(&self, name: &str) -> Option<&Property> {
        self.properties.iter().find(|p| p.name == name)
    }

    /// Todas las propiedades con ese nombre.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Property> + 'a {
        self.properties.iter().filter(move |p| p.name == name)
    }

    /// El valor de la primera, sin espacios alrededor.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.first(name).map(|p| p.value.trim())
    }

    /// Un texto para mostrar: desescapado, sin controles y con tope.
    pub fn text(&self, name: &str, cap: usize) -> Option<String> {
        self.first(name)
            .map(|p| visible(&unescape_text(&p.value), cap))
    }

    /// Una fecha de la primera propiedad con ese nombre.
    pub fn date(&self, name: &str) -> Option<DateValue> {
        self.first(name)
            .and_then(|p| DateValue::parse(&p.value, &p.params))
    }
}

/// Un recurso de calendario leído entero.
#[derive(Debug, Clone, Default)]
pub struct Document {
    /// Los componentes de adentro del `VCALENDAR` —o sueltos, si el archivo
    /// no lo trae—, sin los `VTIMEZONE`, que están en `zones`.
    pub components: Vec<Component>,
    pub zones: Zones,
    /// Si se descartó algo por pasar un tope.
    pub truncated: bool,
}

/// Lee un recurso a su árbol de componentes, con topes.
///
/// Un componente que no se cierra no cuenta —un archivo cortado a la mitad no
/// da un evento a medias—, y un `END` que no corresponde al componente abierto
/// cierra hasta el que sí corresponde, o se ignora si no hay ninguno.
pub fn parse_document(ical: &str) -> Document {
    let mut document = Document {
        zones: timezones::zones_from(ical),
        ..Default::default()
    };
    // La pila de lo abierto. Lo que se cierra se cuelga de su padre, y lo que
    // se cierra sin padre es de primer nivel.
    let mut stack: Vec<Component> = Vec::new();
    let mut roots: Vec<Component> = Vec::new();
    let mut count = 0usize;
    // Cuántos componentes de más se están salteando, anidados.
    let mut skipping = 0usize;

    for line in unfold_lines(ical) {
        let Some((name, params, value)) = split_line(&line) else {
            continue;
        };
        match name.as_str() {
            "BEGIN" => {
                let component = value.trim().to_ascii_uppercase();
                if skipping > 0 || stack.len() >= MAX_DEPTH || count >= MAX_COMPONENTS {
                    skipping += 1;
                    document.truncated = true;
                    continue;
                }
                count += 1;
                stack.push(Component {
                    name: component,
                    ..Default::default()
                });
            }
            "END" => {
                if skipping > 0 {
                    skipping -= 1;
                    continue;
                }
                let component = value.trim().to_ascii_uppercase();
                let Some(open) = stack.iter().rposition(|c| c.name == component) else {
                    continue;
                };
                // Lo abierto adentro y sin cerrar se descarta.
                stack.truncate(open + 1);
                let done = stack.pop().expect("la posición está en la pila");
                match stack.last_mut() {
                    Some(parent) => parent.children.push(done),
                    None => roots.push(done),
                }
            }
            _ if skipping > 0 => {}
            _ => {
                if let Some(current) = stack.last_mut() {
                    if current.properties.len() >= MAX_PROPERTIES {
                        document.truncated = true;
                        continue;
                    }
                    current.properties.push(Property {
                        name,
                        params,
                        value,
                    });
                }
            }
        }
    }

    for root in roots {
        if root.name == "VCALENDAR" {
            document
                .components
                .extend(root.children.into_iter().filter(|c| c.name != "VTIMEZONE"));
        } else if root.name != "VTIMEZONE" {
            document.components.push(root);
        }
    }
    document
}

// ---------------------------------------------------------------------------
// Un evento para mostrar
// ---------------------------------------------------------------------------

/// Un evento, ya listo para mostrar: lo que `vasak-calendar` sacaba de cada
/// `VEVENT`, y lo que el almacén guarda para indexar cada objeto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub uid: String,
    pub title: String,
    /// Cuándo empieza, en UTC y en ISO 8601. La ventana lo pasa a la hora local.
    pub start: String,
    pub end: String,
    /// Si dura todo el día. Se guarda aparte porque un evento de día completo no
    /// tiene hora, y mostrarle una —la medianoche de alguna zona— lo correría de
    /// día para quien esté en otra.
    pub all_day: bool,
    /// Si se repite.
    pub recurring: bool,
    /// La zona en la que lo escribieron, tal como venía en el archivo.
    ///
    /// Vacía cuando el evento venía en UTC, cuando es de día completo o cuando
    /// no declaraba ninguna. Va como texto y no resuelta porque es para
    /// **mostrar**: la ventana avisa cuando un evento está escrito en una zona
    /// distinta de aquella en la que se está mirando la agenda, y para eso hace
    /// falta el nombre que le puso quien lo escribió.
    pub zone: String,
}

/// El nombre de la zona de un `DTSTART`, como se muestra: vacío en UTC y en un
/// día completo.
pub fn zone_name(component: &Component) -> String {
    component
        .first("DTSTART")
        .filter(|p| !p.value.trim().ends_with('Z'))
        .filter(|p| DateValue::parse(&p.value, &p.params).is_some_and(|d| !d.is_date()))
        .and_then(|p| tzid_of(&p.params))
        .map(|tzid| visible(tzid, MAX_TEXT))
        .unwrap_or_default()
}

/// El evento de un `VEVENT`, o nada si no tiene comienzo.
pub fn event_of(component: &Component, zones: &Zones) -> Option<Event> {
    // Sin comienzo no hay dónde ponerlo en el mes, así que no se muestra. El
    // estándar lo exige, pero un servidor puede mandar cualquier cosa.
    let start_value = component.date("DTSTART")?;
    let all_day = start_value.is_date();
    let (start, _) = start_value.resolve(zones)?;
    // Sin fin, dura lo que el estándar dice: un día si es de día completo, y
    // nada si tiene hora. Inventar una hora de fin mostraría una barra que no
    // corresponde.
    let end = component
        .date("DTEND")
        .and_then(|end| end.resolve(zones))
        .map(|(end, _)| end)
        .unwrap_or(if all_day {
            start + chrono::Duration::days(1)
        } else {
            start
        });

    Some(Event {
        uid: component
            .value("UID")
            .map(|uid| clipped(uid, MAX_TEXT))
            .unwrap_or_default(),
        // Un evento sin título existe: se muestra vacío y no se descarta,
        // porque ocupa lugar en el día de la persona igual.
        title: component.text("SUMMARY", MAX_TEXT).unwrap_or_default(),
        start: start.to_rfc3339(),
        end: end.to_rfc3339(),
        all_day,
        recurring: component.first("RRULE").is_some(),
        // Un evento de día completo no tiene hora, así que no tiene zona,
        // aunque el archivo le haya puesto una.
        zone: zone_name(component),
    })
}

/// Saca los eventos de un iCalendar.
///
/// Sólo `VEVENT`: un calendario trae también tareas y notas, y mostrarlas como
/// si fueran eventos llenaría el mes de cosas que no lo son.
///
/// Las zonas se leen **antes** y en una pasada aparte: un `VTIMEZONE` puede
/// venir después del evento que lo usa, y el formato no fija el orden. Y lo que
/// está anidado adentro de un evento —el `VALARM`, con su propio `SUMMARY` y a
/// veces su propio `DTSTART`— es del recordatorio, no del evento.
///
/// La usan las pruebas que vinieron de `vasak-calendar`; el almacén va por
/// [`parse_document`] y [`event_of`], objeto por objeto.
#[cfg(test)]
pub fn events_from(ical: &str) -> Vec<Event> {
    let document = parse_document(ical);
    document
        .components
        .iter()
        .filter(|c| c.name == "VEVENT")
        .filter_map(|c| event_of(c, &document.zones))
        .collect()
}

/// Un instante como lo espera la respuesta: RFC 3339 en UTC.
pub fn rfc3339(seconds: i64) -> String {
    Utc.timestamp_opt(seconds, 0)
        .single()
        .map(|moment| moment.to_rfc3339())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El formato corta las líneas largas y sigue en la siguiente con un espacio
    /// adelante. Sin volver a juntarlas, un título largo aparece cortado a la
    /// mitad — y los títulos largos son justamente los que más se cortan.
    #[test]
    fn las_lineas_partidas_se_vuelven_a_juntar() {
        let ical = "SUMMARY:Reunión de\r\n  equipo\r\nUID:1\r\n";
        let lines = unfold_lines(ical);

        assert_eq!(lines[0], "SUMMARY:Reunión de equipo");
        assert_eq!(lines[1], "UID:1");
    }

    /// Con tabulación también, que el estándar permite igual — y el carácter
    /// que pliega **se va**, no se convierte en un espacio. Un título cortado
    /// justo en el medio de una palabra tiene que volver a quedar entero: en el
    /// test de arriba el espacio que sobrevive es el segundo, el que el evento
    /// tenía de verdad.
    #[test]
    fn una_continuacion_con_tabulacion_tambien_se_junta() {
        assert_eq!(unfold_lines("SUMMARY:algo\r\n\tmás")[0], "SUMMARY:algomás");
        assert_eq!(
            unfold_lines("SUMMARY:algo\r\n\t más")[0],
            "SUMMARY:algo más"
        );
    }

    /// El valor puede tener dos puntos —una URL, por ejemplo— así que el corte
    /// va por el primero. Cortar por el último partiría la línea en el lugar
    /// equivocado.
    #[test]
    fn la_linea_se_corta_por_el_primer_dos_puntos() {
        let (name, _, value) = split_line("DESCRIPTION:ver https://ejemplo.com/x").unwrap();
        assert_eq!(name, "DESCRIPTION");
        assert_eq!(value, "ver https://ejemplo.com/x");
    }

    /// Y no por uno que esté entre comillas: un parámetro puede llevarlos.
    #[test]
    fn un_dos_puntos_entre_comillas_no_corta() {
        let (name, params, value) =
            split_line(r#"DTSTART;TZID="America/Argentina/Buenos Aires":20260915T140000"#).unwrap();
        assert_eq!(name, "DTSTART");
        assert_eq!(value, "20260915T140000");
        assert!(params[0].contains("America"));
    }

    #[test]
    fn los_parametros_se_separan_del_nombre() {
        let (name, params, value) = split_line("DTSTART;VALUE=DATE:20260915").unwrap();
        assert_eq!(name, "DTSTART");
        assert_eq!(params, vec!["VALUE=DATE"]);
        assert_eq!(value, "20260915");
    }

    /// Un punto y coma entre comillas no separa parámetros: `CN="Pérez; Ana"`
    /// es uno. `vasak-calendar` partía por cualquiera.
    #[test]
    fn un_punto_y_coma_entre_comillas_no_separa_parametros() {
        let (_, params, _) =
            split_line(r#"ATTENDEE;CN="Pérez; Ana";PARTSTAT=ACCEPTED:mailto:ana@x.com"#).unwrap();
        assert_eq!(params, vec![r#"CN="Pérez; Ana""#, "PARTSTAT=ACCEPTED"]);
        assert_eq!(param(&params, "CN"), Some("Pérez; Ana"));
    }

    /// Una línea con miles de parámetros no llena la memoria.
    #[test]
    fn hay_tope_de_parametros() {
        let line = format!("X{}:valor", ";A=1".repeat(10_000));
        let (_, params, value) = split_line(&line).unwrap();
        assert_eq!(params.len(), MAX_PARAMS);
        assert_eq!(value, "valor");
    }

    /// Sin deshacer lo escapado, «Reunión, con Ana» se muestra con la barra a la
    /// vista.
    #[test]
    fn el_texto_se_desescapa() {
        assert_eq!(unescape_text(r"Reunión\, con Ana"), "Reunión, con Ana");
        assert_eq!(unescape_text(r"Uno\nDos"), "Uno\nDos");
        assert_eq!(unescape_text(r"punto\; y coma"), "punto; y coma");
        assert_eq!(unescape_text(r"barra\\sola"), r"barra\sola");
    }

    /// Una barra que no escapa nada conocido se deja: es un dato de alguien y no
    /// hay motivo para tragárselo.
    #[test]
    fn una_barra_que_no_escapa_nada_se_deja() {
        assert_eq!(unescape_text(r"C:\Users"), r"C:\Users");
        assert_eq!(unescape_text("termina en barra\\"), "termina en barra\\");
    }

    /// Un evento de día completo **no tiene hora**, y darle una lo correría de
    /// día para quien esté en otra zona.
    #[test]
    fn una_fecha_sin_hora_es_de_dia_completo() {
        let (moment, all_day) =
            parse_date("20260915", &["VALUE=DATE".into()], &Zones::default()).unwrap();
        assert!(all_day);
        assert_eq!(moment.to_rfc3339(), "2026-09-15T00:00:00+00:00");

        // Y también si no viene el parámetro: ocho dígitos ya son una fecha.
        assert!(parse_date("20260915", &[], &Zones::default()).unwrap().1);
    }

    #[test]
    fn una_fecha_con_hora_no_es_de_dia_completo() {
        let (moment, all_day) = parse_date("20260915T140000Z", &[], &Zones::default()).unwrap();
        assert!(!all_day);
        assert_eq!(moment.to_rfc3339(), "2026-09-15T14:00:00+00:00");
    }

    #[test]
    fn una_fecha_que_no_se_entiende_no_se_inventa() {
        for garbage in [
            "",
            "mañana",
            "2026-09-15",
            "20261301",
            "20260915T99",
            // Años de más cifras y con signo, que `chrono` sí aceptaría.
            "+2026091",
            "+20260915T140000",
            "2026091500T1400",
        ] {
            assert_eq!(
                parse_date(garbage, &[], &Zones::default()),
                None,
                "{garbage:?}"
            );
        }
    }

    /// **El bug que este módulo tenía en `vasak-calendar`.** Una fecha con
    /// `TZID` se trataba como UTC, así que una reunión de las dos de la tarde
    /// en Buenos Aires se mostraba a las once de la mañana.
    #[test]
    fn una_fecha_con_tzid_no_es_utc() {
        let (moment, all_day) = parse_date(
            "20260915T140000",
            &["TZID=America/Argentina/Buenos_Aires".into()],
            &Zones::default(),
        )
        .unwrap();
        assert!(!all_day);
        assert_eq!(moment.to_rfc3339(), "2026-09-15T17:00:00+00:00");
    }

    /// El `TZID` entre comillas, que es como lo escribe un cliente cuando el
    /// nombre tiene barras o espacios. El nombre es el de IANA, con guion
    /// bajo: con el espacio no es ninguna zona, queda como hora flotante y la
    /// prueba pasaba sólo en una máquina con la hora de Buenos Aires (así
    /// venía de `vasak-calendar`, y en el CI, que corre en UTC, fallaba).
    #[test]
    fn el_tzid_entre_comillas_se_resuelve_igual() {
        let (moment, _) = parse_date(
            "20260915T140000",
            &[r#"TZID="America/Argentina/Buenos_Aires""#.into()],
            &Zones::default(),
        )
        .unwrap();
        assert_eq!(moment.to_rfc3339(), "2026-09-15T17:00:00+00:00");
    }

    /// Una `Z` es un instante y manda sobre cualquier `TZID` al lado: eso es un
    /// archivo mal escrito, no otra interpretación.
    #[test]
    fn la_z_manda_sobre_el_tzid() {
        let (moment, _) = parse_date(
            "20260915T140000Z",
            &["TZID=Europe/Madrid".into()],
            &Zones::default(),
        )
        .unwrap();
        assert_eq!(moment.to_rfc3339(), "2026-09-15T14:00:00+00:00");
    }

    /// Un `TZID` que no se conoce no pierde el evento: queda a la hora de
    /// quien mira y marcado como desconocido.
    #[test]
    fn una_zona_desconocida_queda_flotante_y_marcada() {
        let date = DateValue::parse("20260915T140000", &["TZID=Zona Inventada".into()]).unwrap();
        let (moment, kind) = date.resolve(&Zones::default()).unwrap();
        assert_eq!(kind, ZoneKind::Unknown);
        assert!(kind.is_floating());
        assert_eq!(
            Some(moment),
            Zone::Floating.to_utc(date.wall_clock()),
            "a la hora de la sesión"
        );
    }

    /// Un evento entero con su `VTIMEZONE`, como lo manda Outlook: el `TZID` no
    /// es un nombre de IANA y las reglas vienen en el mismo archivo.
    #[test]
    fn un_evento_con_su_propio_vtimezone_cae_a_la_hora_correcta() {
        let ical = "BEGIN:VCALENDAR\r\n\
            BEGIN:VTIMEZONE\r\n\
            TZID:Romance Standard Time\r\n\
            BEGIN:STANDARD\r\n\
            DTSTART:16010101T030000\r\n\
            TZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\n\
            RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=10\r\n\
            END:STANDARD\r\n\
            BEGIN:DAYLIGHT\r\n\
            DTSTART:16010101T020000\r\n\
            TZOFFSETFROM:+0100\r\nTZOFFSETTO:+0200\r\n\
            RRULE:FREQ=YEARLY;BYDAY=-1SU;BYMONTH=3\r\n\
            END:DAYLIGHT\r\n\
            END:VTIMEZONE\r\n\
            BEGIN:VEVENT\r\nUID:abc\r\nSUMMARY:Reunión\r\n\
            DTSTART;TZID=Romance Standard Time:20260715T090000\r\n\
            DTEND;TZID=Romance Standard Time:20260715T100000\r\n\
            END:VEVENT\r\nEND:VCALENDAR\r\n";

        let events = events_from(ical);
        assert_eq!(events.len(), 1);
        // Julio es verano en Madrid: +2.
        assert_eq!(events[0].start, "2026-07-15T07:00:00+00:00");
        assert_eq!(events[0].end, "2026-07-15T08:00:00+00:00");
    }

    /// Un evento de día completo sigue sin tener zona, aunque el archivo defina
    /// una: darle una hora lo correría de día para quien esté en otra.
    #[test]
    fn un_evento_de_dia_completo_no_se_corre_de_dia() {
        let ical = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:abc\r\n\
            DTSTART;VALUE=DATE:20260915\r\nDTEND;VALUE=DATE:20260916\r\n\
            END:VEVENT\r\nEND:VCALENDAR\r\n";

        let events = events_from(ical);
        assert!(events[0].all_day);
        assert_eq!(events[0].start, "2026-09-15T00:00:00+00:00");
    }

    const ONE_EVENT: &str = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:abc\r\n\
        SUMMARY:Reunión\\, con Ana\r\nDTSTART:20260915T140000Z\r\n\
        DTEND:20260915T150000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    /// El evento lleva la zona en la que lo escribieron, para que la ventana
    /// pueda avisar cuando no es la misma en la que se está mirando la agenda.
    #[test]
    fn el_evento_lleva_la_zona_en_la_que_lo_escribieron() {
        let ical = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:a\r\n\
            DTSTART;TZID=Europe/Madrid:20260915T140000\r\n\
            DTEND;TZID=Europe/Madrid:20260915T150000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert_eq!(events_from(ical)[0].zone, "Europe/Madrid");

        // Entre comillas es el mismo nombre, no otro.
        let quoted = ical.replace("TZID=Europe/Madrid", "TZID=\"Europe/Madrid\"");
        assert_eq!(events_from(&quoted)[0].zone, "Europe/Madrid");
    }

    /// Una fecha en UTC ya es un instante: no hay ninguna zona que mostrar.
    #[test]
    fn un_evento_en_utc_no_lleva_zona() {
        assert_eq!(events_from(ONE_EVENT)[0].zone, "");
    }

    /// Y uno de día completo tampoco, aunque el archivo le ponga una: no tiene
    /// hora, así que no hay a qué reloj referirla.
    #[test]
    fn un_evento_de_dia_completo_no_lleva_zona() {
        let ical = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:a\r\n\
            DTSTART;TZID=Europe/Madrid;VALUE=DATE:20260915\r\n\
            END:VEVENT\r\nEND:VCALENDAR\r\n";
        assert_eq!(events_from(ical)[0].zone, "");
    }

    #[test]
    fn se_lee_un_evento() {
        let events = events_from(ONE_EVENT);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].uid, "abc");
        assert_eq!(events[0].title, "Reunión, con Ana");
        assert!(!events[0].all_day);
        assert!(!events[0].recurring);
    }

    /// Un calendario trae también tareas y notas. Mostrarlas como eventos
    /// llenaría el mes de cosas que no lo son.
    #[test]
    fn las_tareas_y_las_notas_no_son_eventos() {
        let ical = "BEGIN:VCALENDAR\r\n\
            BEGIN:VTODO\r\nUID:t\r\nSUMMARY:Comprar pan\r\nDTSTART:20260915T140000Z\r\nEND:VTODO\r\n\
            BEGIN:VJOURNAL\r\nUID:j\r\nSUMMARY:Nota\r\nDTSTART:20260915T140000Z\r\nEND:VJOURNAL\r\n\
            BEGIN:VEVENT\r\nUID:e\r\nSUMMARY:Reunión\r\nDTSTART:20260915T140000Z\r\nEND:VEVENT\r\n\
            END:VCALENDAR\r\n";

        let events = events_from(ical);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].uid, "e");
    }

    /// El recordatorio de un evento no es el título del evento.
    ///
    /// Un `VEVENT` casi siempre trae un `VALARM` adentro, y el `VALARM` tiene su
    /// propio `SUMMARY` —«Recordatorio», o lo que le haya puesto el cliente que
    /// creó el evento—. Sin contar la anidación, esa línea pisaba el título y la
    /// cuadrícula del mes aparecía llena de «Recordatorio» en vez de reuniones.
    #[test]
    fn el_summary_de_un_recordatorio_no_pisa_el_del_evento() {
        let ical = "BEGIN:VEVENT\r\nUID:a\r\nSUMMARY:Reunión con Ana\r\n\
            DTSTART:20260915T140000Z\r\n\
            BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\n\
            SUMMARY:Recordatorio\r\nDESCRIPTION:Falta un rato\r\nEND:VALARM\r\n\
            END:VEVENT\r\n";

        let events = events_from(ical);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].title, "Reunión con Ana");
    }

    /// Y un `DTSTART` de adentro tampoco corre el evento de día.
    ///
    /// Un `VALARM` con disparador absoluto lleva su propia fecha, que es la del
    /// aviso y no la de la reunión.
    #[test]
    fn la_fecha_de_un_recordatorio_no_mueve_el_evento() {
        let ical = "BEGIN:VEVENT\r\nUID:a\r\nDTSTART:20260915T140000Z\r\n\
            BEGIN:VALARM\r\nACTION:DISPLAY\r\nDTSTART:20260101T000000Z\r\n\
            RRULE:FREQ=DAILY\r\nEND:VALARM\r\n\
            END:VEVENT\r\n";

        let event = &events_from(ical)[0];
        assert_eq!(event.start, "2026-09-15T14:00:00+00:00");
        // Y el `RRULE` del aviso tampoco lo marca como repetido: el que se
        // repite es el recordatorio, no la reunión.
        assert!(!event.recurring);
    }

    /// Sin comienzo no hay dónde ponerlo en el mes. El estándar lo exige, pero
    /// un servidor puede mandar cualquier cosa y no puede tirar la lista entera.
    #[test]
    fn un_evento_sin_comienzo_se_saltea_sin_perder_los_demas() {
        let ical = "BEGIN:VCALENDAR\r\n\
            BEGIN:VEVENT\r\nUID:roto\r\nSUMMARY:Sin fecha\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nUID:sano\r\nSUMMARY:Con fecha\r\nDTSTART:20260915T140000Z\r\nEND:VEVENT\r\n\
            END:VCALENDAR\r\n";

        let events = events_from(ical);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].uid, "sano");
    }

    /// Sin `DTEND`, un evento de día completo dura un día y uno con hora no dura
    /// nada. Inventar una hora de fin mostraría una barra que no corresponde.
    #[test]
    fn sin_fin_la_duracion_es_la_que_dice_el_estandar() {
        let by_day = "BEGIN:VEVENT\r\nUID:d\r\nDTSTART;VALUE=DATE:20260915\r\nEND:VEVENT\r\n";
        let event = &events_from(by_day)[0];
        assert_eq!(event.start, "2026-09-15T00:00:00+00:00");
        assert_eq!(event.end, "2026-09-16T00:00:00+00:00");

        let timed = "BEGIN:VEVENT\r\nUID:h\r\nDTSTART:20260915T140000Z\r\nEND:VEVENT\r\n";
        let event = &events_from(timed)[0];
        assert_eq!(event.start, event.end);
    }

    /// Un evento que se repite se marca: la ventana puede decir que hay más, en
    /// vez de mostrar una reunión semanal como si fuera única.
    #[test]
    fn un_evento_que_se_repite_queda_marcado() {
        let ical = "BEGIN:VEVENT\r\nUID:r\r\nDTSTART:20260915T140000Z\r\n\
                    RRULE:FREQ=WEEKLY;COUNT=10\r\nEND:VEVENT\r\n";
        assert!(events_from(ical)[0].recurring);
    }

    /// Un evento sin título existe y ocupa lugar en el día de la persona igual,
    /// así que se muestra vacío en vez de descartarse.
    #[test]
    fn un_evento_sin_titulo_se_muestra_igual() {
        let ical = "BEGIN:VEVENT\r\nUID:x\r\nDTSTART:20260915T140000Z\r\nEND:VEVENT\r\n";
        let events = events_from(ical);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].title, "");
    }

    /// Basura no puede hacer caer nada: viene de un servidor y de eventos que
    /// escribió cualquiera.
    #[test]
    fn lo_que_no_es_un_calendario_no_da_eventos() {
        for garbage in [
            "",
            "no es un calendario",
            "BEGIN:VEVENT",
            "END:VEVENT\r\n",
            ":::",
        ] {
            assert!(events_from(garbage).is_empty(), "{garbage:?}");
        }
    }

    /// Lo que se muestra no lleva caracteres de control: un título con un
    /// `\u{1b}` o un salto de línea escapado no pinta la terminal ni parte la
    /// fila del widget.
    #[test]
    fn el_titulo_no_lleva_caracteres_de_control() {
        let ical = "BEGIN:VEVENT\r\nUID:x\r\nDTSTART:20260915T140000Z\r\n\
                    SUMMARY:Uno\\nDos\u{1b}[31m\u{7}\r\nEND:VEVENT\r\n";
        assert_eq!(events_from(ical)[0].title, "Uno Dos[31m");
    }

    /// El árbol tiene topes: un archivo con miles de componentes o anidado sin
    /// fin se lee hasta el tope y lo dice, sin llenar la memoria ni la pila.
    #[test]
    fn el_arbol_tiene_topes_de_componentes_y_de_anidado() {
        let many = format!(
            "BEGIN:VCALENDAR\r\n{}END:VCALENDAR\r\n",
            "BEGIN:VEVENT\r\nUID:x\r\nDTSTART:20260915T140000Z\r\nEND:VEVENT\r\n".repeat(5000)
        );
        let document = parse_document(&many);
        assert!(document.truncated);
        assert_eq!(document.components.len(), MAX_COMPONENTS - 1);

        let deep = format!(
            "{}{}",
            "BEGIN:X\r\n".repeat(100_000),
            "END:X\r\n".repeat(100_000)
        );
        let document = parse_document(&deep);
        assert!(document.truncated);
        assert_eq!(document.components.len(), 1);

        let props = format!(
            "BEGIN:VEVENT\r\n{}END:VEVENT\r\n",
            "X-A:1\r\n".repeat(MAX_PROPERTIES + 10)
        );
        let document = parse_document(&props);
        assert!(document.truncated);
        assert_eq!(document.components[0].properties.len(), MAX_PROPERTIES);
    }

    /// Un `END` que no corresponde no desarma el árbol: cierra hasta el que sí
    /// corresponde, y uno sin abrir se ignora.
    #[test]
    fn un_end_que_no_corresponde_no_rompe_el_arbol() {
        let ical = "BEGIN:VCALENDAR\r\nEND:VALARM\r\nBEGIN:VEVENT\r\nUID:a\r\n\
                    DTSTART:20260915T140000Z\r\nBEGIN:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let events = events_from(ical);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].uid, "a");
    }

    /// Los recortes no parten un carácter.
    #[test]
    fn los_recortes_no_parten_un_caracter() {
        assert_eq!(clipped("añb", 2), "a");
        assert_eq!(visible("ññññ", 3), "ñ");
        assert_eq!(visible_multiline("uno\n\tdos\u{1}", 100), "uno\n\tdos");
    }
}
