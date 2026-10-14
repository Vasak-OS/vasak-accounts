//! Escribir iCalendar, conservador: se parte del crudo y se toca sólo lo que
//! cambió.
//!
//! [`apply_changes`] edita un `VEVENT` que ya existe —cambia las propiedades que
//! el parche nombra, deja el resto byte por byte y sube el `SEQUENCE`—, y
//! [`new_event`] arma uno desde cero con lo mínimo que exige el estándar (`UID`,
//! `DTSTAMP`) más lo que el parche traiga.
//!
//! ── Qué no se toca ──────────────────────────────────────────────────────────
//!
//! Un `VTIMEZONE` no se reescribe: puede venir de Outlook con reglas que el
//! programa no modela, y rehacerlo correría las horas de todos los eventos que
//! lo usan. Un `VALARM` adentro del evento tampoco: es del recordatorio. Sólo se
//! editan las propiedades que cuelgan directo del `VEVENT` que se edita.
//!
//! ── Cuál `VEVENT` se edita ──────────────────────────────────────────────────
//!
//! Un recurso de CalDAV puede traer varios `VEVENT` con el mismo `UID`: el
//! maestro de una serie y sus excepciones, cada una con un `RECURRENCE-ID`. Se
//! edita el **maestro** —el primero sin `RECURRENCE-ID`—, porque editar «el
//! evento» es editar la serie, no una de sus apariciones. Si todos tienen
//! `RECURRENCE-ID`, se edita el primero; si no hay ninguno, el crudo vuelve
//! igual.

use super::{detect_eol, escape_text, fold, logical_lines, render, Change, Logical};
use crate::ical::{split_line, DateValue};

/// Lo que puede salir mal al serializar.
///
/// Un valor o un parámetro vienen de afuera —en el PR de la cola, de la ventana
/// por D-Bus—, y lo que se escribe se sube al servidor con la credencial de la
/// persona. Un `\r` o un `\n` incrustado en una fecha o en un parámetro partiría
/// la línea e inyectaría una propiedad o un componente entero en el cuerpo
/// CalDAV. Por eso no se filtra en silencio —fabricaría una fecha distinta de la
/// que se pidió—: se **rechaza**. Los mensajes son fijos y no repiten el valor,
/// que podría terminar en un registro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SerializeError {
    /// La fecha no cumple el formato de iCalendar, o trae caracteres de control.
    MalformedDate,
    /// Un parámetro trae un carácter que partiría la línea (`:`, CR o LF).
    InjectableParam,
    /// Un identificador (`UID`, `DTSTAMP`) trae un carácter de control.
    ControlInField,
}

impl std::fmt::Display for SerializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SerializeError::MalformedDate => "la fecha no tiene el formato de iCalendar",
            SerializeError::InjectableParam => "un parámetro tiene un carácter que no se permite",
            SerializeError::ControlInField => "un identificador tiene un carácter de control",
        })
    }
}

impl std::error::Error for SerializeError {}

/// Si un texto trae algún carácter de control —`\r` y `\n` entre ellos—, que
/// partiría la línea al escribirla.
fn has_control(text: &str) -> bool {
    text.chars().any(char::is_control)
}

/// Comprueba una fecha antes de escribirla: los parámetros sin control ni dos
/// puntos, y el valor con un formato de fecha de iCalendar de verdad.
///
/// Validar el valor con el **mismo** lector que usa la lectura
/// ([`DateValue::parse`]) cierra la inyección por el valor: un `20260101T000000Z`
/// con un `\r\n` y una propiedad pegada detrás no es una fecha, así que no pasa.
fn validate_date(spec: &DateSpec) -> Result<(), SerializeError> {
    for param in &spec.params {
        if has_control(param) || param.contains(':') {
            return Err(SerializeError::InjectableParam);
        }
    }
    if DateValue::parse(&spec.value, &spec.params).is_none() {
        return Err(SerializeError::MalformedDate);
    }
    Ok(())
}

/// Comprueba las fechas que el parche fija.
fn validate_patch(patch: &EventPatch) -> Result<(), SerializeError> {
    if let Change::Set(spec) = &patch.start {
        validate_date(spec)?;
    }
    if let Change::Set(spec) = &patch.end {
        validate_date(spec)?;
    }
    Ok(())
}

/// Una fecha para escribir: el valor tal como va y sus parámetros.
///
/// El valor —`20260915T140000`, `20260915`, `20260915T140000Z`— y los
/// parámetros —`TZID=Europe/Madrid`, `VALUE=DATE`— los arma quien llama, que es
/// quien sabe la zona. Acá no se interpretan: se escriben. Así la escritura no
/// vuelve a resolver una zona que la lectura ya resolvió.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DateSpec {
    pub value: String,
    pub params: Vec<String>,
}

/// Lo que cambia de un `VEVENT`.
///
/// Cada campo es un [`Change`]: por omisión no se toca, así que un parche sólo
/// nombra lo que cambia. Las propiedades de texto —`SUMMARY`, `DESCRIPTION`,
/// `LOCATION`— se escapan; las fechas van tal como las arma quien llama.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventPatch {
    pub summary: Change<String>,
    pub description: Change<String>,
    pub location: Change<String>,
    pub start: Change<DateSpec>,
    pub end: Change<DateSpec>,
}

impl EventPatch {
    /// Si no cambia nada: todos los campos en `Leave`.
    pub fn is_empty(&self) -> bool {
        self.summary == Change::Leave
            && self.description == Change::Leave
            && self.location == Change::Leave
            && self.start == Change::Leave
            && self.end == Change::Leave
    }
}

/// El nombre y el valor de una línea lógica, en mayúsculas el nombre. El valor
/// vacío cuando la línea no tiene dos puntos.
fn name_and_value(logical: &Logical) -> (String, String) {
    match split_line(&logical.unfolded()) {
        Some((name, _, value)) => (name, value),
        None => (String::new(), String::new()),
    }
}

/// Si una pila de componentes abiertos deja al `VEVENT` que se abre como de
/// primer nivel: suelto, o colgando directo del `VCALENDAR`.
fn is_top_level(stack: &[String]) -> bool {
    stack.is_empty() || stack == ["VCALENDAR"]
}

/// Qué `VEVENT` de primer nivel se edita: el primero sin `RECURRENCE-ID`, o el
/// primero a secas, o ninguno si no hay `VEVENT`.
fn target_ordinal(logicals: &[Logical]) -> Option<usize> {
    let mut stack: Vec<String> = Vec::new();
    // Por cada `VEVENT` de primer nivel, si trae un `RECURRENCE-ID`.
    let mut has_recurrence_id: Vec<bool> = Vec::new();
    // El índice y la profundidad del `VEVENT` que se está mirando.
    let mut recording: Option<(usize, usize)> = None;

    for logical in logicals {
        let (name, value) = name_and_value(logical);
        match name.as_str() {
            "BEGIN" => {
                let component = value.trim().to_ascii_uppercase();
                let top_level = is_top_level(&stack);
                stack.push(component.clone());
                if component == "VEVENT" && top_level {
                    recording = Some((has_recurrence_id.len(), stack.len()));
                    has_recurrence_id.push(false);
                }
            }
            "END" => {
                if let Some((_, depth)) = recording {
                    if stack.len() == depth {
                        recording = None;
                    }
                }
                stack.pop();
            }
            "RECURRENCE-ID" => {
                if let Some((index, depth)) = recording {
                    if stack.len() == depth {
                        has_recurrence_id[index] = true;
                    }
                }
            }
            _ => {}
        }
    }

    has_recurrence_id
        .iter()
        .position(|has| !has)
        .or((!has_recurrence_id.is_empty()).then_some(0))
}

/// Edita un `VEVENT` que ya existe: cambia lo que el parche nombra, deja el
/// resto intacto y sube el `SEQUENCE`.
///
/// Un parche vacío devuelve el crudo tal cual —no hay edición, no hay que subir
/// el `SEQUENCE`—, y un crudo sin `VEVENT` también: no hay qué editar. Una fecha
/// o un parámetro que inyectaría una línea devuelve `Err` (ver [`SerializeError`]).
pub fn apply_changes(raw_ical: &str, patch: &EventPatch) -> Result<String, SerializeError> {
    if patch.is_empty() {
        return Ok(raw_ical.to_string());
    }
    validate_patch(patch)?;
    let eol = detect_eol(raw_ical);
    let logicals = logical_lines(raw_ical);
    let Some(target) = target_ordinal(&logicals) else {
        return Ok(raw_ical.to_string());
    };

    let mut out: Vec<String> = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut vevents_begun = 0usize;
    // En qué profundidad quedó el `VEVENT` que se edita, mientras está abierto.
    let mut target_depth: Option<usize> = None;

    // Qué propiedades del parche ya se escribieron en el objetivo.
    let mut done = Done::default();
    let mut sequence_seen = false;

    for logical in &logicals {
        let (name, value) = name_and_value(logical);
        match name.as_str() {
            "BEGIN" => {
                let component = value.trim().to_ascii_uppercase();
                let top_level = is_top_level(&stack);
                stack.push(component.clone());
                if component == "VEVENT" && top_level {
                    if vevents_begun == target {
                        target_depth = Some(stack.len());
                    }
                    vevents_begun += 1;
                }
                out.extend_from_slice(&logical.physical);
            }
            "END" => {
                let closing_target = component_closes_target(&stack, &target_depth, &value);
                if closing_target {
                    flush(&mut out, patch, &done, sequence_seen);
                    target_depth = None;
                }
                stack.pop();
                out.extend_from_slice(&logical.physical);
            }
            _ => {
                if direct_in_target(&stack, &target_depth) {
                    edit_property(
                        &mut out,
                        logical,
                        &name,
                        &value,
                        patch,
                        &mut done,
                        &mut sequence_seen,
                    );
                } else {
                    out.extend_from_slice(&logical.physical);
                }
            }
        }
    }

    let mut text = out.join(eol);
    text.push_str(eol);
    Ok(text)
}

/// Arma un `VEVENT` desde cero, con lo mínimo que exige el estándar más lo que
/// traiga el parche.
///
/// El `UID` y el `DTSTAMP` los da quien llama: el `UID` identifica el evento en
/// el servidor para siempre, y el `DTSTAMP` es cuándo se armó este objeto. No
/// lleva `SEQUENCE`: uno nuevo es la versión cero, y el estándar la supone
/// cuando no está. Un `UID` o un `DTSTAMP` con caracteres de control, o una
/// fecha del parche que inyectaría una línea, devuelven `Err`.
pub fn new_event(uid: &str, dtstamp: &str, patch: &EventPatch) -> Result<String, SerializeError> {
    if has_control(uid) {
        return Err(SerializeError::ControlInField);
    }
    // El `DTSTAMP` es un instante en UTC: se valida como una fecha de verdad, que
    // de paso rechaza un `\r\n` incrustado.
    if DateValue::parse(dtstamp, &[]).is_none() {
        return Err(SerializeError::ControlInField);
    }
    validate_patch(patch)?;
    let eol = "\r\n";
    let mut out: Vec<String> = vec![
        "BEGIN:VCALENDAR".into(),
        "VERSION:2.0".into(),
        "PRODID:-//Vasak Group//VasakOS//ES".into(),
        "BEGIN:VEVENT".into(),
    ];
    out.extend(fold(&render("UID", &[], uid)));
    out.extend(fold(&render("DTSTAMP", &[], dtstamp)));
    push_set(&mut out, patch);
    out.push("END:VEVENT".into());
    out.push("END:VCALENDAR".into());

    let mut text = out.join(eol);
    text.push_str(eol);
    Ok(text)
}

/// Qué propiedades del objetivo ya se reescribieron, para no duplicarlas ni
/// volver a agregarlas al cerrar.
#[derive(Default)]
struct Done {
    summary: bool,
    description: bool,
    location: bool,
    start: bool,
    end: bool,
}

/// Si lo que se está cerrando es el `VEVENT` que se edita: un `END:VEVENT` a la
/// profundidad en la que quedó el objetivo.
fn component_closes_target(stack: &[String], target_depth: &Option<usize>, value: &str) -> bool {
    matches!(target_depth, Some(depth) if *depth == stack.len())
        && value.trim().eq_ignore_ascii_case("VEVENT")
}

/// Si la propiedad actual cuelga directo del `VEVENT` que se edita (y no de un
/// `VALARM` de adentro).
fn direct_in_target(stack: &[String], target_depth: &Option<usize>) -> bool {
    matches!(target_depth, Some(depth) if *depth == stack.len())
}

/// Decide qué hacer con una propiedad que cuelga del objetivo: reescribirla,
/// sacarla, subir el `SEQUENCE`, o dejarla como estaba.
fn edit_property(
    out: &mut Vec<String>,
    logical: &Logical,
    name: &str,
    value: &str,
    patch: &EventPatch,
    done: &mut Done,
    sequence_seen: &mut bool,
) {
    let params = split_line(&logical.unfolded())
        .map(|(_, params, _)| params)
        .unwrap_or_default();
    match name {
        "SUMMARY" => put_text(
            out,
            &patch.summary,
            &mut done.summary,
            name,
            &params,
            logical,
        ),
        "DESCRIPTION" => put_text(
            out,
            &patch.description,
            &mut done.description,
            name,
            &params,
            logical,
        ),
        "LOCATION" => put_text(
            out,
            &patch.location,
            &mut done.location,
            name,
            &params,
            logical,
        ),
        "DTSTART" => put_date(out, &patch.start, &mut done.start, name, logical),
        "DTEND" => put_date(out, &patch.end, &mut done.end, name, logical),
        "SEQUENCE" => {
            *sequence_seen = true;
            let current = value.trim().parse::<u64>().unwrap_or(0);
            let next = current.saturating_add(1);
            out.extend(fold(&render("SEQUENCE", &[], &next.to_string())));
        }
        _ => out.extend_from_slice(&logical.physical),
    }
}

/// Reescribe —o saca, o deja— una propiedad de texto, **conservando sus
/// parámetros**: al editar el valor no se tira el `LANGUAGE` ni el `ALTREP` que
/// tenía. Una segunda aparición de la misma propiedad ya fijada se descarta.
fn put_text(
    out: &mut Vec<String>,
    change: &Change<String>,
    done: &mut bool,
    name: &str,
    params: &[String],
    logical: &Logical,
) {
    match change {
        Change::Leave => out.extend_from_slice(&logical.physical),
        Change::Clear => {}
        Change::Set(text) => {
            if !*done {
                *done = true;
                out.extend(fold(&render(name, params, &escape_text(text))));
            }
        }
    }
}

/// Reescribe —o saca, o deja— una fecha. A diferencia del texto, los parámetros
/// vienen con el valor nuevo ([`DateSpec`]): la zona es parte de lo que cambió.
fn put_date(
    out: &mut Vec<String>,
    change: &Change<DateSpec>,
    done: &mut bool,
    name: &str,
    logical: &Logical,
) {
    match change {
        Change::Leave => out.extend_from_slice(&logical.physical),
        Change::Clear => {}
        Change::Set(spec) => {
            if !*done {
                *done = true;
                out.extend(fold(&render(name, &spec.params, &spec.value)));
            }
        }
    }
}

/// Al cerrar el objetivo: agrega lo que el parche fija y no estaba, y sube el
/// `SEQUENCE` (lo pone en 1 si no estaba). En un orden fijo, para que dos
/// corridas den lo mismo.
fn flush(out: &mut Vec<String>, patch: &EventPatch, done: &Done, sequence_seen: bool) {
    if let Change::Set(text) = &patch.summary {
        if !done.summary {
            out.extend(fold(&render("SUMMARY", &[], &escape_text(text))));
        }
    }
    if let Change::Set(text) = &patch.description {
        if !done.description {
            out.extend(fold(&render("DESCRIPTION", &[], &escape_text(text))));
        }
    }
    if let Change::Set(text) = &patch.location {
        if !done.location {
            out.extend(fold(&render("LOCATION", &[], &escape_text(text))));
        }
    }
    if let Change::Set(spec) = &patch.start {
        if !done.start {
            out.extend(fold(&render("DTSTART", &spec.params, &spec.value)));
        }
    }
    if let Change::Set(spec) = &patch.end {
        if !done.end {
            out.extend(fold(&render("DTEND", &spec.params, &spec.value)));
        }
    }
    // Editar es subir el `SEQUENCE`; si no estaba, la primera edición lo pone en 1.
    if !sequence_seen {
        out.extend(fold(&render("SEQUENCE", &[], "1")));
    }
}

/// Escribe las propiedades que el parche fija, para armar un evento nuevo.
fn push_set(out: &mut Vec<String>, patch: &EventPatch) {
    if let Change::Set(text) = &patch.summary {
        out.extend(fold(&render("SUMMARY", &[], &escape_text(text))));
    }
    if let Change::Set(text) = &patch.description {
        out.extend(fold(&render("DESCRIPTION", &[], &escape_text(text))));
    }
    if let Change::Set(text) = &patch.location {
        out.extend(fold(&render("LOCATION", &[], &escape_text(text))));
    }
    if let Change::Set(spec) = &patch.start {
        out.extend(fold(&render("DTSTART", &spec.params, &spec.value)));
    }
    if let Change::Set(spec) = &patch.end {
        out.extend(fold(&render("DTEND", &spec.params, &spec.value)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ical::{events_from, parse_document};

    /// Edita y desenvuelve: las pruebas de camino feliz no esperan error.
    fn edited(raw: &str, patch: &EventPatch) -> String {
        apply_changes(raw, patch).unwrap()
    }

    /// Crea y desenvuelve.
    fn created(uid: &str, dtstamp: &str, patch: &EventPatch) -> String {
        new_event(uid, dtstamp, patch).unwrap()
    }

    fn set(text: &str) -> Change<String> {
        Change::Set(text.to_string())
    }

    fn utc(value: &str) -> Change<DateSpec> {
        Change::Set(DateSpec {
            value: value.to_string(),
            params: Vec::new(),
        })
    }

    const EVENT: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:abc\r\n\
        SUMMARY:Reunión\r\nDTSTART:20260915T140000Z\r\nDTEND:20260915T150000Z\r\n\
        SEQUENCE:3\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    /// **El corazón de la escritura conservadora: lo que no se toca sale igual.**
    /// Se edita sólo el `SUMMARY` y el resto del objeto —`UID`, las fechas, la
    /// versión— vuelve a leerse idéntico. Sin partir del crudo, reconstruir
    /// desde el modelo perdería todo lo que el modelo no guarda.
    #[test]
    fn editar_una_propiedad_deja_el_resto_intacto() {
        let patch = EventPatch {
            summary: set("Reunión movida"),
            ..Default::default()
        };
        let out = edited(EVENT, &patch);

        let before = &events_from(EVENT)[0];
        let after = &events_from(&out)[0];
        assert_eq!(after.title, "Reunión movida");
        // Todo lo demás, igual que antes de editar.
        assert_eq!(after.uid, before.uid);
        assert_eq!(after.start, before.start);
        assert_eq!(after.end, before.end);
        // Y la versión del calendario sigue ahí, byte por byte.
        assert!(out.contains("VERSION:2.0"));
    }

    /// Editar sube el `SEQUENCE`: 3 → 4. Es como un servidor CalDAV sabe que la
    /// copia de la persona es más nueva que la suya.
    #[test]
    fn editar_sube_el_sequence() {
        let patch = EventPatch {
            summary: set("Otra cosa"),
            ..Default::default()
        };
        let out = edited(EVENT, &patch);
        assert!(out.contains("SEQUENCE:4"), "{out}");
        assert!(!out.contains("SEQUENCE:3"));
    }

    /// Un evento sin `SEQUENCE` empieza en 1 a la primera edición (el estándar
    /// supone 0 cuando no está).
    #[test]
    fn sin_sequence_la_primera_edicion_lo_pone_en_uno() {
        let raw =
            "BEGIN:VEVENT\r\nUID:a\r\nSUMMARY:X\r\nDTSTART:20260915T140000Z\r\nEND:VEVENT\r\n";
        let out = edited(
            raw,
            &EventPatch {
                summary: set("Y"),
                ..Default::default()
            },
        );
        assert!(out.contains("SEQUENCE:1"), "{out}");
    }

    /// **Las propiedades desconocidas no se pierden.** Una `X-` que el programa
    /// no entiende, y un `VALARM` entero, salen tal como entraron.
    #[test]
    fn lo_desconocido_y_el_valarm_se_conservan() {
        let raw = "BEGIN:VEVENT\r\nUID:a\r\nSUMMARY:Vieja\r\n\
            X-MICROSOFT-CDO-BUSYSTATUS:BUSY\r\nDTSTART:20260915T140000Z\r\n\
            BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT15M\r\nSUMMARY:Aviso\r\nEND:VALARM\r\n\
            END:VEVENT\r\n";
        let out = edited(
            raw,
            &EventPatch {
                summary: set("Nueva"),
                ..Default::default()
            },
        );
        assert!(out.contains("X-MICROSOFT-CDO-BUSYSTATUS:BUSY"), "{out}");
        assert!(out.contains("BEGIN:VALARM"));
        assert!(out.contains("TRIGGER:-PT15M"));
        // El `SUMMARY` del evento cambió, pero el del `VALARM` no.
        assert!(out.contains("SUMMARY:Nueva"));
        assert!(out.contains("SUMMARY:Aviso"));
    }

    /// Un `VTIMEZONE` no se reescribe: sus reglas pueden no estar modeladas y
    /// rehacerlo correría las horas de todo lo que lo usa.
    #[test]
    fn el_vtimezone_no_se_toca() {
        let raw = "BEGIN:VCALENDAR\r\nBEGIN:VTIMEZONE\r\nTZID:Romance Standard Time\r\n\
            BEGIN:STANDARD\r\nDTSTART:16010101T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\n\
            END:STANDARD\r\nEND:VTIMEZONE\r\n\
            BEGIN:VEVENT\r\nUID:a\r\nSUMMARY:Vieja\r\n\
            DTSTART;TZID=Romance Standard Time:20260715T090000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let out = edited(
            raw,
            &EventPatch {
                summary: set("Nueva"),
                ..Default::default()
            },
        );
        assert!(out.contains("BEGIN:VTIMEZONE"));
        assert!(out.contains("TZID:Romance Standard Time"));
        assert!(out.contains("TZOFFSETTO:+0100"));
        // El `DTSTART` con su zona sigue igual: no se editó.
        assert!(out.contains("DTSTART;TZID=Romance Standard Time:20260715T090000"));
    }

    /// Se edita el maestro de una serie, no una excepción con `RECURRENCE-ID`.
    #[test]
    fn se_edita_el_maestro_y_no_la_excepcion() {
        let raw = "BEGIN:VCALENDAR\r\n\
            BEGIN:VEVENT\r\nUID:s\r\nSUMMARY:Maestro\r\nDTSTART:20260915T140000Z\r\n\
            RRULE:FREQ=WEEKLY\r\nEND:VEVENT\r\n\
            BEGIN:VEVENT\r\nUID:s\r\nRECURRENCE-ID:20260922T140000Z\r\nSUMMARY:Excepción\r\n\
            DTSTART:20260922T150000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let out = edited(
            raw,
            &EventPatch {
                summary: set("Maestro nuevo"),
                ..Default::default()
            },
        );
        assert!(out.contains("SUMMARY:Maestro nuevo"), "{out}");
        // La excepción no se tocó.
        assert!(out.contains("SUMMARY:Excepción"));
        assert!(!out.contains("SUMMARY:Maestro\r"));
    }

    /// Fijar una propiedad que no estaba la agrega; sacar una que estaba la
    /// quita.
    #[test]
    fn se_agrega_lo_que_falta_y_se_saca_lo_que_sobra() {
        let raw = "BEGIN:VEVENT\r\nUID:a\r\nSUMMARY:X\r\nLOCATION:Sala 1\r\n\
            DTSTART:20260915T140000Z\r\nEND:VEVENT\r\n";
        let out = edited(
            raw,
            &EventPatch {
                description: set("Agenda del día"),
                location: Change::Clear,
                ..Default::default()
            },
        );
        assert!(out.contains("DESCRIPTION:Agenda del día"), "{out}");
        assert!(!out.contains("LOCATION"));
    }

    /// El texto se escapa como lo deshace la lectura: una coma no parte el
    /// título, y al leerlo otra vez vuelve entero.
    #[test]
    fn el_texto_editado_se_escapa_y_vuelve_entero() {
        let out = edited(
            EVENT,
            &EventPatch {
                summary: set("Reunión, con Ana; y Marta"),
                ..Default::default()
            },
        );
        assert!(
            out.contains(r"SUMMARY:Reunión\, con Ana\; y Marta"),
            "{out}"
        );
        assert_eq!(events_from(&out)[0].title, "Reunión, con Ana; y Marta");
    }

    /// Al cambiar la fecha, los parámetros nuevos mandan: la zona es parte de lo
    /// que cambió.
    #[test]
    fn cambiar_la_fecha_reemplaza_valor_y_parametros() {
        let out = edited(
            EVENT,
            &EventPatch {
                start: Change::Set(DateSpec {
                    value: "20261001T100000".into(),
                    params: vec!["TZID=Europe/Madrid".into()],
                }),
                ..Default::default()
            },
        );
        assert!(
            out.contains("DTSTART;TZID=Europe/Madrid:20261001T100000"),
            "{out}"
        );
        assert!(!out.contains("DTSTART:20260915T140000Z"));
    }

    /// Un valor largo se pliega a 75 octetos, como las líneas que no se tocan, y
    /// al leerlo vuelve entero.
    #[test]
    fn un_valor_largo_editado_se_pliega() {
        let largo = "Reunión ".repeat(40);
        let out = edited(
            EVENT,
            &EventPatch {
                summary: set(&largo),
                ..Default::default()
            },
        );
        for line in out.split("\r\n") {
            assert!(line.len() <= 75, "línea sin plegar: {line:?}");
        }
        assert_eq!(events_from(&out)[0].title, largo.trim());
    }

    /// **H1 (seguridad): una fecha con `\r\n` incrustado no inyecta líneas.**
    /// El valor viene de afuera —de la ventana por D-Bus en el PR de la cola— y
    /// lo que se escribe se sube al servidor con la credencial de la persona. Un
    /// `20260101T000000Z\r\nATTENDEE:mailto:x\r\nX-:` escrito crudo partiría la
    /// línea y metería un `ATTENDEE` y una propiedad en el `VEVENT`. Se rechaza,
    /// no se filtra: filtrar fabricaría una fecha distinta de la que se pidió.
    #[test]
    fn una_fecha_con_crlf_incrustado_se_rechaza() {
        let patch = EventPatch {
            start: Change::Set(DateSpec {
                value: "20260101T000000Z\r\nATTENDEE:mailto:x\r\nX-:".into(),
                params: Vec::new(),
            }),
            ..Default::default()
        };
        assert_eq!(
            apply_changes(EVENT, &patch),
            Err(SerializeError::MalformedDate)
        );

        // Y por `new_event` tampoco pasa: no se arma un evento con la inyección.
        assert_eq!(
            new_event("a", "20260101T000000Z", &patch),
            Err(SerializeError::MalformedDate)
        );
    }

    /// Y un parámetro de fecha con `\r\n` o con dos puntos tampoco: partiría la
    /// línea o se haría pasar por el valor.
    #[test]
    fn un_parametro_de_fecha_que_inyecta_se_rechaza() {
        for param in ["TZID=Europe/Madrid\r\nATTENDEE:mailto:x", "TZID=x:mailto:y"] {
            let patch = EventPatch {
                start: Change::Set(DateSpec {
                    value: "20260101T000000".into(),
                    params: vec![param.into()],
                }),
                ..Default::default()
            };
            assert_eq!(
                apply_changes(EVENT, &patch),
                Err(SerializeError::InjectableParam),
                "{param:?}"
            );
        }
    }

    /// Un `UID` o un `DTSTAMP` con caracteres de control tampoco arma un evento:
    /// son la misma clase de inyección por otra puerta.
    #[test]
    fn un_uid_o_dtstamp_con_control_se_rechaza() {
        let patch = EventPatch {
            summary: set("X"),
            ..Default::default()
        };
        assert_eq!(
            new_event("a\r\nX-:1", "20260101T000000Z", &patch),
            Err(SerializeError::ControlInField)
        );
        assert_eq!(
            new_event("a", "20260101T000000Z\r\nX-:1", &patch),
            Err(SerializeError::ControlInField)
        );
    }

    /// Una fecha bien formada —con su zona— sí pasa: la validación no es un muro
    /// para el uso normal.
    #[test]
    fn una_fecha_valida_con_zona_pasa() {
        let patch = EventPatch {
            start: Change::Set(DateSpec {
                value: "20261001T100000".into(),
                params: vec!["TZID=Europe/Madrid".into()],
            }),
            ..Default::default()
        };
        assert!(apply_changes(EVENT, &patch).is_ok());
    }

    /// Un parche vacío no toca nada —ni el `SEQUENCE`— y un crudo sin `VEVENT`
    /// vuelve igual.
    #[test]
    fn un_parche_vacio_o_sin_vevent_no_cambia_nada() {
        assert_eq!(edited(EVENT, &EventPatch::default()), EVENT);
        let no_event = "BEGIN:VCALENDAR\r\nBEGIN:VTODO\r\nUID:t\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";
        assert_eq!(
            edited(
                no_event,
                &EventPatch {
                    summary: set("X"),
                    ..Default::default()
                }
            ),
            no_event
        );
    }

    /// Un evento nuevo trae lo mínimo del estándar y lo que el parche fija, y se
    /// lee como un evento.
    #[test]
    fn un_evento_nuevo_es_valido_y_se_lee() {
        let out = created(
            "nuevo-123",
            "20261001T120000Z",
            &EventPatch {
                summary: set("Almuerzo"),
                start: utc("20261001T130000Z"),
                end: utc("20261001T140000Z"),
                ..Default::default()
            },
        );
        assert!(out.starts_with("BEGIN:VCALENDAR\r\n"));
        assert!(out.contains("UID:nuevo-123"));
        assert!(out.contains("DTSTAMP:20261001T120000Z"));
        // Uno nuevo es la versión cero: no lleva `SEQUENCE`.
        assert!(!out.contains("SEQUENCE"));

        let events = events_from(&out);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].uid, "nuevo-123");
        assert_eq!(events[0].title, "Almuerzo");
        assert_eq!(events[0].start, "2026-10-01T13:00:00+00:00");
    }

    /// Lo que se escribe es un calendario de verdad: el árbol de componentes se
    /// parsea sin truncarse.
    #[test]
    fn lo_escrito_es_un_arbol_valido() {
        let out = created(
            "x",
            "20261001T120000Z",
            &EventPatch {
                summary: set("Algo"),
                ..Default::default()
            },
        );
        let document = parse_document(&out);
        assert!(!document.truncated);
        assert_eq!(document.components.len(), 1);
        assert_eq!(document.components[0].name, "VEVENT");
    }
}
