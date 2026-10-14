//! Escribir iCalendar, conservador: se parte del crudo y se toca sólo lo que
//! cambió.
//!
//! [`apply_changes`] edita un `VEVENT` que ya existe —cambia las propiedades que
//! el parche nombra, deja el resto byte por byte y sube el `SEQUENCE`—, y
//! [`new_event`] arma uno desde cero con lo mínimo que exige el estándar (`UID`,
//! `DTSTAMP`) más lo que el parche traiga. [`apply_todo_changes`] y [`new_todo`]
//! hacen lo mismo con un `VTODO` —una tarea—, que vive en la misma colección de
//! calendario y se escribe por el mismo camino conservador.
//!
//! ── Qué no se toca ──────────────────────────────────────────────────────────
//!
//! Un `VTIMEZONE` no se reescribe: puede venir de Outlook con reglas que el
//! programa no modela, y rehacerlo correría las horas de todos los eventos que
//! lo usan. Un `VALARM` adentro del componente tampoco: es del recordatorio.
//! Sólo se editan las propiedades que cuelgan directo del componente que se
//! edita.
//!
//! ── Cuál componente se edita ────────────────────────────────────────────────
//!
//! Un recurso de CalDAV puede traer varios componentes con el mismo `UID`: el
//! maestro de una serie y sus excepciones, cada una con un `RECURRENCE-ID`. Se
//! edita el **maestro** —el primero sin `RECURRENCE-ID`—, porque editar «el
//! evento» (o «la tarea») es editar la serie, no una de sus apariciones. Si
//! todos tienen `RECURRENCE-ID`, se edita el primero; si no hay ninguno del tipo
//! que se busca, el crudo vuelve igual.
//!
//! ── Por qué un parche por tipo y un solo recorrido ──────────────────────────
//!
//! El recorrido del crudo —abrir componentes, saber cuál es el objetivo,
//! preservar lo ajeno, subir el `SEQUENCE`— es idéntico para un evento y para
//! una tarea: lo único que cambia es **qué propiedades** entiende cada parche.
//! Por eso el recorrido es genérico sobre [`ComponentPatch`] y cada tipo de
//! parche ([`EventPatch`], [`TaskPatch`]) sólo dice su nombre de componente,
//! cómo validarse contra inyección, y cómo reescribir sus propias líneas. Así
//! una sola pieza —la que preserva lo desconocido y la que valida— se audita una
//! vez y vale para los dos.

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
    /// El `PERCENT-COMPLETE` de una tarea está fuera de 0..=100.
    PercentOutOfRange,
    /// La `PRIORITY` de una tarea está fuera de 0..=9.
    PriorityOutOfRange,
}

impl std::fmt::Display for SerializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SerializeError::MalformedDate => "la fecha no tiene el formato de iCalendar",
            SerializeError::InjectableParam => "un parámetro tiene un carácter que no se permite",
            SerializeError::ControlInField => "un identificador tiene un carácter de control",
            SerializeError::PercentOutOfRange => "el porcentaje de una tarea va de 0 a 100",
            SerializeError::PriorityOutOfRange => "la prioridad de una tarea va de 0 a 9",
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
///
/// **Pero `DateValue::parse` recorta antes de validar**, así que un CR o un LF
/// al principio o al final del valor —`20260101T000000Z\r\n`— pasaría el parseo
/// y después la escritura, que usa `spec.value` **sin recortar**, metería el
/// salto crudo en la línea. Por eso el valor se rechaza por `has_control`
/// primero, igual que el `UID` y los parámetros: el control no es parte de una
/// fecha, venga en el medio o en el borde.
fn validate_date(spec: &DateSpec) -> Result<(), SerializeError> {
    for param in &spec.params {
        if has_control(param) || param.contains(':') {
            return Err(SerializeError::InjectableParam);
        }
    }
    if has_control(&spec.value) {
        return Err(SerializeError::MalformedDate);
    }
    if DateValue::parse(&spec.value, &spec.params).is_none() {
        return Err(SerializeError::MalformedDate);
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

/// El `STATUS` de una tarea, acotado a los cuatro valores del RFC 5545 §3.8.1.11
/// para un `VTODO`.
///
/// **Es un dominio cerrado a propósito:** el `STATUS` no sale de un texto libre
/// que termine en la línea, sino de uno de estos cuatro, así que no hay forma de
/// que un valor adversario escriba una propiedad nueva por acá. El parser JSON
/// de `store_api.rs` lo arma con [`TodoStatus::parse`], que rechaza cualquier
/// otra cosa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TodoStatus {
    NeedsAction,
    Completed,
    InProcess,
    Cancelled,
}

impl TodoStatus {
    /// El texto fijo que va a la línea `STATUS:`.
    pub fn as_ical(self) -> &'static str {
        match self {
            TodoStatus::NeedsAction => "NEEDS-ACTION",
            TodoStatus::Completed => "COMPLETED",
            TodoStatus::InProcess => "IN-PROCESS",
            TodoStatus::Cancelled => "CANCELLED",
        }
    }

    /// Un `STATUS` desde el texto que mandó quien llama; `None` si no es uno de
    /// los cuatro. No distingue mayúsculas: iCalendar los escribe en mayúsculas,
    /// pero una ventana podría mandar `completed`.
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_uppercase().as_str() {
            "NEEDS-ACTION" => Some(Self::NeedsAction),
            "COMPLETED" => Some(Self::Completed),
            "IN-PROCESS" => Some(Self::InProcess),
            "CANCELLED" => Some(Self::Cancelled),
            _ => None,
        }
    }
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

/// Lo que cambia de un `VTODO` —una tarea—.
///
/// Espejo conservador de [`EventPatch`]: cada campo es un [`Change`], así que un
/// parche sólo nombra lo que cambia. El texto se escapa; `due` es la fecha de
/// vencimiento, con valor y parámetros como las fechas de un evento; `status`,
/// `percent_complete` y `priority` van acotados a su dominio (ver
/// [`TodoStatus`], y la validación de rango en [`ComponentPatch::validate`]), no
/// como texto libre a la línea.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskPatch {
    pub summary: Change<String>,
    pub description: Change<String>,
    pub due: Change<DateSpec>,
    pub status: Change<TodoStatus>,
    pub percent_complete: Change<u8>,
    pub priority: Change<u8>,
}

impl TaskPatch {
    /// Si no cambia nada: todos los campos en `Leave`.
    pub fn is_empty(&self) -> bool {
        self.summary == Change::Leave
            && self.description == Change::Leave
            && self.due == Change::Leave
            && self.status == Change::Leave
            && self.percent_complete == Change::Leave
            && self.priority == Change::Leave
    }
}

/// Un parche de un componente de calendario que se edita conservador.
///
/// Sabe su nombre (`VEVENT` o `VTODO`), si está vacío, cómo validarse contra
/// inyección y rango, y cómo reescribir cada una de **sus propias**
/// propiedades. El recorrido del crudo —preservar lo ajeno, encontrar el
/// objetivo, subir el `SEQUENCE`— es común y vive en [`apply_component_changes`]
/// y [`new_component`], que son genéricos sobre este rasgo.
trait ComponentPatch {
    /// Qué propiedades propias ya se reescribieron, para no duplicarlas al
    /// cerrar el componente.
    type Done: Default;

    /// El nombre del componente: `VEVENT` o `VTODO`.
    const COMPONENT: &'static str;

    /// Si no cambia nada.
    fn is_empty(&self) -> bool;

    /// Comprueba lo que el parche fija antes de escribir nada: fechas que no
    /// inyecten una línea, rangos dentro de su dominio.
    fn validate(&self) -> Result<(), SerializeError>;

    /// Reescribe —o saca, o deja— una propiedad que cuelga del objetivo, si es
    /// una de las que este parche conoce. Devuelve `true` si la manejó (ya
    /// escribió lo que correspondía), `false` si no la conoce y hay que dejarla
    /// intacta. El `SEQUENCE` **no** pasa por acá: lo sube el recorrido genérico.
    fn edit_field(
        &self,
        out: &mut Vec<String>,
        logical: &Logical,
        name: &str,
        params: &[String],
        done: &mut Self::Done,
    ) -> bool;

    /// Al cerrar el objetivo: agrega lo que el parche fija y no estaba. En un
    /// orden fijo, para que dos corridas den lo mismo. El `SEQUENCE` lo agrega el
    /// recorrido genérico.
    fn flush_missing(&self, out: &mut Vec<String>, done: &Self::Done);

    /// Al crear: escribe lo que el parche fija. Es [`Self::flush_missing`] con
    /// nada hecho todavía —un objeto nuevo no trae ninguna propiedad, así que
    /// todas las que el parche fija se escriben—, así que las dos salen del mismo
    /// código y en el mismo orden.
    fn push_set(&self, out: &mut Vec<String>) {
        self.flush_missing(out, &Self::Done::default());
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

/// Si una pila de componentes abiertos deja al componente que se abre como de
/// primer nivel: suelto, o colgando directo del `VCALENDAR`.
fn is_top_level(stack: &[String]) -> bool {
    stack.is_empty() || stack == ["VCALENDAR"]
}

/// Qué componente de primer nivel del tipo buscado se edita: el primero sin
/// `RECURRENCE-ID`, o el primero a secas, o ninguno si no hay ninguno del tipo.
fn target_ordinal(logicals: &[Logical], component: &str) -> Option<usize> {
    let mut stack: Vec<String> = Vec::new();
    // Por cada componente de primer nivel del tipo, si trae un `RECURRENCE-ID`.
    let mut has_recurrence_id: Vec<bool> = Vec::new();
    // El índice y la profundidad del componente que se está mirando.
    let mut recording: Option<(usize, usize)> = None;

    for logical in logicals {
        let (name, value) = name_and_value(logical);
        match name.as_str() {
            "BEGIN" => {
                let begun = value.trim().to_ascii_uppercase();
                let top_level = is_top_level(&stack);
                stack.push(begun.clone());
                if begun == component && top_level {
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
    apply_component_changes(raw_ical, patch)
}

/// Edita un `VTODO` que ya existe. Espejo de [`apply_changes`] para una tarea:
/// mismo recorrido conservador, mismos resguardos contra inyección, otro juego
/// de propiedades (ver [`TaskPatch`]). Un crudo sin `VTODO` vuelve igual.
pub fn apply_todo_changes(raw_ical: &str, patch: &TaskPatch) -> Result<String, SerializeError> {
    apply_component_changes(raw_ical, patch)
}

/// El recorrido conservador, común al evento y a la tarea: encuentra el
/// componente objetivo, reescribe lo que el parche nombra, preserva lo ajeno
/// byte por byte y sube el `SEQUENCE`.
fn apply_component_changes<P: ComponentPatch>(
    raw: &str,
    patch: &P,
) -> Result<String, SerializeError> {
    if patch.is_empty() {
        return Ok(raw.to_string());
    }
    patch.validate()?;
    let eol = detect_eol(raw);
    let logicals = logical_lines(raw);
    let Some(target) = target_ordinal(&logicals, P::COMPONENT) else {
        return Ok(raw.to_string());
    };

    let mut out: Vec<String> = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut components_begun = 0usize;
    // En qué profundidad quedó el componente que se edita, mientras está abierto.
    let mut target_depth: Option<usize> = None;

    let mut done = P::Done::default();
    let mut sequence_seen = false;

    for logical in &logicals {
        let (name, value) = name_and_value(logical);
        match name.as_str() {
            "BEGIN" => {
                let begun = value.trim().to_ascii_uppercase();
                let top_level = is_top_level(&stack);
                stack.push(begun.clone());
                if begun == P::COMPONENT && top_level {
                    if components_begun == target {
                        target_depth = Some(stack.len());
                    }
                    components_begun += 1;
                }
                out.extend_from_slice(&logical.physical);
            }
            "END" => {
                if component_closes_target(&stack, &target_depth, &value, P::COMPONENT) {
                    patch.flush_missing(&mut out, &done);
                    // Editar es subir el `SEQUENCE`; si no estaba, va en 1.
                    if !sequence_seen {
                        out.extend(fold(&render("SEQUENCE", &[], "1")));
                    }
                    target_depth = None;
                }
                stack.pop();
                out.extend_from_slice(&logical.physical);
            }
            _ => {
                if direct_in_target(&stack, &target_depth) {
                    edit_direct(
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

/// Decide qué hacer con una propiedad que cuelga del objetivo: subir el
/// `SEQUENCE` (común a los dos tipos), reescribirla si el parche la conoce, o
/// dejarla como estaba.
fn edit_direct<P: ComponentPatch>(
    out: &mut Vec<String>,
    logical: &Logical,
    name: &str,
    value: &str,
    patch: &P,
    done: &mut P::Done,
    sequence_seen: &mut bool,
) {
    if name == "SEQUENCE" {
        *sequence_seen = true;
        let current = value.trim().parse::<u64>().unwrap_or(0);
        let next = current.saturating_add(1);
        out.extend(fold(&render("SEQUENCE", &[], &next.to_string())));
        return;
    }
    let params = split_line(&logical.unfolded())
        .map(|(_, params, _)| params)
        .unwrap_or_default();
    if !patch.edit_field(out, logical, name, &params, done) {
        out.extend_from_slice(&logical.physical);
    }
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
    new_component(uid, dtstamp, patch)
}

/// Arma un `VTODO` desde cero. Espejo de [`new_event`] para una tarea: mismo
/// mínimo del estándar (`UID`, `DTSTAMP`), mismos resguardos, las propiedades de
/// [`TaskPatch`].
pub fn new_todo(uid: &str, dtstamp: &str, patch: &TaskPatch) -> Result<String, SerializeError> {
    new_component(uid, dtstamp, patch)
}

/// El armado desde cero, común al evento y a la tarea.
fn new_component<P: ComponentPatch>(
    uid: &str,
    dtstamp: &str,
    patch: &P,
) -> Result<String, SerializeError> {
    if has_control(uid) {
        return Err(SerializeError::ControlInField);
    }
    // El `DTSTAMP` es un instante en UTC: se valida como una fecha de verdad, que
    // de paso rechaza un `\r\n` incrustado.
    if DateValue::parse(dtstamp, &[]).is_none() {
        return Err(SerializeError::ControlInField);
    }
    patch.validate()?;
    let eol = "\r\n";
    let mut out: Vec<String> = vec![
        "BEGIN:VCALENDAR".into(),
        "VERSION:2.0".into(),
        "PRODID:-//Vasak Group//VasakOS//ES".into(),
        format!("BEGIN:{}", P::COMPONENT),
    ];
    out.extend(fold(&render("UID", &[], uid)));
    out.extend(fold(&render("DTSTAMP", &[], dtstamp)));
    patch.push_set(&mut out);
    out.push(format!("END:{}", P::COMPONENT));
    out.push("END:VCALENDAR".into());

    let mut text = out.join(eol);
    text.push_str(eol);
    Ok(text)
}

/// Si lo que se está cerrando es el componente que se edita: un `END` a la
/// profundidad en la que quedó el objetivo, del tipo buscado.
fn component_closes_target(
    stack: &[String],
    target_depth: &Option<usize>,
    value: &str,
    component: &str,
) -> bool {
    matches!(target_depth, Some(depth) if *depth == stack.len())
        && value.trim().eq_ignore_ascii_case(component)
}

/// Si la propiedad actual cuelga directo del componente que se edita (y no de un
/// `VALARM` de adentro).
fn direct_in_target(stack: &[String], target_depth: &Option<usize>) -> bool {
    matches!(target_depth, Some(depth) if *depth == stack.len())
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

/// Reescribe —o saca, o deja— el `STATUS` de una tarea, conservando sus
/// parámetros. El valor es uno de los cuatro fijos de [`TodoStatus`]: no hay
/// texto libre que pueda inyectar una línea.
fn put_status(
    out: &mut Vec<String>,
    change: &Change<TodoStatus>,
    done: &mut bool,
    params: &[String],
    logical: &Logical,
) {
    match change {
        Change::Leave => out.extend_from_slice(&logical.physical),
        Change::Clear => {}
        Change::Set(status) => {
            if !*done {
                *done = true;
                out.extend(fold(&render("STATUS", params, status.as_ical())));
            }
        }
    }
}

/// Reescribe —o saca, o deja— un entero (`PERCENT-COMPLETE`, `PRIORITY`),
/// conservando sus parámetros. El valor es un número en decimal: no puede
/// inyectar una línea, y el rango ya lo comprobó [`TaskPatch::validate`].
fn put_number(
    out: &mut Vec<String>,
    change: &Change<u8>,
    done: &mut bool,
    name: &str,
    params: &[String],
    logical: &Logical,
) {
    match change {
        Change::Leave => out.extend_from_slice(&logical.physical),
        Change::Clear => {}
        Change::Set(number) => {
            if !*done {
                *done = true;
                out.extend(fold(&render(name, params, &number.to_string())));
            }
        }
    }
}

// ── Agregar lo que falta al cerrar (o al crear) ──────────────────────────────
//
// Las de arriba (`put_*`) editan una propiedad **en el lugar** mientras se
// recorre el objetivo: dejan lo que no cambia, sacan lo que se limpia. Las de
// abajo (`append_*`) son lo contrario: al cerrar el componente agregan lo que el
// parche fija y todavía **no** se escribió (`done` en `false`), y al crear uno
// nuevo —con `done` en `false` para todo— escriben lo que el parche fija. Son
// comunes al evento y a la tarea, así que `flush_missing` de cada uno es una
// lista de llamadas y no dos bloques casi iguales. Un valor nuevo nunca lleva
// los parámetros del crudo: no hay crudo.

/// Agrega una propiedad de texto si el parche la fija y no se escribió ya.
fn append_text(out: &mut Vec<String>, change: &Change<String>, done: bool, name: &str) {
    if let Change::Set(text) = change {
        if !done {
            out.extend(fold(&render(name, &[], &escape_text(text))));
        }
    }
}

/// Agrega una fecha si el parche la fija y no se escribió ya. Lleva sus
/// parámetros, que son parte del valor nuevo ([`DateSpec`]).
fn append_date(out: &mut Vec<String>, change: &Change<DateSpec>, done: bool, name: &str) {
    if let Change::Set(spec) = change {
        if !done {
            out.extend(fold(&render(name, &spec.params, &spec.value)));
        }
    }
}

/// Agrega el `STATUS` de una tarea si el parche lo fija y no se escribió ya.
fn append_status(out: &mut Vec<String>, change: &Change<TodoStatus>, done: bool, name: &str) {
    if let Change::Set(status) = change {
        if !done {
            out.extend(fold(&render(name, &[], status.as_ical())));
        }
    }
}

/// Agrega un entero (`PERCENT-COMPLETE`, `PRIORITY`) si el parche lo fija y no se
/// escribió ya.
fn append_number(out: &mut Vec<String>, change: &Change<u8>, done: bool, name: &str) {
    if let Change::Set(number) = change {
        if !done {
            out.extend(fold(&render(name, &[], &number.to_string())));
        }
    }
}

/// Qué propiedades de un evento ya se reescribieron, para no duplicarlas ni
/// volver a agregarlas al cerrar.
#[derive(Default)]
struct EventDone {
    summary: bool,
    description: bool,
    location: bool,
    start: bool,
    end: bool,
}

impl ComponentPatch for EventPatch {
    type Done = EventDone;
    const COMPONENT: &'static str = "VEVENT";

    fn is_empty(&self) -> bool {
        EventPatch::is_empty(self)
    }

    fn validate(&self) -> Result<(), SerializeError> {
        if let Change::Set(spec) = &self.start {
            validate_date(spec)?;
        }
        if let Change::Set(spec) = &self.end {
            validate_date(spec)?;
        }
        Ok(())
    }

    fn edit_field(
        &self,
        out: &mut Vec<String>,
        logical: &Logical,
        name: &str,
        params: &[String],
        done: &mut Self::Done,
    ) -> bool {
        match name {
            "SUMMARY" => put_text(out, &self.summary, &mut done.summary, name, params, logical),
            "DESCRIPTION" => put_text(
                out,
                &self.description,
                &mut done.description,
                name,
                params,
                logical,
            ),
            "LOCATION" => put_text(
                out,
                &self.location,
                &mut done.location,
                name,
                params,
                logical,
            ),
            "DTSTART" => put_date(out, &self.start, &mut done.start, name, logical),
            "DTEND" => put_date(out, &self.end, &mut done.end, name, logical),
            _ => return false,
        }
        true
    }

    fn flush_missing(&self, out: &mut Vec<String>, done: &Self::Done) {
        append_text(out, &self.summary, done.summary, "SUMMARY");
        append_text(out, &self.description, done.description, "DESCRIPTION");
        append_text(out, &self.location, done.location, "LOCATION");
        append_date(out, &self.start, done.start, "DTSTART");
        append_date(out, &self.end, done.end, "DTEND");
    }
}

/// Qué propiedades de una tarea ya se reescribieron.
#[derive(Default)]
struct TaskDone {
    summary: bool,
    description: bool,
    due: bool,
    status: bool,
    percent: bool,
    priority: bool,
}

impl ComponentPatch for TaskPatch {
    type Done = TaskDone;
    const COMPONENT: &'static str = "VTODO";

    fn is_empty(&self) -> bool {
        TaskPatch::is_empty(self)
    }

    fn validate(&self) -> Result<(), SerializeError> {
        if let Change::Set(spec) = &self.due {
            validate_date(spec)?;
        }
        if let Change::Set(percent) = &self.percent_complete {
            if *percent > 100 {
                return Err(SerializeError::PercentOutOfRange);
            }
        }
        if let Change::Set(priority) = &self.priority {
            if *priority > 9 {
                return Err(SerializeError::PriorityOutOfRange);
            }
        }
        Ok(())
    }

    fn edit_field(
        &self,
        out: &mut Vec<String>,
        logical: &Logical,
        name: &str,
        params: &[String],
        done: &mut Self::Done,
    ) -> bool {
        match name {
            "SUMMARY" => put_text(out, &self.summary, &mut done.summary, name, params, logical),
            "DESCRIPTION" => put_text(
                out,
                &self.description,
                &mut done.description,
                name,
                params,
                logical,
            ),
            "DUE" => put_date(out, &self.due, &mut done.due, name, logical),
            "STATUS" => put_status(out, &self.status, &mut done.status, params, logical),
            "PERCENT-COMPLETE" => put_number(
                out,
                &self.percent_complete,
                &mut done.percent,
                "PERCENT-COMPLETE",
                params,
                logical,
            ),
            "PRIORITY" => put_number(
                out,
                &self.priority,
                &mut done.priority,
                "PRIORITY",
                params,
                logical,
            ),
            _ => return false,
        }
        true
    }

    fn flush_missing(&self, out: &mut Vec<String>, done: &Self::Done) {
        append_text(out, &self.summary, done.summary, "SUMMARY");
        append_text(out, &self.description, done.description, "DESCRIPTION");
        append_date(out, &self.due, done.due, "DUE");
        append_status(out, &self.status, done.status, "STATUS");
        append_number(
            out,
            &self.percent_complete,
            done.percent,
            "PERCENT-COMPLETE",
        );
        append_number(out, &self.priority, done.priority, "PRIORITY");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ical::{events_from, parse_document, Component};

    /// El primer `VTODO` de un crudo, leído con el parser de verdad, para
    /// comprobar lo escrito.
    fn todo_of(raw: &str) -> Component {
        parse_document(raw)
            .components
            .into_iter()
            .find(|c| c.name == "VTODO")
            .expect("hay un VTODO")
    }

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

    /// **El borde que el incrustado no cubría: un CR/LF al principio o al final
    /// del valor.** `DateValue::parse` recorta antes de validar, así que
    /// `" 20260101T000000Z\r\n"` **parsearía** como una fecha; pero la escritura
    /// usa el valor sin recortar y metería el salto crudo en la línea. Se rechaza
    /// por `has_control`, no por el formato. Es código compartido: vale para el
    /// evento y para la tarea.
    #[test]
    fn una_fecha_de_evento_con_crlf_al_final_se_rechaza() {
        let patch = EventPatch {
            start: Change::Set(DateSpec {
                value: " 20260101T000000Z\r\n".into(),
                params: Vec::new(),
            }),
            ..Default::default()
        };
        assert_eq!(
            apply_changes(EVENT, &patch),
            Err(SerializeError::MalformedDate)
        );
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

    // ── Tareas (VTODO) ──────────────────────────────────────────────────────
    //
    // El mismo recorrido conservador, con las propiedades de una tarea. Lo que
    // se comprueba del lado del evento —preservar lo ajeno, subir el `SEQUENCE`,
    // rechazar la inyección— vale igual acá, porque es la misma pieza; estas
    // pruebas ejercen lo propio de la tarea: `due`, `status`, `percent` y
    // `priority`, y que sus dominios se respetan.

    /// Edita una tarea y desenvuelve.
    fn task_edited(raw: &str, patch: &TaskPatch) -> String {
        apply_todo_changes(raw, patch).unwrap()
    }

    /// Crea una tarea y desenvuelve.
    fn task_created(uid: &str, dtstamp: &str, patch: &TaskPatch) -> String {
        new_todo(uid, dtstamp, patch).unwrap()
    }

    const TASK: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTODO\r\nUID:t1\r\n\
        SUMMARY:Comprar pan\r\nDUE:20261001T100000Z\r\nSTATUS:NEEDS-ACTION\r\n\
        PERCENT-COMPLETE:0\r\nPRIORITY:5\r\nSEQUENCE:2\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";

    /// **Lo conservador también en la tarea: lo que no se toca sale igual.** Se
    /// edita sólo el `SUMMARY` y el resto —`UID`, el vencimiento, la versión—
    /// vuelve a leerse idéntico.
    #[test]
    fn editar_una_tarea_deja_el_resto_intacto() {
        let out = task_edited(
            TASK,
            &TaskPatch {
                summary: set("Comprar pan y leche"),
                ..Default::default()
            },
        );
        let after = todo_of(&out);
        assert_eq!(after.text("SUMMARY", 256).unwrap(), "Comprar pan y leche");
        // Todo lo demás, igual que antes de editar.
        assert_eq!(after.value("UID"), Some("t1"));
        assert_eq!(after.value("DUE"), Some("20261001T100000Z"));
        assert!(out.contains("VERSION:2.0"));
    }

    /// Editar una tarea sube el `SEQUENCE`: 2 → 3, por la misma pieza común que
    /// el evento.
    #[test]
    fn editar_una_tarea_sube_el_sequence() {
        let out = task_edited(
            TASK,
            &TaskPatch {
                status: Change::Set(TodoStatus::InProcess),
                ..Default::default()
            },
        );
        assert!(out.contains("SEQUENCE:3"), "{out}");
        assert!(!out.contains("SEQUENCE:2"));
    }

    /// Fijar el estado, el porcentaje y la prioridad de una tarea los reescribe
    /// en el lugar; sacar uno con `Clear` lo quita.
    #[test]
    fn cambiar_estado_porcentaje_y_prioridad() {
        let out = task_edited(
            TASK,
            &TaskPatch {
                status: Change::Set(TodoStatus::Completed),
                percent_complete: Change::Set(100),
                priority: Change::Clear,
                ..Default::default()
            },
        );
        assert!(out.contains("STATUS:COMPLETED"), "{out}");
        assert!(out.contains("PERCENT-COMPLETE:100"));
        assert!(!out.contains("PRIORITY"));
    }

    /// Fijar lo que no estaba lo agrega al cerrar la tarea, en el orden fijo.
    #[test]
    fn se_agrega_lo_que_falta_en_una_tarea() {
        let raw = "BEGIN:VTODO\r\nUID:t\r\nSUMMARY:Algo\r\nEND:VTODO\r\n";
        let out = task_edited(
            raw,
            &TaskPatch {
                due: Change::Set(DateSpec {
                    value: "20261115T090000Z".into(),
                    params: Vec::new(),
                }),
                status: Change::Set(TodoStatus::InProcess),
                priority: Change::Set(1),
                ..Default::default()
            },
        );
        assert!(out.contains("DUE:20261115T090000Z"), "{out}");
        assert!(out.contains("STATUS:IN-PROCESS"));
        assert!(out.contains("PRIORITY:1"));
        assert!(out.contains("SEQUENCE:1"));
    }

    /// **Lo desconocido de una tarea no se pierde**, igual que en un evento: una
    /// `X-` y un `VALARM` entero salen tal como entraron.
    #[test]
    fn lo_desconocido_de_una_tarea_se_conserva() {
        let raw = "BEGIN:VTODO\r\nUID:t\r\nSUMMARY:Vieja\r\n\
            X-APPLE-SORT-ORDER:12\r\nSTATUS:NEEDS-ACTION\r\n\
            BEGIN:VALARM\r\nACTION:DISPLAY\r\nTRIGGER:-PT1H\r\nEND:VALARM\r\n\
            END:VTODO\r\n";
        let out = task_edited(
            raw,
            &TaskPatch {
                summary: set("Nueva"),
                ..Default::default()
            },
        );
        assert!(out.contains("X-APPLE-SORT-ORDER:12"), "{out}");
        assert!(out.contains("BEGIN:VALARM"));
        assert!(out.contains("TRIGGER:-PT1H"));
        assert!(out.contains("SUMMARY:Nueva"));
    }

    /// El texto de una tarea se escapa como lo deshace la lectura, y vuelve
    /// entero.
    #[test]
    fn el_texto_de_una_tarea_se_escapa() {
        let out = task_edited(
            TASK,
            &TaskPatch {
                description: set("Harina, sal; y agua"),
                ..Default::default()
            },
        );
        assert!(out.contains(r"DESCRIPTION:Harina\, sal\; y agua"), "{out}");
        assert_eq!(
            todo_of(&out).text("DESCRIPTION", 256).unwrap(),
            "Harina, sal; y agua"
        );
    }

    /// Una tarea nueva trae lo mínimo del estándar y lo que el parche fija, y se
    /// lee como una tarea.
    #[test]
    fn una_tarea_nueva_es_valida_y_se_lee() {
        let out = task_created(
            "tarea-9",
            "20261001T120000Z",
            &TaskPatch {
                summary: set("Pagar la luz"),
                due: Change::Set(DateSpec {
                    value: "20261010T235900Z".into(),
                    params: Vec::new(),
                }),
                status: Change::Set(TodoStatus::NeedsAction),
                priority: Change::Set(3),
                ..Default::default()
            },
        );
        assert!(out.starts_with("BEGIN:VCALENDAR\r\n"));
        assert!(out.contains("BEGIN:VTODO"));
        assert!(out.contains("UID:tarea-9"));
        assert!(out.contains("DTSTAMP:20261001T120000Z"));
        assert!(out.contains("STATUS:NEEDS-ACTION"));
        assert!(out.contains("PRIORITY:3"));
        assert!(!out.contains("SEQUENCE"));

        let document = parse_document(&out);
        assert!(!document.truncated);
        assert_eq!(document.components.len(), 1);
        assert_eq!(document.components[0].name, "VTODO");
        let todo = &document.components[0];
        assert_eq!(todo.value("UID"), Some("tarea-9"));
        assert_eq!(todo.text("SUMMARY", 256).unwrap(), "Pagar la luz");
    }

    /// **H1 en la tarea: un `due` con `\r\n` incrustado no inyecta líneas.** Es
    /// la misma validación de fecha que un evento, por la misma pieza.
    #[test]
    fn un_due_con_crlf_incrustado_se_rechaza() {
        let patch = TaskPatch {
            due: Change::Set(DateSpec {
                value: "20260101T000000Z\r\nATTENDEE:mailto:x\r\nX-:".into(),
                params: Vec::new(),
            }),
            ..Default::default()
        };
        assert_eq!(
            apply_todo_changes(TASK, &patch),
            Err(SerializeError::MalformedDate)
        );
        assert_eq!(
            new_todo("t", "20260101T000000Z", &patch),
            Err(SerializeError::MalformedDate)
        );
    }

    /// **El borde de la tarea: un `due` con un CR/LF al final.** Igual que en el
    /// evento, `DateValue::parse` lo recortaría y lo daría por válido, pero la
    /// escritura usa el valor crudo; `has_control` lo rechaza antes.
    #[test]
    fn un_due_con_crlf_al_final_se_rechaza() {
        let patch = TaskPatch {
            due: Change::Set(DateSpec {
                value: "20261001T100000Z\r\n".into(),
                params: Vec::new(),
            }),
            ..Default::default()
        };
        assert_eq!(
            apply_todo_changes(TASK, &patch),
            Err(SerializeError::MalformedDate)
        );
        assert_eq!(
            new_todo("t", "20260101T000000Z", &patch),
            Err(SerializeError::MalformedDate)
        );
    }

    /// **El dominio del porcentaje y de la prioridad se respeta:** fuera de
    /// rango se rechaza, no se recorta ni se escribe un número cualquiera a la
    /// línea.
    #[test]
    fn el_porcentaje_y_la_prioridad_fuera_de_rango_se_rechazan() {
        let percent = TaskPatch {
            percent_complete: Change::Set(101),
            ..Default::default()
        };
        assert_eq!(
            apply_todo_changes(TASK, &percent),
            Err(SerializeError::PercentOutOfRange)
        );
        assert_eq!(
            new_todo("t", "20260101T000000Z", &percent),
            Err(SerializeError::PercentOutOfRange)
        );

        let priority = TaskPatch {
            priority: Change::Set(10),
            ..Default::default()
        };
        assert_eq!(
            apply_todo_changes(TASK, &priority),
            Err(SerializeError::PriorityOutOfRange)
        );
    }

    /// Los bordes del rango —100 y 9— sí pasan: la validación no es un muro para
    /// el uso normal.
    #[test]
    fn los_bordes_del_rango_pasan() {
        let patch = TaskPatch {
            percent_complete: Change::Set(100),
            priority: Change::Set(9),
            ..Default::default()
        };
        assert!(apply_todo_changes(TASK, &patch).is_ok());
    }

    /// El `STATUS` se arma de un dominio cerrado: cualquier texto que no sea uno
    /// de los cuatro no se interpreta como estado, y los cuatro vuelven a su
    /// texto fijo.
    #[test]
    fn el_status_sale_de_un_dominio_cerrado() {
        assert_eq!(TodoStatus::parse("completed"), Some(TodoStatus::Completed));
        assert_eq!(
            TodoStatus::parse("NEEDS-ACTION"),
            Some(TodoStatus::NeedsAction)
        );
        assert_eq!(TodoStatus::parse("IN-PROCESS"), Some(TodoStatus::InProcess));
        assert_eq!(TodoStatus::parse("CANCELLED"), Some(TodoStatus::Cancelled));
        // Un texto con una inyección no es un estado: no hay forma de que llegue
        // a la línea.
        assert_eq!(TodoStatus::parse("DONE\r\nX-:1"), None);
        assert_eq!(TodoStatus::parse("cualquier cosa"), None);
    }

    /// Un parche de tarea vacío no toca nada, y un crudo sin `VTODO` —sólo con
    /// un `VEVENT`— vuelve igual: `apply_todo_changes` no edita un evento.
    #[test]
    fn un_parche_de_tarea_vacio_o_sin_vtodo_no_cambia_nada() {
        assert_eq!(task_edited(TASK, &TaskPatch::default()), TASK);
        assert_eq!(
            apply_todo_changes(
                EVENT,
                &TaskPatch {
                    summary: set("X"),
                    ..Default::default()
                }
            )
            .unwrap(),
            EVENT
        );
    }
}
