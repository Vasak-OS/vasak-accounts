//! Interpretar una tarjeta de contacto.
//!
//! Viene de `vasak-contacts` (`src-tauri/src/vcard.rs`), con sus pruebas, y con
//! los nombres pasados al inglés. Lo que se sumó acá: `RELATED` (y su par de
//! Apple), el grupo de cada propiedad, el tope de datos por contacto y la clave
//! para ordenar.
//!
//! ── De dónde viene esto ─────────────────────────────────────────────────────
//!
//! De la libreta de la persona, pero **lo escribió cualquiera**: una tarjeta
//! puede haber llegado adjunta a un correo, importada de un teléfono viejo, o
//! sincronizada desde un servidor compartido. No es contenido de confianza sólo
//! por estar en la libreta de alguien.
//!
//! Por eso el parseo tiene topes, no tiene `unsafe`, y todo lo que no se
//! entiende devuelve algo razonable en vez de cortar. Una tarjeta rota no puede
//! impedir ver las otras trescientas.
//!
//! ── Las tres versiones ──────────────────────────────────────────────────────
//!
//! Conviven la 2.1, la 3.0 y la 4.0, y las diferencias que importan son pocas
//! pero muerden:
//!
//! - En **2.1** los parámetros van sueltos (`TEL;HOME;VOICE:`) y el texto puede
//!   venir en `quoted-printable`. La escriben los teléfonos viejos y los
//!   exportadores de agendas de hace veinte años, que es justo lo que la gente
//!   tiene guardado.
//! - En **3.0** los parámetros llevan nombre (`TEL;TYPE=HOME:`) y el juego de
//!   caracteres puede ser cualquiera.
//! - En **4.0** todo es UTF-8 y las direcciones llevan `mailto:`.
//!
//! Se leen las tres. **Escribir no se hace**: lo que se guarda en el almacén es
//! la tarjeta cruda tal como vino, y esto sólo saca de ella lo que hace falta
//! para ordenar y buscar.
//!
//! ── Las relaciones ──────────────────────────────────────────────────────────
//!
//! Hay dos formas de decir «la esposa de Ana es Marta», y no se mezclan
//! (decisión 3 del taller, `vasak-contacts#2`): `RELATED` de la 4.0, y el par
//! de Apple `itemN.X-ABRELATEDNAMES` + `itemN.X-ABLabel`. Se lee `RELATED` si
//! la tarjeta trae alguno, y **sólo si no trae ninguno** se lee la de Apple.
//! Las dos van al mismo campo, [`Contact::related`], así que quien la use
//! después no tiene que saber de dónde vino.

use serde::{Deserialize, Serialize};

/// Cuántas propiedades se leen de una tarjeta.
///
/// Un contacto real tiene decenas. Mil es un archivo armado para hacer trabajar
/// al programa, o una tarjeta con la foto partida en pedazos — que igual no se
/// muestra.
const MAX_PROPERTIES: usize = 1000;

/// Tope de un valor que se muestra.
///
/// Un nombre de diez mil caracteres no es un nombre: es algo que va a romper la
/// lista al dibujarla.
const MAX_VALUE: usize = 4096;

/// Cuántos correos, cuántos teléfonos y cuántas relaciones se leen de un
/// contacto, cada uno por su lado.
///
/// Una persona real tiene dos o tres de cada uno. Cincuenta ya es una tarjeta
/// armada para llenar las tablas del almacén: cada dato es una fila y una
/// entrada del índice de búsqueda.
pub const MAX_FIELDS_PER_KIND: usize = 50;

/// Una dirección de correo, un teléfono, o cualquier cosa con una etiqueta.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    /// «casa», «trabajo», «celular»… tal como lo escribió quien hizo la
    /// tarjeta, en minúsculas. Vacío si no dijo nada.
    pub label: String,
    pub value: String,
}

/// Un contacto, listo para mostrar.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    /// El identificador de la tarjeta dentro de la libreta.
    pub uid: String,
    /// Cómo se llama, para mostrar.
    pub display_name: String,
    /// Para ordenar: «Pérez, Ana» en vez de «Ana Pérez».
    ///
    /// Va aparte porque ordenar por el nombre que se muestra pone a todas las
    /// Anas juntas y a los Pérez desparramados, que no es como nadie busca a
    /// alguien en una agenda.
    pub sort_name: String,
    pub emails: Vec<Field>,
    pub phones: Vec<Field>,
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub notes: String,
    /// Las personas relacionadas: de `RELATED`, o de `X-ABRELATEDNAMES` si la
    /// tarjeta no trae ningún `RELATED`. Nunca de las dos a la vez.
    #[serde(default)]
    pub related: Vec<Field>,
    /// La dirección de la tarjeta en el servidor, para volver a buscarla.
    #[serde(default)]
    pub href: String,
}

// ---------------------------------------------------------------------------
// Las líneas
// ---------------------------------------------------------------------------

/// Junta las líneas partidas de una tarjeta.
///
/// **Hay dos formas de partir una línea y no se parecen en nada.**
///
/// La normal, de la 3.0 y la 4.0: se corta a 75 octetos y la siguiente empieza
/// con un espacio o una tabulación. Sin volver a juntarlas, un nombre largo
/// aparece cortado y una foto en base64 —que ocupa cientos de líneas— se
/// interpreta como cientos de propiedades basura.
///
/// La otra es de la 2.1, y sólo dentro de un valor en `quoted-printable`: la
/// línea termina en `=` y la siguiente **no lleva nada adelante**. Sin
/// reconocerla, la línea que sigue no tiene dos puntos y se descarta entera, y
/// el valor queda cortado con un signo de igual pegado al final — que es
/// exactamente el síntoma que leer la 2.1 viene a evitar.
///
/// Por eso este juntador tiene que saber de `quoted-printable`: no es
/// acoplamiento de más, es cómo está definido el formato. Y por eso el `=` no
/// junta líneas por sí solo — el base64 de una foto termina en `=` y se comería
/// la propiedad siguiente.
pub fn unfold_lines(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut continues_printable = false;

    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);

        // Continuación de la 2.1: se le saca el `=` que anunciaba que seguía y
        // se pega lo que vino, sin mirar con qué empieza.
        if continues_printable {
            if let Some(last) = lines.last_mut() {
                last.pop();
                last.push_str(line);
                continues_printable = is_unfinished_quoted_printable(last);
                continue;
            }
        }

        match line.strip_prefix([' ', '\t']) {
            Some(continuation) => match lines.last_mut() {
                Some(last) => last.push_str(continuation),
                None => lines.push(continuation.to_string()),
            },
            None => lines.push(line.to_string()),
        }

        continues_printable = lines
            .last()
            .is_some_and(|l| is_unfinished_quoted_printable(l));
    }

    lines
}

/// Si una línea es un `quoted-printable` que sigue en la siguiente.
///
/// Las dos condiciones juntas: que el valor esté en `quoted-printable` **y** que
/// termine en `=`. Con una sola no alcanza — el base64 de una foto termina en
/// `=` y no sigue, y un valor en `quoted-printable` que termina donde termina
/// tampoco.
fn is_unfinished_quoted_printable(line: &str) -> bool {
    if !line.ends_with('=') {
        return false;
    }
    let Some((left, _)) = line.split_once(':') else {
        return false;
    };
    left.to_ascii_lowercase()
        .replace(' ', "")
        .contains("encoding=quoted-printable")
}

/// Una propiedad ya separada en sus partes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    /// El grupo de adelante (`item1` en `item1.EMAIL`), en minúsculas.
    pub group: Option<String>,
    pub name: String,
    pub params: Vec<String>,
    pub value: String,
}

/// Separa el nombre y sus parámetros del valor.
///
/// Se corta por el **primer** dos puntos fuera de comillas: el valor puede
/// tener varios —`URL:https://x`— y cortar por el último dejaría la mitad de la
/// dirección en el nombre de la propiedad.
///
/// El nombre puede venir con un grupo adelante (`item1.EMAIL`), que ponen los
/// exportadores de Apple. El grupo va aparte y no pegado al nombre: pegado,
/// `item1.EMAIL` no se reconocería como un correo. Casi siempre no se usa; la
/// excepción es la etiqueta de una relación de Apple, que es otra propiedad del
/// mismo grupo.
pub fn split_property(line: &str) -> Option<Property> {
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

    let mut parts = left.split(';');
    let raw = parts.next()?.trim();
    // El grupo va antes de un punto. `X-ABLabel` de Apple viene así.
    let (group, name) = match raw.rsplit_once('.') {
        Some((group, name)) => (Some(group.to_ascii_lowercase()), name),
        None => (None, raw),
    };

    Some(Property {
        group,
        name: name.to_ascii_uppercase(),
        params: parts.map(|p| p.trim().to_string()).collect(),
        value,
    })
}

/// Deshace lo escapado de un valor de texto.
///
/// En vCard la coma, el punto y coma y el salto de línea van escapados. Sin
/// deshacerlo, una nota con una coma se muestra con la barra a la vista.
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
            Some(':') => out.push(':'),
            Some('\\') => out.push('\\'),
            // Una barra que no escapa nada conocido se deja: es un dato de
            // alguien y tragárselo cambiaría el texto.
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }

    out
}

/// Los campos de un valor con varias partes, como `N` o `ADR`.
///
/// El separador es el punto y coma **sin escapar**: un apellido compuesto que
/// lleve uno escapado no puede partir el campo en dos.
pub fn split_fields(value: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut escaped = false;

    for c in value.chars() {
        if escaped {
            current.push('\\');
            current.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            ';' => fields.push(std::mem::take(&mut current)),
            other => current.push(other),
        }
    }
    if escaped {
        current.push('\\');
    }
    fields.push(current);

    fields.into_iter().map(|f| unescape_text(&f)).collect()
}

/// La etiqueta de una propiedad: «casa», «trabajo», «celular».
///
/// Se leen las dos formas: `TYPE=HOME` de la 3.0 y la 4.0, y `HOME` suelto de
/// la 2.1. Sin la segunda, cualquier agenda exportada de un teléfono viejo
/// muestra todos los teléfonos sin etiqueta.
pub fn label_from(params: &[String]) -> String {
    let meaningful = |p: &str| {
        let lower = p.to_ascii_lowercase();
        // Lo que no es una etiqueta para mostrar: cómo viene codificado, en qué
        // juego de caracteres, y cuál es el preferido.
        !matches!(lower.as_str(), "pref" | "internet" | "voice" | "x400")
            && !lower.starts_with("encoding=")
            && !lower.starts_with("charset=")
            && !lower.starts_with("value=")
            && !lower.starts_with("pref=")
    };

    params
        .iter()
        .flat_map(|p| match p.split_once('=') {
            // `TYPE=HOME,VOICE` puede traer varias juntas.
            Some((name, value)) if name.eq_ignore_ascii_case("type") => {
                value.split(',').map(str::to_string).collect::<Vec<_>>()
            }
            Some(_) => vec![p.clone()],
            None => vec![p.clone()],
        })
        .map(|p| p.trim().trim_matches('"').to_string())
        .find(|p| meaningful(p))
        .map(|p| p.to_ascii_lowercase())
        .unwrap_or_default()
}

/// Deshace `quoted-printable`, que es como la 2.1 manda los acentos.
pub fn decode_quoted_printable(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] != b'=' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let digit = |b: Option<&u8>| (*b? as char).to_digit(16);
        match (digit(bytes.get(i + 1)), digit(bytes.get(i + 2))) {
            (Some(high), Some(low)) => {
                out.push((high * 16 + low) as u8);
                i += 3;
            }
            // Un `=` que no es un escape válido se deja como está.
            _ => {
                out.push(b'=');
                i += 1;
            }
        }
    }

    out
}

/// El juego de caracteres que declaró la propiedad, si declaró alguno.
fn declared_charset(property: &Property) -> Option<&str> {
    property.params.iter().find_map(|p| {
        let (name, value) = p.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("charset")
            .then(|| value.trim().trim_matches('"'))
    })
}

/// Deshace la codificación de transporte y el juego de caracteres, **y nada
/// más**.
///
/// Separado del desescape a propósito. Un valor con varias partes —`N`, `ADR`,
/// `ORG`— se parte por los puntos y coma **después** de decodificar y **antes**
/// de desescapar: al revés, un `N;ENCODING=QUOTED-PRINTABLE:P=E9rez;Ana;;;`
/// mostraba «P=E9rez» y ordenaba la agenda por eso.
pub fn decoded(property: &Property) -> String {
    let has = |what: &str| {
        property
            .params
            .iter()
            .any(|p| p.to_ascii_lowercase().replace(' ', "") == what)
    };

    let declared = declared_charset(property);
    let printable = has("encoding=quoted-printable") || has("quoted-printable");

    // Sin nada declarado y sin codificar, el valor ya es texto: es el caso de
    // la 3.0 y la 4.0, que es casi todo.
    if !printable && declared.is_none() {
        return property.value.clone();
    }

    let bytes = if printable {
        decode_quoted_printable(&property.value)
    } else {
        // Ya vino como texto, pero declarando otro juego: los bytes originales
        // se recuperan del texto tal como llegó.
        property.value.as_bytes().to_vec()
    };

    to_text(&bytes, declared)
}

/// Pasa bytes a texto según el juego que declaró la tarjeta.
///
/// **Se respeta lo declarado.** Una 2.1 puede decir `CHARSET=WINDOWS-1252`, y
/// suponer latin-1 ahí convierte las comillas tipográficas y el guión largo en
/// caracteres de control invisibles.
///
/// Sin juego declarado, o con uno que no se conoce: se prueba UTF-8 y se cae a
/// Windows-1252, que es lo que manda una agenda exportada hace quince años. Sin
/// ese respaldo, cada acento sale como un rombo.
pub fn to_text(bytes: &[u8], charset: Option<&str>) -> String {
    let declared = charset.and_then(|j| encoding_rs::Encoding::for_label(j.trim().as_bytes()));

    let encoding = match declared {
        // `us-ascii` con bytes que no son ASCII no es us-ascii: el estándar de
        // codificaciones lo trata como Windows-1252, que decodifica cualquier
        // byte sin dar error, así que un valor en UTF-8 mal declarado saldría
        // con «Ã³» y nada lo notaría.
        Some(c) if c == encoding_rs::WINDOWS_1252 && std::str::from_utf8(bytes).is_ok() => {
            encoding_rs::UTF_8
        }
        Some(c) => c,
        None if std::str::from_utf8(bytes).is_ok() => encoding_rs::UTF_8,
        None => encoding_rs::WINDOWS_1252,
    };

    encoding.decode(bytes).0.into_owned()
}

/// El valor de una propiedad, listo para mostrar.
pub fn display_value(property: &Property) -> String {
    unescape_text(&decoded(property))
}

// ---------------------------------------------------------------------------
// La tarjeta entera
// ---------------------------------------------------------------------------

/// Una relación de Apple, esperando su etiqueta.
struct AppleRelated {
    group: Option<String>,
    label: String,
    value: String,
}

/// Lee un contacto de una tarjeta.
///
/// `None` si no hay nada que mostrar: una tarjeta sin nombre y sin datos ocupa
/// lugar en la lista y no sirve para nada.
pub fn contact_from(raw: &str, href: &str) -> Option<Contact> {
    let mut contact = Contact {
        href: href.to_string(),
        ..Default::default()
    };
    let mut structured_name: Vec<String> = Vec::new();
    let mut apple_related: Vec<AppleRelated> = Vec::new();
    // Las etiquetas de Apple, por grupo: `item1.X-ABLabel:_$!<Spouse>!$_`.
    let mut apple_labels: Vec<(String, String)> = Vec::new();

    for (i, line) in unfold_lines(raw).into_iter().enumerate() {
        if i >= MAX_PROPERTIES {
            break;
        }
        let Some(property) = split_property(&line) else {
            continue;
        };

        match property.name.as_str() {
            "UID" => contact.uid = truncated(&display_value(&property)),
            "FN" => contact.display_name = truncated(&display_value(&property)),
            "N" => structured_name = split_fields(&decoded(&property)),
            "EMAIL" => {
                // En la 4.0 la dirección viene como `mailto:ana@x`. Dejarlo
                // haría que el botón de escribirle abriera «mailto:mailto:…».
                let value = display_value(&property);
                let value = strip_scheme(&value, "mailto:").trim().to_string();
                push_field(&mut contact.emails, &property, value);
            }
            "TEL" => {
                let value = display_value(&property);
                let value = strip_scheme(&value, "tel:").trim().to_string();
                push_field(&mut contact.phones, &property, value);
            }
            "ORG" => {
                // `ORG` trae la empresa y sus divisiones separadas por punto y
                // coma. Se muestran juntas y no sólo la primera: «Vasak Group»
                // y «Vasak Group, Soporte» son cosas distintas.
                contact.organization = truncated(
                    &split_fields(&decoded(&property))
                        .into_iter()
                        .filter(|c| !c.trim().is_empty())
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            }
            "NOTE" => contact.notes = truncated(&display_value(&property)),
            "RELATED" => {
                let value = display_value(&property).trim().to_string();
                push_field(&mut contact.related, &property, value);
            }
            "X-ABRELATEDNAMES" => {
                if apple_related.len() < MAX_FIELDS_PER_KIND {
                    apple_related.push(AppleRelated {
                        group: property.group.clone(),
                        label: label_from(&property.params),
                        value: display_value(&property).trim().to_string(),
                    });
                }
            }
            "X-ABLABEL" => {
                if let Some(group) = &property.group {
                    if apple_labels.len() < MAX_FIELDS_PER_KIND {
                        apple_labels.push((group.clone(), apple_label(&display_value(&property))));
                    }
                }
            }
            _ => {}
        }
    }

    // Las de Apple, **sólo si no hubo ningún `RELATED`**: las dos formas juntas
    // dirían dos veces lo mismo, o peor, dos cosas distintas.
    if contact.related.is_empty() {
        for related in apple_related {
            if related.value.is_empty() {
                continue;
            }
            let label = related
                .group
                .as_ref()
                .and_then(|g| apple_labels.iter().find(|(group, _)| group == g))
                .map(|(_, label)| label.clone())
                .unwrap_or(related.label);
            contact.related.push(Field {
                label,
                value: truncated(&related.value),
            });
        }
    }

    // El nombre que se muestra: el `FN` si está, y si no se arma con el `N`.
    // Una tarjeta sin `FN` es inválida según el estándar y aparece igual, así
    // que armarlo es la diferencia entre ver a alguien y ver un renglón vacío.
    if contact.display_name.trim().is_empty() {
        contact.display_name = display_name_from(&structured_name);
    }
    contact.sort_name = sort_name_from(&structured_name, &contact.display_name);

    let has_something = !contact.display_name.trim().is_empty()
        || !contact.emails.is_empty()
        || !contact.phones.is_empty();
    has_something.then_some(contact)
}

/// La etiqueta de Apple, sin su envoltorio.
///
/// Las de fábrica vienen como `_$!<Spouse>!$_`; las que escribió la persona,
/// tal cual («Compadre»). Las dos van en minúsculas, como las demás etiquetas.
fn apple_label(raw: &str) -> String {
    let trimmed = raw.trim();
    let inner = trimmed
        .strip_prefix("_$!<")
        .and_then(|rest| rest.strip_suffix(">!$_"))
        .unwrap_or(trimmed);
    truncated(&inner.to_lowercase())
}

/// Saca el esquema de un valor, **sin mirar mayúsculas**.
///
/// Los esquemas de una URI no las distinguen: `MailTo:` y `TEL:` son tan
/// válidos como los de minúscula, y los escriben los exportadores de verdad.
/// Dejarlos pegados hace que el botón de escribir abra «mailto:MailTo:…» y que
/// el de llamar reciba algo que no es un número.
fn strip_scheme<'a>(value: &'a str, scheme: &str) -> &'a str {
    if value.len() >= scheme.len()
        && value.is_char_boundary(scheme.len())
        && value[..scheme.len()].eq_ignore_ascii_case(scheme)
    {
        return &value[scheme.len()..];
    }
    value
}

/// Suma un dato, hasta [`MAX_FIELDS_PER_KIND`]. Los de más se descartan.
fn push_field(target: &mut Vec<Field>, property: &Property, value: String) {
    if value.is_empty() || target.len() >= MAX_FIELDS_PER_KIND {
        return;
    }
    target.push(Field {
        label: label_from(&property.params),
        value: truncated(&value),
    });
}

/// Un valor que no rompa la lista al dibujarla.
fn truncated(value: &str) -> String {
    if value.len() <= MAX_VALUE {
        return value.to_string();
    }
    let mut cut = MAX_VALUE;
    while cut > 0 && !value.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &value[..cut])
}

/// Arma «Ana Pérez» a partir del `N`, que viene al revés y por partes.
///
/// El orden del campo es apellido, nombre, segundos nombres, tratamiento y
/// sufijo. Mostrarlo tal cual daría «Pérez;Ana;;Sra.;».
fn display_name_from(fields: &[String]) -> String {
    let field = |i: usize| fields.get(i).map(String::as_str).unwrap_or("").trim();
    [field(3), field(1), field(2), field(0), field(4)]
        .iter()
        .filter(|p| !p.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join(" ")
}

/// «Pérez, Ana»: cómo se busca a alguien en una agenda.
///
/// Ordenar por el nombre que se muestra pone a todas las Anas juntas y a los
/// Pérez desparramados, que no es como nadie busca.
fn sort_name_from(fields: &[String], display_name: &str) -> String {
    let field = |i: usize| fields.get(i).map(String::as_str).unwrap_or("").trim();
    let family = field(0);
    let given = field(1);

    match (family.is_empty(), given.is_empty()) {
        (false, false) => format!("{family}, {given}"),
        (false, true) => family.to_string(),
        // Sin apellido, se ordena por lo que se muestra: es lo único que hay.
        _ => display_name.to_string(),
    }
}

/// La clave con la que se ordena en el almacén: el nombre para ordenar en
/// minúsculas y sin los acentos del alfabeto latino.
///
/// SQLite ordena por bytes: sin esto «Ábalos» queda después de «Zapata» y
/// «ana» después de «Zoe». No es una intercalación completa —no hay tablas de
/// Unicode en el programa—, pero cubre el castellano, el portugués, el francés
/// y el alemán, que es lo que hay en las agendas de acá. Lo demás queda en
/// minúsculas y ordenado por bytes, que es lo de antes.
pub fn sort_key(sort_name: &str) -> String {
    let mut out = String::with_capacity(sort_name.len());
    for c in sort_name.trim().chars().flat_map(char::to_lowercase) {
        match c {
            'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ā' | 'ă' | 'ą' => out.push('a'),
            'æ' => out.push_str("ae"),
            'ç' | 'ć' | 'č' => out.push('c'),
            'ď' | 'đ' => out.push('d'),
            'è' | 'é' | 'ê' | 'ë' | 'ē' | 'ė' | 'ę' | 'ě' => out.push('e'),
            'ì' | 'í' | 'î' | 'ï' | 'ī' | 'į' => out.push('i'),
            'ł' => out.push('l'),
            'ñ' | 'ń' | 'ň' => out.push('n'),
            'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ō' | 'ő' => out.push('o'),
            'œ' => out.push_str("oe"),
            'ř' => out.push('r'),
            'ś' | 'š' | 'ş' => out.push('s'),
            'ß' => out.push_str("ss"),
            'ť' | 'ţ' => out.push('t'),
            'ù' | 'ú' | 'û' | 'ü' | 'ū' | 'ů' | 'ű' => out.push('u'),
            'ý' | 'ÿ' => out.push('y'),
            'ź' | 'ż' | 'ž' => out.push('z'),
            other => out.push(other),
        }
    }
    out
}

/// Separa las tarjetas de una respuesta que trae varias pegadas.
///
/// Un servidor puede devolver un archivo con muchas, y hay libretas exportadas
/// que son un solo archivo con miles. Sin separarlas, se leería una sola con
/// los datos de todas mezclados.
pub fn split_cards(raw: &str) -> Vec<String> {
    let mut cards = Vec::new();
    let mut current: Option<Vec<String>> = None;

    for line in unfold_lines(raw) {
        let upper = line.trim().to_ascii_uppercase();
        if upper == "BEGIN:VCARD" {
            current = Some(vec![line]);
            continue;
        }
        if upper == "END:VCARD" {
            if let Some(mut lines) = current.take() {
                lines.push(line);
                cards.push(lines.join("\r\n"));
            }
            continue;
        }
        if let Some(lines) = current.as_mut() {
            lines.push(line);
        }
    }

    // Una tarjeta sin su `END` está mal formada, pero lo que se leyó se
    // aprovecha: es preferible a perder un contacto por dos palabras que
    // faltaron.
    if let Some(lines) = current {
        cards.push(lines.join("\r\n"));
    }

    cards
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANA: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:abc-123\r\n\
        FN:Ana Pérez\r\nN:Pérez;Ana;;;\r\n\
        EMAIL;TYPE=WORK:ana@ejemplo.com\r\n\
        TEL;TYPE=CELL:+54 11 5555-5555\r\n\
        ORG:Vasak Group;Soporte\r\nEND:VCARD\r\n";

    #[test]
    fn se_lee_una_tarjeta() {
        let c = contact_from(ANA, "https://x/ana.vcf").unwrap();

        assert_eq!(c.uid, "abc-123");
        assert_eq!(c.display_name, "Ana Pérez");
        assert_eq!(c.emails[0].value, "ana@ejemplo.com");
        assert_eq!(c.emails[0].label, "work");
        assert_eq!(c.phones[0].value, "+54 11 5555-5555");
        assert_eq!(c.href, "https://x/ana.vcf");
    }

    // ── Las líneas ─────────────────────────────────────────────────────────

    /// Sin volver a juntarlas, un nombre largo aparece cortado y una foto en
    /// base64 —que ocupa cientos de líneas— se interpreta como cientos de
    /// propiedades basura.
    #[test]
    fn las_lineas_partidas_se_vuelven_a_juntar() {
        let raw = "FN:Ana\r\n  Pérez\r\nUID:1\r\n";
        let lines = unfold_lines(raw);
        assert_eq!(lines[0], "FN:Ana Pérez");
        assert_eq!(lines[1], "UID:1");
    }

    /// El carácter que pliega **se va**: en el test de arriba el espacio que
    /// sobrevive es el segundo, el que el nombre tenía de verdad.
    #[test]
    fn el_caracter_que_pliega_no_deja_espacio() {
        assert_eq!(unfold_lines("FN:Ana\r\n\tPérez")[0], "FN:AnaPérez");
    }

    /// **La otra forma de partir una línea, la de la 2.1.** El valor termina en
    /// `=` y la línea siguiente no lleva nada adelante. Sin reconocerla, esa
    /// línea no tiene dos puntos y se descarta entera: el nombre queda cortado
    /// con un signo de igual pegado, que es justo el síntoma que leer la 2.1
    /// viene a evitar.
    #[test]
    fn una_continuacion_de_quoted_printable_se_junta() {
        // El corte cae en el medio de una palabra, que es donde cae de verdad:
        // el formato parte a los 75 octetos sin mirar qué hay ahí. Y el `=` no
        // deja nada en su lugar — un espacio lo pondría donde no estaba.
        let old = "BEGIN:VCARD\r\nVERSION:2.1\r\n\
            FN;ENCODING=QUOTED-PRINTABLE:Ana Mar=C3=ADa P=C3=A9r=\r\nez\r\nEND:VCARD";

        let c = contact_from(old, "").unwrap();
        assert_eq!(c.display_name, "Ana María Pérez");
        assert!(
            !c.display_name.contains('='),
            "quedó el signo de igual: {}",
            c.display_name
        );
    }

    /// Y con varias continuaciones seguidas, que es lo que pasa con un valor de
    /// verdad largo.
    #[test]
    fn varias_continuaciones_seguidas_tambien() {
        let old = "NOTE;ENCODING=QUOTED-PRINTABLE:uno=\r\ndos=\r\ntres\r\nFN:Ana";
        let lines = unfold_lines(old);

        assert_eq!(lines[0], "NOTE;ENCODING=QUOTED-PRINTABLE:unodostres");
        // Y la propiedad siguiente no se la comió.
        assert_eq!(lines[1], "FN:Ana");
    }

    /// **El `=` solo no junta nada.** El base64 de una foto termina en `=` y no
    /// sigue: juntar por el signo se comería la propiedad de abajo, que es peor
    /// que el problema que se quería arreglar.
    #[test]
    fn un_base64_que_termina_en_igual_no_se_come_lo_que_sigue() {
        let with_photo = "PHOTO;ENCODING=b:iVBORw0KGgo=\r\nFN:Ana\r\n";
        let lines = unfold_lines(with_photo);

        assert_eq!(lines[0], "PHOTO;ENCODING=b:iVBORw0KGgo=");
        assert_eq!(lines[1], "FN:Ana");
    }

    /// El valor puede tener dos puntos —una URL— así que el corte va por el
    /// primero. Cortar por el último dejaría media dirección en el nombre.
    #[test]
    fn la_linea_se_corta_por_el_primer_dos_puntos() {
        let p = split_property("URL:https://ejemplo.com/ana").unwrap();
        assert_eq!(p.name, "URL");
        assert_eq!(p.value, "https://ejemplo.com/ana");
    }

    /// Los exportadores de Apple ponen un grupo adelante. Dejarlo pegado haría
    /// que `item1.EMAIL` no se reconociera como un correo.
    #[test]
    fn el_grupo_de_apple_no_esconde_la_propiedad() {
        let p = split_property("item1.EMAIL;TYPE=HOME:ana@x.com").unwrap();
        assert_eq!(p.name, "EMAIL");
        assert_eq!(p.group.as_deref(), Some("item1"));

        let c = contact_from(
            "BEGIN:VCARD\r\nFN:Ana\r\nitem1.EMAIL;TYPE=HOME:ana@x.com\r\nEND:VCARD",
            "",
        )
        .unwrap();
        assert_eq!(c.emails.len(), 1);
    }

    #[test]
    fn el_texto_se_desescapa() {
        assert_eq!(unescape_text(r"Pérez\, Ana"), "Pérez, Ana");
        assert_eq!(unescape_text(r"uno\ndos"), "uno\ndos");
        assert_eq!(unescape_text(r"punto\; y coma"), "punto; y coma");
    }

    /// Un apellido compuesto con un punto y coma escapado no puede partir el
    /// campo en dos.
    #[test]
    fn un_punto_y_coma_escapado_no_parte_el_campo() {
        assert_eq!(
            split_fields(r"Pérez\;Gómez;Ana"),
            vec!["Pérez;Gómez", "Ana"]
        );
        assert_eq!(
            split_fields("Pérez;Ana;;;"),
            vec!["Pérez", "Ana", "", "", ""]
        );
    }

    // ── Las tres versiones ─────────────────────────────────────────────────

    /// **Los teléfonos viejos escriben 2.1**, con los parámetros sueltos. Sin
    /// leerlos, cualquier agenda exportada de uno muestra todos los teléfonos
    /// sin etiqueta.
    #[test]
    fn se_lee_la_etiqueta_de_las_tres_versiones() {
        assert_eq!(label_from(&["TYPE=WORK".into()]), "work");
        assert_eq!(label_from(&["HOME".into()]), "home");
        assert_eq!(label_from(&["TYPE=\"HOME\"".into()]), "home");
        // Y con varias juntas, la primera que sirva.
        assert_eq!(label_from(&["TYPE=VOICE,HOME".into()]), "home");
    }

    /// Lo que no es una etiqueta para mostrar no puede terminar en pantalla:
    /// «internet» no dice nada de un correo, y «pref» tampoco.
    #[test]
    fn lo_que_no_es_una_etiqueta_no_se_muestra_como_tal() {
        assert_eq!(label_from(&["INTERNET".into()]), "");
        assert_eq!(label_from(&["PREF".into()]), "");
        assert_eq!(label_from(&["ENCODING=QUOTED-PRINTABLE".into()]), "");
        assert_eq!(label_from(&["CHARSET=UTF-8".into()]), "");
        assert_eq!(label_from(&[]), "");
        // Pero si además hay una de verdad, ésa sí.
        assert_eq!(label_from(&["INTERNET".into(), "HOME".into()]), "home");
    }

    /// La 2.1 manda los acentos en `quoted-printable`. Sin deshacerlo, media
    /// agenda en español se ve con signos de igual en el medio de los nombres.
    #[test]
    fn una_tarjeta_vieja_con_acentos_se_lee() {
        let old = "BEGIN:VCARD\r\nVERSION:2.1\r\n\
            FN;CHARSET=UTF-8;ENCODING=QUOTED-PRINTABLE:Ana P=C3=A9rez\r\n\
            TEL;HOME:11-5555\r\nEND:VCARD";

        let c = contact_from(old, "").unwrap();
        assert_eq!(c.display_name, "Ana Pérez");
        assert_eq!(c.phones[0].label, "home");
    }

    /// **El `N` se decodifica antes de partirlo en campos.** Sin eso, una
    /// tarjeta 2.1 mostraba «P=E9rez» y ordenaba la agenda por eso — que es
    /// peor que no mostrar el apellido, porque parece que anda.
    #[test]
    fn el_nombre_estructurado_se_decodifica_antes_de_partirse() {
        let old = "BEGIN:VCARD\r\nVERSION:2.1\r\n\
            N;ENCODING=QUOTED-PRINTABLE:P=E9rez;Ana;;;\r\nEND:VCARD";

        let c = contact_from(old, "").unwrap();
        assert_eq!(c.display_name, "Ana Pérez");
        assert_eq!(c.sort_name, "Pérez, Ana");
    }

    /// Y la organización igual, que tiene el mismo defecto y las mismas partes.
    #[test]
    fn la_organizacion_tambien_se_decodifica_antes() {
        let old = "BEGIN:VCARD\r\nFN:Ana\r\n\
            ORG;ENCODING=QUOTED-PRINTABLE:Panader=EDa;Mostrador\r\nEND:VCARD";
        assert_eq!(
            contact_from(old, "").unwrap().organization,
            "Panadería, Mostrador"
        );
    }

    /// **Se respeta el juego declarado.** Suponer latin-1 cuando la tarjeta
    /// dice `windows-1252` convierte las comillas tipográficas y el guión largo
    /// en caracteres de control invisibles.
    #[test]
    fn el_charset_declarado_se_respeta() {
        // 0x93 y 0x94 son las comillas tipográficas en windows-1252; en
        // latin-1 son controles que no se ven.
        let bytes = b"dijo \x93hola\x94";
        assert_eq!(to_text(bytes, Some("windows-1252")), "dijo “hola”");

        // Y el que no se conoce cae al respaldo en vez de romper.
        assert_eq!(to_text(b"caf\xe9", Some("juego-inventado")), "café");
    }

    /// Los esquemas de una URI no distinguen mayúsculas, y los exportadores de
    /// verdad escriben `MailTo:`. Dejarlo pegado hace que el botón de escribir
    /// abra «mailto:MailTo:…».
    #[test]
    fn el_esquema_se_saca_sin_mirar_mayusculas() {
        let new = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Ana\r\n\
            EMAIL:MailTo:ana@ejemplo.com\r\nTEL:TEL:+541155555555\r\nEND:VCARD";

        let c = contact_from(new, "").unwrap();
        assert_eq!(c.emails[0].value, "ana@ejemplo.com");
        assert_eq!(c.phones[0].value, "+541155555555");
    }

    /// Un valor corto que empieza con una letra de varios bytes no puede
    /// hacer caer la comparación del esquema: se corta por un carácter.
    #[test]
    fn un_valor_con_acentos_al_principio_no_rompe_el_esquema() {
        // El byte 4 cae en el medio de la segunda «ñ»: el original cortaba ahí
        // sin mirar y el programa caía.
        let c = contact_from("BEGIN:VCARD\r\nFN:Ana\r\nTEL:aññ\r\nEND:VCARD", "").unwrap();
        assert_eq!(c.phones[0].value, "aññ");
    }

    /// Y si los bytes no son UTF-8, se leen como latin-1 en vez de mostrar
    /// rombos: es lo que manda una agenda exportada hace quince años.
    #[test]
    fn una_tarjeta_vieja_en_latin1_tambien() {
        let old = "BEGIN:VCARD\r\nVERSION:2.1\r\n\
            FN;ENCODING=QUOTED-PRINTABLE:Ana P=E9rez\r\nEND:VCARD";
        assert_eq!(contact_from(old, "").unwrap().display_name, "Ana Pérez");
    }

    /// En la 4.0 la dirección viene con `mailto:` adelante. Dejarlo haría que
    /// el botón de escribirle abriera «mailto:mailto:…».
    #[test]
    fn el_mailto_de_la_version_4_no_queda_pegado() {
        let new = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Ana\r\n\
            EMAIL:mailto:ana@ejemplo.com\r\nTEL:tel:+541155555555\r\nEND:VCARD";

        let c = contact_from(new, "").unwrap();
        assert_eq!(c.emails[0].value, "ana@ejemplo.com");
        assert_eq!(c.phones[0].value, "+541155555555");
    }

    // ── El nombre ──────────────────────────────────────────────────────────

    /// Una tarjeta sin `FN` es inválida según el estándar y aparece igual.
    /// Armar el nombre con el `N` es la diferencia entre ver a alguien y ver un
    /// renglón vacío.
    #[test]
    fn sin_fn_el_nombre_se_arma_con_el_n() {
        let without_fn = "BEGIN:VCARD\r\nN:Pérez;Ana;María;Sra.;\r\nEND:VCARD";
        assert_eq!(
            contact_from(without_fn, "").unwrap().display_name,
            "Sra. Ana María Pérez"
        );
    }

    /// Ordenar por el nombre que se muestra pone a todas las Anas juntas y a
    /// los Pérez desparramados, que no es como nadie busca en una agenda.
    #[test]
    fn se_ordena_por_apellido() {
        assert_eq!(contact_from(ANA, "").unwrap().sort_name, "Pérez, Ana");

        // Sin apellido se ordena por lo que se muestra: es lo único que hay.
        let only_fn = "BEGIN:VCARD\r\nFN:Panadería del barrio\r\nEND:VCARD";
        assert_eq!(
            contact_from(only_fn, "").unwrap().sort_name,
            "Panadería del barrio"
        );
    }

    /// SQLite ordena por bytes: sin la clave, «Ábalos» queda después de
    /// «Zapata» y «ana» después de «Zoe».
    #[test]
    fn la_clave_para_ordenar_no_mira_mayusculas_ni_acentos() {
        assert_eq!(sort_key("Ábalos, José"), "abalos, jose");
        assert_eq!(sort_key("  Muñoz "), "munoz");
        assert_eq!(sort_key("Straße"), "strasse");
        let mut names = vec!["Zapata", "ana", "Ábalos", "Zoe", "Émile"];
        names.sort_by_key(|n| sort_key(n));
        assert_eq!(names, vec!["Ábalos", "ana", "Émile", "Zapata", "Zoe"]);
        // Lo que no es latino queda como estaba, en minúsculas.
        assert_eq!(sort_key("Ωμέγα"), "ωμέγα");
    }

    /// `ORG` trae la empresa y sus divisiones. «Vasak Group» y «Vasak Group,
    /// Soporte» son cosas distintas.
    #[test]
    fn la_organizacion_incluye_la_division() {
        assert_eq!(
            contact_from(ANA, "").unwrap().organization,
            "Vasak Group, Soporte"
        );
    }

    // ── Las relaciones ─────────────────────────────────────────────────────

    /// `RELATED` de la 4.0, con su tipo como etiqueta.
    #[test]
    fn se_lee_related_de_la_version_4() {
        let card = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Ana\r\n\
            RELATED;TYPE=spouse;VALUE=text:Marta Gómez\r\n\
            RELATED;TYPE=child:urn:uuid:03a0e51f-d1aa-4385-8a53-e29025acd8af\r\nEND:VCARD";
        let c = contact_from(card, "").unwrap();
        assert_eq!(
            c.related,
            vec![
                Field {
                    label: "spouse".into(),
                    value: "Marta Gómez".into()
                },
                Field {
                    label: "child".into(),
                    value: "urn:uuid:03a0e51f-d1aa-4385-8a53-e29025acd8af".into()
                },
            ]
        );
    }

    /// La forma de Apple: el nombre en `X-ABRELATEDNAMES` y la etiqueta en el
    /// `X-ABLabel` **del mismo grupo**, con el envoltorio `_$!<…>!$_` en las de
    /// fábrica y sin él en las que escribió la persona.
    #[test]
    fn se_lee_la_relacion_de_apple_con_la_etiqueta_de_su_grupo() {
        let card = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Ana\r\n\
            item1.X-ABRELATEDNAMES;type=pref:Marta Gómez\r\n\
            item1.X-ABLabel:_$!<Spouse>!$_\r\n\
            item2.X-ABRELATEDNAMES:Juan\r\n\
            item2.X-ABLabel:Compadre\r\n\
            item3.EMAIL:ana@x.com\r\n\
            item3.X-ABLabel:_$!<Other>!$_\r\nEND:VCARD";
        let c = contact_from(card, "").unwrap();
        assert_eq!(
            c.related,
            vec![
                Field {
                    label: "spouse".into(),
                    value: "Marta Gómez".into()
                },
                Field {
                    label: "compadre".into(),
                    value: "Juan".into()
                },
            ]
        );
    }

    /// **Nunca las dos a la vez.** Si hay algún `RELATED`, el par de Apple se
    /// ignora: juntas dirían dos veces lo mismo, o dos cosas distintas.
    #[test]
    fn con_related_la_forma_de_apple_no_se_lee() {
        let card = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Ana\r\n\
            item1.X-ABRELATEDNAMES:Marta Vieja\r\n\
            item1.X-ABLabel:_$!<Spouse>!$_\r\n\
            RELATED;TYPE=spouse;VALUE=text:Marta Gómez\r\nEND:VCARD";
        let c = contact_from(card, "").unwrap();
        assert_eq!(c.related.len(), 1);
        assert_eq!(c.related[0].value, "Marta Gómez");
    }

    /// Una etiqueta de otro grupo no se le pega a la relación: sin su propia
    /// etiqueta se queda con la de sus parámetros, o sin ninguna.
    #[test]
    fn una_etiqueta_de_otro_grupo_no_se_usa() {
        let card = "BEGIN:VCARD\r\nFN:Ana\r\n\
            item1.X-ABRELATEDNAMES:Marta\r\n\
            item2.X-ABLabel:_$!<Spouse>!$_\r\nEND:VCARD";
        let c = contact_from(card, "").unwrap();
        assert_eq!(
            c.related,
            vec![Field {
                label: String::new(),
                value: "Marta".into()
            }]
        );
    }

    // ── Lo que llega roto ──────────────────────────────────────────────────

    /// Una tarjeta sin nada que mostrar ocupa lugar en la lista y no sirve para
    /// nada.
    #[test]
    fn una_tarjeta_vacia_no_es_un_contacto() {
        assert!(contact_from("BEGIN:VCARD\r\nVERSION:3.0\r\nEND:VCARD", "").is_none());
        assert!(contact_from("", "").is_none());
        assert!(contact_from("no es una tarjeta", "").is_none());
    }

    /// Una tarjeta puede haber llegado adjunta a un correo o importada de un
    /// teléfono: no es contenido de confianza por estar en la libreta.
    #[test]
    fn lo_que_esta_roto_no_hace_caer_nada() {
        for garbage in [
            ":::",
            "FN:",
            ";;;",
            "BEGIN:VCARD",
            "\r\n\r\n",
            "\\",
            "N:;;;;;;;;;;",
            ".X-ABLabel:",
            "a.b.c.RELATED:",
        ] {
            let _ = contact_from(garbage, "");
            let _ = split_cards(garbage);
        }
    }

    /// Un archivo armado para hacer trabajar al programa, o una tarjeta con la
    /// foto partida en pedazos: en los dos casos tiene que volver.
    #[test]
    fn una_tarjeta_desmedida_no_cuelga() {
        let huge = "BEGIN:VCARD\r\nFN:Ana\r\n".to_string()
            + &"X-BASURA:algo\r\n".repeat(50_000)
            + "END:VCARD";
        let c = contact_from(&huge, "").unwrap();
        assert_eq!(c.display_name, "Ana");
    }

    /// Cada correo y cada teléfono es una fila del almacén y una entrada del
    /// índice: una tarjeta con miles no los llena.
    #[test]
    fn los_datos_de_un_contacto_tienen_tope() {
        let many = "BEGIN:VCARD\r\nFN:Ana\r\n".to_string()
            + &(0..300)
                .map(|i| format!("EMAIL:ana{i}@x.com\r\nTEL:{i}\r\nRELATED:r{i}\r\n"))
                .collect::<String>()
            + "END:VCARD";
        let c = contact_from(&many, "").unwrap();
        assert_eq!(c.emails.len(), MAX_FIELDS_PER_KIND);
        assert_eq!(c.phones.len(), MAX_FIELDS_PER_KIND);
        assert_eq!(c.related.len(), MAX_FIELDS_PER_KIND);
        assert_eq!(c.emails[0].value, "ana0@x.com", "se quedan los primeros");
    }

    /// Un nombre de diez mil caracteres no es un nombre: es algo que va a
    /// romper la lista al dibujarla.
    #[test]
    fn un_valor_desmedido_se_recorta_sin_partir_un_caracter() {
        let long = format!("BEGIN:VCARD\r\nFN:{}\r\nEND:VCARD", "ñ".repeat(MAX_VALUE));
        let c = contact_from(&long, "").unwrap();

        assert!(c.display_name.len() <= MAX_VALUE + 4);
        assert!(c.display_name.ends_with('…'));
        assert!(!c.display_name.contains('\u{FFFD}'));
    }

    // ── Varias tarjetas ────────────────────────────────────────────────────

    /// Hay libretas exportadas que son un solo archivo con miles. Sin
    /// separarlas se leería una sola con los datos de todas mezclados.
    #[test]
    fn se_separan_las_tarjetas_de_un_archivo() {
        let two = format!("{ANA}BEGIN:VCARD\r\nFN:Juan\r\nEND:VCARD\r\n");
        let cards = split_cards(&two);

        assert_eq!(cards.len(), 2);
        assert_eq!(
            contact_from(&cards[0], "").unwrap().display_name,
            "Ana Pérez"
        );
        assert_eq!(contact_from(&cards[1], "").unwrap().display_name, "Juan");
    }

    /// Una tarjeta sin su `END` está mal formada, pero perder un contacto por
    /// dos palabras que faltaron sería peor.
    #[test]
    fn una_tarjeta_sin_cierre_se_aprovecha_igual() {
        let unclosed = "BEGIN:VCARD\r\nFN:Ana\r\n";
        let cards = split_cards(unclosed);
        assert_eq!(cards.len(), 1);
        assert_eq!(contact_from(&cards[0], "").unwrap().display_name, "Ana");
    }
}
