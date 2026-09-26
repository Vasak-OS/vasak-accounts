//! Qué se busca, y cómo se le dice al servidor.
//!
//! # Por qué esto existe y no se le pasa el criterio crudo
//!
//! La interfaz de búsqueda recibe lo que escribió alguien en un campo de texto.
//! Si eso se metiera tal cual en el comando `SEARCH`, un término con espacios y
//! palabras clave del protocolo sería un comando distinto del que se quiso
//! mandar — contra la casilla de la propia persona, pero igual: sería la ventana
//! decidiendo qué comando IMAP se ejecuta.
//!
//! Así que la ventana manda **qué** busca, no cómo. Acá se arma el criterio, y
//! el texto viaja siempre como una cadena entre comillas o como un literal,
//! nunca como parte de la sintaxis.

/// Lo que se puede pedir.
///
/// Chico a propósito. RFC 3501 §6.4.4 define muchos más criterios, y agregarlos
/// es agregar una variante acá; lo que no se puede es mandar uno que este tipo
/// no contemple, que es justamente la propiedad que se busca.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "campo", content = "valor")]
pub enum Term {
    /// En el remitente.
    #[serde(rename = "de")]
    Sender(String),
    /// En el destinatario.
    #[serde(rename = "para")]
    Recipient(String),
    #[serde(rename = "asunto")]
    Subject(String),
    /// En el cuerpo del mensaje.
    #[serde(rename = "cuerpo")]
    Body(String),
    /// En cualquier parte: encabezados y cuerpo.
    #[serde(rename = "cualquiera")]
    Any(String),
    /// Sin leer.
    #[serde(rename = "sin_leer")]
    Unread,
    /// Destacado.
    #[serde(rename = "destacado")]
    Flagged,
    /// Desde una fecha, en el formato de IMAP: `1-Jan-2026`.
    #[serde(rename = "desde")]
    Since(String),
}

/// Cómo se le manda un texto al servidor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chunk {
    /// Va tal cual en la línea del comando.
    Inline(String),
    /// Va como literal de IMAP: `{N}\r\n` y después los bytes, en otra línea.
    ///
    /// Hace falta cuando el texto tiene bytes que no son ASCII. Un «reunión»
    /// entre comillas contra un servidor que asume US-ASCII no encuentra nada.
    Literal(String),
}

/// La palabra clave de IMAP de cada término.
fn search_key(term: &Term) -> &'static str {
    match term {
        Term::Sender(_) => "FROM",
        Term::Recipient(_) => "TO",
        Term::Subject(_) => "SUBJECT",
        Term::Body(_) => "BODY",
        Term::Any(_) => "TEXT",
        Term::Unread => "UNSEEN",
        Term::Flagged => "FLAGGED",
        Term::Since(_) => "SINCE",
    }
}

/// El texto que acompaña al término, si lleva alguno.
fn term_text(term: &Term) -> Option<&str> {
    match term {
        Term::Sender(t)
        | Term::Recipient(t)
        | Term::Subject(t)
        | Term::Body(t)
        | Term::Any(t)
        | Term::Since(t) => Some(t),
        Term::Unread | Term::Flagged => None,
    }
}

/// Si una fecha tiene la forma que IMAP espera: `1-Jan-2026`.
///
/// Se comprueba y no se confía: una fecha es lo único que va **sin comillas** en
/// el comando, así que es el único lugar por donde un texto cualquiera podría
/// llegar a la sintaxis. Lo que no tiene esa forma se descarta.
fn is_imap_date(value: &str) -> bool {
    let mut parts = value.split('-');
    let (Some(day), Some(month), Some(year), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };

    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    (1..=2).contains(&day.len())
        && day.chars().all(|c| c.is_ascii_digit())
        && MONTHS.contains(&month)
        && year.len() == 4
        && year.chars().all(|c| c.is_ascii_digit())
}

/// Arma el criterio de `SEARCH` a partir de lo que se pidió.
///
/// Los términos se juntan con un `AND` implícito, que es lo que hace IMAP
/// cuando van uno detrás de otro.
///
/// Devuelve los trozos y no una cadena porque los textos que no son ASCII
/// tienen que viajar como literales, o sea en líneas aparte: la conversión a
/// bytes la hace quien escribe en el socket.
pub fn build_criteria(terms: &[Term]) -> Vec<Chunk> {
    let mut chunks = Vec::new();

    for term in terms {
        let key = search_key(term);
        match term_text(term) {
            None => chunks.push(Chunk::Inline(key.to_string())),
            Some("") => {
                // Un término vacío no acota nada y `SUBJECT ""` hace que algunos
                // servidores contesten un error. Se saltea.
                continue;
            }
            Some(value) => {
                if matches!(term, Term::Since(_)) {
                    if !is_imap_date(value) {
                        continue;
                    }
                    chunks.push(Chunk::Inline(format!("{key} {value}")));
                    continue;
                }
                chunks.push(Chunk::Inline(key.to_string()));
                if value.is_ascii() {
                    chunks.push(Chunk::Inline(quote_string(value)));
                } else {
                    chunks.push(Chunk::Literal(value.to_string()));
                }
            }
        }
    }

    chunks
}

/// Una cadena de IMAP: entre comillas, con `\` y `"` escapados.
fn quote_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        // Los saltos de línea no pueden ir en una cadena de IMAP, ni escapados:
        // partirían el comando en dos. Se reemplazan por un espacio, que para
        // buscar da lo mismo y no cambia la sintaxis.
        out.push(if c == '\r' || c == '\n' { ' ' } else { c });
    }
    out.push('"');
    out
}

/// Los UID que devolvió un `SEARCH`.
///
/// La respuesta es `* SEARCH 1 3 7`. Lo que no sea un número se descarta: hay
/// servidores que agregan cosas al final, y un número que no se entiende es
/// peor que uno que falta.
pub fn search_uids(line: &str) -> Option<Vec<u32>> {
    let rest = after_search(line)?;
    Some(
        rest.split_whitespace()
            .filter_map(|t| t.parse().ok())
            .collect(),
    )
}

/// Lo que sigue a `* SEARCH` en una línea, si la línea es ésa.
///
/// El corte después de la palabra importa: sin comprobar que lo que sigue sea un
/// espacio o el final, `* SEARCHING 1` pasa por una respuesta de `SEARCH` con un
/// resultado. Es la misma clase de error que el de las etiquetas, que ya tiene
/// su prueba en `imap.rs`.
pub fn after_search(line: &str) -> Option<&str> {
    let after_star = line.strip_prefix("* ")?;
    let upper = after_star.to_ascii_uppercase();
    if !upper.starts_with("SEARCH") {
        return None;
    }
    let rest = &after_star["SEARCH".len()..];
    if rest.is_empty() || rest.starts_with(' ') {
        Some(rest)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La propiedad que ordena el módulo: el texto que escribió alguien **nunca**
    /// llega a la sintaxis del comando.
    #[test]
    fn el_texto_no_puede_cambiar_el_comando() {
        // Palabras clave del protocolo adentro del término: van entre comillas y
        // el servidor las lee como texto, no como criterio.
        let chunks = build_criteria(&[Term::Subject("UNSEEN OR FROM jefe".into())]);
        assert_eq!(
            chunks,
            vec![
                Chunk::Inline("SUBJECT".into()),
                Chunk::Inline("\"UNSEEN OR FROM jefe\"".into()),
            ]
        );
    }

    #[test]
    fn las_comillas_y_las_barras_se_escapan() {
        let chunks = build_criteria(&[Term::Sender(r#"el "jefe" \ raro"#.into())]);
        assert_eq!(chunks[1], Chunk::Inline(r#""el \"jefe\" \\ raro""#.into()));
    }

    /// Un salto de línea partiría el comando en dos, y la segunda mitad sería
    /// un comando que nadie escribió. No se pueden escapar en una cadena de
    /// IMAP, así que se reemplazan.
    #[test]
    fn un_salto_de_linea_no_parte_el_comando() {
        let chunks = build_criteria(&[Term::Subject("hola\r\na1 LOGOUT".into())]);
        let Chunk::Inline(chain) = &chunks[1] else {
            panic!("tendría que ser literal");
        };
        assert!(!chain.contains('\r'));
        assert!(!chain.contains('\n'));
    }

    /// Sin esto, buscar «reunión» contra un servidor que asume US-ASCII no
    /// encuentra nada o falla con `BADCHARSET`.
    #[test]
    fn lo_que_no_es_ascii_viaja_como_literal() {
        let chunks = build_criteria(&[Term::Subject("reunión".into())]);
        assert_eq!(chunks[0], Chunk::Inline("SUBJECT".into()));
        assert_eq!(chunks[1], Chunk::Literal("reunión".into()));
    }

    #[test]
    fn los_que_no_llevan_texto_van_solos() {
        assert_eq!(
            build_criteria(&[Term::Unread, Term::Flagged]),
            vec![
                Chunk::Inline("UNSEEN".into()),
                Chunk::Inline("FLAGGED".into()),
            ]
        );
    }

    #[test]
    fn varios_terminos_se_juntan() {
        let chunks = build_criteria(&[Term::Unread, Term::Sender("ana".into())]);
        assert_eq!(
            chunks,
            vec![
                Chunk::Inline("UNSEEN".into()),
                Chunk::Inline("FROM".into()),
                Chunk::Inline("\"ana\"".into()),
            ]
        );
    }

    /// La fecha es lo único que va **sin comillas**, así que es el único lugar
    /// por donde un texto cualquiera podría llegar a la sintaxis.
    #[test]
    fn una_fecha_que_no_es_una_fecha_se_descarta() {
        for bad in [
            "ayer",
            "1-Jan-2026 OR ALL",
            "1-Ene-2026",
            "32-Jan-26",
            "1-Jan-26",
            "",
            "--",
            "1 Jan 2026",
        ] {
            assert!(
                build_criteria(&[Term::Since(bad.into())]).is_empty(),
                "pasó: {bad:?}"
            );
        }

        assert_eq!(
            build_criteria(&[Term::Since("1-Jan-2026".into())]),
            vec![Chunk::Inline("SINCE 1-Jan-2026".into())]
        );
        assert_eq!(
            build_criteria(&[Term::Since("28-Feb-2026".into())]),
            vec![Chunk::Inline("SINCE 28-Feb-2026".into())]
        );
    }

    /// `SUBJECT ""` hace que algunos servidores contesten un error, y buscar
    /// «nada» no acota nada.
    #[test]
    fn un_termino_vacio_se_saltea() {
        assert!(build_criteria(&[Term::Subject(String::new())]).is_empty());
        assert_eq!(
            build_criteria(&[Term::Subject(String::new()), Term::Unread]),
            vec![Chunk::Inline("UNSEEN".into())]
        );
    }

    #[test]
    fn sin_terminos_no_hay_criterio() {
        assert!(build_criteria(&[]).is_empty());
    }

    #[test]
    fn los_uids_salen_de_la_respuesta() {
        assert_eq!(search_uids("* SEARCH 1 3 7"), Some(vec![1, 3, 7]));
        assert_eq!(search_uids("* search 42"), Some(vec![42]));
        // Sin resultados: la línea viene igual, vacía.
        assert_eq!(search_uids("* SEARCH"), Some(vec![]));
        // Lo que no se entiende se descarta en vez de adivinarse.
        assert_eq!(search_uids("* SEARCH 1 dos 3"), Some(vec![1, 3]));
    }

    #[test]
    fn lo_que_no_es_una_respuesta_de_search_se_descarta() {
        for another in [
            "* 12 EXISTS",
            "a1 OK SEARCH completado",
            "",
            "* SEARCHING 1",
        ] {
            assert!(search_uids(another).is_none(), "{another:?}");
        }
    }
}
