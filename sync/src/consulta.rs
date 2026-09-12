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
pub enum Termino {
    /// En el remitente.
    De(String),
    /// En el destinatario.
    Para(String),
    Asunto(String),
    /// En el cuerpo del mensaje.
    Cuerpo(String),
    /// En cualquier parte: encabezados y cuerpo.
    Cualquiera(String),
    /// Sin leer.
    SinLeer,
    /// Destacado.
    Destacado,
    /// Desde una fecha, en el formato de IMAP: `1-Jan-2026`.
    Desde(String),
}

/// Cómo se le manda un texto al servidor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trozo {
    /// Va tal cual en la línea del comando.
    Literal(String),
    /// Va como literal de IMAP: `{N}\r\n` y después los bytes, en otra línea.
    ///
    /// Hace falta cuando el texto tiene bytes que no son ASCII. Un «reunión»
    /// entre comillas contra un servidor que asume US-ASCII no encuentra nada.
    Cadena(String),
}

/// La palabra clave de IMAP de cada término.
fn clave(termino: &Termino) -> &'static str {
    match termino {
        Termino::De(_) => "FROM",
        Termino::Para(_) => "TO",
        Termino::Asunto(_) => "SUBJECT",
        Termino::Cuerpo(_) => "BODY",
        Termino::Cualquiera(_) => "TEXT",
        Termino::SinLeer => "UNSEEN",
        Termino::Destacado => "FLAGGED",
        Termino::Desde(_) => "SINCE",
    }
}

/// El texto que acompaña al término, si lleva alguno.
fn texto(termino: &Termino) -> Option<&str> {
    match termino {
        Termino::De(t)
        | Termino::Para(t)
        | Termino::Asunto(t)
        | Termino::Cuerpo(t)
        | Termino::Cualquiera(t)
        | Termino::Desde(t) => Some(t),
        Termino::SinLeer | Termino::Destacado => None,
    }
}

/// Si una fecha tiene la forma que IMAP espera: `1-Jan-2026`.
///
/// Se comprueba y no se confía: una fecha es lo único que va **sin comillas** en
/// el comando, así que es el único lugar por donde un texto cualquiera podría
/// llegar a la sintaxis. Lo que no tiene esa forma se descarta.
fn es_fecha(valor: &str) -> bool {
    let mut partes = valor.split('-');
    let (Some(dia), Some(mes), Some(anio), None) =
        (partes.next(), partes.next(), partes.next(), partes.next())
    else {
        return false;
    };

    const MESES: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    (1..=2).contains(&dia.len())
        && dia.chars().all(|c| c.is_ascii_digit())
        && MESES.contains(&mes)
        && anio.len() == 4
        && anio.chars().all(|c| c.is_ascii_digit())
}

/// Arma el criterio de `SEARCH` a partir de lo que se pidió.
///
/// Los términos se juntan con un `AND` implícito, que es lo que hace IMAP
/// cuando van uno detrás de otro.
///
/// Devuelve los trozos y no una cadena porque los textos que no son ASCII
/// tienen que viajar como literales, o sea en líneas aparte: la conversión a
/// bytes la hace quien escribe en el socket.
pub fn armar(terminos: &[Termino]) -> Vec<Trozo> {
    let mut trozos = Vec::new();

    for termino in terminos {
        let clave = clave(termino);
        match texto(termino) {
            None => trozos.push(Trozo::Literal(clave.to_string())),
            Some("") => {
                // Un término vacío no acota nada y `SUBJECT ""` hace que algunos
                // servidores contesten un error. Se saltea.
                continue;
            }
            Some(valor) => {
                if matches!(termino, Termino::Desde(_)) {
                    if !es_fecha(valor) {
                        continue;
                    }
                    trozos.push(Trozo::Literal(format!("{clave} {valor}")));
                    continue;
                }
                trozos.push(Trozo::Literal(clave.to_string()));
                if valor.is_ascii() {
                    trozos.push(Trozo::Literal(entrecomillar(valor)));
                } else {
                    trozos.push(Trozo::Cadena(valor.to_string()));
                }
            }
        }
    }

    trozos
}

/// Una cadena de IMAP: entre comillas, con `\` y `"` escapados.
fn entrecomillar(valor: &str) -> String {
    let mut salida = String::with_capacity(valor.len() + 2);
    salida.push('"');
    for c in valor.chars() {
        if c == '"' || c == '\\' {
            salida.push('\\');
        }
        // Los saltos de línea no pueden ir en una cadena de IMAP, ni escapados:
        // partirían el comando en dos. Se reemplazan por un espacio, que para
        // buscar da lo mismo y no cambia la sintaxis.
        salida.push(if c == '\r' || c == '\n' { ' ' } else { c });
    }
    salida.push('"');
    salida
}

/// Los UID que devolvió un `SEARCH`.
///
/// La respuesta es `* SEARCH 1 3 7`. Lo que no sea un número se descarta: hay
/// servidores que agregan cosas al final, y un número que no se entiende es
/// peor que uno que falta.
pub fn uids_de_search(linea: &str) -> Option<Vec<u32>> {
    let resto = tras_search(linea)?;
    Some(resto.split_whitespace().filter_map(|t| t.parse().ok()).collect())
}

/// Lo que sigue a `* SEARCH` en una línea, si la línea es ésa.
///
/// El corte después de la palabra importa: sin comprobar que lo que sigue sea un
/// espacio o el final, `* SEARCHING 1` pasa por una respuesta de `SEARCH` con un
/// resultado. Es la misma clase de error que el de las etiquetas, que ya tiene
/// su prueba en `imap.rs`.
pub fn tras_search(linea: &str) -> Option<&str> {
    let sin_asterisco = linea.strip_prefix("* ")?;
    let mayusculas = sin_asterisco.to_ascii_uppercase();
    if !mayusculas.starts_with("SEARCH") {
        return None;
    }
    let resto = &sin_asterisco["SEARCH".len()..];
    if resto.is_empty() || resto.starts_with(' ') {
        Some(resto)
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
        let trozos = armar(&[Termino::Asunto("UNSEEN OR FROM jefe".into())]);
        assert_eq!(
            trozos,
            vec![
                Trozo::Literal("SUBJECT".into()),
                Trozo::Literal("\"UNSEEN OR FROM jefe\"".into()),
            ]
        );
    }

    #[test]
    fn las_comillas_y_las_barras_se_escapan() {
        let trozos = armar(&[Termino::De(r#"el "jefe" \ raro"#.into())]);
        assert_eq!(
            trozos[1],
            Trozo::Literal(r#""el \"jefe\" \\ raro""#.into())
        );
    }

    /// Un salto de línea partiría el comando en dos, y la segunda mitad sería
    /// un comando que nadie escribió. No se pueden escapar en una cadena de
    /// IMAP, así que se reemplazan.
    #[test]
    fn un_salto_de_linea_no_parte_el_comando() {
        let trozos = armar(&[Termino::Asunto("hola\r\na1 LOGOUT".into())]);
        let Trozo::Literal(cadena) = &trozos[1] else {
            panic!("tendría que ser literal");
        };
        assert!(!cadena.contains('\r'));
        assert!(!cadena.contains('\n'));
    }

    /// Sin esto, buscar «reunión» contra un servidor que asume US-ASCII no
    /// encuentra nada o falla con `BADCHARSET`.
    #[test]
    fn lo_que_no_es_ascii_viaja_como_literal() {
        let trozos = armar(&[Termino::Asunto("reunión".into())]);
        assert_eq!(trozos[0], Trozo::Literal("SUBJECT".into()));
        assert_eq!(trozos[1], Trozo::Cadena("reunión".into()));
    }

    #[test]
    fn los_que_no_llevan_texto_van_solos() {
        assert_eq!(
            armar(&[Termino::SinLeer, Termino::Destacado]),
            vec![
                Trozo::Literal("UNSEEN".into()),
                Trozo::Literal("FLAGGED".into()),
            ]
        );
    }

    #[test]
    fn varios_terminos_se_juntan() {
        let trozos = armar(&[Termino::SinLeer, Termino::De("ana".into())]);
        assert_eq!(
            trozos,
            vec![
                Trozo::Literal("UNSEEN".into()),
                Trozo::Literal("FROM".into()),
                Trozo::Literal("\"ana\"".into()),
            ]
        );
    }

    /// La fecha es lo único que va **sin comillas**, así que es el único lugar
    /// por donde un texto cualquiera podría llegar a la sintaxis.
    #[test]
    fn una_fecha_que_no_es_una_fecha_se_descarta() {
        for mala in [
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
                armar(&[Termino::Desde(mala.into())]).is_empty(),
                "pasó: {mala:?}"
            );
        }

        assert_eq!(
            armar(&[Termino::Desde("1-Jan-2026".into())]),
            vec![Trozo::Literal("SINCE 1-Jan-2026".into())]
        );
        assert_eq!(
            armar(&[Termino::Desde("28-Feb-2026".into())]),
            vec![Trozo::Literal("SINCE 28-Feb-2026".into())]
        );
    }

    /// `SUBJECT ""` hace que algunos servidores contesten un error, y buscar
    /// «nada» no acota nada.
    #[test]
    fn un_termino_vacio_se_saltea() {
        assert!(armar(&[Termino::Asunto(String::new())]).is_empty());
        assert_eq!(
            armar(&[Termino::Asunto(String::new()), Termino::SinLeer]),
            vec![Trozo::Literal("UNSEEN".into())]
        );
    }

    #[test]
    fn sin_terminos_no_hay_criterio() {
        assert!(armar(&[]).is_empty());
    }

    #[test]
    fn los_uids_salen_de_la_respuesta() {
        assert_eq!(uids_de_search("* SEARCH 1 3 7"), Some(vec![1, 3, 7]));
        assert_eq!(uids_de_search("* search 42"), Some(vec![42]));
        // Sin resultados: la línea viene igual, vacía.
        assert_eq!(uids_de_search("* SEARCH"), Some(vec![]));
        // Lo que no se entiende se descarta en vez de adivinarse.
        assert_eq!(uids_de_search("* SEARCH 1 dos 3"), Some(vec![1, 3]));
    }

    #[test]
    fn lo_que_no_es_una_respuesta_de_search_se_descarta() {
        for otra in ["* 12 EXISTS", "a1 OK SEARCH completado", "", "* SEARCHING 1"] {
            assert!(uids_de_search(otra).is_none(), "{otra:?}");
        }
    }
}
