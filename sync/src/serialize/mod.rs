//! Escribir iCalendar y vCard: el lado de la escritura, conservador.
//!
//! El lado de la lectura vive en `ical.rs` y `vcard.rs`; esto es lo contrario, y
//! sigue la decisión 3 del taller (`vasak-calendar#2`, `vasak-contacts#2`):
//! **escritura conservadora**. No se reconstruye el objeto desde el modelo —eso
//! tiraría todo lo que el programa no entiende—, sino que se parte del **crudo
//! que ya está guardado** (`ObjectRow::raw_ical`, `ContactRow::raw_vcard`) y se
//! toca sólo lo que cambió. Una propiedad que no se edita sale byte por byte
//! como vino, con su plegado y su fin de línea intactos; un `VTIMEZONE` ajeno,
//! un `VALARM`, una foto en base64 o una `X-` que nadie conoce no se tocan.
//!
//! ── Por qué partir del crudo y no del modelo ────────────────────────────────
//!
//! El modelo que el programa saca de un objeto ([`crate::ical::Event`],
//! [`crate::vcard::Contact`]) es **lo que hace falta para mostrar y ordenar**,
//! no el objeto entero. Volver a serializar desde ahí perdería cada propiedad
//! que no cayó en el modelo —la mitad de un `VEVENT` de verdad—. Partir del
//! crudo y editar en el lugar es lo único que conserva lo ajeno.
//!
//! ── Lo que hay acá ──────────────────────────────────────────────────────────
//!
//! - [`fold`], que parte una línea larga en los 75 octetos del RFC 5545/6350 sin
//!   cortar un carácter de varios bytes;
//! - [`escape_text`], el inverso de los `unescape_text` de la lectura;
//! - [`logical_lines`], que agrupa las líneas físicas del crudo en propiedades
//!   lógicas **sin perder su forma**, para poder devolver tal cual lo que no se
//!   toca;
//! - [`Change`], cómo se pide un cambio: dejar, fijar o sacar.
//!
//! Lo específico de cada formato está en [`ical`] y [`vcard`].

pub mod ical;
pub mod vcard;

/// Qué se hace con una propiedad al aplicar un parche.
///
/// `Leave` es dejarla como está —el valor por omisión, así un parche sólo nombra
/// lo que cambia—; `Set` la fija a un valor nuevo; `Clear` la saca.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Change<T> {
    /// No tocar: lo que diga el crudo se queda.
    #[default]
    Leave,
    /// Fijar un valor nuevo.
    Set(T),
    /// Sacar la propiedad.
    Clear,
}

/// El fin de línea del crudo: `\r\n` si aparece, y si no `\n`.
///
/// iCalendar y vCard mandan `\r\n`, pero un archivo exportado a mano puede venir
/// con `\n` a secas. Lo que se devuelve usa el mismo que traía, así una
/// propiedad que no se toca sale con el fin de línea con el que entró.
pub fn detect_eol(raw: &str) -> &'static str {
    if raw.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

/// Una propiedad lógica: la línea de contenido más sus continuaciones plegadas,
/// tal como vinieron.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logical {
    /// Las líneas físicas, sin el fin de línea y en el orden en que estaban. La
    /// primera es la de contenido; las siguientes empiezan con un espacio o una
    /// tabulación (una continuación plegada).
    pub physical: Vec<String>,
}

impl Logical {
    /// El contenido desplegado, para leer el nombre y el valor: se le saca a
    /// cada continuación el único espacio o tabulación que la plegó.
    ///
    /// Es el inverso del plegado normal del RFC 5545/6350. No deshace el plegado
    /// blando de `quoted-printable` de la 2.1 (el que termina en `=`): eso sólo
    /// hace falta para **leer** el valor, y acá alcanza con reconocer el nombre
    /// de la propiedad —que nunca va en `quoted-printable`— para decidir si se
    /// toca o se deja. Lo que se deja sale por [`Logical::physical`], intacto.
    pub fn unfolded(&self) -> String {
        let mut out = String::new();
        for (i, line) in self.physical.iter().enumerate() {
            if i == 0 {
                out.push_str(line);
            } else {
                out.push_str(line.strip_prefix([' ', '\t']).unwrap_or(line));
            }
        }
        out
    }
}

/// Parte el crudo en propiedades lógicas, conservando la forma de cada una.
///
/// Una línea que empieza con un espacio o una tabulación es la continuación de
/// la de arriba y se le cuelga; cualquier otra empieza una propiedad nueva. La
/// última línea vacía —la que deja el fin de línea final— no cuenta.
pub fn logical_lines(raw: &str) -> Vec<Logical> {
    let mut physical: Vec<String> = raw
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line).to_string())
        .collect();
    // El fin de línea final deja una línea vacía al partir: no es una propiedad.
    if physical.last().is_some_and(String::is_empty) {
        physical.pop();
    }

    let mut out: Vec<Logical> = Vec::new();
    for line in physical {
        let is_continuation = line.starts_with([' ', '\t']) && !out.is_empty();
        match out.last_mut() {
            Some(last) if is_continuation => last.physical.push(line),
            _ => out.push(Logical {
                physical: vec![line],
            }),
        }
    }
    out
}

/// Deshace lo que [`crate::ical::unescape_text`] y [`crate::vcard::unescape_text`]
/// hacen al leer: escapa la barra, la coma, el punto y coma y el salto de línea.
///
/// Es común a los dos formatos (RFC 5545 §3.3.11 y RFC 6350 §3.4). Los dos
/// puntos **no** se escapan en el valor —ni iCalendar ni vCard lo piden—, y un
/// retorno de carro suelto no entra al valor: un salto va como `\n`.
pub fn escape_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            // Un `\r` suelto no es parte del valor; el salto ya fue como `\n`.
            '\r' => {}
            other => out.push(other),
        }
    }
    out
}

/// El largo máximo de una línea de contenido, en octetos (RFC 5545 §3.1,
/// RFC 6350 §3.2): 75 sin contar el fin de línea.
const FOLD_OCTETS: usize = 75;

/// Parte una línea de contenido en los 75 octetos del estándar.
///
/// Devuelve las líneas físicas sin el fin de línea: la primera entera y cada
/// continuación con un espacio adelante, que es como las vuelve a juntar la
/// lectura. **Se cuenta en octetos, no en caracteres**, pero no se parte un
/// carácter de varios bytes por el medio: un acento o un emoji que no entra en
/// lo que queda de la línea abre la siguiente. Así una propiedad que se reescribe
/// sale plegada como la que no se tocó.
pub fn fold(content: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut octets = 0usize;

    for c in content.chars() {
        let len = c.len_utf8();
        if octets + len > FOLD_OCTETS {
            lines.push(std::mem::take(&mut current));
            // La continuación empieza con un espacio, que ya ocupa un octeto.
            current.push(' ');
            octets = 1;
        }
        current.push(c);
        octets += len;
    }
    lines.push(current);
    lines
}

/// Arma una línea de contenido: `NOMBRE;PARAM=X;PARAM=Y:valor`.
///
/// Los parámetros vienen ya en la forma `CLAVE=VALOR`, sin el punto y coma. El
/// valor va tal cual: quien llama ya lo escapó si era texto, o es una fecha que
/// no se escapa.
pub(crate) fn render(name: &str, params: &[String], value: &str) -> String {
    let mut line = String::with_capacity(name.len() + value.len() + 1);
    line.push_str(name);
    for param in params {
        line.push(';');
        line.push_str(param);
    }
    line.push(':');
    line.push_str(value);
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_fin_de_linea_sale_del_crudo() {
        assert_eq!(detect_eol("A\r\nB\r\n"), "\r\n");
        assert_eq!(detect_eol("A\nB\n"), "\n");
        assert_eq!(detect_eol(""), "\n");
    }

    /// Las continuaciones se agrupan con su propiedad y se les saca el único
    /// espacio o tabulación que las plegó, pero las líneas físicas quedan tal
    /// cual para devolver lo que no se toca sin cambiarle la forma.
    #[test]
    fn las_lineas_logicas_conservan_su_forma() {
        let raw = "SUMMARY:Reunión de\r\n  equipo\r\nUID:1\r\n";
        let logicals = logical_lines(raw);
        assert_eq!(logicals.len(), 2);
        assert_eq!(logicals[0].unfolded(), "SUMMARY:Reunión de equipo");
        assert_eq!(
            logicals[0].physical,
            vec!["SUMMARY:Reunión de".to_string(), "  equipo".to_string()]
        );
        assert_eq!(logicals[1].unfolded(), "UID:1");
    }

    /// El fin de línea final no deja una propiedad lógica vacía.
    #[test]
    fn el_fin_de_linea_final_no_es_una_propiedad() {
        assert_eq!(logical_lines("A\r\n").len(), 1);
        assert_eq!(logical_lines("A").len(), 1);
        assert!(logical_lines("").is_empty());
    }

    #[test]
    fn el_texto_se_escapa_como_lo_deshace_la_lectura() {
        assert_eq!(escape_text("Reunión, con Ana"), r"Reunión\, con Ana");
        assert_eq!(escape_text("uno\ndos"), r"uno\ndos");
        assert_eq!(escape_text("punto; y coma"), r"punto\; y coma");
        assert_eq!(escape_text(r"barra\sola"), r"barra\\sola");
        // Ida y vuelta con la lectura de iCalendar y la de vCard.
        let original = "a, b; c\nd\\e";
        assert_eq!(crate::ical::unescape_text(&escape_text(original)), original);
        assert_eq!(
            crate::vcard::unescape_text(&escape_text(original)),
            original
        );
    }

    /// Se parte en los 75 octetos y no por el medio de un carácter de varios
    /// bytes, con un espacio adelante en cada continuación.
    #[test]
    fn el_plegado_corta_en_75_octetos_sin_partir_un_caracter() {
        let corto = fold("SUMMARY:hola");
        assert_eq!(corto, vec!["SUMMARY:hola".to_string()]);

        // 80 «ñ» son 160 octetos: no entran en una línea.
        let largo = fold(&"ñ".repeat(80));
        assert!(largo.len() > 1);
        for (i, line) in largo.iter().enumerate() {
            assert!(
                line.len() <= FOLD_OCTETS,
                "línea {i}: {} octetos",
                line.len()
            );
            if i > 0 {
                assert!(line.starts_with(' '), "la continuación {i} no pliega");
            }
            // No quedó ningún carácter partido.
            assert!(!line.contains('\u{FFFD}'));
            assert!(std::str::from_utf8(line.as_bytes()).is_ok());
        }
        // Al juntarlas otra vez —como hace la lectura— vuelve lo mismo.
        let rejoined: String = largo
            .iter()
            .enumerate()
            .map(|(i, l)| {
                if i == 0 {
                    l.clone()
                } else {
                    l.strip_prefix(' ').unwrap().to_string()
                }
            })
            .collect();
        assert_eq!(rejoined, "ñ".repeat(80));
    }

    #[test]
    fn una_linea_se_arma_con_sus_parametros() {
        assert_eq!(render("SUMMARY", &[], "hola"), "SUMMARY:hola");
        assert_eq!(
            render("DTSTART", &["TZID=Europe/Madrid".into()], "20260915T140000"),
            "DTSTART;TZID=Europe/Madrid:20260915T140000"
        );
    }
}
