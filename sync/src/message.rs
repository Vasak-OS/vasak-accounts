//! Interpretar un correo: cabeceras, MIME y el texto que se muestra.
//!
//! ── Éste es el parser peligroso ─────────────────────────────────────────────
//!
//! El módulo de IMAP dice, desde que se escribió, que el día que hubiera que
//! leer mensajes de verdad el parser sería la parte peligrosa y merecería su
//! propia discusión. Ésta es esa discusión, y esto es ese parser.
//!
//! Lo que entra acá **lo escribió un desconocido**. No un servidor con el que la
//! persona decidió tener una cuenta: cualquiera que sepa su dirección. Es la
//! superficie más expuesta de todo el escritorio, y por eso:
//!
//! - Corre como el usuario, nunca como root. Por eso este binario existe aparte
//!   del servicio de cuentas.
//! - **No hay `unsafe`, ni un solo `unwrap` sobre datos de la red.** Todo lo que
//!   no se entiende devuelve algo razonable en vez de cortar.
//! - Todo tiene tope: el tamaño del mensaje, la profundidad de las partes
//!   anidadas y la cantidad de partes. Un mensaje puede estar armado para gastar
//!   memoria o tiempo, y sin topes lo consigue.
//! - **No se interpreta HTML.** Se extrae texto. Un motor de HTML acá sería
//!   traer imágenes remotas —que le confirman al remitente que se leyó y desde
//!   qué dirección IP—, CSS que puede tapar cosas y una superficie enorme por
//!   nada. Lo que se muestra es texto plano; si el mensaje sólo trae HTML, se le
//!   sacan las etiquetas.
//!
//! ── Lo que **no** hace ──────────────────────────────────────────────────────
//!
//! No verifica firmas, no descifra y no lista adjuntos. Cada una de esas cosas
//! es su propio trabajo. Lo que hace es: de quién viene, de qué se trata, cuándo
//! llegó, y qué dice.

use encoding_rs::Encoding;
use serde::{Deserialize, Serialize};

/// Hasta dónde se sigue una anidación de partes.
///
/// Un `multipart` puede contener otro, y eso es normal —un mensaje con adjuntos
/// y con versión en texto y en HTML tiene dos niveles—. Ocho es de sobra para
/// cualquier correo real y corta un mensaje armado para anidar mil veces, que
/// sin tope reventaría la pila.
pub const MAX_DEPTH: usize = 8;

/// Cuántas partes se miran en un mismo nivel.
///
/// Un `multipart` con cien mil partes vacías es barato de escribir y caro de
/// recorrer. Ninguno legítimo pasa de unas decenas.
const MAX_PARTS: usize = 64;

/// Cuántas referencias se copian a una respuesta.
///
/// Una conversación de años acumula cientos, y la cadena entera se copia en cada
/// mensaje: sin tope, la cabecera crece hasta que algún servidor del camino
/// rechaza el mensaje por el tamaño de sus cabeceras.
const MAX_REFERENCES: usize = 20;

/// Tope del texto que se devuelve para mostrar.
///
/// Un megabyte de texto son unas doscientas mil palabras: nadie escribe eso y
/// nadie lo lee. Lo que pasa de ahí es un archivo pegado en el cuerpo, y
/// mandárselo entero a la ventana la trabaría al dibujarlo.
const MAX_TEXT: usize = 1024 * 1024;

/// Lo que se muestra de un mensaje en la lista.
///
/// Sin el cuerpo: la lista de una casilla con diez mil mensajes tiene que caber
/// en memoria y viajar por D-Bus. El cuerpo se pide de a uno, cuando alguien
/// abre el mensaje.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSummary {
    /// El identificador estable del mensaje dentro de su casilla.
    ///
    /// El UID y no el número de secuencia: el número cambia cuando se borra
    /// cualquier mensaje anterior, así que guardarlo en un caché sería guardar
    /// algo que apunta a otro mensaje mañana.
    pub uid: u32,
    /// Cómo se firma quien lo mandó, ya legible.
    #[serde(rename = "de")]
    pub from: String,
    /// Su dirección, aparte del nombre.
    ///
    /// Separada a propósito: un remitente que se llama a sí mismo
    /// «soporte@banco.com» y escribe desde otra dirección es el fraude más común
    /// que hay, y juntar las dos cosas en una sola línea es lo que lo hace
    /// funcionar.
    #[serde(rename = "direccion")]
    pub address: String,
    #[serde(rename = "asunto")]
    pub subject: String,
    /// Cuándo lo mandaron, en ISO 8601. Vacío si la fecha no se entendió.
    #[serde(rename = "fecha")]
    pub date: String,
    #[serde(rename = "sin_leer")]
    pub unread: bool,
    /// Si tiene algo pegado. No qué, todavía: sólo que hay.
    #[serde(rename = "con_adjuntos")]
    pub has_attachments: bool,
}

// ---------------------------------------------------------------------------
// Cabeceras
// ---------------------------------------------------------------------------

/// Las cabeceras de un mensaje, ya desplegadas.
#[derive(Debug, Default, Clone)]
pub struct Headers(Vec<(String, String)>);

impl Headers {
    /// Lee el bloque de cabeceras de un mensaje.
    ///
    /// Una cabecera larga se parte en varias líneas y las siguientes empiezan
    /// con espacio o tabulación. Sin volver a juntarlas, un asunto largo queda
    /// cortado y un `Content-Type` partido pierde su `boundary` — o sea, el
    /// mensaje entero se muestra como un bloque de basura.
    pub fn parse(text: &str) -> Self {
        let mut fields: Vec<(String, String)> = Vec::new();

        for raw_line in text.split('\n') {
            let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
            // Una línea vacía termina las cabeceras y empieza el cuerpo.
            if line.is_empty() {
                break;
            }

            if line.starts_with([' ', '\t']) {
                if let Some((_, value)) = fields.last_mut() {
                    value.push(' ');
                    value.push_str(line.trim());
                }
                continue;
            }

            if let Some((name, value)) = line.split_once(':') {
                fields.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }

        Headers(fields)
    }

    /// El valor de una cabecera, tal cual vino.
    ///
    /// La primera de las que haya: un mensaje puede traer dos `Subject`, y ésa
    /// es justamente una forma de esconder cosas —un cliente muestra una y otro
    /// muestra la otra—. Quedarse con la primera es lo que hacen los servidores
    /// que las procesan, así que es la que corresponde mostrar.
    pub fn get(&self, name: &str) -> Option<&str> {
        let wanted = name.to_ascii_lowercase();
        self.0
            .iter()
            .find(|(n, _)| *n == wanted)
            .map(|(_, v)| v.as_str())
    }

    /// El valor de una cabecera, ya legible.
    pub fn decoded(&self, name: &str) -> String {
        self.get(name).map(decode_words).unwrap_or_default()
    }
}

/// Deshace las «palabras codificadas» de una cabecera.
///
/// Una cabecera sólo puede llevar ASCII, así que todo lo demás va envuelto en
/// `=?UTF-8?B?...?=`. Sin deshacerlo, cualquier asunto con una tilde —o sea,
/// medio correo en español— se muestra como una ristra de signos.
pub fn decode_words(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    // Si la palabra anterior estaba codificada y sólo hay espacios hasta la
    // siguiente, esos espacios **no van**: el estándar los pone para poder
    // partir la línea, no porque estén en el texto. Sin esto, un asunto largo
    // en otro idioma sale con espacios en el medio de las palabras.
    let mut prev_encoded = false;

    while let Some(start) = rest.find("=?") {
        let (before, from) = rest.split_at(start);
        let only_spaces = !before.is_empty() && before.trim().is_empty();
        if !(prev_encoded && only_spaces) {
            out.push_str(before);
        }

        match decode_encoded_word(from) {
            Some((decoded, following)) => {
                out.push_str(&decoded);
                prev_encoded = true;
                rest = following;
            }
            None => {
                // Un `=?` que no abre una palabra válida es texto: se copia y se
                // sigue después de él, o el bucle no avanza nunca.
                out.push_str("=?");
                prev_encoded = false;
                rest = &from[2..];
            }
        }
    }

    out.push_str(rest);
    out
}

/// Decodifica una palabra que empieza en `=?`, y devuelve lo que sigue.
fn decode_encoded_word(from: &str) -> Option<(String, &str)> {
    let body = from.strip_prefix("=?")?;
    let end = body.find("?=")?;
    let (inside, after) = body.split_at(end);
    let after = &after["?=".len()..];

    let mut parts = inside.splitn(3, '?');
    let charset = parts.next()?;
    let encoding = parts.next()?;
    let text = parts.next()?;
    // Tres partes exactas: `charset?encoding?texto`. Menos no es una palabra
    // codificada, y un `?` de más va dentro del texto.
    if text.contains('?') {
        return None;
    }

    let bytes = match encoding.to_ascii_uppercase().as_str() {
        "B" => decode_base64(text)?,
        "Q" => quoted_printable_decode(text.as_bytes(), true),
        _ => return None,
    };

    // El juego de caracteres puede traer un idioma pegado: `UTF-8*es`.
    let charset = charset.split('*').next().unwrap_or(charset);
    Some((decode_text(&bytes, charset), after))
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    // Sin relleno y tolerante: hay clientes que mandan el `=` final y otros que
    // no, y rechazar por eso perdería el asunto entero de un mensaje real.
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .or_else(|_| {
            base64::engine::general_purpose::STANDARD_NO_PAD.decode(cleaned.trim_end_matches('='))
        })
        .ok()
}

/// Los bytes de un mensaje como texto, **sin perder ninguno**.
///
/// Latin-1 es la única codificación donde cada byte es exactamente un carácter y
/// la vuelta es exacta: el byte `n` es `U+00n` y nada más. Sirve para recorrer la
/// estructura del mensaje —que es ASCII: las fronteras, los nombres de las
/// cabeceras, el `base64`— **sin decidir todavía en qué idioma está escrito el
/// cuerpo**.
///
/// Eso es lo que hace que se pueda usar `&str` en todo el recorrido sin romper
/// nada. Convertir con `from_utf8_lossy` en cambio reemplaza cada byte que no es
/// UTF-8 por un rombo, y ahí ya no hay vuelta atrás: un mensaje en `iso-8859-1`
/// pierde el `0xF3` de la «ó» **antes** de que se sepa que había que leerlo como
/// latin-1. En la hoja se vuelven a sacar los bytes originales con `from_latin1` y
/// recién ahí se usa el juego que declaró el mensaje.
pub fn as_latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|b| char::from(*b)).collect()
}

/// La vuelta de `as_latin1`, exacta.
///
/// Los caracteres que no salieron de un byte —no pueden aparecer si el texto
/// viene de `as_latin1`, pero la función es pública— se descartan en vez de
/// recortarse: inventar un byte sería peor que perderlo.
pub fn from_latin1(text: &str) -> Vec<u8> {
    text.chars()
        .filter_map(|c| u8::try_from(c as u32).ok())
        .collect()
}

/// Deshace `quoted-printable`.
///
/// `in_header` cambia una sola cosa: dentro de una cabecera el `_` es un
/// espacio. En un cuerpo es un guión bajo, y confundirlos llena el texto de
/// espacios donde había nombres_con_guion.
pub fn quoted_printable_decode(bytes: &[u8], in_header: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'_' if in_header => {
                out.push(b' ');
                i += 1;
            }
            b'=' if !in_header && bytes.get(i + 1) == Some(&b'\r') => {
                // Un `=` al final de la línea es un corte blando: la línea sigue
                // y ni el `=` ni el salto van al texto.
                i += if bytes.get(i + 2) == Some(&b'\n') {
                    3
                } else {
                    2
                };
            }
            b'=' if !in_header && bytes.get(i + 1) == Some(&b'\n') => i += 2,
            b'=' => match hex_pair(bytes.get(i + 1).copied(), bytes.get(i + 2).copied()) {
                Some(byte) => {
                    out.push(byte);
                    i += 3;
                }
                // Un `=` que no es un escape válido se deja: es un dato de
                // alguien y tragárselo cambiaría el texto.
                None => {
                    out.push(b'=');
                    i += 1;
                }
            },
            other => {
                out.push(other);
                i += 1;
            }
        }
    }

    out
}

fn hex_pair(high: Option<u8>, lower: Option<u8>) -> Option<u8> {
    let hex_digit = |b: Option<u8>| (b? as char).to_digit(16);
    Some((hex_digit(high)? * 16 + hex_digit(lower)?) as u8)
}

/// Pasa bytes a texto según el juego de caracteres que declaró el mensaje.
///
/// Con dos casos en los que **se le cree a los bytes antes que a la etiqueta**,
/// porque creerle a la etiqueta da texto ilegible y nada avisa:
///
/// 1. **No hay etiqueta, o no se conoce.** Se prueba UTF-8 y se cae a
///    Windows-1252 —lo que el mundo llama «latin-1»—, que es lo que manda medio
///    correo viejo. Sin ese respaldo, un mensaje en español de hace quince años
///    se ve con un rombo en cada acento.
///
/// 2. **Dice `us-ascii` y los bytes no son ASCII.** Un mensaje sin
///    `Content-Type` es us-ascii por definición del estándar, y el estándar de
///    codificaciones hace de us-ascii un alias de Windows-1252 — que decodifica
///    **cualquier** byte sin dar error. O sea: un mensaje en UTF-8 sin declarar,
///    que son muchísimos, saldría con «Ã³» en cada «ó» y el programa no tendría
///    forma de notarlo. Si los bytes son UTF-8 válido, son UTF-8.
pub fn decode_text(bytes: &[u8], charset: &str) -> String {
    let label = charset.trim();
    let is_utf8 = std::str::from_utf8(bytes).is_ok();

    let Some(declared) = Encoding::for_label(label.as_bytes()) else {
        return decode_unlabeled(bytes, is_utf8);
    };

    let says_ascii = label.eq_ignore_ascii_case("us-ascii") || label.eq_ignore_ascii_case("ascii");
    if says_ascii && !bytes.is_ascii() && is_utf8 {
        return String::from_utf8_lossy(bytes).into_owned();
    }

    declared.decode(bytes).0.into_owned()
}

fn decode_unlabeled(bytes: &[u8], is_utf8: bool) -> String {
    let encoding = if is_utf8 {
        encoding_rs::UTF_8
    } else {
        encoding_rs::WINDOWS_1252
    };
    encoding.decode(bytes).0.into_owned()
}

// ---------------------------------------------------------------------------
// MIME
// ---------------------------------------------------------------------------

/// Lo que dice un `Content-Type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentType {
    /// En minúsculas, sin parámetros: `text/plain`.
    pub media_type: String,
    pub charset: String,
    /// El separador de las partes, si es un `multipart`.
    pub boundary: Option<String>,
}

impl Default for ContentType {
    fn default() -> Self {
        // Lo que dice el estándar para un mensaje sin `Content-Type`: texto
        // plano en US-ASCII. Suponer otra cosa haría ilegible un mensaje que
        // está perfectamente bien.
        ContentType {
            media_type: "text/plain".into(),
            charset: "us-ascii".into(),
            boundary: None,
        }
    }
}

/// Lee un `Content-Type`.
pub fn parse_content_type(value: &str) -> ContentType {
    let mut parts = value.split(';');
    let media_type = parts.next().unwrap_or_default().trim().to_ascii_lowercase();

    let mut content_type = ContentType {
        media_type: if media_type.is_empty() {
            "text/plain".into()
        } else {
            media_type
        },
        charset: "us-ascii".into(),
        boundary: None,
    };

    for param in parts {
        let Some((name, value)) = param.split_once('=') else {
            continue;
        };
        let value = unquote(value.trim());
        match name.trim().to_ascii_lowercase().as_str() {
            "charset" => content_type.charset = value.to_string(),
            // Vacío no sirve de separador: partiría el mensaje en cada línea.
            "boundary" if !value.is_empty() => content_type.boundary = Some(value.to_string()),
            _ => {}
        }
    }

    content_type
}

fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

/// Deshace la codificación de transporte de un cuerpo.
///
/// Sobre **bytes** y no sobre texto: `8bit` y `binary` quieren decir exactamente
/// que el cuerpo trae bytes que no son ASCII, y en qué idioma están lo dice el
/// `charset`, que se aplica después.
pub fn decode_transfer(body: &[u8], encoding: &str) -> Vec<u8> {
    match encoding.trim().to_ascii_lowercase().as_str() {
        // El base64 es ASCII por definición, así que leerlo como texto es
        // seguro; si trae algo que no lo es, no es base64 y se deja crudo.
        "base64" => std::str::from_utf8(body)
            .ok()
            .and_then(decode_base64)
            .unwrap_or_else(|| body.to_vec()),
        "quoted-printable" => quoted_printable_decode(body, false),
        // `7bit`, `8bit`, `binary` y cualquier cosa que no se conozca: los bytes
        // tal cual. Es lo correcto para los tres primeros, y para el resto es
        // mejor mostrar algo raro que no mostrar nada.
        _ => body.to_vec(),
    }
}

/// Separa un mensaje —o una parte— en sus cabeceras y su cuerpo.
///
/// El corte es la primera línea vacía. Si no hay ninguna, el mensaje es todo
/// cabeceras y no tiene cuerpo, que es raro pero posible.
pub fn split_headers(raw: &str) -> (Headers, &str) {
    let cut = raw
        .find("\r\n\r\n")
        .map(|i| (i, i + 4))
        .or_else(|| raw.find("\n\n").map(|i| (i, i + 2)));

    match cut {
        Some((end, body_start)) => (Headers::parse(&raw[..end]), &raw[body_start..]),
        None => (Headers::parse(raw), ""),
    }
}

/// Parte un `multipart` por su frontera.
///
/// Cada parte va entre `--frontera` y la siguiente; `--frontera--` cierra. Lo
/// que hay antes de la primera es el «preámbulo», que existe para los clientes
/// que no entienden MIME y no se muestra.
pub fn split_parts<'a>(body: &'a str, boundary: &str) -> Vec<&'a str> {
    let separator = format!("--{boundary}");
    let closing = format!("--{boundary}--");
    let mut parts = Vec::new();
    let mut current: Option<usize> = None;

    let mut pos = 0usize;
    for line in body.split_inclusive('\n') {
        let start = pos;
        pos += line.len();
        let trimmed = line.trim_end();

        if trimmed == closing {
            if let Some(from) = current.take() {
                parts.push(&body[from..start]);
            }
            break;
        }
        if trimmed == separator {
            if let Some(from) = current.take() {
                parts.push(&body[from..start]);
            }
            if parts.len() >= MAX_PARTS {
                break;
            }
            current = Some(pos);
        }
    }

    // Un mensaje sin la línea de cierre está mal formado, pero lo que ya se
    // había abierto se muestra igual: es preferible a perder el cuerpo entero
    // por un `--` que faltó.
    if let Some(from) = current {
        parts.push(&body[from..]);
    }

    parts
}

/// El texto que se le muestra a la persona.
///
/// Busca la mejor parte legible: primero `text/plain`, y si no hay, el
/// `text/html` con las etiquetas sacadas. Los adjuntos no entran — un PDF
/// convertido a caracteres es ruido.
pub fn plain_text(raw: &[u8]) -> String {
    // La vista latin-1 conserva cada byte tal cual mientras se recorre la
    // estructura. Ver `as_latin1`.
    let view = as_latin1(raw);
    let (headers, body) = split_headers(&view);
    let mut text = find_text(&headers, body, 0).unwrap_or_default();

    if text.len() > MAX_TEXT {
        text.truncate(floor_char_boundary(&text, MAX_TEXT));
        text.push_str("\n\n[…]");
    }
    text
}

/// Un `String` no se puede cortar en cualquier byte: hacerlo en el medio de un
/// carácter es un pánico. Se retrocede hasta el comienzo del carácter.
fn floor_char_boundary(text: &str, limit: usize) -> usize {
    let mut cut = limit.min(text.len());
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    cut
}

/// El HTML del mensaje, decodificado y **sin sanear**.
///
/// Aparte de [`plain_text`] y no como una variante suya, porque lo que se busca es
/// lo contrario: aquella prefiere el texto plano y cae al HTML sin etiquetas;
/// ésta quiere el HTML y **no** cae a nada. Si el mensaje no trae una parte
/// `text/html`, no hay formato que mostrar y la ventana se queda con el texto.
///
/// Lo que sale de acá lo escribió un desconocido y no se puede dibujar así:
/// pasa por `html::sanitize` antes de salir del servicio.
pub fn html_part(raw: &[u8]) -> Option<String> {
    let view = as_latin1(raw);
    let (headers, body) = split_headers(&view);
    find_html(&headers, body, 0)
}

fn find_html(headers: &Headers, body: &str, depth: usize) -> Option<String> {
    if depth > MAX_DEPTH {
        return None;
    }

    let content_type = headers
        .get("content-type")
        .map(parse_content_type)
        .unwrap_or_default();

    if let Some(boundary) = &content_type.boundary {
        // El primero que aparezca. En un `multipart/alternative` el HTML va
        // después del texto plano —de peor a mejor, dice el estándar— así que
        // recorrer en orden y quedarse con el primero que sea HTML da el que
        // corresponde sin tener que saber qué clase de `multipart` es.
        return split_parts(body, boundary).into_iter().find_map(|part| {
            let (part_headers, part_body) = split_headers(part);
            find_html(&part_headers, part_body, depth + 1)
        });
    }

    // Un adjunto no es el cuerpo, aunque sea una página web: un `.html` pegado
    // no es lo que escribió la persona.
    if is_attachment(headers) || content_type.media_type != "text/html" {
        return None;
    }

    let encoding = headers.get("content-transfer-encoding").unwrap_or("7bit");
    let bytes = decode_transfer(&from_latin1(body), encoding);
    Some(decode_text(&bytes, &content_type.charset))
}

fn find_text(headers: &Headers, body: &str, depth: usize) -> Option<String> {
    if depth > MAX_DEPTH {
        return None;
    }

    let content_type = headers
        .get("content-type")
        .map(parse_content_type)
        .unwrap_or_default();

    if let Some(boundary) = &content_type.boundary {
        let parts = split_parts(body, boundary);
        // `multipart/alternative` trae la misma cosa en varios formatos, de peor
        // a mejor, y hay que quedarse con **una**. Se prefiere el texto plano
        // aunque venga primero y el HTML después: acá el HTML no se dibuja, así
        // que la versión «mejor» del estándar es la peor para esta ventana.
        let mut fallback = None;
        for part in parts {
            let (part_headers, part_body) = split_headers(part);
            let part_type = part_headers
                .get("content-type")
                .map(parse_content_type)
                .unwrap_or_default();
            let Some(text) = find_text(&part_headers, part_body, depth + 1) else {
                continue;
            };
            if part_type.media_type == "text/plain" && !is_attachment(&part_headers) {
                return Some(text);
            }
            if fallback.is_none() {
                fallback = Some(text);
            }
        }
        return fallback;
    }

    // Un adjunto no es el cuerpo, aunque sea texto: un .csv pegado no es lo que
    // escribió la persona.
    if is_attachment(headers) {
        return None;
    }

    let encoding = headers.get("content-transfer-encoding").unwrap_or("7bit");
    // Acá se sale de la vista latin-1 y se vuelve a los bytes que mandó el
    // servidor. Es el único lugar donde se decide en qué idioma está escrito
    // esto, y es el último momento en que los bytes originales todavía existen.
    let bytes = decode_transfer(&from_latin1(body), encoding);
    let text = decode_text(&bytes, &content_type.charset);

    match content_type.media_type.as_str() {
        "text/plain" => Some(text),
        "text/html" => Some(strip_tags(&text)),
        _ => None,
    }
}

/// Si una parte viene marcada como adjunto.
pub fn is_attachment(headers: &Headers) -> bool {
    headers
        .get("content-disposition")
        .map(|d| d.trim().to_ascii_lowercase().starts_with("attachment"))
        .unwrap_or(false)
}

/// Saca las etiquetas de un HTML y deja el texto.
///
/// **Lo que devuelve es texto plano y hay que tratarlo como tal.** Puede
/// contener `<` y `>`: las entidades se deshacen *después* de sacar las
/// etiquetas, así que un mensaje con el texto literal `&lt;script&gt;` sale como
/// `<script>`. Eso es correcto para mostrarlo como texto —que es lo único que
/// hace esta aplicación— y **no** lo es para nadie que después lo meta en un
/// marcado sin escaparlo: le estaría devolviendo las etiquetas que esta función
/// sacó.
///
/// **No es un motor de HTML y no quiere serlo.** Es lo que hace que un mensaje
/// que sólo viene en HTML se pueda leer sin traer imágenes remotas —que le
/// confirman al remitente que se leyó y desde qué IP— ni ejecutar nada.
///
/// El contenido de `<script>` y `<style>` se descarta entero: no es texto para
/// nadie, y dejarlo volcaría código JavaScript en el medio del mensaje.
pub fn strip_tags(html: &str) -> String {
    // En minúsculas sólo lo ASCII, que es lo que deja los índices idénticos a
    // los del original: comparar sobre esta copia y cortar sobre la otra es
    // seguro únicamente por eso.
    let lower = html.to_ascii_lowercase();
    let mut out = String::with_capacity(html.len());
    let mut i = 0;

    while i < html.len() {
        let Some(end) = html[i..].find('<') else {
            out.push_str(&html[i..]);
            break;
        };
        out.push_str(&html[i..i + end]);
        i += end;

        // Un bloque que no es texto para nadie se salta entero, contenido
        // incluido: dejarlo volcaría JavaScript o una hoja de estilos en el
        // medio del mensaje.
        let mut skipped = false;
        for (label, closing) in [("<script", "</script>"), ("<style", "</style>")] {
            if lower[i..].starts_with(label) {
                // Sin cierre, lo que queda es todo parte del bloque.
                i = lower[i..]
                    .find(closing)
                    .map(|f| i + f + closing.len())
                    .unwrap_or(html.len());
                skipped = true;
                break;
            }
        }
        if skipped {
            // **`continue` y no seguir de largo.** Saliendo por abajo, el salto
            // hasta el próximo `>` se comía la etiqueta que venía después del
            // bloque: con `<script>…</script><style>…`, el `<` del `<style>`
            // desaparecía y su contenido terminaba en el mensaje.
            continue;
        }

        // Un salto de línea donde el HTML lo tenía: sin esto un mensaje entero
        // queda en un solo párrafo interminable.
        if lower[i..].starts_with("<br")
            || lower[i..].starts_with("</p")
            || lower[i..].starts_with("</div")
        {
            out.push('\n');
        }

        // Y saltear la etiqueta. Un `<` sin su `>` es una etiqueta abierta y no
        // texto: lo que queda no se muestra.
        i = match html[i..].find('>') {
            Some(f) => i + f + 1,
            None => html.len(),
        };
    }

    decode_entities(&out)
}

/// Deshace las entidades: las cinco con nombre que aparecen siempre, y todas las
/// numéricas.
///
/// Las numéricas importan más de lo que parece. El correo en HTML de los
/// remitentes viejos escribe los acentos así —`&#243;` por «ó»—, y sin
/// deshacerlas un mensaje en español se lee lleno de números en el medio de las
/// palabras. Una tabla completa de nombres, en cambio, serían mil quinientas
/// entradas para casos que casi no aparecen.
fn decode_entities(text: &str) -> String {
    let named = text
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'");

    let numeric = decode_numeric_entities(&named);
    // `&amp;` al final: si fuera primero, un `&amp;lt;` —que es el texto
    // literal «&lt;»— terminaría convertido en `<`.
    numeric.replace("&amp;", "&")
}

/// Deshace `&#243;` y `&#xF3;`.
fn decode_numeric_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(start) = rest.find("&#") {
        out.push_str(&rest[..start]);
        let body = &rest[start + 2..];

        // Una entidad numérica termina en `;` y es corta. El tope evita
        // recorrer el mensaje entero buscando un `;` que no está.
        let end = body.char_indices().take(10).find(|(_, c)| *c == ';');
        let converted = end.and_then(|(f, _)| {
            let digits = &body[..f];
            let number = match digits.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => digits.parse().ok()?,
            };
            char::from_u32(number).map(|c| (c, f + 3))
        });

        match converted {
            Some((ch, advance)) => {
                out.push(ch);
                rest = &rest[start + advance..];
            }
            // Un `&#` que no abre una entidad es texto: se copia y se sigue
            // después de él, o el bucle no avanza nunca.
            None => {
                out.push_str("&#");
                rest = body;
            }
        }
    }

    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------
// De un mensaje crudo a lo que se muestra
// ---------------------------------------------------------------------------

/// Separa el nombre de la dirección en un `From`.
///
/// Van separados porque juntarlos es lo que hace funcionar el fraude más común
/// que hay: un remitente que se pone de nombre «soporte@banco.com» y escribe
/// desde otra dirección. Mostrados aparte, no se puede hacer pasar uno por otro.
pub fn parse_sender(value: &str) -> (String, String) {
    // **Se parte primero y se decodifica después.**
    //
    // Al revés —decodificando la cabecera entera y buscando el `<` en el
    // resultado— alcanzaría con ponerse de nombre una palabra codificada que
    // contenga `<algo@banco.com>` para que la dirección que se muestra sea una
    // que nunca estuvo en el mensaje. O sea: exactamente el engaño que esta
    // función existe para impedir, servido por la función misma.
    //
    // Los `<` y `>` que delimitan la dirección son ASCII y están en el texto
    // crudo, así que buscarlos ahí no pierde nada. El último, porque un nombre
    // puede contener uno.
    if let Some(open_at) = value.rfind('<') {
        if let Some(close_at) = value[open_at..].find('>') {
            let address = value[open_at + 1..open_at + close_at].trim().to_string();
            // El nombre sí se decodifica: es texto para leer, y ahí una palabra
            // codificada es lo normal y no un truco.
            let name = decode_words(&value[..open_at]);
            let name = name.trim().trim_matches('"').trim().to_string();
            let name = if name.is_empty() {
                address.clone()
            } else {
                name
            };
            return (name, address);
        }
    }

    // Una dirección pelada: el nombre es la dirección. Se decodifica igual, por
    // si es un nombre suelto sin dirección.
    let address = decode_words(value).trim().to_string();
    (address.clone(), address)
}

/// Lee la fecha de un mensaje y la deja en ISO 8601.
///
/// Vacío si no se entiende, y **no la hora de ahora**: un mensaje de hace tres
/// años con fecha rota aparecería arriba de todo, encima del correo de hoy.
pub fn parse_date(value: &str) -> String {
    // La zona horaria puede venir como nombre —`(CEST)`— pegada al desfase, y
    // eso hace fallar el parseo aunque el resto esté perfecto.
    let cleaned = value.split('(').next().unwrap_or(value).trim();
    chrono::DateTime::parse_from_rfc2822(cleaned)
        .map(|f| f.to_rfc3339())
        .unwrap_or_default()
}

/// Lo que hace falta para responder un mensaje.
///
/// Sale de las cabeceras del original y va derecho a las del que se escribe, así
/// que **todo esto lo escribió quien mandó el mensaje**: puede traer saltos de
/// línea puestos a propósito. No se limpia acá sino al armar la respuesta, que
/// es donde está la función que sabe hacerlo y donde el peligro es visible; acá
/// se dejaría a medias y con dos lugares que arreglar.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyInfo {
    /// El identificador del original. Es lo que engancha la respuesta a la
    /// conversación en el cliente de quien la recibe; sin esto, la respuesta
    /// aparece como un mensaje suelto y la conversación se parte.
    pub message_id: String,
    /// La cadena de la conversación, ya con el original al final.
    #[serde(rename = "referencias")]
    pub references: Vec<String>,
    /// A dónde va la respuesta.
    ///
    /// `Reply-To` si el mensaje lo trae, y `From` si no. La diferencia importa:
    /// las listas de correo y los sistemas de tickets ponen `Reply-To`
    /// justamente para que la respuesta no le llegue sólo a quien apretó el
    /// botón de mandar.
    #[serde(rename = "responder_a")]
    pub reply_to: String,
    #[serde(rename = "nombre")]
    pub name: String,
}

/// Lee de un mensaje lo que hace falta para responderlo.
pub fn reply_info(raw: &[u8]) -> ReplyInfo {
    let view = as_latin1(raw);
    let (headers, _) = split_headers(&view);

    let message_id = headers
        .get("message-id")
        .unwrap_or_default()
        .trim()
        .to_string();

    // `References` es la cadena entera; si no está, la arma el `In-Reply-To`.
    // Y el original va al final: es el que sigue en la conversación.
    let mut references: Vec<String> = headers
        .get("references")
        .or_else(|| headers.get("in-reply-to"))
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    if !message_id.is_empty() && references.last() != Some(&message_id) {
        references.push(message_id.clone());
    }

    // Un `References` de una conversación de años puede tener cientos de
    // entradas, y se copia entera en cada respuesta. Se recortan las del medio
    // —que es lo que hacen los clientes— dejando el principio, que es lo que
    // identifica la conversación, y el final, que es lo que la engancha.
    if references.len() > MAX_REFERENCES {
        let tail = references.split_off(references.len() - (MAX_REFERENCES - 1));
        references.truncate(1);
        references.extend(tail);
    }

    let from = headers
        .get("reply-to")
        .filter(|v| !v.trim().is_empty())
        .or_else(|| headers.get("from"))
        .unwrap_or_default();
    let (name, reply_to) = parse_sender(from);

    ReplyInfo {
        message_id,
        references,
        reply_to,
        name,
    }
}

/// Arma el resumen de un mensaje a partir de sus cabeceras.
pub fn summary_from(
    uid: u32,
    raw_headers: &str,
    unread: bool,
    has_attachments: bool,
) -> MessageSummary {
    let headers = Headers::parse(raw_headers);
    let (from, address) = parse_sender(headers.get("from").unwrap_or_default());

    MessageSummary {
        uid,
        from,
        address,
        subject: headers.decoded("subject"),
        date: parse_date(headers.get("date").unwrap_or_default()),
        unread,
        has_attachments,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // ── Cabeceras ──────────────────────────────────────────────────────────

    /// Una cabecera larga se parte en varias líneas. Sin volver a juntarlas, un
    /// `Content-Type` partido pierde su `boundary` y el mensaje entero se
    /// muestra como un bloque de basura.
    #[test]
    fn una_cabecera_partida_se_vuelve_a_juntar() {
        let raw = "Content-Type: multipart/mixed;\r\n\tboundary=\"abc123\"\r\nFrom: ana@x\r\n";
        let headers = Headers::parse(raw);

        let content_type = parse_content_type(headers.get("content-type").unwrap());
        assert_eq!(content_type.media_type, "multipart/mixed");
        assert_eq!(content_type.boundary.as_deref(), Some("abc123"));
        assert_eq!(headers.get("from"), Some("ana@x"));
    }

    #[test]
    fn el_nombre_de_la_cabecera_no_distingue_mayusculas() {
        let headers = Headers::parse("SUBJECT: Hola\r\n");
        assert_eq!(headers.get("Subject"), Some("Hola"));
        assert_eq!(headers.get("subject"), Some("Hola"));
    }

    /// Un mensaje puede traer dos `Subject`, y ésa es una forma de esconder
    /// cosas: un cliente muestra una y otro muestra la otra. Se toma la primera,
    /// que es la que procesan los servidores.
    #[test]
    fn con_dos_cabeceras_iguales_gana_la_primera() {
        let headers = Headers::parse("Subject: la de verdad\r\nSubject: la escondida\r\n");
        assert_eq!(headers.get("subject"), Some("la de verdad"));
    }

    #[test]
    fn las_cabeceras_terminan_en_la_linea_vacia() {
        let headers = Headers::parse("From: ana@x\r\n\r\nSubject: esto es el cuerpo\r\n");
        assert_eq!(headers.get("subject"), None);
    }

    // ── Palabras codificadas ───────────────────────────────────────────────

    /// Sin esto, cualquier asunto con una tilde —o sea, medio correo en
    /// español— se muestra como una ristra de signos.
    #[test]
    fn un_asunto_codificado_se_lee() {
        assert_eq!(
            decode_words("=?UTF-8?B?UmV1bmnDs24gZGUgbWHDsWFuYQ==?="),
            "Reunión de mañana"
        );
        assert_eq!(
            decode_words("=?utf-8?Q?Reuni=C3=B3n_de_ma=C3=B1ana?="),
            "Reunión de mañana"
        );
    }

    /// El texto sin codificar de alrededor se conserva.
    #[test]
    fn lo_que_no_esta_codificado_queda_igual() {
        assert_eq!(
            decode_words("Re: =?UTF-8?B?SG9sYQ==?= (urgente)"),
            "Re: Hola (urgente)"
        );
        assert_eq!(decode_words("Un asunto normal"), "Un asunto normal");
    }

    /// Un asunto largo va en varias palabras seguidas, y el espacio que las
    /// separa **no es parte del texto**: está para poder partir la línea. Sin
    /// esta regla el asunto sale con espacios en el medio de las palabras.
    #[test]
    fn el_espacio_entre_dos_palabras_codificadas_no_va() {
        assert_eq!(
            decode_words("=?UTF-8?B?UmV1?= =?UTF-8?B?bmnDs24=?="),
            "Reunión"
        );
        // Pero entre una codificada y texto normal sí va.
        assert_eq!(decode_words("=?UTF-8?B?UmU=?= normal"), "Re normal");
    }

    /// Un `=?` que no abre nada válido es texto, y el bucle tiene que avanzar
    /// igual: si no, un asunto con un `=?` suelto cuelga el proceso.
    #[test]
    fn una_palabra_mal_formada_no_cuelga_ni_se_come_el_texto() {
        for garbage in ["=?", "=?UTF-8?", "=?UTF-8?B?", "=?UTF-8?X?abc?=", "a =? b"] {
            let out = decode_words(garbage);
            assert!(!out.is_empty() || garbage.is_empty(), "{garbage:?}");
        }
        assert_eq!(decode_words("a =? b"), "a =? b");
    }

    /// En una cabecera el `_` es un espacio; en un cuerpo es un guión bajo.
    /// Confundirlos llena el texto de espacios donde había nombres_así.
    #[test]
    fn el_guion_bajo_es_un_espacio_solo_en_la_cabecera() {
        assert_eq!(quoted_printable_decode(b"a_b", true), b"a b");
        assert_eq!(quoted_printable_decode(b"a_b", false), b"a_b");
    }

    /// Un `=` al final de línea es un corte blando: la línea sigue y no va nada
    /// al texto. Sin esto, un párrafo largo aparece con `=` cada 76 caracteres.
    #[test]
    fn el_corte_blando_de_quoted_printable_desaparece() {
        assert_eq!(
            quoted_printable_decode(b"hola =\r\nmundo", false),
            b"hola mundo"
        );
        assert_eq!(
            quoted_printable_decode(b"hola =\nmundo", false),
            b"hola mundo"
        );
    }

    /// Un `=` que no es un escape válido se deja: es un dato de alguien.
    #[test]
    fn un_igual_suelto_no_se_come_nada() {
        assert_eq!(quoted_printable_decode(b"2 = 2", false), b"2 = 2");
        assert_eq!(
            quoted_printable_decode(b"termina en =", false),
            b"termina en ="
        );
    }

    /// **El byte tiene que llegar vivo hasta que se sepa cómo leerlo.**
    ///
    /// Recorrer la estructura del mensaje como texto es cómodo, pero convertir
    /// con `from_utf8_lossy` reemplaza cada byte que no es UTF-8 por un rombo, y
    /// ahí ya no hay vuelta: el `0xF3` de la «ó» se pierde **antes** de que el
    /// `charset` diga que había que leerlo como latin-1. La vista latin-1 es la
    /// única que conserva cada byte y vuelve exacta.
    #[test]
    fn la_vista_latin1_conserva_todos_los_bytes() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        assert_eq!(from_latin1(&as_latin1(&bytes)), bytes);
    }

    /// Una cabecera **no vuelve a bytes nunca**: lo que sale del resumen es lo
    /// que se muestra. Por eso la vista latin-1, que sirve para recorrer un
    /// cuerpo, ahí sería un error — un `Subject` con UTF-8 crudo se vería como
    /// «ReuniÃ³n». Los clientes mandan esas cabeceras aunque el estándar no las
    /// permita.
    #[test]
    fn una_cabecera_con_utf8_crudo_se_lee_bien() {
        let headers = decode_text("Subject: Reunión de mañana\r\n".as_bytes(), "");
        let summary = summary_from(1, &headers, false, false);
        assert_eq!(summary.subject, "Reunión de mañana");
    }

    /// Y una en latin-1 crudo también, que es el otro caso que aparece.
    #[test]
    fn una_cabecera_con_latin1_crudo_tambien() {
        let headers = decode_text(b"Subject: Reuni\xf3n\r\n", "");
        assert_eq!(summary_from(1, &headers, false, false).subject, "Reunión");
    }

    /// El caso de punta a punta: un mensaje en latin-1 con bytes que no son
    /// UTF-8 válido llega entero al final.
    #[test]
    fn un_cuerpo_en_latin1_sobrevive_el_recorrido() {
        let mut raw = b"Content-Type: text/plain; charset=iso-8859-1\r\n\r\n".to_vec();
        raw.extend_from_slice(b"Reuni\xf3n de ma\xf1ana");

        assert_eq!(plain_text(&raw), "Reunión de mañana");
    }

    /// Y dentro de un multiparte, que es el recorrido largo.
    #[test]
    fn un_latin1_adentro_de_un_multiparte_tambien_sobrevive() {
        let mut raw = b"Content-Type: multipart/mixed; boundary=\"lim\"\r\n\r\n\
            --lim\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\n"
            .to_vec();
        raw.extend_from_slice(b"caf\xe9\r\n--lim--\r\n");

        assert!(plain_text(&raw).contains("café"));
    }

    // ── Juegos de caracteres ───────────────────────────────────────────────

    /// Medio correo viejo viene en latin-1. Sin el respaldo, un mensaje en
    /// español de hace quince años se ve con un rombo en cada acento.
    #[test]
    fn el_correo_viejo_en_latin1_se_lee() {
        // «Reunión» en ISO-8859-1: la ó es un solo byte, 0xF3.
        let bytes = b"Reuni\xf3n";
        assert_eq!(decode_text(bytes, "iso-8859-1"), "Reunión");
        // Y sin juego declarado, con bytes que no son UTF-8 válido, se cae al
        // mismo lugar en vez de mostrar rombos.
        assert_eq!(decode_text(bytes, ""), "Reunión");
    }

    /// Un mensaje sin `Content-Type` es «us-ascii» por definición del estándar,
    /// y el estándar de codificaciones hace de us-ascii un alias de
    /// Windows-1252, que decodifica **cualquier** byte sin dar error. O sea: un
    /// mensaje en UTF-8 sin declarar —que son muchísimos— salía con «Ã³» en cada
    /// «ó» y nada lo notaba. Si los bytes son UTF-8 válido, son UTF-8.
    #[test]
    fn un_utf8_que_dice_ser_ascii_no_sale_con_rombos() {
        assert_eq!(
            decode_text("Algo quedó".as_bytes(), "us-ascii"),
            "Algo quedó"
        );
        assert_eq!(decode_text("Algo quedó".as_bytes(), "ASCII"), "Algo quedó");
        // Pero unos bytes que **no** son UTF-8 sí se leen como latin-1: es lo
        // que el alias significa, y ahí sí acierta.
        assert_eq!(decode_text(b"Reuni\xf3n", "us-ascii"), "Reunión");
    }

    /// Y un juego declarado de verdad se respeta aunque los bytes se dejen leer
    /// como UTF-8: la etiqueta la puso quien escribió el mensaje.
    #[test]
    fn un_juego_declarado_de_verdad_se_respeta() {
        // 0x41 0x42 en UTF-16LE es «A» en... nada útil; alcanza con comprobar
        // que no se ignora la etiqueta y se sale por UTF-8.
        assert_eq!(decode_text(b"caf\xe9", "iso-8859-1"), "café");
    }

    #[test]
    fn el_utf8_se_lee_aunque_no_lo_declaren() {
        assert_eq!(decode_text("Reunión".as_bytes(), ""), "Reunión");
        assert_eq!(
            decode_text("Reunión".as_bytes(), "juego-inventado"),
            "Reunión"
        );
    }

    // ── MIME ───────────────────────────────────────────────────────────────

    /// Un mensaje sin `Content-Type` es texto plano en US-ASCII, y suponer otra
    /// cosa haría ilegible un mensaje que está perfectamente bien.
    #[test]
    fn sin_content_type_es_texto_plano() {
        assert_eq!(ContentType::default().media_type, "text/plain");
        assert_eq!(plain_text(b"From: ana@x\r\n\r\nHola"), "Hola");
    }

    const MULTIPART: &str = "Content-Type: multipart/alternative; boundary=\"lim\"\r\n\
        \r\n\
        esto es el preámbulo, no se muestra\r\n\
        --lim\r\n\
        Content-Type: text/html; charset=utf-8\r\n\
        \r\n\
        <p>Hola en <b>HTML</b></p>\r\n\
        --lim\r\n\
        Content-Type: text/plain; charset=utf-8\r\n\
        \r\n\
        Hola en texto\r\n\
        --lim--\r\n";

    /// El estándar pone la versión «mejor» al final, que suele ser el HTML. Acá
    /// el HTML no se dibuja, así que la mejor para esta ventana es el texto
    /// plano — venga en el orden que venga.
    #[test]
    fn en_un_alternative_gana_el_texto_plano() {
        let text = plain_text(MULTIPART.as_bytes());
        assert!(text.contains("Hola en texto"), "{text:?}");
        assert!(!text.contains("HTML"), "{text:?}");
    }

    /// Lo que hay antes de la primera frontera es para clientes que no entienden
    /// MIME, y mostrarlo sería mostrar texto que no escribió nadie.
    #[test]
    fn el_preambulo_no_se_muestra() {
        assert!(!plain_text(MULTIPART.as_bytes()).contains("preámbulo"));
    }

    /// Si sólo hay HTML se muestra igual, sin etiquetas: es preferible a un
    /// mensaje en blanco.
    #[test]
    fn si_solo_hay_html_se_muestra_sin_etiquetas() {
        let html_only = "Content-Type: text/html; charset=utf-8\r\n\r\n\
            <p>Hola <b>Ana</b></p>";
        let text = plain_text(html_only.as_bytes());
        assert!(text.contains("Hola"), "{text:?}");
        assert!(text.contains("Ana"), "{text:?}");
        assert!(!text.contains('<'), "{text:?}");
    }

    /// Un adjunto no es el cuerpo, aunque sea texto: un .csv pegado no es lo que
    /// escribió la persona.
    #[test]
    fn un_adjunto_de_texto_no_es_el_cuerpo() {
        let with_attachment = "Content-Type: multipart/mixed; boundary=\"lim\"\r\n\
            \r\n\
            --lim\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            El cuerpo de verdad\r\n\
            --lim\r\n\
            Content-Type: text/plain\r\n\
            Content-Disposition: attachment; filename=\"datos.csv\"\r\n\
            \r\n\
            a,b,c\r\n\
            --lim--\r\n";

        let text = plain_text(with_attachment.as_bytes());
        assert!(text.contains("El cuerpo de verdad"), "{text:?}");
        assert!(!text.contains("a,b,c"), "{text:?}");
    }

    /// Un mensaje armado para anidar mil veces reventaría la pila. El tope corta
    /// y lo que devuelve es un mensaje vacío, no un proceso muerto.
    #[test]
    fn una_anidacion_sin_fin_no_revienta_la_pila() {
        let mut raw = String::new();
        for i in 0..500 {
            raw.push_str(&format!(
                "Content-Type: multipart/mixed; boundary=\"l{i}\"\r\n\r\n--l{i}\r\n"
            ));
        }
        raw.push_str("Content-Type: text/plain\r\n\r\nal fondo\r\n");

        // Lo único que importa es que vuelva.
        let _ = plain_text(raw.as_bytes());
    }

    /// Un mensaje sin la línea de cierre está mal formado, pero perder el cuerpo
    /// entero por un `--` que faltó sería peor.
    #[test]
    fn un_multiparte_sin_cierre_muestra_lo_que_hay() {
        let unclosed = "Content-Type: multipart/mixed; boundary=\"lim\"\r\n\
            \r\n--lim\r\nContent-Type: text/plain\r\n\r\nAlgo quedó\r\n";
        assert!(plain_text(unclosed.as_bytes()).contains("Algo quedó"));
    }

    /// Una frontera vacía partiría el mensaje en cada línea.
    #[test]
    fn una_frontera_vacia_no_se_usa() {
        assert_eq!(
            parse_content_type("multipart/mixed; boundary=\"\"").boundary,
            None
        );
    }

    #[test]
    fn el_cuerpo_en_base64_se_decodifica() {
        let raw = "Content-Type: text/plain; charset=utf-8\r\n\
            Content-Transfer-Encoding: base64\r\n\r\n\
            UmV1bmnDs24gZGUgbWHDsWFuYQ==";
        assert_eq!(plain_text(raw.as_bytes()), "Reunión de mañana");
    }

    // ── HTML ───────────────────────────────────────────────────────────────

    /// Dejar el contenido de `<script>` volcaría código JavaScript en el medio
    /// del mensaje. Y `<style>`, hojas de estilo.
    #[test]
    fn el_script_y_el_estilo_se_descartan_enteros() {
        let html = "<p>Hola</p><script>alert('x')</script><style>p{color:red}</style><p>Chau</p>";
        let text = strip_tags(html);
        assert!(text.contains("Hola") && text.contains("Chau"), "{text:?}");
        assert!(!text.contains("alert"), "{text:?}");
        assert!(!text.contains("color"), "{text:?}");
    }

    /// Dos bloques pegados: saliendo por abajo del salto, el brinco hasta el
    /// próximo `>` se comía el `<` del segundo y su contenido terminaba en el
    /// mensaje. Éste es el caso exacto que lo destapó.
    #[test]
    fn un_script_pegado_a_un_style_no_deja_pasar_el_segundo() {
        let html = "<script>alert(1)</script><style>p{color:red}</style>Hola";
        let text = strip_tags(html);
        assert_eq!(text.trim(), "Hola", "{text:?}");
    }

    /// Sin los saltos, un mensaje entero queda en un solo párrafo interminable.
    #[test]
    fn los_parrafos_y_los_br_dejan_un_salto() {
        assert!(strip_tags("uno<br>dos").contains('\n'));
        assert!(strip_tags("<p>uno</p><p>dos</p>").contains('\n'));
    }

    /// `&amp;` va al final: si fuera primero, `&amp;lt;` —que es el texto
    /// literal «&lt;»— terminaría convertido en `<`.
    #[test]
    fn las_entidades_no_se_deshacen_dos_veces() {
        assert_eq!(decode_entities("&amp;lt;"), "&lt;");
        assert_eq!(decode_entities("a &lt; b &amp; c"), "a < b & c");
    }

    /// El correo en HTML de los remitentes viejos escribe los acentos como
    /// entidades numéricas. Sin deshacerlas, un mensaje en español se lee lleno
    /// de números en el medio de las palabras.
    #[test]
    fn las_entidades_numericas_se_deshacen() {
        assert_eq!(decode_entities("Reuni&#243;n"), "Reunión");
        assert_eq!(decode_entities("Reuni&#xF3;n"), "Reunión");
        assert_eq!(decode_entities("comilla&#8217;s"), "comilla\u{2019}s");
    }

    /// Un `&#` que no abre una entidad es texto, y el bucle tiene que avanzar
    /// igual: si no, un mensaje con un `&#` suelto cuelga el proceso.
    #[test]
    fn una_entidad_numerica_rota_no_cuelga_ni_se_come_el_texto() {
        for garbage in [
            "&#",
            "&#;",
            "&#xZZ;",
            "&#99999999999;",
            "a &# b",
            "&#123456789012345;",
        ] {
            let out = decode_entities(garbage);
            assert!(!out.is_empty(), "{garbage:?}");
        }
        assert_eq!(decode_entities("a &# b"), "a &# b");
    }

    /// Un `<` sin su `>` es una etiqueta abierta, no texto: lo que sigue no se
    /// muestra, y sobre todo el bucle termina.
    #[test]
    fn un_html_roto_no_cuelga() {
        for garbage in ["<", "<p", "<script>sin cierre", "<<<<", "a < b"] {
            let _ = strip_tags(garbage);
        }
    }

    /// **El caso que destapó el orden de las operaciones.**
    ///
    /// Decodificando la cabecera entera y buscando el `<` en el resultado,
    /// alcanza con ponerse de nombre una palabra codificada que contenga
    /// `<algo@banco.com>` para que la dirección que se muestra sea una que nunca
    /// estuvo en el mensaje — o sea, exactamente el engaño que esta función
    /// existe para impedir, servido por la función misma.
    #[test]
    fn un_nombre_codificado_no_puede_inventar_una_direccion() {
        // «<soporte@banco.com>» en base64.
        let disguise = "=?UTF-8?B?PHNvcG9ydGVAYmFuY28uY29tPg==?= <atacante@otro.net>";
        let (name, address) = parse_sender(disguise);

        assert_eq!(address, "atacante@otro.net");
        // El nombre se sigue mostrando decodificado, que es lo correcto: es
        // texto para leer. Lo que no puede es pasar por dirección.
        assert_eq!(name, "<soporte@banco.com>");
    }

    /// Y sin dirección de verdad, una palabra codificada tampoco se convierte en
    /// una: el nombre es el nombre.
    #[test]
    fn una_cabecera_con_un_menor_codificado_y_nada_mas() {
        let (_, address) = parse_sender("=?UTF-8?B?PGFuYUB4Pg==?=");
        assert_eq!(address, "<ana@x>");
    }

    // ── Remitente y fecha ──────────────────────────────────────────────────

    #[test]
    fn el_nombre_y_la_direccion_van_separados() {
        let (name, address) = parse_sender("Ana Pérez <ana@ejemplo.com>");
        assert_eq!(name, "Ana Pérez");
        assert_eq!(address, "ana@ejemplo.com");
    }

    /// El fraude más común que hay: ponerse de nombre una dirección y escribir
    /// desde otra. Separados, no se puede hacer pasar uno por otro.
    #[test]
    fn un_nombre_que_finge_ser_una_direccion_no_tapa_la_de_verdad() {
        let (name, address) = parse_sender("\"soporte@banco.com\" <atacante@otro.net>");
        assert_eq!(name, "soporte@banco.com");
        assert_eq!(address, "atacante@otro.net");
    }

    /// Un nombre puede contener un `<`, y ése es justamente el truco: con el
    /// primero, la dirección saldría de adentro del nombre.
    #[test]
    fn con_dos_menores_gana_el_ultimo() {
        let (_, address) = parse_sender("Ana <no@esta> <ana@ejemplo.com>");
        assert_eq!(address, "ana@ejemplo.com");
    }

    #[test]
    fn una_direccion_pelada_se_usa_de_nombre() {
        let (name, address) = parse_sender("ana@ejemplo.com");
        assert_eq!(name, "ana@ejemplo.com");
        assert_eq!(address, "ana@ejemplo.com");
    }

    #[test]
    fn el_nombre_del_remitente_tambien_se_decodifica() {
        let (name, _) = parse_sender("=?UTF-8?B?QW5hIFDDqXJleg==?= <ana@x>");
        assert_eq!(name, "Ana Pérez");
    }

    #[test]
    fn la_fecha_queda_en_iso() {
        let date = parse_date("Tue, 15 Sep 2026 14:30:00 +0200");
        assert!(date.starts_with("2026-09-15T14:30:00+02:00"), "{date}");
    }

    /// La zona puede venir con su nombre pegado, y eso hace fallar el parseo
    /// aunque el resto esté perfecto.
    #[test]
    fn una_fecha_con_el_nombre_de_la_zona_se_entiende() {
        assert!(!parse_date("Tue, 15 Sep 2026 14:30:00 +0200 (CEST)").is_empty());
    }

    /// Vacío y **no la hora de ahora**: un mensaje de hace tres años con la
    /// fecha rota aparecería arriba de todo, encima del correo de hoy.
    #[test]
    fn una_fecha_rota_queda_vacia() {
        for garbage in ["", "ayer", "2026-09-15", "Tue, 99 Xxx 2026"] {
            assert_eq!(parse_date(garbage), "", "{garbage:?}");
        }
    }

    // ── Responder ──────────────────────────────────────────────────────────

    /// Sin el `Message-ID` del original, la respuesta aparece como un mensaje
    /// suelto y la conversación se parte en el cliente de quien la recibe.
    #[test]
    fn se_saca_lo_que_hace_falta_para_responder() {
        let raw = b"From: Ana=?x?= <ana@ejemplo.com>\r\n\
            Message-ID: <original@ejemplo.com>\r\n\
            References: <uno@x.com> <dos@x.com>\r\n\r\nHola";

        let r = reply_info(raw);
        assert_eq!(r.message_id, "<original@ejemplo.com>");
        assert_eq!(r.reply_to, "ana@ejemplo.com");
        // El original va al final: es el que sigue en la conversación.
        assert_eq!(
            r.references,
            vec!["<uno@x.com>", "<dos@x.com>", "<original@ejemplo.com>"]
        );
    }

    /// **Las listas de correo y los sistemas de tickets ponen `Reply-To`**
    /// justamente para que la respuesta no le llegue sólo a quien apretó
    /// mandar. Ignorarlo manda la respuesta al lugar equivocado.
    #[test]
    fn el_reply_to_gana_sobre_el_from() {
        let raw = b"From: Ana <ana@ejemplo.com>\r\n\
            Reply-To: lista@grupo.com\r\n\r\nHola";
        assert_eq!(reply_info(raw).reply_to, "lista@grupo.com");

        // Vacío no cuenta: hay clientes que lo mandan así.
        let empty = b"From: Ana <ana@ejemplo.com>\r\nReply-To:   \r\n\r\nHola";
        assert_eq!(reply_info(empty).reply_to, "ana@ejemplo.com");
    }

    /// Sin `References`, la cadena la arma el `In-Reply-To`: hay clientes que
    /// mandan sólo ése.
    #[test]
    fn sin_references_alcanza_el_in_reply_to() {
        let raw = b"Message-ID: <b@x>\r\nIn-Reply-To: <a@x>\r\n\r\nHola";
        assert_eq!(reply_info(raw).references, vec!["<a@x>", "<b@x>"]);
    }

    /// Una conversación de años acumula cientos de referencias y la cadena se
    /// copia entera en cada mensaje: sin tope, la cabecera crece hasta que algún
    /// servidor del camino rechaza el mensaje.
    #[test]
    fn una_conversacion_larga_no_arrastra_todo() {
        let long_refs: Vec<String> = (0..500).map(|i| format!("<{i}@x>")).collect();
        let raw = format!(
            "Message-ID: <ultimo@x>\r\nReferences: {}\r\n\r\nHola",
            long_refs.join(" ")
        );

        let r = reply_info(raw.as_bytes());
        assert_eq!(r.references.len(), MAX_REFERENCES);
        // Se conserva la primera, que identifica la conversación…
        assert_eq!(r.references[0], "<0@x>");
        // …y la última, que es la que la engancha.
        assert_eq!(r.references.last().unwrap(), "<ultimo@x>");
    }

    /// Un mensaje sin `Message-ID` existe —los hay mal armados—, y responderlo
    /// tiene que poder pasar igual: sin cabecera de conversación, pero con
    /// destinatario.
    #[test]
    fn un_mensaje_sin_identificador_se_puede_responder_igual() {
        let r = reply_info(b"From: ana@ejemplo.com\r\n\r\nHola");
        assert_eq!(r.message_id, "");
        assert!(r.references.is_empty());
        assert_eq!(r.reply_to, "ana@ejemplo.com");
    }

    // ── El resumen entero ──────────────────────────────────────────────────

    #[test]
    fn se_arma_el_resumen_de_un_mensaje() {
        let headers = "From: =?UTF-8?B?QW5hIFDDqXJleg==?= <ana@ejemplo.com>\r\n\
            Subject: =?UTF-8?Q?Reuni=C3=B3n?=\r\n\
            Date: Tue, 15 Sep 2026 14:30:00 +0200\r\n";

        let summary = summary_from(42, headers, true, false);
        assert_eq!(summary.uid, 42);
        assert_eq!(summary.from, "Ana Pérez");
        assert_eq!(summary.address, "ana@ejemplo.com");
        assert_eq!(summary.subject, "Reunión");
        assert!(summary.date.starts_with("2026-09-15"));
        assert!(summary.unread);
    }

    /// Un mensaje sin nada se resume vacío y no rompe: la lista tiene que poder
    /// mostrarlo igual, porque ocupa lugar en la casilla de la persona.
    #[test]
    fn un_mensaje_sin_cabeceras_se_resume_vacio() {
        let summary = summary_from(1, "", false, false);
        assert_eq!(summary.subject, "");
        assert_eq!(summary.from, "");
        assert_eq!(summary.date, "");
    }

    /// Un cuerpo enorme trabaría la ventana al dibujarlo, y cortar un `String`
    /// en el medio de un carácter es un pánico.
    #[test]
    fn un_cuerpo_enorme_se_recorta_sin_partir_un_caracter() {
        let body = "ñ".repeat(MAX_TEXT);
        let raw = format!("Content-Type: text/plain; charset=utf-8\r\n\r\n{body}");

        let text = plain_text(raw.as_bytes());
        assert!(text.len() <= MAX_TEXT + 16, "{}", text.len());
        assert!(text.ends_with("[…]"));
        // Que sea un `String` válido ya lo garantiza el tipo; esto comprueba que
        // no se cortó en el medio de la ñ dejando un carácter de reemplazo.
        assert!(!text.contains('\u{FFFD}'));
    }

    /// Un mensaje que sólo trae HTML: hay formato que mostrar.
    #[test]
    fn el_html_de_un_mensaje_se_encuentra() {
        let raw = b"Content-Type: text/html; charset=utf-8\r\n\r\n<p>Hola</p>";
        assert_eq!(html_part(raw).as_deref(), Some("<p>Hola</p>"));
    }

    /// Uno que trae las dos versiones: se devuelve la de formato, al revés que
    /// `plain_text`, que prefiere la plana.
    #[test]
    fn de_las_dos_versiones_se_devuelve_la_de_formato() {
        let raw = b"Content-Type: multipart/alternative; boundary=lim\r\n\r\n\
            --lim\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHola\r\n\
            --lim\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Hola</p>\r\n\
            --lim--\r\n";
        // Con `trim`: el cuerpo de una parte se queda con el salto de línea que
        // va antes de la frontera, y eso es del formato, no del mensaje. Para
        // HTML da igual, y el saneador lo normaliza después.
        assert_eq!(
            html_part(raw).as_deref().map(str::trim),
            Some("<p>Hola</p>")
        );
        // Y el texto plano sigue saliendo por su camino de siempre.
        assert!(plain_text(raw).contains("Hola"));
    }

    /// Uno que sólo trae texto: no hay formato, y eso no es un error.
    #[test]
    fn un_mensaje_sin_html_no_devuelve_nada() {
        let raw = b"Content-Type: text/plain; charset=utf-8\r\n\r\nHola";
        assert_eq!(html_part(raw), None);
    }

    /// Un `.html` pegado no es el cuerpo del mensaje.
    #[test]
    fn un_html_adjunto_no_es_el_cuerpo() {
        let raw = b"Content-Type: multipart/mixed; boundary=lim\r\n\r\n\
            --lim\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nMira esto\r\n\
            --lim\r\nContent-Type: text/html; charset=utf-8\r\n\
            Content-Disposition: attachment; filename=\"pagina.html\"\r\n\r\n<p>otra cosa</p>\r\n\
            --lim--\r\n";
        assert_eq!(html_part(raw), None);
    }

    /// El juego de caracteres se respeta, igual que en el texto plano.
    #[test]
    fn el_html_se_decodifica_con_su_juego_de_caracteres() {
        let mut raw = b"Content-Type: text/html; charset=iso-8859-1\r\n\r\n".to_vec();
        // «<p>Pérez</p>» en latin-1: la «é» es un solo byte, 0xE9.
        raw.extend_from_slice(b"<p>P\xE9rez</p>");
        assert_eq!(html_part(&raw).as_deref(), Some("<p>Pérez</p>"));
    }
}
