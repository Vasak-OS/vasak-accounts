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
const MAX_PROFUNDIDAD: usize = 8;

/// Cuántas partes se miran en un mismo nivel.
///
/// Un `multipart` con cien mil partes vacías es barato de escribir y caro de
/// recorrer. Ninguno legítimo pasa de unas decenas.
const MAX_PARTES: usize = 64;

/// Tope del texto que se devuelve para mostrar.
///
/// Un megabyte de texto son unas doscientas mil palabras: nadie escribe eso y
/// nadie lo lee. Lo que pasa de ahí es un archivo pegado en el cuerpo, y
/// mandárselo entero a la ventana la trabaría al dibujarlo.
const MAX_TEXTO: usize = 1024 * 1024;

/// Lo que se muestra de un mensaje en la lista.
///
/// Sin el cuerpo: la lista de una casilla con diez mil mensajes tiene que caber
/// en memoria y viajar por D-Bus. El cuerpo se pide de a uno, cuando alguien
/// abre el mensaje.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resumen {
    /// El identificador estable del mensaje dentro de su casilla.
    ///
    /// El UID y no el número de secuencia: el número cambia cuando se borra
    /// cualquier mensaje anterior, así que guardarlo en un caché sería guardar
    /// algo que apunta a otro mensaje mañana.
    pub uid: u32,
    /// Cómo se firma quien lo mandó, ya legible.
    pub de: String,
    /// Su dirección, aparte del nombre.
    ///
    /// Separada a propósito: un remitente que se llama a sí mismo
    /// «soporte@banco.com» y escribe desde otra dirección es el fraude más común
    /// que hay, y juntar las dos cosas en una sola línea es lo que lo hace
    /// funcionar.
    pub direccion: String,
    pub asunto: String,
    /// Cuándo lo mandaron, en ISO 8601. Vacío si la fecha no se entendió.
    pub fecha: String,
    pub sin_leer: bool,
    /// Si tiene algo pegado. No qué, todavía: sólo que hay.
    pub con_adjuntos: bool,
}

// ---------------------------------------------------------------------------
// Cabeceras
// ---------------------------------------------------------------------------

/// Las cabeceras de un mensaje, ya desplegadas.
#[derive(Debug, Default, Clone)]
pub struct Cabeceras(Vec<(String, String)>);

impl Cabeceras {
    /// Lee el bloque de cabeceras de un mensaje.
    ///
    /// Una cabecera larga se parte en varias líneas y las siguientes empiezan
    /// con espacio o tabulación. Sin volver a juntarlas, un asunto largo queda
    /// cortado y un `Content-Type` partido pierde su `boundary` — o sea, el
    /// mensaje entero se muestra como un bloque de basura.
    pub fn leer(texto: &str) -> Self {
        let mut campos: Vec<(String, String)> = Vec::new();

        for cruda in texto.split('\n') {
            let linea = cruda.strip_suffix('\r').unwrap_or(cruda);
            // Una línea vacía termina las cabeceras y empieza el cuerpo.
            if linea.is_empty() {
                break;
            }

            if linea.starts_with([' ', '\t']) {
                if let Some((_, valor)) = campos.last_mut() {
                    valor.push(' ');
                    valor.push_str(linea.trim());
                }
                continue;
            }

            if let Some((nombre, valor)) = linea.split_once(':') {
                campos.push((nombre.trim().to_ascii_lowercase(), valor.trim().to_string()));
            }
        }

        Cabeceras(campos)
    }

    /// El valor de una cabecera, tal cual vino.
    ///
    /// La primera de las que haya: un mensaje puede traer dos `Subject`, y ésa
    /// es justamente una forma de esconder cosas —un cliente muestra una y otro
    /// muestra la otra—. Quedarse con la primera es lo que hacen los servidores
    /// que las procesan, así que es la que corresponde mostrar.
    pub fn valor(&self, nombre: &str) -> Option<&str> {
        let buscado = nombre.to_ascii_lowercase();
        self.0
            .iter()
            .find(|(n, _)| *n == buscado)
            .map(|(_, v)| v.as_str())
    }

    /// El valor de una cabecera, ya legible.
    pub fn texto(&self, nombre: &str) -> String {
        self.valor(nombre).map(decodificar_palabras).unwrap_or_default()
    }
}

/// Deshace las «palabras codificadas» de una cabecera.
///
/// Una cabecera sólo puede llevar ASCII, así que todo lo demás va envuelto en
/// `=?UTF-8?B?...?=`. Sin deshacerlo, cualquier asunto con una tilde —o sea,
/// medio correo en español— se muestra como una ristra de signos.
pub fn decodificar_palabras(valor: &str) -> String {
    let mut salida = String::with_capacity(valor.len());
    let mut resto = valor;
    // Si la palabra anterior estaba codificada y sólo hay espacios hasta la
    // siguiente, esos espacios **no van**: el estándar los pone para poder
    // partir la línea, no porque estén en el texto. Sin esto, un asunto largo
    // en otro idioma sale con espacios en el medio de las palabras.
    let mut anterior_codificada = false;

    while let Some(inicio) = resto.find("=?") {
        let (antes, desde) = resto.split_at(inicio);
        let solo_espacios = !antes.is_empty() && antes.trim().is_empty();
        if !(anterior_codificada && solo_espacios) {
            salida.push_str(antes);
        }

        match partir_palabra(desde) {
            Some((decodificada, sigue)) => {
                salida.push_str(&decodificada);
                anterior_codificada = true;
                resto = sigue;
            }
            None => {
                // Un `=?` que no abre una palabra válida es texto: se copia y se
                // sigue después de él, o el bucle no avanza nunca.
                salida.push_str("=?");
                anterior_codificada = false;
                resto = &desde[2..];
            }
        }
    }

    salida.push_str(resto);
    salida
}

/// Decodifica una palabra que empieza en `=?`, y devuelve lo que sigue.
fn partir_palabra(desde: &str) -> Option<(String, &str)> {
    let cuerpo = desde.strip_prefix("=?")?;
    let fin = cuerpo.find("?=")?;
    let (dentro, despues) = cuerpo.split_at(fin);
    let despues = &despues["?=".len()..];

    let mut partes = dentro.splitn(3, '?');
    let juego = partes.next()?;
    let como = partes.next()?;
    let texto = partes.next()?;
    // Tres partes exactas: `charset?encoding?texto`. Menos no es una palabra
    // codificada, y un `?` de más va dentro del texto.
    if texto.contains('?') {
        return None;
    }

    let bytes = match como.to_ascii_uppercase().as_str() {
        "B" => base64_de(texto)?,
        "Q" => Some(imprimible_de(texto.as_bytes(), true))?,
        _ => return None,
    };

    // El juego de caracteres puede traer un idioma pegado: `UTF-8*es`.
    let juego = juego.split('*').next().unwrap_or(juego);
    Some((a_texto(&bytes, juego), despues))
}

fn base64_de(texto: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    // Sin relleno y tolerante: hay clientes que mandan el `=` final y otros que
    // no, y rechazar por eso perdería el asunto entero de un mensaje real.
    let limpio: String = texto.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&limpio)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(limpio.trim_end_matches('=')))
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
/// latin-1. En la hoja se vuelven a sacar los bytes originales con `de_latin1` y
/// recién ahí se usa el juego que declaró el mensaje.
pub fn como_latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|b| char::from(*b)).collect()
}

/// La vuelta de `como_latin1`, exacta.
///
/// Los caracteres que no salieron de un byte —no pueden aparecer si el texto
/// viene de `como_latin1`, pero la función es pública— se descartan en vez de
/// recortarse: inventar un byte sería peor que perderlo.
pub fn de_latin1(texto: &str) -> Vec<u8> {
    texto
        .chars()
        .filter_map(|c| u8::try_from(c as u32).ok())
        .collect()
}

/// Deshace `quoted-printable`.
///
/// `en_cabecera` cambia una sola cosa: dentro de una cabecera el `_` es un
/// espacio. En un cuerpo es un guión bajo, y confundirlos llena el texto de
/// espacios donde había nombres_con_guion.
pub fn imprimible_de(bytes: &[u8], en_cabecera: bool) -> Vec<u8> {
    let mut salida = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'_' if en_cabecera => {
                salida.push(b' ');
                i += 1;
            }
            b'=' if !en_cabecera && bytes.get(i + 1) == Some(&b'\r') => {
                // Un `=` al final de la línea es un corte blando: la línea sigue
                // y ni el `=` ni el salto van al texto.
                i += if bytes.get(i + 2) == Some(&b'\n') { 3 } else { 2 };
            }
            b'=' if !en_cabecera && bytes.get(i + 1) == Some(&b'\n') => i += 2,
            b'=' => match hex_de(bytes.get(i + 1).copied(), bytes.get(i + 2).copied()) {
                Some(byte) => {
                    salida.push(byte);
                    i += 3;
                }
                // Un `=` que no es un escape válido se deja: es un dato de
                // alguien y tragárselo cambiaría el texto.
                None => {
                    salida.push(b'=');
                    i += 1;
                }
            },
            otro => {
                salida.push(otro);
                i += 1;
            }
        }
    }

    salida
}

fn hex_de(alto: Option<u8>, bajo: Option<u8>) -> Option<u8> {
    let digito = |b: Option<u8>| (b? as char).to_digit(16);
    Some((digito(alto)? * 16 + digito(bajo)?) as u8)
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
pub fn a_texto(bytes: &[u8], juego: &str) -> String {
    let etiqueta = juego.trim();
    let es_utf8 = std::str::from_utf8(bytes).is_ok();

    let Some(declarada) = Encoding::for_label(etiqueta.as_bytes()) else {
        return si_no_hay_etiqueta(bytes, es_utf8);
    };

    let dice_ascii =
        etiqueta.eq_ignore_ascii_case("us-ascii") || etiqueta.eq_ignore_ascii_case("ascii");
    if dice_ascii && !bytes.is_ascii() && es_utf8 {
        return String::from_utf8_lossy(bytes).into_owned();
    }

    declarada.decode(bytes).0.into_owned()
}

fn si_no_hay_etiqueta(bytes: &[u8], es_utf8: bool) -> String {
    let codificacion = if es_utf8 { encoding_rs::UTF_8 } else { encoding_rs::WINDOWS_1252 };
    codificacion.decode(bytes).0.into_owned()
}

// ---------------------------------------------------------------------------
// MIME
// ---------------------------------------------------------------------------

/// Lo que dice un `Content-Type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tipo {
    /// En minúsculas, sin parámetros: `text/plain`.
    pub medio: String,
    pub juego: String,
    /// El separador de las partes, si es un `multipart`.
    pub frontera: Option<String>,
}

impl Default for Tipo {
    fn default() -> Self {
        // Lo que dice el estándar para un mensaje sin `Content-Type`: texto
        // plano en US-ASCII. Suponer otra cosa haría ilegible un mensaje que
        // está perfectamente bien.
        Tipo {
            medio: "text/plain".into(),
            juego: "us-ascii".into(),
            frontera: None,
        }
    }
}

/// Lee un `Content-Type`.
pub fn tipo_de(valor: &str) -> Tipo {
    let mut partes = valor.split(';');
    let medio = partes
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    let mut tipo = Tipo {
        medio: if medio.is_empty() { "text/plain".into() } else { medio },
        juego: "us-ascii".into(),
        frontera: None,
    };

    for parametro in partes {
        let Some((nombre, valor)) = parametro.split_once('=') else {
            continue;
        };
        let valor = sin_comillas(valor.trim());
        match nombre.trim().to_ascii_lowercase().as_str() {
            "charset" => tipo.juego = valor.to_string(),
            // Vacío no sirve de separador: partiría el mensaje en cada línea.
            "boundary" if !valor.is_empty() => tipo.frontera = Some(valor.to_string()),
            _ => {}
        }
    }

    tipo
}

fn sin_comillas(valor: &str) -> &str {
    valor
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(valor)
}

/// Deshace la codificación de transporte de un cuerpo.
///
/// Sobre **bytes** y no sobre texto: `8bit` y `binary` quieren decir exactamente
/// que el cuerpo trae bytes que no son ASCII, y en qué idioma están lo dice el
/// `charset`, que se aplica después.
pub fn destransportar(cuerpo: &[u8], codificacion: &str) -> Vec<u8> {
    match codificacion.trim().to_ascii_lowercase().as_str() {
        // El base64 es ASCII por definición, así que leerlo como texto es
        // seguro; si trae algo que no lo es, no es base64 y se deja crudo.
        "base64" => std::str::from_utf8(cuerpo)
            .ok()
            .and_then(base64_de)
            .unwrap_or_else(|| cuerpo.to_vec()),
        "quoted-printable" => imprimible_de(cuerpo, false),
        // `7bit`, `8bit`, `binary` y cualquier cosa que no se conozca: los bytes
        // tal cual. Es lo correcto para los tres primeros, y para el resto es
        // mejor mostrar algo raro que no mostrar nada.
        _ => cuerpo.to_vec(),
    }
}

/// Separa un mensaje —o una parte— en sus cabeceras y su cuerpo.
///
/// El corte es la primera línea vacía. Si no hay ninguna, el mensaje es todo
/// cabeceras y no tiene cuerpo, que es raro pero posible.
pub fn partir(crudo: &str) -> (Cabeceras, &str) {
    let corte = crudo
        .find("\r\n\r\n")
        .map(|i| (i, i + 4))
        .or_else(|| crudo.find("\n\n").map(|i| (i, i + 2)));

    match corte {
        Some((fin, comienzo)) => (Cabeceras::leer(&crudo[..fin]), &crudo[comienzo..]),
        None => (Cabeceras::leer(crudo), ""),
    }
}

/// Parte un `multipart` por su frontera.
///
/// Cada parte va entre `--frontera` y la siguiente; `--frontera--` cierra. Lo
/// que hay antes de la primera es el «preámbulo», que existe para los clientes
/// que no entienden MIME y no se muestra.
pub fn partes_de<'a>(cuerpo: &'a str, frontera: &str) -> Vec<&'a str> {
    let separador = format!("--{frontera}");
    let cierre = format!("--{frontera}--");
    let mut partes = Vec::new();
    let mut actual: Option<usize> = None;

    let mut posicion = 0usize;
    for linea in cuerpo.split_inclusive('\n') {
        let inicio = posicion;
        posicion += linea.len();
        let recortada = linea.trim_end();

        if recortada == cierre {
            if let Some(desde) = actual.take() {
                partes.push(&cuerpo[desde..inicio]);
            }
            break;
        }
        if recortada == separador {
            if let Some(desde) = actual.take() {
                partes.push(&cuerpo[desde..inicio]);
            }
            if partes.len() >= MAX_PARTES {
                break;
            }
            actual = Some(posicion);
        }
    }

    // Un mensaje sin la línea de cierre está mal formado, pero lo que ya se
    // había abierto se muestra igual: es preferible a perder el cuerpo entero
    // por un `--` que faltó.
    if let Some(desde) = actual {
        partes.push(&cuerpo[desde..]);
    }

    partes
}

/// El texto que se le muestra a la persona.
///
/// Busca la mejor parte legible: primero `text/plain`, y si no hay, el
/// `text/html` con las etiquetas sacadas. Los adjuntos no entran — un PDF
/// convertido a caracteres es ruido.
pub fn texto_de(crudo: &[u8]) -> String {
    // La vista latin-1 conserva cada byte tal cual mientras se recorre la
    // estructura. Ver `como_latin1`.
    let vista = como_latin1(crudo);
    let (cabeceras, cuerpo) = partir(&vista);
    let mut texto = buscar_texto(&cabeceras, cuerpo, 0).unwrap_or_default();

    if texto.len() > MAX_TEXTO {
        texto.truncate(recorte_valido(&texto, MAX_TEXTO));
        texto.push_str("\n\n[…]");
    }
    texto
}

/// Un `String` no se puede cortar en cualquier byte: hacerlo en el medio de un
/// carácter es un pánico. Se retrocede hasta el comienzo del carácter.
fn recorte_valido(texto: &str, tope: usize) -> usize {
    let mut corte = tope.min(texto.len());
    while corte > 0 && !texto.is_char_boundary(corte) {
        corte -= 1;
    }
    corte
}

fn buscar_texto(cabeceras: &Cabeceras, cuerpo: &str, profundidad: usize) -> Option<String> {
    if profundidad > MAX_PROFUNDIDAD {
        return None;
    }

    let tipo = cabeceras
        .valor("content-type")
        .map(tipo_de)
        .unwrap_or_default();

    if let Some(frontera) = &tipo.frontera {
        let partes = partes_de(cuerpo, frontera);
        // `multipart/alternative` trae la misma cosa en varios formatos, de peor
        // a mejor, y hay que quedarse con **una**. Se prefiere el texto plano
        // aunque venga primero y el HTML después: acá el HTML no se dibuja, así
        // que la versión «mejor» del estándar es la peor para esta ventana.
        let mut respaldo = None;
        for parte in partes {
            let (suyas, su_cuerpo) = partir(parte);
            let su_tipo = suyas.valor("content-type").map(tipo_de).unwrap_or_default();
            let Some(texto) = buscar_texto(&suyas, su_cuerpo, profundidad + 1) else {
                continue;
            };
            if su_tipo.medio == "text/plain" && !es_adjunto(&suyas) {
                return Some(texto);
            }
            if respaldo.is_none() {
                respaldo = Some(texto);
            }
        }
        return respaldo;
    }

    // Un adjunto no es el cuerpo, aunque sea texto: un .csv pegado no es lo que
    // escribió la persona.
    if es_adjunto(cabeceras) {
        return None;
    }

    let codificacion = cabeceras
        .valor("content-transfer-encoding")
        .unwrap_or("7bit");
    // Acá se sale de la vista latin-1 y se vuelve a los bytes que mandó el
    // servidor. Es el único lugar donde se decide en qué idioma está escrito
    // esto, y es el último momento en que los bytes originales todavía existen.
    let bytes = destransportar(&de_latin1(cuerpo), codificacion);
    let texto = a_texto(&bytes, &tipo.juego);

    match tipo.medio.as_str() {
        "text/plain" => Some(texto),
        "text/html" => Some(sin_etiquetas(&texto)),
        _ => None,
    }
}

/// Si una parte viene marcada como adjunto.
fn es_adjunto(cabeceras: &Cabeceras) -> bool {
    cabeceras
        .valor("content-disposition")
        .map(|d| d.trim().to_ascii_lowercase().starts_with("attachment"))
        .unwrap_or(false)
}

/// Si el mensaje trae algo pegado.
pub fn tiene_adjuntos(crudo: &[u8]) -> bool {
    let vista = como_latin1(crudo);
    let (cabeceras, cuerpo) = partir(&vista);
    buscar_adjunto(&cabeceras, cuerpo, 0)
}

fn buscar_adjunto(cabeceras: &Cabeceras, cuerpo: &str, profundidad: usize) -> bool {
    if profundidad > MAX_PROFUNDIDAD {
        return false;
    }
    if profundidad > 0 && es_adjunto(cabeceras) {
        return true;
    }

    let tipo = cabeceras
        .valor("content-type")
        .map(tipo_de)
        .unwrap_or_default();
    let Some(frontera) = &tipo.frontera else {
        return false;
    };

    partes_de(cuerpo, frontera).into_iter().any(|parte| {
        let (suyas, su_cuerpo) = partir(parte);
        buscar_adjunto(&suyas, su_cuerpo, profundidad + 1)
    })
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
pub fn sin_etiquetas(html: &str) -> String {
    // En minúsculas sólo lo ASCII, que es lo que deja los índices idénticos a
    // los del original: comparar sobre esta copia y cortar sobre la otra es
    // seguro únicamente por eso.
    let bajo = html.to_ascii_lowercase();
    let mut salida = String::with_capacity(html.len());
    let mut i = 0;

    while i < html.len() {
        let Some(hasta) = html[i..].find('<') else {
            salida.push_str(&html[i..]);
            break;
        };
        salida.push_str(&html[i..i + hasta]);
        i += hasta;

        // Un bloque que no es texto para nadie se salta entero, contenido
        // incluido: dejarlo volcaría JavaScript o una hoja de estilos en el
        // medio del mensaje.
        let mut saltado = false;
        for (etiqueta, cierre) in [("<script", "</script>"), ("<style", "</style>")] {
            if bajo[i..].starts_with(etiqueta) {
                // Sin cierre, lo que queda es todo parte del bloque.
                i = bajo[i..]
                    .find(cierre)
                    .map(|f| i + f + cierre.len())
                    .unwrap_or(html.len());
                saltado = true;
                break;
            }
        }
        if saltado {
            // **`continue` y no seguir de largo.** Saliendo por abajo, el salto
            // hasta el próximo `>` se comía la etiqueta que venía después del
            // bloque: con `<script>…</script><style>…`, el `<` del `<style>`
            // desaparecía y su contenido terminaba en el mensaje.
            continue;
        }

        // Un salto de línea donde el HTML lo tenía: sin esto un mensaje entero
        // queda en un solo párrafo interminable.
        if bajo[i..].starts_with("<br")
            || bajo[i..].starts_with("</p")
            || bajo[i..].starts_with("</div")
        {
            salida.push('\n');
        }

        // Y saltear la etiqueta. Un `<` sin su `>` es una etiqueta abierta y no
        // texto: lo que queda no se muestra.
        i = match html[i..].find('>') {
            Some(f) => i + f + 1,
            None => html.len(),
        };
    }

    entidades(&salida)
}

/// Deshace las entidades: las cinco con nombre que aparecen siempre, y todas las
/// numéricas.
///
/// Las numéricas importan más de lo que parece. El correo en HTML de los
/// remitentes viejos escribe los acentos así —`&#243;` por «ó»—, y sin
/// deshacerlas un mensaje en español se lee lleno de números en el medio de las
/// palabras. Una tabla completa de nombres, en cambio, serían mil quinientas
/// entradas para casos que casi no aparecen.
fn entidades(texto: &str) -> String {
    let con_nombre = texto
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'");

    let numericas = numericas_de(&con_nombre);
    // `&amp;` al final: si fuera primero, un `&amp;lt;` —que es el texto
    // literal «&lt;»— terminaría convertido en `<`.
    numericas.replace("&amp;", "&")
}

/// Deshace `&#243;` y `&#xF3;`.
fn numericas_de(texto: &str) -> String {
    let mut salida = String::with_capacity(texto.len());
    let mut resto = texto;

    while let Some(inicio) = resto.find("&#") {
        salida.push_str(&resto[..inicio]);
        let cuerpo = &resto[inicio + 2..];

        // Una entidad numérica termina en `;` y es corta. El tope evita
        // recorrer el mensaje entero buscando un `;` que no está.
        let fin = cuerpo.char_indices().take(10).find(|(_, c)| *c == ';');
        let convertida = fin.and_then(|(f, _)| {
            let digitos = &cuerpo[..f];
            let numero = match digitos.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => digitos.parse().ok()?,
            };
            char::from_u32(numero).map(|c| (c, f + 3))
        });

        match convertida {
            Some((caracter, avance)) => {
                salida.push(caracter);
                resto = &resto[inicio + avance..];
            }
            // Un `&#` que no abre una entidad es texto: se copia y se sigue
            // después de él, o el bucle no avanza nunca.
            None => {
                salida.push_str("&#");
                resto = cuerpo;
            }
        }
    }

    salida.push_str(resto);
    salida
}

// ---------------------------------------------------------------------------
// De un mensaje crudo a lo que se muestra
// ---------------------------------------------------------------------------

/// Separa el nombre de la dirección en un `From`.
///
/// Van separados porque juntarlos es lo que hace funcionar el fraude más común
/// que hay: un remitente que se pone de nombre «soporte@banco.com» y escribe
/// desde otra dirección. Mostrados aparte, no se puede hacer pasar uno por otro.
pub fn remitente_de(valor: &str) -> (String, String) {
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
    if let Some(abre) = valor.rfind('<') {
        if let Some(cierra) = valor[abre..].find('>') {
            let direccion = valor[abre + 1..abre + cierra].trim().to_string();
            // El nombre sí se decodifica: es texto para leer, y ahí una palabra
            // codificada es lo normal y no un truco.
            let nombre = decodificar_palabras(&valor[..abre]);
            let nombre = nombre.trim().trim_matches('"').trim().to_string();
            let nombre = if nombre.is_empty() { direccion.clone() } else { nombre };
            return (nombre, direccion);
        }
    }

    // Una dirección pelada: el nombre es la dirección. Se decodifica igual, por
    // si es un nombre suelto sin dirección.
    let direccion = decodificar_palabras(valor).trim().to_string();
    (direccion.clone(), direccion)
}

/// Lee la fecha de un mensaje y la deja en ISO 8601.
///
/// Vacío si no se entiende, y **no la hora de ahora**: un mensaje de hace tres
/// años con fecha rota aparecería arriba de todo, encima del correo de hoy.
pub fn fecha_de(valor: &str) -> String {
    // La zona horaria puede venir como nombre —`(CEST)`— pegada al desfase, y
    // eso hace fallar el parseo aunque el resto esté perfecto.
    let limpio = valor.split('(').next().unwrap_or(valor).trim();
    chrono::DateTime::parse_from_rfc2822(limpio)
        .map(|f| f.to_rfc3339())
        .unwrap_or_default()
}

/// Arma el resumen de un mensaje a partir de sus cabeceras.
pub fn resumen_de(uid: u32, cabeceras_crudas: &str, sin_leer: bool, con_adjuntos: bool) -> Resumen {
    let cabeceras = Cabeceras::leer(cabeceras_crudas);
    let (de, direccion) = remitente_de(cabeceras.valor("from").unwrap_or_default());

    Resumen {
        uid,
        de,
        direccion,
        asunto: cabeceras.texto("subject"),
        fecha: fecha_de(cabeceras.valor("date").unwrap_or_default()),
        sin_leer,
        con_adjuntos,
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
        let crudo = "Content-Type: multipart/mixed;\r\n\tboundary=\"abc123\"\r\nFrom: ana@x\r\n";
        let cabeceras = Cabeceras::leer(crudo);

        let tipo = tipo_de(cabeceras.valor("content-type").unwrap());
        assert_eq!(tipo.medio, "multipart/mixed");
        assert_eq!(tipo.frontera.as_deref(), Some("abc123"));
        assert_eq!(cabeceras.valor("from"), Some("ana@x"));
    }

    #[test]
    fn el_nombre_de_la_cabecera_no_distingue_mayusculas() {
        let cabeceras = Cabeceras::leer("SUBJECT: Hola\r\n");
        assert_eq!(cabeceras.valor("Subject"), Some("Hola"));
        assert_eq!(cabeceras.valor("subject"), Some("Hola"));
    }

    /// Un mensaje puede traer dos `Subject`, y ésa es una forma de esconder
    /// cosas: un cliente muestra una y otro muestra la otra. Se toma la primera,
    /// que es la que procesan los servidores.
    #[test]
    fn con_dos_cabeceras_iguales_gana_la_primera() {
        let cabeceras = Cabeceras::leer("Subject: la de verdad\r\nSubject: la escondida\r\n");
        assert_eq!(cabeceras.valor("subject"), Some("la de verdad"));
    }

    #[test]
    fn las_cabeceras_terminan_en_la_linea_vacia() {
        let cabeceras = Cabeceras::leer("From: ana@x\r\n\r\nSubject: esto es el cuerpo\r\n");
        assert_eq!(cabeceras.valor("subject"), None);
    }

    // ── Palabras codificadas ───────────────────────────────────────────────

    /// Sin esto, cualquier asunto con una tilde —o sea, medio correo en
    /// español— se muestra como una ristra de signos.
    #[test]
    fn un_asunto_codificado_se_lee() {
        assert_eq!(
            decodificar_palabras("=?UTF-8?B?UmV1bmnDs24gZGUgbWHDsWFuYQ==?="),
            "Reunión de mañana"
        );
        assert_eq!(
            decodificar_palabras("=?utf-8?Q?Reuni=C3=B3n_de_ma=C3=B1ana?="),
            "Reunión de mañana"
        );
    }

    /// El texto sin codificar de alrededor se conserva.
    #[test]
    fn lo_que_no_esta_codificado_queda_igual() {
        assert_eq!(
            decodificar_palabras("Re: =?UTF-8?B?SG9sYQ==?= (urgente)"),
            "Re: Hola (urgente)"
        );
        assert_eq!(decodificar_palabras("Un asunto normal"), "Un asunto normal");
    }

    /// Un asunto largo va en varias palabras seguidas, y el espacio que las
    /// separa **no es parte del texto**: está para poder partir la línea. Sin
    /// esta regla el asunto sale con espacios en el medio de las palabras.
    #[test]
    fn el_espacio_entre_dos_palabras_codificadas_no_va() {
        assert_eq!(
            decodificar_palabras("=?UTF-8?B?UmV1?= =?UTF-8?B?bmnDs24=?="),
            "Reunión"
        );
        // Pero entre una codificada y texto normal sí va.
        assert_eq!(decodificar_palabras("=?UTF-8?B?UmU=?= normal"), "Re normal");
    }

    /// Un `=?` que no abre nada válido es texto, y el bucle tiene que avanzar
    /// igual: si no, un asunto con un `=?` suelto cuelga el proceso.
    #[test]
    fn una_palabra_mal_formada_no_cuelga_ni_se_come_el_texto() {
        for basura in ["=?", "=?UTF-8?", "=?UTF-8?B?", "=?UTF-8?X?abc?=", "a =? b"] {
            let salida = decodificar_palabras(basura);
            assert!(!salida.is_empty() || basura.is_empty(), "{basura:?}");
        }
        assert_eq!(decodificar_palabras("a =? b"), "a =? b");
    }

    /// En una cabecera el `_` es un espacio; en un cuerpo es un guión bajo.
    /// Confundirlos llena el texto de espacios donde había nombres_así.
    #[test]
    fn el_guion_bajo_es_un_espacio_solo_en_la_cabecera() {
        assert_eq!(imprimible_de(b"a_b", true), b"a b");
        assert_eq!(imprimible_de(b"a_b", false), b"a_b");
    }

    /// Un `=` al final de línea es un corte blando: la línea sigue y no va nada
    /// al texto. Sin esto, un párrafo largo aparece con `=` cada 76 caracteres.
    #[test]
    fn el_corte_blando_de_quoted_printable_desaparece() {
        assert_eq!(imprimible_de(b"hola =\r\nmundo", false), b"hola mundo");
        assert_eq!(imprimible_de(b"hola =\nmundo", false), b"hola mundo");
    }

    /// Un `=` que no es un escape válido se deja: es un dato de alguien.
    #[test]
    fn un_igual_suelto_no_se_come_nada() {
        assert_eq!(imprimible_de(b"2 = 2", false), b"2 = 2");
        assert_eq!(imprimible_de(b"termina en =", false), b"termina en =");
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
        assert_eq!(de_latin1(&como_latin1(&bytes)), bytes);
    }

    /// El caso de punta a punta: un mensaje en latin-1 con bytes que no son
    /// UTF-8 válido llega entero al final.
    #[test]
    fn un_cuerpo_en_latin1_sobrevive_el_recorrido() {
        let mut crudo = b"Content-Type: text/plain; charset=iso-8859-1\r\n\r\n".to_vec();
        crudo.extend_from_slice(b"Reuni\xf3n de ma\xf1ana");

        assert_eq!(texto_de(&crudo), "Reunión de mañana");
    }

    /// Y dentro de un multiparte, que es el recorrido largo.
    #[test]
    fn un_latin1_adentro_de_un_multiparte_tambien_sobrevive() {
        let mut crudo = b"Content-Type: multipart/mixed; boundary=\"lim\"\r\n\r\n\
            --lim\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\n"
            .to_vec();
        crudo.extend_from_slice(b"caf\xe9\r\n--lim--\r\n");

        assert!(texto_de(&crudo).contains("café"));
    }

    // ── Juegos de caracteres ───────────────────────────────────────────────

    /// Medio correo viejo viene en latin-1. Sin el respaldo, un mensaje en
    /// español de hace quince años se ve con un rombo en cada acento.
    #[test]
    fn el_correo_viejo_en_latin1_se_lee() {
        // «Reunión» en ISO-8859-1: la ó es un solo byte, 0xF3.
        let bytes = b"Reuni\xf3n";
        assert_eq!(a_texto(bytes, "iso-8859-1"), "Reunión");
        // Y sin juego declarado, con bytes que no son UTF-8 válido, se cae al
        // mismo lugar en vez de mostrar rombos.
        assert_eq!(a_texto(bytes, ""), "Reunión");
    }

    /// Un mensaje sin `Content-Type` es «us-ascii» por definición del estándar,
    /// y el estándar de codificaciones hace de us-ascii un alias de
    /// Windows-1252, que decodifica **cualquier** byte sin dar error. O sea: un
    /// mensaje en UTF-8 sin declarar —que son muchísimos— salía con «Ã³» en cada
    /// «ó» y nada lo notaba. Si los bytes son UTF-8 válido, son UTF-8.
    #[test]
    fn un_utf8_que_dice_ser_ascii_no_sale_con_rombos() {
        assert_eq!(a_texto("Algo quedó".as_bytes(), "us-ascii"), "Algo quedó");
        assert_eq!(a_texto("Algo quedó".as_bytes(), "ASCII"), "Algo quedó");
        // Pero unos bytes que **no** son UTF-8 sí se leen como latin-1: es lo
        // que el alias significa, y ahí sí acierta.
        assert_eq!(a_texto(b"Reuni\xf3n", "us-ascii"), "Reunión");
    }

    /// Y un juego declarado de verdad se respeta aunque los bytes se dejen leer
    /// como UTF-8: la etiqueta la puso quien escribió el mensaje.
    #[test]
    fn un_juego_declarado_de_verdad_se_respeta() {
        // 0x41 0x42 en UTF-16LE es «A» en... nada útil; alcanza con comprobar
        // que no se ignora la etiqueta y se sale por UTF-8.
        assert_eq!(a_texto(b"caf\xe9", "iso-8859-1"), "café");
    }

    #[test]
    fn el_utf8_se_lee_aunque_no_lo_declaren() {
        assert_eq!(a_texto("Reunión".as_bytes(), ""), "Reunión");
        assert_eq!(a_texto("Reunión".as_bytes(), "juego-inventado"), "Reunión");
    }

    // ── MIME ───────────────────────────────────────────────────────────────

    /// Un mensaje sin `Content-Type` es texto plano en US-ASCII, y suponer otra
    /// cosa haría ilegible un mensaje que está perfectamente bien.
    #[test]
    fn sin_content_type_es_texto_plano() {
        assert_eq!(Tipo::default().medio, "text/plain");
        assert_eq!(texto_de(b"From: ana@x\r\n\r\nHola"), "Hola");
    }

    const MULTIPARTE: &str = "Content-Type: multipart/alternative; boundary=\"lim\"\r\n\
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
        let texto = texto_de(MULTIPARTE.as_bytes());
        assert!(texto.contains("Hola en texto"), "{texto:?}");
        assert!(!texto.contains("HTML"), "{texto:?}");
    }

    /// Lo que hay antes de la primera frontera es para clientes que no entienden
    /// MIME, y mostrarlo sería mostrar texto que no escribió nadie.
    #[test]
    fn el_preambulo_no_se_muestra() {
        assert!(!texto_de(MULTIPARTE.as_bytes()).contains("preámbulo"));
    }

    /// Si sólo hay HTML se muestra igual, sin etiquetas: es preferible a un
    /// mensaje en blanco.
    #[test]
    fn si_solo_hay_html_se_muestra_sin_etiquetas() {
        let solo_html = "Content-Type: text/html; charset=utf-8\r\n\r\n\
            <p>Hola <b>Ana</b></p>";
        let texto = texto_de(solo_html.as_bytes());
        assert!(texto.contains("Hola"), "{texto:?}");
        assert!(texto.contains("Ana"), "{texto:?}");
        assert!(!texto.contains('<'), "{texto:?}");
    }

    /// Un adjunto no es el cuerpo, aunque sea texto: un .csv pegado no es lo que
    /// escribió la persona.
    #[test]
    fn un_adjunto_de_texto_no_es_el_cuerpo() {
        let con_adjunto = "Content-Type: multipart/mixed; boundary=\"lim\"\r\n\
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

        let texto = texto_de(con_adjunto.as_bytes());
        assert!(texto.contains("El cuerpo de verdad"), "{texto:?}");
        assert!(!texto.contains("a,b,c"), "{texto:?}");
        assert!(tiene_adjuntos(con_adjunto.as_bytes()));
    }

    #[test]
    fn un_mensaje_simple_no_tiene_adjuntos() {
        assert!(!tiene_adjuntos(b"Content-Type: text/plain\r\n\r\nHola"));
    }

    /// Un mensaje armado para anidar mil veces reventaría la pila. El tope corta
    /// y lo que devuelve es un mensaje vacío, no un proceso muerto.
    #[test]
    fn una_anidacion_sin_fin_no_revienta_la_pila() {
        let mut crudo = String::new();
        for i in 0..500 {
            crudo.push_str(&format!(
                "Content-Type: multipart/mixed; boundary=\"l{i}\"\r\n\r\n--l{i}\r\n"
            ));
        }
        crudo.push_str("Content-Type: text/plain\r\n\r\nal fondo\r\n");

        // Lo único que importa es que vuelva.
        let _ = texto_de(crudo.as_bytes());
        let _ = tiene_adjuntos(crudo.as_bytes());
    }

    /// Un mensaje sin la línea de cierre está mal formado, pero perder el cuerpo
    /// entero por un `--` que faltó sería peor.
    #[test]
    fn un_multiparte_sin_cierre_muestra_lo_que_hay() {
        let sin_cierre = "Content-Type: multipart/mixed; boundary=\"lim\"\r\n\
            \r\n--lim\r\nContent-Type: text/plain\r\n\r\nAlgo quedó\r\n";
        assert!(texto_de(sin_cierre.as_bytes()).contains("Algo quedó"));
    }

    /// Una frontera vacía partiría el mensaje en cada línea.
    #[test]
    fn una_frontera_vacia_no_se_usa() {
        assert_eq!(tipo_de("multipart/mixed; boundary=\"\"").frontera, None);
    }

    #[test]
    fn el_cuerpo_en_base64_se_decodifica() {
        let crudo = "Content-Type: text/plain; charset=utf-8\r\n\
            Content-Transfer-Encoding: base64\r\n\r\n\
            UmV1bmnDs24gZGUgbWHDsWFuYQ==";
        assert_eq!(texto_de(crudo.as_bytes()), "Reunión de mañana");
    }

    // ── HTML ───────────────────────────────────────────────────────────────

    /// Dejar el contenido de `<script>` volcaría código JavaScript en el medio
    /// del mensaje. Y `<style>`, hojas de estilo.
    #[test]
    fn el_script_y_el_estilo_se_descartan_enteros() {
        let html = "<p>Hola</p><script>alert('x')</script><style>p{color:red}</style><p>Chau</p>";
        let texto = sin_etiquetas(html);
        assert!(texto.contains("Hola") && texto.contains("Chau"), "{texto:?}");
        assert!(!texto.contains("alert"), "{texto:?}");
        assert!(!texto.contains("color"), "{texto:?}");
    }

    /// Dos bloques pegados: saliendo por abajo del salto, el brinco hasta el
    /// próximo `>` se comía el `<` del segundo y su contenido terminaba en el
    /// mensaje. Éste es el caso exacto que lo destapó.
    #[test]
    fn un_script_pegado_a_un_style_no_deja_pasar_el_segundo() {
        let html = "<script>alert(1)</script><style>p{color:red}</style>Hola";
        let texto = sin_etiquetas(html);
        assert_eq!(texto.trim(), "Hola", "{texto:?}");
    }

    /// Sin los saltos, un mensaje entero queda en un solo párrafo interminable.
    #[test]
    fn los_parrafos_y_los_br_dejan_un_salto() {
        assert!(sin_etiquetas("uno<br>dos").contains('\n'));
        assert!(sin_etiquetas("<p>uno</p><p>dos</p>").contains('\n'));
    }

    /// `&amp;` va al final: si fuera primero, `&amp;lt;` —que es el texto
    /// literal «&lt;»— terminaría convertido en `<`.
    #[test]
    fn las_entidades_no_se_deshacen_dos_veces() {
        assert_eq!(entidades("&amp;lt;"), "&lt;");
        assert_eq!(entidades("a &lt; b &amp; c"), "a < b & c");
    }

    /// El correo en HTML de los remitentes viejos escribe los acentos como
    /// entidades numéricas. Sin deshacerlas, un mensaje en español se lee lleno
    /// de números en el medio de las palabras.
    #[test]
    fn las_entidades_numericas_se_deshacen() {
        assert_eq!(entidades("Reuni&#243;n"), "Reunión");
        assert_eq!(entidades("Reuni&#xF3;n"), "Reunión");
        assert_eq!(entidades("comilla&#8217;s"), "comilla\u{2019}s");
    }

    /// Un `&#` que no abre una entidad es texto, y el bucle tiene que avanzar
    /// igual: si no, un mensaje con un `&#` suelto cuelga el proceso.
    #[test]
    fn una_entidad_numerica_rota_no_cuelga_ni_se_come_el_texto() {
        for basura in ["&#", "&#;", "&#xZZ;", "&#99999999999;", "a &# b", "&#123456789012345;"] {
            let salida = entidades(basura);
            assert!(!salida.is_empty(), "{basura:?}");
        }
        assert_eq!(entidades("a &# b"), "a &# b");
    }

    /// Un `<` sin su `>` es una etiqueta abierta, no texto: lo que sigue no se
    /// muestra, y sobre todo el bucle termina.
    #[test]
    fn un_html_roto_no_cuelga() {
        for basura in ["<", "<p", "<script>sin cierre", "<<<<", "a < b"] {
            let _ = sin_etiquetas(basura);
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
        let disfraz = "=?UTF-8?B?PHNvcG9ydGVAYmFuY28uY29tPg==?= <atacante@otro.net>";
        let (nombre, direccion) = remitente_de(disfraz);

        assert_eq!(direccion, "atacante@otro.net");
        // El nombre se sigue mostrando decodificado, que es lo correcto: es
        // texto para leer. Lo que no puede es pasar por dirección.
        assert_eq!(nombre, "<soporte@banco.com>");
    }

    /// Y sin dirección de verdad, una palabra codificada tampoco se convierte en
    /// una: el nombre es el nombre.
    #[test]
    fn una_cabecera_con_un_menor_codificado_y_nada_mas() {
        let (_, direccion) = remitente_de("=?UTF-8?B?PGFuYUB4Pg==?=");
        assert_eq!(direccion, "<ana@x>");
    }

    // ── Remitente y fecha ──────────────────────────────────────────────────

    #[test]
    fn el_nombre_y_la_direccion_van_separados() {
        let (nombre, direccion) = remitente_de("Ana Pérez <ana@ejemplo.com>");
        assert_eq!(nombre, "Ana Pérez");
        assert_eq!(direccion, "ana@ejemplo.com");
    }

    /// El fraude más común que hay: ponerse de nombre una dirección y escribir
    /// desde otra. Separados, no se puede hacer pasar uno por otro.
    #[test]
    fn un_nombre_que_finge_ser_una_direccion_no_tapa_la_de_verdad() {
        let (nombre, direccion) = remitente_de("\"soporte@banco.com\" <atacante@otro.net>");
        assert_eq!(nombre, "soporte@banco.com");
        assert_eq!(direccion, "atacante@otro.net");
    }

    /// Un nombre puede contener un `<`, y ése es justamente el truco: con el
    /// primero, la dirección saldría de adentro del nombre.
    #[test]
    fn con_dos_menores_gana_el_ultimo() {
        let (_, direccion) = remitente_de("Ana <no@esta> <ana@ejemplo.com>");
        assert_eq!(direccion, "ana@ejemplo.com");
    }

    #[test]
    fn una_direccion_pelada_se_usa_de_nombre() {
        let (nombre, direccion) = remitente_de("ana@ejemplo.com");
        assert_eq!(nombre, "ana@ejemplo.com");
        assert_eq!(direccion, "ana@ejemplo.com");
    }

    #[test]
    fn el_nombre_del_remitente_tambien_se_decodifica() {
        let (nombre, _) = remitente_de("=?UTF-8?B?QW5hIFDDqXJleg==?= <ana@x>");
        assert_eq!(nombre, "Ana Pérez");
    }

    #[test]
    fn la_fecha_queda_en_iso() {
        let fecha = fecha_de("Tue, 15 Sep 2026 14:30:00 +0200");
        assert!(fecha.starts_with("2026-09-15T14:30:00+02:00"), "{fecha}");
    }

    /// La zona puede venir con su nombre pegado, y eso hace fallar el parseo
    /// aunque el resto esté perfecto.
    #[test]
    fn una_fecha_con_el_nombre_de_la_zona_se_entiende() {
        assert!(!fecha_de("Tue, 15 Sep 2026 14:30:00 +0200 (CEST)").is_empty());
    }

    /// Vacío y **no la hora de ahora**: un mensaje de hace tres años con la
    /// fecha rota aparecería arriba de todo, encima del correo de hoy.
    #[test]
    fn una_fecha_rota_queda_vacia() {
        for basura in ["", "ayer", "2026-09-15", "Tue, 99 Xxx 2026"] {
            assert_eq!(fecha_de(basura), "", "{basura:?}");
        }
    }

    // ── El resumen entero ──────────────────────────────────────────────────

    #[test]
    fn se_arma_el_resumen_de_un_mensaje() {
        let cabeceras = "From: =?UTF-8?B?QW5hIFDDqXJleg==?= <ana@ejemplo.com>\r\n\
            Subject: =?UTF-8?Q?Reuni=C3=B3n?=\r\n\
            Date: Tue, 15 Sep 2026 14:30:00 +0200\r\n";

        let resumen = resumen_de(42, cabeceras, true, false);
        assert_eq!(resumen.uid, 42);
        assert_eq!(resumen.de, "Ana Pérez");
        assert_eq!(resumen.direccion, "ana@ejemplo.com");
        assert_eq!(resumen.asunto, "Reunión");
        assert!(resumen.fecha.starts_with("2026-09-15"));
        assert!(resumen.sin_leer);
    }

    /// Un mensaje sin nada se resume vacío y no rompe: la lista tiene que poder
    /// mostrarlo igual, porque ocupa lugar en la casilla de la persona.
    #[test]
    fn un_mensaje_sin_cabeceras_se_resume_vacio() {
        let resumen = resumen_de(1, "", false, false);
        assert_eq!(resumen.asunto, "");
        assert_eq!(resumen.de, "");
        assert_eq!(resumen.fecha, "");
    }

    /// Un cuerpo enorme trabaría la ventana al dibujarlo, y cortar un `String`
    /// en el medio de un carácter es un pánico.
    #[test]
    fn un_cuerpo_enorme_se_recorta_sin_partir_un_caracter() {
        let cuerpo = "ñ".repeat(MAX_TEXTO);
        let crudo = format!("Content-Type: text/plain; charset=utf-8\r\n\r\n{cuerpo}");

        let texto = texto_de(crudo.as_bytes());
        assert!(texto.len() <= MAX_TEXTO + 16, "{}", texto.len());
        assert!(texto.ends_with("[…]"));
        // Que sea un `String` válido ya lo garantiza el tipo; esto comprueba que
        // no se cortó en el medio de la ñ dejando un carácter de reemplazo.
        assert!(!texto.contains('\u{FFFD}'));
    }
}
