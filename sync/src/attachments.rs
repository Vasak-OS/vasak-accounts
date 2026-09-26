//! Los archivos pegados a un mensaje: cuáles hay y cómo se llaman.
//!
//! Hasta ahora se **detectaban** y no se podían abrir: la ventana recibía un
//! booleano —«este mensaje trae algo»— y nada más. Está escrito así a propósito,
//! porque alguien que lee un correo sin enterarse de que traía un archivo pierde
//! el archivo; pero enterarse y no poder abrirlo tampoco alcanza.
//!
//! Acá está lo que se puede resolver mirando el mensaje que ya se trajo: qué
//! partes son adjuntos, cómo se llaman, de qué tipo son y **qué número de parte
//! tienen** en el árbol MIME, que es lo que después hace falta para pedirle al
//! servidor esa parte sola.
//!
//! # El nombre del archivo lo eligió un desconocido
//!
//! Es la regla que ordena todo este módulo. El nombre viene dentro de un correo
//! que mandó cualquiera, así que se trata como hostil: se le saca todo separador
//! de ruta, se rechazan `..`, los vacíos, los de control y los nombres
//! reservados. Y **nunca** se usa para decidir dónde escribir: es una sugerencia
//! que se sanea, y el destino lo elige la persona.

use crate::message::{
    as_latin1, decode_text, decode_words, is_attachment, parse_content_type, split_headers,
    Headers, MAX_DEPTH,
};

/// Un archivo pegado a un mensaje.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Attachment {
    /// El número de parte en el árbol MIME —`2`, `1.3`—, como lo numera
    /// RFC 3501 §6.4.5. Es lo que se le manda al servidor para pedir esta parte
    /// sola en vez del mensaje entero.
    #[serde(rename = "parte")]
    pub part: String,
    /// Un nombre ya saneado, listo para proponer. Nunca vacío.
    #[serde(rename = "nombre")]
    pub name: String,
    /// El tipo declarado, en minúsculas. `application/octet-stream` si no dijo.
    #[serde(rename = "tipo")]
    pub content_type: String,
}

/// Un nombre que se puede proponer sin miedo.
///
/// Lo que entra es texto de un desconocido. Lo que sale se puede mostrar en un
/// diálogo y usar como nombre por omisión — **no** como ruta.
///
/// Devuelve `None` cuando no queda nada utilizable, y quien llama pone uno
/// genérico. Inventar acá un «adjunto.bin» escondería que el mensaje venía raro.
pub fn safe_file_name(suggested: &str) -> Option<String> {
    // Sólo la última parte: un `../../etc/passwd` o un `C:\algo\x.txt` se quedan
    // en `passwd` y `x.txt`. Se cortan las tres formas porque el nombre pudo
    // escribirlo cualquier sistema.
    let leaf = suggested
        .rsplit(['/', '\\', ':'])
        .next()
        .unwrap_or(suggested)
        .trim();

    // Los de control incluyen el salto de línea y el nulo. Un nombre con un
    // salto adentro parte cualquier cosa que después lo escriba en una línea.
    let cleaned: String = leaf.chars().filter(|c| !c.is_control()).collect();
    let cleaned = cleaned.trim().trim_matches('.').trim();

    if cleaned.is_empty() {
        return None;
    }

    // Los reservados de Windows. No es nuestro sistema, pero el archivo va a
    // terminar en un pendrive o en un adjunto de vuelta, y un `CON.txt` rompe
    // del otro lado.
    const RESERVED_NAMES: [&str; 22] = [
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
        "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];
    let base = cleaned
        .split('.')
        .next()
        .unwrap_or(cleaned)
        .to_ascii_lowercase();
    if RESERVED_NAMES.contains(&base.as_str()) {
        return None;
    }

    // Un nombre larguísimo no es un ataque, pero no entra en ningún sistema de
    // archivos. Se recorta por caracteres y no por bytes para no partir uno.
    const MAX_NAME_CHARS: usize = 200;
    if cleaned.chars().count() > MAX_NAME_CHARS {
        return Some(cleaned.chars().take(MAX_NAME_CHARS).collect());
    }
    Some(cleaned.to_string())
}

/// Parte una lista de parámetros de cabecera respetando las comillas.
///
/// `filename="a;b.txt"` es **un** parámetro, no dos. Partir por `;` a secas
/// dejaría el nombre cortado a la mitad.
fn parameters(value: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for c in value.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                current.push(c);
            }
            ';' if !in_quotes => {
                out.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }
    out.push(current);

    out.into_iter()
        .skip(1) // El primero es el valor, no un parámetro.
        .filter_map(|chunk| {
            let (name, value) = chunk.split_once('=')?;
            Some((
                name.trim().to_ascii_lowercase(),
                unquote(value.trim()).to_string(),
            ))
        })
        .collect()
}

fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

/// Deshace el `%XX` de un valor extendido y lo pasa a texto con su juego.
fn percent_decode(value: &str, charset: &str) -> String {
    let bytes = value.as_bytes();
    let mut raw = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                raw.push(b);
                i += 3;
                continue;
            }
        }
        raw.push(bytes[i]);
        i += 1;
    }
    decode_text(&raw, charset)
}

/// `utf-8''%C3%A1rbol.pdf` → `árbol.pdf`.
///
/// El juego y el idioma van adelante, separados por comillas simples. Si no
/// están, el valor es texto tal cual: hay clientes que mandan el `*` sin la
/// parte del juego.
fn decode_extended(value: &str) -> String {
    let mut chunks = value.splitn(3, '\'');
    match (chunks.next(), chunks.next(), chunks.next()) {
        (Some(charset), Some(_language), Some(text)) => {
            let charset = if charset.is_empty() { "utf-8" } else { charset };
            percent_decode(text, charset)
        }
        _ => percent_decode(value, "utf-8"),
    }
}

/// El valor de un parámetro, en cualquiera de las tres formas que existen.
///
/// - `filename="informe.pdf"` — el caso corriente.
/// - `filename*=utf-8''%C3%A1rbol.pdf` — RFC 2231, para lo que no es ASCII.
/// - `filename*0*=…; filename*1*=…` — RFC 2231 partido, para los largos.
///
/// Y el nombre puede venir además en RFC 2047 (`=?utf-8?B?…?=`), que es lo que
/// mandan los clientes viejos donde el estándar pedía la otra forma.
pub fn parameter(value: &str, name: &str) -> Option<String> {
    let all = parameters(value);
    let lookup = |key: &str| all.iter().find(|(n, _)| n == key).map(|(_, v)| v.clone());

    // La forma extendida sin partir gana: si están las dos, la otra es la copia
    // en ASCII que dejan algunos clientes para los que no entienden ésta.
    if let Some(v) = lookup(&format!("{name}*")) {
        return Some(decode_extended(&v));
    }

    // Partido en segmentos numerados. Se juntan en orden hasta el primer hueco:
    // seguir después de un segmento que falta pegaría trozos que no van juntos.
    let mut joined = String::new();
    let mut charset = String::new();
    for i in 0.. {
        if let Some(v) = lookup(&format!("{name}*{i}*")) {
            if i == 0 {
                let mut chunks = v.splitn(3, '\'');
                if let (Some(j), Some(_), Some(text)) =
                    (chunks.next(), chunks.next(), chunks.next())
                {
                    charset = if j.is_empty() {
                        "utf-8".into()
                    } else {
                        j.to_string()
                    };
                    joined.push_str(&percent_decode(text, &charset));
                    continue;
                }
            }
            joined.push_str(&percent_decode(
                &v,
                if charset.is_empty() {
                    "utf-8"
                } else {
                    &charset
                },
            ));
        } else if let Some(v) = lookup(&format!("{name}*{i}")) {
            joined.push_str(&v);
        } else {
            break;
        }
    }
    if !joined.is_empty() {
        return Some(joined);
    }

    lookup(name).map(|v| decode_words(&v))
}

/// Deshace la codificación de una parte, según lo que digan sus cabeceras.
///
/// Sin esto, lo que se baja es un bloque de base64: el archivo guardado pesaría
/// un tercio más y no lo abriría ningún programa.
///
/// Lo que no se reconoce se devuelve tal cual, que es lo correcto para `7bit`,
/// `8bit` y `binary` —los tres quieren decir «no hay nada que deshacer»— y lo
/// menos malo para una codificación que no existe: guardar los bytes crudos deja
/// algo que se puede mirar, y devolver un error deja a la persona sin el
/// archivo.
pub fn decode_part(raw_headers: &[u8], content: &[u8]) -> Vec<u8> {
    let view = as_latin1(raw_headers);
    let (headers, _) = split_headers(&view);
    let encoding = headers.decoded("content-transfer-encoding");

    crate::message::decode_transfer(content, encoding.trim())
}

/// Los adjuntos de un mensaje, con su número de parte.
pub fn list(raw: &[u8]) -> Vec<Attachment> {
    let view = as_latin1(raw);
    let (headers, body) = split_headers(&view);
    let mut found = Vec::new();
    walk(&headers, body, "", 0, &mut found);
    found
}

/// Baja por el árbol numerando las partes como RFC 3501 §6.4.5.
///
/// En un `multipart`, las partes son `1`, `2`, `3`…; una anidada dentro de la
/// primera es `1.1`. El mensaje entero —cuando no es `multipart`— es la parte
/// `1`, que es el caso de un correo que es un solo archivo.
fn walk(headers: &Headers, body: &str, prefix: &str, depth: usize, out: &mut Vec<Attachment>) {
    if depth > MAX_DEPTH {
        return;
    }

    let content_type = headers
        .get("content-type")
        .map(parse_content_type)
        .unwrap_or_default();

    if let Some(boundary) = &content_type.boundary {
        for (i, part) in crate::message::split_parts(body, boundary)
            .into_iter()
            .enumerate()
        {
            let number = if prefix.is_empty() {
                (i + 1).to_string()
            } else {
                format!("{prefix}.{}", i + 1)
            };
            let (part_headers, part_body) = split_headers(part);
            walk(&part_headers, part_body, &number, depth + 1, out);
        }
        return;
    }

    if !is_attachment(headers) {
        return;
    }

    // El nombre está en el `Content-Disposition`; si no, en el `Content-Type`,
    // que es donde lo ponen los clientes viejos.
    let suggested = headers
        .get("content-disposition")
        .and_then(|d| parameter(d, "filename"))
        .or_else(|| {
            headers
                .get("content-type")
                .and_then(|t| parameter(t, "name"))
        })
        .unwrap_or_default();

    out.push(Attachment {
        // Un mensaje que es un adjunto y nada más es la parte `1`.
        part: if prefix.is_empty() {
            "1".to_string()
        } else {
            prefix.to_string()
        },
        // Sin nombre utilizable se pone uno genérico **con el número de parte**,
        // para que dos adjuntos sin nombre no se llamen igual.
        name: safe_file_name(&suggested).unwrap_or_else(|| {
            let which = if prefix.is_empty() { "1" } else { prefix };
            format!("adjunto-{which}.bin")
        }),
        content_type: if content_type.media_type == "text/plain"
            && headers.get("content-type").is_none()
        {
            // El `text/plain` por omisión es una suposición del estándar para un
            // mensaje sin `Content-Type`; para un adjunto es casi seguro falsa.
            "application/octet-stream".to_string()
        } else {
            content_type.media_type
        },
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La regla que ordena el módulo: el nombre lo eligió un desconocido.
    #[test]
    fn un_nombre_no_puede_llevar_a_otro_lado() {
        // Una ruta relativa se queda en su última parte.
        assert_eq!(safe_file_name("../../etc/passwd").unwrap(), "passwd");
        assert_eq!(safe_file_name("/etc/shadow").unwrap(), "shadow");
        // Las tres formas de separar, porque el nombre lo pudo escribir
        // cualquier sistema.
        assert_eq!(
            safe_file_name(r"C:\Windows\system32\x.dll").unwrap(),
            "x.dll"
        );
        assert_eq!(
            safe_file_name("carpeta/informe.pdf").unwrap(),
            "informe.pdf"
        );
    }

    #[test]
    fn lo_que_no_deja_nada_utilizable_se_rechaza() {
        // Devolver `None` y no inventar un nombre: quien llama pone uno
        // genérico y queda claro que el mensaje venía raro.
        for bad in ["", "   ", "..", "../..", "/", "...", "\\", "./"] {
            assert!(safe_file_name(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn los_caracteres_de_control_se_van() {
        // Un salto de línea adentro parte cualquier cosa que después lo escriba.
        assert_eq!(safe_file_name("informe\n.pdf").unwrap(), "informe.pdf");
        assert_eq!(safe_file_name("a\u{0}b.txt").unwrap(), "ab.txt");
        assert!(safe_file_name("\u{7}").is_none());
    }

    /// No es nuestro sistema, pero el archivo termina en un pendrive o en un
    /// adjunto de vuelta, y un `CON.txt` rompe del otro lado.
    #[test]
    fn los_nombres_reservados_se_rechazan() {
        for reserved in ["CON", "con.txt", "PRN.pdf", "nul", "COM1.doc", "lpt9"] {
            assert!(safe_file_name(reserved).is_none(), "{reserved}");
        }
        // Y uno que sólo empieza igual, no.
        assert_eq!(safe_file_name("console.log").unwrap(), "console.log");
        assert_eq!(safe_file_name("contrato.pdf").unwrap(), "contrato.pdf");
    }

    #[test]
    fn un_nombre_larguisimo_se_recorta_sin_partir_un_caracter() {
        let length = "á".repeat(500) + ".pdf";
        let out = safe_file_name(&length).unwrap();
        assert_eq!(out.chars().count(), 200);
        // Y sigue siendo texto válido: recortar por bytes partiría una «á».
        assert!(out.chars().all(|c| c == 'á'));
    }

    #[test]
    fn el_caso_corriente_pasa_entero() {
        assert_eq!(
            parameter(r#"attachment; filename="informe final.pdf""#, "filename").unwrap(),
            "informe final.pdf"
        );
        // Y el punto y coma dentro de las comillas no parte el nombre.
        assert_eq!(
            parameter(r#"attachment; filename="a;b.txt""#, "filename").unwrap(),
            "a;b.txt"
        );
    }

    /// RFC 2231. Es el que el issue marcaba como no implementado.
    #[test]
    fn un_nombre_con_acentos_llega_entero() {
        assert_eq!(
            parameter("attachment; filename*=utf-8''%C3%A1rbol.pdf", "filename").unwrap(),
            "árbol.pdf"
        );
        // Sin la parte del juego: hay clientes que mandan el `*` pelado.
        assert_eq!(
            parameter("attachment; filename*=%C3%A1rbol.pdf", "filename").unwrap(),
            "árbol.pdf"
        );
        // Y en otro juego que no sea UTF-8.
        assert_eq!(
            parameter("attachment; filename*=iso-8859-1''%E1rbol.pdf", "filename").unwrap(),
            "árbol.pdf"
        );
    }

    #[test]
    fn un_nombre_partido_en_segmentos_se_junta_en_orden() {
        let header = "attachment; filename*0*=utf-8''informe%20; \
                        filename*1*=muy%20; filename*2*=largo.pdf";
        assert_eq!(
            parameter(header, "filename").unwrap(),
            "informe muy largo.pdf"
        );

        // Un segmento que falta corta el juntado: seguir después de un hueco
        // pegaría trozos que no van juntos.
        let with_gap = "attachment; filename*0*=utf-8''a; filename*2*=c";
        assert_eq!(parameter(with_gap, "filename").unwrap(), "a");
    }

    /// RFC 2047, que es lo que mandan los clientes viejos donde el estándar
    /// pedía la otra forma.
    #[test]
    fn un_nombre_en_palabras_codificadas_se_decodifica() {
        let header = "attachment; filename=\"=?utf-8?B?w6FyYm9sLnBkZg==?=\"";
        assert_eq!(parameter(header, "filename").unwrap(), "árbol.pdf");
    }

    /// Si están las dos formas, gana la extendida: la otra es la copia en ASCII
    /// que dejan algunos clientes para los que no la entienden.
    #[test]
    fn la_forma_extendida_le_gana_a_la_simple() {
        let header = "attachment; filename=\"arbol.pdf\"; filename*=utf-8''%C3%A1rbol.pdf";
        assert_eq!(parameter(header, "filename").unwrap(), "árbol.pdf");
    }

    #[test]
    fn un_parametro_que_no_esta_no_se_inventa() {
        assert!(parameter("attachment", "filename").is_none());
        assert!(parameter("", "filename").is_none());
        assert!(parameter("inline; size=42", "filename").is_none());
    }

    const WITH_TWO: &str = "Content-Type: multipart/mixed; boundary=xyz\r\n\
\r\n\
--xyz\r\n\
Content-Type: text/plain\r\n\
\r\n\
Hola\r\n\
--xyz\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"informe.pdf\"\r\n\
\r\n\
datos\r\n\
--xyz\r\n\
Content-Type: image/png\r\n\
Content-Disposition: attachment; filename=\"foto.png\"\r\n\
\r\n\
datos\r\n\
--xyz--\r\n";

    #[test]
    fn las_partes_se_numeran_como_las_pide_el_servidor() {
        let list = list(WITH_TWO.as_bytes());
        assert_eq!(list.len(), 2);
        // La primera parte es el texto; los adjuntos son la 2 y la 3.
        assert_eq!(list[0].part, "2");
        assert_eq!(list[0].name, "informe.pdf");
        assert_eq!(list[0].content_type, "application/pdf");
        assert_eq!(list[1].part, "3");
        assert_eq!(list[1].name, "foto.png");
    }

    #[test]
    fn una_parte_anidada_lleva_el_numero_de_su_padre() {
        let raw = "Content-Type: multipart/mixed; boundary=a\r\n\r\n\
--a\r\n\
Content-Type: multipart/alternative; boundary=b\r\n\r\n\
--b\r\n\
Content-Type: text/plain\r\n\r\n\
Hola\r\n\
--b\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"x.pdf\"\r\n\r\n\
datos\r\n\
--b--\r\n\
--a--\r\n";
        let list = list(raw.as_bytes());
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].part, "1.2");
    }

    #[test]
    fn un_mensaje_sin_adjuntos_no_devuelve_ninguno() {
        let raw = "Content-Type: text/plain\r\n\r\nHola\r\n";
        assert!(list(raw.as_bytes()).is_empty());
        assert!(list(b"").is_empty());
    }

    /// Dos adjuntos sin nombre no se pueden llamar igual: quien los guarde
    /// pisaría el primero con el segundo sin enterarse.
    #[test]
    fn dos_adjuntos_sin_nombre_no_chocan() {
        let raw = "Content-Type: multipart/mixed; boundary=z\r\n\r\n\
--z\r\n\
Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment\r\n\r\n\
uno\r\n\
--z\r\n\
Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment\r\n\r\n\
dos\r\n\
--z--\r\n";
        let list = list(raw.as_bytes());
        assert_eq!(list.len(), 2);
        assert_ne!(list[0].name, list[1].name);
    }

    /// El nombre del adjunto pasa por el saneador igual que cualquier otro: es
    /// el camino por el que llegaría un `../`.
    #[test]
    fn un_adjunto_con_nombre_hostil_llega_saneado() {
        let raw = "Content-Type: multipart/mixed; boundary=z\r\n\r\n\
--z\r\n\
Content-Type: application/pdf\r\n\
Content-Disposition: attachment; filename=\"../../../etc/passwd\"\r\n\r\n\
datos\r\n\
--z--\r\n";
        let list = list(raw.as_bytes());
        assert_eq!(list[0].name, "passwd");
        assert!(!list[0].name.contains('/'));
    }

    /// El nombre en el `Content-Type` es donde lo ponen los clientes viejos.
    #[test]
    fn si_no_hay_filename_se_mira_el_name() {
        let raw = "Content-Type: multipart/mixed; boundary=z\r\n\r\n\
--z\r\n\
Content-Type: application/pdf; name=\"viejo.pdf\"\r\n\
Content-Disposition: attachment\r\n\r\n\
datos\r\n\
--z--\r\n";
        assert_eq!(list(raw.as_bytes())[0].name, "viejo.pdf");
    }

    #[test]
    fn una_parte_en_base64_se_deshace() {
        let headers = b"Content-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n";
        assert_eq!(decode_part(headers, b"SGkgdGhlcmU="), b"Hi there");
    }

    #[test]
    fn una_parte_en_quoted_printable_se_deshace() {
        let headers = b"Content-Transfer-Encoding: quoted-printable\r\n";
        assert_eq!(decode_part(headers, b"reuni=C3=B3n"), "reunión".as_bytes());
    }

    /// `7bit`, `8bit` y `binary` quieren decir «no hay nada que deshacer», y una
    /// codificación que no existe es mejor guardarla cruda que dejar a la
    /// persona sin el archivo.
    #[test]
    fn lo_que_no_hay_que_deshacer_se_deja_igual() {
        for headers in [
            &b"Content-Transfer-Encoding: 7bit\r\n"[..],
            &b"Content-Transfer-Encoding: binary\r\n"[..],
            &b"Content-Transfer-Encoding: lo-que-sea\r\n"[..],
            &b"Content-Type: application/pdf\r\n"[..],
            &b""[..],
        ] {
            assert_eq!(decode_part(headers, b"crudo"), b"crudo");
        }
    }
}
