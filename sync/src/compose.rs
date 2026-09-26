//! Armar un mensaje para mandarlo.
//!
//! ── La parte peligrosa de este archivo ──────────────────────────────────────
//!
//! Un mensaje de correo son cabeceras, una línea vacía, y el cuerpo. El
//! separador entre una cabecera y la siguiente es un salto de línea, y **el
//! asunto lo escribe la persona**.
//!
//! Eso es todo lo que hace falta para la inyección de cabeceras, que es el
//! agujero clásico de cualquier cosa que arma correo: un asunto que contenga un
//! salto de línea y `Bcc: alguien@ajeno.com` manda una copia oculta que quien
//! escribió el mensaje no ve ni en su carpeta de enviados. Con
//! `Content-Type` sirve para hacer pasar el mensaje por otra cosa, y con dos
//! saltos seguidos se corta el bloque de cabeceras y se escribe el cuerpo entero.
//!
//! No hace falta que la persona sea la atacante: alcanza con que pegue un asunto
//! copiado de una página, o que la aplicación rellene el asunto de una respuesta
//! con el de un mensaje que mandó cualquiera. Por eso **nada que venga de afuera
//! se escribe crudo en una cabecera**: o se codifica, o se rechaza.
//!
//! ── Qué arma, y qué no ──────────────────────────────────────────────────────
//!
//! Un mensaje de texto plano, en UTF-8, con `quoted-printable`. Sin adjuntos,
//! sin HTML y sin firma: cada una de esas cosas es su propio trabajo, y las tres
//! agrandan lo que hay que cuidar acá.

use serde::{Deserialize, Serialize};

/// Tope de cada línea del cuerpo, en octetos.
///
/// El estándar prohíbe pasar de 998 sin contar el salto, y hay servidores que
/// cortan la conexión ante una línea más larga. 76 es lo que usa
/// `quoted-printable` desde siempre y lo que dejan los clientes que leen sin
/// reajustar el texto.
const QP_LINE_LENGTH: usize = 76;

/// Tope del cuerpo de un mensaje.
///
/// Un megabyte de texto son unas doscientas mil palabras. Lo que pase de ahí es
/// un archivo pegado en el cuerpo, que es justo lo que esta versión no hace.
const MAX_BODY: usize = 1024 * 1024;

/// Tope de una línea de cabecera, en octetos.
///
/// El estándar prohíbe pasar de 998 sin contar el salto. 78 es el tope
/// «recomendado», y es lo que usan los clientes: una cabecera más corta que eso
/// se ve entera en cualquier lado y ningún servidor la toca.
const HEADER_LINE_LENGTH: usize = 78;

/// Topes de lo que llega de afuera y termina en una cabecera.
///
/// Nada de esto lo escribe una persona: un asunto de mil caracteres es un
/// programa mal hecho o alguien probando, y una respuesta hereda el asunto de un
/// mensaje que mandó cualquiera. Sin tope, un asunto de un megabyte se convierte
/// en un `DATA` de un megabyte que el servidor rechaza **después** de recibirlo
/// entero — o sea, después de gastar la conexión de la persona.
///
/// Se rechaza en vez de recortar: recortar cambia en silencio lo que alguien
/// escribió, y estos tamaños no los alcanza nadie escribiendo.
const MAX_SUBJECT: usize = 512;
const MAX_NAME: usize = 128;
const MAX_MESSAGE_ID: usize = 512;
const MAX_REFERENCES: usize = 20;

/// Cuántos destinatarios se aceptan.
///
/// Cien es más de lo que nadie escribe a mano y menos de lo que un servidor
/// trata como envío masivo. Sin tope, un pegado desafortunado en el campo
/// «Para» puede hacer que el proveedor cierre la cuenta por spam.
const MAX_RECIPIENTS: usize = 100;

/// Lo que la persona escribió.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Draft {
    /// La dirección desde la que sale. Es la de la cuenta, no la elige la
    /// ventana: mandar desde una dirección que no es la de la cuenta que
    /// autentica hace que el servidor rechace, o peor, que el mensaje llegue y
    /// lo marquen como falsificado.
    #[serde(default, rename = "de")]
    pub from: String,
    #[serde(default, rename = "nombre")]
    pub name: String,
    #[serde(rename = "para")]
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default, rename = "asunto")]
    pub subject: String,
    #[serde(default, rename = "cuerpo")]
    pub body: String,
    /// El `Message-ID` del mensaje al que se responde, si es una respuesta.
    ///
    /// Es lo que hace que la respuesta quede enganchada a la conversación en el
    /// cliente de quien la recibe. Sin esto, una respuesta aparece como un
    /// mensaje suelto y la conversación se parte.
    #[serde(default, rename = "en_respuesta_a")]
    pub in_reply_to: String,
    /// La cadena de mensajes anteriores, del más viejo al más nuevo.
    #[serde(default, rename = "referencias")]
    pub references: Vec<String>,
    /// Los archivos que van pegados.
    ///
    /// Llegan **con su contenido** y no con una ruta. Es a propósito: este
    /// servicio corre como la persona y podría leer cualquier archivo suyo, así
    /// que aceptar una ruta de la ventana sería dejar que la ventana elija qué
    /// lee el servicio. Quien eligió el archivo es quien lo abre.
    #[serde(default, rename = "adjuntos")]
    pub attachments: Vec<Attachment>,
}

/// Un archivo para pegar a un mensaje.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Attachment {
    /// Cómo se va a llamar del otro lado.
    #[serde(rename = "nombre")]
    pub name: String,
    /// El tipo declarado. Vacío para que lo decida `content_type_for_name`.
    #[serde(default, rename = "tipo")]
    pub content_type: String,
    /// El contenido, en base64.
    ///
    /// Ya codificado porque así viaja por D-Bus sin que nadie tenga que
    /// inventar cómo mandar bytes crudos en una cadena, y porque es la forma en
    /// la que va a salir en el mensaje de todos modos.
    #[serde(rename = "contenido")]
    pub content: String,
}

impl Draft {
    /// Todos los que van a recibirlo.
    ///
    /// El `Cc` va en la cabecera *y* en los `RCPT TO`: la cabecera es lo que se
    /// muestra y los `RCPT TO` son a quién se le entrega. Poner sólo la cabecera
    /// es el error que hace que una copia nunca llegue.
    pub fn recipients(&self) -> Vec<String> {
        self.to.iter().chain(self.cc.iter()).cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Validación
// ---------------------------------------------------------------------------

/// Si una dirección se puede escribir en una cabecera sin romper nada.
///
/// No valida que exista ni que el buzón esté vivo —eso lo dice el servidor—:
/// valida que **no pueda salirse de su renglón**. Un salto de línea, un `<`, una
/// coma o un `;` en una dirección son o una inyección de cabecera o una lista
/// donde debería haber una sola dirección.
pub fn is_valid_address(address: &str) -> bool {
    let d = address.trim();
    if d.is_empty() || d.len() > 320 {
        return false;
    }
    // Nada de control, y nada que no sea ASCII: las direcciones internacionales
    // necesitan `SMTPUTF8`, que es su propio trabajo, y mandarlas sin negociarlo
    // hace que el servidor rechace el mensaje entero.
    if d.chars().any(|c| c.is_control() || !c.is_ascii()) {
        return false;
    }
    if d.chars().any(|c| " <>,;\"\\()[]".contains(c)) {
        return false;
    }

    // Exactamente una arroba, con algo de cada lado y un punto a la derecha.
    let Some((local, domain)) = d.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !d.contains("@@")
}

/// Revisa el borrador antes de encolarlo.
///
/// Acá y no al mandarlo: un mensaje que no se puede armar tiene que decirlo
/// **mientras la persona todavía lo tiene en pantalla**, no tres minutos después
/// desde una cola en la que ya no está mirando.
pub fn validate(draft: &Draft) -> Result<(), String> {
    if !is_valid_address(&draft.from) {
        return Err(format!("«{}» no es una dirección válida", draft.from));
    }
    if draft.to.is_empty() {
        return Err("hay que poner al menos un destinatario".into());
    }

    let recipients = draft.recipients();
    if recipients.len() > MAX_RECIPIENTS {
        return Err(format!(
            "son {} destinatarios y el tope es {MAX_RECIPIENTS}",
            recipients.len()
        ));
    }
    for address in &recipients {
        if !is_valid_address(address) {
            return Err(format!("«{address}» no es una dirección válida"));
        }
    }

    if draft.body.len() > MAX_BODY {
        return Err("el mensaje es demasiado largo".into());
    }

    // Lo que termina en una cabecera, con su tope. Ver el comentario de las
    // constantes: sin esto un asunto de un megabyte se convierte en un `DATA`
    // de un megabyte que el servidor rechaza después de recibirlo entero.
    for (what, length, limit) in [
        ("el asunto", draft.subject.len(), MAX_SUBJECT),
        ("el nombre del remitente", draft.name.len(), MAX_NAME),
        (
            "el identificador del mensaje al que responde",
            draft.in_reply_to.len(),
            MAX_MESSAGE_ID,
        ),
    ] {
        if length > limit {
            return Err(format!("{what} es demasiado largo ({length} de {limit})"));
        }
    }

    if draft.references.len() > MAX_REFERENCES {
        return Err(format!(
            "la conversación arrastra {} referencias y el tope es {MAX_REFERENCES}",
            draft.references.len()
        ));
    }
    if let Some(long_ref) = draft.references.iter().find(|r| r.len() > MAX_MESSAGE_ID) {
        return Err(format!(
            "una referencia es demasiado larga ({})",
            long_ref.len()
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Cabeceras
// ---------------------------------------------------------------------------

/// Deja un texto en condiciones de ir en una cabecera.
///
/// **Ésta es la función que impide la inyección.** Lo que pueda ir en ASCII
/// imprimible va tal cual, con los saltos de línea y los caracteres de control
/// **quitados**; lo demás va como palabra codificada, que por construcción no
/// puede contener ni un salto ni un dos puntos suelto.
///
/// Se quitan y no se rechazan porque un asunto con un salto de línea casi
/// siempre es un pegado de dos renglones, no un ataque: negarse a mandar el
/// mensaje sería castigar a la persona por algo que se arregla solo. Lo que no
/// puede pasar es que el salto llegue al mensaje.
pub fn safe_header(text: &str) -> String {
    // Los saltos, las tabulaciones y cualquier control se convierten en un
    // espacio antes de decidir nada más. Un `\r\n` acá es una cabecera nueva.
    //
    // Y los espacios seguidos se juntan en uno: un `\r\n` deja dos, y un asunto
    // pegado de dos renglones saldría con un hueco raro en el medio. No cambia
    // nada de lo que importa —el salto ya no está— pero se lee como lo que la
    // persona quiso escribir.
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    let cleaned = cleaned.trim();

    if cleaned.is_ascii() {
        return cleaned.to_string();
    }
    encode_word(cleaned)
}

/// Envuelve un texto como palabra codificada de RFC 2047.
///
/// En base64 y no en «Q»: con acentos en cada palabra —o sea, en español— el
/// resultado de «Q» es más largo y bastante ilegible, y base64 no tiene que
/// escapar nada.
///
/// Se parte en varias palabras porque una cabecera no puede pasar de 76 octetos
/// por renglón, y una palabra codificada **no se puede cortar en cualquier
/// lado**: cada trozo tiene que ser texto completo por sí mismo, o el que la
/// decodifica obtiene basura. Por eso se agrupa por caracteres y no por bytes.
pub fn encode_word(text: &str) -> String {
    use base64::Engine;

    // 45 caracteres por trozo: en el peor caso —cuatro octetos por carácter—
    // son 180 octetos, que en base64 dan 240, más de lo que entra. Se acumula
    // por bytes y se corta antes de pasarse, que es exacto en vez de estimado.
    const MAX_WORD_OCTETS: usize = 45;

    let mut chunks: Vec<String> = Vec::new();
    let mut current = String::new();

    for ch in text.chars() {
        if current.len() + ch.len_utf8() > MAX_WORD_OCTETS && !current.is_empty() {
            chunks.push(std::mem::take(&mut current));
        }
        current.push(ch);
    }
    if !current.is_empty() {
        chunks.push(current);
    }

    chunks
        .iter()
        .map(|t| {
            let encoded = base64::engine::general_purpose::STANDARD.encode(t.as_bytes());
            format!("=?UTF-8?B?{encoded}?=")
        })
        .collect::<Vec<_>>()
        // Un espacio y un salto entre palabras codificadas: el que decodifica
        // descarta ese espacio, así que el texto vuelve a quedar entero.
        .join("\r\n ")
}

/// Escribe una dirección con su nombre, si tiene.
///
/// El nombre va entre comillas y codificado; la dirección va cruda porque ya
/// pasó por `is_valid_address`, que garantiza que no tiene nada que pueda
/// salirse del renglón.
pub fn format_address(name: &str, address: &str) -> String {
    let name = safe_header(name);
    if name.is_empty() || name == address {
        return address.to_string();
    }
    // Sin comillas si ya viene codificado: una palabra codificada entre comillas
    // no se decodifica, y el destinatario ve el `=?UTF-8?B?…?=` en pantalla.
    if name.starts_with("=?") {
        return format!("{name} <{address}>");
    }
    // Se sacan las comillas —cerrarían la que abrimos y lo que siguiera quedaría
    // fuera del nombre— y también los `<` y `>`. Un nombre entre comillas puede
    // llevarlos según el estándar, pero deja la cabecera con dos direcciones a
    // la vista: `"Ana <otro@ajeno.com>" <ana@ejemplo.com>`. Los lectores
    // estrictos aciertan; los que buscan la última dirección también; los que
    // buscan la primera muestran la ajena. Un nombre con corchetes angulares no
    // es nunca legítimo, así que se van.
    let name = name.replace(['"', '\\', '<', '>'], "");
    format!("\"{name}\" <{address}>")
}

// ---------------------------------------------------------------------------
// El cuerpo
// ---------------------------------------------------------------------------

/// Codifica el cuerpo en `quoted-printable`.
///
/// Hace falta por dos cosas: los acentos no pueden viajar como bytes de ocho
/// bits sin que el servidor lo acepte explícitamente, y ninguna línea puede
/// pasar de los 998 octetos que fija el estándar. Un párrafo largo escrito de
/// un tirón los pasa sin que nadie lo note.
pub fn quoted_printable(text: &str) -> String {
    let mut out = String::new();

    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        let line = line.strip_suffix('\r').unwrap_or(line);
        out.push_str(&encode_qp_line(line));
    }

    out
}

fn encode_qp_line(line: &str) -> String {
    let mut out = String::new();
    let mut line_len = 0usize;

    let bytes = line.as_bytes();
    for (i, byte) in bytes.iter().enumerate() {
        // Un espacio o una tabulación **al final de la línea** hay que
        // codificarlos: si no, cualquier cosa en el camino puede recortarlos, y
        // el texto que llega no es el que se escribió.
        let at_end = i + 1 == bytes.len();
        let piece = match byte {
            b'=' => "=3D".to_string(),
            b' ' if at_end => "=20".to_string(),
            b'\t' if at_end => "=09".to_string(),
            0x20..=0x7E => (*byte as char).to_string(),
            other => format!("={other:02X}"),
        };

        // El corte blando: un `=` al final del renglón dice que la línea sigue.
        // Tiene que entrar el `=` también, así que el tope es uno menos.
        if line_len + piece.len() > QP_LINE_LENGTH - 1 {
            out.push_str("=\r\n");
            line_len = 0;
        }
        out.push_str(&piece);
        line_len += piece.len();
    }

    out
}

// ---------------------------------------------------------------------------
// El mensaje entero
// ---------------------------------------------------------------------------

/// Arma el mensaje listo para el `DATA` de SMTP.
///
/// `identificador` y `fecha` entran por argumento en vez de calcularse acá para
/// que el resultado se pueda probar entero: si leyera el reloj, el test tendría
/// que buscar partes sueltas en vez de comparar el mensaje completo.
pub fn build_message(draft: &Draft, message_id: &str, date: &str) -> Result<String, String> {
    validate(draft)?;

    let mut headers: Vec<String> = vec![
        format!("Date: {}", safe_header(date)),
        format!("From: {}", format_address(&draft.name, &draft.from)),
        fold_header("To", &draft.to, ","),
    ];

    if !draft.cc.is_empty() {
        headers.push(fold_header("Cc", &draft.cc, ","));
    }

    headers.push(format!("Subject: {}", safe_header(&draft.subject)));
    headers.push(format!("Message-ID: {}", safe_header(message_id)));

    // Las dos que enganchan la respuesta a su conversación. `References` es la
    // cadena entera y `In-Reply-To` el último: los clientes usan una o la otra
    // según cuál entiendan, así que van las dos o la conversación se parte en
    // alguno de ellos.
    if !draft.in_reply_to.is_empty() {
        headers.push(format!("In-Reply-To: {}", safe_header(&draft.in_reply_to)));
    }
    if !draft.references.is_empty() {
        // Sin separador: las referencias van una atrás de otra, separadas por el
        // espacio que ya pone el plegado.
        let chain: Vec<String> = draft.references.iter().map(|r| safe_header(r)).collect();
        headers.push(fold_header("References", &chain, ""));
    }

    headers.push("MIME-Version: 1.0".into());

    let text = quoted_printable(&draft.body);

    if draft.attachments.is_empty() {
        // Sin adjuntos, un mensaje de una sola parte. Envolverlo en un
        // `multipart` igual sería hacerle leer un árbol a quien recibe un
        // mensaje que es dos renglones de texto.
        headers.push("Content-Type: text/plain; charset=utf-8".into());
        headers.push("Content-Transfer-Encoding: quoted-printable".into());
        return Ok(format!("{}\r\n\r\n{}", headers.join("\r\n"), text));
    }

    // La frontera se calcula sobre **todo** lo que va adentro, incluido cada
    // adjunto: si apareciera dentro de una parte, quien lo lea cortaría ahí y el
    // mensaje llegaría partido en pedazos que no son los que se mandaron.
    let mut contents: Vec<&str> = vec![text.as_str()];
    contents.extend(draft.attachments.iter().map(|a| a.content.as_str()));
    let boundary = boundary(&contents);

    headers.push(format!(
        "Content-Type: multipart/mixed; boundary=\"{boundary}\""
    ));

    let mut body = String::new();
    // El texto primero. Es lo que muestran los clientes que no bajan el árbol
    // entero, y lo que alguien espera ver al abrir el mensaje.
    body.push_str(&format!("--{boundary}\r\n"));
    body.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    body.push_str("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
    body.push_str(&text);
    body.push_str("\r\n");

    for attachment in &draft.attachments {
        let content_type = if attachment.content_type.trim().is_empty() {
            content_type_for_name(&attachment.name)
        } else {
            attachment.content_type.trim()
        };
        body.push_str(&format!("--{boundary}\r\n"));
        // El nombre va en los dos lados: en el `Content-Type` para los clientes
        // viejos, y en el `Content-Disposition`, que es donde lo dice el
        // estándar. Es lo mismo que `attachments.rs` busca al leer.
        body.push_str(&format!(
            "Content-Type: {content_type}; {}\r\n",
            filename_param(&attachment.name).replace("filename", "name")
        ));
        body.push_str(&format!(
            "Content-Disposition: attachment; {}\r\n",
            filename_param(&attachment.name)
        ));
        body.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
        body.push_str(&wrap_base64(&attachment.content));
        body.push_str("\r\n");
    }

    body.push_str(&format!("--{boundary}--\r\n"));

    Ok(format!("{}\r\n\r\n{}", headers.join("\r\n"), body))
}

/// El tipo de un archivo, adivinado por su extensión.
///
/// **Conservador a propósito.** Ante la duda, `application/octet-stream`: un
/// tipo equivocado hace que el cliente de quien lo recibe intente abrirlo con lo
/// que no corresponde, y declarar `text/html` algo que no lo es es peor todavía.
/// La lista es corta y son los que de verdad aparecen pegados a un correo.
pub fn content_type_for_name(name: &str) -> &'static str {
    let extension = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();

    match extension.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "txt" | "log" | "md" => "text/plain",
        "csv" => "text/csv",
        "zip" => "application/zip",
        "odt" => "application/vnd.oasis.opendocument.text",
        "ods" => "application/vnd.oasis.opendocument.spreadsheet",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        _ => "application/octet-stream",
    }
}

/// Una frontera que **no aparece** en ninguna de las partes.
///
/// Es la condición que hace que un `multipart` se pueda volver a partir. Si la
/// frontera aparece dentro de un cuerpo, quien lo lea corta ahí: el mensaje
/// llega partido en pedazos que no son los que se mandaron, y el adjunto se
/// pierde o sale truncado.
///
/// Se arma con un número derivado del contenido y se alarga hasta que no
/// aparezca. El bucle termina siempre: cada vuelta agrega un carácter, y un
/// texto finito no puede contener cadenas arbitrariamente largas.
pub fn boundary(parts: &[&str]) -> String {
    // FNV-1a. No hace falta que sea impredecible —no es un secreto— sino que
    // dependa del contenido, para que dos mensajes no usen la misma.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x1000_0000_01b3);
        }
    }

    let mut candidate = format!("=_vasak_{hash:016x}");
    while parts.iter().any(|p| p.contains(&candidate)) {
        candidate.push('x');
    }
    candidate
}

/// El nombre de archivo para el `Content-Disposition`.
///
/// ASCII entre comillas cuando se puede; RFC 2231 cuando no, que es la forma
/// que el estándar pide para lo que no es ASCII y la que `message.rs` ya sabe
/// leer del otro lado.
///
/// Las comillas y las barras del nombre se escapan, y los saltos de línea se
/// sacan: un salto acá partiría la cabecera y lo que siguiera sería otra cosa.
pub fn filename_param(name: &str) -> String {
    let cleaned: String = name.chars().filter(|c| !c.is_control()).collect();

    if cleaned.is_ascii() {
        let escaped = cleaned.replace('\\', "\\\\").replace('"', "\\\"");
        return format!("filename=\"{escaped}\"");
    }

    let mut encoded = String::new();
    for byte in cleaned.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_') {
            encoded.push(*byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    format!("filename*=utf-8''{encoded}")
}

/// Parte el base64 en renglones de 76, que es lo que pide el estándar.
///
/// Una línea de un megabyte no la acepta ningún servidor: el límite del formato
/// es 998 octetos, y muchos cortan antes.
pub fn wrap_base64(base64: &str) -> String {
    base64
        .as_bytes()
        .chunks(76)
        .map(|t| String::from_utf8_lossy(t).into_owned())
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// Escribe una cabecera de varios valores, partida en renglones.
///
/// **Una cabecera de cien destinatarios no entra en una línea.** Cien
/// direcciones de hasta 320 octetos son treinta y dos mil, y el estándar corta
/// en 998: un servidor rechaza el mensaje, o peor, lo trunca y entrega una lista
/// de destinatarios distinta de la que la persona escribió.
///
/// Se parte poniendo un espacio al principio de cada renglón que sigue, que es
/// como el formato dice que continúa una cabecera. El que la lee vuelve a
/// juntarlas — es lo mismo que hace `message.rs` al leer.
/// `separador` es lo que va **pegado** al valor cuando no es el último: una coma
/// para una lista de direcciones, y nada para una cadena de referencias, donde
/// el espacio que ya pone el plegado alcanza. Pasar un espacio acá daría dos.
fn fold_header(header_name: &str, parts: &[String], separator: &str) -> String {
    let mut out = format!("{header_name}:");
    let mut line_len = out.len();

    for (i, part) in parts.iter().enumerate() {
        let last = i + 1 == parts.len();
        let piece = if last {
            part.trim().to_string()
        } else {
            format!("{}{separator}", part.trim())
        };

        // Un valor que solo ya no entra igual va en su propio renglón: partirlo
        // por la mitad lo rompería, y una dirección no se puede partir.
        if line_len + 1 + piece.len() > HEADER_LINE_LENGTH && line_len > 1 {
            out.push_str("\r\n ");
            line_len = 1;
        } else {
            out.push(' ');
            line_len += 1;
        }

        out.push_str(&piece);
        line_len += piece.len();
    }

    out
}

/// Un identificador único para el mensaje.
///
/// El dominio sale de la dirección de quien manda y no del nombre del equipo:
/// es lo que dice la convención, y además el nombre del equipo de alguien no
/// tiene por qué viajar en cada correo que manda.
pub fn message_id_for(from: &str, moment: chrono::DateTime<chrono::Utc>, unique: u64) -> String {
    let domain = from.split('@').nth(1).unwrap_or("localhost");
    format!("<{}.{unique:016x}@{domain}>", moment.timestamp_micros())
}

/// La fecha en el formato que espera una cabecera.
pub fn header_date(moment: chrono::DateTime<chrono::Local>) -> String {
    moment.to_rfc2822()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> Draft {
        Draft {
            from: "ana@ejemplo.com".into(),
            name: "Ana Pérez".into(),
            to: vec!["juan@otro.com".into()],
            subject: "Hola".into(),
            body: "Buenas.".into(),
            ..Default::default()
        }
    }

    // ── La inyección de cabeceras ──────────────────────────────────────────

    /// **El agujero clásico de cualquier cosa que arma correo.** Un asunto con
    /// un salto de línea y `Bcc:` manda una copia oculta que quien escribió el
    /// mensaje no ve ni en su carpeta de enviados.
    #[test]
    fn un_asunto_con_salto_de_linea_no_agrega_una_cabecera() {
        let mut b = draft();
        b.subject = "Hola\r\nBcc: espia@ajeno.com".into();

        let message = build_message(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();

        assert!(!has_header(&message, "bcc"), "{message}");
        // El texto no se pierde: se pega en el mismo renglón, que es donde no
        // hace nada. Y con un espacio y no con dos, que es lo que dejaría el
        // `\r\n` convertido carácter por carácter.
        assert!(
            message.contains("Subject: Hola Bcc: espia@ajeno.com"),
            "{message}"
        );
    }

    /// Con dos saltos seguidos se corta el bloque de cabeceras y lo que sigue es
    /// el cuerpo: así se reemplaza el mensaje entero.
    #[test]
    fn un_asunto_no_puede_cortar_el_bloque_de_cabeceras() {
        let mut b = draft();
        b.subject = "Hola\r\n\r\nEste es otro mensaje".into();

        let message = build_message(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        // Un solo bloque de cabeceras, o sea un solo `\r\n\r\n`.
        assert_eq!(message.matches("\r\n\r\n").count(), 1, "{message}");
    }

    /// Y con un `\n` solo, que es lo que sale de pegar texto de una página.
    #[test]
    fn un_salto_solo_tampoco_alcanza() {
        for poison in ["a\nBcc: x@y", "a\rBcc: x@y", "a\u{0}b", "a\u{b}b"] {
            let cleaned = safe_header(poison);
            assert!(!cleaned.contains('\n'), "{poison:?} -> {cleaned:?}");
            assert!(!cleaned.contains('\r'), "{poison:?} -> {cleaned:?}");
            assert!(
                !cleaned.chars().any(char::is_control),
                "{poison:?} -> {cleaned:?}"
            );
        }
    }

    /// El nombre del remitente pasa por el mismo filtro: también es una cabecera
    /// y también lo puede llenar cualquier cosa.
    #[test]
    fn el_nombre_del_remitente_tampoco_puede_inyectar() {
        let mut b = draft();
        b.name = "Ana\r\nBcc: espia@ajeno.com".into();

        let message = build_message(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        assert!(!has_header(&message, "bcc"), "{message}");
    }

    /// Si hay una cabecera con ese nombre.
    ///
    /// Por renglón y no por subcadena: que el **texto** «Bcc:» aparezca dentro
    /// de un asunto es inofensivo y es justamente el resultado correcto de
    /// haberlo neutralizado. Lo que no puede haber es un renglón que empiece
    /// así, que es lo que un servidor lee como cabecera.
    fn has_header(message: &str, name: &str) -> bool {
        let headers = message.split("\r\n\r\n").next().unwrap_or_default();
        headers
            .split("\r\n")
            .any(|l| l.to_ascii_lowercase().starts_with(&format!("{name}:")))
    }

    /// Un nombre con comillas cerraría la que abrimos y lo que sigue quedaría
    /// fuera del nombre.
    #[test]
    fn un_nombre_con_comillas_no_se_escapa_del_suyo() {
        let written = format_address("Ana\" <otro@ajeno.com> \"", "ana@ejemplo.com");
        assert_eq!(written.matches('<').count(), 1, "{written}");
        assert!(written.ends_with("<ana@ejemplo.com>"), "{written}");
    }

    // ── Direcciones ────────────────────────────────────────────────────────

    /// Lo que se valida no es que el buzón exista —eso lo dice el servidor—
    /// sino que la dirección **no pueda salirse de su renglón**.
    #[test]
    fn una_direccion_que_puede_inyectar_se_rechaza() {
        for bad in [
            "juan@otro.com\r\nBcc: x@y",
            "juan@otro.com\nX: y",
            "a b@otro.com",
            "<juan@otro.com>",
            "juan@otro.com, otro@x.com",
            "juan@otro.com; otro@x.com",
            "\"juan\"@otro.com",
        ] {
            assert!(!is_valid_address(bad), "{bad:?} tendría que rechazarse");
        }
    }

    #[test]
    fn una_direccion_mal_formada_se_rechaza() {
        for bad in [
            "",
            "  ",
            "juan",
            "@otro.com",
            "juan@",
            "juan@otro",
            "juan@@otro.com",
            "juan@.com",
            "juan@otro.",
        ] {
            assert!(!is_valid_address(bad), "{bad:?} tendría que rechazarse");
        }
    }

    /// Las direcciones con acentos necesitan `SMTPUTF8`, que hay que negociar
    /// con el servidor. Mandarlas sin eso hace que rechace el mensaje entero, y
    /// el error que devuelve no dice nada sobre la dirección.
    #[test]
    fn una_direccion_con_acentos_se_rechaza_por_ahora() {
        assert!(!is_valid_address("josé@ejemplo.com"));
    }

    #[test]
    fn una_direccion_normal_se_acepta() {
        for good in [
            "juan@otro.com",
            "juan.perez+etiqueta@sub.otro.com.ar",
            "j@x.co",
        ] {
            assert!(is_valid_address(good), "{good:?} tendría que aceptarse");
        }
    }

    /// Sin destinatarios no hay a quién mandarlo, y el servidor contestaría un
    /// error que no explica nada. Se dice mientras la persona lo tiene en
    /// pantalla.
    #[test]
    fn un_borrador_sin_destinatarios_no_se_arma() {
        let mut b = draft();
        b.to.clear();
        assert!(build_message(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").is_err());
    }

    /// Un pegado desafortunado en «Para» puede hacer que el proveedor cierre la
    /// cuenta por envío masivo.
    #[test]
    fn hay_un_tope_de_destinatarios() {
        let mut b = draft();
        b.to = (0..MAX_RECIPIENTS + 1)
            .map(|i| format!("x{i}@otro.com"))
            .collect();
        let error = build_message(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap_err();
        assert!(error.contains("tope"), "{error}");
    }

    /// El `Cc` va en la cabecera **y** en los destinatarios. Poner sólo la
    /// cabecera es el error que hace que la copia nunca llegue.
    #[test]
    fn el_cc_va_en_la_cabecera_y_en_la_entrega() {
        let mut b = draft();
        b.cc = vec!["copia@otro.com".into()];

        let message = build_message(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        assert!(message.contains("Cc: copia@otro.com"), "{message}");
        assert_eq!(b.recipients(), vec!["juan@otro.com", "copia@otro.com"]);
    }

    // ── Renglones ──────────────────────────────────────────────────────────

    /// **Cien destinatarios no entran en una línea.** Cien direcciones de hasta
    /// 320 octetos son treinta y dos mil, y el estándar corta en 998: un
    /// servidor rechaza el mensaje, o peor, lo trunca y entrega una lista de
    /// destinatarios distinta de la que la persona escribió.
    #[test]
    fn una_lista_larga_de_destinatarios_se_parte_en_renglones() {
        let mut b = draft();
        b.to = (0..60)
            .map(|i| format!("destinatario.numero{i}@ejemplo.com"))
            .collect();

        let message = build_message(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        for line in message.split("\r\n") {
            assert!(line.len() <= 998, "línea de {} octetos", line.len());
        }

        // Y se vuelve a juntar como una sola cabecera: los renglones que siguen
        // empiezan con un espacio, que es lo que el que lee reconoce.
        let headers = crate::message::Headers::parse(&message);
        let to = headers.get("to").unwrap();
        assert_eq!(to.matches('@').count(), 60, "se perdió algún destinatario");
        assert!(to.contains("destinatario.numero59@ejemplo.com"), "{to}");
    }

    /// Lo mismo con la cadena de la conversación, que llega de afuera.
    #[test]
    fn una_cadena_larga_de_referencias_se_parte() {
        let mut b = draft();
        b.references = (0..20)
            .map(|i| format!("<mensaje.numero{i}@ejemplo.com>"))
            .collect();

        let message = build_message(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        for line in message.split("\r\n") {
            assert!(line.len() <= 998, "línea de {} octetos", line.len());
        }
        let headers = crate::message::Headers::parse(&message);
        assert_eq!(headers.get("references").unwrap().matches('<').count(), 20);
    }

    /// Una dirección que sola no entra en el renglón recomendado va en el suyo:
    /// partirla la rompería.
    #[test]
    fn una_direccion_larga_no_se_parte_por_la_mitad() {
        let long_ref = format!("{}@ejemplo.com", "a".repeat(200));
        let folded = fold_header("To", std::slice::from_ref(&long_ref), ",");
        assert!(folded.contains(&long_ref), "{folded}");
    }

    // ── Lo que llega de afuera, con tope ───────────────────────────────────

    /// Nada de esto lo escribe una persona: una respuesta hereda el asunto de
    /// un mensaje que mandó cualquiera. Sin tope, un asunto de un megabyte se
    /// convierte en un `DATA` de un megabyte que el servidor rechaza
    /// **después** de recibirlo entero.
    #[test]
    fn una_cabecera_desmedida_se_rechaza_antes_de_gastar_la_conexion() {
        let mut b = draft();
        b.subject = "a".repeat(MAX_SUBJECT + 1);
        assert!(build_message(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").is_err());

        let mut b = draft();
        b.name = "a".repeat(MAX_NAME + 1);
        assert!(build_message(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").is_err());

        let mut b = draft();
        b.in_reply_to = format!("<{}@x>", "a".repeat(MAX_MESSAGE_ID));
        assert!(build_message(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").is_err());
    }

    /// La cadena de una conversación llega de afuera y no tiene por qué venir
    /// recortada: quien llama puede ser cualquier cosa en el bus de sesión.
    #[test]
    fn una_cadena_de_referencias_desmedida_se_rechaza() {
        let mut b = draft();
        b.references = (0..MAX_REFERENCES + 1)
            .map(|i| format!("<{i}@x>"))
            .collect();
        let error = build_message(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap_err();
        assert!(error.contains("referencias"), "{error}");
    }

    /// Y lo normal sigue pasando: los topes están para lo absurdo, no para
    /// molestar a nadie.
    #[test]
    fn un_asunto_normal_no_se_rechaza() {
        let mut b = draft();
        b.subject = "Re: ".to_string() + &"palabra ".repeat(30);
        assert!(build_message(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").is_ok());
    }

    // ── Cabeceras con acentos ──────────────────────────────────────────────

    /// Una cabecera sólo puede llevar ASCII. Sin codificar, el asunto llega roto
    /// o el servidor rechaza el mensaje.
    #[test]
    fn un_asunto_con_acentos_va_codificado() {
        let mut b = draft();
        b.subject = "Reunión de mañana".into();

        let message = build_message(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        assert!(message.contains("Subject: =?UTF-8?B?"), "{message}");
        assert!(
            message.is_ascii(),
            "quedó algo que no es ASCII en el mensaje"
        );
    }

    /// Y se puede volver a leer: lo que se codifica acá lo decodifica el módulo
    /// que lee mensajes, así que el viaje de ida y vuelta tiene que cerrar.
    #[test]
    fn lo_codificado_se_vuelve_a_leer_igual() {
        for original in [
            "Reunión de mañana",
            "Año nuevo, año viejo, y un asunto bastante largo para que tenga que partirse en varias palabras codificadas",
            "日本語の件名",
            "emoji 🎉 y acentos á",
        ] {
            let encoded = safe_header(original);
            // Desplegado como lo haría un cliente: las palabras van separadas
            // por un salto y un espacio.
            let unfolded = encoded.replace("\r\n ", " ");
            assert_eq!(
                crate::message::decode_words(&unfolded),
                original,
                "no cerró el viaje de ida y vuelta"
            );
        }
    }

    /// Ninguna línea de una cabecera puede pasar de 76 octetos.
    #[test]
    fn una_cabecera_larga_se_parte() {
        let length = "á".repeat(200);
        let encoded = safe_header(&length);
        for line in encoded.split("\r\n") {
            assert!(line.len() <= 76, "línea de {} octetos: {line}", line.len());
        }
    }

    /// Una palabra codificada entre comillas no se decodifica, y el
    /// destinatario ve el `=?UTF-8?B?…?=` en pantalla.
    #[test]
    fn un_nombre_codificado_no_va_entre_comillas() {
        let written = format_address("Ana Pérez", "ana@ejemplo.com");
        assert!(written.starts_with("=?UTF-8?B?"), "{written}");
        assert!(!written.contains('"'), "{written}");
    }

    // ── El cuerpo ──────────────────────────────────────────────────────────

    /// Ninguna línea puede pasar de los 998 octetos del estándar, y hay
    /// servidores que cortan la conexión ante una más larga. Un párrafo escrito
    /// de un tirón los pasa sin que nadie lo note.
    #[test]
    fn un_parrafo_largo_se_parte_en_lineas() {
        let paragraph = "palabra ".repeat(300);
        let encoded = quoted_printable(&paragraph);

        for line in encoded.split("\r\n") {
            assert!(line.len() <= 76, "línea de {} octetos", line.len());
        }
    }

    /// Y lo que se parte tiene que poder volver a juntarse: el corte blando es
    /// un `=` al final del renglón, y el que lee lo saca junto con el salto.
    #[test]
    fn el_cuerpo_codificado_se_vuelve_a_leer_igual() {
        for original in [
            "Buenas.",
            "Reunión el jueves, a las diez.\nSaludos,\nAna",
            &"palabra ".repeat(300),
            "línea con un = en el medio",
        ] {
            let encoded = quoted_printable(original);
            let round = crate::message::quoted_printable_decode(encoded.as_bytes(), false);
            let round = String::from_utf8_lossy(&round).replace("\r\n", "\n");
            assert_eq!(round, *original, "no cerró el viaje de ida y vuelta");
        }
    }

    /// Un espacio al final de la línea lo puede recortar cualquier cosa en el
    /// camino, y el texto que llega no es el que se escribió.
    #[test]
    fn un_espacio_al_final_de_la_linea_se_codifica() {
        let encoded = quoted_printable("hola \nchau");
        assert!(encoded.starts_with("hola=20"), "{encoded}");
    }

    #[test]
    fn el_igual_se_escapa() {
        assert_eq!(quoted_printable("2 = 2"), "2 =3D 2");
    }

    /// El cuerpo va en UTF-8 codificado, así que el mensaje entero es ASCII y
    /// no depende de que el servidor acepte ocho bits.
    #[test]
    fn el_mensaje_entero_es_ascii() {
        let mut b = draft();
        b.subject = "Reunión".into();
        b.body = "Nos vemos mañana, ¿te va?".into();

        let message = build_message(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        assert!(message.is_ascii(), "{message}");
    }

    // ── La estructura ──────────────────────────────────────────────────────

    /// Un mensaje son cabeceras, una línea vacía y el cuerpo. La línea vacía es
    /// lo único que los separa.
    #[test]
    fn el_mensaje_tiene_la_forma_que_espera_un_servidor() {
        let message = build_message(
            &draft(),
            "<abc@ejemplo.com>",
            "Thu, 10 Sep 2026 12:00:00 +0000",
        )
        .unwrap();

        let (headers, body) = message.split_once("\r\n\r\n").unwrap();
        assert!(headers.starts_with("Date: Thu, 10 Sep 2026"), "{headers}");
        assert!(headers.contains("\r\nTo: juan@otro.com"), "{headers}");
        assert!(
            headers.contains("\r\nMessage-ID: <abc@ejemplo.com>"),
            "{headers}"
        );
        assert!(headers.contains("\r\nMIME-Version: 1.0"), "{headers}");
        assert_eq!(body, "Buenas.");
    }

    /// Las dos cabeceras de conversación van juntas: los clientes usan una o la
    /// otra según cuál entiendan, y con una sola la conversación se parte en
    /// alguno de ellos.
    #[test]
    fn una_respuesta_queda_enganchada_a_su_conversacion() {
        let mut b = draft();
        b.in_reply_to = "<original@otro.com>".into();
        b.references = vec!["<primero@otro.com>".into(), "<original@otro.com>".into()];

        let message = build_message(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        assert!(
            message.contains("In-Reply-To: <original@otro.com>"),
            "{message}"
        );
        assert!(
            message.contains("References: <primero@otro.com> <original@otro.com>"),
            "{message}"
        );
    }

    /// Un mensaje que no es respuesta no lleva esas cabeceras: una `In-Reply-To`
    /// vacía engancha el mensaje a la nada y hay clientes que lo esconden.
    #[test]
    fn un_mensaje_nuevo_no_lleva_cabeceras_de_conversacion() {
        let message = build_message(&draft(), "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        assert!(!message.contains("In-Reply-To"), "{message}");
        assert!(!message.contains("References"), "{message}");
    }

    /// El dominio sale de la dirección de quien manda y no del nombre del
    /// equipo: el nombre del equipo de alguien no tiene por qué viajar en cada
    /// correo que manda.
    #[test]
    fn el_identificador_no_filtra_el_nombre_del_equipo() {
        let moment = chrono::DateTime::from_timestamp(1_757_500_000, 0).unwrap();
        let id = message_id_for("ana@ejemplo.com", moment, 42);

        assert!(id.ends_with("@ejemplo.com>"), "{id}");
        assert!(id.starts_with('<'), "{id}");
        // Y dos seguidos no son iguales, o dos mensajes del mismo segundo
        // compartirían identificador y algún cliente escondería uno.
        assert_ne!(id, message_id_for("ana@ejemplo.com", moment, 43));
    }

    fn with_attachment(name: &str, content: &str) -> Draft {
        Draft {
            from: "ana@ejemplo.com".into(),
            to: vec!["juan@otro.com".into()],
            subject: "Con algo pegado".into(),
            body: "Va el archivo.".into(),
            attachments: vec![Attachment {
                name: name.into(),
                content_type: String::new(),
                content: content.into(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn sin_adjuntos_sigue_siendo_de_una_sola_parte() {
        // Envolver en un `multipart` un mensaje que son dos renglones de texto
        // es hacerle leer un árbol a quien no lo necesita.
        let draft = Draft {
            from: "a@b.c".into(),
            to: vec!["d@e.f".into()],
            body: "Hola".into(),
            ..Default::default()
        };
        let built = build_message(&draft, "<x@b.c>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        assert!(built.contains("Content-Type: text/plain; charset=utf-8"));
        assert!(!built.contains("multipart"));
    }

    /// La vuelta completa: se arma el mensaje y se lo lee con el analizador del
    /// propio proyecto. Comprobar el texto a ojo diría que las cadenas están;
    /// esto dice que el mensaje **se puede volver a partir**.
    #[test]
    fn lo_armado_se_vuelve_a_leer_como_adjunto() {
        let built = build_message(
            &with_attachment("informe.pdf", "SGVsbG8gd29ybGQ="),
            "<x@b.c>",
            "Thu, 10 Sep 2026 12:00:00 +0000",
        )
        .unwrap();

        let listed = crate::attachments::list(built.as_bytes());
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "informe.pdf");
        assert_eq!(listed[0].content_type, "application/pdf");
        // La parte 1 es el texto, la 2 el adjunto.
        assert_eq!(listed[0].part, "2");

        // Y el texto sigue siendo legible.
        assert!(crate::message::plain_text(built.as_bytes()).contains("Va el archivo"));
    }

    /// Es la condición que hace que un `multipart` se pueda volver a partir. Si
    /// la frontera aparece dentro de una parte, quien lo lea corta ahí.
    #[test]
    fn la_frontera_nunca_aparece_en_las_partes() {
        let normal = boundary(&["hola", "chau"]);
        assert!(!normal.contains("hola"));

        // Un contenido que trae adentro la frontera que se le iba a poner.
        let computed = boundary(&["nada"]);
        let malicious = format!("texto --{computed} texto");
        let another = boundary(&[malicious.as_str()]);
        assert!(!malicious.contains(&another));
    }

    /// El bucle que alarga la frontera es una red por si acaso: para que haga
    /// falta, una parte tendría que contener la frontera derivada **de sí
    /// misma**, que es un punto fijo de la huella y no se construye a mano. Lo
    /// que sí se puede comprobar —y es lo que importa— es la invariante: salga
    /// lo que salga, no aparece en ninguna parte.
    #[test]
    fn la_invariante_vale_tambien_con_contenido_hostil() {
        let view = boundary(&[""]);
        let attempts = [
            format!("{view} y {view}x"),
            format!("--{view}--"),
            "=_vasak_0000000000000000".to_string(),
            "=_vasak_".repeat(50),
        ];
        for part in &attempts {
            let chosen = boundary(&[part.as_str()]);
            assert!(!part.contains(&chosen), "{part}");
        }
    }

    #[test]
    fn el_tipo_se_adivina_por_la_extension_y_ante_la_duda_es_octet_stream() {
        assert_eq!(content_type_for_name("informe.pdf"), "application/pdf");
        assert_eq!(content_type_for_name("FOTO.JPG"), "image/jpeg");
        assert_eq!(content_type_for_name("datos.csv"), "text/csv");
        // Ante la duda, el genérico: un tipo equivocado hace que el cliente de
        // quien lo recibe intente abrirlo con lo que no corresponde.
        assert_eq!(
            content_type_for_name("cosa.xyz"),
            "application/octet-stream"
        );
        assert_eq!(
            content_type_for_name("sinextension"),
            "application/octet-stream"
        );
        assert_eq!(content_type_for_name(""), "application/octet-stream");
    }

    #[test]
    fn un_tipo_declarado_le_gana_al_adivinado() {
        let mut draft = with_attachment("cosa.bin", "AAAA");
        draft.attachments[0].content_type = "image/png".into();
        let built = build_message(&draft, "<x@b.c>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        assert!(built.contains("Content-Type: image/png;"));
    }

    #[test]
    fn un_nombre_con_acentos_va_en_rfc_2231() {
        let built = build_message(
            &with_attachment("árbol.pdf", "AAAA"),
            "<x@b.c>",
            "Thu, 10 Sep 2026 12:00:00 +0000",
        )
        .unwrap();
        assert!(built.contains("filename*=utf-8''%C3%A1rbol.pdf"), "{built}");

        // Y del otro lado se vuelve a leer entero.
        assert_eq!(
            crate::attachments::list(built.as_bytes())[0].name,
            "árbol.pdf"
        );
    }

    /// Un salto de línea en el nombre partiría la cabecera, y lo que siguiera
    /// sería una cabecera que nadie escribió.
    ///
    /// Lo que se comprueba no es que el texto no esté —queda adentro del nombre,
    /// entre comillas, que es inofensivo— sino que **no empiece un renglón**,
    /// que es lo que lo convertiría en una cabecera.
    #[test]
    fn un_nombre_con_saltos_no_parte_la_cabecera() {
        let built = build_message(
            &with_attachment("uno\r\nContent-Type: text/html", "AAAA"),
            "<x@b.c>",
            "Thu, 10 Sep 2026 12:00:00 +0000",
        )
        .unwrap();

        for row in built.split("\r\n") {
            assert!(
                !row.starts_with("Content-Type: text/html"),
                "el nombre se convirtió en cabecera: {built}"
            );
        }

        // Y el adjunto se sigue leyendo, con el nombre ya sin los saltos.
        let listed = crate::attachments::list(built.as_bytes());
        assert_eq!(listed.len(), 1);
        assert!(!listed[0].name.contains('\n'));
    }

    #[test]
    fn las_comillas_del_nombre_se_escapan() {
        assert_eq!(
            filename_param(r#"el "bueno".pdf"#),
            r#"filename="el \"bueno\".pdf""#
        );
    }

    /// Una línea de un megabyte no la acepta ningún servidor: el límite del
    /// formato son 998 octetos.
    #[test]
    fn el_base64_sale_en_renglones_cortos() {
        let length = "A".repeat(500);
        for line in wrap_base64(&length).split("\r\n") {
            assert!(line.len() <= 76, "renglón de {}", line.len());
        }
        // Y no se pierde nada.
        assert_eq!(wrap_base64(&length).replace("\r\n", ""), length);
    }

    #[test]
    fn varios_adjuntos_van_cada_uno_en_su_parte() {
        let mut draft = with_attachment("uno.pdf", "AAAA");
        draft.attachments.push(Attachment {
            name: "dos.png".into(),
            content_type: String::new(),
            content: "BBBB".into(),
        });
        let built = build_message(&draft, "<x@b.c>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();

        let listed = crate::attachments::list(built.as_bytes());
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].part, "2");
        assert_eq!(listed[1].part, "3");
        assert_eq!(listed[1].content_type, "image/png");
    }
}
