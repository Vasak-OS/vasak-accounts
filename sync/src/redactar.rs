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
const LARGO_DE_LINEA: usize = 76;

/// Tope del cuerpo de un mensaje.
///
/// Un megabyte de texto son unas doscientas mil palabras. Lo que pase de ahí es
/// un archivo pegado en el cuerpo, que es justo lo que esta versión no hace.
const MAX_CUERPO: usize = 1024 * 1024;

/// Tope de una línea de cabecera, en octetos.
///
/// El estándar prohíbe pasar de 998 sin contar el salto. 78 es el tope
/// «recomendado», y es lo que usan los clientes: una cabecera más corta que eso
/// se ve entera en cualquier lado y ningún servidor la toca.
const LARGO_DE_CABECERA: usize = 78;

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
const MAX_ASUNTO: usize = 512;
const MAX_NOMBRE: usize = 128;
const MAX_IDENTIFICADOR: usize = 512;
const MAX_REFERENCIAS: usize = 20;

/// Cuántos destinatarios se aceptan.
///
/// Cien es más de lo que nadie escribe a mano y menos de lo que un servidor
/// trata como envío masivo. Sin tope, un pegado desafortunado en el campo
/// «Para» puede hacer que el proveedor cierre la cuenta por spam.
const MAX_DESTINATARIOS: usize = 100;

/// Lo que la persona escribió.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Borrador {
    /// La dirección desde la que sale. Es la de la cuenta, no la elige la
    /// ventana: mandar desde una dirección que no es la de la cuenta que
    /// autentica hace que el servidor rechace, o peor, que el mensaje llegue y
    /// lo marquen como falsificado.
    #[serde(default)]
    pub de: String,
    #[serde(default)]
    pub nombre: String,
    pub para: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub asunto: String,
    #[serde(default)]
    pub cuerpo: String,
    /// El `Message-ID` del mensaje al que se responde, si es una respuesta.
    ///
    /// Es lo que hace que la respuesta quede enganchada a la conversación en el
    /// cliente de quien la recibe. Sin esto, una respuesta aparece como un
    /// mensaje suelto y la conversación se parte.
    #[serde(default)]
    pub en_respuesta_a: String,
    /// La cadena de mensajes anteriores, del más viejo al más nuevo.
    #[serde(default)]
    pub referencias: Vec<String>,
    /// Los archivos que van pegados.
    ///
    /// Llegan **con su contenido** y no con una ruta. Es a propósito: este
    /// servicio corre como la persona y podría leer cualquier archivo suyo, así
    /// que aceptar una ruta de la ventana sería dejar que la ventana elija qué
    /// lee el servicio. Quien eligió el archivo es quien lo abre.
    #[serde(default)]
    pub adjuntos: Vec<Adjunto>,
}

/// Un archivo para pegar a un mensaje.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Adjunto {
    /// Cómo se va a llamar del otro lado.
    pub nombre: String,
    /// El tipo declarado. Vacío para que lo decida `tipo_por_nombre`.
    #[serde(default)]
    pub tipo: String,
    /// El contenido, en base64.
    ///
    /// Ya codificado porque así viaja por D-Bus sin que nadie tenga que
    /// inventar cómo mandar bytes crudos en una cadena, y porque es la forma en
    /// la que va a salir en el mensaje de todos modos.
    pub contenido: String,
}

impl Borrador {
    /// Todos los que van a recibirlo.
    ///
    /// El `Cc` va en la cabecera *y* en los `RCPT TO`: la cabecera es lo que se
    /// muestra y los `RCPT TO` son a quién se le entrega. Poner sólo la cabecera
    /// es el error que hace que una copia nunca llegue.
    pub fn destinatarios(&self) -> Vec<String> {
        self.para.iter().chain(self.cc.iter()).cloned().collect()
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
pub fn direccion_valida(direccion: &str) -> bool {
    let d = direccion.trim();
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
    let Some((local, dominio)) = d.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !dominio.is_empty()
        && dominio.contains('.')
        && !dominio.starts_with('.')
        && !dominio.ends_with('.')
        && !d.contains("@@")
}

/// Revisa el borrador antes de encolarlo.
///
/// Acá y no al mandarlo: un mensaje que no se puede armar tiene que decirlo
/// **mientras la persona todavía lo tiene en pantalla**, no tres minutos después
/// desde una cola en la que ya no está mirando.
pub fn revisar(borrador: &Borrador) -> Result<(), String> {
    if !direccion_valida(&borrador.de) {
        return Err(format!("«{}» no es una dirección válida", borrador.de));
    }
    if borrador.para.is_empty() {
        return Err("hay que poner al menos un destinatario".into());
    }

    let destinatarios = borrador.destinatarios();
    if destinatarios.len() > MAX_DESTINATARIOS {
        return Err(format!(
            "son {} destinatarios y el tope es {MAX_DESTINATARIOS}",
            destinatarios.len()
        ));
    }
    for direccion in &destinatarios {
        if !direccion_valida(direccion) {
            return Err(format!("«{direccion}» no es una dirección válida"));
        }
    }

    if borrador.cuerpo.len() > MAX_CUERPO {
        return Err("el mensaje es demasiado largo".into());
    }

    // Lo que termina en una cabecera, con su tope. Ver el comentario de las
    // constantes: sin esto un asunto de un megabyte se convierte en un `DATA`
    // de un megabyte que el servidor rechaza después de recibirlo entero.
    for (que, largo, tope) in [
        ("el asunto", borrador.asunto.len(), MAX_ASUNTO),
        ("el nombre del remitente", borrador.nombre.len(), MAX_NOMBRE),
        (
            "el identificador del mensaje al que responde",
            borrador.en_respuesta_a.len(),
            MAX_IDENTIFICADOR,
        ),
    ] {
        if largo > tope {
            return Err(format!("{que} es demasiado largo ({largo} de {tope})"));
        }
    }

    if borrador.referencias.len() > MAX_REFERENCIAS {
        return Err(format!(
            "la conversación arrastra {} referencias y el tope es {MAX_REFERENCIAS}",
            borrador.referencias.len()
        ));
    }
    if let Some(larga) = borrador.referencias.iter().find(|r| r.len() > MAX_IDENTIFICADOR) {
        return Err(format!("una referencia es demasiado larga ({})", larga.len()));
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
pub fn cabecera_segura(texto: &str) -> String {
    // Los saltos, las tabulaciones y cualquier control se convierten en un
    // espacio antes de decidir nada más. Un `\r\n` acá es una cabecera nueva.
    //
    // Y los espacios seguidos se juntan en uno: un `\r\n` deja dos, y un asunto
    // pegado de dos renglones saldría con un hueco raro en el medio. No cambia
    // nada de lo que importa —el salto ya no está— pero se lee como lo que la
    // persona quiso escribir.
    let limpio: String = texto
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let limpio = limpio.split_whitespace().collect::<Vec<_>>().join(" ");
    let limpio = limpio.trim();

    if limpio.is_ascii() {
        return limpio.to_string();
    }
    codificar_palabra(limpio)
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
pub fn codificar_palabra(texto: &str) -> String {
    use base64::Engine;

    // 45 caracteres por trozo: en el peor caso —cuatro octetos por carácter—
    // son 180 octetos, que en base64 dan 240, más de lo que entra. Se acumula
    // por bytes y se corta antes de pasarse, que es exacto en vez de estimado.
    const MAX_OCTETOS: usize = 45;

    let mut trozos: Vec<String> = Vec::new();
    let mut actual = String::new();

    for caracter in texto.chars() {
        if actual.len() + caracter.len_utf8() > MAX_OCTETOS && !actual.is_empty() {
            trozos.push(std::mem::take(&mut actual));
        }
        actual.push(caracter);
    }
    if !actual.is_empty() {
        trozos.push(actual);
    }

    trozos
        .iter()
        .map(|t| {
            let codificado = base64::engine::general_purpose::STANDARD.encode(t.as_bytes());
            format!("=?UTF-8?B?{codificado}?=")
        })
        .collect::<Vec<_>>()
        // Un espacio y un salto entre palabras codificadas: el que decodifica
        // descarta ese espacio, así que el texto vuelve a quedar entero.
        .join("\r\n ")
}

/// Escribe una dirección con su nombre, si tiene.
///
/// El nombre va entre comillas y codificado; la dirección va cruda porque ya
/// pasó por `direccion_valida`, que garantiza que no tiene nada que pueda
/// salirse del renglón.
pub fn buzon(nombre: &str, direccion: &str) -> String {
    let nombre = cabecera_segura(nombre);
    if nombre.is_empty() || nombre == direccion {
        return direccion.to_string();
    }
    // Sin comillas si ya viene codificado: una palabra codificada entre comillas
    // no se decodifica, y el destinatario ve el `=?UTF-8?B?…?=` en pantalla.
    if nombre.starts_with("=?") {
        return format!("{nombre} <{direccion}>");
    }
    // Se sacan las comillas —cerrarían la que abrimos y lo que siguiera quedaría
    // fuera del nombre— y también los `<` y `>`. Un nombre entre comillas puede
    // llevarlos según el estándar, pero deja la cabecera con dos direcciones a
    // la vista: `"Ana <otro@ajeno.com>" <ana@ejemplo.com>`. Los lectores
    // estrictos aciertan; los que buscan la última dirección también; los que
    // buscan la primera muestran la ajena. Un nombre con corchetes angulares no
    // es nunca legítimo, así que se van.
    let nombre = nombre.replace(['"', '\\', '<', '>'], "");
    format!("\"{nombre}\" <{direccion}>")
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
pub fn quoted_printable(texto: &str) -> String {
    let mut salida = String::new();

    for (i, linea) in texto.split('\n').enumerate() {
        if i > 0 {
            salida.push_str("\r\n");
        }
        let linea = linea.strip_suffix('\r').unwrap_or(linea);
        salida.push_str(&codificar_linea(linea));
    }

    salida
}

fn codificar_linea(linea: &str) -> String {
    let mut salida = String::new();
    let mut en_la_linea = 0usize;

    let bytes = linea.as_bytes();
    for (i, byte) in bytes.iter().enumerate() {
        // Un espacio o una tabulación **al final de la línea** hay que
        // codificarlos: si no, cualquier cosa en el camino puede recortarlos, y
        // el texto que llega no es el que se escribió.
        let al_final = i + 1 == bytes.len();
        let pieza = match byte {
            b'=' => "=3D".to_string(),
            b' ' if al_final => "=20".to_string(),
            b'\t' if al_final => "=09".to_string(),
            0x20..=0x7E => (*byte as char).to_string(),
            otro => format!("={otro:02X}"),
        };

        // El corte blando: un `=` al final del renglón dice que la línea sigue.
        // Tiene que entrar el `=` también, así que el tope es uno menos.
        if en_la_linea + pieza.len() > LARGO_DE_LINEA - 1 {
            salida.push_str("=\r\n");
            en_la_linea = 0;
        }
        salida.push_str(&pieza);
        en_la_linea += pieza.len();
    }

    salida
}

// ---------------------------------------------------------------------------
// El mensaje entero
// ---------------------------------------------------------------------------

/// Arma el mensaje listo para el `DATA` de SMTP.
///
/// `identificador` y `fecha` entran por argumento en vez de calcularse acá para
/// que el resultado se pueda probar entero: si leyera el reloj, el test tendría
/// que buscar partes sueltas en vez de comparar el mensaje completo.
pub fn armar(borrador: &Borrador, identificador: &str, fecha: &str) -> Result<String, String> {
    revisar(borrador)?;

    let mut cabeceras: Vec<String> = vec![
        format!("Date: {}", cabecera_segura(fecha)),
        format!("From: {}", buzon(&borrador.nombre, &borrador.de)),
        plegada("To", &borrador.para, ","),
    ];

    if !borrador.cc.is_empty() {
        cabeceras.push(plegada("Cc", &borrador.cc, ","));
    }

    cabeceras.push(format!("Subject: {}", cabecera_segura(&borrador.asunto)));
    cabeceras.push(format!("Message-ID: {}", cabecera_segura(identificador)));

    // Las dos que enganchan la respuesta a su conversación. `References` es la
    // cadena entera y `In-Reply-To` el último: los clientes usan una o la otra
    // según cuál entiendan, así que van las dos o la conversación se parte en
    // alguno de ellos.
    if !borrador.en_respuesta_a.is_empty() {
        cabeceras.push(format!(
            "In-Reply-To: {}",
            cabecera_segura(&borrador.en_respuesta_a)
        ));
    }
    if !borrador.referencias.is_empty() {
        // Sin separador: las referencias van una atrás de otra, separadas por el
        // espacio que ya pone el plegado.
        let cadena: Vec<String> = borrador.referencias.iter().map(|r| cabecera_segura(r)).collect();
        cabeceras.push(plegada("References", &cadena, ""));
    }

    cabeceras.push("MIME-Version: 1.0".into());

    let texto = quoted_printable(&borrador.cuerpo);

    if borrador.adjuntos.is_empty() {
        // Sin adjuntos, un mensaje de una sola parte. Envolverlo en un
        // `multipart` igual sería hacerle leer un árbol a quien recibe un
        // mensaje que es dos renglones de texto.
        cabeceras.push("Content-Type: text/plain; charset=utf-8".into());
        cabeceras.push("Content-Transfer-Encoding: quoted-printable".into());
        return Ok(format!("{}\r\n\r\n{}", cabeceras.join("\r\n"), texto));
    }

    // La frontera se calcula sobre **todo** lo que va adentro, incluido cada
    // adjunto: si apareciera dentro de una parte, quien lo lea cortaría ahí y el
    // mensaje llegaría partido en pedazos que no son los que se mandaron.
    let mut contenidos: Vec<&str> = vec![texto.as_str()];
    contenidos.extend(borrador.adjuntos.iter().map(|a| a.contenido.as_str()));
    let frontera = frontera(&contenidos);

    cabeceras.push(format!(
        "Content-Type: multipart/mixed; boundary=\"{frontera}\""
    ));

    let mut cuerpo = String::new();
    // El texto primero. Es lo que muestran los clientes que no bajan el árbol
    // entero, y lo que alguien espera ver al abrir el mensaje.
    cuerpo.push_str(&format!("--{frontera}\r\n"));
    cuerpo.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    cuerpo.push_str("Content-Transfer-Encoding: quoted-printable\r\n\r\n");
    cuerpo.push_str(&texto);
    cuerpo.push_str("\r\n");

    for adjunto in &borrador.adjuntos {
        let tipo = if adjunto.tipo.trim().is_empty() {
            tipo_por_nombre(&adjunto.nombre)
        } else {
            adjunto.tipo.trim()
        };
        cuerpo.push_str(&format!("--{frontera}\r\n"));
        // El nombre va en los dos lados: en el `Content-Type` para los clientes
        // viejos, y en el `Content-Disposition`, que es donde lo dice el
        // estándar. Es lo mismo que `adjuntos.rs` busca al leer.
        cuerpo.push_str(&format!(
            "Content-Type: {tipo}; {}\r\n",
            nombre_de_archivo(&adjunto.nombre).replace("filename", "name")
        ));
        cuerpo.push_str(&format!(
            "Content-Disposition: attachment; {}\r\n",
            nombre_de_archivo(&adjunto.nombre)
        ));
        cuerpo.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
        cuerpo.push_str(&en_renglones(&adjunto.contenido));
        cuerpo.push_str("\r\n");
    }

    cuerpo.push_str(&format!("--{frontera}--\r\n"));

    Ok(format!("{}\r\n\r\n{}", cabeceras.join("\r\n"), cuerpo))
}

/// El tipo de un archivo, adivinado por su extensión.
///
/// **Conservador a propósito.** Ante la duda, `application/octet-stream`: un
/// tipo equivocado hace que el cliente de quien lo recibe intente abrirlo con lo
/// que no corresponde, y declarar `text/html` algo que no lo es es peor todavía.
/// La lista es corta y son los que de verdad aparecen pegados a un correo.
pub fn tipo_por_nombre(nombre: &str) -> &'static str {
    let extension = nombre
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
pub fn frontera(partes: &[&str]) -> String {
    // FNV-1a. No hace falta que sea impredecible —no es un secreto— sino que
    // dependa del contenido, para que dos mensajes no usen la misma.
    let mut huella: u64 = 0xcbf2_9ce4_8422_2325;
    for parte in partes {
        for byte in parte.as_bytes() {
            huella ^= u64::from(*byte);
            huella = huella.wrapping_mul(0x1000_0000_01b3);
        }
    }

    let mut candidata = format!("=_vasak_{huella:016x}");
    while partes.iter().any(|p| p.contains(&candidata)) {
        candidata.push('x');
    }
    candidata
}

/// El nombre de archivo para el `Content-Disposition`.
///
/// ASCII entre comillas cuando se puede; RFC 2231 cuando no, que es la forma
/// que el estándar pide para lo que no es ASCII y la que `mensaje.rs` ya sabe
/// leer del otro lado.
///
/// Las comillas y las barras del nombre se escapan, y los saltos de línea se
/// sacan: un salto acá partiría la cabecera y lo que siguiera sería otra cosa.
pub fn nombre_de_archivo(nombre: &str) -> String {
    let limpio: String = nombre.chars().filter(|c| !c.is_control()).collect();

    if limpio.is_ascii() {
        let escapado = limpio.replace('\\', "\\\\").replace('"', "\\\"");
        return format!("filename=\"{escapado}\"");
    }

    let mut codificado = String::new();
    for byte in limpio.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_') {
            codificado.push(*byte as char);
        } else {
            codificado.push_str(&format!("%{byte:02X}"));
        }
    }
    format!("filename*=utf-8''{codificado}")
}

/// Parte el base64 en renglones de 76, que es lo que pide el estándar.
///
/// Una línea de un megabyte no la acepta ningún servidor: el límite del formato
/// es 998 octetos, y muchos cortan antes.
pub fn en_renglones(base64: &str) -> String {
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
/// juntarlas — es lo mismo que hace `mensaje.rs` al leer.
/// `separador` es lo que va **pegado** al valor cuando no es el último: una coma
/// para una lista de direcciones, y nada para una cadena de referencias, donde
/// el espacio que ya pone el plegado alcanza. Pasar un espacio acá daría dos.
fn plegada(etiqueta: &str, partes: &[String], separador: &str) -> String {
    let mut salida = format!("{etiqueta}:");
    let mut en_la_linea = salida.len();

    for (i, parte) in partes.iter().enumerate() {
        let ultima = i + 1 == partes.len();
        let pieza = if ultima {
            parte.trim().to_string()
        } else {
            format!("{}{separador}", parte.trim())
        };

        // Un valor que solo ya no entra igual va en su propio renglón: partirlo
        // por la mitad lo rompería, y una dirección no se puede partir.
        if en_la_linea + 1 + pieza.len() > LARGO_DE_CABECERA && en_la_linea > 1 {
            salida.push_str("\r\n ");
            en_la_linea = 1;
        } else {
            salida.push(' ');
            en_la_linea += 1;
        }

        salida.push_str(&pieza);
        en_la_linea += pieza.len();
    }

    salida
}

/// Un identificador único para el mensaje.
///
/// El dominio sale de la dirección de quien manda y no del nombre del equipo:
/// es lo que dice la convención, y además el nombre del equipo de alguien no
/// tiene por qué viajar en cada correo que manda.
pub fn identificador(de: &str, momento: chrono::DateTime<chrono::Utc>, unico: u64) -> String {
    let dominio = de.split('@').nth(1).unwrap_or("localhost");
    format!("<{}.{unico:016x}@{dominio}>", momento.timestamp_micros())
}

/// La fecha en el formato que espera una cabecera.
pub fn fecha_de_cabecera(momento: chrono::DateTime<chrono::Local>) -> String {
    momento.to_rfc2822()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn borrador() -> Borrador {
        Borrador {
            de: "ana@ejemplo.com".into(),
            nombre: "Ana Pérez".into(),
            para: vec!["juan@otro.com".into()],
            asunto: "Hola".into(),
            cuerpo: "Buenas.".into(),
            ..Default::default()
        }
    }

    // ── La inyección de cabeceras ──────────────────────────────────────────

    /// **El agujero clásico de cualquier cosa que arma correo.** Un asunto con
    /// un salto de línea y `Bcc:` manda una copia oculta que quien escribió el
    /// mensaje no ve ni en su carpeta de enviados.
    #[test]
    fn un_asunto_con_salto_de_linea_no_agrega_una_cabecera() {
        let mut b = borrador();
        b.asunto = "Hola\r\nBcc: espia@ajeno.com".into();

        let mensaje = armar(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();

        assert!(!hay_cabecera(&mensaje, "bcc"), "{mensaje}");
        // El texto no se pierde: se pega en el mismo renglón, que es donde no
        // hace nada. Y con un espacio y no con dos, que es lo que dejaría el
        // `\r\n` convertido carácter por carácter.
        assert!(mensaje.contains("Subject: Hola Bcc: espia@ajeno.com"), "{mensaje}");
    }

    /// Con dos saltos seguidos se corta el bloque de cabeceras y lo que sigue es
    /// el cuerpo: así se reemplaza el mensaje entero.
    #[test]
    fn un_asunto_no_puede_cortar_el_bloque_de_cabeceras() {
        let mut b = borrador();
        b.asunto = "Hola\r\n\r\nEste es otro mensaje".into();

        let mensaje = armar(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        // Un solo bloque de cabeceras, o sea un solo `\r\n\r\n`.
        assert_eq!(mensaje.matches("\r\n\r\n").count(), 1, "{mensaje}");
    }

    /// Y con un `\n` solo, que es lo que sale de pegar texto de una página.
    #[test]
    fn un_salto_solo_tampoco_alcanza() {
        for veneno in ["a\nBcc: x@y", "a\rBcc: x@y", "a\u{0}b", "a\u{b}b"] {
            let limpio = cabecera_segura(veneno);
            assert!(!limpio.contains('\n'), "{veneno:?} -> {limpio:?}");
            assert!(!limpio.contains('\r'), "{veneno:?} -> {limpio:?}");
            assert!(!limpio.chars().any(char::is_control), "{veneno:?} -> {limpio:?}");
        }
    }

    /// El nombre del remitente pasa por el mismo filtro: también es una cabecera
    /// y también lo puede llenar cualquier cosa.
    #[test]
    fn el_nombre_del_remitente_tampoco_puede_inyectar() {
        let mut b = borrador();
        b.nombre = "Ana\r\nBcc: espia@ajeno.com".into();

        let mensaje = armar(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        assert!(!hay_cabecera(&mensaje, "bcc"), "{mensaje}");
    }

    /// Si hay una cabecera con ese nombre.
    ///
    /// Por renglón y no por subcadena: que el **texto** «Bcc:» aparezca dentro
    /// de un asunto es inofensivo y es justamente el resultado correcto de
    /// haberlo neutralizado. Lo que no puede haber es un renglón que empiece
    /// así, que es lo que un servidor lee como cabecera.
    fn hay_cabecera(mensaje: &str, nombre: &str) -> bool {
        let cabeceras = mensaje.split("\r\n\r\n").next().unwrap_or_default();
        cabeceras
            .split("\r\n")
            .any(|l| l.to_ascii_lowercase().starts_with(&format!("{nombre}:")))
    }

    /// Un nombre con comillas cerraría la que abrimos y lo que sigue quedaría
    /// fuera del nombre.
    #[test]
    fn un_nombre_con_comillas_no_se_escapa_del_suyo() {
        let escrito = buzon("Ana\" <otro@ajeno.com> \"", "ana@ejemplo.com");
        assert_eq!(escrito.matches('<').count(), 1, "{escrito}");
        assert!(escrito.ends_with("<ana@ejemplo.com>"), "{escrito}");
    }

    // ── Direcciones ────────────────────────────────────────────────────────

    /// Lo que se valida no es que el buzón exista —eso lo dice el servidor—
    /// sino que la dirección **no pueda salirse de su renglón**.
    #[test]
    fn una_direccion_que_puede_inyectar_se_rechaza() {
        for mala in [
            "juan@otro.com\r\nBcc: x@y",
            "juan@otro.com\nX: y",
            "a b@otro.com",
            "<juan@otro.com>",
            "juan@otro.com, otro@x.com",
            "juan@otro.com; otro@x.com",
            "\"juan\"@otro.com",
        ] {
            assert!(!direccion_valida(mala), "{mala:?} tendría que rechazarse");
        }
    }

    #[test]
    fn una_direccion_mal_formada_se_rechaza() {
        for mala in ["", "  ", "juan", "@otro.com", "juan@", "juan@otro", "juan@@otro.com", "juan@.com", "juan@otro."] {
            assert!(!direccion_valida(mala), "{mala:?} tendría que rechazarse");
        }
    }

    /// Las direcciones con acentos necesitan `SMTPUTF8`, que hay que negociar
    /// con el servidor. Mandarlas sin eso hace que rechace el mensaje entero, y
    /// el error que devuelve no dice nada sobre la dirección.
    #[test]
    fn una_direccion_con_acentos_se_rechaza_por_ahora() {
        assert!(!direccion_valida("josé@ejemplo.com"));
    }

    #[test]
    fn una_direccion_normal_se_acepta() {
        for buena in [
            "juan@otro.com",
            "juan.perez+etiqueta@sub.otro.com.ar",
            "j@x.co",
        ] {
            assert!(direccion_valida(buena), "{buena:?} tendría que aceptarse");
        }
    }

    /// Sin destinatarios no hay a quién mandarlo, y el servidor contestaría un
    /// error que no explica nada. Se dice mientras la persona lo tiene en
    /// pantalla.
    #[test]
    fn un_borrador_sin_destinatarios_no_se_arma() {
        let mut b = borrador();
        b.para.clear();
        assert!(armar(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").is_err());
    }

    /// Un pegado desafortunado en «Para» puede hacer que el proveedor cierre la
    /// cuenta por envío masivo.
    #[test]
    fn hay_un_tope_de_destinatarios() {
        let mut b = borrador();
        b.para = (0..MAX_DESTINATARIOS + 1).map(|i| format!("x{i}@otro.com")).collect();
        let error = armar(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap_err();
        assert!(error.contains("tope"), "{error}");
    }

    /// El `Cc` va en la cabecera **y** en los destinatarios. Poner sólo la
    /// cabecera es el error que hace que la copia nunca llegue.
    #[test]
    fn el_cc_va_en_la_cabecera_y_en_la_entrega() {
        let mut b = borrador();
        b.cc = vec!["copia@otro.com".into()];

        let mensaje = armar(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        assert!(mensaje.contains("Cc: copia@otro.com"), "{mensaje}");
        assert_eq!(b.destinatarios(), vec!["juan@otro.com", "copia@otro.com"]);
    }

    // ── Renglones ──────────────────────────────────────────────────────────

    /// **Cien destinatarios no entran en una línea.** Cien direcciones de hasta
    /// 320 octetos son treinta y dos mil, y el estándar corta en 998: un
    /// servidor rechaza el mensaje, o peor, lo trunca y entrega una lista de
    /// destinatarios distinta de la que la persona escribió.
    #[test]
    fn una_lista_larga_de_destinatarios_se_parte_en_renglones() {
        let mut b = borrador();
        b.para = (0..60).map(|i| format!("destinatario.numero{i}@ejemplo.com")).collect();

        let mensaje = armar(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        for linea in mensaje.split("\r\n") {
            assert!(linea.len() <= 998, "línea de {} octetos", linea.len());
        }

        // Y se vuelve a juntar como una sola cabecera: los renglones que siguen
        // empiezan con un espacio, que es lo que el que lee reconoce.
        let cabeceras = crate::mensaje::Cabeceras::leer(&mensaje);
        let to = cabeceras.valor("to").unwrap();
        assert_eq!(to.matches('@').count(), 60, "se perdió algún destinatario");
        assert!(to.contains("destinatario.numero59@ejemplo.com"), "{to}");
    }

    /// Lo mismo con la cadena de la conversación, que llega de afuera.
    #[test]
    fn una_cadena_larga_de_referencias_se_parte() {
        let mut b = borrador();
        b.referencias = (0..20).map(|i| format!("<mensaje.numero{i}@ejemplo.com>")).collect();

        let mensaje = armar(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        for linea in mensaje.split("\r\n") {
            assert!(linea.len() <= 998, "línea de {} octetos", linea.len());
        }
        let cabeceras = crate::mensaje::Cabeceras::leer(&mensaje);
        assert_eq!(cabeceras.valor("references").unwrap().matches('<').count(), 20);
    }

    /// Una dirección que sola no entra en el renglón recomendado va en el suyo:
    /// partirla la rompería.
    #[test]
    fn una_direccion_larga_no_se_parte_por_la_mitad() {
        let larga = format!("{}@ejemplo.com", "a".repeat(200));
        let plegada_ = plegada("To", std::slice::from_ref(&larga), ",");
        assert!(plegada_.contains(&larga), "{plegada_}");
    }

    // ── Lo que llega de afuera, con tope ───────────────────────────────────

    /// Nada de esto lo escribe una persona: una respuesta hereda el asunto de
    /// un mensaje que mandó cualquiera. Sin tope, un asunto de un megabyte se
    /// convierte en un `DATA` de un megabyte que el servidor rechaza
    /// **después** de recibirlo entero.
    #[test]
    fn una_cabecera_desmedida_se_rechaza_antes_de_gastar_la_conexion() {
        let mut b = borrador();
        b.asunto = "a".repeat(MAX_ASUNTO + 1);
        assert!(armar(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").is_err());

        let mut b = borrador();
        b.nombre = "a".repeat(MAX_NOMBRE + 1);
        assert!(armar(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").is_err());

        let mut b = borrador();
        b.en_respuesta_a = format!("<{}@x>", "a".repeat(MAX_IDENTIFICADOR));
        assert!(armar(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").is_err());
    }

    /// La cadena de una conversación llega de afuera y no tiene por qué venir
    /// recortada: quien llama puede ser cualquier cosa en el bus de sesión.
    #[test]
    fn una_cadena_de_referencias_desmedida_se_rechaza() {
        let mut b = borrador();
        b.referencias = (0..MAX_REFERENCIAS + 1).map(|i| format!("<{i}@x>")).collect();
        let error = armar(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap_err();
        assert!(error.contains("referencias"), "{error}");
    }

    /// Y lo normal sigue pasando: los topes están para lo absurdo, no para
    /// molestar a nadie.
    #[test]
    fn un_asunto_normal_no_se_rechaza() {
        let mut b = borrador();
        b.asunto = "Re: ".to_string() + &"palabra ".repeat(30);
        assert!(armar(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").is_ok());
    }

    // ── Cabeceras con acentos ──────────────────────────────────────────────

    /// Una cabecera sólo puede llevar ASCII. Sin codificar, el asunto llega roto
    /// o el servidor rechaza el mensaje.
    #[test]
    fn un_asunto_con_acentos_va_codificado() {
        let mut b = borrador();
        b.asunto = "Reunión de mañana".into();

        let mensaje = armar(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        assert!(mensaje.contains("Subject: =?UTF-8?B?"), "{mensaje}");
        assert!(mensaje.is_ascii(), "quedó algo que no es ASCII en el mensaje");
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
            let codificado = cabecera_segura(original);
            // Desplegado como lo haría un cliente: las palabras van separadas
            // por un salto y un espacio.
            let desplegado = codificado.replace("\r\n ", " ");
            assert_eq!(
                crate::mensaje::decodificar_palabras(&desplegado),
                original,
                "no cerró el viaje de ida y vuelta"
            );
        }
    }

    /// Ninguna línea de una cabecera puede pasar de 76 octetos.
    #[test]
    fn una_cabecera_larga_se_parte() {
        let largo = "á".repeat(200);
        let codificado = cabecera_segura(&largo);
        for linea in codificado.split("\r\n") {
            assert!(linea.len() <= 76, "línea de {} octetos: {linea}", linea.len());
        }
    }

    /// Una palabra codificada entre comillas no se decodifica, y el
    /// destinatario ve el `=?UTF-8?B?…?=` en pantalla.
    #[test]
    fn un_nombre_codificado_no_va_entre_comillas() {
        let escrito = buzon("Ana Pérez", "ana@ejemplo.com");
        assert!(escrito.starts_with("=?UTF-8?B?"), "{escrito}");
        assert!(!escrito.contains('"'), "{escrito}");
    }

    // ── El cuerpo ──────────────────────────────────────────────────────────

    /// Ninguna línea puede pasar de los 998 octetos del estándar, y hay
    /// servidores que cortan la conexión ante una más larga. Un párrafo escrito
    /// de un tirón los pasa sin que nadie lo note.
    #[test]
    fn un_parrafo_largo_se_parte_en_lineas() {
        let parrafo = "palabra ".repeat(300);
        let codificado = quoted_printable(&parrafo);

        for linea in codificado.split("\r\n") {
            assert!(linea.len() <= 76, "línea de {} octetos", linea.len());
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
            let codificado = quoted_printable(original);
            let vuelta = crate::mensaje::imprimible_de(codificado.as_bytes(), false);
            let vuelta = String::from_utf8_lossy(&vuelta).replace("\r\n", "\n");
            assert_eq!(vuelta, *original, "no cerró el viaje de ida y vuelta");
        }
    }

    /// Un espacio al final de la línea lo puede recortar cualquier cosa en el
    /// camino, y el texto que llega no es el que se escribió.
    #[test]
    fn un_espacio_al_final_de_la_linea_se_codifica() {
        let codificado = quoted_printable("hola \nchau");
        assert!(codificado.starts_with("hola=20"), "{codificado}");
    }

    #[test]
    fn el_igual_se_escapa() {
        assert_eq!(quoted_printable("2 = 2"), "2 =3D 2");
    }

    /// El cuerpo va en UTF-8 codificado, así que el mensaje entero es ASCII y
    /// no depende de que el servidor acepte ocho bits.
    #[test]
    fn el_mensaje_entero_es_ascii() {
        let mut b = borrador();
        b.asunto = "Reunión".into();
        b.cuerpo = "Nos vemos mañana, ¿te va?".into();

        let mensaje = armar(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        assert!(mensaje.is_ascii(), "{mensaje}");
    }

    // ── La estructura ──────────────────────────────────────────────────────

    /// Un mensaje son cabeceras, una línea vacía y el cuerpo. La línea vacía es
    /// lo único que los separa.
    #[test]
    fn el_mensaje_tiene_la_forma_que_espera_un_servidor() {
        let mensaje = armar(&borrador(), "<abc@ejemplo.com>", "Thu, 10 Sep 2026 12:00:00 +0000")
            .unwrap();

        let (cabeceras, cuerpo) = mensaje.split_once("\r\n\r\n").unwrap();
        assert!(cabeceras.starts_with("Date: Thu, 10 Sep 2026"), "{cabeceras}");
        assert!(cabeceras.contains("\r\nTo: juan@otro.com"), "{cabeceras}");
        assert!(cabeceras.contains("\r\nMessage-ID: <abc@ejemplo.com>"), "{cabeceras}");
        assert!(cabeceras.contains("\r\nMIME-Version: 1.0"), "{cabeceras}");
        assert_eq!(cuerpo, "Buenas.");
    }

    /// Las dos cabeceras de conversación van juntas: los clientes usan una o la
    /// otra según cuál entiendan, y con una sola la conversación se parte en
    /// alguno de ellos.
    #[test]
    fn una_respuesta_queda_enganchada_a_su_conversacion() {
        let mut b = borrador();
        b.en_respuesta_a = "<original@otro.com>".into();
        b.referencias = vec!["<primero@otro.com>".into(), "<original@otro.com>".into()];

        let mensaje = armar(&b, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        assert!(mensaje.contains("In-Reply-To: <original@otro.com>"), "{mensaje}");
        assert!(
            mensaje.contains("References: <primero@otro.com> <original@otro.com>"),
            "{mensaje}"
        );
    }

    /// Un mensaje que no es respuesta no lleva esas cabeceras: una `In-Reply-To`
    /// vacía engancha el mensaje a la nada y hay clientes que lo esconden.
    #[test]
    fn un_mensaje_nuevo_no_lleva_cabeceras_de_conversacion() {
        let mensaje = armar(&borrador(), "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        assert!(!mensaje.contains("In-Reply-To"), "{mensaje}");
        assert!(!mensaje.contains("References"), "{mensaje}");
    }

    /// El dominio sale de la dirección de quien manda y no del nombre del
    /// equipo: el nombre del equipo de alguien no tiene por qué viajar en cada
    /// correo que manda.
    #[test]
    fn el_identificador_no_filtra_el_nombre_del_equipo() {
        let momento = chrono::DateTime::from_timestamp(1_757_500_000, 0).unwrap();
        let id = identificador("ana@ejemplo.com", momento, 42);

        assert!(id.ends_with("@ejemplo.com>"), "{id}");
        assert!(id.starts_with('<'), "{id}");
        // Y dos seguidos no son iguales, o dos mensajes del mismo segundo
        // compartirían identificador y algún cliente escondería uno.
        assert_ne!(id, identificador("ana@ejemplo.com", momento, 43));
    }

    fn con_adjunto(nombre: &str, contenido: &str) -> Borrador {
        Borrador {
            de: "ana@ejemplo.com".into(),
            para: vec!["juan@otro.com".into()],
            asunto: "Con algo pegado".into(),
            cuerpo: "Va el archivo.".into(),
            adjuntos: vec![Adjunto {
                nombre: nombre.into(),
                tipo: String::new(),
                contenido: contenido.into(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn sin_adjuntos_sigue_siendo_de_una_sola_parte() {
        // Envolver en un `multipart` un mensaje que son dos renglones de texto
        // es hacerle leer un árbol a quien no lo necesita.
        let borrador = Borrador {
            de: "a@b.c".into(),
            para: vec!["d@e.f".into()],
            cuerpo: "Hola".into(),
            ..Default::default()
        };
        let armado = armar(&borrador, "<x@b.c>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        assert!(armado.contains("Content-Type: text/plain; charset=utf-8"));
        assert!(!armado.contains("multipart"));
    }

    /// La vuelta completa: se arma el mensaje y se lo lee con el analizador del
    /// propio proyecto. Comprobar el texto a ojo diría que las cadenas están;
    /// esto dice que el mensaje **se puede volver a partir**.
    #[test]
    fn lo_armado_se_vuelve_a_leer_como_adjunto() {
        let armado = armar(
            &con_adjunto("informe.pdf", "SGVsbG8gd29ybGQ="),
            "<x@b.c>",
            "Thu, 10 Sep 2026 12:00:00 +0000",
        )
        .unwrap();

        let leidos = crate::adjuntos::listar(armado.as_bytes());
        assert_eq!(leidos.len(), 1);
        assert_eq!(leidos[0].nombre, "informe.pdf");
        assert_eq!(leidos[0].tipo, "application/pdf");
        // La parte 1 es el texto, la 2 el adjunto.
        assert_eq!(leidos[0].parte, "2");

        // Y el texto sigue siendo legible.
        assert!(crate::mensaje::texto_de(armado.as_bytes()).contains("Va el archivo"));
    }

    /// Es la condición que hace que un `multipart` se pueda volver a partir. Si
    /// la frontera aparece dentro de una parte, quien lo lea corta ahí.
    #[test]
    fn la_frontera_nunca_aparece_en_las_partes() {
        let normal = frontera(&["hola", "chau"]);
        assert!(!normal.contains("hola"));

        // Un contenido que trae adentro la frontera que se le iba a poner.
        let calculada = frontera(&["nada"]);
        let malicioso = format!("texto --{calculada} texto");
        let otra = frontera(&[malicioso.as_str()]);
        assert!(!malicioso.contains(&otra));
    }

    /// El bucle que alarga la frontera es una red por si acaso: para que haga
    /// falta, una parte tendría que contener la frontera derivada **de sí
    /// misma**, que es un punto fijo de la huella y no se construye a mano. Lo
    /// que sí se puede comprobar —y es lo que importa— es la invariante: salga
    /// lo que salga, no aparece en ninguna parte.
    #[test]
    fn la_invariante_vale_tambien_con_contenido_hostil() {
        let vista = frontera(&[""]);
        let intentos = [
            format!("{vista} y {vista}x"),
            format!("--{vista}--"),
            "=_vasak_0000000000000000".to_string(),
            "=_vasak_".repeat(50),
        ];
        for parte in &intentos {
            let elegida = frontera(&[parte.as_str()]);
            assert!(!parte.contains(&elegida), "{parte}");
        }
    }

    #[test]
    fn el_tipo_se_adivina_por_la_extension_y_ante_la_duda_es_octet_stream() {
        assert_eq!(tipo_por_nombre("informe.pdf"), "application/pdf");
        assert_eq!(tipo_por_nombre("FOTO.JPG"), "image/jpeg");
        assert_eq!(tipo_por_nombre("datos.csv"), "text/csv");
        // Ante la duda, el genérico: un tipo equivocado hace que el cliente de
        // quien lo recibe intente abrirlo con lo que no corresponde.
        assert_eq!(tipo_por_nombre("cosa.xyz"), "application/octet-stream");
        assert_eq!(tipo_por_nombre("sinextension"), "application/octet-stream");
        assert_eq!(tipo_por_nombre(""), "application/octet-stream");
    }

    #[test]
    fn un_tipo_declarado_le_gana_al_adivinado() {
        let mut borrador = con_adjunto("cosa.bin", "AAAA");
        borrador.adjuntos[0].tipo = "image/png".into();
        let armado = armar(&borrador, "<x@b.c>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();
        assert!(armado.contains("Content-Type: image/png;"));
    }

    #[test]
    fn un_nombre_con_acentos_va_en_rfc_2231() {
        let armado = armar(
            &con_adjunto("árbol.pdf", "AAAA"),
            "<x@b.c>",
            "Thu, 10 Sep 2026 12:00:00 +0000",
        )
        .unwrap();
        assert!(armado.contains("filename*=utf-8''%C3%A1rbol.pdf"), "{armado}");

        // Y del otro lado se vuelve a leer entero.
        assert_eq!(
            crate::adjuntos::listar(armado.as_bytes())[0].nombre,
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
        let armado = armar(
            &con_adjunto("uno\r\nContent-Type: text/html", "AAAA"),
            "<x@b.c>",
            "Thu, 10 Sep 2026 12:00:00 +0000",
        )
        .unwrap();

        for renglon in armado.split("\r\n") {
            assert!(
                !renglon.starts_with("Content-Type: text/html"),
                "el nombre se convirtió en cabecera: {armado}"
            );
        }

        // Y el adjunto se sigue leyendo, con el nombre ya sin los saltos.
        let leidos = crate::adjuntos::listar(armado.as_bytes());
        assert_eq!(leidos.len(), 1);
        assert!(!leidos[0].nombre.contains('\n'));
    }

    #[test]
    fn las_comillas_del_nombre_se_escapan() {
        assert_eq!(
            nombre_de_archivo(r#"el "bueno".pdf"#),
            r#"filename="el \"bueno\".pdf""#
        );
    }

    /// Una línea de un megabyte no la acepta ningún servidor: el límite del
    /// formato son 998 octetos.
    #[test]
    fn el_base64_sale_en_renglones_cortos() {
        let largo = "A".repeat(500);
        for linea in en_renglones(&largo).split("\r\n") {
            assert!(linea.len() <= 76, "renglón de {}", linea.len());
        }
        // Y no se pierde nada.
        assert_eq!(en_renglones(&largo).replace("\r\n", ""), largo);
    }

    #[test]
    fn varios_adjuntos_van_cada_uno_en_su_parte() {
        let mut borrador = con_adjunto("uno.pdf", "AAAA");
        borrador.adjuntos.push(Adjunto {
            nombre: "dos.png".into(),
            tipo: String::new(),
            contenido: "BBBB".into(),
        });
        let armado = armar(&borrador, "<x@b.c>", "Thu, 10 Sep 2026 12:00:00 +0000").unwrap();

        let leidos = crate::adjuntos::listar(armado.as_bytes());
        assert_eq!(leidos.len(), 2);
        assert_eq!(leidos[0].parte, "2");
        assert_eq!(leidos[1].parte, "3");
        assert_eq!(leidos[1].tipo, "image/png");
    }

}
