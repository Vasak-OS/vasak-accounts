//! Lo de IMAP que hace falta para saber qué correo hay y leerlo.
//!
//! ── Cómo creció esto ────────────────────────────────────────────────────────
//!
//! Empezó contando sin leer y nada más, a propósito: `STATUS` y `SEARCH`
//! devuelven números, así que no había que tocar ni una cabecera ni un cuerpo —o
//! sea, ni una línea de parser sobre lo que escribió un desconocido—. Ese módulo
//! decía que el día que hubiera que leer mensajes de verdad el parser sería la
//! parte peligrosa y merecería su propia discusión. Ese día llegó con la
//! aplicación de correo, y esa discusión está en `message.rs`.
//!
//! Acá sigue viviendo sólo el **protocolo**: pedirle cosas al servidor y
//! entender su respuesta. Lo que dice el mensaje se interpreta en el otro lado.
//!
//! ── Literales ───────────────────────────────────────────────────────────────
//!
//! IMAP es un protocolo de líneas hasta que se piden cuerpos. Ahí el servidor
//! anuncia `{1234}` al final de una línea y manda esos bytes crudos: pueden
//! contener saltos de línea, comillas y bytes que no son texto. Leerlos como
//! líneas parte el mensaje en pedazos y desincroniza la conexión para siempre —
//! todo lo que venga después se lee corrido. Por eso hay un lector aparte.
//!
//! ── Sobre el proceso donde corre ────────────────────────────────────────────
//!
//! Como el usuario, nunca como root. Es la razón de que este binario exista
//! aparte del servicio de cuentas.

use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::broker::{Credential, Endpoint};
use crate::mailboxes::{mailbox_from_list, uidvalidity_from, Mailbox};
use crate::query::{build_criteria, search_uids, Chunk, Term};

/// Tope para conectarse y autenticarse.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Tope de un intercambio con el servidor: mandar un comando y leer su
/// respuesta.
///
/// **Todo lo que no sea la espera de IDLE tiene que tenerlo.** Un servidor que
/// deja de escribir sin cerrar el socket —un NAT que olvidó la conexión, un
/// proceso matado sin FIN— no produce ningún error: la lectura simplemente no
/// vuelve nunca. En una conexión que dura horas eso pasa, y sin este tope la
/// tarea de esa cuenta se queda esperando para siempre: no publica el fallo, no
/// llega a reconectar, y la cuenta queda muda hasta que se reinicie el proceso.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(60);

/// Tope de una línea de respuesta.
///
/// IMAP es un protocolo de líneas cortas salvo cuando se piden cuerpos, que acá
/// no se piden. Sin tope, un servidor que manda bytes sin cortar nunca hace
/// crecer la memoria del proceso sin límite.
const MAX_LINE: u64 = 64 * 1024;

/// Tope de un literal: lo que el servidor manda como bloque de bytes.
///
/// Un mensaje con un adjunto de veinticinco megas es normal, y traerlo entero
/// para mostrar tres líneas de texto sería gastar la conexión de la persona en
/// algo que no se va a ver. Se pide **de a un pedazo** con `<0.N>`, que el
/// protocolo permite, y esto es ese pedazo.
///
/// La contra, dicha donde se ve: si el texto del mensaje viene **después** de un
/// adjunto grande, se corta. Los clientes ponen el texto primero, así que en la
/// práctica no pasa; cuando haya un lector de adjuntos de verdad va a mirar la
/// estructura del mensaje y a pedir sólo la parte que se muestra.
pub const MAX_BODY: usize = 1024 * 1024;

/// Cuántos mensajes se traen de la casilla.
///
/// No todos: una casilla de veinte años tiene decenas de miles, y traerlos en el
/// arranque haría esperar minutos para ver el correo de hoy. Los últimos
/// doscientos son varias pantallas y llegan en un segundo.
pub const RECENT_COUNT: u32 = 200;

#[derive(Debug)]
pub enum ImapError {
    /// El servidor dijo que no a las credenciales. Se distingue porque es el
    /// caso en que hay que avisar y **dejar de reintentar**: insistir con una
    /// contraseña que el servidor rechaza es cómo se bloquea una cuenta.
    Rejected(String),
    /// La conexión quedó a mitad de camino de algo y lo que venga después se
    /// va a leer corrido. **No se puede seguir usando**: hay que tirarla y abrir
    /// otra. Se distingue de `Failed` porque un fallo cualquiera deja la sesión
    /// utilizable y éste no.
    Desynced(String),
    Failed(String),
}

impl std::fmt::Display for ImapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImapError::Rejected(d) => write!(f, "el servidor rechazó las credenciales: {d}"),
            ImapError::Desynced(d) => write!(f, "la conexión quedó desincronizada: {d}"),
            ImapError::Failed(d) => write!(f, "{d}"),
        }
    }
}

impl std::error::Error for ImapError {}

/// Por qué volvió la espera.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleWake {
    /// El servidor avisó que algo cambió.
    Changed,
    /// Se cumplió el tiempo y hay que renovar la espera.
    TimedOut,
}

/// Lo que se sabe de una casilla después de mirarla.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct MailboxStatus {
    #[serde(rename = "mensajes")]
    pub messages: u32,
    #[serde(rename = "sin_leer")]
    pub unread: u32,
}

// ---------------------------------------------------------------------------
// Lo que se puede probar sin red
// ---------------------------------------------------------------------------

/// Escapa un texto para meterlo entre comillas en un comando IMAP.
///
/// `None` si no se puede: un salto de línea partiría el comando en dos y lo que
/// siga se leería como un comando nuevo. Es la inyección clásica de este
/// protocolo.
pub fn quoted(text: &str) -> Option<String> {
    if text.contains(['\r', '\n', '\0']) {
        return None;
    }
    Some(format!(
        "\"{}\"",
        text.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

/// El estado de una respuesta con etiqueta.
#[derive(Debug, PartialEq, Eq)]
pub enum TaggedStatus {
    Ok,
    No(String),
    Bad(String),
}

/// Interpreta una línea contra la etiqueta que se mandó.
///
/// `None` para las que no son la respuesta final: las que empiezan con `*` son
/// datos sin pedir y el servidor manda varias antes de contestar. Tomarlas por
/// la respuesta daría por buena una sesión que todavía no se autenticó.
pub fn tagged_status(line: &str, tag: &str) -> Option<TaggedStatus> {
    let rest = line.strip_prefix(tag)?.strip_prefix(' ')?;
    let (state, detail) = rest.split_once(' ').unwrap_or((rest, ""));
    match state.to_ascii_uppercase().as_str() {
        "OK" => Some(TaggedStatus::Ok),
        "NO" => Some(TaggedStatus::No(detail.trim().into())),
        "BAD" => Some(TaggedStatus::Bad(detail.trim().into())),
        _ => None,
    }
}

/// El cuerpo de un `AUTHENTICATE XOAUTH2`.
///
/// El formato lo fijan Google y Microsoft y no se parece a nada más del
/// protocolo: `user=…^Aauth=Bearer …^A^A`, donde `^A` es el byte 0x01. Escribirlo
/// con espacios o dos puntos, que es lo intuitivo, da un rechazo que parece de
/// credenciales y no lo es.
pub fn xoauth2_payload(username: &str, token: &str) -> String {
    let raw = format!("user={username}\x01auth=Bearer {token}\x01\x01");
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// Las capacidades que anuncia el servidor.
///
/// Llegan en una línea `* CAPABILITY IMAP4rev1 IDLE …`, y también pegadas al
/// saludo entre corchetes: `* OK [CAPABILITY …] listo`. Se leen de las dos
/// formas porque hay servidores que sólo las dan en el saludo, y preguntar de
/// nuevo por algo que ya dijeron es una vuelta de más en cada conexión.
pub fn capabilities_from(line: &str) -> Vec<String> {
    let upper = line.to_ascii_uppercase();

    let list = if let Some(from) = upper.find("[CAPABILITY ") {
        let rest = &upper[from + "[CAPABILITY ".len()..];
        rest.split_once(']').map(|(inside, _)| inside)
    } else {
        upper.strip_prefix("* CAPABILITY ")
    };

    list.map(|l| l.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Cuántos mensajes anuncia un `* n EXISTS`.
pub fn exists_count(line: &str) -> Option<u32> {
    let after_star = line.strip_prefix("* ")?;
    let (number, rest) = after_star.split_once(' ')?;
    rest.trim()
        .eq_ignore_ascii_case("EXISTS")
        .then(|| number.parse().ok())
        .flatten()
}

/// Cuántos resultados trae un `* SEARCH 3 5 9`.
///
/// Se cuentan y no se leen: los números son identificadores de mensaje y lo
/// único que hace falta es cuántos hay.
pub fn search_result_count(line: &str) -> Option<u32> {
    // El corte después de la palabra lo comprueba `after_search`. Sin eso,
    // `* SEARCHING 1` pasaba por una respuesta de `SEARCH` con un resultado —
    // la misma clase de error que el de las etiquetas, que ya tiene su prueba
    // más abajo.
    Some(crate::query::after_search(line)?.split_whitespace().count() as u32)
}

/// Cómo terminó un movimiento.
///
/// No es un booleano porque hay un tercer final, y es el que importa: el mensaje
/// se copió y se marcó para borrar, pero **la copia vieja sigue ahí** porque
/// borrarla de verdad habría borrado también lo de otro. Quien llame tiene que
/// poder decirlo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MoveOutcome {
    /// Está en el destino y ya no está en el origen.
    #[serde(rename = "entero")]
    Complete,
    /// Está en el destino y en el origen sigue, marcado para borrar.
    #[serde(rename = "sin_borrar_el_viejo")]
    OldCopyKept,
}

/// Si un número de parte tiene la forma que IMAP espera: `2`, `1.3.2`.
///
/// Se comprueba porque **va crudo en el comando**. El número sale de recorrer el
/// árbol de un mensaje que mandó cualquiera, y aunque hoy lo genera este mismo
/// programa, un día va a venir de la ventana: una parte con un espacio y una
/// palabra clave adentro sería un comando distinto del que se quiso mandar.
pub fn is_valid_part(part: &str) -> bool {
    !part.is_empty()
        && part
            .split('.')
            .all(|t| !t.is_empty() && t.len() <= 4 && t.chars().all(|c| c.is_ascii_digit()))
}

/// Saca una línea del búfer, si ya hay una entera.
///
/// Aparte de la sesión para poder probarla: el búfer es lo que hace que esperar
/// con reloj sea seguro, y esa propiedad merece un test que no necesite una
/// conexión de verdad.
pub fn line_from_buffer(pending: &mut Vec<u8>) -> Option<String> {
    let end = pending.iter().position(|b| *b == b'\n')?;
    let line: Vec<u8> = pending.drain(..=end).collect();
    Some(String::from_utf8_lossy(&line).trim_end().to_string())
}

/// Si una línea que llegó durante IDLE dice que algo cambió.
///
/// `EXISTS` es correo nuevo, `EXPUNGE` es un mensaje borrado y `FETCH` es una
/// marca que cambió —leído, sin leer— desde otro dispositivo. Los tres importan
/// para el contador.
///
/// `RECENT` **no** alcanza por sí solo: hay servidores que lo mandan junto con
/// el `EXISTS` y otros que lo repiten sin que haya nada nuevo, así que actuar
/// sobre él sería despertarse de más. Cuando hay algo de verdad, viene el
/// `EXISTS`.
pub fn announces_change(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("* ") else {
        return false;
    };
    let upper = rest.to_ascii_uppercase();
    // `n EXISTS`, `n EXPUNGE`, `n FETCH (...)`: siempre el número primero.
    let Some((number, tail)) = upper.split_once(' ') else {
        return false;
    };
    if number.parse::<u32>().is_err() {
        return false;
    }
    tail.starts_with("EXISTS") || tail.starts_with("EXPUNGE") || tail.starts_with("FETCH")
}

/// Cuántos bytes anuncia un literal al final de una línea.
///
/// `{1234}` o `{1234+}`: la segunda forma es la de los servidores que no esperan
/// confirmación. Las dos significan lo mismo para quien lee.
///
/// Sin esto, esos bytes se leerían como si fueran líneas del protocolo: el
/// mensaje se parte en pedazos y la conexión queda desincronizada para siempre,
/// porque todo lo que venga después se interpreta corrido.
pub fn literal_length(line: &str) -> Option<usize> {
    let without_brace = line.strip_suffix('}')?;
    let start = without_brace.rfind('{')?;
    let number = &without_brace[start + 1..];
    // El `+` de LITERAL+ va pegado al número.
    number.strip_suffix('+').unwrap_or(number).parse().ok()
}

/// El UID que trae una respuesta de `FETCH`.
///
/// El UID y no el número de secuencia: el número cambia en cuanto se borra
/// cualquier mensaje anterior, así que guardarlo sería guardar algo que mañana
/// apunta a otro mensaje.
pub fn uid_from(reply: &str) -> Option<u32> {
    let upper = reply.to_ascii_uppercase();
    let mut from = 0;
    while let Some(pos) = upper[from..].find("UID ") {
        let abs_pos = from + pos;
        // Que sea la palabra «UID» y no el final de otra, como «BODYUID».
        let previous = upper[..abs_pos].chars().next_back();
        if previous.is_none_or(|c| c == '(' || c == ' ') {
            let tail = &reply[abs_pos + "UID ".len()..];
            let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(uid) = digits.parse() {
                return Some(uid);
            }
        }
        from = abs_pos + "UID ".len();
    }
    None
}

/// Si el mensaje está marcado como leído.
///
/// Se mira `\Seen` dentro de `FLAGS (...)` y no en la respuesta entera: un
/// asunto que diga «Seen» no puede marcar un mensaje como leído.
pub fn is_seen(reply: &str) -> bool {
    let upper = reply.to_ascii_uppercase();
    let Some(start) = upper.find("FLAGS (") else {
        return false;
    };
    let from = start + "FLAGS (".len();
    let end = upper[from..]
        .find(')')
        .map(|f| from + f)
        .unwrap_or(upper.len());
    upper[from..end].split_whitespace().any(|b| b == "\\SEEN")
}

/// El rango de secuencia de los últimos `count` mensajes de una casilla.
///
/// `None` si la casilla está vacía: pedir `1:0` es un error de sintaxis, y un
/// servidor que lo recibe puede cortar la sesión en vez de contestar.
pub fn last_range(messages: u32, count: u32) -> Option<String> {
    if messages == 0 || count == 0 {
        return None;
    }
    let from = messages.saturating_sub(count - 1).max(1);
    Some(format!("{from}:{messages}"))
}

// ---------------------------------------------------------------------------
// La parte que habla por la red
// ---------------------------------------------------------------------------

type Transport = tokio_rustls::client::TlsStream<TcpStream>;

/// Una sesión IMAP abierta.
///
/// El flujo es un parámetro con valor por omisión, y eso es lo que hace que
/// esto se pueda probar. En producción siempre es el TLS de arriba; en las
/// pruebas es un par de tuberías en memoria contra un servidor de mentira, y
/// así se puede ejercer la conversación entera —qué comando se manda, en qué
/// orden, qué se hace con las respuestas sin etiqueta— que es exactamente lo
/// que un analizador suelto no comprueba.
pub struct Session<F = Transport> {
    stream: F,
    /// Lo que se leyó del socket y todavía no se consumió como línea.
    ///
    /// El búfer es **nuestro** y no de un `BufReader`, y eso es lo que hace que
    /// leer con tiempo límite sea seguro. `read_line` no se puede cancelar sin
    /// perder datos: si el temporizador gana, lo que ya había leído en la cadena
    /// se pierde. Con IDLE eso pasaría cada vez que hay que renovar la espera, y
    /// el síntoma sería una respuesta cortada al azar cada media hora.
    ///
    /// `read_buf` sobre un búfer propio sí se puede cancelar: lo leído queda
    /// acá, y la próxima lectura sigue donde iba.
    pending: Vec<u8>,
    tag: u32,
    capabilities: Vec<String>,
    /// El `UIDVALIDITY` de la última casilla que se abrió.
    ///
    /// Se guarda porque es lo único que dice si los UID que tenemos siguen
    /// valiendo. Cuando el servidor lo cambia, el 412 de ayer **no** es el 412
    /// de hoy: quien tenga una lista vieja tiene que tirarla. Sin esto, un
    /// «borrar» le puede caer a otro mensaje.
    uidvalidity: Option<u32>,
}

impl Session<Transport> {
    /// Abre la sesión y se autentica.
    ///
    /// Siempre sobre TLS desde el primer byte. STARTTLS no se implementa acá a
    /// propósito: el formulario propone 993 y el autodescubrimiento también, así
    /// que una cuenta que llegara hasta acá con un puerto en claro sería una
    /// configurada a mano contra la recomendación — y mandarle la credencial sin
    /// cifrar no es algo que este proceso deba hacer en silencio.
    pub async fn open(destination: &Endpoint) -> Result<Self, ImapError> {
        tokio::time::timeout(TIMEOUT, Self::open_unbounded(destination))
            .await
            .map_err(|_| {
                ImapError::Failed(format!(
                    "{}:{} no contestó en {} segundos",
                    destination.host,
                    destination.port,
                    TIMEOUT.as_secs()
                ))
            })?
    }

    async fn open_unbounded(destination: &Endpoint) -> Result<Self, ImapError> {
        let tcp = TcpStream::connect((destination.host.as_str(), destination.port))
            .await
            .map_err(|e| {
                ImapError::Failed(format!(
                    "no se pudo conectar a {}:{}: {e}",
                    destination.host, destination.port
                ))
            })?;

        let name = ServerName::try_from(destination.host.clone()).map_err(|e| {
            ImapError::Failed(format!(
                "«{}» no es un nombre de servidor: {e}",
                destination.host
            ))
        })?;
        let encrypted = crate::tls::connector()
            .map_err(ImapError::Failed)?
            .connect(name, tcp)
            .await
            .map_err(|e| ImapError::Failed(format!("no se pudo cifrar la conexión: {e}")))?;

        let mut session = Session {
            stream: encrypted,
            pending: Vec::new(),
            tag: 0,
            capabilities: Vec::new(),
            uidvalidity: None,
        };

        let greeting = session.read_line().await?;
        if greeting.starts_with("* BYE") {
            return Err(ImapError::Failed(format!(
                "el servidor cerró la conexión: {greeting}"
            )));
        }
        // Muchos servidores las pegan al saludo; si vienen, una vuelta menos.
        session.capabilities = capabilities_from(&greeting);

        session.authenticate(&destination.credential).await?;

        // Después de autenticarse las capacidades pueden cambiar —IDLE suele
        // anunciarse recién ahí— así que se vuelven a pedir. Preguntarlo antes
        // sería quedarse con una lista que no vale.
        session.refresh_capabilities().await?;
        Ok(session)
    }
}

/// Todo lo demás no necesita saber que abajo hay TLS: le alcanza con poder leer
/// y escribir bytes.
impl<F: AsyncRead + AsyncWrite + Unpin + Send> Session<F> {
    async fn authenticate(&mut self, credential: &Credential) -> Result<(), ImapError> {
        match credential {
            Credential::Password { username, secret } => {
                let (Some(u), Some(s)) = (quoted(username), quoted(secret)) else {
                    return Err(ImapError::Failed(
                        "el usuario o la contraseña tienen un salto de línea".into(),
                    ));
                };
                self.command(&format!("LOGIN {u} {s}")).await
            }
            Credential::Token { username, token } => {
                // En una sola línea, que es la forma que aceptan Google y
                // Microsoft. Partirlo en `AUTHENTICATE XOAUTH2` y después la
                // carga obliga a leer el `+` intermedio, y hay servidores que no
                // lo mandan igual.
                self.command(&format!(
                    "AUTHENTICATE XOAUTH2 {}",
                    xoauth2_payload(username, token)
                ))
                .await
            }
        }
    }

    /// Le pone tope a un intercambio.
    ///
    /// El error dice que fue un tiempo agotado y no un fallo cualquiera, porque
    /// quien lo recibe lo trata como conexión cortada y reconecta — que es
    /// justamente lo que hay que hacer con un servidor que dejó de contestar.
    async fn with_timeout<T>(
        what: &str,
        future: impl std::future::Future<Output = Result<T, ImapError>>,
    ) -> Result<T, ImapError> {
        tokio::time::timeout(EXCHANGE_TIMEOUT, future)
            .await
            .unwrap_or_else(|_| {
                Err(ImapError::Failed(format!(
                    "el servidor dejó de contestar durante {what} ({}s)",
                    EXCHANGE_TIMEOUT.as_secs()
                )))
            })
    }

    /// Si el servidor sabe avisar en vez de que haya que preguntarle.
    pub fn supports_idle(&self) -> bool {
        self.capabilities.iter().any(|c| c == "IDLE")
    }

    async fn refresh_capabilities(&mut self) -> Result<(), ImapError> {
        let tag = self.next_tag();
        self.write_line(&format!("{tag} CAPABILITY")).await?;

        let seen_caps = Self::with_timeout("la lista de capacidades", async {
            let mut seen_caps = Vec::new();
            loop {
                let line = self.read_line().await?;
                let announced = capabilities_from(&line);
                if !announced.is_empty() {
                    seen_caps = announced;
                }
                match tagged_status(&line, &tag) {
                    Some(TaggedStatus::Ok) => return Ok(seen_caps),
                    Some(TaggedStatus::No(d)) | Some(TaggedStatus::Bad(d)) => {
                        return Err(ImapError::Failed(format!("CAPABILITY falló: {d}")))
                    }
                    None => continue,
                }
            }
        })
        .await?;

        if !seen_caps.is_empty() {
            self.capabilities = seen_caps;
        }
        Ok(())
    }

    /// Abre una casilla **en sólo lectura** y devuelve cuántos mensajes tiene.
    ///
    /// `EXAMINE` y no `SELECT`: los dos sirven para IDLE, pero `SELECT` puede
    /// borrar la marca de reciente y, según el servidor, tocar banderas. Este
    /// proceso cuenta correo; no tiene por qué cambiar nada de la casilla de
    /// nadie.
    pub async fn examine(&mut self, mailbox: &str) -> Result<u32, ImapError> {
        self.open_mailbox("EXAMINE", mailbox).await
    }

    /// El `UIDVALIDITY` de la casilla abierta, si el servidor lo dijo.
    ///
    /// Hay que compararlo con el que se tenía guardado para esa casilla
    /// **antes** de usar ningún UID: si cambió, la lista guardada no sirve.
    pub fn uidvalidity(&self) -> Option<u32> {
        self.uidvalidity
    }

    /// Enumera las casillas del servidor.
    ///
    /// `LIST "" "*"`: todas, desde la raíz. Las que el servidor marca
    /// `\Noselect` vienen igual y marcadas — existen sólo como rama de la
    /// jerarquía, y hace falta saber que están para dibujar el árbol.
    ///
    /// Las líneas que no se entienden se descartan en vez de cortar la
    /// enumeración: perder una casilla rara es mejor que quedarse sin ninguna.
    /// Un nombre como literal `{N}` es una de ésas — se resolvería leyendo más
    /// líneas, y todavía no apareció ningún servidor que los mande para esto.
    pub async fn list_mailboxes(&mut self) -> Result<Vec<Mailbox>, ImapError> {
        let tag = self.next_tag();
        self.write_line(&format!("{tag} LIST \"\" \"*\"")).await?;

        Self::with_timeout("listar las casillas", async {
            let mut mailboxes = Vec::new();
            loop {
                let line = self.read_line().await?;
                if let Some(mailbox) = mailbox_from_list(&line) {
                    mailboxes.push(mailbox);
                }
                match tagged_status(&line, &tag) {
                    Some(TaggedStatus::Ok) => return Ok(mailboxes),
                    Some(TaggedStatus::No(d)) | Some(TaggedStatus::Bad(d)) => {
                        return Err(ImapError::Failed(format!("LIST falló: {d}")))
                    }
                    None => continue,
                }
            }
        })
        .await
    }

    /// Abre una casilla con el comando que se le diga y devuelve cuántos
    /// mensajes tiene.
    ///
    /// `mailbox` es la **ruta**, o sea el nombre tal como lo escribe el
    /// servidor: la que trae `Mailbox::path`, ya en UTF-7 modificado si hacía
    /// falta. No se codifica acá porque codificar dos veces rompería el nombre,
    /// y los nombres siempre vienen de un `LIST`.
    async fn open_mailbox(&mut self, command: &str, mailbox: &str) -> Result<u32, ImapError> {
        let name = quoted(mailbox)
            .ok_or_else(|| ImapError::Failed("el nombre de la casilla no es válido".into()))?;

        let tag = self.next_tag();
        self.write_line(&format!("{tag} {command} {name}")).await?;

        Self::with_timeout("abrir la casilla", async {
            let mut messages = 0;
            loop {
                let line = self.read_line().await?;
                if let Some(n) = exists_count(&line) {
                    messages = n;
                }
                if let Some(v) = uidvalidity_from(&line) {
                    self.uidvalidity = Some(v);
                }
                match tagged_status(&line, &tag) {
                    Some(TaggedStatus::Ok) => return Ok(messages),
                    Some(TaggedStatus::No(d)) | Some(TaggedStatus::Bad(d)) => {
                        return Err(ImapError::Failed(format!(
                            "no se pudo abrir «{mailbox}»: {d}"
                        )))
                    }
                    None => continue,
                }
            }
        })
        .await
    }

    /// Busca en la casilla abierta y devuelve los UID que coinciden.
    ///
    /// `UID SEARCH` y no `SEARCH`: los números que vuelven tienen que ser los
    /// mismos que usa el resto del servicio. `SEARCH` a secas devuelve números
    /// de secuencia, que cambian cuando se borra cualquier mensaje anterior.
    ///
    /// # Los dos intentos
    ///
    /// Primero con `CHARSET UTF-8`, que es lo que hace falta para que «reunión»
    /// encuentre algo. Hay servidores viejos que lo rechazan con
    /// `NO [BADCHARSET]`; para ésos se reintenta sin declararlo, que es lo que
    /// el estándar permite y lo que hacen todos los clientes.
    ///
    /// Se reintenta **una vez** y sólo ante ese error. Insistir con otros es
    /// mandar dos veces un comando que ya se sabe que falla.
    pub async fn search(&mut self, terms: &[Term]) -> Result<Vec<u32>, ImapError> {
        let chunks = build_criteria(terms);
        if chunks.is_empty() {
            // Sin criterio, `SEARCH` devuelve la casilla entera. Eso no es una
            // búsqueda vacía, es todo: contestar nada es más honesto.
            return Ok(Vec::new());
        }

        match self.search_with(&chunks, true).await {
            Err(ImapError::Rejected(detail)) if detail.contains("BADCHARSET") => {
                self.search_with(&chunks, false).await
            }
            other => other,
        }
    }

    /// Un intento de búsqueda, declarando el juego de caracteres o no.
    async fn search_with(
        &mut self,
        chunks: &[Chunk],
        with_charset: bool,
    ) -> Result<Vec<u32>, ImapError> {
        let tag = self.next_tag();
        let mut line = format!("{tag} UID SEARCH");
        if with_charset {
            line.push_str(" CHARSET UTF-8");
        }

        // Los trozos que son literales de IMAP interrumpen la línea: se anuncia
        // el largo **en bytes**, el servidor contesta `+` y recién ahí van los
        // bytes. Un `chars().count()` acá mandaría un largo que no es el que el
        // servidor va a leer, y la sesión queda desincronizada.
        for chunk in chunks {
            match chunk {
                Chunk::Inline(text) => {
                    line.push(' ');
                    line.push_str(text);
                }
                Chunk::Literal(text) => {
                    line.push_str(&format!(" {{{}}}", text.len()));
                    self.write_line(&line).await?;
                    self.await_continuation().await?;
                    line = text.clone();
                }
            }
        }
        self.write_line(&line).await?;

        Self::with_timeout("buscar", async {
            let mut uids = Vec::new();
            loop {
                let line = self.read_line().await?;
                if let Some(found) = search_uids(&line) {
                    uids.extend(found);
                }
                match tagged_status(&line, &tag) {
                    Some(TaggedStatus::Ok) => return Ok(uids),
                    // `No` va como `Rejected` y no como `Failed` para que el
                    // reintento sin `CHARSET` pueda reconocerlo.
                    Some(TaggedStatus::No(d)) => return Err(ImapError::Rejected(d)),
                    Some(TaggedStatus::Bad(d)) => {
                        return Err(ImapError::Failed(format!("SEARCH falló: {d}")))
                    }
                    None => continue,
                }
            }
        })
        .await
    }

    /// Espera el `+` con el que el servidor pide los bytes de un literal.
    ///
    /// Sin esperarlo, los bytes salen antes de que el servidor esté listo para
    /// leerlos y los toma como el comando siguiente.
    async fn await_continuation(&mut self) -> Result<(), ImapError> {
        Self::with_timeout("esperar la continuación", async {
            loop {
                let line = self.read_line().await?;
                if line.starts_with('+') {
                    return Ok(());
                }
                // Un `NO` o un `BAD` acá quieren decir que el comando no va a
                // pasar. Seguir esperando el `+` sería esperar para siempre.
                let upper = line.to_ascii_uppercase();
                if upper.contains(" NO ") || upper.contains(" BAD ") {
                    return Err(ImapError::Rejected(line));
                }
            }
        })
        .await
    }

    /// Los resúmenes de unos UID puntuales.
    ///
    /// Mismo `FETCH` que `recent_summaries`, pero por UID en vez de por rango de
    /// secuencia: es lo que hace falta después de un `SEARCH`.
    pub async fn summaries_of(
        &mut self,
        uids: &[u32],
    ) -> Result<Vec<crate::message::MessageSummary>, ImapError> {
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        // Los más nuevos primero y con tope: una búsqueda amplia puede traer
        // diez mil, y pedir los encabezados de todos tarda lo que tarda y llena
        // la memoria de la ventana con algo que nadie va a leer entero.
        let mut recent: Vec<u32> = uids.to_vec();
        recent.sort_unstable_by(|a, b| b.cmp(a));
        recent.truncate(RECENT_COUNT as usize);

        let list = recent
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join(",");
        self.fetch_summaries(&format!("UID FETCH {list}")).await
    }

    /// Cuántos sin leer hay en la casilla abierta.
    ///
    /// Con `SEARCH` y no con `STATUS`: el estándar dice que `STATUS` no se use
    /// sobre la casilla que está abierta, y hay servidores que directamente
    /// contestan un error.
    pub async fn count_unread(&mut self) -> Result<u32, ImapError> {
        let tag = self.next_tag();
        self.write_line(&format!("{tag} SEARCH UNSEEN")).await?;

        Self::with_timeout("contar los sin leer", async {
            let mut count = 0;
            loop {
                let line = self.read_line().await?;
                if let Some(n) = search_result_count(&line) {
                    count = n;
                }
                match tagged_status(&line, &tag) {
                    Some(TaggedStatus::Ok) => return Ok(count),
                    Some(TaggedStatus::No(d)) | Some(TaggedStatus::Bad(d)) => {
                        return Err(ImapError::Failed(format!("SEARCH falló: {d}")))
                    }
                    None => continue,
                }
            }
        })
        .await
    }

    /// Espera a que el servidor avise que algo cambió.
    ///
    /// Vuelve cuando hay novedades o cuando se cumple `max_wait`, lo que pase
    /// primero. **Hay que volver a llamarla**: el estándar pide renovar la
    /// espera al menos cada veintinueve minutos, porque si no el servidor —o
    /// cualquier NAT en el medio— corta la conexión por inactividad.
    pub async fn idle(&mut self, max_wait: Duration) -> Result<IdleWake, ImapError> {
        let tag = self.next_tag();
        self.write_line(&format!("{tag} IDLE")).await?;

        // El servidor contesta `+ idling` antes de empezar. Si en vez de eso
        // manda un `NO`, es que no acepta IDLE aunque lo haya anunciado.
        //
        // Con tope: esperar acá sin límite es cómo una cuenta queda muda para
        // siempre contra un servidor que dejó de escribir sin cerrar.
        Self::with_timeout("el comienzo de la espera", async {
            loop {
                let line = self.read_line().await?;
                if line.starts_with('+') {
                    return Ok(());
                }
                if let Some(TaggedStatus::No(d)) | Some(TaggedStatus::Bad(d)) =
                    tagged_status(&line, &tag)
                {
                    return Err(ImapError::Failed(format!(
                        "el servidor no acepta IDLE: {d}"
                    )));
                }
            }
        })
        .await?;

        let end = tokio::time::Instant::now() + max_wait;
        let mut wake = IdleWake::TimedOut;
        loop {
            let remaining = end.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            // Cancelar esta lectura no pierde nada: el búfer es nuestro.
            match tokio::time::timeout(remaining, self.read_line()).await {
                Err(_) => break,
                Ok(Err(e)) => return Err(e),
                Ok(Ok(line)) => {
                    if announces_change(&line) {
                        wake = IdleWake::Changed;
                        break;
                    }
                }
            }
        }

        // `DONE` va **sin etiqueta**: es la única línea del protocolo que no
        // lleva una, y ponérsela hace que el servidor no la reconozca y la
        // sesión quede colgada esperando.
        self.write_line("DONE").await?;
        Self::with_timeout("el fin de la espera", async {
            loop {
                let line = self.read_line().await?;
                match tagged_status(&line, &tag) {
                    Some(TaggedStatus::Ok) => return Ok(()),
                    Some(TaggedStatus::No(d)) | Some(TaggedStatus::Bad(d)) => {
                        return Err(ImapError::Failed(format!("IDLE terminó mal: {d}")))
                    }
                    None => continue,
                }
            }
        })
        .await?;

        Ok(wake)
    }

    /// Los últimos mensajes de la casilla abierta, con lo que hace falta para
    /// listarlos.
    ///
    /// Sólo las cabeceras que se muestran, y no el mensaje entero: una casilla
    /// con diez mil mensajes son gigabytes, y para pintar una lista alcanzan
    /// cuatro campos. El cuerpo se pide de a uno, cuando alguien abre algo.
    ///
    /// `BODY.PEEK` y no `BODY`: el segundo **marca el mensaje como leído** por el
    /// solo hecho de mirarlo. Que abrir la aplicación te vacíe el contador de sin
    /// leer sin que hayas leído nada es de los errores más molestos que puede
    /// tener un cliente de correo, y se comete escribiendo cuatro letras de
    /// menos.
    pub async fn recent_summaries(
        &mut self,
        messages: u32,
    ) -> Result<Vec<crate::message::MessageSummary>, ImapError> {
        let Some(range) = last_range(messages, RECENT_COUNT) else {
            return Ok(Vec::new());
        };

        self.fetch_summaries(&format!("FETCH {range}")).await
    }

    /// El `FETCH` de encabezados y lo que se hace con lo que vuelve.
    ///
    /// Está aparte porque lo usan dos: la lista de una casilla, que pide un
    /// rango de secuencia, y la búsqueda, que pide UID puntuales. Lo único que
    /// cambia es el comando; qué se pide y cómo se lee lo que vuelve es idéntico
    /// — y dos copias de eso son dos que se separan.
    async fn fetch_summaries(
        &mut self,
        command: &str,
    ) -> Result<Vec<crate::message::MessageSummary>, ImapError> {
        let tag = self.next_tag();
        // `CONTENT-TYPE` viene para saber si hay algo pegado. Es una pista y no
        // una certeza —un `multipart/mixed` puede ser texto con una imagen
        // incrustada—, pero cuesta cero y acierta casi siempre; saberlo de verdad
        // pide traer la estructura completa del mensaje.
        self.write_line(&format!(
            "{tag} {command} (UID FLAGS \
             BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE CONTENT-TYPE)])"
        ))
        .await?;

        Self::with_timeout("la lista de mensajes", async {
            let mut summaries = Vec::new();
            loop {
                let (line, literals) = self.read_response().await?;

                // **Sólo si trajo las cabeceras.** Mientras este comando corre, el
                // servidor puede intercalar un `FETCH` que nadie pidió: es cómo
                // avisa que otro dispositivo marcó algo como leído, y viene con
                // UID y sin literal. Tomarlo por un mensaje dejaba una fila en
                // blanco en la lista, y si después llegaba el de verdad, el
                // mismo mensaje aparecía dos veces.
                if let (Some(uid), Some(block)) = (uid_from(&line), literals.first()) {
                    // Sin etiqueta de juego de caracteres, que es lo correcto
                    // acá: una cabecera **no** vuelve a bytes nunca —lo que sale
                    // de `summary_from` es lo que se muestra—, así que la vista
                    // latin-1 que sirve para recorrer un cuerpo acá dejaría un
                    // `Subject` en UTF-8 crudo mostrándose como «ReuniÃ³n».
                    //
                    // Las palabras codificadas son ASCII y no se ven afectadas;
                    // lo que esto arregla son las cabeceras con bytes de ocho
                    // bits sin codificar, que el estándar no permite y los
                    // clientes mandan igual.
                    let headers = crate::message::decode_text(block, "");
                    let attachments = headers.to_ascii_lowercase().contains("multipart/mixed");
                    summaries.push(crate::message::summary_from(
                        uid,
                        &headers,
                        !is_seen(&line),
                        attachments,
                    ));
                }

                match tagged_status(&line, &tag) {
                    Some(TaggedStatus::Ok) => return Ok(summaries),
                    Some(TaggedStatus::No(d)) | Some(TaggedStatus::Bad(d)) => {
                        return Err(ImapError::Failed(format!("no se pudo listar: {d}")))
                    }
                    None => continue,
                }
            }
        })
        .await
    }

    /// El mensaje entero de un UID, tal como lo mandaron.
    ///
    /// Devuelve además si se cortó: se pide sólo el primer pedazo (ver
    /// `MAX_BODY`), y quien muestra el mensaje tiene que poder decir que hay
    /// más en vez de dejar el texto terminado a la mitad sin explicación.
    ///
    /// `BODY.PEEK` otra vez: abrir un mensaje **sí** lo marca como leído, pero eso
    /// lo decide la aplicación con un comando explícito, no el efecto secundario
    /// de haberlo traído.
    pub async fn fetch_body(&mut self, uid: u32) -> Result<(Vec<u8>, bool), ImapError> {
        let tag = self.next_tag();
        self.write_line(&format!(
            "{tag} UID FETCH {uid} (BODY.PEEK[]<0.{MAX_BODY}>)"
        ))
        .await?;

        Self::with_timeout("traer el mensaje", async {
            let mut raw: Vec<u8> = Vec::new();
            loop {
                let (line, literals) = self.read_response().await?;
                if let Some(bytes) = literals.into_iter().next() {
                    raw = bytes;
                }
                match tagged_status(&line, &tag) {
                    Some(TaggedStatus::Ok) => {
                        let truncated = raw.len() >= MAX_BODY;
                        return Ok((raw, truncated));
                    }
                    Some(TaggedStatus::No(d)) | Some(TaggedStatus::Bad(d)) => {
                        return Err(ImapError::Failed(format!("no se pudo traer: {d}")))
                    }
                    None => continue,
                }
            }
        })
        .await
    }

    /// Una parte suelta de un mensaje, con sus cabeceras.
    ///
    /// `parte` es el número del árbol MIME —`2`, `1.3`—, el mismo que devuelve
    /// `attachments::list`. Traer la parte sola y no el mensaje entero es lo que
    /// hace que se pueda bajar un adjunto de veinte megas sin traer los otros
    /// tres que venían con él.
    ///
    /// Vienen las cabeceras **y** el contenido, en dos pedidos: las cabeceras
    /// dicen cómo está codificado el contenido, y sin eso lo que se baja es un
    /// bloque de base64 que nadie sabe deshacer.
    ///
    /// El tope es el mismo que el del mensaje entero por ahora, y va explícito
    /// en el comando: un servidor puede anunciar el tamaño que quiera, y pedir
    /// «desde el byte cero, tantos» es lo que garantiza que no llegue más.
    /// Devuelve las cabeceras, el contenido, y **si se cortó**.
    ///
    /// Lo tercero no es un detalle. El tope va en el comando, así que un adjunto
    /// más grande llega recortado y con la misma pinta que uno entero: se
    /// guardaría un archivo que no abre ningún programa, sin nada que explique
    /// por qué. Es el mismo motivo por el que `cuerpo` devuelve `recortado`.
    pub async fn fetch_part(
        &mut self,
        uid: u32,
        part: &str,
        limit: usize,
    ) -> Result<(Vec<u8>, Vec<u8>, bool), ImapError> {
        if !is_valid_part(part) {
            return Err(ImapError::Failed(format!(
                "«{part}» no es un número de parte"
            )));
        }

        let tag = self.next_tag();
        self.write_line(&format!(
            "{tag} UID FETCH {uid} (BODY.PEEK[{part}.MIME] BODY.PEEK[{part}]<0.{limit}>)"
        ))
        .await?;

        Self::with_timeout("traer la parte", async {
            let mut received: Vec<Vec<u8>> = Vec::new();
            loop {
                let (line, literals) = self.read_response().await?;
                received.extend(literals);
                match tagged_status(&line, &tag) {
                    Some(TaggedStatus::Ok) => {
                        // En el orden en que se pidieron: primero las cabeceras
                        // de la parte, después su contenido. Si viniera uno
                        // solo, no se adivina cuál es.
                        if received.len() < 2 {
                            return Err(ImapError::Failed(
                                "el servidor no mandó la parte completa".into(),
                            ));
                        }
                        let content = received.pop().unwrap_or_default();
                        let headers = received.pop().unwrap_or_default();
                        // Llegó justo el tope: o cabía exacto, o hay más. No se
                        // puede distinguir desde acá, y decir «puede estar
                        // cortado» de un archivo que estaba entero es mucho
                        // menos malo que callar uno que sí se cortó.
                        let truncated = content.len() >= limit;
                        return Ok((headers, content, truncated));
                    }
                    Some(TaggedStatus::No(d)) | Some(TaggedStatus::Bad(d)) => {
                        return Err(ImapError::Failed(format!("no se pudo traer la parte: {d}")))
                    }
                    None => continue,
                }
            }
        })
        .await
    }

    /// Marca un mensaje como leído en el servidor.
    ///
    /// En el servidor y no sólo acá: la persona lee en el teléfono y en el
    /// escritorio, y un «leído» que no viaja hace que el mismo mensaje aparezca
    /// sin leer en el otro lado para siempre.
    ///
    /// Necesita la casilla abierta con `SELECT`. Con `EXAMINE` —que es como la
    /// abre el bucle que sólo cuenta— el servidor contesta que es de sólo
    /// lectura, y eso es correcto: cambiar banderas es una decisión de la
    /// persona, no un efecto de estar sincronizando.
    pub async fn mark_read(&mut self, uid: u32) -> Result<(), ImapError> {
        self.command(&format!("UID STORE {uid} +FLAGS (\\Seen)"))
            .await
    }

    /// Mueve un mensaje a otra casilla.
    ///
    /// # Los tres caminos, y por qué el tercero no borra
    ///
    /// Con `MOVE` (RFC 6851) es un solo comando y el servidor se encarga.
    ///
    /// Sin `MOVE` pero con `UIDPLUS` (RFC 4315): `UID COPY`, marcar `\Deleted`,
    /// y `UID EXPUNGE` **de ese UID**, que borra ese y nada más.
    ///
    /// Sin ninguno de los dos se copia y se marca, y **no se expurga**. Un
    /// `EXPUNGE` a secas borra de la casilla *todos* los mensajes marcados
    /// `\Deleted`, no el nuestro: si la persona tiene mensajes marcados desde
    /// otro cliente —hay clientes que marcan y no expurgan— mover uno le
    /// borraría los otros para siempre. Dejar una copia de más es un problema
    /// que se ve y se arregla; borrar correo ajeno a la operación no se deshace.
    pub async fn move_to(&mut self, uid: u32, destination: &str) -> Result<MoveOutcome, ImapError> {
        let name = quoted(destination)
            .ok_or_else(|| ImapError::Failed("el nombre de la casilla no es válido".into()))?;

        if self.capabilities.iter().any(|c| c == "MOVE") {
            self.command(&format!("UID MOVE {uid} {name}")).await?;
            return Ok(MoveOutcome::Complete);
        }

        // La copia primero. Si falla, no se marcó nada y el mensaje sigue donde
        // estaba: el orden es lo que hace que un fallo a mitad de camino no
        // pierda nada.
        self.command(&format!("UID COPY {uid} {name}")).await?;
        self.command(&format!("UID STORE {uid} +FLAGS (\\Deleted)"))
            .await?;

        if self.capabilities.iter().any(|c| c == "UIDPLUS") {
            self.command(&format!("UID EXPUNGE {uid}")).await?;
            return Ok(MoveOutcome::Complete);
        }

        Ok(MoveOutcome::OldCopyKept)
    }

    /// Abre una casilla **para escribir** y devuelve cuántos mensajes tiene.
    ///
    /// Se usa sólo cuando hay que cambiar una bandera. El resto del tiempo la
    /// casilla se abre con `EXAMINE`, que no puede tocar nada.
    pub async fn select(&mut self, mailbox: &str) -> Result<u32, ImapError> {
        self.open_mailbox("SELECT", mailbox).await
    }

    /// Lee una respuesta entera, con sus literales.
    ///
    /// Una respuesta puede ocupar varias líneas: cada `{N}` al final de una
    /// significa que siguen N bytes crudos y después continúa la respuesta. Se
    /// devuelven el texto —con los literales sacados— y los bloques de bytes
    /// aparte, **sin convertirlos a texto**: el juego de caracteres de un
    /// mensaje lo decide el mensaje, y pasarlos por UTF-8 acá destruiría los
    /// acentos de todo el correo viejo antes de que nadie pueda arreglarlo.
    async fn read_response(&mut self) -> Result<(String, Vec<Vec<u8>>), ImapError> {
        let mut text = String::new();
        let mut literals: Vec<Vec<u8>> = Vec::new();

        loop {
            let line = self.read_line().await?;
            let Some(count) = literal_length(&line) else {
                text.push_str(&line);
                return Ok((text, literals));
            };

            if count > MAX_BODY {
                // **Esta conexión ya no sirve.**
                //
                // El servidor escribió esos bytes en el socket antes de que este
                // control corriera. Volver sin leerlos los deja ahí, y la
                // próxima lectura arranca en el medio del mensaje e interpreta
                // el correo de alguien como si fueran líneas del protocolo — que
                // es exactamente el desastre que este lector existe para evitar.
                //
                // Leerlos igual tampoco sirve: son más de los que se pidieron,
                // así que el número lo elige el servidor y podrían ser
                // gigabytes. Se avisa que la sesión quedó rota, y quien la tenga
                // la tira y abre otra.
                return Err(ImapError::Desynced(format!(
                    "el servidor anunció {count} bytes, más de los {MAX_BODY} que se piden"
                )));
            }
            // Sin la marca `{N}`: es del protocolo y no del mensaje.
            if let Some(marker) = line.rfind('{') {
                text.push_str(&line[..marker]);
            }
            literals.push(self.read_bytes(count).await?);
        }
    }

    /// Lee exactamente `count` bytes, empezando por lo que ya esté en el búfer.
    async fn read_bytes(&mut self, count: usize) -> Result<Vec<u8>, ImapError> {
        while self.pending.len() < count {
            let read_count = self
                .stream
                .read_buf(&mut self.pending)
                .await
                .map_err(|e| ImapError::Failed(format!("no se pudo leer: {e}")))?;
            if read_count == 0 {
                return Err(ImapError::Failed(
                    "el servidor cortó la conexión en medio de un mensaje".into(),
                ));
            }
        }
        Ok(self.pending.drain(..count).collect())
    }

    fn next_tag(&mut self) -> String {
        self.tag += 1;
        format!("a{}", self.tag)
    }

    /// Manda un comando y espera su respuesta con etiqueta.
    async fn command(&mut self, command: &str) -> Result<(), ImapError> {
        let tag = self.next_tag();
        self.write_line(&format!("{tag} {command}")).await?;

        Self::with_timeout("la respuesta al comando", async {
            loop {
                let line = self.read_line().await?;
                match tagged_status(&line, &tag) {
                    Some(TaggedStatus::Ok) => return Ok(()),
                    // `NO` es el servidor entendiendo y diciendo que no: casi
                    // siempre, credenciales. Se distingue porque insistir con una
                    // contraseña rechazada es cómo se bloquea una cuenta.
                    Some(TaggedStatus::No(d)) => return Err(ImapError::Rejected(d)),
                    Some(TaggedStatus::Bad(d)) => {
                        return Err(ImapError::Failed(format!("el servidor no entendió: {d}")))
                    }
                    None => continue,
                }
            }
        })
        .await
    }

    async fn write_line(&mut self, line: &str) -> Result<(), ImapError> {
        let writing = async {
            self.stream.write_all(line.as_bytes()).await?;
            self.stream.write_all(b"\r\n").await?;
            self.stream.flush().await
        };
        writing
            .await
            .map_err(|e| ImapError::Failed(format!("no se pudo escribir: {e}")))
    }

    /// Lee una línea, y **se puede cancelar sin perder nada**.
    ///
    /// Todo lo que llega del socket va a un búfer propio antes de partirse en
    /// líneas, así que si quien llama abandona la espera —con un tiempo límite,
    /// por ejemplo— lo leído sigue ahí para la próxima. Es lo que hace posible
    /// esperar en IDLE con un reloj al lado.
    async fn read_line(&mut self) -> Result<String, ImapError> {
        loop {
            if let Some(line) = line_from_buffer(&mut self.pending) {
                return Ok(line);
            }
            if self.pending.len() as u64 > MAX_LINE {
                return Err(ImapError::Failed(
                    "el servidor mandó una línea sin fin".into(),
                ));
            }

            let read_count = self
                .stream
                .read_buf(&mut self.pending)
                .await
                .map_err(|e| ImapError::Failed(format!("no se pudo leer: {e}")))?;
            if read_count == 0 {
                return Err(ImapError::Failed("el servidor cortó la conexión".into()));
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt as _, BufReader};

    /// Una sesión contra un servidor de mentira, para ejercer la conversación.
    ///
    /// # Por qué hace falta
    ///
    /// Todas las pruebas de este archivo eran de analizadores sueltos: se les
    /// da una línea y se mira qué devuelven. Eso no comprueba **la
    /// conversación**, que es donde están los errores que importan: mandar
    /// `FETCH` sin haber abierto la casilla, confundir una respuesta sin
    /// etiqueta con la del comando en curso, o quedarse esperando una línea que
    /// ya llegó. El issue que pide todo esto dice que la fase está sin verificar
    /// contra un servidor real, y esto no lo reemplaza — pero cubre lo que sí se
    /// puede comprobar sin uno.
    ///
    /// `script` son pares de «lo que se espera recibir» y «lo que se contesta».
    /// El servidor de mentira comprueba que el comando contenga lo esperado y
    /// falla la prueba si no, así que el orden de los comandos queda fijado.
    fn with_server(
        greeting: &str,
        script: Vec<(&'static str, Vec<&'static str>)>,
    ) -> (
        Session<tokio::io::DuplexStream>,
        tokio::task::JoinHandle<Vec<String>>,
    ) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let greeting = greeting.to_string();

        let task = tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(server);
            let mut lines = BufReader::new(reader).lines();
            let mut received = Vec::new();
            let mut tag = String::from("a1");
            let mut awaiting_literal = false;

            writer.write_all(greeting.as_bytes()).await.unwrap();
            writer.write_all(b"\r\n").await.unwrap();

            for (expected, reply) in script {
                let Ok(Some(line)) = lines.next_line().await else {
                    break;
                };
                assert!(
                    line.contains(expected),
                    "se esperaba un comando con «{expected}» y llegó «{line}»"
                );
                received.push(line.clone());

                // La etiqueta que mandó el cliente, para poder contestarle con
                // la suya: usar una fija haría pasar una prueba que en la vida
                // real se colgaría esperando.
                //
                // **Salvo después de un `+`.** Lo que sigue a una continuación
                // son los bytes de un literal, no un comando: no empiezan con
                // etiqueta, y tomarles la primera palabra por una haría
                // contestar con una etiqueta inventada. Es lo que hace un
                // servidor de verdad, y sin esto la prueba del término con
                // acentos se colgaba esperando una respuesta que nunca
                // emparejaba.
                if !awaiting_literal {
                    tag = line.split_whitespace().next().unwrap_or("a1").to_string();
                }
                awaiting_literal = reply.iter().any(|l| l.starts_with('+'));

                for l in reply {
                    let l = l.replace("{tag}", &tag);
                    writer.write_all(l.as_bytes()).await.unwrap();
                    writer.write_all(b"\r\n").await.unwrap();
                }
            }

            received
        });

        let session = Session {
            stream: client,
            pending: Vec::new(),
            tag: 0,
            capabilities: Vec::new(),
            uidvalidity: None,
        };
        (session, task)
    }

    #[tokio::test]
    async fn buscar_manda_uid_search_con_el_juego_declarado() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![(
                "UID SEARCH CHARSET UTF-8 FROM \"ana\"",
                vec!["* SEARCH 3 7 11", "{tag} OK SEARCH completado"],
            )],
        );

        let uids = session
            .search(&[crate::query::Term::Sender("ana".into())])
            .await
            .unwrap();
        task.await.unwrap();
        assert_eq!(uids, vec![3, 7, 11]);
    }

    /// Hay servidores viejos que rechazan el juego declarado. El estándar
    /// permite mandarlo sin declarar, y es lo que hacen todos los clientes.
    #[tokio::test]
    async fn si_rechazan_el_juego_se_reintenta_sin_el() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![
                (
                    "CHARSET UTF-8",
                    vec!["{tag} NO [BADCHARSET] UTF-8 no soportado"],
                ),
                (
                    "UID SEARCH FROM \"ana\"",
                    vec!["* SEARCH 5", "{tag} OK completado"],
                ),
            ],
        );

        let uids = session
            .search(&[crate::query::Term::Sender("ana".into())])
            .await
            .unwrap();
        let received = task.await.unwrap();

        assert_eq!(uids, vec![5]);
        assert_eq!(received.len(), 2, "tenía que reintentar una vez");
        assert!(!received[1].contains("CHARSET"));
    }

    /// Un `NO` que no es por el juego de caracteres no se reintenta: mandar dos
    /// veces un comando que ya se sabe que falla no arregla nada.
    #[tokio::test]
    async fn otro_rechazo_no_se_reintenta() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![("UID SEARCH", vec!["{tag} NO no se puede"])],
        );

        assert!(session
            .search(&[crate::query::Term::Sender("ana".into())])
            .await
            .is_err());
        assert_eq!(task.await.unwrap().len(), 1);
    }

    /// Un término que no es ASCII va como literal: se anuncia el largo **en
    /// bytes**, el servidor contesta `+` y recién ahí van los bytes.
    #[tokio::test]
    async fn un_termino_con_acentos_va_como_literal() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![
                // «reunión» son 8 bytes en UTF-8, no 7 caracteres. Mandar 7
                // dejaría la sesión desincronizada.
                ("SUBJECT {8}", vec!["+ dale"]),
                ("reunión", vec!["* SEARCH 9", "{tag} OK completado"]),
            ],
        );

        let uids = session
            .search(&[crate::query::Term::Subject("reunión".into())])
            .await
            .unwrap();
        task.await.unwrap();
        assert_eq!(uids, vec![9]);
    }

    /// Sin criterio, `SEARCH` devolvería la casilla entera. Eso no es una
    /// búsqueda vacía: es todo, y contestar nada es más honesto.
    #[tokio::test]
    async fn sin_criterio_no_se_manda_nada() {
        let (mut session, task) = with_server("* OK listo", vec![]);
        assert!(session.search(&[]).await.unwrap().is_empty());
        assert!(task.await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn una_busqueda_sin_resultados_no_es_un_error() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![("UID SEARCH", vec!["* SEARCH", "{tag} OK completado"])],
        );

        let uids = session
            .search(&[crate::query::Term::Sender("nadie".into())])
            .await
            .unwrap();
        task.await.unwrap();
        assert!(uids.is_empty());
    }

    /// Una búsqueda amplia puede traer diez mil UID. Pedir los encabezados de
    /// todos llena la memoria de la ventana con algo que nadie va a leer.
    #[tokio::test]
    async fn los_resumenes_de_una_busqueda_se_acotan_a_los_mas_nuevos() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![("UID FETCH", vec!["{tag} OK completado"])],
        );

        let many: Vec<u32> = (1..=500).collect();
        session.summaries_of(&many).await.unwrap();
        let received = task.await.unwrap();

        let requested = received[0].split(',').count();
        assert_eq!(requested, RECENT_COUNT as usize);
        // Y son los más nuevos: el primero de la lista es el UID más alto.
        assert!(received[0].contains("UID FETCH 500,499,"));
    }

    #[test]
    fn un_numero_de_parte_tiene_forma_de_numero_de_parte() {
        for good in ["1", "2", "1.3", "1.2.3.4", "12"] {
            assert!(is_valid_part(good), "{good}");
        }
    }

    /// Va crudo en el comando. El número sale de recorrer el árbol de un mensaje
    /// que mandó cualquiera, así que una parte con un espacio y una palabra
    /// clave adentro sería un comando distinto del que se quiso mandar.
    #[test]
    fn lo_que_no_es_un_numero_de_parte_se_rechaza() {
        for bad in [
            "",
            "1 BODY[]",
            "1.",
            ".1",
            "1..2",
            "uno",
            "1;2",
            "*",
            "99999",
            "1\r\na1 LOGOUT",
        ] {
            assert!(!is_valid_part(bad), "pasó: {bad:?}");
        }
    }

    #[tokio::test]
    async fn traer_una_parte_pide_sus_cabeceras_y_su_contenido() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![(
                "BODY.PEEK[2.MIME] BODY.PEEK[2]",
                vec![
                    "* 1 FETCH (UID 5 BODY[2.MIME] {47}",
                    "Content-Transfer-Encoding: base64\r\n\r\n",
                    " BODY[2]<0> {8}",
                    "SGkgdGhl",
                    ")",
                    "{tag} OK FETCH completado",
                ],
            )],
        );

        let (headers, content, truncated) = session.fetch_part(5, "2", 1024).await.unwrap();
        task.await.unwrap();

        assert!(String::from_utf8_lossy(&headers).contains("base64"));
        assert_eq!(content, b"SGkgdGhl");
        assert!(!truncated);
    }

    /// El tope va en el comando, así que un adjunto más grande llega recortado
    /// y con la misma pinta que uno entero: se guardaría un archivo que no abre
    /// ningún programa, sin nada que explique por qué.
    #[tokio::test]
    async fn una_parte_que_llega_al_tope_se_dice_recortada() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![(
                "BODY.PEEK",
                vec![
                    "* 1 FETCH (UID 5 BODY[2.MIME] {2}",
                    "x\r\n",
                    " BODY[2]<0> {8}",
                    "AAAABBBB",
                    ")",
                    "{tag} OK completado",
                ],
            )],
        );

        // Se pide un tope de 8 y llegan 8: o cabía exacto, o hay más. No se
        // puede distinguir, y decir «puede estar cortado» de algo que estaba
        // entero es mucho menos malo que callar lo que sí se cortó.
        let (_, _, truncated) = session.fetch_part(5, "2", 8).await.unwrap();
        task.await.unwrap();
        assert!(truncated);
    }

    /// Si viniera un solo literal no se puede adivinar cuál es: devolver el
    /// contenido tomándolo por cabeceras dejaría un archivo vacío, y al revés
    /// un archivo con el encabezado adentro.
    #[tokio::test]
    async fn una_parte_a_medias_es_un_error() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![(
                "BODY.PEEK",
                vec![
                    "* 1 FETCH (UID 5 BODY[2] {4}",
                    "AAAA",
                    ")",
                    "{tag} OK completado",
                ],
            )],
        );

        assert!(session.fetch_part(5, "2", 1024).await.is_err());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn una_parte_invalida_no_llega_al_servidor() {
        let (mut session, task) = with_server("* OK listo", vec![]);
        assert!(session.fetch_part(5, "1 BODY[]", 1024).await.is_err());
        // Y no se mandó nada: el comando ni se arma.
        assert!(task.await.unwrap().is_empty());
    }

    /// Con `MOVE` es un solo comando y el servidor se encarga.
    #[tokio::test]
    async fn con_move_se_manda_uno_solo() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![("UID MOVE 7 \"Papelera\"", vec!["{tag} OK MOVE completado"])],
        );
        session.capabilities = vec!["MOVE".into(), "UIDPLUS".into()];

        assert_eq!(
            session.move_to(7, "Papelera").await.unwrap(),
            MoveOutcome::Complete
        );
        assert_eq!(task.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn sin_move_pero_con_uidplus_se_copia_marca_y_expurga_ese() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![
                ("UID COPY 7 \"Papelera\"", vec!["{tag} OK completado"]),
                (
                    "UID STORE 7 +FLAGS (\\Deleted)",
                    vec!["{tag} OK completado"],
                ),
                ("UID EXPUNGE 7", vec!["{tag} OK completado"]),
            ],
        );
        session.capabilities = vec!["UIDPLUS".into()];

        assert_eq!(
            session.move_to(7, "Papelera").await.unwrap(),
            MoveOutcome::Complete
        );
        let received = task.await.unwrap();
        assert_eq!(received.len(), 3);
        // El UID **en** el expurgo: `EXPUNGE` a secas borraría todo lo marcado.
        assert!(received[2].contains("UID EXPUNGE 7"));
    }

    /// El caso que importa. `EXPUNGE` a secas borra de la casilla **todos** los
    /// mensajes marcados `\Deleted`, no el nuestro. Si la persona tiene
    /// mensajes marcados desde otro cliente, mover uno le borraría los otros
    /// para siempre.
    #[tokio::test]
    async fn sin_uidplus_no_se_expurga_nada() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![
                ("UID COPY 7", vec!["{tag} OK completado"]),
                ("UID STORE 7 +FLAGS", vec!["{tag} OK completado"]),
            ],
        );
        session.capabilities = vec![];

        assert_eq!(
            session.move_to(7, "Papelera").await.unwrap(),
            MoveOutcome::OldCopyKept
        );
        let received = task.await.unwrap();
        assert_eq!(received.len(), 2, "no tenía que mandar un tercer comando");
        for command in &received {
            assert!(
                !command.to_ascii_uppercase().contains("EXPUNGE"),
                "mandó un expurgo: {command}"
            );
        }
    }

    /// El orden es lo que hace que un fallo a mitad de camino no pierda nada: si
    /// la copia falla, el mensaje sigue entero donde estaba y sin marcar.
    #[tokio::test]
    async fn si_la_copia_falla_no_se_marca_nada() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![(
                "UID COPY",
                vec!["{tag} NO [TRYCREATE] la casilla no existe"],
            )],
        );
        session.capabilities = vec!["UIDPLUS".into()];

        assert!(session.move_to(7, "NoExiste").await.is_err());
        assert_eq!(task.await.unwrap().len(), 1, "no tenía que marcar nada");
    }

    /// Una casilla con espacios sin comillas son dos argumentos, y el servidor
    /// contesta un error — o peor, mueve a otro lado.
    #[tokio::test]
    async fn la_casilla_de_destino_va_entre_comillas() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![("UID MOVE 7 \"[Gmail]/Trash\"", vec!["{tag} OK completado"])],
        );
        session.capabilities = vec!["MOVE".into()];

        session.move_to(7, "[Gmail]/Trash").await.unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn un_destino_invalido_no_llega_al_servidor() {
        let (mut session, task) = with_server("* OK listo", vec![]);
        session.capabilities = vec!["MOVE".into()];
        assert!(session.move_to(7, "con\r\nsalto").await.is_err());
        assert!(task.await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn listar_casillas_manda_list_y_junta_lo_que_vuelve() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![(
                "LIST \"\" \"*\"",
                vec![
                    r#"* LIST (\HasNoChildren) "/" "INBOX""#,
                    r#"* LIST (\HasNoChildren \Sent) "/" "[Gmail]/Sent Mail""#,
                    r#"* LIST (\Noselect \HasChildren) "/" "[Gmail]""#,
                    "{tag} OK LIST completado",
                ],
            )],
        );

        let mailboxes = session.list_mailboxes().await.unwrap();
        task.await.unwrap();

        assert_eq!(mailboxes.len(), 3);
        assert_eq!(mailboxes[0].path, "INBOX");
        assert_eq!(mailboxes[1].role, crate::mailboxes::MailboxRole::Sent);
        // La `\Noselect` viene igual y marcada: hace falta para dibujar el
        // árbol, y quien la muestre decide si la ofrece.
        assert!(!mailboxes[2].selectable);
    }

    /// Es el caso que un analizador suelto no puede cubrir: las respuestas sin
    /// etiqueta se juntan y el comando termina **cuando llega la suya**, no con
    /// la primera línea que se parezca.
    #[tokio::test]
    async fn una_respuesta_sin_etiqueta_no_termina_el_comando() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![(
                "LIST",
                vec![
                    "* 4 EXISTS",
                    "* OK [UNSEEN 2] algo",
                    r#"* LIST (\HasNoChildren) "/" "Trabajo""#,
                    "* 1 RECENT",
                    "{tag} OK LIST completado",
                ],
            )],
        );

        let mailboxes = session.list_mailboxes().await.unwrap();
        task.await.unwrap();
        assert_eq!(mailboxes.len(), 1);
        assert_eq!(mailboxes[0].path, "Trabajo");
    }

    #[tokio::test]
    async fn abrir_una_casilla_lee_cuantos_hay_y_el_uidvalidity() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![(
                "EXAMINE \"INBOX\"",
                vec![
                    "* FLAGS (\\Seen \\Answered)",
                    "* 42 EXISTS",
                    "* OK [UIDVALIDITY 3857529045] UIDs valid",
                    "* OK [UIDNEXT 4392] Predicted next UID",
                    "{tag} OK [READ-ONLY] EXAMINE completado",
                ],
            )],
        );

        let count = session.examine("INBOX").await.unwrap();
        task.await.unwrap();

        assert_eq!(count, 42);
        assert_eq!(session.uidvalidity(), Some(3857529045));
    }

    /// La casilla va **entre comillas** en el comando. Sin ellas, una con
    /// espacios —«Sent Mail», que es la de Gmail— se lee como dos argumentos y
    /// el servidor contesta un error.
    #[tokio::test]
    async fn una_casilla_con_espacios_va_entre_comillas() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![(
                "EXAMINE \"[Gmail]/Sent Mail\"",
                vec!["* 3 EXISTS", "{tag} OK completado"],
            )],
        );

        assert_eq!(session.examine("[Gmail]/Sent Mail").await.unwrap(), 3);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn un_no_del_servidor_es_un_error_y_no_una_lista_vacia() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![("EXAMINE", vec!["{tag} NO [NONEXISTENT] Unknown Mailbox"])],
        );

        let failure = session.examine("NoExiste").await.unwrap_err();
        task.await.unwrap();

        // Devolver cero mensajes diría «esta carpeta está vacía», que es otra
        // cosa muy distinta de «esta carpeta no existe».
        assert!(
            failure.to_string().contains("NoExiste"),
            "el error tiene que nombrar la casilla: {failure}"
        );
    }

    /// Cada comando lleva su propia etiqueta, creciente. Repetirlas haría que
    /// la respuesta de uno se tome como la del siguiente.
    #[tokio::test]
    async fn cada_comando_lleva_su_etiqueta() {
        let (mut session, task) = with_server(
            "* OK listo",
            vec![
                ("EXAMINE", vec!["* 1 EXISTS", "{tag} OK completado"]),
                ("LIST", vec!["{tag} OK completado"]),
            ],
        );

        session.examine("INBOX").await.unwrap();
        session.list_mailboxes().await.unwrap();
        let received = task.await.unwrap();

        assert_eq!(received.len(), 2);
        let first = received[0].split_whitespace().next().unwrap();
        let second = received[1].split_whitespace().next().unwrap();
        assert_ne!(first, second, "dos comandos con la misma etiqueta");
    }
    use super::*;

    /// Sin reconocer el literal, esos bytes se leen como si fueran líneas del
    /// protocolo: el mensaje se parte en pedazos y la conexión queda
    /// desincronizada **para siempre**, porque todo lo que venga después se
    /// interpreta corrido.
    #[test]
    fn se_reconoce_el_anuncio_de_un_literal() {
        assert_eq!(literal_length("* 1 FETCH (UID 5 BODY[] {1234}"), Some(1234));
        // LITERAL+: el servidor no espera confirmación. Significa lo mismo para
        // quien lee, y no reconocerlo es el mismo desastre.
        assert_eq!(
            literal_length("* 1 FETCH (UID 5 BODY[] {1234+}"),
            Some(1234)
        );
        assert_eq!(literal_length("* 1 FETCH (UID 5 FLAGS (\\Seen))"), None);
        assert_eq!(literal_length("a1 OK FETCH completado"), None);
        assert_eq!(literal_length("{no es un número}"), None);
        assert_eq!(literal_length(""), None);
    }

    /// El UID y no el número de secuencia: el número cambia en cuanto se borra
    /// cualquier mensaje anterior, así que guardarlo sería guardar algo que
    /// mañana apunta a otro mensaje.
    #[test]
    fn se_saca_el_uid_de_un_fetch() {
        assert_eq!(uid_from("* 12 FETCH (UID 345 FLAGS (\\Seen))"), Some(345));
        // El orden de los campos lo elige el servidor.
        assert_eq!(uid_from("* 12 FETCH (FLAGS () UID 7)"), Some(7));
        assert_eq!(uid_from("* 12 FETCH (FLAGS ())"), None);
    }

    /// «UID» tiene que ser la palabra y no el final de otra, o cualquier campo
    /// que termine así daría un identificador inventado.
    #[test]
    fn una_palabra_que_termina_en_uid_no_es_el_uid() {
        assert_eq!(uid_from("* 1 FETCH (X-MYUID 999 UID 3)"), Some(3));
        assert_eq!(uid_from("* 1 FETCH (X-MYUID 999)"), None);
    }

    /// Se mira dentro de `FLAGS (...)`: un asunto que diga «Seen» no puede
    /// marcar un mensaje como leído.
    #[test]
    fn lo_leido_se_mira_solo_en_las_banderas() {
        assert!(is_seen("* 1 FETCH (FLAGS (\\Seen \\Answered) UID 3)"));
        assert!(!is_seen("* 1 FETCH (FLAGS (\\Answered) UID 3)"));
        assert!(!is_seen("* 1 FETCH (FLAGS () UID 3)"));
        // El asunto viene en un literal aparte, pero por las dudas.
        assert!(!is_seen("* 1 FETCH (FLAGS () BODY[HEADER] Seen this?)"));
    }

    /// Mientras corre el `FETCH`, el servidor puede intercalar uno que nadie
    /// pidió: es cómo avisa que otro dispositivo marcó algo como leído. Viene
    /// con UID y **sin literal**, y tomarlo por un mensaje dejaba una fila en
    /// blanco en la lista — y si después llegaba el de verdad, el mismo mensaje
    /// aparecía dos veces.
    #[test]
    fn un_fetch_sin_literal_no_es_un_mensaje() {
        // El aviso trae UID, así que `uid_from` lo reconoce: lo que lo distingue
        // es que no viene con cabeceras.
        let notice = "* 7 FETCH (UID 12 FLAGS (\\Seen))";
        assert_eq!(uid_from(notice), Some(12));
        assert_eq!(literal_length(notice), None);
    }

    /// Un literal más grande de lo que se pidió deja la conexión inservible: sus
    /// bytes ya están en el socket, y lo que venga después se va a leer corrido.
    /// Tiene que distinguirse de un fallo cualquiera, que sí deja seguir.
    #[test]
    fn una_desincronizacion_no_es_un_fallo_cualquiera() {
        let broken = ImapError::Desynced("anunció de más".into());
        assert!(matches!(broken, ImapError::Desynced(_)));
        assert!(broken.to_string().contains("desincronizada"), "{broken}");

        // Y no se confunde con las otras dos, que son las que dejan la sesión
        // utilizable o mandan a dejar de reintentar.
        assert!(!matches!(
            ImapError::Failed("x".into()),
            ImapError::Desynced(_)
        ));
        assert!(!matches!(
            ImapError::Rejected("x".into()),
            ImapError::Desynced(_)
        ));
    }

    /// Pedir `1:0` es un error de sintaxis, y hay servidores que ante uno cortan
    /// la sesión en vez de contestar. Una casilla vacía es de lo más común: una
    /// carpeta recién creada, o una cuenta nueva.
    #[test]
    fn una_casilla_vacia_no_genera_un_rango_invalido() {
        assert_eq!(last_range(0, RECENT_COUNT), None);
        assert_eq!(last_range(10, 0), None);
    }

    #[test]
    fn el_rango_toma_los_ultimos_y_no_se_pasa_del_principio() {
        assert_eq!(last_range(1000, 200), Some("801:1000".into()));
        // Con menos mensajes que el tope, se piden todos: no hay un `0:` ni un
        // número negativo dado vuelta.
        assert_eq!(last_range(5, 200), Some("1:5".into()));
        assert_eq!(last_range(1, 200), Some("1:1".into()));
    }

    /// El formato del XOAUTH2 lo fijan Google y Microsoft y no se parece a nada
    /// más del protocolo. Escribirlo con espacios o dos puntos, que es lo
    /// intuitivo, da un rechazo que parece de credenciales y no lo es.
    #[test]
    fn el_xoauth2_usa_el_separador_que_fija_el_proveedor() {
        let payload = xoauth2_payload("ana@ejemplo.com", "el-token");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&payload)
            .unwrap();

        assert_eq!(raw, b"user=ana@ejemplo.com\x01auth=Bearer el-token\x01\x01");
        // Y termina en dos separadores, no en uno: los servidores rechazan la
        // carga si falta el último.
        assert!(raw.ends_with(b"\x01\x01"));
    }

    #[test]
    fn una_credencial_con_salto_de_linea_no_se_manda() {
        for poison in ["a\r\nA1 LOGOUT", "a\nb", "a\rb", "a\0b"] {
            assert_eq!(quoted(poison), None, "{poison:?} tenía que rechazarse");
        }
    }

    #[test]
    fn las_comillas_y_las_barras_se_escapan() {
        assert_eq!(quoted("simple").unwrap(), "\"simple\"");
        assert_eq!(quoted(r#"con"comilla"#).unwrap(), r#""con\"comilla""#);
        // El orden importa: escapar la comilla primero dejaría sin escapar la
        // barra que se acaba de agregar.
        assert_eq!(quoted(r#"\""#).unwrap(), r#""\\\"""#);
    }

    #[test]
    fn se_reconoce_la_respuesta_con_etiqueta() {
        assert_eq!(tagged_status("a1 OK listo", "a1"), Some(TaggedStatus::Ok));
        assert_eq!(tagged_status("a1 ok listo", "a1"), Some(TaggedStatus::Ok));
        assert_eq!(
            tagged_status("a1 NO [AUTHENTICATIONFAILED] mal", "a1"),
            Some(TaggedStatus::No("[AUTHENTICATIONFAILED] mal".into()))
        );
    }

    /// Una etiqueta que es prefijo de otra no puede confundirse: con diez
    /// comandos en una sesión, `a1` no tiene que emparejar con `a10`.
    #[test]
    fn una_etiqueta_no_empareja_con_otra_mas_larga() {
        assert_eq!(tagged_status("a10 OK listo", "a1"), None);
        assert_eq!(tagged_status("* OK sin etiqueta", "a1"), None);
        assert_eq!(tagged_status("+ continuá", "a1"), None);
    }

    /// Las capacidades llegan de dos formas y hay servidores que sólo usan una:
    /// pegadas al saludo entre corchetes, o en su propia línea. Leer sólo una
    /// haría que IDLE se diera por no soportado contra la mitad de los
    /// servidores que sí lo tienen.
    #[test]
    fn las_capacidades_se_leen_del_saludo_y_de_su_propia_linea() {
        let from_greeting = capabilities_from("* OK [CAPABILITY IMAP4rev1 IDLE LITERAL+] listo");
        assert!(from_greeting.contains(&"IDLE".to_string()));
        assert!(from_greeting.contains(&"IMAP4REV1".to_string()));
        // Y no se lleva lo que viene después del corchete.
        assert!(!from_greeting.iter().any(|c| c.contains("LISTO")));

        let from_own_line = capabilities_from("* CAPABILITY IMAP4rev1 IDLE UIDPLUS");
        assert!(from_own_line.contains(&"IDLE".to_string()));
        assert!(from_own_line.contains(&"UIDPLUS".to_string()));
    }

    /// En minúsculas también: el protocolo no distingue, y un servidor que
    /// anuncie `idle` soporta IDLE igual.
    #[test]
    fn las_capacidades_no_distinguen_mayusculas() {
        assert!(capabilities_from("* capability imap4rev1 idle").contains(&"IDLE".to_string()));
    }

    #[test]
    fn una_linea_sin_capacidades_no_devuelve_ninguna() {
        for another in ["", "* OK listo", "a1 OK", "* 5 EXISTS"] {
            assert!(capabilities_from(another).is_empty(), "{another:?}");
        }
    }

    #[test]
    fn se_lee_cuantos_mensajes_hay() {
        assert_eq!(exists_count("* 42 EXISTS"), Some(42));
        assert_eq!(exists_count("* 0 EXISTS"), Some(0));
        // Y no se confunde con otras respuestas que también llevan un número.
        for another in ["* 3 RECENT", "* 7 EXPUNGE", "* OK listo", "", "* EXISTS"] {
            assert_eq!(exists_count(another), None, "{another:?}");
        }
    }

    /// Los números del SEARCH son identificadores de mensaje: lo único que hace
    /// falta es cuántos hay. Sumarlos, que es el error fácil, daría un contador
    /// disparatado.
    #[test]
    fn del_search_se_cuentan_los_resultados() {
        assert_eq!(search_result_count("* SEARCH 3 5 9"), Some(3));
        assert_eq!(search_result_count("* SEARCH 100"), Some(1));
        // Sin resultados: la casilla está toda leída.
        assert_eq!(search_result_count("* SEARCH"), Some(0));
        assert_eq!(search_result_count("* search 1 2"), Some(2));
        assert_eq!(search_result_count("* OK listo"), None);
    }

    /// Qué avisos hacen que valga la pena volver a contar.
    ///
    /// `EXISTS` es correo nuevo, `EXPUNGE` un borrado y `FETCH` una marca que
    /// cambió desde otro dispositivo. `RECENT` **no**: hay servidores que lo
    /// repiten sin que haya nada nuevo, y despertarse por él sería contar de más
    /// sin motivo.
    #[test]
    fn se_reconoce_lo_que_cambia_de_lo_que_no() {
        for changed in [
            "* 5 EXISTS",
            "* 3 EXPUNGE",
            "* 2 FETCH (FLAGS (\\Seen))",
            "* 12 exists",
        ] {
            assert!(announces_change(changed), "{changed:?} tenía que despertar");
        }
        for quiet in [
            "* 3 RECENT",
            "* OK todavía nada",
            "+ idling",
            "a1 OK IDLE terminated",
            "",
            "* CAPABILITY IMAP4rev1",
        ] {
            assert!(!announces_change(quiet), "{quiet:?} no tenía que despertar");
        }
    }

    /// El búfer propio es lo que hace que se pueda esperar con reloj: sin él,
    /// cancelar una lectura a medias perdería lo leído y la respuesta siguiente
    /// llegaría cortada.
    #[test]
    fn las_lineas_salen_del_buffer_de_a_una() {
        let mut pending = b"* OK uno\r\n* OK dos\r\n* OK incom".to_vec();

        assert_eq!(line_from_buffer(&mut pending).as_deref(), Some("* OK uno"));
        assert_eq!(line_from_buffer(&mut pending).as_deref(), Some("* OK dos"));
        // La tercera está a medias: no se entrega hasta que llegue su fin de
        // línea, y lo leído sigue en el búfer esperándola.
        assert_eq!(line_from_buffer(&mut pending), None);
        assert_eq!(pending, b"* OK incom");
    }

    /// La propiedad que hace posible esperar con reloj: si la espera se
    /// abandona a mitad de una línea, lo leído **no se pierde**.
    ///
    /// Con el `read_line` de un `BufReader` esto no se cumple —está documentado
    /// que cancelar pierde lo leído— y el síntoma sería una respuesta cortada al
    /// azar cada media hora, cuando IDLE renueva la espera.
    #[test]
    fn lo_leido_a_medias_sigue_ahi_para_la_proxima() {
        let mut pending = Vec::new();

        // Llega media línea y la espera se abandona.
        pending.extend_from_slice(b"* 5 EX");
        assert_eq!(line_from_buffer(&mut pending), None);

        // Llega el resto: la línea sale entera.
        pending.extend_from_slice(b"ISTS\r\n");
        assert_eq!(
            line_from_buffer(&mut pending).as_deref(),
            Some("* 5 EXISTS")
        );
        assert!(pending.is_empty());
    }
}
