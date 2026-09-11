//! Lo de IMAP que hace falta para saber qué correo hay y leerlo.
//!
//! ── Cómo creció esto ────────────────────────────────────────────────────────
//!
//! Empezó contando sin leer y nada más, a propósito: `STATUS` y `SEARCH`
//! devuelven números, así que no había que tocar ni una cabecera ni un cuerpo —o
//! sea, ni una línea de parser sobre lo que escribió un desconocido—. Ese módulo
//! decía que el día que hubiera que leer mensajes de verdad el parser sería la
//! parte peligrosa y merecería su propia discusión. Ese día llegó con la
//! aplicación de correo, y esa discusión está en `mensaje.rs`.
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

use crate::broker::{Credencial, Destino};
use crate::casillas::{casilla_de_list, uidvalidity_de, Casilla};
use crate::consulta::{armar, uids_de_search, Termino, Trozo};

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
const INTERCAMBIO: Duration = Duration::from_secs(60);

/// Tope de una línea de respuesta.
///
/// IMAP es un protocolo de líneas cortas salvo cuando se piden cuerpos, que acá
/// no se piden. Sin tope, un servidor que manda bytes sin cortar nunca hace
/// crecer la memoria del proceso sin límite.
const MAX_LINEA: u64 = 64 * 1024;

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
pub const MAX_CUERPO: usize = 1024 * 1024;

/// Cuántos mensajes se traen de la casilla.
///
/// No todos: una casilla de veinte años tiene decenas de miles, y traerlos en el
/// arranque haría esperar minutos para ver el correo de hoy. Los últimos
/// doscientos son varias pantallas y llegan en un segundo.
pub const CUANTOS: u32 = 200;

#[derive(Debug)]
pub enum ImapError {
    /// El servidor dijo que no a las credenciales. Se distingue porque es el
    /// caso en que hay que avisar y **dejar de reintentar**: insistir con una
    /// contraseña que el servidor rechaza es cómo se bloquea una cuenta.
    Rechazado(String),
    /// La conexión quedó a mitad de camino de algo y lo que venga después se
    /// va a leer corrido. **No se puede seguir usando**: hay que tirarla y abrir
    /// otra. Se distingue de `Fallo` porque un fallo cualquiera deja la sesión
    /// utilizable y éste no.
    Desincronizada(String),
    Fallo(String),
}

impl std::fmt::Display for ImapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImapError::Rechazado(d) => write!(f, "el servidor rechazó las credenciales: {d}"),
            ImapError::Desincronizada(d) => write!(f, "la conexión quedó desincronizada: {d}"),
            ImapError::Fallo(d) => write!(f, "{d}"),
        }
    }
}

impl std::error::Error for ImapError {}

/// Por qué volvió la espera.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Novedad {
    /// El servidor avisó que algo cambió.
    Cambio,
    /// Se cumplió el tiempo y hay que renovar la espera.
    Vencio,
}

/// Lo que se sabe de una casilla después de mirarla.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct Estado {
    pub mensajes: u32,
    pub sin_leer: u32,
}

// ---------------------------------------------------------------------------
// Lo que se puede probar sin red
// ---------------------------------------------------------------------------

/// Escapa un texto para meterlo entre comillas en un comando IMAP.
///
/// `None` si no se puede: un salto de línea partiría el comando en dos y lo que
/// siga se leería como un comando nuevo. Es la inyección clásica de este
/// protocolo.
pub fn comillas(texto: &str) -> Option<String> {
    if texto.contains(['\r', '\n', '\0']) {
        return None;
    }
    Some(format!(
        "\"{}\"",
        texto.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

/// El estado de una respuesta con etiqueta.
#[derive(Debug, PartialEq, Eq)]
pub enum Respuesta {
    Ok,
    No(String),
    Bad(String),
}

/// Interpreta una línea contra la etiqueta que se mandó.
///
/// `None` para las que no son la respuesta final: las que empiezan con `*` son
/// datos sin pedir y el servidor manda varias antes de contestar. Tomarlas por
/// la respuesta daría por buena una sesión que todavía no se autenticó.
pub fn respuesta_de(linea: &str, etiqueta: &str) -> Option<Respuesta> {
    let resto = linea.strip_prefix(etiqueta)?.strip_prefix(' ')?;
    let (estado, detalle) = resto.split_once(' ').unwrap_or((resto, ""));
    match estado.to_ascii_uppercase().as_str() {
        "OK" => Some(Respuesta::Ok),
        "NO" => Some(Respuesta::No(detalle.trim().into())),
        "BAD" => Some(Respuesta::Bad(detalle.trim().into())),
        _ => None,
    }
}

/// El cuerpo de un `AUTHENTICATE XOAUTH2`.
///
/// El formato lo fijan Google y Microsoft y no se parece a nada más del
/// protocolo: `user=…^Aauth=Bearer …^A^A`, donde `^A` es el byte 0x01. Escribirlo
/// con espacios o dos puntos, que es lo intuitivo, da un rechazo que parece de
/// credenciales y no lo es.
pub fn carga_xoauth2(usuario: &str, token: &str) -> String {
    let crudo = format!("user={usuario}\x01auth=Bearer {token}\x01\x01");
    base64::engine::general_purpose::STANDARD.encode(crudo)
}

/// Las capacidades que anuncia el servidor.
///
/// Llegan en una línea `* CAPABILITY IMAP4rev1 IDLE …`, y también pegadas al
/// saludo entre corchetes: `* OK [CAPABILITY …] listo`. Se leen de las dos
/// formas porque hay servidores que sólo las dan en el saludo, y preguntar de
/// nuevo por algo que ya dijeron es una vuelta de más en cada conexión.
pub fn capacidades_de(linea: &str) -> Vec<String> {
    let mayusculas = linea.to_ascii_uppercase();

    let lista = if let Some(desde) = mayusculas.find("[CAPABILITY ") {
        let resto = &mayusculas[desde + "[CAPABILITY ".len()..];
        resto.split_once(']').map(|(dentro, _)| dentro)
    } else {
        mayusculas.strip_prefix("* CAPABILITY ")
    };

    lista
        .map(|l| l.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Cuántos mensajes anuncia un `* n EXISTS`.
pub fn exists_de(linea: &str) -> Option<u32> {
    let sin_asterisco = linea.strip_prefix("* ")?;
    let (numero, resto) = sin_asterisco.split_once(' ')?;
    resto
        .trim()
        .eq_ignore_ascii_case("EXISTS")
        .then(|| numero.parse().ok())
        .flatten()
}

/// Cuántos resultados trae un `* SEARCH 3 5 9`.
///
/// Se cuentan y no se leen: los números son identificadores de mensaje y lo
/// único que hace falta es cuántos hay.
pub fn resultados_de_search(linea: &str) -> Option<u32> {
    // El corte después de la palabra lo comprueba `tras_search`. Sin eso,
    // `* SEARCHING 1` pasaba por una respuesta de `SEARCH` con un resultado —
    // la misma clase de error que el de las etiquetas, que ya tiene su prueba
    // más abajo.
    Some(crate::consulta::tras_search(linea)?.split_whitespace().count() as u32)
}

/// Saca una línea del búfer, si ya hay una entera.
///
/// Aparte de la sesión para poder probarla: el búfer es lo que hace que esperar
/// con reloj sea seguro, y esa propiedad merece un test que no necesite una
/// conexión de verdad.
pub fn linea_del_buffer(pendiente: &mut Vec<u8>) -> Option<String> {
    let fin = pendiente.iter().position(|b| *b == b'\n')?;
    let linea: Vec<u8> = pendiente.drain(..=fin).collect();
    Some(String::from_utf8_lossy(&linea).trim_end().to_string())
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
pub fn anuncia_cambio(linea: &str) -> bool {
    let Some(resto) = linea.strip_prefix("* ") else {
        return false;
    };
    let mayusculas = resto.to_ascii_uppercase();
    // `n EXISTS`, `n EXPUNGE`, `n FETCH (...)`: siempre el número primero.
    let Some((numero, cola)) = mayusculas.split_once(' ') else {
        return false;
    };
    if numero.parse::<u32>().is_err() {
        return false;
    }
    cola.starts_with("EXISTS") || cola.starts_with("EXPUNGE") || cola.starts_with("FETCH")
}

/// Cuántos bytes anuncia un literal al final de una línea.
///
/// `{1234}` o `{1234+}`: la segunda forma es la de los servidores que no esperan
/// confirmación. Las dos significan lo mismo para quien lee.
///
/// Sin esto, esos bytes se leerían como si fueran líneas del protocolo: el
/// mensaje se parte en pedazos y la conexión queda desincronizada para siempre,
/// porque todo lo que venga después se interpreta corrido.
pub fn literal_de(linea: &str) -> Option<usize> {
    let sin_llave = linea.strip_suffix('}')?;
    let inicio = sin_llave.rfind('{')?;
    let numero = &sin_llave[inicio + 1..];
    // El `+` de LITERAL+ va pegado al número.
    numero.strip_suffix('+').unwrap_or(numero).parse().ok()
}

/// El UID que trae una respuesta de `FETCH`.
///
/// El UID y no el número de secuencia: el número cambia en cuanto se borra
/// cualquier mensaje anterior, así que guardarlo sería guardar algo que mañana
/// apunta a otro mensaje.
pub fn uid_de(respuesta: &str) -> Option<u32> {
    let mayusculas = respuesta.to_ascii_uppercase();
    let mut desde = 0;
    while let Some(posicion) = mayusculas[desde..].find("UID ") {
        let absoluta = desde + posicion;
        // Que sea la palabra «UID» y no el final de otra, como «BODYUID».
        let anterior = mayusculas[..absoluta].chars().next_back();
        if anterior.is_none_or(|c| c == '(' || c == ' ') {
            let cola = &respuesta[absoluta + "UID ".len()..];
            let digitos: String = cola.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(uid) = digitos.parse() {
                return Some(uid);
            }
        }
        desde = absoluta + "UID ".len();
    }
    None
}

/// Si el mensaje está marcado como leído.
///
/// Se mira `\Seen` dentro de `FLAGS (...)` y no en la respuesta entera: un
/// asunto que diga «Seen» no puede marcar un mensaje como leído.
pub fn esta_visto(respuesta: &str) -> bool {
    let mayusculas = respuesta.to_ascii_uppercase();
    let Some(inicio) = mayusculas.find("FLAGS (") else {
        return false;
    };
    let desde = inicio + "FLAGS (".len();
    let hasta = mayusculas[desde..].find(')').map(|f| desde + f).unwrap_or(mayusculas.len());
    mayusculas[desde..hasta].split_whitespace().any(|b| b == "\\SEEN")
}

/// El rango de secuencia de los últimos `cuantos` mensajes de una casilla.
///
/// `None` si la casilla está vacía: pedir `1:0` es un error de sintaxis, y un
/// servidor que lo recibe puede cortar la sesión en vez de contestar.
pub fn ultimos(mensajes: u32, cuantos: u32) -> Option<String> {
    if mensajes == 0 || cuantos == 0 {
        return None;
    }
    let desde = mensajes.saturating_sub(cuantos - 1).max(1);
    Some(format!("{desde}:{mensajes}"))
}

// ---------------------------------------------------------------------------
// La parte que habla por la red
// ---------------------------------------------------------------------------

type Flujo = tokio_rustls::client::TlsStream<TcpStream>;

/// Una sesión IMAP abierta.
///
/// El flujo es un parámetro con valor por omisión, y eso es lo que hace que
/// esto se pueda probar. En producción siempre es el TLS de arriba; en las
/// pruebas es un par de tuberías en memoria contra un servidor de mentira, y
/// así se puede ejercer la conversación entera —qué comando se manda, en qué
/// orden, qué se hace con las respuestas sin etiqueta— que es exactamente lo
/// que un analizador suelto no comprueba.
pub struct Sesion<F = Flujo> {
    flujo: F,
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
    pendiente: Vec<u8>,
    etiqueta: u32,
    capacidades: Vec<String>,
    /// El `UIDVALIDITY` de la última casilla que se abrió.
    ///
    /// Se guarda porque es lo único que dice si los UID que tenemos siguen
    /// valiendo. Cuando el servidor lo cambia, el 412 de ayer **no** es el 412
    /// de hoy: quien tenga una lista vieja tiene que tirarla. Sin esto, un
    /// «borrar» le puede caer a otro mensaje.
    uidvalidity: Option<u32>,
}

impl Sesion<Flujo> {
    /// Abre la sesión y se autentica.
    ///
    /// Siempre sobre TLS desde el primer byte. STARTTLS no se implementa acá a
    /// propósito: el formulario propone 993 y el autodescubrimiento también, así
    /// que una cuenta que llegara hasta acá con un puerto en claro sería una
    /// configurada a mano contra la recomendación — y mandarle la credencial sin
    /// cifrar no es algo que este proceso deba hacer en silencio.
    pub async fn abrir(destino: &Destino) -> Result<Self, ImapError> {
        tokio::time::timeout(TIMEOUT, Self::abrir_sin_tope(destino))
            .await
            .map_err(|_| {
                ImapError::Fallo(format!(
                    "{}:{} no contestó en {} segundos",
                    destino.host,
                    destino.puerto,
                    TIMEOUT.as_secs()
                ))
            })?
    }

    async fn abrir_sin_tope(destino: &Destino) -> Result<Self, ImapError> {
        let tcp = TcpStream::connect((destino.host.as_str(), destino.puerto))
            .await
            .map_err(|e| {
                ImapError::Fallo(format!(
                    "no se pudo conectar a {}:{}: {e}",
                    destino.host, destino.puerto
                ))
            })?;

        let nombre = ServerName::try_from(destino.host.clone()).map_err(|e| {
            ImapError::Fallo(format!("«{}» no es un nombre de servidor: {e}", destino.host))
        })?;
        let cifrado = crate::tls::conector().map_err(ImapError::Fallo)?
            .connect(nombre, tcp)
            .await
            .map_err(|e| ImapError::Fallo(format!("no se pudo cifrar la conexión: {e}")))?;

        let mut sesion = Sesion {
            flujo: cifrado,
            pendiente: Vec::new(),
            etiqueta: 0,
            capacidades: Vec::new(),
            uidvalidity: None,
        };

        let saludo = sesion.leer_linea().await?;
        if saludo.starts_with("* BYE") {
            return Err(ImapError::Fallo(format!("el servidor cerró la conexión: {saludo}")));
        }
        // Muchos servidores las pegan al saludo; si vienen, una vuelta menos.
        sesion.capacidades = capacidades_de(&saludo);

        sesion.autenticar(&destino.credencial).await?;

        // Después de autenticarse las capacidades pueden cambiar —IDLE suele
        // anunciarse recién ahí— así que se vuelven a pedir. Preguntarlo antes
        // sería quedarse con una lista que no vale.
        sesion.refrescar_capacidades().await?;
        Ok(sesion)
    }
}

/// Todo lo demás no necesita saber que abajo hay TLS: le alcanza con poder leer
/// y escribir bytes.
impl<F: AsyncRead + AsyncWrite + Unpin + Send> Sesion<F> {
    async fn autenticar(&mut self, credencial: &Credencial) -> Result<(), ImapError> {
        match credencial {
            Credencial::Contrasena { usuario, secreto } => {
                let (Some(u), Some(s)) = (comillas(usuario), comillas(secreto)) else {
                    return Err(ImapError::Fallo(
                        "el usuario o la contraseña tienen un salto de línea".into(),
                    ));
                };
                self.mandar(&format!("LOGIN {u} {s}")).await
            }
            Credencial::Token { usuario, token } => {
                // En una sola línea, que es la forma que aceptan Google y
                // Microsoft. Partirlo en `AUTHENTICATE XOAUTH2` y después la
                // carga obliga a leer el `+` intermedio, y hay servidores que no
                // lo mandan igual.
                self.mandar(&format!(
                    "AUTHENTICATE XOAUTH2 {}",
                    carga_xoauth2(usuario, token)
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
    async fn con_tope<T>(
        que: &str,
        futuro: impl std::future::Future<Output = Result<T, ImapError>>,
    ) -> Result<T, ImapError> {
        tokio::time::timeout(INTERCAMBIO, futuro)
            .await
            .unwrap_or_else(|_| {
                Err(ImapError::Fallo(format!(
                    "el servidor dejó de contestar durante {que} ({}s)",
                    INTERCAMBIO.as_secs()
                )))
            })
    }

    /// Si el servidor sabe avisar en vez de que haya que preguntarle.
    pub fn soporta_idle(&self) -> bool {
        self.capacidades.iter().any(|c| c == "IDLE")
    }

    async fn refrescar_capacidades(&mut self) -> Result<(), ImapError> {
        let etiqueta = self.siguiente_etiqueta();
        self.escribir(&format!("{etiqueta} CAPABILITY")).await?;

        let vistas = Self::con_tope("la lista de capacidades", async {
            let mut vistas = Vec::new();
            loop {
                let linea = self.leer_linea().await?;
                let anunciadas = capacidades_de(&linea);
                if !anunciadas.is_empty() {
                    vistas = anunciadas;
                }
                match respuesta_de(&linea, &etiqueta) {
                    Some(Respuesta::Ok) => return Ok(vistas),
                    Some(Respuesta::No(d)) | Some(Respuesta::Bad(d)) => {
                        return Err(ImapError::Fallo(format!("CAPABILITY falló: {d}")))
                    }
                    None => continue,
                }
            }
        })
        .await?;

        if !vistas.is_empty() {
            self.capacidades = vistas;
        }
        Ok(())
    }

    /// Abre una casilla **en sólo lectura** y devuelve cuántos mensajes tiene.
    ///
    /// `EXAMINE` y no `SELECT`: los dos sirven para IDLE, pero `SELECT` puede
    /// borrar la marca de reciente y, según el servidor, tocar banderas. Este
    /// proceso cuenta correo; no tiene por qué cambiar nada de la casilla de
    /// nadie.
    pub async fn examinar(&mut self, casilla: &str) -> Result<u32, ImapError> {
        self.abrir_casilla("EXAMINE", casilla).await
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
    pub async fn listar_casillas(&mut self) -> Result<Vec<Casilla>, ImapError> {
        let etiqueta = self.siguiente_etiqueta();
        self.escribir(&format!("{etiqueta} LIST \"\" \"*\"")).await?;

        Self::con_tope("listar las casillas", async {
            let mut casillas = Vec::new();
            loop {
                let linea = self.leer_linea().await?;
                if let Some(casilla) = casilla_de_list(&linea) {
                    casillas.push(casilla);
                }
                match respuesta_de(&linea, &etiqueta) {
                    Some(Respuesta::Ok) => return Ok(casillas),
                    Some(Respuesta::No(d)) | Some(Respuesta::Bad(d)) => {
                        return Err(ImapError::Fallo(format!("LIST falló: {d}")))
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
    /// `casilla` es la **ruta**, o sea el nombre tal como lo escribe el
    /// servidor: la que trae `Casilla::ruta`, ya en UTF-7 modificado si hacía
    /// falta. No se codifica acá porque codificar dos veces rompería el nombre,
    /// y los nombres siempre vienen de un `LIST`.
    async fn abrir_casilla(&mut self, comando: &str, casilla: &str) -> Result<u32, ImapError> {
        let nombre = comillas(casilla)
            .ok_or_else(|| ImapError::Fallo("el nombre de la casilla no es válido".into()))?;

        let etiqueta = self.siguiente_etiqueta();
        self.escribir(&format!("{etiqueta} {comando} {nombre}")).await?;

        Self::con_tope("abrir la casilla", async {
            let mut mensajes = 0;
            loop {
                let linea = self.leer_linea().await?;
                if let Some(n) = exists_de(&linea) {
                    mensajes = n;
                }
                if let Some(v) = uidvalidity_de(&linea) {
                    self.uidvalidity = Some(v);
                }
                match respuesta_de(&linea, &etiqueta) {
                    Some(Respuesta::Ok) => return Ok(mensajes),
                    Some(Respuesta::No(d)) | Some(Respuesta::Bad(d)) => {
                        return Err(ImapError::Fallo(format!(
                            "no se pudo abrir «{casilla}»: {d}"
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
    pub async fn buscar(&mut self, terminos: &[Termino]) -> Result<Vec<u32>, ImapError> {
        let trozos = armar(terminos);
        if trozos.is_empty() {
            // Sin criterio, `SEARCH` devuelve la casilla entera. Eso no es una
            // búsqueda vacía, es todo: contestar nada es más honesto.
            return Ok(Vec::new());
        }

        match self.buscar_con(&trozos, true).await {
            Err(ImapError::Rechazado(detalle)) if detalle.contains("BADCHARSET") => {
                self.buscar_con(&trozos, false).await
            }
            otro => otro,
        }
    }

    /// Un intento de búsqueda, declarando el juego de caracteres o no.
    async fn buscar_con(
        &mut self,
        trozos: &[Trozo],
        con_charset: bool,
    ) -> Result<Vec<u32>, ImapError> {
        let etiqueta = self.siguiente_etiqueta();
        let mut linea = format!("{etiqueta} UID SEARCH");
        if con_charset {
            linea.push_str(" CHARSET UTF-8");
        }

        // Los trozos que son literales de IMAP interrumpen la línea: se anuncia
        // el largo **en bytes**, el servidor contesta `+` y recién ahí van los
        // bytes. Un `chars().count()` acá mandaría un largo que no es el que el
        // servidor va a leer, y la sesión queda desincronizada.
        for trozo in trozos {
            match trozo {
                Trozo::Literal(texto) => {
                    linea.push(' ');
                    linea.push_str(texto);
                }
                Trozo::Cadena(texto) => {
                    linea.push_str(&format!(" {{{}}}", texto.len()));
                    self.escribir(&linea).await?;
                    self.esperar_continuacion().await?;
                    linea = texto.clone();
                }
            }
        }
        self.escribir(&linea).await?;

        Self::con_tope("buscar", async {
            let mut uids = Vec::new();
            loop {
                let linea = self.leer_linea().await?;
                if let Some(encontrados) = uids_de_search(&linea) {
                    uids.extend(encontrados);
                }
                match respuesta_de(&linea, &etiqueta) {
                    Some(Respuesta::Ok) => return Ok(uids),
                    // `No` va como `Rechazado` y no como `Fallo` para que el
                    // reintento sin `CHARSET` pueda reconocerlo.
                    Some(Respuesta::No(d)) => return Err(ImapError::Rechazado(d)),
                    Some(Respuesta::Bad(d)) => {
                        return Err(ImapError::Fallo(format!("SEARCH falló: {d}")))
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
    async fn esperar_continuacion(&mut self) -> Result<(), ImapError> {
        Self::con_tope("esperar la continuación", async {
            loop {
                let linea = self.leer_linea().await?;
                if linea.starts_with('+') {
                    return Ok(());
                }
                // Un `NO` o un `BAD` acá quieren decir que el comando no va a
                // pasar. Seguir esperando el `+` sería esperar para siempre.
                let mayusculas = linea.to_ascii_uppercase();
                if mayusculas.contains(" NO ") || mayusculas.contains(" BAD ") {
                    return Err(ImapError::Rechazado(linea));
                }
            }
        })
        .await
    }

    /// Los resúmenes de unos UID puntuales.
    ///
    /// Mismo `FETCH` que `resumenes`, pero por UID en vez de por rango de
    /// secuencia: es lo que hace falta después de un `SEARCH`.
    pub async fn resumenes_de(
        &mut self,
        uids: &[u32],
    ) -> Result<Vec<crate::mensaje::Resumen>, ImapError> {
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        // Los más nuevos primero y con tope: una búsqueda amplia puede traer
        // diez mil, y pedir los encabezados de todos tarda lo que tarda y llena
        // la memoria de la ventana con algo que nadie va a leer entero.
        let mut recientes: Vec<u32> = uids.to_vec();
        recientes.sort_unstable_by(|a, b| b.cmp(a));
        recientes.truncate(CUANTOS as usize);

        let lista = recientes
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join(",");
        self.fetch_de_resumenes(&format!("UID FETCH {lista}")).await
    }

    /// Cuántos sin leer hay en la casilla abierta.
    ///
    /// Con `SEARCH` y no con `STATUS`: el estándar dice que `STATUS` no se use
    /// sobre la casilla que está abierta, y hay servidores que directamente
    /// contestan un error.
    pub async fn sin_leer(&mut self) -> Result<u32, ImapError> {
        let etiqueta = self.siguiente_etiqueta();
        self.escribir(&format!("{etiqueta} SEARCH UNSEEN")).await?;

        Self::con_tope("contar los sin leer", async {
            let mut cuantos = 0;
            loop {
                let linea = self.leer_linea().await?;
                if let Some(n) = resultados_de_search(&linea) {
                    cuantos = n;
                }
                match respuesta_de(&linea, &etiqueta) {
                    Some(Respuesta::Ok) => return Ok(cuantos),
                    Some(Respuesta::No(d)) | Some(Respuesta::Bad(d)) => {
                        return Err(ImapError::Fallo(format!("SEARCH falló: {d}")))
                    }
                    None => continue,
                }
            }
        })
        .await
    }

    /// Espera a que el servidor avise que algo cambió.
    ///
    /// Vuelve cuando hay novedades o cuando se cumple `maximo`, lo que pase
    /// primero. **Hay que volver a llamarla**: el estándar pide renovar la
    /// espera al menos cada veintinueve minutos, porque si no el servidor —o
    /// cualquier NAT en el medio— corta la conexión por inactividad.
    pub async fn esperar(&mut self, maximo: Duration) -> Result<Novedad, ImapError> {
        let etiqueta = self.siguiente_etiqueta();
        self.escribir(&format!("{etiqueta} IDLE")).await?;

        // El servidor contesta `+ idling` antes de empezar. Si en vez de eso
        // manda un `NO`, es que no acepta IDLE aunque lo haya anunciado.
        //
        // Con tope: esperar acá sin límite es cómo una cuenta queda muda para
        // siempre contra un servidor que dejó de escribir sin cerrar.
        Self::con_tope("el comienzo de la espera", async {
            loop {
                let linea = self.leer_linea().await?;
                if linea.starts_with('+') {
                    return Ok(());
                }
                if let Some(Respuesta::No(d)) | Some(Respuesta::Bad(d)) =
                    respuesta_de(&linea, &etiqueta)
                {
                    return Err(ImapError::Fallo(format!("el servidor no acepta IDLE: {d}")));
                }
            }
        })
        .await?;

        let hasta = tokio::time::Instant::now() + maximo;
        let mut novedad = Novedad::Vencio;
        loop {
            let queda = hasta.saturating_duration_since(tokio::time::Instant::now());
            if queda.is_zero() {
                break;
            }
            // Cancelar esta lectura no pierde nada: el búfer es nuestro.
            match tokio::time::timeout(queda, self.leer_linea()).await {
                Err(_) => break,
                Ok(Err(e)) => return Err(e),
                Ok(Ok(linea)) => {
                    if anuncia_cambio(&linea) {
                        novedad = Novedad::Cambio;
                        break;
                    }
                }
            }
        }

        // `DONE` va **sin etiqueta**: es la única línea del protocolo que no
        // lleva una, y ponérsela hace que el servidor no la reconozca y la
        // sesión quede colgada esperando.
        self.escribir("DONE").await?;
        Self::con_tope("el fin de la espera", async {
            loop {
                let linea = self.leer_linea().await?;
                match respuesta_de(&linea, &etiqueta) {
                    Some(Respuesta::Ok) => return Ok(()),
                    Some(Respuesta::No(d)) | Some(Respuesta::Bad(d)) => {
                        return Err(ImapError::Fallo(format!("IDLE terminó mal: {d}")))
                    }
                    None => continue,
                }
            }
        })
        .await?;

        Ok(novedad)
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
    pub async fn resumenes(&mut self, mensajes: u32) -> Result<Vec<crate::mensaje::Resumen>, ImapError> {
        let Some(rango) = ultimos(mensajes, CUANTOS) else {
            return Ok(Vec::new());
        };

        self.fetch_de_resumenes(&format!("FETCH {rango}")).await
    }

    /// El `FETCH` de encabezados y lo que se hace con lo que vuelve.
    ///
    /// Está aparte porque lo usan dos: la lista de una casilla, que pide un
    /// rango de secuencia, y la búsqueda, que pide UID puntuales. Lo único que
    /// cambia es el comando; qué se pide y cómo se lee lo que vuelve es idéntico
    /// — y dos copias de eso son dos que se separan.
    async fn fetch_de_resumenes(
        &mut self,
        comando: &str,
    ) -> Result<Vec<crate::mensaje::Resumen>, ImapError> {
        let etiqueta = self.siguiente_etiqueta();
        // `CONTENT-TYPE` viene para saber si hay algo pegado. Es una pista y no
        // una certeza —un `multipart/mixed` puede ser texto con una imagen
        // incrustada—, pero cuesta cero y acierta casi siempre; saberlo de verdad
        // pide traer la estructura completa del mensaje.
        self.escribir(&format!(
            "{etiqueta} {comando} (UID FLAGS \
             BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE CONTENT-TYPE)])"
        ))
        .await?;

        Self::con_tope("la lista de mensajes", async {
            let mut resumenes = Vec::new();
            loop {
                let (linea, literales) = self.leer_respuesta().await?;

                // **Sólo si trajo las cabeceras.** Mientras este comando corre, el
                // servidor puede intercalar un `FETCH` que nadie pidió: es cómo
                // avisa que otro dispositivo marcó algo como leído, y viene con
                // UID y sin literal. Tomarlo por un mensaje dejaba una fila en
                // blanco en la lista, y si después llegaba el de verdad, el
                // mismo mensaje aparecía dos veces.
                if let (Some(uid), Some(bloque)) = (uid_de(&linea), literales.first()) {
                    // Sin etiqueta de juego de caracteres, que es lo correcto
                    // acá: una cabecera **no** vuelve a bytes nunca —lo que sale
                    // de `resumen_de` es lo que se muestra—, así que la vista
                    // latin-1 que sirve para recorrer un cuerpo acá dejaría un
                    // `Subject` en UTF-8 crudo mostrándose como «ReuniÃ³n».
                    //
                    // Las palabras codificadas son ASCII y no se ven afectadas;
                    // lo que esto arregla son las cabeceras con bytes de ocho
                    // bits sin codificar, que el estándar no permite y los
                    // clientes mandan igual.
                    let cabeceras = crate::mensaje::a_texto(bloque, "");
                    let adjuntos = cabeceras.to_ascii_lowercase().contains("multipart/mixed");
                    resumenes.push(crate::mensaje::resumen_de(
                        uid,
                        &cabeceras,
                        !esta_visto(&linea),
                        adjuntos,
                    ));
                }

                match respuesta_de(&linea, &etiqueta) {
                    Some(Respuesta::Ok) => return Ok(resumenes),
                    Some(Respuesta::No(d)) | Some(Respuesta::Bad(d)) => {
                        return Err(ImapError::Fallo(format!("no se pudo listar: {d}")))
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
    /// `MAX_CUERPO`), y quien muestra el mensaje tiene que poder decir que hay
    /// más en vez de dejar el texto terminado a la mitad sin explicación.
    ///
    /// `BODY.PEEK` otra vez: abrir un mensaje **sí** lo marca como leído, pero eso
    /// lo decide la aplicación con un comando explícito, no el efecto secundario
    /// de haberlo traído.
    pub async fn cuerpo(&mut self, uid: u32) -> Result<(Vec<u8>, bool), ImapError> {
        let etiqueta = self.siguiente_etiqueta();
        self.escribir(&format!(
            "{etiqueta} UID FETCH {uid} (BODY.PEEK[]<0.{MAX_CUERPO}>)"
        ))
        .await?;

        Self::con_tope("traer el mensaje", async {
            let mut crudo: Vec<u8> = Vec::new();
            loop {
                let (linea, literales) = self.leer_respuesta().await?;
                if let Some(bytes) = literales.into_iter().next() {
                    crudo = bytes;
                }
                match respuesta_de(&linea, &etiqueta) {
                    Some(Respuesta::Ok) => {
                        let recortado = crudo.len() >= MAX_CUERPO;
                        return Ok((crudo, recortado));
                    }
                    Some(Respuesta::No(d)) | Some(Respuesta::Bad(d)) => {
                        return Err(ImapError::Fallo(format!("no se pudo traer: {d}")))
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
    pub async fn marcar_leido(&mut self, uid: u32) -> Result<(), ImapError> {
        self.mandar(&format!("UID STORE {uid} +FLAGS (\\Seen)")).await
    }

    /// Abre una casilla **para escribir** y devuelve cuántos mensajes tiene.
    ///
    /// Se usa sólo cuando hay que cambiar una bandera. El resto del tiempo la
    /// casilla se abre con `EXAMINE`, que no puede tocar nada.
    pub async fn seleccionar(&mut self, casilla: &str) -> Result<u32, ImapError> {
        self.abrir_casilla("SELECT", casilla).await
    }

    /// Lee una respuesta entera, con sus literales.
    ///
    /// Una respuesta puede ocupar varias líneas: cada `{N}` al final de una
    /// significa que siguen N bytes crudos y después continúa la respuesta. Se
    /// devuelven el texto —con los literales sacados— y los bloques de bytes
    /// aparte, **sin convertirlos a texto**: el juego de caracteres de un
    /// mensaje lo decide el mensaje, y pasarlos por UTF-8 acá destruiría los
    /// acentos de todo el correo viejo antes de que nadie pueda arreglarlo.
    async fn leer_respuesta(&mut self) -> Result<(String, Vec<Vec<u8>>), ImapError> {
        let mut texto = String::new();
        let mut literales: Vec<Vec<u8>> = Vec::new();

        loop {
            let linea = self.leer_linea().await?;
            let Some(cuantos) = literal_de(&linea) else {
                texto.push_str(&linea);
                return Ok((texto, literales));
            };

            if cuantos > MAX_CUERPO {
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
                return Err(ImapError::Desincronizada(format!(
                    "el servidor anunció {cuantos} bytes, más de los {MAX_CUERPO} que se piden"
                )));
            }
            // Sin la marca `{N}`: es del protocolo y no del mensaje.
            if let Some(marca) = linea.rfind('{') {
                texto.push_str(&linea[..marca]);
            }
            literales.push(self.leer_bytes(cuantos).await?);
        }
    }

    /// Lee exactamente `cuantos` bytes, empezando por lo que ya esté en el búfer.
    async fn leer_bytes(&mut self, cuantos: usize) -> Result<Vec<u8>, ImapError> {
        while self.pendiente.len() < cuantos {
            let leidos = self
                .flujo
                .read_buf(&mut self.pendiente)
                .await
                .map_err(|e| ImapError::Fallo(format!("no se pudo leer: {e}")))?;
            if leidos == 0 {
                return Err(ImapError::Fallo(
                    "el servidor cortó la conexión en medio de un mensaje".into(),
                ));
            }
        }
        Ok(self.pendiente.drain(..cuantos).collect())
    }

    fn siguiente_etiqueta(&mut self) -> String {
        self.etiqueta += 1;
        format!("a{}", self.etiqueta)
    }

    /// Manda un comando y espera su respuesta con etiqueta.
    async fn mandar(&mut self, comando: &str) -> Result<(), ImapError> {
        let etiqueta = self.siguiente_etiqueta();
        self.escribir(&format!("{etiqueta} {comando}")).await?;

        Self::con_tope("la respuesta al comando", async {
            loop {
                let linea = self.leer_linea().await?;
                match respuesta_de(&linea, &etiqueta) {
                    Some(Respuesta::Ok) => return Ok(()),
                    // `NO` es el servidor entendiendo y diciendo que no: casi
                    // siempre, credenciales. Se distingue porque insistir con una
                    // contraseña rechazada es cómo se bloquea una cuenta.
                    Some(Respuesta::No(d)) => return Err(ImapError::Rechazado(d)),
                    Some(Respuesta::Bad(d)) => {
                        return Err(ImapError::Fallo(format!("el servidor no entendió: {d}")))
                    }
                    None => continue,
                }
            }
        })
        .await
    }

    async fn escribir(&mut self, linea: &str) -> Result<(), ImapError> {
        let escribir = async {
            self.flujo.write_all(linea.as_bytes()).await?;
            self.flujo.write_all(b"\r\n").await?;
            self.flujo.flush().await
        };
        escribir
            .await
            .map_err(|e| ImapError::Fallo(format!("no se pudo escribir: {e}")))
    }

    /// Lee una línea, y **se puede cancelar sin perder nada**.
    ///
    /// Todo lo que llega del socket va a un búfer propio antes de partirse en
    /// líneas, así que si quien llama abandona la espera —con un tiempo límite,
    /// por ejemplo— lo leído sigue ahí para la próxima. Es lo que hace posible
    /// esperar en IDLE con un reloj al lado.
    async fn leer_linea(&mut self) -> Result<String, ImapError> {
        loop {
            if let Some(linea) = linea_del_buffer(&mut self.pendiente) {
                return Ok(linea);
            }
            if self.pendiente.len() as u64 > MAX_LINEA {
                return Err(ImapError::Fallo(
                    "el servidor mandó una línea sin fin".into(),
                ));
            }

            let leidos = self
                .flujo
                .read_buf(&mut self.pendiente)
                .await
                .map_err(|e| ImapError::Fallo(format!("no se pudo leer: {e}")))?;
            if leidos == 0 {
                return Err(ImapError::Fallo("el servidor cortó la conexión".into()));
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
    /// `guion` son pares de «lo que se espera recibir» y «lo que se contesta».
    /// El servidor de mentira comprueba que el comando contenga lo esperado y
    /// falla la prueba si no, así que el orden de los comandos queda fijado.
    fn con_servidor(
        saludo: &str,
        guion: Vec<(&'static str, Vec<&'static str>)>,
    ) -> (
        Sesion<tokio::io::DuplexStream>,
        tokio::task::JoinHandle<Vec<String>>,
    ) {
        let (cliente, servidor) = tokio::io::duplex(64 * 1024);
        let saludo = saludo.to_string();

        let tarea = tokio::spawn(async move {
            let (lectura, mut escritura) = tokio::io::split(servidor);
            let mut lineas = BufReader::new(lectura).lines();
            let mut recibidos = Vec::new();
            let mut etiqueta = String::from("a1");
            let mut esperando_literal = false;

            escritura.write_all(saludo.as_bytes()).await.unwrap();
            escritura.write_all(b"\r\n").await.unwrap();

            for (esperado, respuesta) in guion {
                let Ok(Some(linea)) = lineas.next_line().await else {
                    break;
                };
                assert!(
                    linea.contains(esperado),
                    "se esperaba un comando con «{esperado}» y llegó «{linea}»"
                );
                recibidos.push(linea.clone());

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
                if !esperando_literal {
                    etiqueta = linea.split_whitespace().next().unwrap_or("a1").to_string();
                }
                esperando_literal = respuesta.iter().any(|l| l.starts_with('+'));

                for l in respuesta {
                    let l = l.replace("{etiqueta}", &etiqueta);
                    escritura.write_all(l.as_bytes()).await.unwrap();
                    escritura.write_all(b"\r\n").await.unwrap();
                }
            }

            recibidos
        });

        let sesion = Sesion {
            flujo: cliente,
            pendiente: Vec::new(),
            etiqueta: 0,
            capacidades: Vec::new(),
            uidvalidity: None,
        };
        (sesion, tarea)
    }

    #[tokio::test]
    async fn buscar_manda_uid_search_con_el_juego_declarado() {
        let (mut sesion, tarea) = con_servidor(
            "* OK listo",
            vec![(
                "UID SEARCH CHARSET UTF-8 FROM \"ana\"",
                vec!["* SEARCH 3 7 11", "{etiqueta} OK SEARCH completado"],
            )],
        );

        let uids = sesion
            .buscar(&[crate::consulta::Termino::De("ana".into())])
            .await
            .unwrap();
        tarea.await.unwrap();
        assert_eq!(uids, vec![3, 7, 11]);
    }

    /// Hay servidores viejos que rechazan el juego declarado. El estándar
    /// permite mandarlo sin declarar, y es lo que hacen todos los clientes.
    #[tokio::test]
    async fn si_rechazan_el_juego_se_reintenta_sin_el() {
        let (mut sesion, tarea) = con_servidor(
            "* OK listo",
            vec![
                (
                    "CHARSET UTF-8",
                    vec!["{etiqueta} NO [BADCHARSET] UTF-8 no soportado"],
                ),
                (
                    "UID SEARCH FROM \"ana\"",
                    vec!["* SEARCH 5", "{etiqueta} OK completado"],
                ),
            ],
        );

        let uids = sesion
            .buscar(&[crate::consulta::Termino::De("ana".into())])
            .await
            .unwrap();
        let recibidos = tarea.await.unwrap();

        assert_eq!(uids, vec![5]);
        assert_eq!(recibidos.len(), 2, "tenía que reintentar una vez");
        assert!(!recibidos[1].contains("CHARSET"));
    }

    /// Un `NO` que no es por el juego de caracteres no se reintenta: mandar dos
    /// veces un comando que ya se sabe que falla no arregla nada.
    #[tokio::test]
    async fn otro_rechazo_no_se_reintenta() {
        let (mut sesion, tarea) = con_servidor(
            "* OK listo",
            vec![("UID SEARCH", vec!["{etiqueta} NO no se puede"])],
        );

        assert!(sesion
            .buscar(&[crate::consulta::Termino::De("ana".into())])
            .await
            .is_err());
        assert_eq!(tarea.await.unwrap().len(), 1);
    }

    /// Un término que no es ASCII va como literal: se anuncia el largo **en
    /// bytes**, el servidor contesta `+` y recién ahí van los bytes.
    #[tokio::test]
    async fn un_termino_con_acentos_va_como_literal() {
        let (mut sesion, tarea) = con_servidor(
            "* OK listo",
            vec![
                // «reunión» son 8 bytes en UTF-8, no 7 caracteres. Mandar 7
                // dejaría la sesión desincronizada.
                ("SUBJECT {8}", vec!["+ dale"]),
                ("reunión", vec!["* SEARCH 9", "{etiqueta} OK completado"]),
            ],
        );

        let uids = sesion
            .buscar(&[crate::consulta::Termino::Asunto("reunión".into())])
            .await
            .unwrap();
        tarea.await.unwrap();
        assert_eq!(uids, vec![9]);
    }

    /// Sin criterio, `SEARCH` devolvería la casilla entera. Eso no es una
    /// búsqueda vacía: es todo, y contestar nada es más honesto.
    #[tokio::test]
    async fn sin_criterio_no_se_manda_nada() {
        let (mut sesion, tarea) = con_servidor("* OK listo", vec![]);
        assert!(sesion.buscar(&[]).await.unwrap().is_empty());
        assert!(tarea.await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn una_busqueda_sin_resultados_no_es_un_error() {
        let (mut sesion, tarea) = con_servidor(
            "* OK listo",
            vec![("UID SEARCH", vec!["* SEARCH", "{etiqueta} OK completado"])],
        );

        let uids = sesion
            .buscar(&[crate::consulta::Termino::De("nadie".into())])
            .await
            .unwrap();
        tarea.await.unwrap();
        assert!(uids.is_empty());
    }

    /// Una búsqueda amplia puede traer diez mil UID. Pedir los encabezados de
    /// todos llena la memoria de la ventana con algo que nadie va a leer.
    #[tokio::test]
    async fn los_resumenes_de_una_busqueda_se_acotan_a_los_mas_nuevos() {
        let (mut sesion, tarea) = con_servidor(
            "* OK listo",
            vec![("UID FETCH", vec!["{etiqueta} OK completado"])],
        );

        let muchos: Vec<u32> = (1..=500).collect();
        sesion.resumenes_de(&muchos).await.unwrap();
        let recibidos = tarea.await.unwrap();

        let pedidos = recibidos[0].split(',').count();
        assert_eq!(pedidos, CUANTOS as usize);
        // Y son los más nuevos: el primero de la lista es el UID más alto.
        assert!(recibidos[0].contains("UID FETCH 500,499,"));
    }

    #[tokio::test]
    async fn listar_casillas_manda_list_y_junta_lo_que_vuelve() {
        let (mut sesion, tarea) = con_servidor(
            "* OK listo",
            vec![(
                "LIST \"\" \"*\"",
                vec![
                    r#"* LIST (\HasNoChildren) "/" "INBOX""#,
                    r#"* LIST (\HasNoChildren \Sent) "/" "[Gmail]/Sent Mail""#,
                    r#"* LIST (\Noselect \HasChildren) "/" "[Gmail]""#,
                    "{etiqueta} OK LIST completado",
                ],
            )],
        );

        let casillas = sesion.listar_casillas().await.unwrap();
        tarea.await.unwrap();

        assert_eq!(casillas.len(), 3);
        assert_eq!(casillas[0].ruta, "INBOX");
        assert_eq!(casillas[1].uso, crate::casillas::Uso::Enviados);
        // La `\Noselect` viene igual y marcada: hace falta para dibujar el
        // árbol, y quien la muestre decide si la ofrece.
        assert!(!casillas[2].seleccionable);
    }

    /// Es el caso que un analizador suelto no puede cubrir: las respuestas sin
    /// etiqueta se juntan y el comando termina **cuando llega la suya**, no con
    /// la primera línea que se parezca.
    #[tokio::test]
    async fn una_respuesta_sin_etiqueta_no_termina_el_comando() {
        let (mut sesion, tarea) = con_servidor(
            "* OK listo",
            vec![(
                "LIST",
                vec![
                    "* 4 EXISTS",
                    "* OK [UNSEEN 2] algo",
                    r#"* LIST (\HasNoChildren) "/" "Trabajo""#,
                    "* 1 RECENT",
                    "{etiqueta} OK LIST completado",
                ],
            )],
        );

        let casillas = sesion.listar_casillas().await.unwrap();
        tarea.await.unwrap();
        assert_eq!(casillas.len(), 1);
        assert_eq!(casillas[0].ruta, "Trabajo");
    }

    #[tokio::test]
    async fn abrir_una_casilla_lee_cuantos_hay_y_el_uidvalidity() {
        let (mut sesion, tarea) = con_servidor(
            "* OK listo",
            vec![(
                "EXAMINE \"INBOX\"",
                vec![
                    "* FLAGS (\\Seen \\Answered)",
                    "* 42 EXISTS",
                    "* OK [UIDVALIDITY 3857529045] UIDs valid",
                    "* OK [UIDNEXT 4392] Predicted next UID",
                    "{etiqueta} OK [READ-ONLY] EXAMINE completado",
                ],
            )],
        );

        let cuantos = sesion.examinar("INBOX").await.unwrap();
        tarea.await.unwrap();

        assert_eq!(cuantos, 42);
        assert_eq!(sesion.uidvalidity(), Some(3857529045));
    }

    /// La casilla va **entre comillas** en el comando. Sin ellas, una con
    /// espacios —«Sent Mail», que es la de Gmail— se lee como dos argumentos y
    /// el servidor contesta un error.
    #[tokio::test]
    async fn una_casilla_con_espacios_va_entre_comillas() {
        let (mut sesion, tarea) = con_servidor(
            "* OK listo",
            vec![(
                "EXAMINE \"[Gmail]/Sent Mail\"",
                vec!["* 3 EXISTS", "{etiqueta} OK completado"],
            )],
        );

        assert_eq!(sesion.examinar("[Gmail]/Sent Mail").await.unwrap(), 3);
        tarea.await.unwrap();
    }

    #[tokio::test]
    async fn un_no_del_servidor_es_un_error_y_no_una_lista_vacia() {
        let (mut sesion, tarea) = con_servidor(
            "* OK listo",
            vec![(
                "EXAMINE",
                vec!["{etiqueta} NO [NONEXISTENT] Unknown Mailbox"],
            )],
        );

        let fallo = sesion.examinar("NoExiste").await.unwrap_err();
        tarea.await.unwrap();

        // Devolver cero mensajes diría «esta carpeta está vacía», que es otra
        // cosa muy distinta de «esta carpeta no existe».
        assert!(
            fallo.to_string().contains("NoExiste"),
            "el error tiene que nombrar la casilla: {fallo}"
        );
    }

    /// Cada comando lleva su propia etiqueta, creciente. Repetirlas haría que
    /// la respuesta de uno se tome como la del siguiente.
    #[tokio::test]
    async fn cada_comando_lleva_su_etiqueta() {
        let (mut sesion, tarea) = con_servidor(
            "* OK listo",
            vec![
                ("EXAMINE", vec!["* 1 EXISTS", "{etiqueta} OK completado"]),
                ("LIST", vec!["{etiqueta} OK completado"]),
            ],
        );

        sesion.examinar("INBOX").await.unwrap();
        sesion.listar_casillas().await.unwrap();
        let recibidos = tarea.await.unwrap();

        assert_eq!(recibidos.len(), 2);
        let primera = recibidos[0].split_whitespace().next().unwrap();
        let segunda = recibidos[1].split_whitespace().next().unwrap();
        assert_ne!(primera, segunda, "dos comandos con la misma etiqueta");
    }
    use super::*;

    /// Sin reconocer el literal, esos bytes se leen como si fueran líneas del
    /// protocolo: el mensaje se parte en pedazos y la conexión queda
    /// desincronizada **para siempre**, porque todo lo que venga después se
    /// interpreta corrido.
    #[test]
    fn se_reconoce_el_anuncio_de_un_literal() {
        assert_eq!(literal_de("* 1 FETCH (UID 5 BODY[] {1234}"), Some(1234));
        // LITERAL+: el servidor no espera confirmación. Significa lo mismo para
        // quien lee, y no reconocerlo es el mismo desastre.
        assert_eq!(literal_de("* 1 FETCH (UID 5 BODY[] {1234+}"), Some(1234));
        assert_eq!(literal_de("* 1 FETCH (UID 5 FLAGS (\\Seen))"), None);
        assert_eq!(literal_de("a1 OK FETCH completado"), None);
        assert_eq!(literal_de("{no es un número}"), None);
        assert_eq!(literal_de(""), None);
    }

    /// El UID y no el número de secuencia: el número cambia en cuanto se borra
    /// cualquier mensaje anterior, así que guardarlo sería guardar algo que
    /// mañana apunta a otro mensaje.
    #[test]
    fn se_saca_el_uid_de_un_fetch() {
        assert_eq!(uid_de("* 12 FETCH (UID 345 FLAGS (\\Seen))"), Some(345));
        // El orden de los campos lo elige el servidor.
        assert_eq!(uid_de("* 12 FETCH (FLAGS () UID 7)"), Some(7));
        assert_eq!(uid_de("* 12 FETCH (FLAGS ())"), None);
    }

    /// «UID» tiene que ser la palabra y no el final de otra, o cualquier campo
    /// que termine así daría un identificador inventado.
    #[test]
    fn una_palabra_que_termina_en_uid_no_es_el_uid() {
        assert_eq!(uid_de("* 1 FETCH (X-MYUID 999 UID 3)"), Some(3));
        assert_eq!(uid_de("* 1 FETCH (X-MYUID 999)"), None);
    }

    /// Se mira dentro de `FLAGS (...)`: un asunto que diga «Seen» no puede
    /// marcar un mensaje como leído.
    #[test]
    fn lo_leido_se_mira_solo_en_las_banderas() {
        assert!(esta_visto("* 1 FETCH (FLAGS (\\Seen \\Answered) UID 3)"));
        assert!(!esta_visto("* 1 FETCH (FLAGS (\\Answered) UID 3)"));
        assert!(!esta_visto("* 1 FETCH (FLAGS () UID 3)"));
        // El asunto viene en un literal aparte, pero por las dudas.
        assert!(!esta_visto("* 1 FETCH (FLAGS () BODY[HEADER] Seen this?)"));
    }

    /// Mientras corre el `FETCH`, el servidor puede intercalar uno que nadie
    /// pidió: es cómo avisa que otro dispositivo marcó algo como leído. Viene
    /// con UID y **sin literal**, y tomarlo por un mensaje dejaba una fila en
    /// blanco en la lista — y si después llegaba el de verdad, el mismo mensaje
    /// aparecía dos veces.
    #[test]
    fn un_fetch_sin_literal_no_es_un_mensaje() {
        // El aviso trae UID, así que `uid_de` lo reconoce: lo que lo distingue
        // es que no viene con cabeceras.
        let aviso = "* 7 FETCH (UID 12 FLAGS (\\Seen))";
        assert_eq!(uid_de(aviso), Some(12));
        assert_eq!(literal_de(aviso), None);
    }

    /// Un literal más grande de lo que se pidió deja la conexión inservible: sus
    /// bytes ya están en el socket, y lo que venga después se va a leer corrido.
    /// Tiene que distinguirse de un fallo cualquiera, que sí deja seguir.
    #[test]
    fn una_desincronizacion_no_es_un_fallo_cualquiera() {
        let rota = ImapError::Desincronizada("anunció de más".into());
        assert!(matches!(rota, ImapError::Desincronizada(_)));
        assert!(rota.to_string().contains("desincronizada"), "{rota}");

        // Y no se confunde con las otras dos, que son las que dejan la sesión
        // utilizable o mandan a dejar de reintentar.
        assert!(!matches!(ImapError::Fallo("x".into()), ImapError::Desincronizada(_)));
        assert!(!matches!(ImapError::Rechazado("x".into()), ImapError::Desincronizada(_)));
    }

    /// Pedir `1:0` es un error de sintaxis, y hay servidores que ante uno cortan
    /// la sesión en vez de contestar. Una casilla vacía es de lo más común: una
    /// carpeta recién creada, o una cuenta nueva.
    #[test]
    fn una_casilla_vacia_no_genera_un_rango_invalido() {
        assert_eq!(ultimos(0, CUANTOS), None);
        assert_eq!(ultimos(10, 0), None);
    }

    #[test]
    fn el_rango_toma_los_ultimos_y_no_se_pasa_del_principio() {
        assert_eq!(ultimos(1000, 200), Some("801:1000".into()));
        // Con menos mensajes que el tope, se piden todos: no hay un `0:` ni un
        // número negativo dado vuelta.
        assert_eq!(ultimos(5, 200), Some("1:5".into()));
        assert_eq!(ultimos(1, 200), Some("1:1".into()));
    }

    /// El formato del XOAUTH2 lo fijan Google y Microsoft y no se parece a nada
    /// más del protocolo. Escribirlo con espacios o dos puntos, que es lo
    /// intuitivo, da un rechazo que parece de credenciales y no lo es.
    #[test]
    fn el_xoauth2_usa_el_separador_que_fija_el_proveedor() {
        let carga = carga_xoauth2("ana@ejemplo.com", "el-token");
        let crudo = base64::engine::general_purpose::STANDARD.decode(&carga).unwrap();

        assert_eq!(crudo, b"user=ana@ejemplo.com\x01auth=Bearer el-token\x01\x01");
        // Y termina en dos separadores, no en uno: los servidores rechazan la
        // carga si falta el último.
        assert!(crudo.ends_with(b"\x01\x01"));
    }

    #[test]
    fn una_credencial_con_salto_de_linea_no_se_manda() {
        for veneno in ["a\r\nA1 LOGOUT", "a\nb", "a\rb", "a\0b"] {
            assert_eq!(comillas(veneno), None, "{veneno:?} tenía que rechazarse");
        }
    }

    #[test]
    fn las_comillas_y_las_barras_se_escapan() {
        assert_eq!(comillas("simple").unwrap(), "\"simple\"");
        assert_eq!(comillas(r#"con"comilla"#).unwrap(), r#""con\"comilla""#);
        // El orden importa: escapar la comilla primero dejaría sin escapar la
        // barra que se acaba de agregar.
        assert_eq!(comillas(r#"\""#).unwrap(), r#""\\\"""#);
    }

    #[test]
    fn se_reconoce_la_respuesta_con_etiqueta() {
        assert_eq!(respuesta_de("a1 OK listo", "a1"), Some(Respuesta::Ok));
        assert_eq!(respuesta_de("a1 ok listo", "a1"), Some(Respuesta::Ok));
        assert_eq!(
            respuesta_de("a1 NO [AUTHENTICATIONFAILED] mal", "a1"),
            Some(Respuesta::No("[AUTHENTICATIONFAILED] mal".into()))
        );
    }

    /// Una etiqueta que es prefijo de otra no puede confundirse: con diez
    /// comandos en una sesión, `a1` no tiene que emparejar con `a10`.
    #[test]
    fn una_etiqueta_no_empareja_con_otra_mas_larga() {
        assert_eq!(respuesta_de("a10 OK listo", "a1"), None);
        assert_eq!(respuesta_de("* OK sin etiqueta", "a1"), None);
        assert_eq!(respuesta_de("+ continuá", "a1"), None);
    }





    /// Las capacidades llegan de dos formas y hay servidores que sólo usan una:
    /// pegadas al saludo entre corchetes, o en su propia línea. Leer sólo una
    /// haría que IDLE se diera por no soportado contra la mitad de los
    /// servidores que sí lo tienen.
    #[test]
    fn las_capacidades_se_leen_del_saludo_y_de_su_propia_linea() {
        let del_saludo = capacidades_de("* OK [CAPABILITY IMAP4rev1 IDLE LITERAL+] listo");
        assert!(del_saludo.contains(&"IDLE".to_string()));
        assert!(del_saludo.contains(&"IMAP4REV1".to_string()));
        // Y no se lleva lo que viene después del corchete.
        assert!(!del_saludo.iter().any(|c| c.contains("LISTO")));

        let de_su_linea = capacidades_de("* CAPABILITY IMAP4rev1 IDLE UIDPLUS");
        assert!(de_su_linea.contains(&"IDLE".to_string()));
        assert!(de_su_linea.contains(&"UIDPLUS".to_string()));
    }

    /// En minúsculas también: el protocolo no distingue, y un servidor que
    /// anuncie `idle` soporta IDLE igual.
    #[test]
    fn las_capacidades_no_distinguen_mayusculas() {
        assert!(capacidades_de("* capability imap4rev1 idle").contains(&"IDLE".to_string()));
    }

    #[test]
    fn una_linea_sin_capacidades_no_devuelve_ninguna() {
        for otra in ["", "* OK listo", "a1 OK", "* 5 EXISTS"] {
            assert!(capacidades_de(otra).is_empty(), "{otra:?}");
        }
    }

    #[test]
    fn se_lee_cuantos_mensajes_hay() {
        assert_eq!(exists_de("* 42 EXISTS"), Some(42));
        assert_eq!(exists_de("* 0 EXISTS"), Some(0));
        // Y no se confunde con otras respuestas que también llevan un número.
        for otra in ["* 3 RECENT", "* 7 EXPUNGE", "* OK listo", "", "* EXISTS"] {
            assert_eq!(exists_de(otra), None, "{otra:?}");
        }
    }

    /// Los números del SEARCH son identificadores de mensaje: lo único que hace
    /// falta es cuántos hay. Sumarlos, que es el error fácil, daría un contador
    /// disparatado.
    #[test]
    fn del_search_se_cuentan_los_resultados() {
        assert_eq!(resultados_de_search("* SEARCH 3 5 9"), Some(3));
        assert_eq!(resultados_de_search("* SEARCH 100"), Some(1));
        // Sin resultados: la casilla está toda leída.
        assert_eq!(resultados_de_search("* SEARCH"), Some(0));
        assert_eq!(resultados_de_search("* search 1 2"), Some(2));
        assert_eq!(resultados_de_search("* OK listo"), None);
    }

    /// Qué avisos hacen que valga la pena volver a contar.
    ///
    /// `EXISTS` es correo nuevo, `EXPUNGE` un borrado y `FETCH` una marca que
    /// cambió desde otro dispositivo. `RECENT` **no**: hay servidores que lo
    /// repiten sin que haya nada nuevo, y despertarse por él sería contar de más
    /// sin motivo.
    #[test]
    fn se_reconoce_lo_que_cambia_de_lo_que_no() {
        for cambio in ["* 5 EXISTS", "* 3 EXPUNGE", "* 2 FETCH (FLAGS (\\Seen))", "* 12 exists"] {
            assert!(anuncia_cambio(cambio), "{cambio:?} tenía que despertar");
        }
        for quieto in [
            "* 3 RECENT",
            "* OK todavía nada",
            "+ idling",
            "a1 OK IDLE terminated",
            "",
            "* CAPABILITY IMAP4rev1",
        ] {
            assert!(!anuncia_cambio(quieto), "{quieto:?} no tenía que despertar");
        }
    }

    /// El búfer propio es lo que hace que se pueda esperar con reloj: sin él,
    /// cancelar una lectura a medias perdería lo leído y la respuesta siguiente
    /// llegaría cortada.
    #[test]
    fn las_lineas_salen_del_buffer_de_a_una() {
        let mut pendiente = b"* OK uno\r\n* OK dos\r\n* OK incom".to_vec();

        assert_eq!(linea_del_buffer(&mut pendiente).as_deref(), Some("* OK uno"));
        assert_eq!(linea_del_buffer(&mut pendiente).as_deref(), Some("* OK dos"));
        // La tercera está a medias: no se entrega hasta que llegue su fin de
        // línea, y lo leído sigue en el búfer esperándola.
        assert_eq!(linea_del_buffer(&mut pendiente), None);
        assert_eq!(pendiente, b"* OK incom");
    }

    /// La propiedad que hace posible esperar con reloj: si la espera se
    /// abandona a mitad de una línea, lo leído **no se pierde**.
    ///
    /// Con el `read_line` de un `BufReader` esto no se cumple —está documentado
    /// que cancelar pierde lo leído— y el síntoma sería una respuesta cortada al
    /// azar cada media hora, cuando IDLE renueva la espera.
    #[test]
    fn lo_leido_a_medias_sigue_ahi_para_la_proxima() {
        let mut pendiente = Vec::new();

        // Llega media línea y la espera se abandona.
        pendiente.extend_from_slice(b"* 5 EX");
        assert_eq!(linea_del_buffer(&mut pendiente), None);

        // Llega el resto: la línea sale entera.
        pendiente.extend_from_slice(b"ISTS\r\n");
        assert_eq!(linea_del_buffer(&mut pendiente).as_deref(), Some("* 5 EXISTS"));
        assert!(pendiente.is_empty());
    }
}
