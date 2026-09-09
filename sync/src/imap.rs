//! Lo justo de IMAP para saber cuánto correo sin leer hay.
//!
//! ── Por qué tan poco ────────────────────────────────────────────────────────
//!
//! Todavía no existe la aplicación de correo, así que un caché de mensajes sería
//! inventarle un formato a un consumidor que no está. Lo que **sí** sirve hoy y
//! no depende de nadie es el contador de sin leer: alcanza para que el
//! escritorio muestre que llegó algo.
//!
//! Y hay una razón de fondo para empezar por ahí: `STATUS` devuelve cuatro
//! números y nada más. No hay que tocar un cuerpo de mensaje, ni una cabecera,
//! ni MIME — o sea, ni una línea de parser sobre lo que escribió un remitente
//! desconocido. El día que haya que leer mensajes de verdad, ese parser va a ser
//! la parte peligrosa y va a merecer su propia discusión.
//!
//! ── Sobre el proceso donde corre ────────────────────────────────────────────
//!
//! Como el usuario, nunca como root. Es la razón de que este binario exista
//! aparte del servicio de cuentas.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::broker::{Credencial, Destino};

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

#[derive(Debug)]
pub enum ImapError {
    /// El servidor dijo que no a las credenciales. Se distingue porque es el
    /// caso en que hay que avisar y **dejar de reintentar**: insistir con una
    /// contraseña que el servidor rechaza es cómo se bloquea una cuenta.
    Rechazado(String),
    Fallo(String),
}

impl std::fmt::Display for ImapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImapError::Rechazado(d) => write!(f, "el servidor rechazó las credenciales: {d}"),
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
    let sin_asterisco = linea.strip_prefix("* ")?;
    let resto = sin_asterisco.strip_prefix("SEARCH").or_else(|| {
        sin_asterisco
            .to_ascii_uppercase()
            .starts_with("SEARCH")
            .then(|| &sin_asterisco["SEARCH".len()..])
    })?;
    Some(resto.split_whitespace().count() as u32)
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

// ---------------------------------------------------------------------------
// La parte que habla por la red
// ---------------------------------------------------------------------------

fn tls() -> Result<TlsConnector, ImapError> {
    let mut raices = RootCertStore::empty();
    for certificado in rustls_native_certs::load_native_certs().certs {
        let _ = raices.add(certificado);
    }
    if raices.is_empty() {
        return Err(ImapError::Fallo(
            "no hay certificados de confianza instalados en el equipo".into(),
        ));
    }
    Ok(TlsConnector::from(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(raices)
            .with_no_client_auth(),
    )))
}

type Flujo = tokio_rustls::client::TlsStream<TcpStream>;

pub struct Sesion {
    flujo: Flujo,
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
}

impl Sesion {
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
        let cifrado = tls()?
            .connect(nombre, tcp)
            .await
            .map_err(|e| ImapError::Fallo(format!("no se pudo cifrar la conexión: {e}")))?;

        let mut sesion = Sesion {
            flujo: cifrado,
            pendiente: Vec::new(),
            etiqueta: 0,
            capacidades: Vec::new(),
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
        let nombre = comillas(casilla)
            .ok_or_else(|| ImapError::Fallo("el nombre de la casilla no es válido".into()))?;

        let etiqueta = self.siguiente_etiqueta();
        self.escribir(&format!("{etiqueta} EXAMINE {nombre}")).await?;

        Self::con_tope("abrir la casilla", async {
            let mut mensajes = 0;
            loop {
                let linea = self.leer_linea().await?;
                if let Some(n) = exists_de(&linea) {
                    mensajes = n;
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
    use super::*;

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
