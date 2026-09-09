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
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use crate::broker::{Credencial, Destino};

/// Tope de cada operación contra el servidor.
const TIMEOUT: Duration = Duration::from_secs(30);

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

/// Lee los contadores de una respuesta `* STATUS`.
///
/// El orden de los elementos lo elige el servidor —el estándar no lo fija— así
/// que se buscan por nombre. Leerlos por posición anda contra unos servidores y
/// contra otros no, que es la peor clase de error.
pub fn estado_de(linea: &str) -> Option<Estado> {
    let dentro = linea.rsplit_once('(')?.1;
    let dentro = dentro.split_once(')')?.0;

    let partes: Vec<&str> = dentro.split_whitespace().collect();
    let buscar = |nombre: &str| -> Option<u32> {
        partes
            .iter()
            .position(|p| p.eq_ignore_ascii_case(nombre))
            .and_then(|i| partes.get(i + 1))
            .and_then(|v| v.parse().ok())
    };

    Some(Estado {
        mensajes: buscar("MESSAGES")?,
        sin_leer: buscar("UNSEEN").unwrap_or(0),
    })
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
    lector: BufReader<Flujo>,
    etiqueta: u32,
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

        let mut sesion = Sesion { lector: BufReader::new(cifrado), etiqueta: 0 };

        let saludo = sesion.leer_linea().await?;
        if saludo.starts_with("* BYE") {
            return Err(ImapError::Fallo(format!("el servidor cerró la conexión: {saludo}")));
        }

        sesion.autenticar(&destino.credencial).await?;
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

    /// Cuántos mensajes y cuántos sin leer hay en una casilla.
    pub async fn estado(&mut self, casilla: &str) -> Result<Estado, ImapError> {
        let nombre = comillas(casilla)
            .ok_or_else(|| ImapError::Fallo("el nombre de la casilla no es válido".into()))?;

        let etiqueta = self.siguiente_etiqueta();
        self.escribir(&format!("{etiqueta} STATUS {nombre} (MESSAGES UNSEEN)"))
            .await?;

        let mut estado = None;
        loop {
            let linea = self.leer_linea().await?;
            if linea.to_uppercase().starts_with("* STATUS") {
                estado = estado_de(&linea);
                continue;
            }
            match respuesta_de(&linea, &etiqueta) {
                Some(Respuesta::Ok) => break,
                Some(Respuesta::No(d)) | Some(Respuesta::Bad(d)) => {
                    return Err(ImapError::Fallo(format!(
                        "el servidor no pudo mirar «{casilla}»: {d}"
                    )))
                }
                None => continue,
            }
        }

        estado.ok_or_else(|| {
            ImapError::Fallo(format!("el servidor no dijo el estado de «{casilla}»"))
        })
    }

    pub async fn cerrar(mut self) {
        let etiqueta = self.siguiente_etiqueta();
        let _ = self.escribir(&format!("{etiqueta} LOGOUT")).await;
    }

    fn siguiente_etiqueta(&mut self) -> String {
        self.etiqueta += 1;
        format!("a{}", self.etiqueta)
    }

    /// Manda un comando y espera su respuesta con etiqueta.
    async fn mandar(&mut self, comando: &str) -> Result<(), ImapError> {
        let etiqueta = self.siguiente_etiqueta();
        self.escribir(&format!("{etiqueta} {comando}")).await?;

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
    }

    async fn escribir(&mut self, linea: &str) -> Result<(), ImapError> {
        let flujo: &mut (dyn AsyncWrite + Unpin + Send) = self.lector.get_mut();
        flujo
            .write_all(linea.as_bytes())
            .await
            .and_then(|_| std::future::ready(Ok(())).into_inner())
            .map_err(|e| ImapError::Fallo(format!("no se pudo escribir: {e}")))?;
        flujo
            .write_all(b"\r\n")
            .await
            .map_err(|e| ImapError::Fallo(format!("no se pudo escribir: {e}")))?;
        flujo
            .flush()
            .await
            .map_err(|e| ImapError::Fallo(format!("no se pudo escribir: {e}")))
    }

    async fn leer_linea(&mut self) -> Result<String, ImapError> {
        let mut linea = String::new();
        let leidos = tokio::io::AsyncReadExt::take(&mut self.lector, MAX_LINEA)
            .read_line(&mut linea)
            .await
            .map_err(|e| ImapError::Fallo(format!("no se pudo leer: {e}")))?;

        if leidos == 0 {
            return Err(ImapError::Fallo("el servidor cortó la conexión".into()));
        }
        Ok(linea.trim_end().to_string())
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

    /// El orden de los elementos del STATUS lo elige el servidor: el estándar no
    /// lo fija. Leerlos por posición anda contra unos y contra otros no, que es
    /// la peor clase de error.
    #[test]
    fn el_estado_se_lee_por_nombre_y_no_por_posicion() {
        let esperado = Estado { mensajes: 42, sin_leer: 7 };

        assert_eq!(
            estado_de("* STATUS \"INBOX\" (MESSAGES 42 UNSEEN 7)"),
            Some(esperado)
        );
        // Al revés, y con algo más en el medio.
        assert_eq!(
            estado_de("* STATUS INBOX (UNSEEN 7 RECENT 3 MESSAGES 42)"),
            Some(esperado)
        );
        // Y sin importar mayúsculas.
        assert_eq!(
            estado_de("* status INBOX (messages 42 unseen 7)"),
            Some(esperado)
        );
    }

    /// Un servidor puede no informar UNSEEN. Cero es la respuesta correcta —no
    /// hay nada que avisar— y no un fallo que deje la cuenta sin sincronizar.
    #[test]
    fn sin_unseen_no_hay_nada_sin_leer() {
        assert_eq!(
            estado_de("* STATUS INBOX (MESSAGES 5)"),
            Some(Estado { mensajes: 5, sin_leer: 0 })
        );
    }

    /// Una casilla con paréntesis en el nombre no puede correr los campos: se
    /// lee desde el **último** paréntesis de apertura.
    #[test]
    fn un_nombre_con_parentesis_no_corre_los_campos() {
        assert_eq!(
            estado_de("* STATUS \"Archivo (viejo)\" (MESSAGES 3 UNSEEN 1)"),
            Some(Estado { mensajes: 3, sin_leer: 1 })
        );
    }

    #[test]
    fn lo_que_no_es_un_estado_no_devuelve_nada() {
        for basura in [
            "",
            "* STATUS INBOX",
            "* STATUS INBOX ()",
            "* STATUS INBOX (UNSEEN 7)",
            "* OK otra cosa",
            "* STATUS INBOX (MESSAGES muchos)",
        ] {
            assert_eq!(estado_de(basura), None, "{basura:?} no es un estado");
        }
    }
}
