//! Entregar un mensaje a un servidor SMTP.
//!
//! ── Cifrado siempre, sin excepción ──────────────────────────────────────────
//!
//! O el puerto habla TLS desde el primer byte —el 465—, o se negocia con
//! `STARTTLS` antes de decir nada. Un servidor que no ofrece `STARTTLS` en un
//! puerto en claro **se rechaza**: seguir sería mandar la contraseña de la
//! persona y el mensaje entero a la vista de cualquiera en la red.
//!
//! Es tentador dejar una salida para «servidores viejos». No la hay: un correo
//! sin cifrar es la contraseña de la cuenta viajando en claro, y la persona no
//! tiene forma de saber que pasó.
//!
//! ── Por qué los errores se separan en tres ──────────────────────────────────
//!
//! Porque la cola necesita saber **si vale la pena volver a intentar**. Un 4xx
//! es «ahora no» y se reintenta; un 5xx es «esto no va a andar nunca» —una
//! dirección que no existe, un mensaje rechazado por tamaño— y reintentarlo es
//! quemar la reputación de la cuenta contra el servidor; y un rechazo de
//! credenciales no se arregla insistiendo, se arregla reconectando la cuenta.
//!
//! Sin esa distinción, una cola termina reintentando para siempre un mensaje que
//! nunca se va a entregar, y la persona ve «enviando…» hasta que apaga el
//! equipo.

use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::broker::{Credential, Endpoint};

/// Tope para conectarse y saludar.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Tope de un intercambio: mandar algo y leer la respuesta.
///
/// Vale lo mismo que en IMAP: un servidor que deja de escribir sin cerrar el
/// socket no produce ningún error, la lectura no vuelve nunca, y sin tope el
/// mensaje se queda «enviando» para siempre.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(120);

/// Tope de una línea de respuesta.
const MAX_LINE: usize = 8 * 1024;

/// El puerto que habla TLS desde el primer byte.
const IMPLICIT_TLS_PORT: u16 = 465;

/// El nombre con el que este equipo se presenta.
///
/// `localhost` y no el nombre real del equipo: el `EHLO` viaja en claro hasta
/// que se negocia el cifrado, y el nombre de la máquina de alguien no tiene por
/// qué ir ahí. Los servidores que importan miran la dirección IP y el resultado
/// de la autenticación, no esto.
const EHLO_NAME: &str = "localhost";

#[derive(Debug)]
pub enum SmtpError {
    /// El servidor no aceptó las credenciales. No se reintenta: insistir con una
    /// contraseña rechazada es cómo se bloquea una cuenta.
    Rejected(String),
    /// El servidor dijo que no y no va a cambiar de opinión: un 5xx. Una
    /// dirección que no existe, un mensaje demasiado grande. Reintentarlo es
    /// quemar la reputación de la cuenta contra el servidor.
    Permanent(String),
    /// Ahora no: un 4xx, o la red. Se vuelve a intentar más tarde.
    Temporary(String),
}

impl std::fmt::Display for SmtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmtpError::Rejected(d) => {
                write!(f, "el servidor rechazó las credenciales: {d}")
            }
            SmtpError::Permanent(d) => write!(f, "{d}"),
            SmtpError::Temporary(d) => write!(f, "{d}"),
        }
    }
}

impl std::error::Error for SmtpError {}

impl SmtpError {
    /// Si tiene sentido volver a intentarlo.
    pub fn is_retryable(&self) -> bool {
        matches!(self, SmtpError::Temporary(_))
    }
}

// ---------------------------------------------------------------------------
// Lo que se puede probar sin red
// ---------------------------------------------------------------------------

/// Lee una línea de respuesta: el código y si la respuesta sigue.
///
/// El formato es `250-texto` cuando sigue y `250 texto` cuando termina. El
/// guión contra el espacio es **toda** la diferencia, y confundirlos deja al
/// cliente esperando una línea que ya llegó o leyendo la respuesta del comando
/// siguiente como si fuera de éste.
pub fn parse_reply(line: &str) -> Option<(u16, bool, String)> {
    if line.len() < 3 {
        return None;
    }
    let code: u16 = line.get(..3)?.parse().ok()?;

    match line.as_bytes().get(3) {
        Some(b'-') => Some((code, true, line[4..].to_string())),
        Some(b' ') => Some((code, false, line[4..].to_string())),
        // `250` pelado, sin texto: es válido y termina la respuesta.
        None => Some((code, false, String::new())),
        _ => None,
    }
}

/// Cómo clasificar el código que contestó el servidor.
pub fn classify_reply(code: u16, detail: String) -> SmtpError {
    match code {
        // Los de autenticación son su propio caso: no se arreglan reintentando
        // y hay que avisarle a la persona que reconecte la cuenta.
        535 | 530 | 534 | 538 => SmtpError::Rejected(detail),
        500..=599 => SmtpError::Permanent(detail),
        _ => SmtpError::Temporary(detail),
    }
}

/// Protege los puntos al principio de línea.
///
/// El bloque de datos termina con una línea que dice sólo `.`, así que una línea
/// del mensaje que empiece con un punto tiene que llevar otro. Sin esto, un
/// mensaje cuyo texto tenga una línea `.` se **corta ahí**: lo que sigue el
/// servidor lo lee como comandos SMTP, y en el mejor de los casos la conexión
/// muere. Es una de las cosas más viejas y más olvidadas del protocolo.
pub fn dot_stuff(message: &str) -> String {
    message
        .split("\r\n")
        .map(|line| {
            if line.starts_with('.') {
                format!(".{line}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// Si una dirección se puede escribir dentro de un comando sin partirlo.
///
/// No valida que sea una dirección —de eso se ocupa `compose`— sino que **no
/// pueda salirse del comando**: un salto de línea la convierte en un comando
/// SMTP más, y desde ahí se manda lo que sea en nombre de la persona.
pub fn fits_in_command(address: &str) -> bool {
    !address.is_empty()
        && address.len() <= 320
        && !address.chars().any(|c| c.is_control() || c.is_whitespace())
        && !address.contains(['<', '>'])
}

/// La carga de `AUTH PLAIN`: `\0usuario\0secreto`, en base64.
pub fn plain_payload(username: &str, secret: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("\0{username}\0{secret}"))
}

/// La carga de `AUTH XOAUTH2`, con el formato que fijan Google y Microsoft.
///
/// El separador es `\x01` y no un espacio ni dos puntos, que es lo intuitivo.
/// Escribirlo mal da un rechazo que parece de credenciales y no lo es.
pub fn xoauth2_payload(username: &str, token: &str) -> String {
    base64::engine::general_purpose::STANDARD
        .encode(format!("user={username}\x01auth=Bearer {token}\x01\x01"))
}

/// Qué mecanismo de autenticación usar.
///
/// Se elige por **la credencial primero** y por lo que ofrece el servidor
/// después: una cuenta con token no puede autenticarse con `PLAIN` aunque el
/// servidor lo ofrezca —mandaría el token donde va una contraseña—, y una con
/// contraseña no puede usar `XOAUTH2`.
pub fn pick_mechanism(offered: &[String], credential: &Credential) -> Option<&'static str> {
    let offers = |name: &str| offered.iter().any(|m| m.eq_ignore_ascii_case(name));

    match credential {
        Credential::Token { .. } => offers("XOAUTH2").then_some("XOAUTH2"),
        Credential::Password { .. } => {
            // `PLAIN` antes que `LOGIN`: es una sola vuelta en vez de tres, y
            // los dos mandan lo mismo. `LOGIN` está para los servidores que no
            // ofrecen el otro, que todavía hay.
            if offers("PLAIN") {
                Some("PLAIN")
            } else if offers("LOGIN") {
                Some("LOGIN")
            } else {
                None
            }
        }
    }
}

/// Los mecanismos que anuncia una línea `250-AUTH ...`.
pub fn mechanisms_from(line: &str) -> Vec<String> {
    let trimmed = line.trim();
    if !trimmed.to_ascii_uppercase().starts_with("AUTH") {
        return Vec::new();
    }

    // El separador es un espacio, pero hay servidores que ponen un `=` después
    // de AUTH: los dos aparecen en la naturaleza.
    trimmed["AUTH".len()..]
        .trim_start_matches(['=', ' '])
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

// ---------------------------------------------------------------------------
// La parte que habla por la red
// ---------------------------------------------------------------------------

/// Uno de los dos flujos posibles: en claro mientras se negocia, cifrado después.
enum Transport {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    /// Ninguno, y **sólo mientras se cambia uno por el otro**.
    ///
    /// Envolver el socket en TLS pide moverlo, y moverlo de adentro de la
    /// estructura deja el hueco: esto es lo que va en el hueco durante esas dos
    /// líneas. Existe para no tener que inventar un socket de mentira para
    /// tapar el agujero, que era la otra salida y consistía en abrir una
    /// conexión que nadie usa y paniquear si fallaba.
    Closed,
}

impl Transport {
    /// Escribe, **con plazo**.
    ///
    /// Sin él, un servidor que deja de leer sin cerrar el socket llena el búfer
    /// del sistema y `write_all` se queda esperando para siempre. Pasa con un
    /// NAT que olvidó la conexión o un proceso matado sin FIN, y como el
    /// despachador manda de a un mensaje por vez, esa espera **frena la cola
    /// entera**: todo lo que la persona escriba después se queda sin salir, sin
    /// ningún error y sin nada en el diario.
    async fn write(&mut self, data: &[u8]) -> Result<(), SmtpError> {
        let writing = async {
            match self {
                Transport::Plain(f) => f.write_all(data).await,
                Transport::Tls(f) => f.write_all(data).await,
                Transport::Closed => Err(std::io::Error::other("no hay conexión")),
            }
        };

        tokio::time::timeout(EXCHANGE_TIMEOUT, writing)
            .await
            .map_err(|_| {
                SmtpError::Temporary(format!(
                    "el servidor dejó de recibir (más de {} segundos)",
                    EXCHANGE_TIMEOUT.as_secs()
                ))
            })?
            .map_err(|e| SmtpError::Temporary(format!("no se pudo escribir: {e}")))
    }

    async fn read(&mut self, destination: &mut Vec<u8>) -> Result<usize, SmtpError> {
        let result = match self {
            Transport::Plain(f) => f.read_buf(destination).await,
            Transport::Tls(f) => f.read_buf(destination).await,
            Transport::Closed => return Err(SmtpError::Temporary("no hay conexión".into())),
        };
        result.map_err(|e| SmtpError::Temporary(format!("no se pudo leer: {e}")))
    }

    fn is_encrypted(&self) -> bool {
        matches!(self, Transport::Tls(_))
    }
}

/// Una sesión SMTP, de la conexión al `QUIT`.
pub struct Session {
    transport: Transport,
    pending: Vec<u8>,
    /// Lo que el servidor dijo saber hacer, del `EHLO`.
    mechanisms: Vec<String>,
    starttls: bool,
}

impl Session {
    /// Conecta, cifra y se autentica.
    pub async fn open(destination: &Endpoint) -> Result<Self, SmtpError> {
        let tcp = tokio::time::timeout(
            TIMEOUT,
            TcpStream::connect((destination.host.as_str(), destination.port)),
        )
        .await
        .map_err(|_| SmtpError::Temporary(format!("{} no contestó a tiempo", destination.host)))?
        .map_err(|e| {
            SmtpError::Temporary(format!("no se pudo conectar a {}: {e}", destination.host))
        })?;

        let mut session = Session {
            transport: Transport::Plain(tcp),
            pending: Vec::new(),
            mechanisms: Vec::new(),
            starttls: false,
        };

        if destination.port == IMPLICIT_TLS_PORT {
            session.upgrade_to_tls(&destination.host).await?;
        }

        // El saludo del servidor va primero, antes de decir nada.
        session.expect_reply(&["220"]).await?;
        session.ehlo().await?;

        if !session.transport.is_encrypted() {
            if !session.starttls {
                // **Sin salida.** Seguir sería mandar la contraseña de la
                // persona y el mensaje entero a la vista de cualquiera.
                return Err(SmtpError::Permanent(format!(
                    "{} no ofrece cifrado en el puerto {}, y sin cifrado no se manda nada",
                    destination.host, destination.port
                )));
            }
            session.command("STARTTLS", &["220"]).await?;
            session.upgrade_to_tls(&destination.host).await?;
            // Y de nuevo el saludo: lo que el servidor anunció antes de cifrar
            // no vale, justamente porque cualquiera pudo haberlo cambiado en el
            // camino. Los mecanismos de autenticación son lo que más importa
            // acá: uno inyectado podría degradar a algo que manda la contraseña
            // en claro.
            session.mechanisms.clear();
            session.ehlo().await?;
        }

        session.authenticate(&destination.credential).await?;
        Ok(session)
    }

    /// Entrega el mensaje.
    pub async fn deliver(
        &mut self,
        sender: &str,
        recipients: &[String],
        message: &str,
    ) -> Result<(), SmtpError> {
        // **Las direcciones se revisan otra vez acá.** Ya pasaron por
        // `compose::validate` antes de encolarse, así que esto no debería
        // encontrar nada — y por eso mismo va: que `deliver` sea segura no
        // puede depender de que quien la llame se haya acordado de validar
        // primero. Una dirección con un salto de línea es un comando SMTP
        // inyectado, y desde ahí se manda cualquier cosa en nombre de la
        // persona. El archivo de la cola además vive en el disco y se puede
        // haber tocado a mano.
        for address in std::iter::once(sender).chain(recipients.iter().map(String::as_str)) {
            if !fits_in_command(address) {
                return Err(SmtpError::Permanent(format!(
                    "«{address}» no se puede usar como dirección"
                )));
            }
        }

        self.command(&format!("MAIL FROM:<{sender}>"), &["250"])
            .await?;

        for recipient in recipients {
            // 251 es «no está acá pero lo reenvío», que es una entrega buena.
            self.command(&format!("RCPT TO:<{recipient}>"), &["250", "251"])
                .await?;
        }

        self.command("DATA", &["354"]).await?;

        let body = dot_stuff(message);
        self.transport.write(body.as_bytes()).await?;
        // El punto solo cierra el bloque. El `\r\n` de antes va siempre, aunque
        // el mensaje ya termine en uno: un `.` pegado al final de la última
        // línea es parte del texto y no el cierre.
        self.transport.write(b"\r\n.\r\n").await?;

        // **Éste es el momento en que el mensaje se mandó o no.** Un 250 acá
        // quiere decir que el servidor se hizo cargo; cualquier otra cosa, que
        // no. La respuesta puede tardar: hay servidores que revisan el mensaje
        // entero antes de contestar, y por eso el tope de intercambio es largo.
        self.expect_reply(&["250"]).await?;
        Ok(())
    }

    /// Se despide. Un fallo acá no importa: el mensaje ya se entregó.
    pub async fn close(&mut self) {
        let _ = self.transport.write(b"QUIT\r\n").await;
    }

    async fn ehlo(&mut self) -> Result<(), SmtpError> {
        self.transport
            .write(format!("EHLO {EHLO_NAME}\r\n").as_bytes())
            .await?;

        let lines = self.expect_reply(&["250"]).await?;
        for line in lines {
            let upper = line.to_ascii_uppercase();
            if upper.starts_with("STARTTLS") {
                self.starttls = true;
            }
            if upper.starts_with("AUTH") {
                self.mechanisms.extend(mechanisms_from(&line));
            }
        }
        Ok(())
    }

    async fn upgrade_to_tls(&mut self, host: &str) -> Result<(), SmtpError> {
        let connector = crate::tls::connector().map_err(SmtpError::Permanent)?;
        let name = ServerName::try_from(host.to_string())
            .map_err(|_| SmtpError::Permanent(format!("«{host}» no es un nombre válido")))?;

        // Sacar el socket de adentro para envolverlo, dejando `Closed` en el
        // hueco mientras tanto. Si el cifrado falla, el hueco queda: cualquier
        // uso posterior da «no hay conexión», que es exactamente lo que pasó y
        // es mejor que dejar puesto un socket en claro por el que se podría
        // seguir hablando sin cifrar.
        let Transport::Plain(tcp) = std::mem::replace(&mut self.transport, Transport::Closed)
        else {
            return Err(SmtpError::Permanent(
                "no hay una conexión en claro que cifrar".into(),
            ));
        };

        // Con plazo, como todo lo demás: un servidor que acepta la conexión y no
        // completa el saludo de TLS deja el apretón de manos colgado, y con él
        // la cola entera.
        let encrypted = tokio::time::timeout(TIMEOUT, connector.connect(name, tcp))
            .await
            .map_err(|_| SmtpError::Temporary(format!("{host} no completó el cifrado a tiempo")))?
            .map_err(|e| SmtpError::Temporary(format!("no se pudo cifrar con {host}: {e}")))?;
        self.transport = Transport::Tls(Box::new(encrypted));
        Ok(())
    }

    async fn authenticate(&mut self, credential: &Credential) -> Result<(), SmtpError> {
        let Some(mechanism) = pick_mechanism(&self.mechanisms, credential) else {
            return Err(SmtpError::Permanent(
                "el servidor no acepta ninguna forma de autenticación que esta cuenta pueda usar"
                    .into(),
            ));
        };

        match (mechanism, credential) {
            ("XOAUTH2", Credential::Token { username, token }) => {
                let payload = xoauth2_payload(username, token);
                self.command(&format!("AUTH XOAUTH2 {payload}"), &["235"])
                    .await
            }
            ("PLAIN", Credential::Password { username, secret }) => {
                let payload = plain_payload(username, secret);
                self.command(&format!("AUTH PLAIN {payload}"), &["235"])
                    .await
            }
            ("LOGIN", Credential::Password { username, secret }) => {
                self.command("AUTH LOGIN", &["334"]).await?;
                let u = base64::engine::general_purpose::STANDARD.encode(username);
                self.command(&u, &["334"]).await?;
                let s = base64::engine::general_purpose::STANDARD.encode(secret);
                self.command(&s, &["235"]).await
            }
            // `pick_mechanism` sólo devuelve combinaciones que existen, así que esto
            // no pasa. Se contesta con un error en vez de con un pánico: un
            // pánico acá se lleva puesta la tarea que estaba mandando.
            _ => Err(SmtpError::Permanent(
                "la credencial no va con el mecanismo elegido".into(),
            )),
        }
    }

    /// Manda una línea y espera una respuesta con uno de los códigos esperados.
    async fn command(&mut self, command: &str, expected: &[&str]) -> Result<(), SmtpError> {
        self.transport
            .write(format!("{command}\r\n").as_bytes())
            .await?;
        self.expect_reply(expected).await?;
        Ok(())
    }

    /// Lee una respuesta entera y comprueba su código.
    ///
    /// Devuelve las líneas sin el código, que es lo que hace falta para leer lo
    /// que anuncia el `EHLO`.
    async fn expect_reply(&mut self, expected: &[&str]) -> Result<Vec<String>, SmtpError> {
        let reading = async {
            let mut lines = Vec::new();
            loop {
                let line = self.read_line().await?;
                let Some((code, more, text)) = parse_reply(&line) else {
                    return Err(SmtpError::Temporary(format!(
                        "el servidor contestó algo que no se entiende: {line}"
                    )));
                };

                let is_expected = expected.iter().any(|e| line.starts_with(e));
                if !is_expected {
                    return Err(classify_reply(code, text));
                }
                lines.push(text);
                if !more {
                    return Ok(lines);
                }
            }
        };

        tokio::time::timeout(EXCHANGE_TIMEOUT, reading)
            .await
            .map_err(|_| {
                SmtpError::Temporary(format!(
                    "el servidor dejó de contestar (más de {} segundos)",
                    EXCHANGE_TIMEOUT.as_secs()
                ))
            })?
    }

    async fn read_line(&mut self) -> Result<String, SmtpError> {
        loop {
            if let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.pending.drain(..=end).collect();
                return Ok(String::from_utf8_lossy(&line).trim_end().to_string());
            }
            if self.pending.len() > MAX_LINE {
                return Err(SmtpError::Temporary(
                    "el servidor mandó una línea sin fin".into(),
                ));
            }

            let mut destination = std::mem::take(&mut self.pending);
            let read_count = self.transport.read(&mut destination).await;
            self.pending = destination;
            if read_count? == 0 {
                return Err(SmtpError::Temporary("el servidor cortó la conexión".into()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// El guión contra el espacio es **toda** la diferencia entre «sigue» y
    /// «terminé». Confundirlos deja al cliente esperando una línea que ya llegó,
    /// o leyendo la respuesta del comando siguiente como si fuera de éste.
    #[test]
    fn se_distingue_la_ultima_linea_de_las_del_medio() {
        assert_eq!(
            parse_reply("250-STARTTLS"),
            Some((250, true, "STARTTLS".into()))
        );
        assert_eq!(
            parse_reply("250 AUTH PLAIN LOGIN"),
            Some((250, false, "AUTH PLAIN LOGIN".into()))
        );
        // Un código pelado es válido y termina.
        assert_eq!(parse_reply("250"), Some((250, false, String::new())));
    }

    #[test]
    fn una_respuesta_que_no_lo_es_no_se_interpreta() {
        for garbage in ["", "ok", "25", "2500 algo", "abc def"] {
            assert_eq!(parse_reply(garbage), None, "{garbage:?}");
        }
    }

    /// La cola necesita saber si vale la pena reintentar. Sin la distinción,
    /// termina reintentando para siempre un mensaje que nunca se va a entregar,
    /// y la persona ve «enviando…» hasta que apaga el equipo.
    #[test]
    fn los_codigos_se_separan_por_lo_que_hay_que_hacer() {
        // 4xx: ahora no.
        assert!(classify_reply(451, "x".into()).is_retryable());
        assert!(classify_reply(421, "x".into()).is_retryable());
        // 5xx: nunca. Reintentarlo quema la reputación de la cuenta.
        assert!(!classify_reply(550, "x".into()).is_retryable());
        assert!(!classify_reply(552, "x".into()).is_retryable());
        // Y el de credenciales es su propio caso, porque lo arregla la persona.
        assert!(matches!(
            classify_reply(535, "x".into()),
            SmtpError::Rejected(_)
        ));
        assert!(!classify_reply(535, "x".into()).is_retryable());
    }

    /// Un salto de línea en una dirección la convierte en un comando SMTP más,
    /// y desde ahí se manda lo que sea en nombre de la persona. La validación
    /// de `compose` ya lo impide antes de encolar; ésta está para que
    /// `deliver` sea segura **sola**, porque el archivo de la cola vive en el
    /// disco y se puede haber tocado a mano.
    #[test]
    fn una_direccion_no_puede_partir_el_comando() {
        for bad in [
            "juan@otro.com\r\nRCPT TO:<espia@ajeno.com>",
            "juan@otro.com\nDATA",
            "juan@otro.com>\r\n",
            "<juan@otro.com>",
            "juan @otro.com",
            "",
        ] {
            assert!(!fits_in_command(bad), "{bad:?} tendría que rechazarse");
        }
        assert!(fits_in_command("juan.perez+x@sub.otro.com"));
    }

    /// **Una de las cosas más viejas y más olvidadas del protocolo.** Sin
    /// proteger el punto, un mensaje cuyo texto tenga una línea con un punto
    /// solo se corta ahí, y lo que sigue el servidor lo lee como comandos.
    #[test]
    fn un_punto_al_principio_de_linea_se_protege() {
        let message = "Hola\r\n.\r\nchau";
        assert_eq!(dot_stuff(message), "Hola\r\n..\r\nchau");
    }

    #[test]
    fn un_punto_en_el_medio_no_se_toca() {
        assert_eq!(dot_stuff("uno. dos"), "uno. dos");
        assert_eq!(dot_stuff("uno\r\n. dos"), "uno\r\n.. dos");
        assert_eq!(dot_stuff(".al principio"), "..al principio");
    }

    /// El formato del XOAUTH2 lo fijan Google y Microsoft. El separador es
    /// `\x01` y no un espacio ni dos puntos, que es lo intuitivo; escribirlo mal
    /// da un rechazo que parece de credenciales y no lo es.
    #[test]
    fn el_xoauth2_usa_el_separador_que_fija_el_proveedor() {
        let payload = xoauth2_payload("ana@ejemplo.com", "el-token");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&payload)
            .unwrap();
        assert_eq!(raw, b"user=ana@ejemplo.com\x01auth=Bearer el-token\x01\x01");
    }

    #[test]
    fn el_plain_lleva_los_nulos_que_lo_separan() {
        let payload = plain_payload("ana", "clave");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&payload)
            .unwrap();
        assert_eq!(raw, b"\0ana\0clave");
    }

    /// **La credencial manda sobre lo que ofrece el servidor.** Una cuenta con
    /// token no puede autenticarse con `PLAIN` aunque el servidor lo ofrezca:
    /// mandaría el token donde va una contraseña, el servidor lo rechazaría, y
    /// el token quedaría escrito en el registro de alguien más.
    #[test]
    fn una_cuenta_con_token_no_usa_plain() {
        let token = Credential::Token {
            username: "ana".into(),
            token: "t".into(),
        };
        let offers_everything = vec!["PLAIN".to_string(), "LOGIN".into(), "XOAUTH2".into()];
        assert_eq!(pick_mechanism(&offers_everything, &token), Some("XOAUTH2"));

        // Y si el servidor no lo ofrece, no hay con qué: mejor no mandar nada
        // que mandar el token de la persona por un mecanismo que no lo espera.
        let without_oauth = vec!["PLAIN".to_string(), "LOGIN".into()];
        assert_eq!(pick_mechanism(&without_oauth, &token), None);
    }

    #[test]
    fn una_cuenta_con_contrasena_prefiere_plain_y_cae_a_login() {
        let key = Credential::Password {
            username: "ana".into(),
            secret: "c".into(),
        };
        assert_eq!(
            pick_mechanism(&["PLAIN".to_string(), "LOGIN".into()], &key),
            Some("PLAIN")
        );
        assert_eq!(pick_mechanism(&["LOGIN".to_string()], &key), Some("LOGIN"));
        assert_eq!(pick_mechanism(&["XOAUTH2".to_string()], &key), None);
        assert_eq!(pick_mechanism(&[], &key), None);
    }

    /// Si el cifrado falla, la conexión **no puede volver a ser la de antes**:
    /// era en claro, y seguir hablando por ahí mandaría la contraseña a la
    /// vista. El hueco que queda hace que cualquier uso posterior falle.
    #[tokio::test]
    async fn un_flujo_sin_conexion_no_deja_escribir() {
        let mut transport = Transport::Closed;
        assert!(transport.write(b"AUTH PLAIN xxx\r\n").await.is_err());
        assert!(!transport.is_encrypted());
    }

    /// Los dos formatos que aparecen en la naturaleza.
    #[test]
    fn se_leen_los_mecanismos_que_anuncia_el_servidor() {
        assert_eq!(
            mechanisms_from("AUTH PLAIN LOGIN XOAUTH2"),
            vec!["PLAIN", "LOGIN", "XOAUTH2"]
        );
        assert_eq!(mechanisms_from("AUTH=PLAIN LOGIN"), vec!["PLAIN", "LOGIN"]);
        assert!(mechanisms_from("SIZE 35882577").is_empty());
        assert!(mechanisms_from("").is_empty());
    }
}
