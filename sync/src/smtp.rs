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

use crate::broker::{Credencial, Destino};

/// Tope para conectarse y saludar.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Tope de un intercambio: mandar algo y leer la respuesta.
///
/// Vale lo mismo que en IMAP: un servidor que deja de escribir sin cerrar el
/// socket no produce ningún error, la lectura no vuelve nunca, y sin tope el
/// mensaje se queda «enviando» para siempre.
const INTERCAMBIO: Duration = Duration::from_secs(120);

/// Tope de una línea de respuesta.
const MAX_LINEA: usize = 8 * 1024;

/// El puerto que habla TLS desde el primer byte.
const TLS_DIRECTO: u16 = 465;

/// El nombre con el que este equipo se presenta.
///
/// `localhost` y no el nombre real del equipo: el `EHLO` viaja en claro hasta
/// que se negocia el cifrado, y el nombre de la máquina de alguien no tiene por
/// qué ir ahí. Los servidores que importan miran la dirección IP y el resultado
/// de la autenticación, no esto.
const NOS_LLAMAMOS: &str = "localhost";

#[derive(Debug)]
pub enum SmtpError {
    /// El servidor no aceptó las credenciales. No se reintenta: insistir con una
    /// contraseña rechazada es cómo se bloquea una cuenta.
    Rechazado(String),
    /// El servidor dijo que no y no va a cambiar de opinión: un 5xx. Una
    /// dirección que no existe, un mensaje demasiado grande. Reintentarlo es
    /// quemar la reputación de la cuenta contra el servidor.
    Permanente(String),
    /// Ahora no: un 4xx, o la red. Se vuelve a intentar más tarde.
    Temporal(String),
}

impl std::fmt::Display for SmtpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmtpError::Rechazado(d) => {
                write!(f, "el servidor rechazó las credenciales: {d}")
            }
            SmtpError::Permanente(d) => write!(f, "{d}"),
            SmtpError::Temporal(d) => write!(f, "{d}"),
        }
    }
}

impl std::error::Error for SmtpError {}

impl SmtpError {
    /// Si tiene sentido volver a intentarlo.
    pub fn se_reintenta(&self) -> bool {
        matches!(self, SmtpError::Temporal(_))
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
pub fn respuesta_de(linea: &str) -> Option<(u16, bool, String)> {
    if linea.len() < 3 {
        return None;
    }
    let codigo: u16 = linea.get(..3)?.parse().ok()?;

    match linea.as_bytes().get(3) {
        Some(b'-') => Some((codigo, true, linea[4..].to_string())),
        Some(b' ') => Some((codigo, false, linea[4..].to_string())),
        // `250` pelado, sin texto: es válido y termina la respuesta.
        None => Some((codigo, false, String::new())),
        _ => None,
    }
}

/// Cómo clasificar el código que contestó el servidor.
pub fn clasificar(codigo: u16, detalle: String) -> SmtpError {
    match codigo {
        // Los de autenticación son su propio caso: no se arreglan reintentando
        // y hay que avisarle a la persona que reconecte la cuenta.
        535 | 530 | 534 | 538 => SmtpError::Rechazado(detalle),
        500..=599 => SmtpError::Permanente(detalle),
        _ => SmtpError::Temporal(detalle),
    }
}

/// Protege los puntos al principio de línea.
///
/// El bloque de datos termina con una línea que dice sólo `.`, así que una línea
/// del mensaje que empiece con un punto tiene que llevar otro. Sin esto, un
/// mensaje cuyo texto tenga una línea `.` se **corta ahí**: lo que sigue el
/// servidor lo lee como comandos SMTP, y en el mejor de los casos la conexión
/// muere. Es una de las cosas más viejas y más olvidadas del protocolo.
pub fn puntos_protegidos(mensaje: &str) -> String {
    mensaje
        .split("\r\n")
        .map(|linea| {
            if linea.starts_with('.') {
                format!(".{linea}")
            } else {
                linea.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// Si una dirección se puede escribir dentro de un comando sin partirlo.
///
/// No valida que sea una dirección —de eso se ocupa `redactar`— sino que **no
/// pueda salirse del comando**: un salto de línea la convierte en un comando
/// SMTP más, y desde ahí se manda lo que sea en nombre de la persona.
pub fn cabe_en_un_comando(direccion: &str) -> bool {
    !direccion.is_empty()
        && direccion.len() <= 320
        && !direccion.chars().any(|c| c.is_control() || c.is_whitespace())
        && !direccion.contains(['<', '>'])
}

/// La carga de `AUTH PLAIN`: `\0usuario\0secreto`, en base64.
pub fn carga_plain(usuario: &str, secreto: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("\0{usuario}\0{secreto}"))
}

/// La carga de `AUTH XOAUTH2`, con el formato que fijan Google y Microsoft.
///
/// El separador es `\x01` y no un espacio ni dos puntos, que es lo intuitivo.
/// Escribirlo mal da un rechazo que parece de credenciales y no lo es.
pub fn carga_xoauth2(usuario: &str, token: &str) -> String {
    base64::engine::general_purpose::STANDARD
        .encode(format!("user={usuario}\x01auth=Bearer {token}\x01\x01"))
}

/// Qué mecanismo de autenticación usar.
///
/// Se elige por **la credencial primero** y por lo que ofrece el servidor
/// después: una cuenta con token no puede autenticarse con `PLAIN` aunque el
/// servidor lo ofrezca —mandaría el token donde va una contraseña—, y una con
/// contraseña no puede usar `XOAUTH2`.
pub fn mecanismo(ofrecidos: &[String], credencial: &Credencial) -> Option<&'static str> {
    let tiene = |nombre: &str| ofrecidos.iter().any(|m| m.eq_ignore_ascii_case(nombre));

    match credencial {
        Credencial::Token { .. } => tiene("XOAUTH2").then_some("XOAUTH2"),
        Credencial::Contrasena { .. } => {
            // `PLAIN` antes que `LOGIN`: es una sola vuelta en vez de tres, y
            // los dos mandan lo mismo. `LOGIN` está para los servidores que no
            // ofrecen el otro, que todavía hay.
            if tiene("PLAIN") {
                Some("PLAIN")
            } else if tiene("LOGIN") {
                Some("LOGIN")
            } else {
                None
            }
        }
    }
}

/// Los mecanismos que anuncia una línea `250-AUTH ...`.
pub fn mecanismos_de(linea: &str) -> Vec<String> {
    let recortada = linea.trim();
    if !recortada.to_ascii_uppercase().starts_with("AUTH") {
        return Vec::new();
    }

    // El separador es un espacio, pero hay servidores que ponen un `=` después
    // de AUTH: los dos aparecen en la naturaleza.
    recortada["AUTH".len()..]
        .trim_start_matches(['=', ' '])
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

// ---------------------------------------------------------------------------
// La parte que habla por la red
// ---------------------------------------------------------------------------

/// Uno de los dos flujos posibles: en claro mientras se negocia, cifrado después.
enum Flujo {
    Claro(TcpStream),
    Cifrado(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    /// Ninguno, y **sólo mientras se cambia uno por el otro**.
    ///
    /// Envolver el socket en TLS pide moverlo, y moverlo de adentro de la
    /// estructura deja el hueco: esto es lo que va en el hueco durante esas dos
    /// líneas. Existe para no tener que inventar un socket de mentira para
    /// tapar el agujero, que era la otra salida y consistía en abrir una
    /// conexión que nadie usa y paniquear si fallaba.
    Ninguno,
}

impl Flujo {
    async fn escribir(&mut self, datos: &[u8]) -> Result<(), SmtpError> {
        let resultado = match self {
            Flujo::Claro(f) => f.write_all(datos).await,
            Flujo::Cifrado(f) => f.write_all(datos).await,
            Flujo::Ninguno => return Err(SmtpError::Temporal("no hay conexión".into())),
        };
        resultado.map_err(|e| SmtpError::Temporal(format!("no se pudo escribir: {e}")))
    }

    async fn leer(&mut self, destino: &mut Vec<u8>) -> Result<usize, SmtpError> {
        let resultado = match self {
            Flujo::Claro(f) => f.read_buf(destino).await,
            Flujo::Cifrado(f) => f.read_buf(destino).await,
            Flujo::Ninguno => return Err(SmtpError::Temporal("no hay conexión".into())),
        };
        resultado.map_err(|e| SmtpError::Temporal(format!("no se pudo leer: {e}")))
    }

    fn esta_cifrado(&self) -> bool {
        matches!(self, Flujo::Cifrado(_))
    }
}

/// Una sesión SMTP, de la conexión al `QUIT`.
pub struct Sesion {
    flujo: Flujo,
    pendiente: Vec<u8>,
    /// Lo que el servidor dijo saber hacer, del `EHLO`.
    mecanismos: Vec<String>,
    starttls: bool,
}

impl Sesion {
    /// Conecta, cifra y se autentica.
    pub async fn abrir(destino: &Destino) -> Result<Self, SmtpError> {
        let tcp = tokio::time::timeout(
            TIMEOUT,
            TcpStream::connect((destino.host.as_str(), destino.puerto)),
        )
        .await
        .map_err(|_| SmtpError::Temporal(format!("{} no contestó a tiempo", destino.host)))?
        .map_err(|e| SmtpError::Temporal(format!("no se pudo conectar a {}: {e}", destino.host)))?;

        let mut sesion = Sesion {
            flujo: Flujo::Claro(tcp),
            pendiente: Vec::new(),
            mecanismos: Vec::new(),
            starttls: false,
        };

        if destino.puerto == TLS_DIRECTO {
            sesion.cifrar(&destino.host).await?;
        }

        // El saludo del servidor va primero, antes de decir nada.
        sesion.esperar(&["220"]).await?;
        sesion.saludar().await?;

        if !sesion.flujo.esta_cifrado() {
            if !sesion.starttls {
                // **Sin salida.** Seguir sería mandar la contraseña de la
                // persona y el mensaje entero a la vista de cualquiera.
                return Err(SmtpError::Permanente(format!(
                    "{} no ofrece cifrado en el puerto {}, y sin cifrado no se manda nada",
                    destino.host, destino.puerto
                )));
            }
            sesion.mandar("STARTTLS", &["220"]).await?;
            sesion.cifrar(&destino.host).await?;
            // Y de nuevo el saludo: lo que el servidor anunció antes de cifrar
            // no vale, justamente porque cualquiera pudo haberlo cambiado en el
            // camino. Los mecanismos de autenticación son lo que más importa
            // acá: uno inyectado podría degradar a algo que manda la contraseña
            // en claro.
            sesion.mecanismos.clear();
            sesion.saludar().await?;
        }

        sesion.autenticar(&destino.credencial).await?;
        Ok(sesion)
    }

    /// Entrega el mensaje.
    pub async fn entregar(
        &mut self,
        remitente: &str,
        destinatarios: &[String],
        mensaje: &str,
    ) -> Result<(), SmtpError> {
        // **Las direcciones se revisan otra vez acá.** Ya pasaron por
        // `redactar::revisar` antes de encolarse, así que esto no debería
        // encontrar nada — y por eso mismo va: que `entregar` sea segura no
        // puede depender de que quien la llame se haya acordado de validar
        // primero. Una dirección con un salto de línea es un comando SMTP
        // inyectado, y desde ahí se manda cualquier cosa en nombre de la
        // persona. El archivo de la cola además vive en el disco y se puede
        // haber tocado a mano.
        for direccion in std::iter::once(remitente).chain(destinatarios.iter().map(String::as_str))
        {
            if !cabe_en_un_comando(direccion) {
                return Err(SmtpError::Permanente(format!(
                    "«{direccion}» no se puede usar como dirección"
                )));
            }
        }

        self.mandar(&format!("MAIL FROM:<{remitente}>"), &["250"]).await?;

        for destinatario in destinatarios {
            // 251 es «no está acá pero lo reenvío», que es una entrega buena.
            self.mandar(&format!("RCPT TO:<{destinatario}>"), &["250", "251"])
                .await?;
        }

        self.mandar("DATA", &["354"]).await?;

        let cuerpo = puntos_protegidos(mensaje);
        self.flujo.escribir(cuerpo.as_bytes()).await?;
        // El punto solo cierra el bloque. El `\r\n` de antes va siempre, aunque
        // el mensaje ya termine en uno: un `.` pegado al final de la última
        // línea es parte del texto y no el cierre.
        self.flujo.escribir(b"\r\n.\r\n").await?;

        // **Éste es el momento en que el mensaje se mandó o no.** Un 250 acá
        // quiere decir que el servidor se hizo cargo; cualquier otra cosa, que
        // no. La respuesta puede tardar: hay servidores que revisan el mensaje
        // entero antes de contestar, y por eso el tope de intercambio es largo.
        self.esperar(&["250"]).await?;
        Ok(())
    }

    /// Se despide. Un fallo acá no importa: el mensaje ya se entregó.
    pub async fn cerrar(&mut self) {
        let _ = self.flujo.escribir(b"QUIT\r\n").await;
    }

    async fn saludar(&mut self) -> Result<(), SmtpError> {
        self.flujo
            .escribir(format!("EHLO {NOS_LLAMAMOS}\r\n").as_bytes())
            .await?;

        let lineas = self.esperar(&["250"]).await?;
        for linea in lineas {
            let mayusculas = linea.to_ascii_uppercase();
            if mayusculas.starts_with("STARTTLS") {
                self.starttls = true;
            }
            if mayusculas.starts_with("AUTH") {
                self.mecanismos.extend(mecanismos_de(&linea));
            }
        }
        Ok(())
    }

    async fn cifrar(&mut self, host: &str) -> Result<(), SmtpError> {
        let conector = crate::tls::conector().map_err(SmtpError::Permanente)?;
        let nombre = ServerName::try_from(host.to_string())
            .map_err(|_| SmtpError::Permanente(format!("«{host}» no es un nombre válido")))?;

        // Sacar el socket de adentro para envolverlo, dejando `Ninguno` en el
        // hueco mientras tanto. Si el cifrado falla, el hueco queda: cualquier
        // uso posterior da «no hay conexión», que es exactamente lo que pasó y
        // es mejor que dejar puesto un socket en claro por el que se podría
        // seguir hablando sin cifrar.
        let Flujo::Claro(tcp) = std::mem::replace(&mut self.flujo, Flujo::Ninguno) else {
            return Err(SmtpError::Permanente(
                "no hay una conexión en claro que cifrar".into(),
            ));
        };

        let cifrado = conector
            .connect(nombre, tcp)
            .await
            .map_err(|e| SmtpError::Temporal(format!("no se pudo cifrar con {host}: {e}")))?;
        self.flujo = Flujo::Cifrado(Box::new(cifrado));
        Ok(())
    }

    async fn autenticar(&mut self, credencial: &Credencial) -> Result<(), SmtpError> {
        let Some(como) = mecanismo(&self.mecanismos, credencial) else {
            return Err(SmtpError::Permanente(
                "el servidor no acepta ninguna forma de autenticación que esta cuenta pueda usar"
                    .into(),
            ));
        };

        match (como, credencial) {
            ("XOAUTH2", Credencial::Token { usuario, token }) => {
                let carga = carga_xoauth2(usuario, token);
                self.mandar(&format!("AUTH XOAUTH2 {carga}"), &["235"]).await
            }
            ("PLAIN", Credencial::Contrasena { usuario, secreto }) => {
                let carga = carga_plain(usuario, secreto);
                self.mandar(&format!("AUTH PLAIN {carga}"), &["235"]).await
            }
            ("LOGIN", Credencial::Contrasena { usuario, secreto }) => {
                self.mandar("AUTH LOGIN", &["334"]).await?;
                let u = base64::engine::general_purpose::STANDARD.encode(usuario);
                self.mandar(&u, &["334"]).await?;
                let s = base64::engine::general_purpose::STANDARD.encode(secreto);
                self.mandar(&s, &["235"]).await
            }
            // `mecanismo` sólo devuelve combinaciones que existen, así que esto
            // no pasa. Se contesta con un error en vez de con un pánico: un
            // pánico acá se lleva puesta la tarea que estaba mandando.
            _ => Err(SmtpError::Permanente(
                "la credencial no va con el mecanismo elegido".into(),
            )),
        }
    }

    /// Manda una línea y espera una respuesta con uno de los códigos esperados.
    async fn mandar(&mut self, comando: &str, esperados: &[&str]) -> Result<(), SmtpError> {
        self.flujo.escribir(format!("{comando}\r\n").as_bytes()).await?;
        self.esperar(esperados).await?;
        Ok(())
    }

    /// Lee una respuesta entera y comprueba su código.
    ///
    /// Devuelve las líneas sin el código, que es lo que hace falta para leer lo
    /// que anuncia el `EHLO`.
    async fn esperar(&mut self, esperados: &[&str]) -> Result<Vec<String>, SmtpError> {
        let leer = async {
            let mut lineas = Vec::new();
            loop {
                let linea = self.leer_linea().await?;
                let Some((codigo, sigue, texto)) = respuesta_de(&linea) else {
                    return Err(SmtpError::Temporal(format!(
                        "el servidor contestó algo que no se entiende: {linea}"
                    )));
                };

                let esperado = esperados.iter().any(|e| linea.starts_with(e));
                if !esperado {
                    return Err(clasificar(codigo, texto));
                }
                lineas.push(texto);
                if !sigue {
                    return Ok(lineas);
                }
            }
        };

        tokio::time::timeout(INTERCAMBIO, leer).await.map_err(|_| {
            SmtpError::Temporal(format!(
                "el servidor dejó de contestar (más de {} segundos)",
                INTERCAMBIO.as_secs()
            ))
        })?
    }

    async fn leer_linea(&mut self) -> Result<String, SmtpError> {
        loop {
            if let Some(fin) = self.pendiente.iter().position(|b| *b == b'\n') {
                let linea: Vec<u8> = self.pendiente.drain(..=fin).collect();
                return Ok(String::from_utf8_lossy(&linea).trim_end().to_string());
            }
            if self.pendiente.len() > MAX_LINEA {
                return Err(SmtpError::Temporal(
                    "el servidor mandó una línea sin fin".into(),
                ));
            }

            let mut destino = std::mem::take(&mut self.pendiente);
            let leidos = self.flujo.leer(&mut destino).await;
            self.pendiente = destino;
            if leidos? == 0 {
                return Err(SmtpError::Temporal(
                    "el servidor cortó la conexión".into(),
                ));
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
            respuesta_de("250-STARTTLS"),
            Some((250, true, "STARTTLS".into()))
        );
        assert_eq!(
            respuesta_de("250 AUTH PLAIN LOGIN"),
            Some((250, false, "AUTH PLAIN LOGIN".into()))
        );
        // Un código pelado es válido y termina.
        assert_eq!(respuesta_de("250"), Some((250, false, String::new())));
    }

    #[test]
    fn una_respuesta_que_no_lo_es_no_se_interpreta() {
        for basura in ["", "ok", "25", "2500 algo", "abc def"] {
            assert_eq!(respuesta_de(basura), None, "{basura:?}");
        }
    }

    /// La cola necesita saber si vale la pena reintentar. Sin la distinción,
    /// termina reintentando para siempre un mensaje que nunca se va a entregar,
    /// y la persona ve «enviando…» hasta que apaga el equipo.
    #[test]
    fn los_codigos_se_separan_por_lo_que_hay_que_hacer() {
        // 4xx: ahora no.
        assert!(clasificar(451, "x".into()).se_reintenta());
        assert!(clasificar(421, "x".into()).se_reintenta());
        // 5xx: nunca. Reintentarlo quema la reputación de la cuenta.
        assert!(!clasificar(550, "x".into()).se_reintenta());
        assert!(!clasificar(552, "x".into()).se_reintenta());
        // Y el de credenciales es su propio caso, porque lo arregla la persona.
        assert!(matches!(clasificar(535, "x".into()), SmtpError::Rechazado(_)));
        assert!(!clasificar(535, "x".into()).se_reintenta());
    }

    /// Un salto de línea en una dirección la convierte en un comando SMTP más,
    /// y desde ahí se manda lo que sea en nombre de la persona. La validación
    /// de `redactar` ya lo impide antes de encolar; ésta está para que
    /// `entregar` sea segura **sola**, porque el archivo de la cola vive en el
    /// disco y se puede haber tocado a mano.
    #[test]
    fn una_direccion_no_puede_partir_el_comando() {
        for mala in [
            "juan@otro.com\r\nRCPT TO:<espia@ajeno.com>",
            "juan@otro.com\nDATA",
            "juan@otro.com>\r\n",
            "<juan@otro.com>",
            "juan @otro.com",
            "",
        ] {
            assert!(!cabe_en_un_comando(mala), "{mala:?} tendría que rechazarse");
        }
        assert!(cabe_en_un_comando("juan.perez+x@sub.otro.com"));
    }

    /// **Una de las cosas más viejas y más olvidadas del protocolo.** Sin
    /// proteger el punto, un mensaje cuyo texto tenga una línea con un punto
    /// solo se corta ahí, y lo que sigue el servidor lo lee como comandos.
    #[test]
    fn un_punto_al_principio_de_linea_se_protege() {
        let mensaje = "Hola\r\n.\r\nchau";
        assert_eq!(puntos_protegidos(mensaje), "Hola\r\n..\r\nchau");
    }

    #[test]
    fn un_punto_en_el_medio_no_se_toca() {
        assert_eq!(puntos_protegidos("uno. dos"), "uno. dos");
        assert_eq!(puntos_protegidos("uno\r\n. dos"), "uno\r\n.. dos");
        assert_eq!(puntos_protegidos(".al principio"), "..al principio");
    }

    /// El formato del XOAUTH2 lo fijan Google y Microsoft. El separador es
    /// `\x01` y no un espacio ni dos puntos, que es lo intuitivo; escribirlo mal
    /// da un rechazo que parece de credenciales y no lo es.
    #[test]
    fn el_xoauth2_usa_el_separador_que_fija_el_proveedor() {
        let carga = carga_xoauth2("ana@ejemplo.com", "el-token");
        let crudo = base64::engine::general_purpose::STANDARD.decode(&carga).unwrap();
        assert_eq!(crudo, b"user=ana@ejemplo.com\x01auth=Bearer el-token\x01\x01");
    }

    #[test]
    fn el_plain_lleva_los_nulos_que_lo_separan() {
        let carga = carga_plain("ana", "clave");
        let crudo = base64::engine::general_purpose::STANDARD.decode(&carga).unwrap();
        assert_eq!(crudo, b"\0ana\0clave");
    }

    /// **La credencial manda sobre lo que ofrece el servidor.** Una cuenta con
    /// token no puede autenticarse con `PLAIN` aunque el servidor lo ofrezca:
    /// mandaría el token donde va una contraseña, el servidor lo rechazaría, y
    /// el token quedaría escrito en el registro de alguien más.
    #[test]
    fn una_cuenta_con_token_no_usa_plain() {
        let token = Credencial::Token {
            usuario: "ana".into(),
            token: "t".into(),
        };
        let ofrece_todo = vec!["PLAIN".to_string(), "LOGIN".into(), "XOAUTH2".into()];
        assert_eq!(mecanismo(&ofrece_todo, &token), Some("XOAUTH2"));

        // Y si el servidor no lo ofrece, no hay con qué: mejor no mandar nada
        // que mandar el token de la persona por un mecanismo que no lo espera.
        let sin_oauth = vec!["PLAIN".to_string(), "LOGIN".into()];
        assert_eq!(mecanismo(&sin_oauth, &token), None);
    }

    #[test]
    fn una_cuenta_con_contrasena_prefiere_plain_y_cae_a_login() {
        let clave = Credencial::Contrasena {
            usuario: "ana".into(),
            secreto: "c".into(),
        };
        assert_eq!(
            mecanismo(&["PLAIN".to_string(), "LOGIN".into()], &clave),
            Some("PLAIN")
        );
        assert_eq!(mecanismo(&["LOGIN".to_string()], &clave), Some("LOGIN"));
        assert_eq!(mecanismo(&["XOAUTH2".to_string()], &clave), None);
        assert_eq!(mecanismo(&[], &clave), None);
    }

    /// Si el cifrado falla, la conexión **no puede volver a ser la de antes**:
    /// era en claro, y seguir hablando por ahí mandaría la contraseña a la
    /// vista. El hueco que queda hace que cualquier uso posterior falle.
    #[tokio::test]
    async fn un_flujo_sin_conexion_no_deja_escribir() {
        let mut flujo = Flujo::Ninguno;
        assert!(flujo.escribir(b"AUTH PLAIN xxx\r\n").await.is_err());
        assert!(!flujo.esta_cifrado());
    }

    /// Los dos formatos que aparecen en la naturaleza.
    #[test]
    fn se_leen_los_mecanismos_que_anuncia_el_servidor() {
        assert_eq!(
            mecanismos_de("AUTH PLAIN LOGIN XOAUTH2"),
            vec!["PLAIN", "LOGIN", "XOAUTH2"]
        );
        assert_eq!(mecanismos_de("AUTH=PLAIN LOGIN"), vec!["PLAIN", "LOGIN"]);
        assert!(mecanismos_de("SIZE 35882577").is_empty());
        assert!(mecanismos_de("").is_empty());
    }
}
