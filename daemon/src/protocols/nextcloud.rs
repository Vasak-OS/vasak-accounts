//! El Login Flow v2 de Nextcloud.
//!
//! El único proveedor que funciona **sin registrar nada con nadie**, y por eso
//! el primero de la lista: las credenciales las emite el servidor de la propia
//! persona, así que no hay `client_id` que pedir, ni verificación que pasar, ni
//! auditoría que pagar.
//!
//! Cómo funciona:
//!
//!   1. Se le pide al servidor que abra un inicio de sesión. Devuelve una URL
//!      para el navegador y un token para sondear.
//!   2. La persona entra a esa URL, se autentica y aprueba el acceso.
//!   3. Se sondea hasta que el servidor entrega el nombre de usuario y una
//!      **contraseña de aplicación**.
//!
//! Lo que sale de acá no es un token OAuth2: es una contraseña de aplicación
//! que no expira y que sirve contra WebDAV, CalDAV y CardDAV con autenticación
//! básica. No hay nada que refrescar, y eso es una ventaja y no una carencia —
//! la persona la revoca desde su propio servidor cuando quiera.

use std::time::Duration;

use serde::Deserialize;

/// Cuánto se le da al servidor para contestar.
///
/// Corto a propósito: el sondeo lo repite el cliente, así que una petición que
/// se cuelga sólo tiene que soltar el turno, no esperar al servidor.
const TIMEOUT: Duration = Duration::from_secs(15);

/// Tope de lo que se lee de la respuesta.
///
/// El servidor lo elige la persona, pero este proceso corre como root: sin
/// tope, un servidor hostil —o mal configurado, devolviendo una página de error
/// enorme— hace que root asigne memoria sin límite. Las respuestas de este
/// protocolo son tres campos de texto; 64 KiB son de sobra.
const MAX_CUERPO: usize = 64 * 1024;

/// Cómo se identifica ante el servidor.
///
/// Nextcloud lo muestra tal cual en «Dispositivos y sesiones» del usuario, que
/// es donde después va a ir a revocar el acceso. Un User-Agent genérico dejaría
/// ahí una línea que no le dice nada a nadie.
const USER_AGENT: &str = "VasakOS";

#[derive(Debug)]
pub enum NextcloudError {
    /// La dirección que escribió la persona no sirve, y el mensaje dice por qué.
    BadServer(String),
    /// El servidor todavía no tiene credenciales: la persona no terminó.
    Pending,
    Failed(String),
}

impl std::fmt::Display for NextcloudError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NextcloudError::BadServer(motivo) => write!(f, "{motivo}"),
            NextcloudError::Pending => {
                write!(f, "todavía no se completó el inicio de sesión en el servidor")
            }
            NextcloudError::Failed(detalle) => write!(f, "{detalle}"),
        }
    }
}

impl std::error::Error for NextcloudError {}

/// Lo que devuelve el servidor al abrir el inicio de sesión.
#[derive(Debug, Deserialize)]
struct RespuestaInicio {
    poll: Poll,
    login: String,
}

#[derive(Debug, Deserialize)]
struct Poll {
    token: String,
    endpoint: String,
}

/// Un inicio de sesión abierto, esperando que la persona lo apruebe.
#[derive(Debug, Clone)]
pub struct LoginStarted {
    /// La URL que hay que abrir en el navegador.
    pub login_url: String,
    pub poll_token: String,
    pub poll_endpoint: String,
}

/// Las credenciales que el servidor entrega al final.
#[derive(Debug, Clone, Deserialize)]
pub struct Credentials {
    pub server: String,
    #[serde(rename = "loginName")]
    pub login_name: String,
    /// La contraseña de aplicación. No expira; se revoca desde el servidor.
    #[serde(rename = "appPassword")]
    pub app_password: String,
}

/// Normaliza y valida la dirección del servidor.
///
/// **Se exige HTTPS**, y no es celo de más: el servidor está por entregar una
/// contraseña que no caduca, así que por HTTP viajaría en claro y quedaría al
/// alcance de cualquiera en la red. Un Nextcloud casero sin certificado no es
/// un caso raro, pero conectarlo así sería regalar la credencial.
///
/// Además se le saca lo que no corresponde: credenciales incrustadas en la URL,
/// consulta y fragmento. Nada de eso pertenece a la dirección de un servidor, y
/// dejarlo pasar es la forma más simple de que la petición termine en otra
/// parte.
pub fn normalize_server(entrada: &str) -> Result<String, NextcloudError> {
    let texto = entrada.trim();
    if texto.is_empty() {
        return Err(NextcloudError::BadServer(
            "hay que escribir la dirección de tu servidor Nextcloud".into(),
        ));
    }

    // Sin esquema se asume https, que es el único que se acepta igual. Así
    // «casa.ejemplo.com» funciona sin que haya que escribir el prefijo.
    let con_esquema = if texto.contains("://") {
        texto.to_string()
    } else {
        format!("https://{texto}")
    };

    let mut url = url::Url::parse(&con_esquema)
        .map_err(|e| NextcloudError::BadServer(format!("«{texto}» no es una dirección válida: {e}")))?;

    if url.scheme() != "https" {
        return Err(NextcloudError::BadServer(format!(
            "sólo se puede conectar por HTTPS, y «{texto}» usa {}. El servidor \
             está por entregar una contraseña que no caduca: por HTTP viajaría \
             en claro",
            url.scheme(),
        )));
    }

    if url.host_str().is_none_or(str::is_empty) {
        return Err(NextcloudError::BadServer(format!(
            "«{texto}» no nombra ningún servidor"
        )));
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(NextcloudError::BadServer(
            "la dirección no lleva usuario ni contraseña: eso lo pide el propio \
             servidor en el navegador"
                .into(),
        ));
    }

    url.set_query(None);
    url.set_fragment(None);

    // Sin barra final, para que las rutas se peguen de una sola forma.
    let normalizada = url.as_str().trim_end_matches('/').to_string();
    Ok(normalizada)
}

fn cliente() -> Result<reqwest::Client, NextcloudError> {
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        // Sin redirecciones: una redirección en este flujo es el servidor
        // mandando el token de sondeo a otra parte.
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| NextcloudError::Failed(format!("no se pudo crear el cliente HTTP: {e}")))
}

/// Lee el cuerpo con tope y lo interpreta como JSON.
async fn json_con_tope<T: serde::de::DeserializeOwned>(
    respuesta: reqwest::Response,
) -> Result<T, NextcloudError> {
    let bytes = respuesta
        .bytes()
        .await
        .map_err(|e| NextcloudError::Failed(format!("no se pudo leer la respuesta: {e}")))?;

    if bytes.len() > MAX_CUERPO {
        return Err(NextcloudError::Failed(format!(
            "el servidor devolvió {} bytes, más de los {MAX_CUERPO} que se leen; \
             ¿es realmente un Nextcloud?",
            bytes.len(),
        )));
    }

    serde_json::from_slice(&bytes).map_err(|e| {
        NextcloudError::Failed(format!(
            "la respuesta del servidor no tiene la forma esperada: {e}. \
             ¿La dirección apunta a un Nextcloud?"
        ))
    })
}

/// Paso 1: pedirle al servidor que abra un inicio de sesión.
pub async fn start_login(server: &str) -> Result<LoginStarted, NextcloudError> {
    let url = format!("{server}/index.php/login/v2");

    let respuesta = cliente()?
        .post(&url)
        .send()
        .await
        .map_err(|e| NextcloudError::Failed(format!("no se pudo contactar a {server}: {e}")))?;

    if !respuesta.status().is_success() {
        return Err(NextcloudError::Failed(format!(
            "{server} respondió {} al abrir el inicio de sesión",
            respuesta.status(),
        )));
    }

    let inicio: RespuestaInicio = json_con_tope(respuesta).await?;

    // El servidor dice adónde sondear, así que hay que comprobar que no mande a
    // otro lado: un endpoint apuntando a un tercero le entregaría el token de
    // sondeo, y con él las credenciales cuando la persona apruebe.
    let endpoint_ok = misma_procedencia(server, &inicio.poll.endpoint);
    let login_ok = misma_procedencia(server, &inicio.login);
    if !endpoint_ok || !login_ok {
        return Err(NextcloudError::Failed(format!(
            "{server} devolvió direcciones de otro servidor; no se sigue"
        )));
    }

    Ok(LoginStarted {
        login_url: inicio.login,
        poll_token: inicio.poll.token,
        poll_endpoint: inicio.poll.endpoint,
    })
}

/// Paso 3: un sondeo. `Pending` mientras la persona no haya terminado.
///
/// Un solo intento y no un bucle, a propósito: quien llama es un método D-Bus, y
/// un método que se queda esperando minutos supera el tiempo de espera del bus.
/// El bucle lo hace el cliente, con una llamada corta cada vez.
pub async fn poll(endpoint: &str, token: &str) -> Result<Credentials, NextcloudError> {
    let respuesta = cliente()?
        .post(endpoint)
        .form(&[("token", token)])
        .send()
        .await
        .map_err(|e| NextcloudError::Failed(format!("falló el sondeo: {e}")))?;

    // Mientras no haya credenciales, Nextcloud contesta 404. No es un error: es
    // «la persona todavía no terminó».
    if respuesta.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(NextcloudError::Pending);
    }

    if !respuesta.status().is_success() {
        return Err(NextcloudError::Failed(format!(
            "el servidor respondió {} al sondeo",
            respuesta.status(),
        )));
    }

    json_con_tope(respuesta).await
}

/// Si dos URLs son del mismo servidor: esquema, host y puerto.
///
/// Compara los tres. Con sólo el host, un servidor podría mover el sondeo a
/// `http://` —perdiendo el cifrado— o a otro puerto donde escuche otra cosa.
fn misma_procedencia(a: &str, b: &str) -> bool {
    let (Ok(a), Ok(b)) = (url::Url::parse(a), url::Url::parse(b)) else {
        return false;
    };
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// Las rutas DAV de una cuenta, a partir del servidor y el usuario.
///
/// Se guardan al conectar para que las aplicaciones no tengan que saber cómo se
/// arman: el gestor de archivos, el calendario y los contactos piden la
/// configuración de su capacidad y ahí está la dirección.
pub fn dav_urls(server: &str, login_name: &str) -> DavUrls {
    // El nombre de usuario va a una ruta, así que hay que codificarlo: un
    // usuario con espacio, `#` o `/` armaría una URL distinta de la que quiere.
    let usuario: String =
        url::form_urlencoded::byte_serialize(login_name.as_bytes()).collect::<String>().replace('+', "%20");

    DavUrls {
        files: format!("{server}/remote.php/dav/files/{usuario}/"),
        calendars: format!("{server}/remote.php/dav/calendars/{usuario}/"),
        addressbooks: format!("{server}/remote.php/dav/addressbooks/users/{usuario}/"),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DavUrls {
    pub files: String,
    pub calendars: String,
    pub addressbooks: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn se_le_agrega_https_a_una_direccion_sin_esquema() {
        assert_eq!(
            normalize_server("nube.ejemplo.com").unwrap(),
            "https://nube.ejemplo.com"
        );
        assert_eq!(
            normalize_server("  nube.ejemplo.com/nextcloud/  ").unwrap(),
            "https://nube.ejemplo.com/nextcloud"
        );
    }

    /// El servidor está por entregar una contraseña que no caduca. Por HTTP
    /// viajaría en claro, así que no se acepta ni en la red de casa.
    #[test]
    fn no_se_acepta_http() {
        for malo in [
            "http://nube.ejemplo.com",
            "http://192.168.0.10",
            "http://localhost:8080",
        ] {
            let error = normalize_server(malo).unwrap_err().to_string();
            assert!(error.contains("HTTPS"), "{malo}: {error}");
            assert!(
                error.contains("en claro"),
                "el error tiene que decir por qué: {error}"
            );
        }
    }

    #[test]
    fn no_se_aceptan_otros_esquemas_ni_basura() {
        for malo in ["ftp://nube.ejemplo.com", "file:///etc/passwd", "", "   ", "https://"] {
            assert!(normalize_server(malo).is_err(), "{malo:?} tenía que rechazarse");
        }
    }

    /// Usuario y contraseña en la URL no pertenecen a la dirección de un
    /// servidor, y dejarlas pasar es la forma más simple de que la petición
    /// termine en otra parte.
    #[test]
    fn no_se_aceptan_credenciales_en_la_direccion() {
        for malo in [
            "https://alguien@nube.ejemplo.com",
            "https://alguien:secreto@nube.ejemplo.com",
        ] {
            assert!(normalize_server(malo).is_err(), "{malo} tenía que rechazarse");
        }
    }

    #[test]
    fn se_descartan_consulta_y_fragmento() {
        assert_eq!(
            normalize_server("https://nube.ejemplo.com/nc?a=1#x").unwrap(),
            "https://nube.ejemplo.com/nc"
        );
    }

    /// El servidor dice adónde sondear. Si pudiera nombrar otro host, le
    /// entregaría a un tercero el token de sondeo — y con él las credenciales
    /// en cuanto la persona apruebe.
    #[test]
    fn un_endpoint_de_otro_servidor_no_es_del_mismo() {
        let servidor = "https://nube.ejemplo.com";
        assert!(misma_procedencia(servidor, "https://nube.ejemplo.com/index.php/login/v2/poll"));
        assert!(misma_procedencia(servidor, "https://nube.ejemplo.com:443/otra/ruta"));

        for ajeno in [
            "https://atacante.com/poll",
            "https://nube.ejemplo.com.atacante.com/poll",
            // Mismo host pero sin cifrar, o en otro puerto: ahí escucha otra cosa.
            "http://nube.ejemplo.com/poll",
            "https://nube.ejemplo.com:8443/poll",
            "no es una url",
        ] {
            assert!(
                !misma_procedencia(servidor, ajeno),
                "{ajeno} no tenía que pasar por del mismo servidor"
            );
        }
    }

    #[test]
    fn las_rutas_dav_se_arman_con_el_usuario() {
        let urls = dav_urls("https://nube.ejemplo.com", "ana");
        assert_eq!(urls.files, "https://nube.ejemplo.com/remote.php/dav/files/ana/");
        assert_eq!(
            urls.calendars,
            "https://nube.ejemplo.com/remote.php/dav/calendars/ana/"
        );
        assert_eq!(
            urls.addressbooks,
            "https://nube.ejemplo.com/remote.php/dav/addressbooks/users/ana/"
        );
    }

    /// El nombre de usuario lo elige el servidor y va dentro de una ruta. Sin
    /// codificarlo, un usuario con `/` o `#` armaría una URL distinta de la que
    /// corresponde — y con `..` podría salirse de su propio directorio.
    #[test]
    fn un_usuario_con_caracteres_raros_se_codifica() {
        let urls = dav_urls("https://nube.ejemplo.com", "ana maría");
        assert!(urls.files.ends_with("/files/ana%20mar%C3%ADa/"), "{}", urls.files);

        let urls = dav_urls("https://nube.ejemplo.com", "../otro");
        assert!(!urls.files.contains("../"), "no puede quedar un salto de ruta: {}", urls.files);

        let urls = dav_urls("https://nube.ejemplo.com", "a#b?c");
        assert!(!urls.files.contains('#') && !urls.files.contains('?'), "{}", urls.files);
    }

    #[test]
    fn el_error_de_pendiente_no_suena_a_fallo() {
        let mensaje = NextcloudError::Pending.to_string();
        assert!(mensaje.contains("todavía"), "{mensaje}");
    }
}
