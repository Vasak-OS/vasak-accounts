//! Traer una imagen de un correo, cuando la persona lo pide.
//!
//! # Por qué la trae el servicio y no la ventana
//!
//! Porque una petición hecha desde el motor que dibuja la aplicación lleva
//! encima todo lo que ese motor sabe: el idioma de la sesión, el tamaño de la
//! ventana, las cookies que tenga guardadas, la versión del navegador. Quien
//! mandó el correo pone la dirección, así que cada uno de esos datos es algo que
//! le llega sin haberlo pedido.
//!
//! Hecha desde acá es una petición pelada: sin cookies, sin `Referer`, con un
//! `User-Agent` que no dice nada, y una sola vez.
//!
//! # Y por qué eso crea un problema nuevo
//!
//! **La dirección la eligió un desconocido, y ahora la pide un proceso que corre
//! adentro de la máquina de la persona.** Un `<img src="http://127.0.0.1:9000/…">`
//! en un correo dejaba de significar nada mientras la imagen no se cargaba;
//! cargándola desde el servicio, pasa a ser una forma de hacer que la máquina se
//! pida cosas a sí misma — a un servicio local, a la impresora de la red, al
//! router. Eso es lo que en la jerga se llama *SSRF*, y es el riesgo que esta
//! función trae y que no existía antes.
//!
//! Por eso el nombre se resuelve **acá**, antes de pedir nada, y se rechaza si
//! apunta a cualquier dirección que no sea de internet: nada de `127.0.0.1`,
//! nada de `192.168.*`, nada de enlaces locales ni de direcciones de máquina
//! virtual. Ver [`direccion_permitida`].
//!
//! Queda una rendija conocida: entre que se resuelve el nombre y que se abre la
//! conexión, un servidor de nombres hostil puede contestar otra cosa (*DNS
//! rebinding*). Cerrarla del todo pide atarse a la dirección ya resuelta al
//! conectar, que con este cliente no se puede sin escribir el conector a mano.
//! Se deja anotado: la ventana es de milisegundos y el ataque necesita que la
//! persona apriete «mostrar imágenes» en ese momento, pero es una rendija.
//!
//! # Nada de SVG
//!
//! Un SVG no es una imagen: es un documento, y puede traer `<script>` adentro.
//! Los navegadores no ejecutan el script de un SVG cargado como `<img>`, pero
//! eso es una propiedad del motor y no de lo que se está devolviendo. Acá se
//! aceptan formatos de mapa de bits y nada más.

use std::net::IpAddr;
use std::time::Duration;

use base64::Engine;

/// Cuánto se espera por una imagen.
///
/// Corto: la persona ya apretó el botón y está mirando. Un servidor que tarda
/// más que esto no va a mejorar la lectura del mensaje.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Tope de lo que se descarga.
///
/// Se cuenta mientras llega y no se confía en lo que el servidor declara: un
/// `Content-Length` es una promesa, no un límite.
const MAX_BYTES: usize = 5 * 1024 * 1024;

/// Lo que se dice ser al pedir.
///
/// Genérico a propósito: el `User-Agent` es uno de los datos que esta función
/// existe para no entregar. No dice versión, ni sistema, ni que esto es un
/// cliente de correo — que ya sería decir que el mensaje se abrió en uno.
const AGENTE: &str = "VasakOS";

/// Los formatos que se aceptan.
///
/// Mapas de bits y nada más. Ver la nota del módulo sobre el SVG.
const TIPOS: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/avif",
    "image/bmp",
    "image/x-icon",
];

/// Una imagen traída, lista para que la ventana la ponga en el documento.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Imagen {
    /// El tipo tal como lo aceptamos, no como lo dijo el servidor.
    pub tipo: String,
    /// El contenido en base64, para poder viajar por D-Bus y terminar en un
    /// `data:` del documento aislado.
    pub base64: String,
}

/// Por qué no se trae una dirección.
///
/// Con motivo y no con un `bool`: la ventana tiene que poder decir **qué** pasó.
/// «No se pudo» sobre una imagen que la persona pidió a propósito no le dice a
/// nadie si el problema es el correo, la red o una decisión de seguridad.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Motivo {
    /// No es `http` ni `https`.
    EsquemaAjeno,
    /// No tiene servidor al que pedirle.
    SinServidor,
    /// Lleva usuario y contraseña adentro de la dirección.
    ConCredenciales,
    /// Apunta a la propia máquina o a la red de al lado.
    RedPrivada,
}

impl std::fmt::Display for Motivo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Motivo::EsquemaAjeno => write!(f, "la dirección no es http ni https"),
            Motivo::SinServidor => write!(f, "la dirección no nombra ningún servidor"),
            Motivo::ConCredenciales => write!(f, "la dirección lleva credenciales adentro"),
            Motivo::RedPrivada => write!(f, "la dirección apunta a tu propia máquina o red"),
        }
    }
}

/// Mira la dirección antes de resolverla.
///
/// Lo que se puede decidir sin tocar la red. Lo demás —a dónde apunta de
/// verdad— hay que resolverlo, y eso pasa en [`traer`].
pub fn revisar(direccion: &str) -> Result<url::Url, Motivo> {
    let url = url::Url::parse(direccion.trim()).map_err(|_| Motivo::SinServidor)?;

    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(Motivo::EsquemaAjeno);
    }
    // `http://usuario:clave@servidor/` manda esas credenciales en la petición.
    // En un correo eso no es un descuido de nadie: es alguien probando a ver si
    // algo las acepta.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Motivo::ConCredenciales);
    }

    let Some(servidor) = url.host_str() else {
        return Err(Motivo::SinServidor);
    };
    if servidor.is_empty() {
        return Err(Motivo::SinServidor);
    }

    // Si ya viene con la dirección numérica puesta, se decide acá y no hace
    // falta resolver nada.
    if let Ok(ip) = servidor.trim_matches(['[', ']']).parse::<IpAddr>() {
        if !direccion_permitida(ip) {
            return Err(Motivo::RedPrivada);
        }
    }

    Ok(url)
}

/// Si a esa dirección se le puede pedir algo.
///
/// **Lista negra explícita y no `is_global`**, que sigue sin estar disponible en
/// Rust estable. Lo que se deja afuera es todo lo que no está en internet:
///
/// - la propia máquina (`127.0.0.0/8`, `::1`),
/// - las redes privadas (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`),
/// - los enlaces locales, que incluyen el `169.254.169.254` del que viven las
///   nubes para entregar credenciales de máquina virtual,
/// - lo no especificado, lo de multidifusión y lo reservado para documentación.
pub fn direccion_permitida(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_documentation()
                // 100.64/10, el rango que usan los proveedores entre su red y la
                // de la persona.
                || (v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
                // 0.0.0.0/8 y 240/4, que no van a ningún lado.
                || v4.octets()[0] == 0
                || v4.octets()[0] >= 240)
        }
        IpAddr::V6(v6) => {
            // Una IPv6 que envuelve una IPv4 se decide por la IPv4 que lleva
            // adentro: `::ffff:127.0.0.1` es la propia máquina con otro nombre.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return direccion_permitida(IpAddr::V4(v4));
            }
            !(v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                // fc00::/7, las privadas.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10, los enlaces locales.
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// El tipo que declaró el servidor, si es uno que aceptamos.
///
/// Se compara contra la lista y se devuelve **el de la lista**, no el que llegó:
/// lo que el servidor manda puede traer parámetros pegados, mayúsculas y
/// espacios, y eso termina en un `data:` del documento de la ventana.
pub fn tipo_aceptado(cabecera: &str) -> Option<&'static str> {
    let declarado = cabecera
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    TIPOS.iter().find(|t| **t == declarado).copied()
}

/// Trae la imagen.
pub async fn traer(direccion: &str) -> Result<Imagen, String> {
    let url = revisar(direccion).map_err(|m| m.to_string())?;

    // A dónde apunta de verdad. Se resuelve acá, antes de pedir nada: es lo que
    // impide que un correo haga que esta máquina se pida cosas a sí misma.
    let servidor = url.host_str().unwrap_or_default().to_string();
    let puerto = url.port_or_known_default().unwrap_or(443);
    let resueltas = tokio::net::lookup_host((servidor.as_str(), puerto))
        .await
        .map_err(|e| format!("no se pudo resolver el nombre: {e}"))?;

    let mut alguna = false;
    for socket in resueltas {
        alguna = true;
        if !direccion_permitida(socket.ip()) {
            return Err(Motivo::RedPrivada.to_string());
        }
    }
    if !alguna {
        return Err(Motivo::SinServidor.to_string());
    }

    let cliente = reqwest::Client::builder()
        // **Sin seguir redirecciones.** Una redirección es la forma de esquivar
        // la comprobación de arriba: la dirección que se revisó es de internet y
        // la siguiente puede ser `127.0.0.1`. Si el servidor quiere mandar a
        // otro lado, la imagen no se muestra.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .user_agent(AGENTE)
        // Sin galletas, y **no porque se apaguen acá**: el cliente se compila
        // sin esa función, así que no hay ningún almacén de galletas que
        // pudiera mandar la sesión de otro sitio a quien puso la dirección en
        // el correo. Está dicho para que nadie la encienda sin pensarlo.
        .build()
        .map_err(|e| format!("no se pudo preparar la petición: {e}"))?;

    let respuesta = cliente
        .get(url)
        // Sin decir de dónde viene. El `Referer` de un correo es la
        // confirmación de que se abrió.
        .header(reqwest::header::REFERER, "")
        .send()
        .await
        .map_err(|e| format!("no se pudo traer la imagen: {e}"))?;

    if !respuesta.status().is_success() {
        return Err(format!("el servidor contestó {}", respuesta.status()));
    }

    let declarado = respuesta
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let Some(tipo) = tipo_aceptado(&declarado) else {
        return Err(format!(
            "eso no es una imagen que se pueda mostrar: {declarado}"
        ));
    };

    let bytes = leer_con_tope(respuesta).await?;

    Ok(Imagen {
        tipo: tipo.to_string(),
        base64: base64::engine::general_purpose::STANDARD.encode(&bytes),
    })
}

/// Lee el cuerpo sin pasarse del tope.
///
/// A medida que llega y no de una: `Content-Length` es lo que el servidor dice
/// que va a mandar, no lo que va a mandar. Sin contar mientras llega, un
/// servidor que promete un kilobyte y manda un gigabyte se lleva puesta la
/// memoria del servicio.
async fn leer_con_tope(respuesta: reqwest::Response) -> Result<Vec<u8>, String> {
    use futures_util::StreamExt;

    let mut recibido: Vec<u8> = Vec::new();
    let mut trozos = respuesta.bytes_stream();

    while let Some(trozo) = trozos.next().await {
        let trozo = trozo.map_err(|e| format!("se cortó la descarga: {e}"))?;
        if recibido.len() + trozo.len() > MAX_BYTES {
            return Err("la imagen es demasiado grande".to_string());
        }
        recibido.extend_from_slice(&trozo);
    }

    if recibido.is_empty() {
        return Err("el servidor no mandó nada".to_string());
    }
    Ok(recibido)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(texto: &str) -> IpAddr {
        texto.parse().expect("es una dirección válida")
    }

    /// **Lo que este módulo existe para impedir.** La dirección la puso quien
    /// escribió el correo, y quien la pide es un proceso de adentro de la
    /// máquina: sin esto, un mensaje puede hacer que la máquina se pida cosas a
    /// sí misma.
    #[test]
    fn no_se_le_pide_nada_a_la_propia_maquina_ni_a_la_red_de_al_lado() {
        for adentro in [
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            // El que entrega credenciales de máquina virtual en casi todas las
            // nubes.
            "169.254.169.254",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "100.64.0.1",
            "240.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            // La propia máquina con otro nombre.
            "::ffff:127.0.0.1",
            "::ffff:192.168.0.1",
        ] {
            assert!(
                !direccion_permitida(ip(adentro)),
                "{adentro} tendría que quedar afuera"
            );
        }
    }

    /// Y lo que sí está en internet se puede pedir, o esto no serviría de nada.
    #[test]
    fn a_internet_si_se_le_pide() {
        for afuera in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700::1111"] {
            assert!(
                direccion_permitida(ip(afuera)),
                "{afuera} tendría que pasar"
            );
        }
    }

    /// `172.16/12` es privado; `172.15` y `172.32` no. Es el rango que más se
    /// escribe mal.
    #[test]
    fn el_borde_del_rango_privado_esta_donde_corresponde() {
        assert!(!direccion_permitida(ip("172.16.0.0")));
        assert!(!direccion_permitida(ip("172.31.255.255")));
        assert!(direccion_permitida(ip("172.15.255.255")));
        assert!(direccion_permitida(ip("172.32.0.0")));
    }

    #[test]
    fn solo_se_piden_direcciones_de_web() {
        assert!(revisar("https://ejemplo.com/p.png").is_ok());
        assert!(revisar("http://ejemplo.com/p.png").is_ok());

        for ajena in [
            "file:///etc/passwd",
            "ftp://ejemplo.com/p.png",
            "data:image/gif;base64,R0lGOD",
            "javascript:alert(1)",
            "cid:parte1@ejemplo",
        ] {
            assert_eq!(revisar(ajena), Err(Motivo::EsquemaAjeno), "{ajena}");
        }
    }

    /// Una dirección con credenciales adentro no es un descuido de nadie: es
    /// alguien probando a ver si algo las acepta.
    #[test]
    fn una_direccion_con_credenciales_no_se_pide() {
        assert_eq!(
            revisar("http://usuario:clave@ejemplo.com/p.png"),
            Err(Motivo::ConCredenciales)
        );
        assert_eq!(
            revisar("http://usuario@ejemplo.com/p.png"),
            Err(Motivo::ConCredenciales)
        );
    }

    /// Con la dirección numérica puesta se decide sin resolver nada.
    #[test]
    fn una_direccion_numerica_privada_se_rechaza_sin_tocar_la_red() {
        assert_eq!(
            revisar("http://127.0.0.1:9000/x.png"),
            Err(Motivo::RedPrivada)
        );
        assert_eq!(revisar("http://192.168.0.1/x.png"), Err(Motivo::RedPrivada));
        // Entre corchetes, que es como va una IPv6 en una dirección web.
        assert_eq!(revisar("http://[::1]/x.png"), Err(Motivo::RedPrivada));
    }

    #[test]
    fn lo_que_no_es_una_direccion_no_se_pide() {
        for basura in [
            "",
            "   ",
            "no es una dirección",
            "http://",
            "://ejemplo.com",
        ] {
            assert!(revisar(basura).is_err(), "{basura:?}");
        }
    }

    /// El tipo se compara con la lista y se devuelve **el de la lista**: lo que
    /// manda el servidor puede traer parámetros, mayúsculas y espacios, y eso
    /// termina en un `data:` del documento de la ventana.
    #[test]
    fn el_tipo_sale_de_la_lista_y_no_del_servidor() {
        assert_eq!(tipo_aceptado("image/png"), Some("image/png"));
        assert_eq!(tipo_aceptado("IMAGE/PNG"), Some("image/png"));
        assert_eq!(
            tipo_aceptado(" image/jpeg ; charset=binario"),
            Some("image/jpeg")
        );
    }

    /// **Un SVG no es una imagen: es un documento, y puede traer script.** Que
    /// los navegadores no lo ejecuten al cargarlo como `<img>` es una propiedad
    /// del motor, no de lo que se está devolviendo.
    #[test]
    fn un_svg_no_se_acepta() {
        assert_eq!(tipo_aceptado("image/svg+xml"), None);
    }

    #[test]
    fn lo_que_no_es_una_imagen_no_se_acepta() {
        for otro in [
            "text/html",
            "application/octet-stream",
            "",
            "image/",
            "imagen/png",
        ] {
            assert_eq!(tipo_aceptado(otro), None, "{otro:?}");
        }
    }
}
