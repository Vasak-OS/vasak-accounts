//! Cliente WKD (Web Key Directory): descubre la clave pública OpenPGP de una
//! dirección por HTTPS, para resolver su estado de clave al redactar (método D-Bus
//! `ResolveRecipientKey`) y, más adelante, para cifrarle. Se usa **al redactar**,
//! nunca en el camino de sync entrante: una descarga síncrona por mensaje sería el
//! peor caso de rendimiento, y por eso verificar entrante usa sólo fuentes locales.
//!
//! El host de la URL lo decide el **dominio del destinatario**, influido por quien
//! escribe el correo, así que la defensa de mismo-origen de `graph.rs` no aplica acá.
//! El endurecimiento anti-SSRF propio de WKD:
//!
//! - **Sólo HTTPS** (la URL se construye `https://` y se reafirma el esquema).
//! - **Se resuelve el host y se vetan los destinos internos** antes de conectar:
//!   loopback, privadas RFC1918, link-local, ULA (`fc00::/7`), no especificada y
//!   multicast. Una IPv4 mapeada en IPv6 se desmapea y se revalida. Si **cualquiera**
//!   de las IPs resueltas es interna, se rechaza el destino entero (fallar cerrado
//!   ante un registro mixto de rebinding).
//! - **Se fija la IP ya validada** en el cliente (`resolve_to_addrs`): el connect va a
//!   esa IP, lo que cierra el TOCTOU/DNS-rebinding; la validación de certificado y el
//!   SNI siguen contra el `domain` original, que es lo correcto.
//! - **No se siguen redirecciones** (política de `graph::http_client`) y hay **plazo**
//!   y **tope de tamaño** por descarga (`graph::REQUEST_TIMEOUT`, `read_capped`): una
//!   clave con millones de firmas/UIDs es una bomba.
//!
//! La clave descargada es **dato de red hostil**: se parsea y se **valida el binding**
//! con el mismo molde que un adjunto (`pgp_import::verify_key_bindings`), y la huella
//! se recomputa desde la clave (no se confía en nada externo). Si no valida o no tiene
//! subclave de cifrado usable, se trata como **sin clave**.

use std::net::{IpAddr, SocketAddr};

use url::Url;

use crate::graph;

/// Tope del cuerpo de la clave descargada por WKD. Igual que `MAX_PGP_KEY_BYTES` del
/// import de identidad (1 MiB): una clave legítima entra de sobra, y más que esto es
/// una bomba de firmas/UIDs. Se aplica con [`graph::read_capped`], que corta a medida
/// que llega sin creerle al `Content-Length`.
pub const MAX_WKD_KEY_BYTES: usize = 1024 * 1024;

/// Alfabeto z-base32 (RFC-draft WKD). **No** es el base32 estándar: el orden de los
/// símbolos es distinto a propósito (optimizado para leerlo y dictarlo).
const ZBASE32_ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// La clave que WKD encontró para una dirección: los bytes tal como se descargaron
/// (ya parseados y validados) y la **huella recomputada** desde la clave.
pub struct WkdKey {
    /// Los bytes de la clave descargada, para guardarla al peerstate (TOFU).
    pub bytes: Vec<u8>,
    /// La huella de la primaria, recomputada desde la clave.
    pub fingerprint: String,
}

/// Lo que puede salir mal al descubrir una clave por WKD. Ninguna variante vuelca la
/// URL (que lleva el localpart) a los registros; quien llama la mapea a su estado.
#[derive(Debug)]
pub enum WkdError {
    /// La dirección no es `localpart@domain`.
    BadAddress,
    /// El destino resuelve a una IP interna/privada o el esquema no es HTTPS: posible
    /// SSRF, se rechaza sin conectar.
    Blocked,
    /// La descarga falló o expiró. El texto no lleva la URL ni el localpart.
    Network(String),
    /// El cuerpo de la clave superó [`MAX_WKD_KEY_BYTES`].
    TooLarge,
}

impl std::fmt::Display for WkdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WkdError::BadAddress => f.write_str("la dirección no es válida para WKD"),
            WkdError::Blocked => f.write_str("el destino WKD es interno o no es HTTPS"),
            WkdError::Network(d) => write!(f, "la descarga WKD falló: {d}"),
            WkdError::TooLarge => f.write_str("la clave WKD supera el tope de tamaño"),
        }
    }
}

impl std::error::Error for WkdError {}

/// Los dos métodos de derivación de la URL WKD. Se prueba *advanced* primero y
/// *direct* como respaldo (RFC-draft WKD §3.1).
#[derive(Clone, Copy)]
enum Method {
    /// `https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<Z>?l=<lp>`.
    Advanced,
    /// `https://<domain>/.well-known/openpgpkey/hu/<Z>?l=<lp>`.
    Direct,
}

/// Descubre la clave pública de `address` por WKD: prueba *advanced* y, si no da una
/// clave usable, *direct*. Devuelve:
///
/// - `Ok(Some(key))` cuando encontró una clave que **parsea, verifica el binding y
///   tiene subclave de cifrado usable**;
/// - `Ok(None)` cuando no hay clave (404 en ambos métodos, o la que respondió no es
///   usable: se trata como sin clave, no como error);
/// - `Err(_)` ante un fallo de red o un destino vetado (SSRF).
pub async fn fetch_key(address: &str) -> Result<Option<WkdKey>, WkdError> {
    let (localpart, domain) = split_address(address)?;
    let mut last_err: Option<WkdError> = None;
    for method in [Method::Advanced, Method::Direct] {
        match fetch_and_validate(&localpart, &domain, method).await {
            Ok(Some(key)) => return Ok(Some(key)),
            Ok(None) => {}
            Err(e) => last_err = Some(e),
        }
    }
    match last_err {
        Some(e) => Err(e),
        None => Ok(None),
    }
}

/// Parte `localpart@domain`. El `domain` se baja a minúsculas (el host es
/// insensible a mayúsculas); el `localpart` se conserva tal cual (va en `?l=` sin
/// tocar; sólo se baja a minúsculas **para el hash**).
fn split_address(address: &str) -> Result<(String, String), WkdError> {
    let at = address.rfind('@').ok_or(WkdError::BadAddress)?;
    let localpart = &address[..at];
    let domain = &address[at + 1..];
    if localpart.is_empty() || domain.is_empty() || domain.contains('@') {
        return Err(WkdError::BadAddress);
    }
    Ok((localpart.to_string(), domain.to_lowercase()))
}

/// z-base32 de un hash SHA-1 de 20 bytes → 32 caracteres (⌈160/5⌉). Implementado
/// inline para no sumar una dependencia por tan poco. El alfabeto no es el estándar
/// ([`ZBASE32_ALPHABET`]).
fn zbase32(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().saturating_mul(8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ZBASE32_ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        // Los bits que sobran se alinean a la izquierda del último símbolo.
        out.push(ZBASE32_ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Deriva la URL WKD para un método. El `<Z>` es z-base32 de SHA-1 del localpart en
/// minúsculas; el `?l=` lleva el localpart **original**, percent-encoded por el crate
/// `url`.
fn build_url(localpart: &str, domain: &str, method: Method) -> Result<Url, WkdError> {
    use sha1::{Digest, Sha1};
    let digest = Sha1::digest(localpart.to_lowercase().as_bytes());
    let z = zbase32(&digest);
    let base = match method {
        Method::Advanced => {
            format!("https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{z}")
        }
        Method::Direct => format!("https://{domain}/.well-known/openpgpkey/hu/{z}"),
    };
    let mut url = Url::parse(&base).map_err(|_| WkdError::BadAddress)?;
    if url.scheme() != "https" {
        return Err(WkdError::Blocked);
    }
    url.query_pairs_mut().append_pair("l", localpart);
    Ok(url)
}

/// Descarga y valida la clave en un método. La red va capada en plazo y tamaño; la
/// clave se valida como un adjunto hostil. `Ok(None)` = sin clave usable acá (se
/// prueba el otro método o se devuelve «sin clave»); `Err` = fallo de red o destino
/// vetado.
async fn fetch_and_validate(
    localpart: &str,
    domain: &str,
    method: Method,
) -> Result<Option<WkdKey>, WkdError> {
    let url = build_url(localpart, domain, method)?;
    // Reafirmar el esquema: sólo HTTPS (build_url ya lo garantiza; defensa barata).
    if url.scheme() != "https" {
        return Err(WkdError::Blocked);
    }
    let host = url.host_str().ok_or(WkdError::BadAddress)?.to_string();
    let port = url.port_or_known_default().unwrap_or(443);

    // Resolver el host nosotros y vetar los destinos internos ANTES de conectar: una
    // URL WKD a un dominio que resuelve a la red interna es el vector SSRF propio de
    // WKD. Se falla cerrado si cualquiera de las IPs es interna (registro mixto de
    // rebinding).
    let resolved: Vec<SocketAddr> = tokio::time::timeout(
        graph::CONNECT_TIMEOUT,
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await
    .map_err(|_| WkdError::Network("la resolución del host expiró".into()))?
    .map_err(|_| WkdError::Network("no se pudo resolver el host".into()))?
    .collect();
    if resolved.is_empty() {
        return Ok(None);
    }
    for addr in &resolved {
        if !ip_allowed(addr.ip()) {
            return Err(WkdError::Blocked);
        }
    }

    // Fijar las IPs ya validadas: el connect va a ellas y no vuelve a resolver, lo que
    // cierra el DNS-rebinding/TOCTOU. El certificado y el SNI siguen contra `host`.
    let client = reqwest::Client::builder()
        .connect_timeout(graph::CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(&host, &resolved)
        .build()
        .map_err(|e| WkdError::Network(e.without_url().to_string()))?;

    let response = tokio::time::timeout(graph::REQUEST_TIMEOUT, client.get(url).send())
        .await
        .map_err(|_| WkdError::Network("la descarga expiró".into()))?
        .map_err(|e| WkdError::Network(e.without_url().to_string()))?;
    // Un 404 (o cualquier no-2xx, incluido un 3xx que no seguimos) es «sin clave acá».
    if !response.status().is_success() {
        return Ok(None);
    }
    let bytes = graph::read_capped(response, MAX_WKD_KEY_BYTES)
        .await
        .map_err(|e| match e {
            graph::CappedReadError::TooLarge => WkdError::TooLarge,
            graph::CappedReadError::Network(n) => WkdError::Network(n),
        })?;

    // La clave es dato de red hostil: mismo trato que un adjunto. Si no parsea, el
    // binding no verifica, o no tiene subclave de cifrado usable → se trata como sin
    // clave (no como error de red): se prueba el otro método.
    let Ok(key) = crate::pgp::parse_public_key(&bytes) else {
        return Ok(None);
    };
    if crate::pgp_import::verify_key_bindings(&key).is_err() {
        return Ok(None);
    }
    if crate::pgp::encryption_subkey(&key).is_none() {
        return Ok(None);
    }
    let fingerprint = crate::pgp::fingerprint(&key);
    Ok(Some(WkdKey { bytes, fingerprint }))
}

/// Si una IP resuelta es un destino **externo** válido para WKD. Rechaza loopback,
/// privadas RFC1918, link-local, ULA (`fc00::/7`), no especificada y multicast. Una
/// IPv4 mapeada en IPv6 se desmapea y se revalida como IPv4.
fn ip_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast())
        }
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return ip_allowed(IpAddr::V4(mapped));
            }
            let octets = v6.octets();
            // ULA `fc00::/7`: el primer octeto es `1111110x`.
            let is_unique_local = (octets[0] & 0xfe) == 0xfc;
            // Link-local `fe80::/10`: los diez bits altos son `1111111010`.
            let is_link_local = (u16::from_be_bytes([octets[0], octets[1]]) & 0xffc0) == 0xfe80;
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_unique_local
                || is_link_local)
        }
    }
}
