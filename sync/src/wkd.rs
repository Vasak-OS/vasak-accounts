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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // El vector del draft WKD: SHA-1 de `joe.doe` en z-base32. Literal a propósito: la
    // prueba no sigue al código, lo vigila.
    const Z_JOE_DOE: &str = "iy9q119eutrkn8s1mk4r39qejnbu3n5q";

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    #[test]
    fn el_hash_del_localpart_coincide_con_el_vector_del_draft() {
        use sha1::{Digest, Sha1};
        let digest = Sha1::digest(b"joe.doe");
        assert_eq!(zbase32(&digest), Z_JOE_DOE);
    }

    #[test]
    fn z_base32_usa_el_alfabeto_propio_y_alinea_los_bits_sobrantes() {
        // Cero bytes → todo `y` (el símbolo 0 del alfabeto, no `a` como en base32).
        assert_eq!(zbase32(&[0u8; 20]), "y".repeat(32));
        // 0xff × 20 → todo el último símbolo (`9`).
        assert_eq!(zbase32(&[0xffu8; 20]), "9".repeat(32));
        // Un byte: 8 bits → 2 símbolos, el segundo con 3 bits alineados a la izquierda.
        assert_eq!(zbase32(&[0x01]), "yr");
    }

    #[test]
    fn la_url_advanced_lleva_el_hash_en_minusculas_y_el_localpart_original_en_l() {
        let url = build_url("Joe.Doe", "example.org", Method::Advanced).unwrap();
        assert_eq!(
            url.as_str(),
            format!(
                "https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/{Z_JOE_DOE}?l=Joe.Doe"
            )
        );
    }

    #[test]
    fn la_url_direct_no_usa_el_subdominio_openpgpkey() {
        let url = build_url("Joe.Doe", "example.org", Method::Direct).unwrap();
        assert_eq!(
            url.as_str(),
            format!("https://example.org/.well-known/openpgpkey/hu/{Z_JOE_DOE}?l=Joe.Doe")
        );
    }

    #[test]
    fn el_localpart_con_caracteres_raros_va_codificado_en_el_query() {
        let url = build_url("a b&c", "example.org", Method::Direct).unwrap();
        // Ni un `&` ni un espacio crudos: no se puede inyectar otro parámetro.
        let query = url.query().unwrap();
        assert!(!query.contains(' '));
        assert_eq!(query.matches('&').count(), 0, "{query}");
        assert_eq!(url.query_pairs().count(), 1);
        assert_eq!(url.query_pairs().next().unwrap().1, "a b&c");
    }

    #[test]
    fn la_direccion_se_parte_en_el_ultimo_arroba_y_el_dominio_va_en_minusculas() {
        let (local, domain) = split_address("Joe.Doe@Example.ORG").unwrap();
        assert_eq!(local, "Joe.Doe");
        assert_eq!(domain, "example.org");
    }

    #[test]
    fn una_direccion_mal_formada_es_bad_address() {
        for malo in ["", "sin-arroba", "@example.org", "joe@"] {
            assert!(
                matches!(split_address(malo), Err(WkdError::BadAddress)),
                "{malo:?}"
            );
        }
    }

    #[test]
    fn las_ips_internas_se_vetan() {
        let internas = [
            v4(127, 0, 0, 1),
            v4(127, 255, 255, 254),
            v4(10, 0, 0, 1),
            v4(172, 16, 0, 1),
            v4(172, 31, 255, 255),
            v4(192, 168, 1, 1),
            v4(169, 254, 169, 254),
            v4(0, 0, 0, 0),
            v4(224, 0, 0, 1),
            v4(255, 255, 255, 255),
            v6("::1"),
            v6("::"),
            v6("fe80::1"),
            v6("febf::1"),
            v6("fc00::1"),
            v6("fd12:3456::1"),
            v6("ff02::1"),
            // IPv4 mapeada en IPv6: se desmapea y se revalida.
            v6("::ffff:127.0.0.1"),
            v6("::ffff:10.1.2.3"),
            v6("::ffff:192.168.0.1"),
        ];
        for ip in internas {
            assert!(!ip_allowed(ip), "{ip} debería vetarse");
        }
    }

    #[test]
    fn las_ips_publicas_pasan() {
        let publicas = [
            v4(93, 184, 216, 34),
            v4(8, 8, 8, 8),
            // Fronteras de las privadas: 172.15 y 172.32 no son RFC1918.
            v4(172, 15, 0, 1),
            v4(172, 32, 0, 1),
            v6("2606:2800:220:1:248:1893:25c8:1946"),
            v6("::ffff:8.8.8.8"),
            // `fec0::/10` (site-local, obsoleta) queda fuera de `fe80::/10`.
            v6("fec0::1"),
        ];
        for ip in publicas {
            assert!(ip_allowed(ip), "{ip} debería pasar");
        }
    }

    // El camino de red real: el host se resuelve y se veta ANTES de conectar. `localhost`
    // resuelve a loopback sin tocar la red; si el veto faltara, el connect a :443 daría
    // `Network` (rechazado) o, peor, conectaría a un servicio interno.
    #[tokio::test]
    async fn un_dominio_que_resuelve_a_loopback_se_veta_sin_conectar() {
        let r = fetch_key("joe@localhost").await;
        assert!(matches!(r, Err(WkdError::Blocked)), "{r:?}", r = r.err());
    }

    #[tokio::test]
    async fn una_ip_privada_literal_como_dominio_se_veta() {
        for dominio in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254"] {
            let r = fetch_key(&format!("joe@{dominio}")).await;
            assert!(
                matches!(r, Err(WkdError::Blocked)),
                "{dominio}: {r:?}",
                r = r.err()
            );
        }
    }

    #[tokio::test]
    async fn una_direccion_mal_formada_no_llega_a_la_red() {
        let r = fetch_key("sin-arroba").await;
        assert!(matches!(r, Err(WkdError::BadAddress)));
    }
}
