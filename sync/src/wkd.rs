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
    try_methods(|method| fetch_and_validate(&localpart, &domain, method)).await
}

/// El respaldo advanced→direct: prueba cada método en orden y devuelve la primera
/// clave usable; un `Ok(None)` pasa al siguiente método, y un `Err` se recuerda pero
/// no corta (un método puede fallar la red y el otro traer la clave). Si ningún método
/// trae clave, devuelve el último error, o `Ok(None)` si todos dieron «sin clave».
/// `attempt` queda inyectable para probar el respaldo sin red (en producción es
/// [`fetch_and_validate`], que pasa por el veto SSRF y el GET).
async fn try_methods<F, Fut>(mut attempt: F) -> Result<Option<WkdKey>, WkdError>
where
    F: FnMut(Method) -> Fut,
    Fut: std::future::Future<Output = Result<Option<WkdKey>, WkdError>>,
{
    let mut last_err: Option<WkdError> = None;
    for method in [Method::Advanced, Method::Direct] {
        match attempt(method).await {
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

/// Descarga y valida la clave en un método, en tres pasos separados para poder
/// probarlos sueltos: vetar el destino ([`resolve_and_screen`]), descargar
/// ([`get_capped`]) y validar ([`validate_key_bytes`]). `Ok(None)` = sin clave usable
/// acá (se prueba el otro método o se devuelve «sin clave»); `Err` = fallo de red o
/// destino vetado.
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

    let pinned = resolve_and_screen(&host, port).await?;
    if pinned.is_empty() {
        return Ok(None);
    }
    match get_capped(url, &pinned).await? {
        Some(bytes) => validate_key_bytes(&bytes),
        None => Ok(None),
    }
}

/// Resuelve el host y **veta los destinos internos ANTES de conectar**: una URL WKD a
/// un dominio que resuelve a la red interna es el vector SSRF propio de WKD. Falla
/// cerrado si **cualquiera** de las IPs es interna (registro mixto de rebinding).
/// Devuelve las IPs validadas (todas externas), que el GET fija como pin. Separada del
/// GET para que el camino HTTP se pueda ejercer contra un servidor de prueba en
/// loopback sin tocar el veto.
async fn resolve_and_screen(host: &str, port: u16) -> Result<Vec<SocketAddr>, WkdError> {
    let resolved: Vec<SocketAddr> = tokio::time::timeout(
        graph::CONNECT_TIMEOUT,
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| WkdError::Network("la resolución del host expiró".into()))?
    .map_err(|_| WkdError::Network("no se pudo resolver el host".into()))?
    .collect();
    for addr in &resolved {
        if !ip_allowed(addr.ip()) {
            return Err(WkdError::Blocked);
        }
    }
    Ok(resolved)
}

/// Hace el GET endurecido a `url` **fijando las IPs ya validadas** (`pinned`): el
/// connect va a ellas y no vuelve a resolver, lo que cierra el DNS-rebinding/TOCTOU; el
/// certificado y el SNI siguen contra el host de la URL. No sigue redirecciones, acota
/// el plazo y capa el cuerpo ([`MAX_WKD_KEY_BYTES`], contra una clave bomba). Devuelve
/// los bytes, o `None` si no hay clave acá (cualquier no-2xx, incluido un 3xx que no
/// seguimos). Separada del veto para ejercer el camino HTTP contra un fake en loopback.
async fn get_capped(url: Url, pinned: &[SocketAddr]) -> Result<Option<Vec<u8>>, WkdError> {
    let host = url.host_str().ok_or(WkdError::BadAddress)?;
    let client = reqwest::Client::builder()
        .connect_timeout(graph::CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, pinned)
        .build()
        .map_err(|e| WkdError::Network(e.without_url().to_string()))?;

    let response = tokio::time::timeout(graph::REQUEST_TIMEOUT, client.get(url).send())
        .await
        .map_err(|_| WkdError::Network("la descarga expiró".into()))?
        .map_err(|e| WkdError::Network(e.without_url().to_string()))?;
    if !response.status().is_success() {
        return Ok(None);
    }
    graph::read_capped(response, MAX_WKD_KEY_BYTES)
        .await
        .map(Some)
        .map_err(|e| match e {
            graph::CappedReadError::TooLarge => WkdError::TooLarge,
            graph::CappedReadError::Network(n) => WkdError::Network(n),
        })
}

/// Valida unos bytes de clave **como un adjunto hostil** (es dato de red no confiable):
/// parsea, verifica el binding ([`crate::pgp_import::verify_key_bindings`]), recomputa la
/// huella y exige subclave de cifrado usable. Si algo de eso falla, se trata como **sin
/// clave** (`Ok(None)`), no como error. Función pura sobre bytes, sin red: es el borde de
/// entrada no confiable, y por eso es `pub(crate)` —se prueba suelta—.
pub(crate) fn validate_key_bytes(bytes: &[u8]) -> Result<Option<WkdKey>, WkdError> {
    let Ok(key) = crate::pgp::parse_public_key(bytes) else {
        return Ok(None);
    };
    if crate::pgp_import::verify_key_bindings(&key).is_err() {
        return Ok(None);
    }
    if crate::pgp::encryption_subkey(&key).is_none() {
        return Ok(None);
    }
    Ok(Some(WkdKey {
        bytes: bytes.to_vec(),
        fingerprint: crate::pgp::fingerprint(&key),
    }))
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

    // ── validate_key_bytes: el borde de entrada no confiable ────────────

    use crate::pgp::tests::{
        clave_completa, clave_vieja, con_primaria_con_vencimiento_en_el_uid, con_primaria_revocada,
        generar, publica, subclave_de_firma,
    };
    use pgp::composed::SignedPublicKey;
    use pgp::ser::Serialize;

    fn bytes_of(key: &SignedPublicKey) -> Vec<u8> {
        key.to_bytes().unwrap()
    }

    #[test]
    fn una_clave_valida_con_subclave_de_cifrado_se_acepta_con_la_huella_recomputada() {
        let key = publica(&clave_completa("Beto <beto@vasak.test>"));
        let bytes = bytes_of(&key);
        let found = validate_key_bytes(&bytes).unwrap().expect("es usable");
        assert_eq!(found.bytes, bytes);
        assert_eq!(found.fingerprint, crate::pgp::fingerprint(&key));
    }

    #[test]
    fn una_subclave_de_cifrado_con_binding_forjado_se_trata_como_sin_clave() {
        // La primaria real de la víctima con la subclave de cifrado del atacante: su
        // binding no verifica contra la primaria de la víctima. El caso adversario.
        let victima = publica(&clave_completa("Victima <victima@vasak.test>"));
        let atacante = publica(&clave_completa("Atacante <atacante@vasak.test>"));
        let mut forjada = victima.clone();
        forjada.public_subkeys[1] = atacante.public_subkeys[1].clone();
        // Premisa: el selector sí la elegiría; sólo el binding la frena.
        assert!(crate::pgp::encryption_subkey(&forjada).is_some());

        assert!(validate_key_bytes(&bytes_of(&forjada)).unwrap().is_none());
    }

    #[test]
    fn una_clave_revocada_o_expirada_se_trata_como_sin_clave() {
        let vivo = clave_vieja("Beto <beto@vasak.test>");
        let revocada = con_primaria_revocada(&vivo);
        let expirada = con_primaria_con_vencimiento_en_el_uid(&vivo, 24 * 3600);
        for (que, key) in [("revocada", revocada), ("expirada", expirada)] {
            assert!(
                validate_key_bytes(&bytes_of(&key)).unwrap().is_none(),
                "{que}"
            );
        }
    }

    #[test]
    fn una_clave_solo_de_firma_se_trata_como_sin_clave() {
        let key = publica(&generar(
            "Beto <beto@vasak.test>",
            vec![subclave_de_firma()],
        ));
        assert!(validate_key_bytes(&bytes_of(&key)).unwrap().is_none());
    }

    #[test]
    fn bytes_que_no_son_una_clave_se_tratan_como_sin_clave() {
        assert!(validate_key_bytes(b"<html>404</html>").unwrap().is_none());
        assert!(validate_key_bytes(b"").unwrap().is_none());
    }

    // ── get_capped contra un servidor HTTP de loopback ──────────────────

    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Qué contesta el servidor de prueba a cada pedido.
    #[derive(Clone)]
    enum Reply {
        /// Estado y cuerpo, con `Content-Length` honesto.
        Plain(u16, Vec<u8>),
        /// 200 con el cuerpo por trozos y SIN `Content-Length`: el servidor no promete
        /// tamaño alguno, así que sólo el tope de `read_capped` puede frenarlo.
        Chunked(Vec<u8>),
        /// Un redirect a otro lado (que no se debe seguir).
        Redirect,
        /// Acepta y no contesta nunca.
        Silent,
    }

    /// Levanta el servidor en loopback y devuelve su dirección y cuántos pedidos vio.
    async fn serve(reply: Reply) -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let reply = reply.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                    }
                    let response: Vec<u8> = match reply {
                        Reply::Silent => {
                            // Retiene el socket abierto sin contestar.
                            tokio::time::sleep(Duration::from_secs(3600)).await;
                            return;
                        }
                        Reply::Plain(status, body) => {
                            let mut r = format!(
                                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            )
                            .into_bytes();
                            r.extend_from_slice(&body);
                            r
                        }
                        Reply::Redirect => b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
                        Reply::Chunked(body) => {
                            let mut r = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
                            for chunk in body.chunks(64 * 1024) {
                                r.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                                r.extend_from_slice(chunk);
                                r.extend_from_slice(b"\r\n");
                            }
                            r.extend_from_slice(b"0\r\n\r\n");
                            r
                        }
                    };
                    let _ = socket.write_all(&response).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        (addr, seen)
    }

    /// `get_capped` contra ese servidor: URL `http://` (el veto SSRF no interviene: eso
    /// es `resolve_and_screen`) y la IP de loopback como pin.
    async fn get(addr: SocketAddr) -> Result<Option<Vec<u8>>, WkdError> {
        let url = Url::parse(&format!(
            "http://wkd.vasak.test:{}/.well-known/openpgpkey/hu/x?l=joe",
            addr.port()
        ))
        .unwrap();
        get_capped(url, &[addr]).await
    }

    #[tokio::test]
    async fn un_200_devuelve_los_bytes() {
        let (addr, _) = serve(Reply::Plain(200, b"clave".to_vec())).await;
        assert_eq!(get(addr).await.unwrap().unwrap(), b"clave");
    }

    #[tokio::test]
    async fn un_404_o_un_500_es_sin_clave_no_un_error() {
        for status in [404, 500] {
            let (addr, _) = serve(Reply::Plain(status, b"no".to_vec())).await;
            assert!(get(addr).await.unwrap().is_none(), "{status}");
        }
    }

    #[tokio::test]
    async fn una_redireccion_no_se_sigue_y_es_sin_clave() {
        let (addr, seen) = serve(Reply::Redirect).await;
        assert!(get(addr).await.unwrap().is_none());
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn un_cuerpo_de_exactamente_el_tope_se_acepta() {
        let (addr, _) = serve(Reply::Plain(200, vec![7u8; MAX_WKD_KEY_BYTES])).await;
        assert_eq!(get(addr).await.unwrap().unwrap().len(), MAX_WKD_KEY_BYTES);
    }

    #[tokio::test]
    async fn un_cuerpo_que_pasa_el_tope_es_too_large_aunque_no_prometa_tamano() {
        let (addr, _) = serve(Reply::Chunked(vec![7u8; MAX_WKD_KEY_BYTES + 1])).await;
        let r = get(addr).await;
        assert!(matches!(r, Err(WkdError::TooLarge)), "{:?}", r.err());
    }

    #[tokio::test]
    async fn un_content_length_gigante_es_too_large() {
        let (addr, _) = serve(Reply::Plain(200, vec![7u8; MAX_WKD_KEY_BYTES * 2])).await;
        let r = get(addr).await;
        assert!(matches!(r, Err(WkdError::TooLarge)), "{:?}", r.err());
    }

    // Reloj de tokio pausado: el plazo de 60 s corre sin esperar de verdad.
    #[tokio::test(start_paused = true)]
    async fn un_servidor_que_no_contesta_da_network_por_el_plazo() {
        let (addr, _) = serve(Reply::Silent).await;
        let r = get(addr).await;
        assert!(matches!(r, Err(WkdError::Network(_))), "{:?}", r.err());
    }

    #[tokio::test]
    async fn un_servidor_que_no_existe_da_network_y_el_error_no_lleva_la_url() {
        // Puerto cerrado: se bindea y se suelta.
        let addr = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let Err(WkdError::Network(detalle)) = get(addr).await else {
            panic!("tenía que ser Network");
        };
        assert!(!detalle.contains("wkd.vasak.test"), "{detalle}");
        assert!(!detalle.contains("joe"), "{detalle}");
    }

    #[tokio::test]
    async fn el_veto_corre_antes_que_el_get_y_no_conecta() {
        // Un servidor en loopback jamás recibe el pedido si pasa por el veto.
        let (addr, seen) = serve(Reply::Plain(200, b"clave".to_vec())).await;
        let r = resolve_and_screen("127.0.0.1", addr.port()).await;
        assert!(matches!(r, Err(WkdError::Blocked)));
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
