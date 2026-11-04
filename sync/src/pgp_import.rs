//! Import y parseo de claves OpenPGP (vasak-accounts#21, PR3). Dos caras:
//!
//! 1. **La identidad propia** (clave secreta): [`parse_identity_secret_key`]
//!    parsea el material y **liga un UID al `From`** de la cuenta, igual que
//!    S/MIME liga el cert al `From` ([`crate::smime_sign::certificate_matches_address`]).
//!    Una clave que no liga la dirección de la cuenta se rechaza con un error
//!    claro: no serviría para firmar (su firma no ligaría al `From`). El guardado
//!    en `vasak-keyring` ya existe ([`crate::store::pgp_key`]); el flujo D-Bus con
//!    memfd sellado es PR5. Acá va sólo la validación previa.
//!
//! 2. **Las claves públicas de terceros** (peerstate TOFU): [`ingest_peer_key`]
//!    toma los bytes de una clave pública y la dirección del remitente —de un
//!    adjunto `application/pgp-keys` o de una cabecera Autocrypt
//!    ([`parse_autocrypt_header`])— y la guarda en el peerstate
//!    ([`crate::store::pgp_peer`]). El **wiring de sync** que camina el mensaje y
//!    llama a esto es PR4; acá van las funciones.
//!
//! **Entrada hostil.** Las claves públicas y las cabeceras Autocrypt vienen de la
//! red. Nada de `unwrap`/`panic`/indexado sin guardia en los caminos de parseo: un
//! adjunto o una cabecera malformada da error o se ignora, nunca panica. El parseo
//! del material reusa [`crate::pgp::parse_public_key`]/[`crate::pgp::parse_secret_key`]
//! (que ya son no-panicantes) y rPGP, que no entra en pánico sobre bytes arbitrarios.
//!
//! **El binding de subclave se verifica, no se supone (hallazgo de security de
//! PR2).** Antes de confiar en una clave pública para cifrarle o verificarle, se
//! comprueba **criptográficamente** que cada subclave cierra su firma de binding
//! contra la primaria y que la primaria trae al menos una auto-firma válida (ver
//! [`verify_key_bindings`]). Sin esto, un blob con la primaria real de la víctima y
//! una subclave de cifrado con un binding **forjado** nos haría cifrar después a la
//! subclave del atacante. No alcanza la mera presencia de firmas.

// PR3 lo consumen el wiring de sync entrante (PR4) y el import de identidad por
// D-Bus (PR5), que todavía no están. Hasta que lo llamen, el chequeo de código
// muerto lo marcaría entero; se saca al engancharlo. Como todavía no trae pruebas
// propias (las escribe `qa`, §3), el `allow` va incondicional —igual que el núcleo
// `pgp.rs` (PR1)— para que también el target de test (sin llamadas aún) quede
// limpio; `pgp_key`/`pgp_peer` usan `cfg_attr(not(test), …)` porque ya traen sus
// pruebas.
#![allow(dead_code)]

use base64::prelude::{Engine as _, BASE64_STANDARD};
use pgp::composed::{SignedPublicKey, SignedSecretKey};
use pgp::types::{KeyDetails, Tag};

use crate::message::parse_sender;
use crate::pgp::{parse_public_key, parse_secret_key, PgpError};
use crate::store::{Store, StoreError};

// ── Normalización de la dirección ───────────────────────────────────────

/// Normaliza una dirección de correo para el peerstate TOFU: recorte y minúsculas
/// ASCII. Es el **único** punto de normalización, y lo reusan la escritura
/// ([`ingest_peer_key`]) y la extracción de correos de los UIDs
/// ([`self_signed_emails`]). Si la escritura y la lectura divergieran, `Ana@` y
/// `ana@` serían dos entradas TOFU distintas y una clave cambiada esquivaría el
/// aviso de cambio; por eso la normalización vive acá y en un solo lugar.
///
/// Sólo minúsculas ASCII: la parte local de una dirección es sensible a
/// mayúsculas en teoría, pero en la práctica los proveedores la tratan como no
/// sensible, y para TOFU conviene colapsar `Ana@` y `ana@` a una entrada antes que
/// dejar dos. El dominio es insensible por definición.
pub fn normalize_address(address: &str) -> String {
    address.trim().to_ascii_lowercase()
}

// ── Import de la identidad propia (clave secreta) ───────────────────────

/// Parsea una clave **secreta** importada y comprueba que **liga al `From`** de la
/// cuenta: la clave tiene que traer un UID con auto-firma válida cuyo correo
/// coincida (normalizado) con `account_address`. Si no parsea, si la dirección de
/// la cuenta está vacía, o si ningún UID firmado liga esa dirección, devuelve un
/// error claro.
///
/// Sólo cuentan los UIDs **con auto-firma válida** (ver [`self_signed_emails`]):
/// un UID sin firmar, o firmado por otro, no liga identidad —así no se importa una
/// clave a la que alguien le pegó un UID con la dirección de la cuenta sin
/// firmarlo—. Espeja a [`crate::smime_sign::certificate_matches_address`].
pub fn parse_identity_secret_key(
    bytes: &[u8],
    account_address: &str,
) -> Result<SignedSecretKey, PgpError> {
    let key = parse_secret_key(bytes)?;
    let wanted = normalize_address(account_address);
    if wanted.is_empty() {
        return Err(PgpError::BadKey(
            "la dirección de la cuenta está vacía".into(),
        ));
    }
    // `to_public_key` deriva la metadata pública (UIDs y sus firmas) soltando el
    // material secreto; alcanza para ligar el UID sin clonar la clave privada.
    let public = key.to_public_key();
    if self_signed_emails(&public)
        .iter()
        .any(|email| email == &wanted)
    {
        Ok(key)
    } else {
        Err(PgpError::BadKey(format!(
            "la clave no liga ningún UID a {wanted}"
        )))
    }
}

// ── Ingesta de claves públicas de terceros al peerstate (TOFU) ──────────

/// El resultado de ingerir una clave pública para una dirección (TOFU).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ingested {
    /// Primera clave que vemos para esta dirección: se guardó.
    New,
    /// La misma clave que ya teníamos (misma huella): se refrescó `updated_at`.
    Unchanged,
    /// Ya teníamos **otra** clave para esta dirección y la nueva difiere. Con
    /// confianza TOFU la política es **conservadora**: la clave conocida **no se
    /// pisa** (se conserva la vieja con su `first_seen`), y el cambio se señala
    /// para que la UI del correo lo muestre (verificación fuera de banda — PR-mail).
    /// Trae la huella conocida y la nueva para mostrarlas; la **detección** es acá,
    /// el aviso es PR-mail. No se pierde la clave vieja sin señal.
    Changed {
        known_fingerprint: String,
        new_fingerprint: String,
    },
}

/// Lo que puede salir mal al ingerir una clave pública al peerstate.
#[derive(Debug)]
pub enum IngestError {
    /// La clave no parsea, no verifica su binding, o la dirección está vacía: se
    /// rechaza, no se guarda nada.
    Key(PgpError),
    /// El almacén falló al leer o escribir.
    Store(StoreError),
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngestError::Key(e) => write!(f, "{e}"),
            IngestError::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for IngestError {}

/// Ingiere una clave pública de un tercero al peerstate (TOFU). `public_key_bytes`
/// son los bytes de la clave (armor o binario) de un adjunto `application/pgp-keys`
/// o de una cabecera Autocrypt; `sender_address` la dirección del remitente; `now`
/// el instante en segundos epoch que decide el llamador (determinista, como el
/// resto del almacén).
///
/// 1. **Verifica el binding criptográficamente** ([`verify_key_bindings`]): sin
///    esto, una subclave de cifrado con binding forjado nos haría cifrar al
///    atacante. Una clave que no verifica se rechaza y **no se guarda**.
/// 2. **Recomputa la huella** desde la clave (no se acepta ninguna provista): es lo
///    que se guarda y lo que se compara.
/// 3. **Normaliza la dirección** ([`normalize_address`]) igual en escritura y en
///    lectura.
/// 4. **Detecta el cambio TOFU**: lee el estado previo ([`Store::find_peer`]) antes
///    de escribir; si ya había una clave con **otra** huella, devuelve
///    [`Ingested::Changed`] y **no pisa** la conocida.
pub fn ingest_peer_key(
    store: &Store,
    sender_address: &str,
    public_key_bytes: &[u8],
    now: i64,
) -> Result<Ingested, IngestError> {
    let key = parse_public_key(public_key_bytes).map_err(IngestError::Key)?;
    verify_key_bindings(&key).map_err(IngestError::Key)?;
    let new_fingerprint = key.primary_key.fingerprint().to_string();

    let address = normalize_address(sender_address);
    if address.is_empty() {
        return Err(IngestError::Key(PgpError::BadKey(
            "la dirección del remitente está vacía".into(),
        )));
    }

    match store.find_peer(&address).map_err(IngestError::Store)? {
        Some(previous) if previous.fingerprint != new_fingerprint => {
            // TOFU: la clave cambió. No se pisa la conocida; se señala el cambio.
            Ok(Ingested::Changed {
                known_fingerprint: previous.fingerprint,
                new_fingerprint,
            })
        }
        Some(_) => {
            // La misma clave: se refresca `updated_at` (los bytes son idénticos).
            store
                .upsert_peer(&address, public_key_bytes, &new_fingerprint, now)
                .map_err(IngestError::Store)?;
            Ok(Ingested::Unchanged)
        }
        None => {
            store
                .upsert_peer(&address, public_key_bytes, &new_fingerprint, now)
                .map_err(IngestError::Store)?;
            Ok(Ingested::New)
        }
    }
}

// ── Verificación criptográfica del binding (el hallazgo de PR2) ─────────

/// Comprueba **criptográficamente** que una clave pública es coherente antes de
/// confiar en ella para cifrar o verificar:
///
/// - **cada subclave** cierra su firma de binding contra la primaria
///   ([`pgp::composed::SignedPublicSubKey::verify_bindings`], que verifica el
///   binding y, para una subclave de firma, su backsig). Un binding **forjado**
///   falla y se **rechaza la clave entera**: no se guarda una clave con una
///   subclave que después elegiríamos para cifrar sin que su binding cierre.
/// - la **primaria** trae al menos una auto-firma válida (una auto-certificación
///   de UID o una firma directa de clave): prueba que el material de la primaria
///   es coherente y auto-firmado, y descarta una primaria trasplantada con un UID
///   pegado sin firma.
///
/// **No se usa el `verify_bindings()` entero de rPGP a propósito.** Ese exige que
/// **todas** las firmas de cada UID cierren como auto-firma, y rechaza cualquier
/// clave que traiga **certificaciones de terceros** (la red de confianza), muy
/// común en una clave adjunta exportada por GnuPG. Acá se tolera eso —alcanza con
/// que **una** auto-firma de la primaria cierre— sin bajar la guardia donde
/// importa: los bindings de subclave, que son el vector del hallazgo de PR2.
fn verify_key_bindings(key: &SignedPublicKey) -> Result<(), PgpError> {
    for subkey in &key.public_subkeys {
        subkey
            .verify_bindings(&key.primary_key)
            .map_err(|e| PgpError::BadKey(format!("binding de subclave inválido: {e}")))?;
    }
    if primary_has_valid_self_signature(key) {
        Ok(())
    } else {
        Err(PgpError::BadKey(
            "la primaria no trae ninguna auto-firma válida".into(),
        ))
    }
}

/// Si la primaria tiene al menos una auto-firma que cierra: una firma directa de
/// clave, o una auto-certificación de alguno de sus UIDs. Tolera firmas de
/// terceros (no exige que todas cierren, sólo que una lo haga).
fn primary_has_valid_self_signature(key: &SignedPublicKey) -> bool {
    let primary = &key.primary_key;
    let direct_ok = key
        .details
        .direct_signatures
        .iter()
        .any(|sig| sig.verify_key(primary).is_ok());
    if direct_ok {
        return true;
    }
    key.details.users.iter().any(|user| {
        user.signatures.iter().any(|sig| {
            sig.verify_certification(primary, Tag::UserId, &user.id)
                .is_ok()
        })
    })
}

/// Los correos de los UIDs **con auto-certificación válida** de una clave,
/// normalizados. Sólo cuentan los UIDs cuya firma cierra contra la primaria: un
/// UID sin firmar o firmado por otro no liga identidad. Se usa para ligar la
/// identidad propia al `From` en [`parse_identity_secret_key`].
fn self_signed_emails(key: &SignedPublicKey) -> Vec<String> {
    let primary = &key.primary_key;
    key.details
        .users
        .iter()
        .filter(|user| {
            user.signatures.iter().any(|sig| {
                sig.verify_certification(primary, Tag::UserId, &user.id)
                    .is_ok()
            })
        })
        .filter_map(|user| user.id.as_str())
        .map(|uid| {
            // Un UID es «Nombre <correo>» o un correo pelado: `parse_sender` saca
            // la dirección en los dos casos, reusando el mismo parser que el `From`.
            let (_name, address) = parse_sender(uid);
            normalize_address(&address)
        })
        .filter(|email| !email.is_empty())
        .collect()
}

// ── Parseo de la cabecera Autocrypt entrante ────────────────────────────

/// La clave pública y la dirección de una cabecera `Autocrypt:`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutocryptHeader {
    /// La dirección que declara la cabecera (atributo `addr`), sin normalizar: la
    /// normaliza quien la ingiere ([`ingest_peer_key`]), en un solo lugar.
    pub addr: String,
    /// Los bytes **binarios** de la clave pública (el `keydata` base64 decodificado),
    /// listos para [`ingest_peer_key`].
    pub key: Vec<u8>,
}

/// Parsea el **valor** de una cabecera `Autocrypt:` (Autocrypt Level 1) y devuelve
/// su `addr` y su clave, o `None` si la cabecera es inválida. El llamador (PR4) ya
/// desdobló la cabecera y decidió que hay exactamente una (Autocrypt ignora un
/// mensaje con cabeceras Autocrypt repetidas; eso es de la extracción, no de acá).
///
/// Reglas de Autocrypt Level 1 que se aplican:
/// - atributos separados por `;`, cada uno `nombre=valor`;
/// - hacen falta `addr` y `keydata`;
/// - `keydata` es base64 (puede venir plegado con espacios: se le quitan antes de
///   decodificar) de la clave **binaria**;
/// - un atributo **crítico desconocido** (nombre que no empieza con `_` y no es uno
///   de los conocidos) invalida la cabecera entera → `None`; los no-críticos
///   (nombre que empieza con `_`) se ignoran, como `prefer-encrypt`.
///
/// Entrada hostil: nada panica. Un `=` ausente, un base64 ilegible o un atributo
/// faltante dan `None`; no se valida acá que la clave parsee ni que ligue (eso lo
/// hace [`ingest_peer_key`]).
pub fn parse_autocrypt_header(value: &str) -> Option<AutocryptHeader> {
    let mut addr: Option<String> = None;
    let mut keydata: Option<String> = None;

    for attribute in value.split(';') {
        let attribute = attribute.trim();
        if attribute.is_empty() {
            continue;
        }
        // `split_once('=')` corta en el **primer** `=`: el nombre no lo lleva, y el
        // relleno base64 de `keydata` (que sí lo lleva, al final) queda en el valor.
        let (name, attr_value) = attribute.split_once('=')?;
        let name = name.trim();
        let attr_value = attr_value.trim();
        match name {
            "addr" => addr = Some(attr_value.to_string()),
            "keydata" => keydata = Some(attr_value.to_string()),
            // Atributo crítico conocido cuyo valor no usamos acá.
            "prefer-encrypt" => {}
            // No-crítico (empieza con `_`): se ignora.
            _ if name.starts_with('_') => {}
            // Crítico desconocido: invalida la cabecera entera (Autocrypt L1).
            _ => return None,
        }
    }

    let addr = addr?;
    let keydata = keydata?;
    // El base64 puede venir plegado en varias líneas con espacios/tabs: se quitan
    // todos los espacios ASCII antes de decodificar.
    let compact: String = keydata
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let key = BASE64_STANDARD.decode(compact.as_bytes()).ok()?;
    if key.is_empty() {
        return None;
    }
    Some(AutocryptHeader { addr, key })
}
