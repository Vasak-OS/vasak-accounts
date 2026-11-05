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
use pgp::packet::SignatureType;
use pgp::ser::Serialize;
use pgp::types::{KeyDetails, Tag};

use crate::message::{
    as_latin1, decode_transfer, from_latin1, parse_content_type, parse_sender, split_headers,
    split_parts, Headers,
};
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
    let mut key = parse_secret_key(bytes)?;
    let wanted = normalize_address(account_address);
    if wanted.is_empty() {
        return Err(PgpError::BadKey(
            "la dirección de la cuenta está vacía".into(),
        ));
    }
    // Descarta las revocaciones de primaria forjadas, igual que el camino de pares
    // (`ingest_peer_key` → `strip_forged_revocations`), pero sobre la secreta: la
    // revocación vive en el mismo `details.revocation_signatures`. `to_public_key`
    // **clona** `details`, así que sanear la pública derivada no tocaría la secreta
    // que devolvemos. `crate::pgp::primary_usable` trata cualquier `KeyRevocation`
    // por **presencia**, de modo que una revocación que un `From` spoofeado adjuntó
    // dejaría la identidad guardada sin poder firmar (`NoSigningKey`). Las
    // auto-revocaciones válidas se conservan (y la clave quedará correctamente
    // inutilizada). `public_key()` deriva la primaria pública para verificar.
    let primary_public = key.primary_key.public_key();
    key.details
        .revocation_signatures
        .retain(|sig| sig.verify_key(&primary_public).is_ok());

    // `to_public_key` deriva la metadata pública (UIDs y sus firmas) soltando el
    // material secreto; alcanza para validar sin clonar la clave privada. Se valida
    // lo mismo que para un par: los bindings de subclave cierran
    // (`verify_key_bindings`, el hallazgo de PR2) y un UID **no revocado** liga el
    // `From`.
    let public = key.to_public_key();
    verify_key_bindings(&public)?;
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
    /// Misma huella que ya teníamos: se refresca sólo `updated_at` sin reescribir la
    /// clave guardada (un blob entrante con la misma primaria no debe **reducirla** —
    /// p. ej. venir sin la subclave de cifrado—).
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
///    de escribir. Si ya había una clave con **otra** huella, devuelve
///    [`Ingested::Changed`] y **no pisa** la conocida; si es la **misma** huella no
///    reescribe `public_key` (sólo refresca `updated_at`), porque un blob entrante
///    nunca debe reducir la clave guardada. Al guardar una clave **nueva** descarta
///    antes las revocaciones de primaria forjadas ([`strip_forged_revocations`]).
pub fn ingest_peer_key(
    store: &Store,
    sender_address: &str,
    public_key_bytes: &[u8],
    now: i64,
) -> Result<Ingested, IngestError> {
    let mut key = parse_public_key(public_key_bytes).map_err(IngestError::Key)?;
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
        Some(previous) => {
            // Misma huella: NO se **reemplaza** la clave guardada —un blob con la
            // subclave de cifrado quitada no debe reducir la ya guardada (TOFU
            // conservador, decisión 3)—, pero sí se **fusionan** las revocaciones y
            // bindings autenticados que traiga la actualización: sin esto, una subclave
            // que el contacto revocó se seguiría aceptando como firmante. Si no hay nada
            // nuevo autenticado, sólo se refresca `updated_at`.
            let mut stored = parse_public_key(&previous.public_key).map_err(IngestError::Key)?;
            if merge_authenticated_updates(&mut stored, &key) {
                let bytes = stored.to_bytes().map_err(|e| {
                    IngestError::Key(PgpError::BadKey(format!(
                        "no se pudo re-serializar la clave fusionada: {e}"
                    )))
                })?;
                store
                    .upsert_peer(&address, &bytes, &new_fingerprint, now)
                    .map_err(IngestError::Store)?;
            } else {
                store
                    .touch_peer(&address, now)
                    .map_err(IngestError::Store)?;
            }
            Ok(Ingested::Unchanged)
        }
        None => {
            // Primera vez: antes de guardar se descartan las revocaciones de primaria
            // forjadas (ver `strip_forged_revocations`); una auto-revocación válida se
            // conserva y la honra `crate::pgp::primary_usable`.
            let stored =
                strip_forged_revocations(&mut key, public_key_bytes).map_err(IngestError::Key)?;
            store
                .upsert_peer(&address, &stored, &new_fingerprint, now)
                .map_err(IngestError::Store)?;
            Ok(Ingested::New)
        }
    }
}

/// Fusiona en la clave guardada (`stored`) las revocaciones de primaria y las firmas
/// de subclave (bindings y revocaciones) **autenticadas** que trae una actualización
/// `incoming` con la **misma** primaria. No quita material (anti-degradación de la
/// decisión 3: se mezcla, no se reemplaza). Devuelve `true` si agregó algo.
///
/// Sólo se mezcla lo que **verifica contra la primaria guardada**: así una
/// actualización con el `From` spoofeado no puede inyectar una revocación forjada
/// (el mismo criterio que `strip_forged_revocations` y `verify_key_bindings`).
///
/// shortcut: no se agregan subclaves **nuevas** del blob entrante (rotación de
/// subclave), sólo se honran las revocaciones/bindings de las ya conocidas; subir a
/// soportar rotación si un contacto rota su subclave de cifrado y hay que adoptarla.
fn merge_authenticated_updates(stored: &mut SignedPublicKey, incoming: &SignedPublicKey) -> bool {
    let primary = stored.primary_key.clone();
    let mut changed = false;

    // Revocaciones de primaria autenticadas que falten.
    for sig in &incoming.details.revocation_signatures {
        if sig.verify_key(&primary).is_ok() && !stored.details.revocation_signatures.contains(sig) {
            stored.details.revocation_signatures.push(sig.clone());
            changed = true;
        }
    }

    // Firmas de subclave (binding/revocación) autenticadas que falten, cotejando la
    // subclave por huella: sólo se tocan subclaves ya conocidas.
    for inc_sub in &incoming.public_subkeys {
        let inc_fp = inc_sub.key.fingerprint();
        let Some(stored_sub) = stored
            .public_subkeys
            .iter_mut()
            .find(|s| s.key.fingerprint() == inc_fp)
        else {
            continue;
        };
        for sig in &inc_sub.signatures {
            if sig.verify_subkey_binding(&primary, &inc_sub.key).is_ok()
                && !stored_sub.signatures.contains(sig)
            {
                stored_sub.signatures.push(sig.clone());
                changed = true;
            }
        }
    }
    changed
}

// ── Verificación criptográfica del binding (el hallazgo de PR2) ─────────

/// Comprueba **criptográficamente** que una clave pública es coherente antes de
/// confiar en ella para cifrar o verificar:
///
/// - **cada subclave** cierra su firma de binding contra la primaria
///   ([`pgp::composed::SignedPublicSubKey::verify_bindings`], que verifica el
///   binding y, para una subclave de firma, su backsig). Una subclave **sin ninguna
///   firma de binding** no llega hasta acá: rPGP 0.21 la descarta al parsear
///   (`SignedPublicKey::new` retiene sólo las subclaves firmadas) y `verify_bindings`
///   además exige al menos una firma (`ensure!(!signatures.is_empty())`) —no es un
///   chequeo vacuo—, así que una subclave sin binding ni se guarda ni se elige para
///   cifrar. Un binding **forjado** falla y se **rechaza la clave entera**: no se
///   guarda una clave con una subclave que después elegiríamos para cifrar sin que su
///   binding cierre.
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

/// Descarta de `key` las firmas de revocación de la primaria que **no** verifican
/// contra ella —forjadas por un atacante que spoofeó el `From`— y devuelve los bytes
/// a guardar. Una **auto-revocación válida** se conserva (el contacto revocó su clave
/// de verdad) y la honra [`crate::pgp::primary_usable`].
///
/// Por qué acá y no al honrar: `primary_usable` trata la clave como revocada por la
/// **mera presencia** de una `KeyRevocation` (más barato por uso). Sin este filtro un
/// atacante adjunta una revocación firmada por él a la primaria real de la víctima y,
/// al guardarse, la inutiliza para cifrar (DoS). Filtrando en el import, lo guardado
/// ya está saneado y el chequeo por presencia es sólido. (`revocation_signatures` sólo
/// trae firmas de tipo `KeyRevocation`, que [`pgp::packet::Signature::verify_key`]
/// comprueba contra la primaria.)
///
/// Si no se descartó ninguna firma, se guardan los bytes originales tal cual se
/// ingirieron; si se descartó alguna, se re-serializa la clave saneada.
fn strip_forged_revocations(
    key: &mut SignedPublicKey,
    original: &[u8],
) -> Result<Vec<u8>, PgpError> {
    let before = key.details.revocation_signatures.len();
    key.details
        .revocation_signatures
        .retain(|sig| sig.verify_key(&key.primary_key).is_ok());
    if key.details.revocation_signatures.len() == before {
        return Ok(original.to_vec());
    }
    key.to_bytes()
        .map_err(|e| PgpError::BadKey(format!("no se pudo re-serializar la clave saneada: {e}")))
}

/// Los correos de los UIDs **con auto-certificación válida y vigente** de una clave,
/// normalizados. Sólo cuentan los UIDs cuya firma cierra contra la primaria y cuya
/// auto-certificación aplicable **más reciente no es una revocación**: un UID sin
/// firmar, firmado por otro, o **revocado** no liga identidad. Se usa para ligar la
/// identidad propia al `From` en [`parse_identity_secret_key`].
fn self_signed_emails(key: &SignedPublicKey) -> Vec<String> {
    let primary = &key.primary_key;
    key.details
        .users
        .iter()
        .filter(|user| {
            // Gana la auto-certificación aplicable **más reciente** (por `created()`):
            // rPGP conserva las `CertRevocation` del UID en `signatures` y
            // `verify_certification` las acepta (la revocación de UID es una
            // certificación tipo 0x30, RFC 9580), así que mirar «alguna firma verifica»
            // aceptaría un UID revocado. El UID liga sólo si la más nueva de sus
            // auto-certificaciones que verifican NO es una revocación.
            user.signatures
                .iter()
                .filter(|sig| {
                    sig.verify_certification(primary, Tag::UserId, &user.id)
                        .is_ok()
                })
                .max_by_key(|sig| sig.created().map(|t| t.as_secs()).unwrap_or(0))
                .is_some_and(|sig| sig.typ() != Some(SignatureType::CertRevocation))
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

// ── Claves públicas que trae un mensaje entrante ────────────────────────

/// Tope del blob de una clave pública adjunta (`application/pgp-keys`), medido sobre
/// los bytes **codificados** de la parte (cota superior holgada del binario). Una
/// clave normal pesa pocos KiB; más de 1 MiB es una clave con miles de firmas de UID
/// —una bomba de CPU/memoria al parsear— y se ignora, no se intenta parsear. Es el
/// follow-up de security de PR3 contra un adjunto gigante.
const MAX_KEY_BLOB: usize = 1024 * 1024;

/// Tope del `keydata` de una cabecera `Autocrypt:`, medido sobre el valor de la
/// cabecera (mayormente base64) y sobre el binario decodificado. 128 KiB es muy
/// holgado para una clave Autocrypt legítima (pocos KiB) y corta en seco una
/// cabecera gigante antes de gastar CPU decodificando base64. Mismo follow-up.
const MAX_AUTOCRYPT_KEYDATA: usize = 128 * 1024;

/// Profundidad máxima de anidado MIME al buscar claves adjuntas, igual criterio que
/// [`crate::attachments`]: un mensaje legítimo no anida tanto, y acota el trabajo
/// ante un `multipart` patológicamente profundo.
const MAX_MIME_DEPTH: usize = 8;

/// Tope de partes `application/pgp-keys` que se juntan de un mensaje. Un mensaje
/// legítimo trae una o dos claves; cientos de partes es un abuso que haría parsear
/// (y verificar bindings de) una clave por cada una. Corta además del tope por blob
/// ([`MAX_KEY_BLOB`]).
const MAX_KEY_PARTS: usize = 16;

/// Las claves públicas que trae un mensaje entrante para ingerir al peerstate: la de
/// la cabecera `Autocrypt:` (atribuida a su `addr`, **sólo si coincide con el `From`**
/// —Autocrypt L1 ignora la cabecera cuyo `addr` no es el del remitente—) y las de los
/// adjuntos `application/pgp-keys` (atribuidas al `From`). Devuelve `(dirección, bytes)`
/// para pasar tal cual a [`ingest_peer_key`]; la normalización de la dirección y la
/// validación del material las hace esa función (un solo lugar).
///
/// Parseo puro, sin red y sin pánico sobre entrada hostil. Respeta los topes de
/// tamaño ([`MAX_KEY_BLOB`], [`MAX_AUTOCRYPT_KEYDATA`]) **antes** de parsear, para
/// que un adjunto o una cabecera gigantes no sean una bomba de CPU/memoria. El
/// wiring de sync (PR4) llama a esto y luego a [`ingest_peer_key`] por cada par.
pub fn incoming_public_keys(raw: &[u8]) -> Vec<(String, Vec<u8>)> {
    let view = as_latin1(raw);
    let (headers, body) = split_headers(&view);
    let mut found = Vec::new();

    // El `From` del mensaje (sólo la dirección): liga tanto los adjuntos como la
    // cabecera Autocrypt. El mismo parser que `smime_sign::message_from`.
    let from = parse_sender(headers.get("from").unwrap_or_default()).1;
    let from_normalized = normalize_address(&from);

    // Cabecera Autocrypt: el valor acotado antes de decodificar, y la clave binaria
    // acotada después. `split_headers` da un solo valor por nombre; tomar sólo ése es
    // conservador (Autocrypt L1 ignora el mensaje con cabeceras repetidas). Autocrypt
    // L1 además manda **ignorar** la cabecera si su `addr` no es el del remitente: sin
    // esto, un `From` spoofeado sembraría en el peerstate TOFU la clave del atacante
    // bajo la dirección de la víctima. Se compara normalizado.
    // Autocrypt L1: se consideran todas las cabeceras `Autocrypt` válidas (parseables,
    // dentro del tope y con `addr` == `From`). Si queda **más de una**, es un error y se
    // ignoran TODAS; sólo se siembra la clave cuando hay **exactamente una**.
    let valid_autocrypt: Vec<AutocryptHeader> = headers
        .get_all("autocrypt")
        .filter(|value| value.len() <= MAX_AUTOCRYPT_KEYDATA)
        .filter_map(parse_autocrypt_header)
        .filter(|header| {
            header.key.len() <= MAX_AUTOCRYPT_KEYDATA
                && normalize_address(&header.addr) == from_normalized
        })
        .collect();
    if let [header] = valid_autocrypt.as_slice() {
        found.push((header.addr.clone(), header.key.clone()));
    }

    // Adjuntos `application/pgp-keys`, atribuidos al `From` del mensaje. Sin `From`
    // no hay dirección bajo la cual ingerirlos: se omiten (`ingest_peer_key` también
    // rechazaría la dirección vacía).
    if !from.is_empty() {
        collect_key_attachments(&headers, body, 0, &from, &mut found);
    }
    found
}

/// Baja por el árbol MIME juntando los blobs de las partes `application/pgp-keys`,
/// decodificados según su `Content-Transfer-Encoding`, atribuidos a `from`. Acota la
/// profundidad y el tamaño; una parte que se pasa del tope se ignora.
fn collect_key_attachments(
    headers: &Headers,
    body: &str,
    depth: usize,
    from: &str,
    out: &mut Vec<(String, Vec<u8>)>,
) {
    if depth > MAX_MIME_DEPTH || out.len() >= MAX_KEY_PARTS {
        return;
    }
    let content_type = headers
        .get("content-type")
        .map(parse_content_type)
        .unwrap_or_default();

    if let Some(boundary) = &content_type.boundary {
        for part in split_parts(body, boundary) {
            let (part_headers, part_body) = split_headers(part);
            collect_key_attachments(&part_headers, part_body, depth + 1, from, out);
        }
        return;
    }

    if content_type.media_type == "application/pgp-keys" {
        // Cota sobre lo codificado antes de decodificar: un adjunto gigante no gasta
        // CPU/memoria en base64.
        if body.len() > MAX_KEY_BLOB {
            return;
        }
        let encoding = headers.get("content-transfer-encoding").unwrap_or("7bit");
        let decoded = decode_transfer(&from_latin1(body), encoding);
        if !decoded.is_empty() && decoded.len() <= MAX_KEY_BLOB {
            out.push((from.to_string(), decoded));
        }
    }
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

#[cfg(test)]
mod tests {
    //! Pruebas del import y la ingesta de claves OpenPGP. Las claves se generan con
    //! el propio `pgp` (helpers de `crate::pgp::tests`): nada de binarios opacos. La
    //! que más importa es la adversaria: una primaria real con una subclave de
    //! cifrado de **binding forjado** no puede entrar al peerstate.
    use super::*;
    use crate::pgp::tests::{clave_completa, publica, vacia};
    use crate::pgp::{encryption_subkey, PgpError};
    use crate::store::contacts::tests::open_store;
    use crate::store::paths::tests::TempDir;
    use pgp::composed::{SignedPublicKey, SignedSecretKey};
    use pgp::packet::{KeyFlags, SignatureConfig, SignatureType, Subpacket, SubpacketData, UserId};
    use pgp::ser::Serialize;
    use pgp::types::{KeyDetails, PacketHeaderVersion, Tag, Timestamp};
    use rand::rngs::OsRng;

    const AHORA: i64 = 1_000;
    // Los topes que fija la especificación, a propósito como literales: la prueba
    // no sigue a las constantes del código, las vigila.
    const MIB: usize = 1024 * 1024;
    const KIB_128: usize = 128 * 1024;

    fn bytes(key: &SignedPublicKey) -> Vec<u8> {
        key.to_bytes().expect("la clave serializa")
    }

    fn huella(key: &SignedPublicKey) -> String {
        key.primary_key.fingerprint().to_string()
    }

    fn es_bad_key<T: std::fmt::Debug>(r: Result<T, PgpError>) -> bool {
        matches!(r, Err(PgpError::BadKey(_)))
    }

    fn es_error_de_clave(r: Result<Ingested, IngestError>) -> bool {
        matches!(r, Err(IngestError::Key(_)))
    }

    // ── Identidad propia (clave secreta) ───────────────────────────────

    #[test]
    fn la_clave_cuyo_uid_liga_la_direccion_de_la_cuenta_se_importa() {
        let key = clave_completa("Ana <ana@example.com>");
        let armada = key.to_armored_bytes(Default::default()).unwrap();
        // Ni la capitalización ni los espacios de la dirección de la cuenta importan.
        assert!(parse_identity_secret_key(&armada, "  Ana@Example.com ").is_ok());
        assert!(parse_identity_secret_key(&key.to_bytes().unwrap(), "ana@example.com").is_ok());
    }

    #[test]
    fn la_clave_con_un_uid_de_otra_direccion_se_rechaza() {
        let key = clave_completa("Ana <ana@example.com>");
        let r = parse_identity_secret_key(&key.to_bytes().unwrap(), "beto@example.com");
        assert!(es_bad_key(r));
    }

    #[test]
    fn bytes_que_no_parsean_como_clave_secreta_son_bad_key() {
        assert!(es_bad_key(parse_identity_secret_key(
            b"esto no es una clave",
            "ana@example.com"
        )));
        assert!(es_bad_key(parse_identity_secret_key(
            b"",
            "ana@example.com"
        )));
    }

    #[test]
    fn la_direccion_de_cuenta_vacia_se_rechaza() {
        let key = clave_completa("Ana <ana@example.com>");
        let b = key.to_bytes().unwrap();
        assert!(es_bad_key(parse_identity_secret_key(&b, "")));
        assert!(es_bad_key(parse_identity_secret_key(&b, "   ")));
    }

    #[test]
    fn un_uid_con_el_correo_correcto_pero_sin_auto_firma_no_liga() {
        let mut key = clave_completa("Ana <ana@example.com>");
        key.details.users[0].signatures.clear();
        let r = parse_identity_secret_key(&key.to_bytes().unwrap(), "ana@example.com");
        assert!(es_bad_key(r), "un UID sin firmar no liga identidad");
    }

    #[test]
    fn un_uid_pegado_con_el_correo_de_la_cuenta_reusando_la_firma_de_otro_no_liga() {
        // La clave firma «otra@»; alguien le pega un UID «ana@» con esa misma firma
        // (que cubre otro UID): la firma no cierra sobre el UID pegado.
        let mut key = clave_completa("Otra <otra@example.com>");
        let mut pegado = key.details.users[0].clone();
        pegado.id = UserId::from_str(PacketHeaderVersion::New, "Ana <ana@example.com>").unwrap();
        key.details.users.push(pegado);
        let b = key.to_bytes().unwrap();
        assert!(es_bad_key(parse_identity_secret_key(&b, "ana@example.com")));
        // Control: el UID genuino sí liga.
        assert!(parse_identity_secret_key(&b, "otra@example.com").is_ok());
    }

    // ── Ingesta pública: el binding forjado (adversario) ───────────────

    /// La primaria real de la víctima con la subclave de **cifrado del atacante**
    /// en su lugar (índice 1 de `clave_completa`), trayendo la firma de binding del
    /// atacante: es válida para la primaria del atacante, no para la de la víctima.
    fn primaria_de_la_victima_con_subclave_forjada() -> (SignedPublicKey, SignedPublicKey) {
        let victima = publica(&clave_completa("Victima <victima@example.com>"));
        let atacante = publica(&clave_completa("Atacante <atacante@example.com>"));
        let mut forjada = victima.clone();
        forjada.public_subkeys[1] = atacante.public_subkeys[1].clone();
        (forjada, atacante)
    }

    #[test]
    fn una_subclave_de_cifrado_con_binding_forjado_no_entra_al_peerstate() {
        let temp = TempDir::new("pgp-import-forjada");
        let store = open_store(&temp);
        let (forjada, atacante) = primaria_de_la_victima_con_subclave_forjada();

        // Premisa: sin la verificación criptográfica, el selector de subclave de
        // cifrado elegiría la del atacante (sólo mira flags y fechas). Es la
        // única defensa: por eso la ingesta tiene que rechazar la clave entera.
        let elegida = encryption_subkey(&forjada).expect("el selector la elegiría");
        assert_eq!(
            elegida.key.fingerprint().to_string(),
            atacante.public_subkeys[1].key.fingerprint().to_string()
        );

        let r = ingest_peer_key(&store, "victima@example.com", &bytes(&forjada), AHORA);
        assert!(es_error_de_clave(r), "el binding forjado debe rechazarse");
        assert!(
            store.find_peer("victima@example.com").unwrap().is_none(),
            "no se guarda nada en el peerstate"
        );
    }

    #[test]
    fn una_subclave_sin_ninguna_firma_de_binding_nunca_se_elige_para_cifrar() {
        // rPGP 0.21 descarta al parsear las subclaves sin firmas y `verify_bindings`
        // exige al menos una: una subclave sin binding ni se guarda ni se elige. Se
        // fija ese invariante: nadie cifra a una subclave que no trae binding.
        let temp = TempDir::new("pgp-import-sin-binding");
        let store = open_store(&temp);
        let mut key = publica(&clave_completa("Ana <ana@example.com>"));
        key.public_subkeys[1].signatures.clear();
        let _ = ingest_peer_key(&store, "ana@example.com", &bytes(&key), AHORA);
        let guardada = store
            .find_peer("ana@example.com")
            .unwrap()
            .map(|p| crate::pgp::parse_public_key(&p.public_key).unwrap());
        if let Some(guardada) = guardada {
            assert!(encryption_subkey(&guardada).is_none());
        }
    }

    #[test]
    fn una_subclave_de_firma_sin_backsig_valida_se_rechaza() {
        let temp = TempDir::new("pgp-import-sin-backsig");
        let store = open_store(&temp);
        let secret = clave_completa("Ana <ana@example.com>");
        // Control: la clave tal cual se generó (la subclave de firma trae su
        // backsig) entra.
        let sana = publica(&secret);
        assert!(ingest_peer_key(&store, "ana@example.com", &bytes(&sana), AHORA).is_ok());

        // Se reata la subclave 0 (de firma) con un binding que declara «firma» pero
        // no trae la firma de vuelta (backsig) de la subclave: cualquiera podría
        // haber atado esa subclave sin que su dueño lo consienta.
        let mut flags = KeyFlags::default();
        flags.set_sign(true);
        let mut key = publica(&secret);
        let subkey = key.public_subkeys[0].clone();
        let primaria = &secret.primary_key;
        let mut config =
            SignatureConfig::from_key(OsRng, primaria, SignatureType::SubkeyBinding).unwrap();
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
            Subpacket::regular(SubpacketData::KeyFlags(flags)).unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(primaria.fingerprint())).unwrap(),
        ];
        key.public_subkeys[0].signatures = vec![config
            .sign_subkey_binding(primaria, primaria.public_key(), &vacia(), &subkey.key)
            .unwrap()];

        let temp2 = TempDir::new("pgp-import-sin-backsig-2");
        let store2 = open_store(&temp2);
        let r = ingest_peer_key(&store2, "ana@example.com", &bytes(&key), AHORA);
        assert!(es_error_de_clave(r), "sin backsig válida se rechaza");
        assert!(store2.find_peer("ana@example.com").unwrap().is_none());
    }

    #[test]
    fn una_primaria_sin_auto_firma_valida_se_rechaza() {
        let temp = TempDir::new("pgp-import-sin-autofirma");
        let store = open_store(&temp);
        let mut key = publica(&clave_completa("Ana <ana@example.com>"));
        key.details.users[0].signatures.clear();
        let r = ingest_peer_key(&store, "ana@example.com", &bytes(&key), AHORA);
        assert!(es_error_de_clave(r));
        assert!(store.find_peer("ana@example.com").unwrap().is_none());
    }

    // ── Revocaciones de la primaria (H1) y no reducir la guardada (H2) ──

    /// Una `KeyRevocation` sobre la primaria de `objetivo`, firmada por `firmante`.
    fn revocacion(
        firmante: &SignedSecretKey,
        objetivo: &SignedSecretKey,
    ) -> pgp::packet::Signature {
        SignatureConfig::from_key(OsRng, &firmante.primary_key, SignatureType::KeyRevocation)
            .unwrap()
            .sign_key(
                &firmante.primary_key,
                &vacia(),
                objetivo.primary_key.public_key(),
            )
            .expect("firma de revocación")
    }

    fn guardada(store: &Store, address: &str) -> SignedPublicKey {
        let peer = store.find_peer(address).unwrap().expect("hay fila");
        parse_public_key(&peer.public_key).unwrap()
    }

    #[test]
    fn una_revocacion_forjada_por_otra_clave_no_inhabilita_la_primaria_de_la_victima() {
        let temp = TempDir::new("pgp-import-revocacion-forjada");
        let store = open_store(&temp);
        let victima = clave_completa("Victima <victima@example.com>");
        let atacante = clave_completa("Atacante <atacante@example.com>");
        let mut key = publica(&victima);
        assert!(encryption_subkey(&key).is_some(), "premisa: usable");
        key.details
            .revocation_signatures
            .push(revocacion(&atacante, &victima));
        // Premisa: sin el saneo, la mera presencia la inutilizaría.
        assert!(encryption_subkey(&key).is_none());

        let r = ingest_peer_key(&store, "victima@example.com", &bytes(&key), AHORA);
        assert_eq!(r.unwrap(), Ingested::New);
        let g = guardada(&store, "victima@example.com");
        assert!(g.details.revocation_signatures.is_empty());
        assert!(encryption_subkey(&g).is_some(), "la forjada se descartó");
    }

    #[test]
    fn una_auto_revocacion_valida_sobrevive_al_saneo_e_inhabilita_la_clave() {
        let temp = TempDir::new("pgp-import-autorevocacion");
        let store = open_store(&temp);
        let ana = clave_completa("Ana <ana@example.com>");
        let mut key = publica(&ana);
        key.details
            .revocation_signatures
            .push(revocacion(&ana, &ana));

        let r = ingest_peer_key(&store, "ana@example.com", &bytes(&key), AHORA);
        assert_eq!(r.unwrap(), Ingested::New);
        let g = guardada(&store, "ana@example.com");
        assert_eq!(g.details.revocation_signatures.len(), 1);
        assert!(
            encryption_subkey(&g).is_none(),
            "la guardada queda revocada"
        );
    }

    #[test]
    fn con_una_revocacion_valida_y_una_forjada_se_conserva_solo_la_valida() {
        let temp = TempDir::new("pgp-import-revocacion-mixta");
        let store = open_store(&temp);
        let ana = clave_completa("Ana <ana@example.com>");
        let atacante = clave_completa("Atacante <atacante@example.com>");
        let mut key = publica(&ana);
        key.details
            .revocation_signatures
            .push(revocacion(&atacante, &ana));
        key.details
            .revocation_signatures
            .push(revocacion(&ana, &ana));

        ingest_peer_key(&store, "ana@example.com", &bytes(&key), AHORA).unwrap();
        let g = guardada(&store, "ana@example.com");
        assert_eq!(g.details.revocation_signatures.len(), 1);
        assert!(g.details.revocation_signatures[0]
            .verify_key(&g.primary_key)
            .is_ok());
        assert!(encryption_subkey(&g).is_none());
    }

    #[test]
    fn la_misma_primaria_sin_la_subclave_de_cifrado_no_reduce_la_clave_guardada() {
        let temp = TempDir::new("pgp-import-no-reduce");
        let store = open_store(&temp);
        let sana = publica(&clave_completa("Ana <ana@example.com>"));
        let original = bytes(&sana);
        ingest_peer_key(&store, "ana@example.com", &original, 100).unwrap();

        let mut reducida = sana.clone();
        reducida.public_subkeys.remove(1);
        assert!(
            encryption_subkey(&reducida).is_none(),
            "premisa: sin cifrado"
        );
        let r = ingest_peer_key(&store, "ana@example.com", &bytes(&reducida), 200);
        assert_eq!(r.unwrap(), Ingested::Unchanged);

        let peer = store.find_peer("ana@example.com").unwrap().unwrap();
        assert_eq!(peer.public_key, original, "la clave guardada no cambia");
        assert!(encryption_subkey(&guardada(&store, "ana@example.com")).is_some());
        assert_eq!((peer.first_seen, peer.updated_at), (100, 200));
    }

    // ── Ingesta pública: TOFU ──────────────────────────────────────────

    #[test]
    fn una_clave_nueva_se_guarda_con_la_huella_recomputada_y_reingerirla_no_cambia_nada() {
        let temp = TempDir::new("pgp-import-nueva");
        let store = open_store(&temp);
        let key = publica(&clave_completa("Ana <ana@example.com>"));
        let b = bytes(&key);

        assert_eq!(
            ingest_peer_key(&store, "ana@example.com", &b, 100).unwrap(),
            Ingested::New
        );
        let peer = store.find_peer("ana@example.com").unwrap().unwrap();
        assert_eq!(peer.fingerprint, huella(&key), "la huella sale de la clave");
        assert_eq!(peer.public_key, b);
        assert_eq!((peer.first_seen, peer.updated_at), (100, 100));

        assert_eq!(
            ingest_peer_key(&store, "ana@example.com", &b, 200).unwrap(),
            Ingested::Unchanged
        );
        let peer = store.find_peer("ana@example.com").unwrap().unwrap();
        assert_eq!(peer.first_seen, 100, "TOFU: first_seen se conserva");
        assert_eq!(peer.updated_at, 200, "se refresca updated_at");
    }

    #[test]
    fn una_clave_distinta_para_la_misma_direccion_se_senala_y_no_pisa_la_conocida() {
        let temp = TempDir::new("pgp-import-cambiada");
        let store = open_store(&temp);
        let a = publica(&clave_completa("Ana <ana@example.com>"));
        let b = publica(&clave_completa("Ana <ana@example.com>"));
        assert_ne!(huella(&a), huella(&b));

        ingest_peer_key(&store, "ana@example.com", &bytes(&a), 100).unwrap();
        let r = ingest_peer_key(&store, "ana@example.com", &bytes(&b), 200).unwrap();
        assert_eq!(
            r,
            Ingested::Changed {
                known_fingerprint: huella(&a),
                new_fingerprint: huella(&b),
            }
        );
        let peer = store.find_peer("ana@example.com").unwrap().unwrap();
        assert_eq!(peer.fingerprint, huella(&a), "sigue la clave conocida");
        assert_eq!(peer.public_key, bytes(&a));
        assert_eq!(peer.updated_at, 100, "no se tocó la fila");
    }

    #[test]
    fn la_direccion_se_normaliza_y_no_hay_dos_filas_por_capitalizacion() {
        let temp = TempDir::new("pgp-import-normaliza");
        let store = open_store(&temp);
        let a = publica(&clave_completa("Ana <ana@example.com>"));
        let b = publica(&clave_completa("Ana <ana@example.com>"));

        ingest_peer_key(&store, "Ana@Example.com", &bytes(&a), 100).unwrap();
        let r = ingest_peer_key(&store, "ana@example.com", &bytes(&b), 200).unwrap();
        assert!(matches!(r, Ingested::Changed { .. }), "{r:?}");
        let filas = crate::store::pgp_peer::list_peers(store.connection()).unwrap();
        assert_eq!(filas.len(), 1);
        assert_eq!(filas[0].address, "ana@example.com");
    }

    #[test]
    fn una_clave_con_certificaciones_de_terceros_se_acepta() {
        // Estilo `gpg --export`: el UID trae, antes de la auto-firma, la
        // certificación de un tercero. El `verify_bindings` entero de rPGP la
        // rechazaría; acá se tolera mientras la auto-firma y los bindings cierren.
        let temp = TempDir::new("pgp-import-terceros");
        let store = open_store(&temp);
        let ana = clave_completa("Ana <ana@example.com>");
        let tercero = clave_completa("Tercero <tercero@example.com>");
        let mut key = publica(&ana);
        let de_tercero =
            SignatureConfig::from_key(OsRng, &tercero.primary_key, SignatureType::CertPositive)
                .unwrap()
                .sign_certification_third_party(
                    &tercero.primary_key,
                    &vacia(),
                    &ana.primary_key.public_key().clone(),
                    Tag::UserId,
                    &key.details.users[0].id,
                )
                .expect("certificación de tercero");
        key.details.users[0].signatures.insert(0, de_tercero);

        let r = ingest_peer_key(&store, "ana@example.com", &bytes(&key), AHORA);
        assert_eq!(r.unwrap(), Ingested::New);
    }

    // ── Endurecimiento del import de la clave propia ────────────────────

    #[test]
    fn un_uid_revocado_mas_recientemente_no_liga_la_direccion_de_la_cuenta() {
        let mut key = clave_completa("Ana <ana@example.com>");
        let primaria = key.primary_key.clone();
        let positiva = key.details.users[0].signatures[0].created().unwrap();
        // Control: sin la revocación, el UID liga.
        assert!(parse_identity_secret_key(&key.to_bytes().unwrap(), "ana@example.com").is_ok());

        // La revocación del UID es estrictamente posterior a la auto-certificación.
        let mut config =
            SignatureConfig::from_key(OsRng, &primaria, SignatureType::CertRevocation).unwrap();
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                positiva.as_secs() + 100,
            )))
            .unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(primaria.fingerprint())).unwrap(),
        ];
        let revocada = config
            .sign_certification(
                &primaria,
                primaria.public_key(),
                &vacia(),
                Tag::UserId,
                &key.details.users[0].id,
            )
            .expect("revocación del UID");
        key.details.users[0].signatures.push(revocada);

        let r = parse_identity_secret_key(&key.to_bytes().unwrap(), "ana@example.com");
        assert!(es_bad_key(r), "un UID revocado no liga identidad");
    }

    #[test]
    fn una_revocacion_forjada_en_la_identidad_se_descarta_y_la_clave_sigue_firmando() {
        let victima = clave_completa("Ana <ana@example.com>");
        let atacante = clave_completa("Atacante <atacante@example.com>");
        let mut key = victima.clone();
        key.details
            .revocation_signatures
            .push(revocacion(&atacante, &victima));
        // Premisa: sin el saneo, la mera presencia la deja sin poder firmar.
        assert!(matches!(
            crate::pgp::sign_detached(b"hola", &key, &vacia()),
            Err(PgpError::NoSigningKey)
        ));

        let sana = parse_identity_secret_key(&key.to_bytes().unwrap(), "ana@example.com")
            .expect("la forjada no impide importar");
        assert!(sana.details.revocation_signatures.is_empty());
        assert!(crate::pgp::sign_detached(b"hola", &sana, &vacia()).is_ok());
    }

    #[test]
    fn una_auto_revocacion_valida_en_la_identidad_la_inutiliza_para_firmar() {
        let ana = clave_completa("Ana <ana@example.com>");
        let mut key = ana.clone();
        key.details
            .revocation_signatures
            .push(revocacion(&ana, &ana));

        let importada = parse_identity_secret_key(&key.to_bytes().unwrap(), "ana@example.com")
            .expect("importa");
        assert_eq!(importada.details.revocation_signatures.len(), 1);
        assert!(matches!(
            crate::pgp::sign_detached(b"hola", &importada, &vacia()),
            Err(PgpError::NoSigningKey)
        ));
    }

    #[test]
    fn la_identidad_con_una_subclave_de_binding_forjado_se_rechaza() {
        let ana = clave_completa("Ana <ana@example.com>");
        let atacante = clave_completa("Atacante <atacante@example.com>");
        // Control: la clave sana se importa.
        assert!(parse_identity_secret_key(&ana.to_bytes().unwrap(), "ana@example.com").is_ok());

        // La subclave de cifrado de Ana queda atada con un binding firmado por el
        // atacante: no cierra contra la primaria de Ana.
        let mut key = ana.clone();
        let subkey = publica(&ana).public_subkeys[1].clone();
        key.secret_subkeys[1].signatures = vec![crate::pgp::tests::firmar_union(
            &atacante,
            &subkey,
            SignatureType::SubkeyBinding,
            None,
        )];

        let r = parse_identity_secret_key(&key.to_bytes().unwrap(), "ana@example.com");
        assert!(es_bad_key(r), "el binding forjado debe rechazarse");
    }

    #[test]
    fn un_remitente_vacio_se_rechaza_y_no_guarda() {
        let temp = TempDir::new("pgp-import-sin-remitente");
        let store = open_store(&temp);
        let b = bytes(&publica(&clave_completa("Ana <ana@example.com>")));
        for vacio in ["", "   "] {
            assert!(es_error_de_clave(ingest_peer_key(&store, vacio, &b, AHORA)));
        }
        assert!(crate::store::pgp_peer::list_peers(store.connection())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn bytes_que_no_son_una_clave_se_rechazan_sin_entrar_en_panico() {
        let temp = TempDir::new("pgp-import-basura");
        let store = open_store(&temp);
        for basura in [
            &b""[..],
            b"hola",
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n",
        ] {
            assert!(es_error_de_clave(ingest_peer_key(
                &store,
                "ana@example.com",
                basura,
                AHORA
            )));
        }
    }

    // ── Autocrypt ──────────────────────────────────────────────────────

    fn b64(b: &[u8]) -> String {
        BASE64_STANDARD.encode(b)
    }

    #[test]
    fn la_cabecera_autocrypt_valida_se_decodifica_aunque_el_base64_venga_plegado() {
        let clave = (0u8..=200).collect::<Vec<u8>>();
        let plegado = b64(&clave)
            .as_bytes()
            .chunks(20)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n\t ");
        let h = parse_autocrypt_header(&format!("addr=ana@example.com; keydata= {plegado}"))
            .expect("válida");
        assert_eq!(h.addr, "ana@example.com");
        assert_eq!(h.key, clave);
    }

    #[test]
    fn la_cabecera_sin_addr_o_sin_keydata_es_invalida() {
        let k = b64(b"clave");
        assert_eq!(parse_autocrypt_header(&format!("keydata={k}")), None);
        assert_eq!(parse_autocrypt_header("addr=ana@example.com"), None);
        assert_eq!(parse_autocrypt_header(""), None);
    }

    #[test]
    fn un_atributo_critico_desconocido_invalida_la_cabecera() {
        let k = b64(b"clave");
        assert_eq!(
            parse_autocrypt_header(&format!("addr=a@b.c; novedad=1; keydata={k}")),
            None
        );
    }

    #[test]
    fn los_atributos_no_criticos_y_prefer_encrypt_se_ignoran() {
        let k = b64(b"clave");
        let h = parse_autocrypt_header(&format!(
            "addr=a@b.c; prefer-encrypt=mutual; _algo=ed25519; keydata={k}"
        ))
        .expect("sigue válida");
        assert_eq!(h.addr, "a@b.c");
        assert_eq!(h.key, b"clave");
    }

    #[test]
    fn un_base64_ilegible_o_vacio_es_invalido() {
        assert_eq!(
            parse_autocrypt_header("addr=a@b.c; keydata=!!!no-base64!!!"),
            None
        );
        assert_eq!(parse_autocrypt_header("addr=a@b.c; keydata="), None);
    }

    #[test]
    fn la_basura_no_entra_en_panico() {
        for basura in [
            ";;;;",
            "=",
            "addr",
            "addr=;keydata=;",
            "\u{0}\u{ffff}=\u{1f980}",
            "keydata==========",
            &"x=;".repeat(10_000),
        ] {
            let _ = parse_autocrypt_header(basura);
        }
    }

    #[test]
    fn de_la_cabecera_autocrypt_a_la_ingesta_con_la_addr_como_remitente() {
        let temp = TempDir::new("pgp-import-autocrypt");
        let store = open_store(&temp);
        let key = publica(&clave_completa("Ana <ana@example.com>"));
        let valor = format!(
            "addr=Ana@Example.com; prefer-encrypt=mutual; keydata={}",
            b64(&bytes(&key))
        );

        let h = parse_autocrypt_header(&valor).expect("cabecera válida");
        assert_eq!(
            ingest_peer_key(&store, &h.addr, &h.key, AHORA).unwrap(),
            Ingested::New
        );
        let peer = store.find_peer("ana@example.com").unwrap().unwrap();
        assert_eq!(peer.fingerprint, huella(&key));
    }

    // ── Claves que trae un mensaje entrante (`incoming_public_keys`) ────

    /// Un correo `multipart/mixed` de `from` con `extra` cabeceras y, por cada
    /// `(Content-Type, Content-Transfer-Encoding, cuerpo)`, una parte.
    fn correo_con_partes(from: &str, extra: &str, partes: &[(&str, &str, String)]) -> Vec<u8> {
        let mut out =
            format!("From: {from}\r\n{extra}Content-Type: multipart/mixed; boundary=\"M\"\r\n\r\n");
        for (tipo, cte, cuerpo) in partes {
            out.push_str(&format!(
                "--M\r\nContent-Type: {tipo}\r\nContent-Transfer-Encoding: {cte}\r\n\r\n{cuerpo}\r\n"
            ));
        }
        out.push_str("--M--\r\n");
        out.into_bytes()
    }

    fn adjunta(key: &SignedPublicKey) -> (&'static str, &'static str, String) {
        ("application/pgp-keys", "base64", b64(&bytes(key)))
    }

    #[test]
    fn un_adjunto_pgp_keys_se_extrae_atribuido_al_from_en_binario() {
        let key = publica(&clave_completa("Ana <ana@example.com>"));
        // base64 y armadura de 7 bits: los dos llegan decodificados.
        let armada = String::from_utf8(key.to_armored_bytes(Default::default()).unwrap()).unwrap();
        for (que, parte) in [
            ("base64", adjunta(&key)),
            ("7bit armado", ("application/pgp-keys", "7bit", armada)),
        ] {
            let raw = correo_con_partes("Ana <ana@example.com>", "", &[parte]);
            let found = incoming_public_keys(&raw);
            assert_eq!(found.len(), 1, "{que}");
            assert_eq!(found[0].0, "ana@example.com", "{que}");
            // Lo extraído es una clave que `ingest_peer_key` entiende.
            let parsed = crate::pgp::parse_public_key(&found[0].1).expect(que);
            assert_eq!(huella(&parsed), huella(&key), "{que}");
        }
    }

    #[test]
    fn la_cabecera_autocrypt_se_extrae_con_su_addr_y_la_clave_binaria() {
        let key = publica(&clave_completa("Ana <ana@example.com>"));
        let raw = format!(
            "From: Ana <ana@example.com>\r\nAutocrypt: addr=ana@example.com; prefer-encrypt=mutual; keydata={}\r\n\
Content-Type: text/plain\r\n\r\nhola\r\n",
            b64(&bytes(&key))
        );
        let found = incoming_public_keys(raw.as_bytes());
        assert_eq!(found, vec![("ana@example.com".to_string(), bytes(&key))]);
    }

    #[test]
    fn un_correo_sin_claves_no_extrae_nada_ni_con_adjuntos_de_otro_tipo() {
        assert!(incoming_public_keys(b"From: a@b.test\r\n\r\nhola\r\n").is_empty());
        let raw = correo_con_partes(
            "a@b.test",
            "",
            &[
                ("text/plain", "7bit", "hola".into()),
                ("application/pdf", "base64", b64(b"%PDF")),
            ],
        );
        assert!(incoming_public_keys(&raw).is_empty());
    }

    #[test]
    fn un_correo_sin_from_no_siembra_claves_ni_por_adjunto_ni_por_autocrypt() {
        let key = publica(&clave_completa("Ana <ana@example.com>"));
        let sin_from = correo_con_partes("", "", &[adjunta(&key)]);
        assert!(incoming_public_keys(&sin_from).is_empty());
        // Sin remitente no hay contra qué cotejar el `addr` (Autocrypt L1): se ignora.
        let cabecera = format!(
            "Autocrypt: addr=ana@example.com; keydata={}\r\n",
            b64(&bytes(&key))
        );
        let con_autocrypt = correo_con_partes("", &cabecera, &[]);
        assert!(incoming_public_keys(&con_autocrypt).is_empty());
        // Control: con un `From` que coincide con el `addr`, la cabecera sí entra.
        let con_from = correo_con_partes("Ana <ana@example.com>", &cabecera, &[]);
        assert_eq!(incoming_public_keys(&con_from).len(), 1);
        // Y con un `From` ajeno, no.
        let ajeno = correo_con_partes("Mallory <mallory@example.com>", &cabecera, &[]);
        assert!(incoming_public_keys(&ajeno).is_empty());
    }

    #[test]
    fn un_adjunto_de_mas_de_un_mebibyte_se_ignora_y_uno_algo_menor_pasa() {
        // 7bit: el cuerpo llega tal cual. El margen de 16 bytes deja afuera el CRLF
        // que la frontera MIME agrega al cuerpo de la parte.
        let justo = "A".repeat(MIB - 16);
        let pasado = "A".repeat(MIB + 16);
        let raw = |cuerpo: &String| {
            correo_con_partes(
                "a@b.test",
                "",
                &[("application/pgp-keys", "7bit", cuerpo.clone())],
            )
        };
        assert_eq!(incoming_public_keys(&raw(&justo)).len(), 1, "bajo el tope");
        assert!(
            incoming_public_keys(&raw(&pasado)).is_empty(),
            "pasado el tope se ignora sin parsear ni entrar en pánico"
        );
        // En base64 el tope se mide sobre lo codificado: un blob que decodificado
        // cabe pero codificado se pasa tampoco entra.
        let codificado = b64(&vec![7u8; MIB]);
        assert!(codificado.len() > MIB);
        let grande = correo_con_partes(
            "a@b.test",
            "",
            &[("application/pgp-keys", "base64", codificado)],
        );
        assert!(incoming_public_keys(&grande).is_empty());
    }

    #[test]
    fn un_keydata_autocrypt_de_mas_de_128_kibibytes_se_ignora_y_uno_normal_pasa() {
        let normal = format!(
            "From: a@b.test\r\nAutocrypt: addr=a@b.test; keydata={}\r\n\r\nx",
            b64(&[1u8; 3000])
        );
        assert_eq!(incoming_public_keys(normal.as_bytes()).len(), 1);

        // Base64 válido pero de más de 128 KiB: no se decodifica ni se devuelve.
        let enorme = b64(&vec![1u8; KIB_128]);
        assert!(enorme.len() > KIB_128);
        let raw = format!("From: a@b.test\r\nAutocrypt: addr=a@b.test; keydata={enorme}\r\n\r\nx");
        assert!(incoming_public_keys(raw.as_bytes()).is_empty());
    }

    #[test]
    fn un_multipart_anidado_mas_alla_del_tope_de_profundidad_no_aporta_claves() {
        let key = publica(&clave_completa("Ana <ana@example.com>"));
        // Un adjunto de claves envuelto en `n` multiparts.
        let anidado = |n: usize| {
            let mut cuerpo = format!(
                "Content-Type: application/pgp-keys\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
                b64(&bytes(&key))
            );
            for nivel in (0..n).rev() {
                cuerpo = format!(
                    "Content-Type: multipart/mixed; boundary=\"N{nivel}\"\r\n\r\n--N{nivel}\r\n{cuerpo}--N{nivel}--\r\n"
                );
            }
            format!("From: ana@example.com\r\n{cuerpo}").into_bytes()
        };
        assert_eq!(incoming_public_keys(&anidado(2)).len(), 1, "poco profundo");
        assert!(
            incoming_public_keys(&anidado(8 + 3)).is_empty(),
            "más profundo que el tope se corta sin recursión sin fin"
        );
    }

    #[test]
    fn la_basura_en_los_adjuntos_y_cabeceras_no_entra_en_panico() {
        for raw in [
            &b""[..],
            b"\xff\xfe\x00From: \x01\r\n\r\n",
            b"From: a@b.test\r\nContent-Type: multipart/mixed\r\n\r\nsin frontera",
            b"From: a@b.test\r\nContent-Type: multipart/mixed; boundary=\"\"\r\n\r\n----\r\n",
            b"From: a@b.test\r\nAutocrypt: \r\n\r\n",
            b"From: a@b.test\r\nAutocrypt: addr=;keydata=;;;=\r\n\r\n",
        ] {
            let _ = incoming_public_keys(raw);
        }
        let basura = correo_con_partes(
            "a@b.test",
            "",
            &[("application/pgp-keys", "base64", "!!no es base64!!".into())],
        );
        // No hay pánico; lo que salga es sólo bytes que `ingest_peer_key` rechazará.
        for (_, blob) in incoming_public_keys(&basura) {
            assert!(parse_public_key(&blob).is_err());
        }
    }

    #[test]
    fn la_normalizacion_recorta_y_pasa_a_minusculas() {
        assert_eq!(normalize_address("  Ana@Example.COM \n"), "ana@example.com");
    }

    // ── Hallazgos de revisión (PR4): fusionar lo autenticado, topes y Autocrypt ──

    /// Una firma `SubkeyRevocation` de `firmante` sobre la subclave `index` de
    /// `objetivo`. Con `firmante` distinto del dueño, no verifica contra su primaria.
    fn revocacion_de_subclave(
        firmante: &SignedSecretKey,
        objetivo: &SignedPublicKey,
        index: usize,
    ) -> pgp::packet::Signature {
        SignatureConfig::from_key(
            OsRng,
            &firmante.primary_key,
            SignatureType::SubkeyRevocation,
        )
        .unwrap()
        .sign_subkey_binding(
            &firmante.primary_key,
            firmante.primary_key.public_key(),
            &vacia(),
            &objetivo.public_subkeys[index].key,
        )
        .expect("firma de revocación de subclave")
    }

    /// Si un cleartext firmado con la subclave de firma de `secret` (la 0) se reporta
    /// como firma de clave conocida contra `candidata`.
    fn firma_de_la_subclave_es_conocida(
        candidata: &SignedPublicKey,
        secret: &SignedSecretKey,
    ) -> bool {
        let bloque = crate::pgp::tests::cleartext_de("hola", &*secret.secret_subkeys[0]);
        let correo = format!("From: a@example.com\r\nContent-Type: text/plain\r\n\r\n{bloque}");
        matches!(
            crate::pgp::verify(correo.as_bytes(), std::slice::from_ref(candidata)),
            crate::pgp::Verification::SignedUntrusted(_)
        )
    }

    #[test]
    fn reingerir_la_misma_primaria_con_una_subclave_revocada_la_deja_de_aceptar_como_firmante() {
        let temp = TempDir::new("pgp-import-merge-revocacion-subclave");
        let store = open_store(&temp);
        let ana = clave_completa("Ana <ana@example.com>");
        let sana = publica(&ana);
        ingest_peer_key(&store, "ana@example.com", &bytes(&sana), 100).unwrap();
        // Premisa: antes de la revocación la subclave de firma cuenta como conocida.
        assert!(firma_de_la_subclave_es_conocida(
            &guardada(&store, "ana@example.com"),
            &ana
        ));

        let mut revocada = sana.clone();
        let revocacion = revocacion_de_subclave(&ana, &revocada, 0);
        revocada.public_subkeys[0].signatures.push(revocacion);
        let r = ingest_peer_key(&store, "ana@example.com", &bytes(&revocada), 200);
        assert_eq!(r.unwrap(), Ingested::Unchanged);

        let g = guardada(&store, "ana@example.com");
        assert!(
            !firma_de_la_subclave_es_conocida(&g, &ana),
            "la subclave revocada no puede seguir elevando a «clave conocida»"
        );
        // Lo demás sigue: misma huella, la subclave de cifrado sirve, primera vez intacta.
        assert!(encryption_subkey(&g).is_some());
        let peer = store.find_peer("ana@example.com").unwrap().unwrap();
        assert_eq!(peer.fingerprint, huella(&sana));
        assert_eq!((peer.first_seen, peer.updated_at), (100, 200));
    }

    #[test]
    fn una_revocacion_de_subclave_ya_guardada_no_se_pierde_con_un_blob_con_menos_material() {
        let temp = TempDir::new("pgp-import-merge-no-degrada");
        let store = open_store(&temp);
        let ana = clave_completa("Ana <ana@example.com>");
        let sana = publica(&ana);
        let mut revocada = sana.clone();
        let revocacion = revocacion_de_subclave(&ana, &revocada, 0);
        revocada.public_subkeys[0].signatures.push(revocacion);
        ingest_peer_key(&store, "ana@example.com", &bytes(&revocada), 100).unwrap();
        assert!(!firma_de_la_subclave_es_conocida(
            &guardada(&store, "ana@example.com"),
            &ana
        ));

        // Un blob viejo (sin la revocación) y uno sin subclaves no revierten ni quitan nada.
        let mut sin_subclaves = sana.clone();
        sin_subclaves.public_subkeys.clear();
        for (que, entrante) in [
            ("sin la revocación", sana.clone()),
            ("sin subclaves", sin_subclaves),
        ] {
            let r = ingest_peer_key(&store, "ana@example.com", &bytes(&entrante), 200);
            assert_eq!(r.unwrap(), Ingested::Unchanged, "{que}");
            let g = guardada(&store, "ana@example.com");
            assert_eq!(g.public_subkeys.len(), 2, "{que}: no se quitan subclaves");
            assert!(
                !firma_de_la_subclave_es_conocida(&g, &ana),
                "{que}: la revocación guardada se conserva"
            );
            assert!(encryption_subkey(&g).is_some(), "{que}");
        }
    }

    #[test]
    fn una_revocacion_forjada_en_una_reingesta_no_se_fusiona() {
        let temp = TempDir::new("pgp-import-merge-forjada");
        let store = open_store(&temp);
        let ana = clave_completa("Ana <ana@example.com>");
        let atacante = clave_completa("Atacante <atacante@example.com>");
        let sana = publica(&ana);
        ingest_peer_key(&store, "ana@example.com", &bytes(&sana), 100).unwrap();

        // El `From` spoofeado trae una revocación de la primaria hecha por el atacante:
        // no verifica contra la primaria guardada y no se fusiona.
        let mut forjada = sana.clone();
        forjada
            .details
            .revocation_signatures
            .push(revocacion(&atacante, &ana));
        ingest_peer_key(&store, "ana@example.com", &bytes(&forjada), 200).unwrap();
        let g = guardada(&store, "ana@example.com");
        assert!(g.details.revocation_signatures.is_empty());
        assert!(encryption_subkey(&g).is_some());

        // Y una revocación de subclave del atacante ni siquiera pasa el gate de bindings:
        // el blob entero se rechaza y lo guardado no cambia.
        let mut con_subclave_forjada = sana.clone();
        let sobre_subclave = revocacion_de_subclave(&atacante, &con_subclave_forjada, 0);
        con_subclave_forjada.public_subkeys[0]
            .signatures
            .push(sobre_subclave);
        let r = ingest_peer_key(
            &store,
            "ana@example.com",
            &bytes(&con_subclave_forjada),
            300,
        );
        assert!(es_error_de_clave(r));
        assert!(firma_de_la_subclave_es_conocida(
            &guardada(&store, "ana@example.com"),
            &ana
        ));
    }

    #[test]
    fn reingerir_la_misma_primaria_con_una_auto_revocacion_valida_inhabilita_la_guardada() {
        let temp = TempDir::new("pgp-import-merge-revocacion-primaria");
        let store = open_store(&temp);
        let ana = clave_completa("Ana <ana@example.com>");
        let sana = publica(&ana);
        ingest_peer_key(&store, "ana@example.com", &bytes(&sana), 100).unwrap();
        assert!(encryption_subkey(&guardada(&store, "ana@example.com")).is_some());

        let mut revocada = sana.clone();
        revocada
            .details
            .revocation_signatures
            .push(revocacion(&ana, &ana));
        let r = ingest_peer_key(&store, "ana@example.com", &bytes(&revocada), 200);
        assert_eq!(r.unwrap(), Ingested::Unchanged);

        let g = guardada(&store, "ana@example.com");
        assert_eq!(g.details.revocation_signatures.len(), 1);
        assert!(encryption_subkey(&g).is_none(), "la revocación se fusionó");
    }

    #[test]
    fn mas_de_16_partes_pgp_keys_se_cortan_en_16() {
        let key = publica(&clave_completa("Ana <ana@example.com>"));
        let con = |n: usize| {
            let partes: Vec<_> = (0..n).map(|_| adjunta(&key)).collect();
            incoming_public_keys(&correo_con_partes("Ana <ana@example.com>", "", &partes)).len()
        };
        assert_eq!(con(15), 15, "control: debajo del tope entran todas");
        assert_eq!(con(16), 16);
        assert_eq!(con(40), 16, "el resto se corta");
    }

    #[test]
    fn con_dos_cabeceras_autocrypt_validas_no_se_siembra_ninguna_clave() {
        let ana = publica(&clave_completa("Ana <ana@example.com>"));
        let otra = publica(&clave_completa("Ana <ana@example.com>"));
        let cabecera = |key: &SignedPublicKey, addr: &str| {
            format!("Autocrypt: addr={addr}; keydata={}\r\n", b64(&bytes(key)))
        };
        let from = "Ana <ana@example.com>";

        // Una sola válida: se siembra.
        let una = correo_con_partes(from, &cabecera(&ana, "ana@example.com"), &[]);
        assert_eq!(
            incoming_public_keys(&una),
            vec![("ana@example.com".to_string(), bytes(&ana))]
        );

        // Dos válidas (claves distintas, o la misma repetida): Autocrypt L1 manda
        // ignorarlas todas, ni siquiera la primera.
        for (que, extra) in [
            (
                "dos claves distintas",
                format!(
                    "{}{}",
                    cabecera(&ana, "ana@example.com"),
                    cabecera(&otra, "ana@example.com")
                ),
            ),
            (
                "la misma repetida",
                format!(
                    "{}{}",
                    cabecera(&ana, "ana@example.com"),
                    cabecera(&ana, "ana@example.com")
                ),
            ),
        ] {
            let raw = correo_con_partes(from, &extra, &[]);
            assert!(incoming_public_keys(&raw).is_empty(), "{que}");
        }

        // Una válida y otra con `addr` ajeno al `From` (inválida para este remitente):
        // sólo cuenta la válida, así que se siembra esa.
        let mixta = format!(
            "{}{}",
            cabecera(&otra, "otro@example.com"),
            cabecera(&ana, "ana@example.com")
        );
        assert_eq!(
            incoming_public_keys(&correo_con_partes(from, &mixta, &[])),
            vec![("ana@example.com".to_string(), bytes(&ana))]
        );
    }
}
