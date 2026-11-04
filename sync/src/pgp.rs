//! OpenPGP para el correo (vasak-accounts#21), con rPGP (crate `pgp`). Éste es el
//! **núcleo puro**: funciones sobre bytes y claves ya parseadas, sin D-Bus, sin
//! almacén y sin red. El wiring de sync entrante (PR4), la identidad D-Bus con
//! firma saliente (PR5), WKD (PR6) y el cifrado en compose (PR7) se construyen
//! encima de esto.
//!
//! Espeja a [`crate::smime_sign`] a propósito: los mismos estados
//! ([`Decryption`]/[`Verification`]), el mismo criterio de **fallar cerrado**
//! ante integridad rota, y la misma captura byte-exact de la parte firmada
//! reusando [`crate::message`] (`as_latin1`/`from_latin1`/`split_parts`), sin
//! reescribir el parser MIME.
//!
//! **Descifrar vs verificar no se confunden.** Descifrar sólo usa *nuestra* clave
//! privada y dice si el sobre se abrió; verificar necesita la clave *pública del
//! firmante* (la pasa el llamador desde el peerstate) y dice si la firma cierra.
//! Son dos operaciones distintas con dos estados distintos, igual que en S/MIME.
//!
//! **Fallar cerrado (la falla rPGP de 2019).** rPGP 0.21 comprueba la integridad
//! (SEIPD/MDC) **a medida que se lee** el contenido descifrado: si falla, la
//! lectura devuelve `Err`. Este módulo trata ese `Err` —y cualquier otro fallo de
//! descifrado— como [`Decryption::Unavailable`], **nunca** devuelve el texto
//! crudo y **nunca** confunde «descifrado» con «verificado». No hay ningún camino
//! de respaldo a `raw` ante un `Err` de descifrado.
//!
//! **Ligado al `From`.** `verify` devuelve la **huella** del firmante cuando la
//! firma cierra contra una de las claves candidatas, pero **no afirma confianza**
//! ni liga todavía esa identidad al `From` del mensaje (eso es PR4, igual que
//! S/MIME reserva «válido» para la validación de confianza X.509). Hasta
//! entonces, lo más que se dice es [`Verification::SignedUntrusted`] con la
//! huella, nunca «válido».

// PR1 es el núcleo puro: lo consumen el wiring de sync entrante (PR4) y la
// firma/cifrado salientes (PR5/PR7), que todavía no están. Hasta que lo llamen,
// el chequeo de código muerto lo marcaría entero; se saca al engancharlo.
#![allow(dead_code)]

use std::io::Read;

use pgp::composed::{
    CleartextSignedMessage, Deserializable, DetachedSignature, Message, MessageBuilder,
    SignedPublicKey, SignedPublicSubKey, SignedSecretKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::SignatureType;
use pgp::types::{KeyDetails, Password, Timestamp};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::message::{as_latin1, from_latin1, parse_content_type, split_headers, split_parts};

/// El `protocol` de un `multipart/encrypted` que es PGP/MIME (RFC 3156).
const PGP_ENCRYPTED_PROTOCOL: &str = "application/pgp-encrypted";
/// El `protocol` de un `multipart/signed` que es PGP/MIME (RFC 3156).
const PGP_SIGNATURE_PROTOCOL: &str = "application/pgp-signature";

const BEGIN_PGP_MESSAGE: &str = "-----BEGIN PGP MESSAGE-----";
const END_PGP_MESSAGE: &str = "-----END PGP MESSAGE-----";
const BEGIN_PGP_SIGNED: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
const END_PGP_SIGNATURE: &str = "-----END PGP SIGNATURE-----";

/// Tope del contenido descifrado **y descomprimido**, contra bombas de
/// compresión (zip/zlib). 64 MiB alcanza para un correo con adjuntos pesados y
/// corta en seco una bomba que se expande sin límite; pasarse es
/// [`Decryption::Unavailable`], nunca se materializa.
///
/// `shortcut: tope fijo de 64 MiB para el descifrado; upgrade si hiciera falta un
/// tope por configuración o por tipo de adjunto`.
const MAX_DECRYPTED: usize = 64 * 1024 * 1024;

// ── Estado expuesto a la ventana (calcado de smime_sign) ───────────────

/// El resultado de intentar descifrar un mensaje entrante.
#[derive(Debug)]
pub enum Decryption {
    /// No venía cifrado con PGP.
    NotEncrypted,
    /// Cifrado y abierto: el contenido descifrado (una entidad MIME, que puede
    /// venir firmada adentro —sign-then-encrypt—). Se borra al soltarlo.
    Opened(Zeroizing<Vec<u8>>),
    /// Cifrado pero no se pudo abrir: integridad rota (SEIPD/MDC), falta nuestra
    /// clave, cifrado no soportado, bomba de compresión, o el descifrado falló. El
    /// motivo es para el diario; a la ventana se le dice «cifrado, no se pudo
    /// abrir». **El resultado es uniforme** (todos los fallos caen acá) para no
    /// darle un oráculo a quien manda ciphertexts, y **nunca** se muestra crudo.
    Unavailable(String),
}

/// El resultado de verificar un mensaje entrante.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// No venía firmado con PGP.
    NotSigned,
    /// La firma criptográfica cerró contra una de las claves candidatas. Trae la
    /// **huella** del firmante. **No afirma confianza ni liga al `From`** (PR4):
    /// la ventana muestra «firmado por <huella>», nunca «válido».
    SignedUntrusted(String),
    /// Firmado, pero la firma no se pudo comprobar: rota, o el firmante es una
    /// clave desconocida (no está en el peerstate). El motivo es para el diario.
    Unverified(String),
}

/// Lo que puede salir mal al firmar o cifrar.
#[derive(Debug)]
pub enum PgpError {
    /// Nuestra clave no tiene ninguna componente capaz de firmar.
    NoSigningKey,
    /// No hay subclave de cifrado usable para un destinatario: sin subclave de
    /// cifrado, o expirada/revocada (se trata como sin clave). Nombra a la clave
    /// (huella), como `smime_send` nombra a quién le falta el certificado.
    NoEncryptionKey(String),
    /// Una clave no se pudo parsear.
    BadKey(String),
    /// La cripto falló.
    Crypto(String),
}

impl std::fmt::Display for PgpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PgpError::NoSigningKey => f.write_str("la clave PGP no puede firmar"),
            PgpError::NoEncryptionKey(who) => {
                write!(f, "no hay clave de cifrado PGP usable para {who}")
            }
            PgpError::BadKey(d) => write!(f, "la clave PGP no se pudo leer: {d}"),
            PgpError::Crypto(d) => write!(f, "la operación PGP falló: {d}"),
        }
    }
}

impl std::error::Error for PgpError {}

// ── Parseo de claves (armor o binario) ─────────────────────────────────

/// Parsea una clave **privada** PGP, armada (ASCII) o binaria. El ligado de la
/// UID al `From` y los rechazos honestos son PR3; acá sólo se interpreta el
/// material.
pub fn parse_secret_key(bytes: &[u8]) -> Result<SignedSecretKey, PgpError> {
    if looks_armored(bytes) {
        SignedSecretKey::from_armor_single(bytes).map(|(key, _)| key)
    } else {
        SignedSecretKey::from_bytes(bytes)
    }
    .map_err(|e| PgpError::BadKey(e.to_string()))
}

/// Parsea una clave **pública** PGP, armada (ASCII) o binaria. Para los adjuntos
/// `application/pgp-keys`, Autocrypt (PR3) y WKD (PR6).
pub fn parse_public_key(bytes: &[u8]) -> Result<SignedPublicKey, PgpError> {
    if looks_armored(bytes) {
        SignedPublicKey::from_armor_single(bytes).map(|(key, _)| key)
    } else {
        SignedPublicKey::from_bytes(bytes)
    }
    .map_err(|e| PgpError::BadKey(e.to_string()))
}

fn looks_armored(bytes: &[u8]) -> bool {
    bytes
        .windows(b"-----BEGIN".len())
        .any(|w| w == b"-----BEGIN")
}

// ── Descifrar ──────────────────────────────────────────────────────────

/// Si un mensaje es un sobre PGP cifrado (PGP/MIME `multipart/encrypted` o un
/// `-----BEGIN PGP MESSAGE-----` inline), sin intentar abrirlo. Para marcar
/// «cifrado, no se pudo abrir» cuando no tenemos la clave. Calca `is_enveloped`.
pub fn is_pgp_encrypted(raw: &[u8]) -> bool {
    encrypted_payload(raw).is_some()
}

/// Descifra un mensaje PGP entrante con **nuestra** clave privada y su
/// passphrase. Nunca entra en pánico sobre la entrada, y **falla cerrado**: una
/// vez que el mensaje dice ser cifrado, cualquier error cae en
/// [`Decryption::Unavailable`], nunca en texto crudo.
pub fn decrypt(raw: &[u8], secret_key: &SignedSecretKey, passphrase: &Password) -> Decryption {
    let Some(payload) = encrypted_payload(raw) else {
        return Decryption::NotEncrypted;
    };
    // A partir de acá el mensaje DICE ser cifrado: todo fallo es Unavailable.
    let message = match parse_message(&payload) {
        Ok(message) => message,
        Err(e) => return Decryption::Unavailable(format!("mensaje PGP ilegible: {e}")),
    };
    if !message.is_encrypted() {
        // Armaba un bloque PGP, pero no es un sobre cifrado (p. ej. sólo
        // comprimido o firmado): no lo mostramos como «descifrado».
        return Decryption::Unavailable("el bloque PGP no es un sobre cifrado".into());
    }

    let decrypted = match message.decrypt(passphrase, secret_key) {
        Ok(decrypted) => decrypted,
        Err(e) => return Decryption::Unavailable(format!("no se pudo descifrar: {e}")),
    };
    // Un sobre PGP suele descifrar a un paquete comprimido (o firmado sobre uno):
    // descomprimir es el idioma de rPGP antes de leer. No-op si no venía comprimido.
    let mut decrypted = match decrypted.decompress() {
        Ok(decrypted) => decrypted,
        Err(e) => return Decryption::Unavailable(format!("descompresión: {e}")),
    };

    match read_capped(&mut decrypted, MAX_DECRYPTED) {
        Ok(data) => Decryption::Opened(Zeroizing::new(data)),
        Err(e) => Decryption::Unavailable(e),
    }
}

/// Lee hasta el final con un tope, que es lo que **dispara la comprobación de
/// integridad** (MDC/SEIPD) del lector de rPGP: si la integridad falla, la
/// lectura devuelve `Err` y cae en `Unavailable` (fallar cerrado). El tope es
/// contra bombas de compresión: se lee `cap + 1` para distinguir «justo en el
/// tope» de «se pasó», y pasarse es un error.
fn read_capped(reader: &mut impl Read, cap: usize) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    reader
        .take(cap as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|e| format!("lectura del contenido descifrado: {e}"))?;
    if data.len() > cap {
        return Err("el contenido descomprimido supera el tope (posible bomba)".into());
    }
    Ok(data)
}

/// Los bytes del mensaje OpenPGP (armado o binario) de un correo cifrado, o
/// `None` si no es un sobre PGP. Soporta PGP/MIME (`multipart/encrypted`) e inline
/// (`-----BEGIN PGP MESSAGE-----`).
fn encrypted_payload(raw: &[u8]) -> Option<Vec<u8>> {
    let view = as_latin1(raw);
    let (headers, body) = split_headers(&view);
    let content_type = headers
        .get("content-type")
        .map(parse_content_type)
        .unwrap_or_default();

    if content_type.media_type == "multipart/encrypted"
        && content_type.protocol.as_deref() == Some(PGP_ENCRYPTED_PROTOCOL)
    {
        let boundary = content_type.boundary.as_deref()?;
        let parts = split_parts(body, boundary);
        // RFC 3156: la 2ª parte (`application/octet-stream`) trae el sobre armado.
        // Se elige por tipo; si no se deja identificar, la última parte.
        let payload_part = parts
            .iter()
            .find(|part| part_media_type(part) == "application/octet-stream")
            .or_else(|| parts.last())?;
        let (_part_headers, part_body) = split_headers(payload_part);
        return Some(from_latin1(part_body));
    }

    // Inline: un bloque `-----BEGIN PGP MESSAGE-----` dentro del cuerpo.
    extract_armor_block(&view, BEGIN_PGP_MESSAGE, END_PGP_MESSAGE).map(|block| from_latin1(&block))
}

/// Parsea un mensaje OpenPGP, detectando solo si es armado o binario.
fn parse_message(bytes: &[u8]) -> Result<Message<'_>, String> {
    Message::from_reader(bytes)
        .map(|(message, _headers)| message)
        .map_err(|e| e.to_string())
}

// ── Verificar ──────────────────────────────────────────────────────────

/// Verifica un mensaje PGP entrante contra las claves públicas candidatas (el
/// peerstate que arma el llamador). `raw` es el RFC822 crudo: la firma va sobre
/// los **bytes exactos** de la parte firmada, no sobre el cuerpo decodificado.
/// Soporta PGP/MIME (`multipart/signed`) e inline (cleartext firmado).
pub fn verify(raw: &[u8], candidate_keys: &[SignedPublicKey]) -> Verification {
    let view = as_latin1(raw);
    let (headers, body) = split_headers(&view);
    let content_type = headers
        .get("content-type")
        .map(parse_content_type)
        .unwrap_or_default();

    if content_type.media_type == "multipart/signed" {
        // El `protocol` tiene que ser el de PGP. Un `multipart/signed` de S/MIME
        // (`application/pkcs7-signature`) no es nuestro: `NotSigned`, para no
        // mostrarlo como «PGP firmado».
        if content_type.protocol.as_deref() != Some(PGP_SIGNATURE_PROTOCOL) {
            return Verification::NotSigned;
        }
        let Some(boundary) = content_type.boundary.as_deref() else {
            return Verification::Unverified("multipart/signed sin frontera".into());
        };
        let parts = split_parts(body, boundary);
        // RFC 1847: `multipart/signed` son **exactamente** dos partes (contenido y
        // firma). Con más, la vista podría mostrar una parte que la firma no cubre.
        if parts.len() != 2 {
            return Verification::Unverified(
                "multipart/signed no tiene exactamente dos partes".into(),
            );
        }
        // El contenido firmado, sin el CRLF que pertenece a la frontera (RFC 3156).
        let signed_content = strip_one_trailing_crlf(from_latin1(parts[0]));
        let Some(signature) = parse_detached_signature(parts[1]) else {
            return Verification::Unverified("firma pgp ilegible".into());
        };
        return verify_detached(&signature, &signed_content, candidate_keys);
    }

    // Inline: un cleartext firmado (`-----BEGIN PGP SIGNED MESSAGE-----`).
    if let Some(block) = extract_armor_block(&view, BEGIN_PGP_SIGNED, END_PGP_SIGNATURE) {
        return verify_cleartext(&block, candidate_keys);
    }

    Verification::NotSigned
}

/// La firma separada de la parte `application/pgp-signature` (armada o binaria).
fn parse_detached_signature(part: &str) -> Option<DetachedSignature> {
    let (_part_headers, body) = split_headers(part);
    let bytes = from_latin1(body);
    DetachedSignature::from_armor_single(bytes.as_slice())
        .map(|(signature, _)| signature)
        .or_else(|_| DetachedSignature::from_bytes(bytes.as_slice()))
        .ok()
}

/// Prueba la firma separada contra cada componente (clave primaria y subclaves)
/// de cada candidata. La primaria **no siempre** es la de verificación (lo avisa
/// rPGP), así que se prueban todas y gana la que cierre. Se devuelve la huella de
/// la clave **primaria** de la candidata que verificó: es la identidad del
/// firmante (ligarla al `From` es PR4).
fn verify_detached(
    signature: &DetachedSignature,
    content: &[u8],
    candidate_keys: &[SignedPublicKey],
) -> Verification {
    for key in candidate_keys {
        if signature.verify(&key.primary_key, content).is_ok() {
            return Verification::SignedUntrusted(key.primary_key.fingerprint().to_string());
        }
        for subkey in &key.public_subkeys {
            if signature.verify(subkey, content).is_ok() {
                return Verification::SignedUntrusted(key.primary_key.fingerprint().to_string());
            }
        }
    }
    unknown_signer(candidate_keys)
}

/// Verifica un cleartext firmado inline contra las claves candidatas.
fn verify_cleartext(block: &str, candidate_keys: &[SignedPublicKey]) -> Verification {
    let message = match CleartextSignedMessage::from_string(block) {
        Ok((message, _headers)) => message,
        Err(e) => return Verification::Unverified(format!("cleartext PGP ilegible: {e}")),
    };
    for key in candidate_keys {
        if message.verify(&key.primary_key).is_ok() {
            return Verification::SignedUntrusted(key.primary_key.fingerprint().to_string());
        }
        for subkey in &key.public_subkeys {
            if message.verify(subkey).is_ok() {
                return Verification::SignedUntrusted(key.primary_key.fingerprint().to_string());
            }
        }
    }
    unknown_signer(candidate_keys)
}

fn unknown_signer(candidate_keys: &[SignedPublicKey]) -> Verification {
    if candidate_keys.is_empty() {
        Verification::Unverified("firmado, la clave del firmante es desconocida".into())
    } else {
        Verification::Unverified("la firma no cierra contra ninguna clave conocida".into())
    }
}

// ── Firmar ─────────────────────────────────────────────────────────────

/// Firma `content` (los bytes exactos de la entidad de contenido) con nuestra
/// clave y devuelve la firma separada **armada**, lista para la parte
/// `application/pgp-signature` de un `multipart/signed`. Elige la componente de
/// firma correcta (subclave de firma válida, o la primaria si puede firmar),
/// nunca una subclave sólo de cifrado.
pub fn sign_detached(
    content: &[u8],
    secret_key: &SignedSecretKey,
    passphrase: &Password,
) -> Result<Vec<u8>, PgpError> {
    let now = Timestamp::now().as_secs();
    let signature = match signing_component(secret_key, now) {
        Some(Signer::Subkey(index)) => DetachedSignature::sign_binary_data(
            OsRng,
            &*secret_key.secret_subkeys[index],
            passphrase,
            HashAlgorithm::Sha256,
            content,
        ),
        Some(Signer::Primary) => DetachedSignature::sign_binary_data(
            OsRng,
            &secret_key.primary_key,
            passphrase,
            HashAlgorithm::Sha256,
            content,
        ),
        None => return Err(PgpError::NoSigningKey),
    }
    .map_err(|e| PgpError::Crypto(e.to_string()))?;

    signature
        .to_armored_bytes(Default::default())
        .map_err(|e| PgpError::Crypto(e.to_string()))
}

/// Qué componente de la clave firma.
enum Signer {
    Primary,
    Subkey(usize),
}

/// Elige la componente de firma: una subclave de firma usable, o la primaria si
/// puede firmar. Las subclaves expiradas o revocadas se saltan.
fn signing_component(key: &SignedSecretKey, now: u32) -> Option<Signer> {
    for (index, subkey) in key.secret_subkeys.iter().enumerate() {
        if subkey_usable(&subkey.signed_public_key(), now, Usage::Sign) {
            return Some(Signer::Subkey(index));
        }
    }
    if primary_can_sign(key) {
        return Some(Signer::Primary);
    }
    None
}

/// La primaria puede firmar si su algoritmo lo permite. (Las flags de la primaria
/// viven en sus auto-firmas de UID; para firmar con la propia clave alcanza con
/// la capacidad del algoritmo. El ligado estricto de flags es PR3.)
fn primary_can_sign(key: &SignedSecretKey) -> bool {
    key.primary_key.algorithm().can_sign()
}

// ── Cifrar ─────────────────────────────────────────────────────────────

/// Cifra `plaintext` a las claves de los destinatarios (que **deben incluir la
/// nuestra**, o el saliente queda ilegible en Enviados). Devuelve el mensaje
/// OpenPGP **armado**, listo para la 2ª parte de un `multipart/encrypted`.
///
/// Elige la **subclave de cifrado** válida de cada destinatario, nunca la
/// primaria. Si a algún destinatario le falta una clave de cifrado usable
/// (expirada o revocada se trata como sin clave), **falla claro** nombrando a esa
/// clave y **no cifra a medias**: calca el molde de la firma saliente de S/MIME
/// («pedir sin clave falla, no manda a medias»).
pub fn encrypt_to_keys(
    plaintext: &[u8],
    recipient_keys: &[SignedPublicKey],
) -> Result<Vec<u8>, PgpError> {
    if recipient_keys.is_empty() {
        return Err(PgpError::NoEncryptionKey("sin destinatarios".into()));
    }

    let mut rng = OsRng;
    let mut builder = MessageBuilder::from_bytes("", plaintext.to_vec())
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);

    for key in recipient_keys {
        let subkey =
            encryption_subkey(key).ok_or_else(|| PgpError::NoEncryptionKey(key_identity(key)))?;
        builder
            .encrypt_to_key(&mut rng, subkey)
            .map_err(|e| PgpError::Crypto(e.to_string()))?;
    }

    builder
        .to_armored_string(&mut rng, Default::default())
        .map(String::into_bytes)
        .map_err(|e| PgpError::Crypto(e.to_string()))
}

/// La subclave de cifrado usable de una clave pública, o `None` si no hay (sin
/// subclave de cifrado, o todas expiradas/revocadas). **Nunca** la primaria. Es
/// pública para que el llamador (compose, PR7) gatee la UI por destinatario y
/// produzca el error «a quién le falta la clave» con la dirección.
pub fn encryption_subkey(key: &SignedPublicKey) -> Option<&SignedPublicSubKey> {
    let now = Timestamp::now().as_secs();
    key.public_subkeys
        .iter()
        .find(|subkey| subkey_usable(subkey, now, Usage::Encrypt))
}

/// Para qué se busca una subclave.
#[derive(Clone, Copy)]
enum Usage {
    Encrypt,
    Sign,
}

/// Si una subclave sirve para `usage`: no revocada, no expirada, y con la
/// capacidad pedida. Una clave **expirada o revocada se trata como sin clave**
/// (no se cifra ni se firma con una clave muerta).
///
/// La capacidad sale de las *key flags* de la binding más reciente; si la binding
/// no trae flags, manda la capacidad del algoritmo. Si trae flags, se respetan
/// **estrictamente** (una subclave marcada sólo de cifrado no firma, aunque su
/// algoritmo pudiera).
fn subkey_usable(subkey: &SignedPublicSubKey, now: u32, usage: Usage) -> bool {
    // Revocada → muerta. (La revocación se toma por presencia; verificar su firma
    // es parte del gate de import, PR3.)
    if subkey
        .signatures
        .iter()
        .any(|sig| sig.typ() == Some(SignatureType::SubkeyRevocation))
    {
        return false;
    }

    let Some(binding) = subkey
        .signatures
        .iter()
        .filter(|sig| sig.typ() == Some(SignatureType::SubkeyBinding))
        .max_by_key(|sig| sig.created().map(|t| t.as_secs()).unwrap_or(0))
    else {
        return false;
    };

    // Expirada → muerta. El vencimiento es relativo a la creación de la subclave.
    if let Some(expiration) = binding.key_expiration_time() {
        let created = subkey.created_at().as_secs();
        if created.saturating_add(expiration.as_secs()) < now {
            return false;
        }
    }

    let flags = binding.key_flags();
    let any_flag =
        flags.certify() || flags.sign() || flags.encrypt_comms() || flags.encrypt_storage();
    if any_flag {
        return match usage {
            Usage::Encrypt => flags.encrypt_comms() || flags.encrypt_storage(),
            Usage::Sign => flags.sign(),
        };
    }

    // Sin flags en la binding: el algoritmo manda.
    match usage {
        Usage::Encrypt => subkey.algorithm().can_encrypt(),
        Usage::Sign => subkey.algorithm().can_sign(),
    }
}

/// Un identificador de una clave para los mensajes de error (la huella de la
/// primaria). La dirección del destinatario la conoce el llamador (compose).
fn key_identity(key: &SignedPublicKey) -> String {
    key.primary_key.fingerprint().to_string()
}

// ── Ayudas de bytes (calcadas de smime_sign) ───────────────────────────

/// El tipo de medio (en minúsculas) de una parte MIME.
fn part_media_type(part: &str) -> String {
    let (headers, _body) = split_headers(part);
    headers
        .get("content-type")
        .map(parse_content_type)
        .unwrap_or_default()
        .media_type
}

/// Extrae un bloque de armor PGP (`begin`..`end`, inclusive) de un texto, o
/// `None` si no está entero. Los marcadores son ASCII, así que buscarlos en la
/// vista latin-1 no pierde nada.
fn extract_armor_block(view: &str, begin: &str, end: &str) -> Option<String> {
    let start = view.find(begin)?;
    let end_at = view[start..].find(end)? + start + end.len();
    Some(view[start..end_at].to_string())
}

fn strip_one_trailing_crlf(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.ends_with(b"\r\n") {
        bytes.truncate(bytes.len() - 2);
    } else if bytes.ends_with(b"\n") {
        bytes.truncate(bytes.len() - 1);
    }
    bytes
}
