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
//! **Fallar cerrado (la falla rPGP de 2019).** Para SEIPD v1 —el camino por
//! defecto— rPGP 0.21 corre en modo `CheckFirst`: lee y verifica el contenido
//! descifrado **entero antes** de soltar un solo byte de texto, y si la integridad
//! (SEIPD/MDC) falla devuelve `Err` sin materializar nada. El «a medida que se lee»
//! vale sólo para AEAD (SEIPD v2), donde cada chunk se autentica al leerlo. En los
//! dos casos este módulo trata ese `Err` —y cualquier otro fallo de descifrado—
//! como [`Decryption::Unavailable`], **nunca** devuelve el texto crudo y **nunca**
//! confunde «descifrado» con «verificado». No hay ningún camino de respaldo a `raw`
//! ante un `Err` de descifrado. El techo de bufferización de `CheckFirst` se iguala
//! a `MAX_DECRYPTED` en [`decrypt`], no lo acota [`read_capped`].
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
    CleartextSignedMessage, DecryptionOptions, Deserializable, DetachedSignature, Esk, Message,
    MessageBuilder, SignedPublicKey, SignedPublicSubKey, SignedSecretKey, TheRing,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::SignatureType;
use pgp::types::{KeyDetails, Password, Seipdv1ReadMode, Tag, Timestamp};
use rand::rngs::OsRng;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::message::{
    as_latin1, decode_transfer, from_latin1, parse_content_type, split_headers, split_parts,
};

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

/// Tope de capas de compresión anidadas al descifrar (un paquete comprimido dentro
/// de otro). Un mensaje legítimo lleva una sola; más allá de esto es una bomba de
/// capas y se trata como [`Decryption::Unavailable`], nunca se materializa.
const MAX_COMPRESSION_LAYERS: u32 = 4;

/// Tope de PKESK **dirigidos a nuestra clave** (o wildcard) en un sobre. Sólo esos
/// disparan una operación de clave privada en `decrypt_the_ring`; un mensaje legítimo
/// trae uno (unos pocos si tenemos varias subclaves de descifrado). Miles es una bomba
/// de CPU que bloquearía la task async (el descifrado corre síncrono en ella): se corta
/// **antes** de intentar descifrar. No cuenta los PKESK de otros destinatarios (no nos
/// matchean y rPGP los saltea barato), así que un cifrado a mucha gente no se penaliza.
const MAX_TARGETED_PKESK: usize = 16;

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

// ── Estado que viaja a la ventana (por `GetMessage`, calcado de smime_sign) ──

/// El estado OpenPGP de un mensaje, como lo ve quien lo lee. `None` (el campo
/// entero) quiere decir que no venía ni firmado ni cifrado con PGP. Espeja a
/// [`crate::smime_sign::SmimeStatus`] y mantiene la **misma honestidad**: nunca se
/// afirma «firmado por Fulano» con tilde verde; a lo sumo «firmado con una clave
/// conocida» (TOFU). La verificación explícita por huella queda fuera de v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PgpStatus {
    /// Estado de la firma, o `None` si no venía firmado. Ver [`SignatureState`].
    pub signature: Option<SignatureState>,
    /// La **huella** del firmante **sólo** cuando la firma cerró contra la clave
    /// **conocida** del `From` ([`SignatureState::Known`]); `None` en los demás
    /// casos. Igual que S/MIME, no se nombra a un firmante que no liga.
    pub signer: Option<String>,
    /// Estado de cifrado, o `None` si no venía cifrado. Ver [`Encryption`].
    pub encryption: Option<Encryption>,
}

/// Cómo quedó la **firma** de un mensaje entrante, con la confianza TOFU del
/// peerstate. Nunca «válido» en el sentido fuerte (verificación por huella fuera
/// de banda): eso es follow-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureState {
    /// La firma cerró contra la clave **conocida** del `From` (su huella está en el
    /// peerstate, TOFU). Lo más alto que se afirma en v1.
    Known,
    /// Firmado, pero **no teníamos ninguna clave** para ese `From` (primer contacto
    /// sin clave adjunta ni Autocrypt): no se puede comprobar quién firmó.
    Unknown,
    /// Firmado, teníamos una clave para el `From`, pero la firma **no cierra** contra
    /// ella (rota, o firmada por otra clave): no verificable.
    Unverifiable,
}

/// Cómo quedó un mensaje **cifrado** después de intentar abrirlo al bajarlo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Encryption {
    /// Cifrado y abierto: el cuerpo que se muestra es el descifrado.
    Opened,
    /// Cifrado pero no se pudo abrir (sin nuestra clave, integridad rota, cifrado no
    /// soportado). El cuerpo no está disponible; nunca «roto».
    Unavailable,
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
    // Binario primero: una clave binaria puede llevar `-----BEGIN` dentro de un UID
    // y no por eso es armadura. El parser binario rechaza enseguida la armadura
    // real (su primer byte, `-`, no es un encabezado de paquete válido), así que se
    // cae al parser armor sin riesgo de interpretar mal.
    SignedSecretKey::from_bytes(bytes)
        .or_else(|_| SignedSecretKey::from_armor_single(bytes).map(|(key, _)| key))
        .map_err(|e| PgpError::BadKey(e.to_string()))
}

/// Parsea una clave **pública** PGP, armada (ASCII) o binaria. Para los adjuntos
/// `application/pgp-keys`, Autocrypt (PR3) y WKD (PR6).
pub fn parse_public_key(bytes: &[u8]) -> Result<SignedPublicKey, PgpError> {
    // Binario primero (ver `parse_secret_key`): una clave binaria con `-----BEGIN`
    // en un UID no es armadura.
    SignedPublicKey::from_bytes(bytes)
        .or_else(|_| SignedPublicKey::from_armor_single(bytes).map(|(key, _)| key))
        .map_err(|e| PgpError::BadKey(e.to_string()))
}

// ── Descifrar ──────────────────────────────────────────────────────────

/// Si un mensaje es un sobre PGP cifrado (PGP/MIME `multipart/encrypted` o un
/// `-----BEGIN PGP MESSAGE-----` inline), sin intentar abrirlo. Para marcar
/// «cifrado, no se pudo abrir» cuando no tenemos la clave. Calca `is_enveloped`.
pub fn is_pgp_encrypted(raw: &[u8]) -> bool {
    encrypted_payload(raw).is_some()
}

/// La región donde buscar una armadura firmada inline, compartida por [`verify`] e
/// [`is_pgp_signed`] para que detecten **lo mismo**: la armadura **pelada** (todo el
/// contenido, cuando empieza por el marcador —el interior de un sign-then-encrypt sin
/// cabeceras MIME, que `split_headers` mal-parsea) o, si no, el **cuerpo propio**
/// (post-cabeceras). Escanear el raw entero marcaría como firmado un mail que sólo CITA
/// un bloque (en el cuerpo o en una cabecera).
fn inline_signed_region<'a>(view: &'a str, body: &'a str) -> &'a str {
    let trimmed = view.trim_start();
    if trimmed.starts_with(BEGIN_PGP_SIGNED) {
        trimmed
    } else {
        body
    }
}

/// Si un mensaje trae una firma PGP (PGP/MIME `multipart/signed` con el protocolo
/// de PGP, o un cleartext firmado inline), **sin** verificarla. Barato: decide si
/// vale la pena resolver el peerstate del firmante en el camino de sync. Usa la misma
/// región que [`verify`] ([`inline_signed_region`]), así no señala «firmado» un bloque
/// que `verify` después trataría como no firmado.
pub fn is_pgp_signed(raw: &[u8]) -> bool {
    let view = as_latin1(raw);
    let (headers, body) = split_headers(&view);
    let content_type = headers
        .get("content-type")
        .map(parse_content_type)
        .unwrap_or_default();
    if content_type.media_type == "multipart/signed"
        && content_type.protocol.as_deref() == Some(PGP_SIGNATURE_PROTOCOL)
    {
        return true;
    }
    extract_armor_block(
        inline_signed_region(&view, body),
        BEGIN_PGP_SIGNED,
        END_PGP_SIGNATURE,
    )
    .is_some()
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

    // Antes de descifrar (síncrono en la task async), se cortan los sobres con una
    // cantidad abusiva de PKESK dirigidos a nuestra clave: cada uno es un intento de
    // clave privada y, sin cota, un mail cargado con miles bloquea la task.
    if let Message::Encrypted { esk, .. } = &message {
        let targeted = esk
            .iter()
            .filter_map(|e| match e {
                Esk::PublicKeyEncryptedSessionKey(k) => Some(k),
                _ => None,
            })
            .filter(|k| {
                k.match_identity(secret_key.primary_key.public_key())
                    || secret_key
                        .secret_subkeys
                        .iter()
                        .any(|sub| k.match_identity(sub.public_key()))
            })
            .count();
        if targeted > MAX_TARGETED_PKESK {
            return Decryption::Unavailable("demasiados PKESK dirigidos a la clave".into());
        }
    }

    // Para SEIPD v1, rPGP corre en modo `CheckFirst`, que bufferiza en RAM el
    // contenido descifrado entero antes de verificarlo y soltarlo; su techo por
    // defecto es 1 GiB. Se iguala a `MAX_DECRYPTED` para que esa bufferización no
    // pueda exceder el mismo tope que el contenido descomprimido. `legacy:false`
    // (el default) se mantiene: no habilitar SED sin MDC (vector EFAIL).
    let ring = TheRing {
        secret_keys: vec![secret_key],
        key_passwords: vec![passphrase],
        decrypt_options: DecryptionOptions::new().set_seipdv1_read_mode(
            Seipdv1ReadMode::CheckFirst {
                max_message_size: MAX_DECRYPTED,
            },
        ),
        ..Default::default()
    };
    let decrypted = match message.decrypt_the_ring(ring, true) {
        Ok((decrypted, _)) => decrypted,
        Err(e) => return Decryption::Unavailable(format!("no se pudo descifrar: {e}")),
    };
    // Un sobre PGP suele descifrar a un paquete comprimido (o firmado sobre uno):
    // descomprimir es el idioma de rPGP antes de leer. La primera pasada corre
    // siempre (es no-op si no venía comprimido, y descomprime también el flujo de un
    // mensaje firmado). Se repite mientras quede OTRO paquete comprimido anidado: sin
    // el loop, `read_capped` soltaría los bytes crudos del paquete interno como si
    // fueran el claro. La profundidad se acota contra una bomba de capas.
    let mut decrypted = decrypted;
    for layer in 0..MAX_COMPRESSION_LAYERS {
        if layer > 0 && !decrypted.is_compressed() {
            break;
        }
        decrypted = match decrypted.decompress() {
            Ok(decrypted) => decrypted,
            Err(e) => return Decryption::Unavailable(format!("descompresión: {e}")),
        };
    }
    if decrypted.is_compressed() {
        return Decryption::Unavailable("demasiadas capas de compresión anidadas".into());
    }

    match read_capped(&mut decrypted, MAX_DECRYPTED) {
        Ok(data) => Decryption::Opened(Zeroizing::new(data)),
        Err(e) => Decryption::Unavailable(e),
    }
}

/// Lee hasta el final con un tope **contra bombas de compresión**: se lee `cap + 1`
/// para distinguir «justo en el tope» de «se pasó», y pasarse es un error.
///
/// El tope **no** acota la memoria que usa rPGP al descifrar: para SEIPD v1 en
/// `CheckFirst` rPGP ya bufferizó y verificó el contenido entero antes de que este
/// lector vea un byte (ese techo es `max_message_size`, que [`decrypt`] iguala a
/// `MAX_DECRYPTED`). Para AEAD (SEIPD v2) la integridad de cada chunk se comprueba
/// **a medida que se lee**, así que acá sí puede llegar un `Err` de integridad, que
/// cae en `Unavailable` (fallar cerrado).
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
        let (part_headers, part_body) = split_headers(payload_part);
        // Se aplica el `Content-Transfer-Encoding` de la parte antes de parsear: si el
        // sobre viene en base64, pasarle base64 a rPGP lo deja ilegible y el mail se
        // guarda como no disponible con cuerpo vacío. Igual que `parse_detached_signature`.
        let encoding = part_headers
            .get("content-transfer-encoding")
            .unwrap_or("7bit");
        return Some(decode_transfer(&from_latin1(part_body), encoding));
    }

    // Inline: un bloque `-----BEGIN PGP MESSAGE-----`. Se escanea el **cuerpo propio**
    // (no el raw entero) y se exige que el bloque sea todo el cuerpo: un mail que sólo
    // CITA un bloque armado (p. ej. una respuesta) no es un sobre cifrado y no debe
    // vaciarse. shortcut: un inline legítimo con texto alrededor del bloque se trata
    // como no cifrado (se muestra la armadura); subir a un walk del árbol MIME si hace falta.
    let block = extract_armor_block(body, BEGIN_PGP_MESSAGE, END_PGP_MESSAGE)?;
    let (before, after) = body.split_once(block.as_str())?;
    if !before.trim().is_empty() || !after.trim().is_empty() {
        return None;
    }
    Some(from_latin1(&block))
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

    // Inline: un cleartext firmado (`-----BEGIN PGP SIGNED MESSAGE-----`). Se escanea el
    // cuerpo propio (o la armadura pelada), no el raw: ver [`inline_signed_region`].
    let scan = inline_signed_region(&view, body);
    if let Some(block) = extract_armor_block(scan, BEGIN_PGP_SIGNED, END_PGP_SIGNATURE) {
        // La firma inline sólo cubre su bloque, pero la vista muestra todo el cuerpo:
        // si hay texto fuera del bloque (antes o después), un atacante lo anteponría a
        // un bloque firmado real y aparecería como «firmado». Se exige que el bloque
        // sea todo el cuerpo; si no, no se marca firmado.
        let (before, after) = scan.split_once(block.as_str()).unwrap_or(("x", "x"));
        if !before.trim().is_empty() || !after.trim().is_empty() {
            return Verification::Unverified(
                "hay contenido fuera del bloque firmado inline".into(),
            );
        }
        // El bloque viene de la vista latin-1: se reconstruyen los bytes originales y
        // se interpretan como UTF-8 antes de verificar. Sin esto, para contenido UTF-8
        // no-ASCII rPGP hashea bytes distintos a los que firmó el emisor y una firma
        // válida se guarda como no verificable.
        let block = String::from_utf8_lossy(&from_latin1(&block)).into_owned();
        return verify_cleartext(&block, candidate_keys);
    }

    Verification::NotSigned
}

/// La firma separada de la parte `application/pgp-signature` (armada o binaria).
fn parse_detached_signature(part: &str) -> Option<DetachedSignature> {
    let (part_headers, body) = split_headers(part);
    // Se aplica el `Content-Transfer-Encoding` de la parte antes de parsear: una
    // firma en base64 no es armadura ni paquete crudo hasta decodificarla. Sin
    // header (o `7bit`/`8bit`/`binary`), `decode_transfer` deja los bytes tal cual.
    let encoding = part_headers
        .get("content-transfer-encoding")
        .unwrap_or("7bit");
    let bytes = decode_transfer(&from_latin1(body), encoding);
    DetachedSignature::from_armor_single(bytes.as_slice())
        .map(|(signature, _)| signature)
        .or_else(|_| DetachedSignature::from_bytes(bytes.as_slice()))
        .ok()
}

/// Prueba la firma separada contra cada componente (clave primaria y subclaves)
/// de cada candidata. La primaria **no siempre** es la de verificación (lo avisa
/// rPGP), así que se prueban todas y gana la que cierre. Se devuelve la huella de
/// la clave **primaria** de la candidata que verificó: es la identidad del
/// firmante (ligada al `From` por el llamador, que pasa como candidatas sólo las
/// claves del peerstate de ese `From`).
///
/// **Sólo se acepta un componente de firma usable** (el follow-up de la revisión de
/// PR1): la primaria viva (no revocada/expirada) y con algoritmo de firma, o una
/// subclave de firma con su flag de firma, binding vigente y no revocada/expirada
/// ([`subkey_usable`]). Así no se eleva a «clave conocida» una firma hecha con una
/// subclave muerta o sin capacidad de firma.
fn verify_detached(
    signature: &DetachedSignature,
    content: &[u8],
    candidate_keys: &[SignedPublicKey],
) -> Verification {
    let now = Timestamp::now().as_secs();
    for key in candidate_keys {
        // Primaria muerta (revocada/expirada) → la clave entera no liga identidad: no
        // se acepta una firma de subclave bajo una primaria revocada (mostraría la
        // identidad revocada como firmante). Mismo gate que `encryption_subkey`.
        if !primary_usable(key, now) {
            continue;
        }
        if primary_signing_usable(key, now) && signature.verify(&key.primary_key, content).is_ok() {
            return Verification::SignedUntrusted(key.primary_key.fingerprint().to_string());
        }
        for subkey in &key.public_subkeys {
            if subkey_usable(subkey, now, Usage::Sign) && signature.verify(subkey, content).is_ok()
            {
                return Verification::SignedUntrusted(key.primary_key.fingerprint().to_string());
            }
        }
    }
    unknown_signer(candidate_keys)
}

/// Si la **primaria** de una clave pública sirve para firmar: viva (no
/// revocada/expirada, [`primary_usable`]) y con un algoritmo capaz de firmar. Es la
/// simétrica pública de [`signing_component`] para el camino de verificación.
fn primary_signing_usable(key: &SignedPublicKey, now: u32) -> bool {
    primary_usable(key, now) && key.primary_key.algorithm().can_sign()
}

/// Verifica un cleartext firmado inline contra las claves candidatas.
fn verify_cleartext(block: &str, candidate_keys: &[SignedPublicKey]) -> Verification {
    let message = match CleartextSignedMessage::from_string(block) {
        Ok((message, _headers)) => message,
        Err(e) => return Verification::Unverified(format!("cleartext PGP ilegible: {e}")),
    };
    let now = Timestamp::now().as_secs();
    for key in candidate_keys {
        // Primaria muerta (revocada/expirada) → la clave entera no liga identidad,
        // tampoco por una subclave bajo ella. Igual que en `verify_detached`.
        if !primary_usable(key, now) {
            continue;
        }
        if primary_signing_usable(key, now) && message.verify(&key.primary_key).is_ok() {
            return Verification::SignedUntrusted(key.primary_key.fingerprint().to_string());
        }
        for subkey in &key.public_subkeys {
            if subkey_usable(subkey, now, Usage::Sign) && message.verify(subkey).is_ok() {
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
    // Una primaria muerta (revocada o expirada) descarta la clave entera para
    // firmar, igual que para cifrar: no se firma con una subclave bajo una
    // identidad revocada, ni se cae a la primaria muerta aunque su algoritmo
    // pueda firmar. Es la simétrica del gate de `encryption_subkey`.
    // `to_public_key()` deriva la metadata pública soltando el material secreto,
    // sin clonar la clave privada entera.
    if !primary_usable(&key.to_public_key(), now) {
        return None;
    }
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

/// El resumen **público** de una identidad OpenPGP para mostrar su estado SIN
/// material secreto: la huella de la primaria y los correos de sus UIDs con
/// auto-firma válida y vigente. Reusa el mismo criterio que liga la identidad al
/// `From` ([`crate::pgp_import::self_signed_emails`]), así el resumen no muestra un
/// UID que no ligaría. Lo consume `GetPgpIdentity` sobre la clave pública derivada
/// de la guardada.
pub fn identity_summary(public: &SignedPublicKey) -> (String, Vec<String>) {
    let fingerprint = public.primary_key.fingerprint().to_string();
    let uids = crate::pgp_import::self_signed_emails(public);
    (fingerprint, uids)
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
        .to_armored_string(rng, Default::default())
        .map(String::into_bytes)
        .map_err(|e| PgpError::Crypto(e.to_string()))
}

/// La subclave de cifrado usable de una clave pública, o `None` si no hay (sin
/// subclave de cifrado, o todas expiradas/revocadas). **Nunca** la primaria. Es
/// pública para que el llamador (compose, PR7) gatee la UI por destinatario y
/// produzca el error «a quién le falta la clave» con la dirección.
pub fn encryption_subkey(key: &SignedPublicKey) -> Option<&SignedPublicSubKey> {
    let now = Timestamp::now().as_secs();
    // Una primaria muerta (revocada o expirada) descarta la clave entera, aunque
    // tenga una subclave de cifrado vigente: no se cifra a una identidad revocada.
    if !primary_usable(key, now) {
        return None;
    }
    key.public_subkeys
        .iter()
        .find(|subkey| subkey_usable(subkey, now, Usage::Encrypt))
}

/// Si la clave **primaria** sigue viva: no revocada y no expirada. Una primaria
/// revocada o expirada mata la clave entera para cifrar, igual que una subclave
/// muerta. La revocación se toma por **presencia** de una `KeyRevocation`: es seguro
/// porque el gate de import ya descartó las forjadas y guardó sólo las que verifican
/// contra la primaria (`crate::pgp_import::ingest_peer_key`). La expiración sale de la
/// self-signature más reciente **que verifica contra la primaria** (firma directa de
/// clave o auto-certificación de UID): el import no descarta certificaciones forjadas
/// (sólo revocaciones y bindings), así que sin este filtro una certificación forjada
/// con `created` futuro reviviría una clave expirada o expiraría una viva. La
/// expiración es relativa a la creación de la primaria; cero segundos significa «nunca
/// expira».
fn primary_usable(key: &SignedPublicKey, now: u32) -> bool {
    if key
        .details
        .revocation_signatures
        .iter()
        .any(|sig| sig.typ() == Some(SignatureType::KeyRevocation))
    {
        return false;
    }

    let primary = &key.primary_key;
    let direct = key
        .details
        .direct_signatures
        .iter()
        .filter(|sig| sig.verify_key(primary).is_ok());
    let uid = key.details.users.iter().flat_map(|user| {
        user.signatures.iter().filter(move |sig| {
            sig.verify_certification(primary, Tag::UserId, &user.id)
                .is_ok()
        })
    });
    let latest_self_sig = direct
        .chain(uid)
        .filter_map(|sig| sig.created().map(|t| (t.as_secs(), sig)))
        .max_by_key(|(created, _)| *created)
        .map(|(_, sig)| sig);

    if let Some(expiration) = latest_self_sig
        .and_then(|sig| sig.key_expiration_time())
        .filter(|d| d.as_secs() != 0)
    {
        let created = key.primary_key.created_at().as_secs();
        if created.saturating_add(expiration.as_secs()) < now {
            return false;
        }
    }
    true
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
    // `key_expiration_time()` de cero segundos significa «nunca expira» (RFC 9580
    // §5.2.3.13), no «expiró al crearse»: se filtra para no matar esas subclaves.
    if let Some(expiration) = binding.key_expiration_time().filter(|d| d.as_secs() != 0) {
        let created = subkey.created_at().as_secs();
        if created.saturating_add(expiration.as_secs()) < now {
            return false;
        }
    }

    // La **firma de binding** puede tener su propia expiración (distinta de la de
    // clave); rPGP 0.21 no la aplica. Vencida → el binding ya no vale → subclave
    // muerta. Es relativa a la creación de la firma, cero = «nunca expira».
    if let Some(sig_expiration) = binding
        .signature_expiration_time()
        .filter(|d| d.as_secs() != 0)
    {
        let sig_created = binding.created().map(|t| t.as_secs()).unwrap_or(0);
        if sig_created.saturating_add(sig_expiration.as_secs()) < now {
            return false;
        }
    }

    let flags = binding.key_flags();
    let any_flag = flags.certify()
        || flags.sign()
        || flags.encrypt_comms()
        || flags.encrypt_storage()
        || flags.authentication();
    if any_flag {
        // Con flags presentes se exige la capacidad pedida **y** que el algoritmo la
        // soporte: una subclave con un flag de cifrado errado sobre un algoritmo que
        // sólo firma no se elige (y al revés), para que la búsqueda siga a la próxima
        // subclave en vez de elegir una que después falla en `encrypt_to_keys`.
        return match usage {
            Usage::Encrypt => {
                (flags.encrypt_comms() || flags.encrypt_storage())
                    && subkey.algorithm().can_encrypt()
            }
            Usage::Sign => flags.sign() && subkey.algorithm().can_sign(),
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

#[cfg(test)]
pub(crate) mod tests {
    //! Pruebas del núcleo OpenPGP. Las claves y los mensajes se generan acá con el
    //! propio `pgp`: nada de binarios externos ni fixtures opacos. Lo que más
    //! importa es **fallar cerrado**: un ciphertext manipulado nunca puede
    //! mostrarse como texto, y una clave expirada o revocada no cifra.
    use super::*;
    use base64::Engine as _;
    use pgp::armor::Dearmor;
    use pgp::composed::{
        EncryptionCaps, KeyType, SecretKeyParamsBuilder, SubkeyParams, SubkeyParamsBuilder,
    };
    use pgp::crypto::ecc_curve::ECCCurve;
    use pgp::packet::{KeyFlags, SignatureConfig, Subpacket, SubpacketData};
    use pgp::types::{CompressionAlgorithm, Duration as PgpDuration};

    const CLARO: &str =
        "Content-Type: text/plain; charset=utf-8\r\n\r\nSECRETO-DEL-TEST: el lince cena a las ocho";

    pub(crate) fn vacia() -> Password {
        Password::empty()
    }

    // ── Fixtures generadas con rPGP ────────────────────────────────────

    pub(crate) fn subclave_de_firma() -> SubkeyParams {
        let mut p = SubkeyParamsBuilder::default();
        p.key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .can_authenticate(false);
        p.build().expect("params de la subclave de firma")
    }

    pub(crate) fn subclave_de_cifrado(creada: Option<Timestamp>) -> SubkeyParams {
        let mut p = SubkeyParamsBuilder::default();
        p.key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
            .can_sign(false)
            .can_encrypt(EncryptionCaps::All)
            .can_authenticate(false);
        if let Some(creada) = creada {
            p.created_at(creada);
        }
        p.build().expect("params de la subclave de cifrado")
    }

    pub(crate) fn generar(uid: &str, subclaves: Vec<SubkeyParams>) -> SignedSecretKey {
        let mut p = SecretKeyParamsBuilder::default();
        p.key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(false)
            .can_encrypt(EncryptionCaps::None)
            .primary_user_id(uid.into())
            .subkeys(subclaves);
        p.build()
            .expect("params de la clave")
            .generate(OsRng)
            .expect("la clave se genera")
    }

    /// Una clave completa: primaria, subclave de firma y subclave de cifrado.
    pub(crate) fn clave_completa(uid: &str) -> SignedSecretKey {
        generar(uid, vec![subclave_de_firma(), subclave_de_cifrado(None)])
    }

    pub(crate) fn publica(secret: &SignedSecretKey) -> SignedPublicKey {
        SignedPublicKey::from(secret.clone())
    }

    pub(crate) fn firmar_union(
        secret: &SignedSecretKey,
        subkey: &SignedPublicSubKey,
        typ: SignatureType,
        expiracion: Option<u32>,
    ) -> pgp::packet::Signature {
        let primaria = &secret.primary_key;
        let mut flags = KeyFlags::default();
        flags.set_encrypt_comms(true);
        flags.set_encrypt_storage(true);
        let mut config = SignatureConfig::from_key(OsRng, primaria, typ).expect("config");
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
            Subpacket::regular(SubpacketData::KeyFlags(flags)).unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(primaria.fingerprint())).unwrap(),
        ];
        if let Some(segundos) = expiracion {
            config.hashed_subpackets.push(
                Subpacket::regular(SubpacketData::KeyExpirationTime(PgpDuration::from_secs(
                    segundos,
                )))
                .unwrap(),
            );
        }
        config
            .sign_subkey_binding(primaria, primaria.public_key(), &vacia(), &subkey.key)
            .expect("firma de la unión")
    }

    /// La pública de `secret` con la subclave `index` reatada: con vencimiento
    /// (`expiracion`, segundos desde su creación) y/o revocada.
    pub(crate) fn con_subclave_reatada(
        secret: &SignedSecretKey,
        index: usize,
        expiracion: Option<u32>,
        revocada: bool,
    ) -> SignedPublicKey {
        let mut public = publica(secret);
        let subkey = public.public_subkeys[index].clone();
        let mut firmas = vec![firmar_union(
            secret,
            &subkey,
            SignatureType::SubkeyBinding,
            expiracion,
        )];
        if revocada {
            firmas.push(firmar_union(
                secret,
                &subkey,
                SignatureType::SubkeyRevocation,
                None,
            ));
        }
        public.public_subkeys[index].signatures = firmas;
        public
    }

    // ── Armado de mensajes ─────────────────────────────────────────────

    pub(crate) fn cifrar(claro: &[u8], para: &SignedPublicKey) -> Vec<u8> {
        encrypt_to_keys(claro, std::slice::from_ref(para)).expect("el cifrado sale")
    }

    fn abrir(raw: &[u8], secret: &SignedSecretKey) -> Decryption {
        decrypt(raw, secret, &vacia())
    }

    fn texto_abierto(d: Decryption) -> String {
        match d {
            Decryption::Opened(bytes) => String::from_utf8(bytes.to_vec()).unwrap(),
            otro => panic!("se esperaba Opened, salió {otro:?}"),
        }
    }

    /// Reenvuelve bytes binarios OpenPGP como armadura de mensaje.
    fn armar(binario: &[u8]) -> Vec<u8> {
        let cuerpo = base64::engine::general_purpose::STANDARD.encode(binario);
        let mut out = String::from("-----BEGIN PGP MESSAGE-----\n\n");
        for linea in cuerpo.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(linea).unwrap());
            out.push('\n');
        }
        out.push_str("-----END PGP MESSAGE-----\n");
        out.into_bytes()
    }

    /// Desarma el mensaje, aplica `cambio` a los bytes binarios y lo rearma:
    /// así se manipula el ciphertext sin romper la armadura ni su CRC.
    pub(crate) fn manipular(armado: &[u8], cambio: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let mut binario = Vec::new();
        Dearmor::new(armado)
            .read_to_end(&mut binario)
            .expect("la armadura se desarma");
        cambio(&mut binario);
        armar(&binario)
    }

    pub(crate) fn correo_inline(armado: &[u8]) -> Vec<u8> {
        let mut out = b"From: a@vasak.test\r\nContent-Type: text/plain\r\n\r\n".to_vec();
        out.extend_from_slice(armado);
        out
    }

    pub(crate) fn correo_pgp_mime(armado: &[u8]) -> Vec<u8> {
        let mut out = b"From: a@vasak.test\r\nContent-Type: multipart/encrypted; \
protocol=\"application/pgp-encrypted\"; boundary=\"B\"\r\n\r\n--B\r\n\
Content-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--B\r\n\
Content-Type: application/octet-stream\r\n\r\n"
            .to_vec();
        out.extend_from_slice(armado);
        out.extend_from_slice(b"\r\n--B--\r\n");
        out
    }

    fn assert_cerrado(resultado: &Decryption) {
        match resultado {
            Decryption::Unavailable(motivo) => {
                assert!(
                    !motivo.contains("SECRETO-DEL-TEST"),
                    "el motivo no puede filtrar el claro: {motivo}"
                );
            }
            Decryption::Opened(bytes) => panic!(
                "falló abierto: un mensaje manipulado se mostró como texto: {:?}",
                String::from_utf8_lossy(bytes)
            ),
            Decryption::NotEncrypted => panic!("no se reconoció como cifrado"),
        }
    }

    // ── 1. Fallar cerrado ante ciphertext manipulado ───────────────────

    /// El mensaje de referencia: cifrado a `bob`, y se comprueba que SIN
    /// manipular sí abre (si no, los «falla cerrado» serían vacíos).
    fn cifrado_de_referencia() -> (SignedSecretKey, Vec<u8>) {
        let bob = clave_completa("Bob <bob@vasak.test>");
        let armado = cifrar(CLARO.as_bytes(), &publica(&bob));
        assert_eq!(
            texto_abierto(abrir(&correo_inline(&armado), &bob)),
            CLARO,
            "sin manipular tiene que abrir"
        );
        (bob, armado)
    }

    #[test]
    fn un_byte_cambiado_al_final_del_sobre_rompe_el_mdc_y_no_se_muestra() {
        // SEIPD v1. El último byte del ciphertext cae dentro del MDC cifrado: el
        // claro queda intacto y sólo la integridad avisa. Es el caso de la falla
        // rPGP de 2019. rPGP 0.21 lo verifica entero al abrir, antes de soltar nada.
        let (bob, armado) = cifrado_de_referencia();
        let roto = manipular(&armado, |b| *b.last_mut().unwrap() ^= 0x01);
        assert_cerrado(&abrir(&correo_inline(&roto), &bob));
    }

    #[test]
    fn un_byte_cambiado_en_el_cuerpo_del_sobre_no_se_muestra() {
        let (bob, armado) = cifrado_de_referencia();
        let roto = manipular(&armado, |b| {
            let medio = b.len() - 40;
            b[medio] ^= 0x80;
        });
        assert_cerrado(&abrir(&correo_inline(&roto), &bob));
    }

    #[test]
    fn un_sobre_sin_el_mdc_porque_lo_cortaron_no_se_muestra() {
        let (bob, armado) = cifrado_de_referencia();
        let roto = manipular(&armado, |b| b.truncate(b.len() - 12));
        assert_cerrado(&abrir(&correo_inline(&roto), &bob));
    }

    /// Un sobre SEIPD v2 (AEAD, OCB) de varios chunks de 4 KiB, cifrado a `para`.
    /// A diferencia de SEIPD v1 (que rPGP verifica entero antes de soltar nada),
    /// cada chunk AEAD se autentica **a medida que se lee**: es el camino que
    /// protege `read_capped`.
    fn cifrar_aead(claro: &[u8], para: &SignedPublicKey) -> Vec<u8> {
        use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
        let mut rng = OsRng;
        let mut builder = MessageBuilder::from_bytes("", claro.to_vec()).seipd_v2(
            &mut rng,
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
            ChunkSize::C4KiB,
        );
        builder
            .encrypt_to_key(&mut rng, encryption_subkey(para).unwrap())
            .unwrap();
        builder
            .to_armored_string(rng, Default::default())
            .unwrap()
            .into_bytes()
    }

    fn cifrado_aead_de_referencia() -> (SignedSecretKey, Vec<u8>, String) {
        let bob = clave_completa("Bob <bob@vasak.test>");
        let claro = format!("{CLARO}{}", "relleno ".repeat(12_000));
        let armado = cifrar_aead(claro.as_bytes(), &publica(&bob));
        assert_eq!(
            texto_abierto(abrir(&correo_inline(&armado), &bob)),
            claro,
            "sin manipular tiene que abrir"
        );
        (bob, armado, claro)
    }

    #[test]
    fn un_chunk_aead_manipulado_en_la_lectura_no_entrega_texto_parcial() {
        // El primer chunk (que se autentica al abrir) queda sano: lo que falla es
        // un chunk posterior, mientras se lee. Si `read_capped` tragara ese error
        // devolvería el texto de los chunks anteriores como si fuera completo.
        let (bob, armado, _claro) = cifrado_aead_de_referencia();
        for posicion in [|len: usize| len - 1, |len: usize| len / 2] {
            let roto = manipular(&armado, |b| {
                let i = posicion(b.len());
                b[i] ^= 0x01;
            });
            let resultado = abrir(&correo_inline(&roto), &bob);
            assert_cerrado(&resultado);
            match resultado {
                Decryption::Unavailable(motivo) => assert!(
                    motivo.contains("lectura del contenido descifrado"),
                    "tenía que fallar en la lectura, no al abrir: {motivo}"
                ),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn un_sobre_aead_cortado_no_entrega_texto_parcial() {
        let (bob, armado, _claro) = cifrado_aead_de_referencia();
        let roto = manipular(&armado, |b| b.truncate(b.len() - 200));
        assert_cerrado(&abrir(&correo_inline(&roto), &bob));
    }

    #[test]
    fn el_mdc_roto_tambien_falla_cerrado_dentro_de_pgp_mime() {
        let (bob, armado) = cifrado_de_referencia();
        let roto = manipular(&armado, |b| *b.last_mut().unwrap() ^= 0x01);
        assert_cerrado(&abrir(&correo_pgp_mime(&roto), &bob));
    }

    #[test]
    fn sin_nuestra_clave_el_sobre_queda_no_disponible() {
        let (_bob, armado) = cifrado_de_referencia();
        let carol = clave_completa("Carol <carol@vasak.test>");
        assert_cerrado(&abrir(&correo_inline(&armado), &carol));
    }

    #[test]
    fn un_bloque_pgp_ilegible_queda_no_disponible_y_no_entra_en_panico() {
        let basura = b"-----BEGIN PGP MESSAGE-----\n\nAAAA\n-----END PGP MESSAGE-----\n";
        let bob = clave_completa("Bob <bob@vasak.test>");
        assert_cerrado(&abrir(&correo_inline(basura), &bob));
    }

    #[test]
    fn un_mensaje_sin_pgp_no_esta_cifrado() {
        let bob = clave_completa("Bob <bob@vasak.test>");
        let raw = b"From: a@vasak.test\r\nContent-Type: text/plain\r\n\r\nhola\r\n";
        assert!(!is_pgp_encrypted(raw));
        assert!(matches!(abrir(raw, &bob), Decryption::NotEncrypted));
    }

    // ── 1b. SED (tag 9, sin MDC): EFAIL / legacy ───────────────────────

    /// Un sobre **SED crudo** (paquete tag 9, `SymEncryptedData`, sin MDC) cifrado a
    /// `para`: PKESK v3 con la clave de sesión + SED con el CFB sin integridad. Se
    /// arma a mano porque rPGP ya no sabe emitirlo (RFC 9580: «MUST NOT create»).
    /// El claro es un paquete literal con `claro`, así que, **con `legacy` encendido**,
    /// este sobre sí se abriría: eso lo comprueba la prueba de abajo como control.
    fn cifrar_sed(claro: &[u8], para: &SignedPublicKey) -> Vec<u8> {
        use pgp::composed::RawSessionKey;
        use pgp::packet::{PacketTrait, PublicKeyEncryptedSessionKey};

        let alg = SymmetricKeyAlgorithm::AES256;
        let clave = vec![0x42u8; alg.key_size()];
        let literal = MessageBuilder::from_bytes("", claro.to_vec())
            .to_vec(OsRng)
            .expect("el paquete literal");
        let cuerpo = alg
            .encrypt(OsRng, &clave, &literal)
            .expect("el CFB sin MDC");

        let mut sobre = Vec::new();
        PublicKeyEncryptedSessionKey::from_session_key_v3(
            OsRng,
            &RawSessionKey::from(clave),
            alg,
            encryption_subkey(para).unwrap(),
        )
        .expect("el PKESK")
        .to_writer_with_header(&mut sobre)
        .expect("se serializa el PKESK");
        // Cabecera de formato viejo: 0x80 | (tag 9 << 2) | longitud de 4 bytes.
        sobre.push(0x80 | (9 << 2) | 0x02);
        sobre.extend_from_slice(&(cuerpo.len() as u32).to_be_bytes());
        sobre.extend_from_slice(&cuerpo);
        sobre
    }

    #[test]
    fn un_sobre_sed_sin_mdc_no_se_abre_aunque_traiga_nuestra_clave() {
        // Blinda contra EFAIL (2019): SED es maleable y rPGP lo rechaza mientras
        // `legacy` esté apagado en `TheRing`. Si alguien llama a `enable_legacy()`
        // en `decrypt`, este sobre pasa a abrirse como texto y la prueba se rompe.
        let bob = clave_completa("Bob <bob@vasak.test>");
        let sed = cifrar_sed(CLARO.as_bytes(), &publica(&bob));
        let armado = armar(&sed);

        // Control: el sobre es válido. Con `legacy` encendido, rPGP lo abre al claro;
        // si no, el «no se abre» de abajo pasaría por un sobre mal armado.
        let (mensaje, _) = Message::from_reader(&armado[..]).expect("el sobre se parsea");
        assert!(mensaje.is_encrypted());
        let sin_passphrase = vacia();
        let anillo = TheRing {
            secret_keys: vec![&bob],
            key_passwords: vec![&sin_passphrase],
            decrypt_options: DecryptionOptions::new().enable_legacy(),
            ..Default::default()
        };
        let (mut abierto, _) = mensaje
            .decrypt_the_ring(anillo, true)
            .expect("con legacy el SED se abriría");
        let mut claro = Vec::new();
        abierto.read_to_end(&mut claro).expect("se lee el claro");
        assert_eq!(String::from_utf8(claro).unwrap(), CLARO);

        // Lo que importa: nuestro núcleo, con `legacy` apagado, no lo abre.
        for correo in [correo_inline(&armado), correo_pgp_mime(&armado)] {
            let resultado = abrir(&correo, &bob);
            assert_cerrado(&resultado);
            match resultado {
                Decryption::Unavailable(motivo) => assert!(
                    motivo.contains("SymEncryptedData"),
                    "tenía que rechazarlo por ser SED, no por otra cosa: {motivo}"
                ),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn un_paquete_sed_suelto_o_con_basura_queda_no_disponible_y_no_entra_en_panico() {
        // Un sobre que sólo trae el tag 9 (sin PKESK) y otro con cuerpo basura.
        let bob = clave_completa("Bob <bob@vasak.test>");
        for cuerpo in [&[][..], &[0xAB; 64][..]] {
            let mut sed = vec![0x80 | (9 << 2) | 0x02];
            sed.extend_from_slice(&(cuerpo.len() as u32).to_be_bytes());
            sed.extend_from_slice(cuerpo);
            assert_cerrado(&abrir(&correo_inline(&armar(&sed)), &bob));
        }
    }

    // ── 5. Tope anti-bomba ─────────────────────────────────────────────
    //
    // Fuera de alcance, a propósito: probar que `CheckFirst { max_message_size:
    // MAX_DECRYPTED }` corta un SEIPD v1 *cifrado* de más de 64 MiB antes de
    // bufferizar. Hace falta generar y cifrar > 64 MiB de ciphertext (la bomba de
    // abajo comprime, así que su sobre es chico y no llega a ese tope): una prueba
    // lenta y pesada para el CI. Ese techo queda cubierto por inspección de
    // `decrypt` (`set_seipdv1_read_mode`), no por una prueba.

    #[test]
    fn el_tope_deja_pasar_justo_el_limite_y_corta_un_byte_mas() {
        let justo = vec![7u8; 10];
        assert_eq!(read_capped(&mut justo.as_slice(), 10).unwrap(), justo);
        let pasado = vec![7u8; 11];
        let error = read_capped(&mut pasado.as_slice(), 10).unwrap_err();
        assert!(error.contains("supera el tope"), "{error}");
    }

    fn cifrar_comprimido(claro: Vec<u8>, para: &SignedPublicKey) -> Vec<u8> {
        let mut rng = OsRng;
        let mut builder =
            MessageBuilder::from_bytes("", claro).seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder.compression(CompressionAlgorithm::ZLIB);
        builder
            .encrypt_to_key(&mut rng, encryption_subkey(para).unwrap())
            .unwrap();
        builder
            .to_armored_string(rng, Default::default())
            .unwrap()
            .into_bytes()
    }

    #[test]
    fn un_mensaje_comprimido_chico_se_abre_y_uno_bomba_no_se_materializa() {
        let bob = clave_completa("Bob <bob@vasak.test>");
        let publica = publica(&bob);

        // Control: la compresión funciona, así que la bomba no falla por eso.
        let normal = cifrar_comprimido(vec![b'a'; 1024 * 1024], &publica);
        let abierto = texto_abierto(abrir(&correo_inline(&normal), &bob));
        assert_eq!(abierto.len(), 1024 * 1024);

        // Bomba: una MiB más que el tope, comprimida a unos pocos KiB.
        let bomba = cifrar_comprimido(vec![0u8; MAX_DECRYPTED + 1024 * 1024], &publica);
        assert!(bomba.len() < 256 * 1024, "la bomba debe pesar poco");
        match abrir(&correo_inline(&bomba), &bob) {
            Decryption::Unavailable(motivo) => {
                assert!(motivo.contains("supera el tope"), "{motivo}")
            }
            otro => panic!("la bomba no puede abrirse: {otro:?}"),
        }
    }

    // ── 2. Ida y vuelta de cifrado ─────────────────────────────────────

    #[test]
    fn cifrar_a_una_publica_y_descifrar_con_su_privada_recupera_el_claro() {
        let bob = clave_completa("Bob <bob@vasak.test>");
        let armado = cifrar(CLARO.as_bytes(), &publica(&bob));
        let texto = String::from_utf8(armado.clone()).unwrap();
        assert!(texto.starts_with(BEGIN_PGP_MESSAGE), "{texto}");
        assert!(!texto.contains("SECRETO-DEL-TEST"), "el claro no viaja");
        assert_eq!(texto_abierto(abrir(&correo_inline(&armado), &bob)), CLARO);
    }

    #[test]
    fn el_sobre_en_pgp_mime_tambien_se_abre() {
        let bob = clave_completa("Bob <bob@vasak.test>");
        let correo = correo_pgp_mime(&cifrar(CLARO.as_bytes(), &publica(&bob)));
        assert!(is_pgp_encrypted(&correo));
        assert_eq!(texto_abierto(abrir(&correo, &bob)), CLARO);
    }

    #[test]
    fn un_sobre_para_dos_destinatarios_lo_abre_cada_uno_y_un_tercero_no() {
        let (bob, carol, dave) = (
            clave_completa("Bob <bob@vasak.test>"),
            clave_completa("Carol <carol@vasak.test>"),
            clave_completa("Dave <dave@vasak.test>"),
        );
        let armado = encrypt_to_keys(CLARO.as_bytes(), &[publica(&bob), publica(&carol)]).unwrap();
        let correo = correo_inline(&armado);
        assert_eq!(texto_abierto(abrir(&correo, &bob)), CLARO);
        assert_eq!(texto_abierto(abrir(&correo, &carol)), CLARO);
        assert_cerrado(&abrir(&correo, &dave));
    }

    #[test]
    fn sin_destinatarios_no_se_cifra() {
        assert!(matches!(
            encrypt_to_keys(b"x", &[]),
            Err(PgpError::NoEncryptionKey(_))
        ));
    }

    // ── 3. Selección de subclave ───────────────────────────────────────

    #[test]
    fn la_subclave_de_cifrado_valida_se_elige_y_no_la_de_firma() {
        let bob = clave_completa("Bob <bob@vasak.test>");
        let publica = publica(&bob);
        let elegida = encryption_subkey(&publica).expect("hay subclave de cifrado");
        assert_eq!(
            elegida.fingerprint(),
            bob.secret_subkeys[1].fingerprint(),
            "tiene que ser la de cifrado (la 2ª), no la de firma"
        );
    }

    #[test]
    fn una_subclave_de_cifrado_expirada_cuenta_como_sin_clave() {
        let hace_un_ano = Timestamp::from_secs(Timestamp::now().as_secs() - 365 * 24 * 3600);
        let bob = generar(
            "Bob <bob@vasak.test>",
            vec![subclave_de_firma(), subclave_de_cifrado(Some(hace_un_ano))],
        );
        // Venció hace unos 364 días.
        let expirada = con_subclave_reatada(&bob, 1, Some(24 * 3600), false);
        assert!(encryption_subkey(&expirada).is_none());
        assert!(matches!(
            encrypt_to_keys(b"x", &[expirada]),
            Err(PgpError::NoEncryptionKey(_))
        ));
    }

    #[test]
    fn una_subclave_con_vencimiento_futuro_sigue_sirviendo() {
        let hace_un_dia = Timestamp::from_secs(Timestamp::now().as_secs() - 24 * 3600);
        let bob = generar(
            "Bob <bob@vasak.test>",
            vec![subclave_de_firma(), subclave_de_cifrado(Some(hace_un_dia))],
        );
        let vigente = con_subclave_reatada(&bob, 1, Some(30 * 24 * 3600), false);
        assert!(encryption_subkey(&vigente).is_some());
        let armado = encrypt_to_keys(CLARO.as_bytes(), &[vigente]).unwrap();
        assert_eq!(texto_abierto(abrir(&correo_inline(&armado), &bob)), CLARO);
    }

    #[test]
    fn una_subclave_de_cifrado_revocada_cuenta_como_sin_clave() {
        let bob = clave_completa("Bob <bob@vasak.test>");
        let revocada = con_subclave_reatada(&bob, 1, None, true);
        assert!(encryption_subkey(&revocada).is_none());
        assert!(matches!(
            encrypt_to_keys(b"x", &[revocada]),
            Err(PgpError::NoEncryptionKey(_))
        ));
    }

    #[test]
    fn con_una_expirada_y_otra_vigente_se_elige_la_vigente() {
        let hace_un_ano = Timestamp::from_secs(Timestamp::now().as_secs() - 365 * 24 * 3600);
        let bob = generar(
            "Bob <bob@vasak.test>",
            vec![
                subclave_de_cifrado(Some(hace_un_ano)),
                subclave_de_cifrado(None),
            ],
        );
        let publica = con_subclave_reatada(&bob, 0, Some(24 * 3600), false);
        let elegida = encryption_subkey(&publica).expect("queda la vigente");
        assert_eq!(elegida.fingerprint(), bob.secret_subkeys[1].fingerprint());
    }

    #[test]
    fn una_clave_con_solo_subclave_de_firma_no_cae_a_la_primaria() {
        let solo_firma = generar("Solo <solo@vasak.test>", vec![subclave_de_firma()]);
        let publica = publica(&solo_firma);
        assert!(encryption_subkey(&publica).is_none());
        match encrypt_to_keys(b"x", std::slice::from_ref(&publica)) {
            Err(PgpError::NoEncryptionKey(quien)) => {
                assert_eq!(quien, publica.primary_key.fingerprint().to_string())
            }
            otro => panic!("se esperaba NoEncryptionKey, salió {otro:?}"),
        }
    }

    #[test]
    fn si_a_un_destinatario_le_falta_la_clave_no_se_cifra_a_medias() {
        let bob = clave_completa("Bob <bob@vasak.test>");
        let solo_firma = generar("Solo <solo@vasak.test>", vec![subclave_de_firma()]);
        let resultado = encrypt_to_keys(b"x", &[publica(&bob), publica(&solo_firma)]);
        assert!(matches!(resultado, Err(PgpError::NoEncryptionKey(_))));
    }

    // ── 4. Firmar y verificar ──────────────────────────────────────────

    const CONTENIDO: &str = "Content-Type: text/plain; charset=utf-8\r\n\r\nhola, esto va firmado";

    fn correo_firmado(contenido: &str, firma_armada: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "From: a@vasak.test\r\nContent-Type: multipart/signed; \
protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"S\"\r\n\r\n\
--S\r\n{contenido}\r\n--S\r\nContent-Type: application/pgp-signature\r\n\r\n"
        )
        .into_bytes();
        out.extend_from_slice(firma_armada);
        out.extend_from_slice(b"\r\n--S--\r\n");
        out
    }

    #[test]
    fn la_firma_separada_verifica_contra_la_clave_correcta() {
        let alice = clave_completa("Alice <alice@vasak.test>");
        let firma = sign_detached(CONTENIDO.as_bytes(), &alice, &vacia()).unwrap();
        assert!(String::from_utf8_lossy(&firma).contains("BEGIN PGP SIGNATURE"));
        let correo = correo_firmado(CONTENIDO, &firma);
        assert_eq!(
            verify(&correo, &[publica(&alice)]),
            Verification::SignedUntrusted(alice.primary_key.fingerprint().to_string())
        );
    }

    #[test]
    fn la_firma_separada_no_verifica_contra_otra_clave() {
        let alice = clave_completa("Alice <alice@vasak.test>");
        let mallory = clave_completa("Mallory <mallory@vasak.test>");
        let firma = sign_detached(CONTENIDO.as_bytes(), &alice, &vacia()).unwrap();
        let correo = correo_firmado(CONTENIDO, &firma);
        assert!(matches!(
            verify(&correo, &[publica(&mallory)]),
            Verification::Unverified(_)
        ));
        // Sin ninguna candidata (firmante desconocido) tampoco hay «firmado».
        assert!(matches!(verify(&correo, &[]), Verification::Unverified(_)));
    }

    #[test]
    fn la_firma_separada_gana_la_clave_que_cierra_entre_varias_candidatas() {
        let alice = clave_completa("Alice <alice@vasak.test>");
        let mallory = clave_completa("Mallory <mallory@vasak.test>");
        let firma = sign_detached(CONTENIDO.as_bytes(), &alice, &vacia()).unwrap();
        let correo = correo_firmado(CONTENIDO, &firma);
        assert_eq!(
            verify(&correo, &[publica(&mallory), publica(&alice)]),
            Verification::SignedUntrusted(alice.primary_key.fingerprint().to_string())
        );
    }

    #[test]
    fn un_byte_cambiado_en_el_contenido_firmado_no_verifica() {
        let alice = clave_completa("Alice <alice@vasak.test>");
        let firma = sign_detached(CONTENIDO.as_bytes(), &alice, &vacia()).unwrap();
        let adulterado = CONTENIDO.replace("hola", "chau");
        let correo = correo_firmado(&adulterado, &firma);
        assert!(matches!(
            verify(&correo, &[publica(&alice)]),
            Verification::Unverified(_)
        ));
    }

    #[test]
    fn se_firma_con_la_subclave_de_firma_aunque_la_de_cifrado_venga_primero() {
        // Si eligiera la subclave ECDH (sólo de cifrado) la firma fallaría.
        let alice = generar(
            "Alice <alice@vasak.test>",
            vec![subclave_de_cifrado(None), subclave_de_firma()],
        );
        let firma = sign_detached(CONTENIDO.as_bytes(), &alice, &vacia()).unwrap();
        let correo = correo_firmado(CONTENIDO, &firma);
        assert!(matches!(
            verify(&correo, &[publica(&alice)]),
            Verification::SignedUntrusted(_)
        ));
    }

    #[test]
    fn sin_subclave_de_firma_firma_la_primaria_y_verifica() {
        let alice = generar("Alice <alice@vasak.test>", vec![subclave_de_cifrado(None)]);
        let firma = sign_detached(CONTENIDO.as_bytes(), &alice, &vacia()).unwrap();
        let correo = correo_firmado(CONTENIDO, &firma);
        assert_eq!(
            verify(&correo, &[publica(&alice)]),
            Verification::SignedUntrusted(alice.primary_key.fingerprint().to_string())
        );
    }

    #[test]
    fn un_multipart_signed_con_una_tercera_parte_no_verifica() {
        // RFC 1847: son exactamente dos partes; una tercera podría mostrar algo que
        // la firma no cubre.
        let alice = clave_completa("Alice <alice@vasak.test>");
        let firma = sign_detached(CONTENIDO.as_bytes(), &alice, &vacia()).unwrap();
        let correo = correo_firmado(CONTENIDO, &firma);
        let texto = String::from_utf8(correo).unwrap();
        let con_extra = texto.replace(
            "\r\n--S--\r\n",
            "\r\n--S\r\nContent-Type: text/plain\r\n\r\nINYECTADO\r\n--S--\r\n",
        );
        assert!(matches!(
            verify(con_extra.as_bytes(), &[publica(&alice)]),
            Verification::Unverified(_)
        ));
    }

    #[test]
    fn un_multipart_signed_que_no_es_pgp_no_se_muestra_como_pgp() {
        let alice = clave_completa("Alice <alice@vasak.test>");
        let firma = sign_detached(CONTENIDO.as_bytes(), &alice, &vacia()).unwrap();
        let correo = String::from_utf8(correo_firmado(CONTENIDO, &firma))
            .unwrap()
            .replace(
                "application/pgp-signature\"",
                "application/pkcs7-signature\"",
            );
        assert_eq!(
            verify(correo.as_bytes(), &[publica(&alice)]),
            Verification::NotSigned
        );
    }

    pub(crate) fn cleartext_de(texto: &str, firmante: &impl pgp::types::SigningKey) -> String {
        CleartextSignedMessage::sign(OsRng, texto, firmante, &vacia())
            .expect("firma cleartext")
            .to_armored_string(Default::default())
            .expect("armadura")
    }

    fn correo_con(bloque: &str) -> Vec<u8> {
        format!("From: a@vasak.test\r\nContent-Type: text/plain\r\n\r\n{bloque}").into_bytes()
    }

    #[test]
    fn el_cleartext_inline_verifica_con_la_subclave_de_firma() {
        let alice = clave_completa("Alice <alice@vasak.test>");
        let bloque = cleartext_de("hola en claro", &*alice.secret_subkeys[0]);
        assert_eq!(
            verify(&correo_con(&bloque), &[publica(&alice)]),
            Verification::SignedUntrusted(alice.primary_key.fingerprint().to_string())
        );
    }

    #[test]
    fn el_cleartext_inline_verifica_con_la_primaria() {
        let alice = clave_completa("Alice <alice@vasak.test>");
        let bloque = cleartext_de("hola en claro", &alice.primary_key);
        assert_eq!(
            verify(&correo_con(&bloque), &[publica(&alice)]),
            Verification::SignedUntrusted(alice.primary_key.fingerprint().to_string())
        );
    }

    #[test]
    fn el_cleartext_inline_no_verifica_contra_otra_clave() {
        let alice = clave_completa("Alice <alice@vasak.test>");
        let mallory = clave_completa("Mallory <mallory@vasak.test>");
        let bloque = cleartext_de("hola en claro", &*alice.secret_subkeys[0]);
        assert!(matches!(
            verify(&correo_con(&bloque), &[publica(&mallory)]),
            Verification::Unverified(_)
        ));
    }

    #[test]
    fn un_cleartext_con_el_texto_cambiado_no_verifica() {
        let alice = clave_completa("Alice <alice@vasak.test>");
        let bloque = cleartext_de("pago 100 pesos", &*alice.secret_subkeys[0])
            .replace("100 pesos", "900 pesos");
        assert!(matches!(
            verify(&correo_con(&bloque), &[publica(&alice)]),
            Verification::Unverified(_)
        ));
    }

    #[test]
    fn un_correo_sin_firma_no_esta_firmado() {
        let alice = clave_completa("Alice <alice@vasak.test>");
        let raw = b"From: a@vasak.test\r\nContent-Type: text/plain\r\n\r\nhola\r\n";
        assert_eq!(verify(raw, &[publica(&alice)]), Verification::NotSigned);
    }

    // ── Claves: armadura y binario ─────────────────────────────────────

    #[test]
    fn las_claves_se_leen_armadas_y_binarias_y_una_basura_es_bad_key() {
        use pgp::ser::Serialize;
        let alice = clave_completa("Alice <alice@vasak.test>");
        let pub_key = publica(&alice);

        let armada = pub_key.to_armored_bytes(Default::default()).unwrap();
        assert_eq!(parse_public_key(&armada).unwrap(), pub_key);
        assert_eq!(
            parse_public_key(&pub_key.to_bytes().unwrap()).unwrap(),
            pub_key
        );

        let secreta = alice.to_armored_bytes(Default::default()).unwrap();
        assert_eq!(parse_secret_key(&secreta).unwrap(), alice);
        assert_eq!(parse_secret_key(&alice.to_bytes().unwrap()).unwrap(), alice);

        assert!(matches!(
            parse_public_key(b"esto no es una clave"),
            Err(PgpError::BadKey(_))
        ));
        assert!(matches!(
            parse_secret_key(b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nAAAA\n-----END PGP PRIVATE KEY BLOCK-----\n"),
            Err(PgpError::BadKey(_))
        ));
    }

    // ── 7 correcciones de la revisión (PR #157) ────────────────────────
    //
    // Cada prueba de abajo falla sin su corrección puntual: el bloque dice cuál.

    // ── A. Clave binaria con `-----BEGIN` dentro de un UID ─────────────

    #[test]
    fn una_clave_binaria_con_begin_en_el_uid_se_lee_y_no_se_toma_por_armadura() {
        use pgp::ser::Serialize;
        // Un UID es texto libre: nada impide que traiga la cadena de un encabezado de
        // armadura. Una clave **binaria** así no es armadura, y el viejo `looks_armored`
        // la mandaba por el camino armor y fallaba con `BadKey`.
        let alice = clave_completa("Alice <-----BEGIN PGP MESSAGE-----@vasak.test>");
        let pub_key = publica(&alice);
        let binaria_publica = pub_key.to_bytes().unwrap();
        let binaria_secreta = alice.to_bytes().unwrap();
        for bytes in [&binaria_publica, &binaria_secreta] {
            assert!(
                bytes.windows(10).any(|w| w == b"-----BEGIN"),
                "el fixture tiene que llevar el encabezado dentro del UID"
            );
        }

        assert_eq!(parse_public_key(&binaria_publica).unwrap(), pub_key);
        assert_eq!(parse_secret_key(&binaria_secreta).unwrap(), alice);

        // Controles: la misma clave armada sigue leyéndose, y la basura sigue siendo
        // `BadKey` (tampoco se traga lo que no es clave sólo por llevar `-----BEGIN`).
        let armada = pub_key.to_armored_bytes(Default::default()).unwrap();
        assert_eq!(parse_public_key(&armada).unwrap(), pub_key);
        assert!(matches!(
            parse_public_key(b"-----BEGIN basura -----"),
            Err(PgpError::BadKey(_))
        ));
        assert!(matches!(
            parse_secret_key(&binaria_publica),
            Err(PgpError::BadKey(_))
        ));
    }

    // ── B. Compresión anidada ──────────────────────────────────────────

    /// Un paquete OpenPGP «Compressed Data» (tag 8) que envuelve `interior`. La
    /// compresión es DEFLATE crudo con un único bloque *stored* (sin comprimir de
    /// verdad): alcanza para anidar paquetes sin sumar una dependencia, y el
    /// descompresor de rPGP lo lee igual que a cualquiera.
    fn paquete_comprimido(interior: &[u8]) -> Vec<u8> {
        let largo = u16::try_from(interior.len()).expect("el interior entra en un bloque stored");
        let mut cuerpo = vec![1u8]; // algoritmo de compresión 1 = ZIP (DEFLATE crudo)
        cuerpo.push(0x01); // BFINAL=1, BTYPE=00 (stored)
        cuerpo.extend_from_slice(&largo.to_le_bytes());
        cuerpo.extend_from_slice(&(!largo).to_le_bytes());
        cuerpo.extend_from_slice(interior);
        // Cabecera de formato viejo: 0x80 | (tag 8 << 2) | longitud de 4 bytes.
        let mut paquete = vec![0x80 | (8 << 2) | 0x02];
        paquete.extend_from_slice(&(cuerpo.len() as u32).to_be_bytes());
        paquete.extend_from_slice(&cuerpo);
        paquete
    }

    /// Un sobre SEIPD v1 cuyo claro es un literal envuelto en `capas` paquetes
    /// comprimidos, uno dentro de otro. El `MessageBuilder` sólo sabe comprimir una
    /// vez (y envuelve en literal), así que el claro se arma paquete a paquete.
    fn cifrar_con_capas(claro: &[u8], capas: usize, para: &SignedPublicKey) -> Vec<u8> {
        use pgp::composed::RawSessionKey;
        use pgp::packet::{PacketTrait, PublicKeyEncryptedSessionKey, SymEncryptedProtectedData};

        let mut paquetes = MessageBuilder::from_bytes("", claro.to_vec())
            .to_vec(OsRng)
            .expect("el paquete literal");
        for _ in 0..capas {
            paquetes = paquete_comprimido(&paquetes);
        }

        let alg = SymmetricKeyAlgorithm::AES256;
        let clave = vec![0x42u8; alg.key_size()];
        let mut sobre = Vec::new();
        PublicKeyEncryptedSessionKey::from_session_key_v3(
            OsRng,
            &RawSessionKey::from(clave.clone()),
            alg,
            encryption_subkey(para).unwrap(),
        )
        .expect("el PKESK")
        .to_writer_with_header(&mut sobre)
        .expect("se serializa el PKESK");
        SymEncryptedProtectedData::encrypt_seipdv1(OsRng, alg, &clave, &paquetes)
            .expect("el SEIPD v1")
            .to_writer_with_header(&mut sobre)
            .expect("se serializa el SEIPD");
        armar(&sobre)
    }

    #[test]
    fn un_comprimido_dentro_de_otro_comprimido_abre_al_claro_final() {
        // Sin el loop de descompresión, una sola pasada dejaba el paquete interno
        // sin abrir y `read_capped` lo entregaba como si fuera el claro: bytes crudos.
        let bob = clave_completa("Bob <bob@vasak.test>");
        let publica = publica(&bob);
        // Control: una capa (el caso normal) abre.
        let una = cifrar_con_capas(CLARO.as_bytes(), 1, &publica);
        assert_eq!(texto_abierto(abrir(&correo_inline(&una), &bob)), CLARO);
        // Dos capas, y justo en el tope de capas permitidas.
        for capas in [2, MAX_COMPRESSION_LAYERS as usize] {
            let sobre = cifrar_con_capas(CLARO.as_bytes(), capas, &publica);
            assert_eq!(
                texto_abierto(abrir(&correo_inline(&sobre), &bob)),
                CLARO,
                "con {capas} capas tiene que abrir al claro final"
            );
        }
    }

    #[test]
    fn mas_capas_de_compresion_que_el_tope_no_se_materializan() {
        let bob = clave_completa("Bob <bob@vasak.test>");
        let sobre = cifrar_con_capas(
            CLARO.as_bytes(),
            MAX_COMPRESSION_LAYERS as usize + 1,
            &publica(&bob),
        );
        match abrir(&correo_inline(&sobre), &bob) {
            Decryption::Unavailable(motivo) => {
                assert!(motivo.contains("demasiadas capas"), "{motivo}")
            }
            otro => panic!("una bomba de capas no puede abrirse: {otro:?}"),
        }
    }

    #[test]
    fn firmar_y_despues_comprimir_sigue_abriendo() {
        // Control del loop: el mensaje firmado y comprimido no es «comprimido
        // anidado»; tras la primera pasada ya no hay nada que descomprimir.
        let bob = clave_completa("Bob <bob@vasak.test>");
        let alice = clave_completa("Alice <alice@vasak.test>");
        let mut rng = OsRng;
        let mut builder = MessageBuilder::from_bytes("", CLARO.as_bytes().to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder.sign(&alice.primary_key, vacia(), HashAlgorithm::Sha256);
        builder.compression(CompressionAlgorithm::ZLIB);
        builder
            .encrypt_to_key(&mut rng, encryption_subkey(&publica(&bob)).unwrap())
            .unwrap();
        let armado = builder
            .to_armored_string(rng, Default::default())
            .unwrap()
            .into_bytes();
        assert_eq!(texto_abierto(abrir(&correo_inline(&armado), &bob)), CLARO);
    }

    // ── C. Firma separada con Content-Transfer-Encoding ────────────────

    fn base64_en_lineas(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD
            .encode(bytes)
            .as_bytes()
            .chunks(76)
            .map(|linea| std::str::from_utf8(linea).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n")
    }

    /// Como `correo_firmado`, pero la parte de la firma lleva
    /// `Content-Transfer-Encoding: <cte>` y el cuerpo que se le pasa.
    fn correo_firmado_con_cte(contenido: &str, cte: &str, cuerpo_firma: &str) -> Vec<u8> {
        format!(
            "From: a@vasak.test\r\nContent-Type: multipart/signed; \
protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"S\"\r\n\r\n\
--S\r\n{contenido}\r\n--S\r\nContent-Type: application/pgp-signature\r\n\
Content-Transfer-Encoding: {cte}\r\n\r\n{cuerpo_firma}\r\n--S--\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn una_firma_pgp_mime_en_base64_verifica() {
        use pgp::ser::Serialize;
        // Sin aplicar el CTE de la parte, el base64 no era armadura ni paquete: la
        // firma salía «ilegible» aunque fuera buena.
        let alice = clave_completa("Alice <alice@vasak.test>");
        let esperado = Verification::SignedUntrusted(alice.primary_key.fingerprint().to_string());
        let armada = sign_detached(CONTENIDO.as_bytes(), &alice, &vacia()).unwrap();
        let (firma, _) = DetachedSignature::from_armor_single(&armada[..]).unwrap();

        // La armadura recodificada en base64, y el paquete binario en base64.
        for cuerpo in [
            base64_en_lineas(&armada),
            base64_en_lineas(&firma.to_bytes().unwrap()),
        ] {
            let correo = correo_firmado_con_cte(CONTENIDO, "base64", &cuerpo);
            assert_eq!(verify(&correo, &[publica(&alice)]), esperado);
        }

        // Controles: `7bit` con la armadura cruda sigue verificando, y una firma en
        // base64 de contenido adulterado sigue sin cerrar (el CTE no relaja nada).
        let cruda = String::from_utf8(armada.clone()).unwrap();
        assert_eq!(
            verify(
                &correo_firmado_con_cte(CONTENIDO, "7bit", &cruda),
                &[publica(&alice)]
            ),
            esperado
        );
        let adulterado = CONTENIDO.replace("hola", "chau");
        assert!(matches!(
            verify(
                &correo_firmado_con_cte(&adulterado, "base64", &base64_en_lineas(&armada)),
                &[publica(&alice)]
            ),
            Verification::Unverified(motivo) if motivo.contains("no cierra")
        ));
    }

    // ── D. Primaria revocada o expirada ────────────────────────────────

    const UN_ANO: u32 = 365 * 24 * 3600;

    fn hace_un_ano() -> Timestamp {
        Timestamp::from_secs(Timestamp::now().as_secs() - UN_ANO)
    }

    /// Una clave completa cuya **primaria** se creó `hace_un_ano()`.
    fn clave_vieja(uid: &str) -> SignedSecretKey {
        let mut p = SecretKeyParamsBuilder::default();
        p.key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(false)
            .can_encrypt(EncryptionCaps::None)
            .created_at(hace_un_ano())
            .primary_user_id(uid.into())
            .subkeys(vec![subclave_de_firma(), subclave_de_cifrado(None)]);
        p.build()
            .expect("params de la clave")
            .generate(OsRng)
            .expect("la clave se genera")
    }

    /// Una auto-firma de la primaria (`typ`) con `KeyExpirationTime` opcional.
    fn auto_firma_con_expiracion(
        secret: &SignedSecretKey,
        typ: SignatureType,
        expiracion: Option<u32>,
        publica: &SignedPublicKey,
    ) -> pgp::packet::Signature {
        use pgp::types::Tag;
        let primaria = &secret.primary_key;
        let mut flags = KeyFlags::default();
        flags.set_certify(true);
        let mut config = SignatureConfig::from_key(OsRng, primaria, typ).expect("config");
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
            Subpacket::regular(SubpacketData::KeyFlags(flags)).unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(primaria.fingerprint())).unwrap(),
        ];
        if let Some(segundos) = expiracion {
            config.hashed_subpackets.push(
                Subpacket::regular(SubpacketData::KeyExpirationTime(PgpDuration::from_secs(
                    segundos,
                )))
                .unwrap(),
            );
        }
        match typ {
            SignatureType::KeyRevocation | SignatureType::Key => config
                .sign_key(primaria, &vacia(), primaria.public_key())
                .expect("firma directa de la primaria"),
            _ => config
                .sign_certification(
                    primaria,
                    primaria.public_key(),
                    &vacia(),
                    Tag::UserId,
                    &publica.details.users[0].id,
                )
                .expect("auto-certificación del UID"),
        }
    }

    /// La pública con la primaria revocada.
    fn con_primaria_revocada(secret: &SignedSecretKey) -> SignedPublicKey {
        let mut public = publica(secret);
        let revocacion =
            auto_firma_con_expiracion(secret, SignatureType::KeyRevocation, None, &public);
        public.details.revocation_signatures.push(revocacion);
        public
    }

    /// La pública con la auto-firma del UID reemplazada por una con vencimiento
    /// `expiracion` (segundos desde la creación de la primaria).
    fn con_primaria_con_vencimiento_en_el_uid(
        secret: &SignedSecretKey,
        expiracion: u32,
    ) -> SignedPublicKey {
        let mut public = publica(secret);
        let firma = auto_firma_con_expiracion(
            secret,
            SignatureType::CertPositive,
            Some(expiracion),
            &public,
        );
        public.details.users[0].signatures = vec![firma];
        public
    }

    /// La pública con una firma directa de clave con vencimiento, y sin
    /// auto-firmas de UID que empaten con ella en fecha.
    fn con_primaria_con_vencimiento_directo(
        secret: &SignedSecretKey,
        expiracion: u32,
    ) -> SignedPublicKey {
        let mut public = publica(secret);
        let firma =
            auto_firma_con_expiracion(secret, SignatureType::Key, Some(expiracion), &public);
        public.details.direct_signatures = vec![firma];
        public.details.users[0].signatures.clear();
        public
    }

    #[test]
    fn una_primaria_revocada_mata_la_clave_aunque_la_subclave_este_vigente() {
        let bob = clave_completa("Bob <bob@vasak.test>");
        // Control: sin revocar, la misma clave cifra.
        assert!(encryption_subkey(&publica(&bob)).is_some());

        let revocada = con_primaria_revocada(&bob);
        assert!(
            subkey_usable(
                &revocada.public_subkeys[1],
                Timestamp::now().as_secs(),
                Usage::Encrypt
            ),
            "la subclave sola sigue vigente: lo que la mata es la primaria"
        );
        assert!(encryption_subkey(&revocada).is_none());
        assert!(matches!(
            encrypt_to_keys(b"x", &[revocada]),
            Err(PgpError::NoEncryptionKey(_))
        ));
    }

    #[test]
    fn una_primaria_expirada_mata_la_clave_aunque_la_subclave_este_vigente() {
        let bob = clave_vieja("Bob <bob@vasak.test>");
        // Control: la clave vieja, sin vencimiento, cifra.
        assert!(encryption_subkey(&publica(&bob)).is_some());

        // Venció hace unos 364 días, por la auto-firma del UID y por la directa.
        for expirada in [
            con_primaria_con_vencimiento_en_el_uid(&bob, 24 * 3600),
            con_primaria_con_vencimiento_directo(&bob, 24 * 3600),
        ] {
            assert!(encryption_subkey(&expirada).is_none());
            assert!(matches!(
                encrypt_to_keys(b"x", &[expirada]),
                Err(PgpError::NoEncryptionKey(_))
            ));
        }
    }

    /// La secreta con la metadata de la primaria tomada de `muerta` (la pública
    /// revocada o expirada): lo que `signing_component` mira vía `to_public_key()`.
    fn con_primaria_muerta(secret: &SignedSecretKey, muerta: SignedPublicKey) -> SignedSecretKey {
        let mut secret = secret.clone();
        secret.details = muerta.details;
        secret
    }

    #[test]
    fn una_primaria_muerta_no_firma_ni_con_una_subclave_de_firma_vigente() {
        let ahora = Timestamp::now().as_secs();
        // Control: viva, la clave firma con la subclave de firma.
        let vivo = clave_vieja("Alice <alice@vasak.test>");
        assert!(matches!(
            signing_component(&vivo, ahora),
            Some(Signer::Subkey(0))
        ));

        let revocada = con_primaria_muerta(&vivo, con_primaria_revocada(&vivo));
        let expirada = con_primaria_muerta(
            &vivo,
            con_primaria_con_vencimiento_en_el_uid(&vivo, 24 * 3600),
        );
        for muerta in [revocada, expirada] {
            assert!(
                subkey_usable(
                    &muerta.secret_subkeys[0].signed_public_key(),
                    ahora,
                    Usage::Sign
                ),
                "la subclave sola sigue vigente: lo que la mata es la primaria"
            );
            assert!(signing_component(&muerta, ahora).is_none());
            assert!(matches!(
                sign_detached(CONTENIDO.as_bytes(), &muerta, &vacia()),
                Err(PgpError::NoSigningKey)
            ));
        }
    }

    #[test]
    fn una_primaria_muerta_sin_subclave_de_firma_no_cae_a_firmar_con_ella() {
        let ahora = Timestamp::now().as_secs();
        // Control: viva y sin subclaves, firma la primaria (su algoritmo puede).
        let vivo = generar("Alice <alice@vasak.test>", vec![]);
        assert!(primary_can_sign(&vivo));
        assert!(matches!(
            signing_component(&vivo, ahora),
            Some(Signer::Primary)
        ));

        let revocada = con_primaria_muerta(&vivo, con_primaria_revocada(&vivo));
        assert!(matches!(
            sign_detached(CONTENIDO.as_bytes(), &revocada, &vacia()),
            Err(PgpError::NoSigningKey)
        ));
    }

    #[test]
    fn una_primaria_con_vencimiento_futuro_o_cero_sigue_cifrando() {
        let bob = clave_vieja("Bob <bob@vasak.test>");
        // Vence en unos 100 días; y cero segundos = «nunca expira».
        for vigente in [
            con_primaria_con_vencimiento_en_el_uid(&bob, UN_ANO + 100 * 24 * 3600),
            con_primaria_con_vencimiento_en_el_uid(&bob, 0),
            con_primaria_con_vencimiento_directo(&bob, 0),
        ] {
            assert!(encryption_subkey(&vigente).is_some());
            let armado = encrypt_to_keys(CLARO.as_bytes(), &[vigente]).unwrap();
            assert_eq!(texto_abierto(abrir(&correo_inline(&armado), &bob)), CLARO);
        }
    }

    // ── E. Expiración cero = nunca expira ──────────────────────────────

    #[test]
    fn una_subclave_con_vencimiento_cero_nunca_expira() {
        // `KeyExpirationTime(0)` no es «expiró al crearse»: sin el filtro, una
        // subclave de hace un año con vencimiento 0 contaba como muerta.
        let bob = generar(
            "Bob <bob@vasak.test>",
            vec![
                subclave_de_firma(),
                subclave_de_cifrado(Some(hace_un_ano())),
            ],
        );
        let publica = con_subclave_reatada(&bob, 1, Some(0), false);
        let elegida = encryption_subkey(&publica).expect("vencimiento cero no expira");
        assert_eq!(elegida.fingerprint(), bob.secret_subkeys[1].fingerprint());
        let armado = encrypt_to_keys(CLARO.as_bytes(), &[publica]).unwrap();
        assert_eq!(texto_abierto(abrir(&correo_inline(&armado), &bob)), CLARO);
    }

    /// La pública de `secret` con la subclave `index` reatada con **exactamente** esos
    /// `flags`: el builder de rPGP no deja armar un flag que el algoritmo no soporta
    /// (el caso de una clave mal marcada que llega de afuera), así que se re-firma la
    /// binding a mano.
    fn con_subclave_reatada_con_flags(
        secret: &SignedSecretKey,
        index: usize,
        flags: KeyFlags,
    ) -> SignedPublicKey {
        let mut public = publica(secret);
        let subkey = public.public_subkeys[index].clone();
        let primaria = &secret.primary_key;
        let mut config = SignatureConfig::from_key(OsRng, primaria, SignatureType::SubkeyBinding)
            .expect("config");
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
            Subpacket::regular(SubpacketData::KeyFlags(flags)).unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(primaria.fingerprint())).unwrap(),
        ];
        public.public_subkeys[index].signatures = vec![config
            .sign_subkey_binding(primaria, primaria.public_key(), &vacia(), &subkey.key)
            .expect("firma de la unión")];
        public
    }

    // ── F. Subclave sólo de autenticación ──────────────────────────────

    fn solo_autenticacion() -> KeyFlags {
        let mut flags = KeyFlags::default();
        flags.set_authentication(true);
        flags
    }

    #[test]
    fn una_subclave_solo_de_autenticacion_que_podria_firmar_no_firma() {
        // Con el flag de autenticación fuera de `any_flag`, la binding «sin flags»
        // caía al algoritmo: una auth-only Ed25519 se elegía para firmar.
        let ahora = Timestamp::now().as_secs();
        let alice = generar(
            "Alice <alice@vasak.test>",
            vec![{
                let mut p = SubkeyParamsBuilder::default();
                p.key_type(KeyType::Ed25519Legacy)
                    .can_sign(false)
                    .can_encrypt(EncryptionCaps::None)
                    .can_authenticate(true);
                p.build().expect("params de la subclave de autenticación")
            }],
        );
        let publica_alice = publica(&alice);
        let auth_firma = &publica_alice.public_subkeys[0];
        assert!(
            auth_firma.signatures.iter().any(|s| {
                let f = s.key_flags();
                f.authentication() && !f.sign() && !f.encrypt_comms()
            }),
            "el fixture tiene que ser sólo de autenticación"
        );
        assert!(!subkey_usable(auth_firma, ahora, Usage::Sign));
        assert!(!subkey_usable(auth_firma, ahora, Usage::Encrypt));
        // Sin otra subclave de firma, firma la primaria; nunca la auth-only.
        assert!(matches!(
            signing_component(&alice, ahora),
            Some(Signer::Primary)
        ));
    }

    #[test]
    fn una_subclave_solo_de_autenticacion_que_podria_cifrar_no_cifra() {
        // Lo mismo para cifrar: una auth-only ECDH se elegía por su algoritmo.
        let ahora = Timestamp::now().as_secs();
        let bob = generar("Bob <bob@vasak.test>", vec![subclave_de_cifrado(None)]);
        let publica_bob = con_subclave_reatada_con_flags(&bob, 0, solo_autenticacion());
        assert!(!subkey_usable(
            &publica_bob.public_subkeys[0],
            ahora,
            Usage::Encrypt
        ));
        assert!(encryption_subkey(&publica_bob).is_none());
    }

    // ── G. Flag erróneo + algoritmo incapaz ────────────────────────────

    #[test]
    fn una_subclave_solo_firma_con_flag_de_cifrado_se_salta_y_se_elige_la_valida() {
        // La binding de la primera subclave dice «cifrado», pero Ed25519 no cifra.
        // Sin exigir el algoritmo, se elegía ésa y `encrypt_to_keys` fallaba sin
        // probar la subclave válida que viene después.
        let bob = generar(
            "Bob <bob@vasak.test>",
            vec![subclave_de_firma(), subclave_de_cifrado(None)],
        );
        let mut cifrar_y_comunicar = KeyFlags::default();
        cifrar_y_comunicar.set_encrypt_comms(true);
        cifrar_y_comunicar.set_encrypt_storage(true);
        let publica = con_subclave_reatada_con_flags(&bob, 0, cifrar_y_comunicar);
        assert!(
            publica.public_subkeys[0]
                .signatures
                .iter()
                .any(|s| s.key_flags().encrypt_comms()),
            "el fixture tiene que llevar el flag de cifrado en la subclave de firma"
        );
        let elegida = encryption_subkey(&publica).expect("queda la subclave válida");
        assert_eq!(
            elegida.fingerprint(),
            bob.secret_subkeys[1].fingerprint(),
            "tiene que ser la de cifrado real, no la sólo-firma mal marcada"
        );
        let armado = encrypt_to_keys(CLARO.as_bytes(), &[publica]).unwrap();
        assert_eq!(texto_abierto(abrir(&correo_inline(&armado), &bob)), CLARO);
    }

    #[test]
    fn una_subclave_solo_cifrado_con_flag_de_firma_no_se_elige_para_firmar() {
        let ahora = Timestamp::now().as_secs();
        let alice = generar("Alice <alice@vasak.test>", vec![subclave_de_cifrado(None)]);
        let mut firmar = KeyFlags::default();
        firmar.set_sign(true);
        let publica = con_subclave_reatada_con_flags(&alice, 0, firmar);
        assert!(
            publica.public_subkeys[0]
                .signatures
                .iter()
                .any(|s| s.key_flags().sign()),
            "el fixture tiene que llevar el flag de firma en la subclave ECDH"
        );
        assert!(!subkey_usable(
            &publica.public_subkeys[0],
            ahora,
            Usage::Sign
        ));
        // Cae a la primaria, y la firma que sale verifica.
        assert!(matches!(
            signing_component(&alice, ahora),
            Some(Signer::Primary)
        ));
        let firma = sign_detached(CONTENIDO.as_bytes(), &alice, &vacia()).unwrap();
        assert!(matches!(
            verify(&correo_firmado(CONTENIDO, &firma), &[publica]),
            Verification::SignedUntrusted(_)
        ));
    }

    // ── H. `verify` exige un componente de firma usable ────────────────
    //
    // Antes de PR4, `verify_*` aceptaba cualquier componente cuya firma cerrara:
    // una subclave expirada, revocada o sin flag de firma elevaba el mensaje a
    // «clave conocida». Estas pruebas firman **con la secreta de esa subclave** (lo
    // que hace el atacante, o el dueño con una clave muerta) y miran qué dice `verify`.

    use pgp::composed::DetachedSignature as Detached;
    use pgp::types::SigningKey;

    fn subclave_de_firma_creada(creada: Timestamp) -> SubkeyParams {
        let mut p = SubkeyParamsBuilder::default();
        p.key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .can_authenticate(false)
            .created_at(creada);
        p.build().expect("params de la subclave de firma")
    }

    fn flags_de_firma() -> KeyFlags {
        let mut flags = KeyFlags::default();
        flags.set_sign(true);
        flags
    }

    fn flags_de_cifrado() -> KeyFlags {
        let mut flags = KeyFlags::default();
        flags.set_encrypt_comms(true);
        flags.set_encrypt_storage(true);
        flags
    }

    /// Firma de unión (o de revocación) de la subclave `subkey` con `flags` y
    /// vencimiento opcional, hecha por la primaria de `secret`.
    fn union_con_flags(
        secret: &SignedSecretKey,
        subkey: &SignedPublicSubKey,
        typ: SignatureType,
        flags: KeyFlags,
        expiracion: Option<u32>,
    ) -> pgp::packet::Signature {
        let primaria = &secret.primary_key;
        let mut config = SignatureConfig::from_key(OsRng, primaria, typ).expect("config");
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
            Subpacket::regular(SubpacketData::KeyFlags(flags)).unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(primaria.fingerprint())).unwrap(),
        ];
        if let Some(segundos) = expiracion {
            config.hashed_subpackets.push(
                Subpacket::regular(SubpacketData::KeyExpirationTime(PgpDuration::from_secs(
                    segundos,
                )))
                .unwrap(),
            );
        }
        config
            .sign_subkey_binding(primaria, primaria.public_key(), &vacia(), &subkey.key)
            .expect("firma de la unión")
    }

    /// La pública de `secret` con la subclave 0 (la de firma) reatada con esos
    /// `flags`, ese vencimiento y, si `revocada`, con su revocación.
    fn firma_reatada(
        secret: &SignedSecretKey,
        flags: KeyFlags,
        expiracion: Option<u32>,
        revocada: bool,
    ) -> SignedPublicKey {
        let mut public = publica(secret);
        let subkey = public.public_subkeys[0].clone();
        let mut firmas = vec![union_con_flags(
            secret,
            &subkey,
            SignatureType::SubkeyBinding,
            flags,
            expiracion,
        )];
        if revocada {
            firmas.push(union_con_flags(
                secret,
                &subkey,
                SignatureType::SubkeyRevocation,
                KeyFlags::default(),
                None,
            ));
        }
        public.public_subkeys[0].signatures = firmas;
        public
    }

    /// Los dos caminos de firma entrante, con la misma firmante: PGP/MIME (firma
    /// separada) e inline (cleartext). Devuelve `(nombre, correo)`.
    fn correos_firmados_por(firmante: &impl SigningKey) -> Vec<(&'static str, Vec<u8>)> {
        let separada = Detached::sign_binary_data(
            OsRng,
            firmante,
            &vacia(),
            HashAlgorithm::Sha256,
            CONTENIDO.as_bytes(),
        )
        .expect("firma separada")
        .to_armored_bytes(Default::default())
        .expect("armadura");
        vec![
            ("pgp/mime", correo_firmado(CONTENIDO, &separada)),
            (
                "cleartext",
                correo_con(&cleartext_de("hola en claro", firmante)),
            ),
        ]
    }

    fn assert_no_verifica(correos: Vec<(&'static str, Vec<u8>)>, candidata: &SignedPublicKey) {
        for (via, correo) in correos {
            assert!(
                matches!(
                    verify(&correo, std::slice::from_ref(candidata)),
                    Verification::Unverified(_)
                ),
                "{via}: una firma con un componente inservible no puede elevar a «clave conocida»"
            );
        }
    }

    #[test]
    fn la_firma_de_una_subclave_vigente_con_flag_de_firma_verifica() {
        // Control de las pruebas de abajo: el mismo montaje, con el componente sano,
        // verifica. Si no, los «no verifica» serían vacíos.
        let alice = generar(
            "Alice <alice@vasak.test>",
            vec![subclave_de_firma_creada(hace_un_ano())],
        );
        let candidata = firma_reatada(&alice, flags_de_firma(), Some(2 * UN_ANO), false);
        for (via, correo) in correos_firmados_por(&*alice.secret_subkeys[0]) {
            assert_eq!(
                verify(&correo, std::slice::from_ref(&candidata)),
                Verification::SignedUntrusted(alice.primary_key.fingerprint().to_string()),
                "{via}"
            );
        }
    }

    #[test]
    fn la_firma_de_una_subclave_expirada_no_eleva_a_clave_conocida() {
        let alice = generar(
            "Alice <alice@vasak.test>",
            vec![subclave_de_firma_creada(hace_un_ano())],
        );
        // Creada hace un año con vencimiento a un día: murió hace ~364 días.
        let candidata = firma_reatada(&alice, flags_de_firma(), Some(24 * 3600), false);
        assert_no_verifica(correos_firmados_por(&*alice.secret_subkeys[0]), &candidata);
    }

    #[test]
    fn la_firma_de_una_subclave_revocada_no_eleva_a_clave_conocida() {
        let alice = clave_completa("Alice <alice@vasak.test>");
        let candidata = firma_reatada(&alice, flags_de_firma(), None, true);
        assert_no_verifica(correos_firmados_por(&*alice.secret_subkeys[0]), &candidata);
    }

    #[test]
    fn la_firma_de_una_subclave_sin_flag_de_firma_no_eleva_a_clave_conocida() {
        let alice = clave_completa("Alice <alice@vasak.test>");
        // La binding la declara sólo de cifrado, o sólo de autenticación.
        for (que, flags) in [
            ("sólo cifrado", flags_de_cifrado()),
            ("sólo autenticación", solo_autenticacion()),
        ] {
            let candidata = firma_reatada(&alice, flags, None, false);
            for (via, correo) in correos_firmados_por(&*alice.secret_subkeys[0]) {
                assert!(
                    matches!(
                        verify(&correo, std::slice::from_ref(&candidata)),
                        Verification::Unverified(_)
                    ),
                    "{que} / {via}: no firma, no puede elevar"
                );
            }
        }
    }

    #[test]
    fn la_firma_de_una_primaria_revocada_o_expirada_no_eleva_a_clave_conocida() {
        let alice = clave_vieja("Alice <alice@vasak.test>");
        // Control: la primaria sana verifica (la firma la hace la primaria).
        for (via, correo) in correos_firmados_por(&alice.primary_key) {
            assert_eq!(
                verify(&correo, &[publica(&alice)]),
                Verification::SignedUntrusted(alice.primary_key.fingerprint().to_string()),
                "control {via}"
            );
        }
        for (que, muerta) in [
            ("revocada", con_primaria_revocada(&alice)),
            (
                "expirada",
                con_primaria_con_vencimiento_directo(&alice, 24 * 3600),
            ),
        ] {
            for (via, correo) in correos_firmados_por(&alice.primary_key) {
                assert!(
                    matches!(
                        verify(&correo, std::slice::from_ref(&muerta)),
                        Verification::Unverified(_)
                    ),
                    "primaria {que} / {via}"
                );
            }
        }
    }

    #[test]
    fn is_pgp_signed_reconoce_pgp_mime_e_inline_y_no_a_s_mime_ni_al_texto_plano() {
        let alice = clave_completa("Alice <alice@vasak.test>");
        for (via, correo) in correos_firmados_por(&alice.primary_key) {
            assert!(is_pgp_signed(&correo), "{via}");
        }
        let smime = b"From: a@vasak.test\r\nContent-Type: multipart/signed; \
protocol=\"application/pkcs7-signature\"; boundary=\"S\"\r\n\r\n--S\r\nx\r\n--S--\r\n";
        assert!(!is_pgp_signed(smime), "S/MIME no es PGP");
        assert!(!is_pgp_signed(
            b"From: a@vasak.test\r\nContent-Type: text/plain\r\n\r\nhola\r\n"
        ));
    }

    // ── Hallazgos de revisión del sync entrante (PR4) ──────────────────

    /// Un correo cuyo cuerpo (`Content-Type: text/plain`) es `cuerpo`, tal cual.
    fn correo_texto(cuerpo: &str) -> Vec<u8> {
        correo_con(cuerpo)
    }

    #[test]
    fn el_cleartext_pelado_sin_cabeceras_ni_texto_alrededor_sigue_verificando_como_conocido() {
        // El interior de un sign-then-encrypt llega sin cabeceras MIME: no se puede
        // romper ese caso legítimo al exigir que el bloque sea todo el cuerpo.
        let alice = clave_completa("Alice <alice@vasak.test>");
        let esperado = Verification::SignedUntrusted(alice.primary_key.fingerprint().to_string());
        let bloque = cleartext_de("hola en claro", &*alice.secret_subkeys[0]);
        for (que, raw) in [
            ("pelado", bloque.clone().into_bytes()),
            (
                "pelado con saltos al borde",
                format!("\r\n{bloque}\r\n").into_bytes(),
            ),
            ("con cabeceras", correo_texto(&bloque)),
        ] {
            assert_eq!(verify(&raw, &[publica(&alice)]), esperado, "{que}");
        }
    }

    #[test]
    fn el_texto_antepuesto_o_pospuesto_al_bloque_firmado_no_se_marca_firmado() {
        // Anti-spoof: la firma sólo cubre su bloque, pero la vista muestra todo.
        let alice = clave_completa("Alice <alice@vasak.test>");
        let bloque = cleartext_de("pago 100 pesos", &*alice.secret_subkeys[0]);
        let casos = [
            (
                "antepuesto, con cabeceras",
                correo_texto(&format!(
                    "El banco confirma tu transferencia de 9 millones.\r\n\r\n{bloque}"
                )),
            ),
            (
                "pospuesto, con cabeceras",
                correo_texto(&format!("{bloque}\r\nDepositá a la cuenta 123.\r\n")),
            ),
            (
                "pospuesto, pelado",
                format!("{bloque}\r\nTexto del atacante\r\n").into_bytes(),
            ),
        ];
        for (que, raw) in casos {
            assert!(
                matches!(
                    verify(&raw, &[publica(&alice)]),
                    Verification::Unverified(_)
                ),
                "{que}: con contenido fuera del bloque no puede quedar firmado"
            );
        }
    }

    #[test]
    fn el_cleartext_inline_con_utf8_no_ascii_verifica_como_conocido() {
        let alice = clave_completa("Alice <alice@vasak.test>");
        let esperado = Verification::SignedUntrusted(alice.primary_key.fingerprint().to_string());
        let bloque = cleartext_de("canción de cuna — ñandú ✓ 日本", &*alice.secret_subkeys[0]);
        assert_eq!(verify(&correo_texto(&bloque), &[publica(&alice)]), esperado);
        // Y una alteración sigue sin cerrar (el UTF-8 no relaja nada).
        let alterado = bloque.replace("ñandú", "ñandu");
        assert!(matches!(
            verify(&correo_texto(&alterado), &[publica(&alice)]),
            Verification::Unverified(_)
        ));
    }

    /// Cifra `claro` a `para` repetido `veces` (un PKESK por vez, todos a la misma clave).
    fn cifrar_con_pkesk_repetidos(claro: &[u8], para: &SignedPublicKey, veces: usize) -> Vec<u8> {
        encrypt_to_keys(claro, &vec![para.clone(); veces]).expect("el cifrado sale")
    }

    #[test]
    fn mas_de_16_pkesk_dirigidos_a_nuestra_clave_se_rechazan_antes_de_descifrar() {
        let bob = clave_completa("Bob <bob@vasak.test>");
        // En el tope abre (control: la cota no rompe lo legítimo)...
        let justo = cifrar_con_pkesk_repetidos(CLARO.as_bytes(), &publica(&bob), 16);
        assert_eq!(texto_abierto(abrir(&correo_inline(&justo), &bob)), CLARO);
        // ...y uno más se corta, con un motivo que no filtra el claro.
        let pasado = cifrar_con_pkesk_repetidos(CLARO.as_bytes(), &publica(&bob), 17);
        match abrir(&correo_inline(&pasado), &bob) {
            Decryption::Unavailable(motivo) => {
                assert!(motivo.contains("PKESK"), "motivo: {motivo}");
            }
            otro => panic!("se esperaba Unavailable, salió {otro:?}"),
        }
    }

    #[test]
    fn los_pkesk_de_otros_destinatarios_no_cuentan_para_la_cota() {
        let bob = clave_completa("Bob <bob@vasak.test>");
        let otras: Vec<SignedPublicKey> = (0..20)
            .map(|i| publica(&clave_completa(&format!("Otro{i} <o{i}@vasak.test>"))))
            .collect();
        let mut destinatarios = otras;
        destinatarios.push(publica(&bob));
        let armado = encrypt_to_keys(CLARO.as_bytes(), &destinatarios).unwrap();
        assert_eq!(texto_abierto(abrir(&correo_inline(&armado), &bob)), CLARO);
    }

    #[test]
    fn la_firma_de_una_subclave_bajo_una_primaria_revocada_o_expirada_no_eleva_a_clave_conocida() {
        let alice = clave_vieja("Alice <alice@vasak.test>");
        // Control: con la primaria sana, la subclave de firma verifica por las dos vías.
        for (via, correo) in correos_firmados_por(&*alice.secret_subkeys[0]) {
            assert_eq!(
                verify(&correo, &[publica(&alice)]),
                Verification::SignedUntrusted(alice.primary_key.fingerprint().to_string()),
                "control {via}"
            );
        }
        for (que, muerta) in [
            ("revocada", con_primaria_revocada(&alice)),
            (
                "expirada",
                con_primaria_con_vencimiento_directo(&alice, 24 * 3600),
            ),
        ] {
            assert!(
                subkey_usable(
                    &muerta.public_subkeys[0],
                    Timestamp::now().as_secs(),
                    Usage::Sign
                ),
                "premisa: la subclave sola sigue vigente, la mata la primaria"
            );
            for (via, correo) in correos_firmados_por(&*alice.secret_subkeys[0]) {
                assert!(
                    matches!(
                        verify(&correo, std::slice::from_ref(&muerta)),
                        Verification::Unverified(_)
                    ),
                    "subclave bajo primaria {que} / {via}"
                );
            }
        }
    }

    /// Una firma de `atacante` sobre **su propia** clave (`Key` directa o `CertPositive`
    /// de su UID), con `created` una hora en el futuro (gana a cualquier auto-firma
    /// legítima en «la más reciente») y `KeyExpirationTime` = `expiracion`. Pegada a la
    /// clave de la víctima, no verifica contra la primaria de ésta.
    fn firma_forjada_del_futuro(
        atacante: &SignedSecretKey,
        typ: SignatureType,
        expiracion: u32,
    ) -> pgp::packet::Signature {
        let primaria = &atacante.primary_key;
        let futuro = Timestamp::from_secs(Timestamp::now().as_secs() + 3600);
        let mut config = SignatureConfig::from_key(OsRng, primaria, typ).expect("config");
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(futuro)).unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(primaria.fingerprint())).unwrap(),
            Subpacket::regular(SubpacketData::KeyExpirationTime(PgpDuration::from_secs(
                expiracion,
            )))
            .unwrap(),
        ];
        match typ {
            SignatureType::Key => config
                .sign_key(primaria, &vacia(), primaria.public_key())
                .expect("firma directa"),
            _ => config
                .sign_certification(
                    primaria,
                    primaria.public_key(),
                    &vacia(),
                    pgp::types::Tag::UserId,
                    &publica(atacante).details.users[0].id,
                )
                .expect("certificación del UID"),
        }
    }

    /// Las dos formas de la forjada: pegada como certificación de UID y como directa.
    fn con_forjada(
        victima: &SignedPublicKey,
        atacante: &SignedSecretKey,
        expiracion: u32,
    ) -> Vec<(&'static str, SignedPublicKey)> {
        let mut por_uid = victima.clone();
        por_uid.details.users[0]
            .signatures
            .push(firma_forjada_del_futuro(
                atacante,
                SignatureType::CertPositive,
                expiracion,
            ));
        let mut directa = victima.clone();
        directa
            .details
            .direct_signatures
            .push(firma_forjada_del_futuro(
                atacante,
                SignatureType::Key,
                expiracion,
            ));
        vec![
            ("certificación de UID", por_uid),
            ("firma directa", directa),
        ]
    }

    #[test]
    fn una_certificacion_forjada_que_dice_expirada_no_inutiliza_una_clave_viva() {
        let bob = clave_vieja("Bob <bob@vasak.test>");
        let atacante = clave_vieja("Atacante <atacante@vasak.test>");
        let ahora = Timestamp::now().as_secs();
        assert!(primary_usable(&publica(&bob), ahora), "premisa: viva");

        for (que, forjada) in con_forjada(&publica(&bob), &atacante, 24 * 3600) {
            assert!(primary_usable(&forjada, ahora), "{que}");
            assert!(encryption_subkey(&forjada).is_some(), "{que}");
        }

        // Control: la misma firma pero **válida** (de la propia primaria) sí la expira.
        let expirada = con_primaria_con_vencimiento_en_el_uid(&bob, 24 * 3600);
        assert!(!primary_usable(&expirada, ahora));
    }

    #[test]
    fn una_certificacion_forjada_con_nunca_expira_no_revive_una_clave_expirada() {
        let bob = clave_vieja("Bob <bob@vasak.test>");
        let atacante = clave_vieja("Atacante <atacante@vasak.test>");
        let ahora = Timestamp::now().as_secs();
        let expirada = con_primaria_con_vencimiento_en_el_uid(&bob, 24 * 3600);
        assert!(!primary_usable(&expirada, ahora), "premisa: expirada");
        for (que, forjada) in con_forjada(&expirada, &atacante, 0) {
            assert!(!primary_usable(&forjada, ahora), "{que}: no la revive");
        }
    }

    /// La pública de `secret` con la subclave `index` reatada con una firma de binding
    /// creada `hace_un_ano()` cuya **propia** expiración es `expiracion_de_la_firma`
    /// (la clave en sí no vence).
    fn con_binding_que_expira(
        secret: &SignedSecretKey,
        index: usize,
        flags: KeyFlags,
        expiracion_de_la_firma: Option<u32>,
    ) -> SignedPublicKey {
        let mut public = publica(secret);
        let subkey = public.public_subkeys[index].clone();
        let primaria = &secret.primary_key;
        let mut config =
            SignatureConfig::from_key(OsRng, primaria, SignatureType::SubkeyBinding).unwrap();
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(hace_un_ano())).unwrap(),
            Subpacket::regular(SubpacketData::KeyFlags(flags)).unwrap(),
            Subpacket::regular(SubpacketData::IssuerFingerprint(primaria.fingerprint())).unwrap(),
        ];
        if let Some(segundos) = expiracion_de_la_firma {
            config.hashed_subpackets.push(
                Subpacket::regular(SubpacketData::SignatureExpirationTime(
                    PgpDuration::from_secs(segundos),
                ))
                .unwrap(),
            );
        }
        public.public_subkeys[index].signatures = vec![config
            .sign_subkey_binding(primaria, primaria.public_key(), &vacia(), &subkey.key)
            .expect("firma de la unión")];
        public
    }

    #[test]
    fn una_subclave_con_la_firma_de_binding_vencida_se_rechaza_aunque_la_clave_no_expire() {
        let bob = clave_completa("Bob <bob@vasak.test>");
        let ahora = Timestamp::now().as_secs();
        // Subclave 1 = cifrado. Control: binding sin expiración propia, o con una
        // futura (hace un año + dos años), sirve.
        for (que, expiracion) in [
            ("sin expiración", None),
            ("futura", Some(2 * UN_ANO)),
            ("cero", Some(0)),
        ] {
            let ok = con_binding_que_expira(&bob, 1, flags_de_cifrado(), expiracion);
            assert!(
                subkey_usable(&ok.public_subkeys[1], ahora, Usage::Encrypt),
                "{que}"
            );
            assert!(encryption_subkey(&ok).is_some(), "{que}");
        }
        // Vencida hace ~364 días.
        let vencida = con_binding_que_expira(&bob, 1, flags_de_cifrado(), Some(24 * 3600));
        assert!(!subkey_usable(
            &vencida.public_subkeys[1],
            ahora,
            Usage::Encrypt
        ));
        assert!(encryption_subkey(&vencida).is_none());
        assert!(matches!(
            encrypt_to_keys(b"x", &[vencida]),
            Err(PgpError::NoEncryptionKey(_))
        ));
    }

    /// Un correo PGP/MIME cuyo `application/octet-stream` lleva `cte` y `cuerpo`.
    fn correo_pgp_mime_con_cte(cte: &str, cuerpo: &str) -> Vec<u8> {
        format!(
            "From: a@vasak.test\r\nContent-Type: multipart/encrypted; \
protocol=\"application/pgp-encrypted\"; boundary=\"B\"\r\n\r\n--B\r\n\
Content-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--B\r\n\
Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: {cte}\r\n\r\n\
{cuerpo}\r\n--B--\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn un_sobre_pgp_mime_en_base64_se_decodifica_y_se_abre() {
        let bob = clave_completa("Bob <bob@vasak.test>");
        let armado = cifrar(CLARO.as_bytes(), &publica(&bob));
        let mut binario = Vec::new();
        Dearmor::new(&armado[..]).read_to_end(&mut binario).unwrap();
        for (que, bytes) in [
            ("armadura en base64", armado.clone()),
            ("binario en base64", binario),
        ] {
            let raw = correo_pgp_mime_con_cte("base64", &base64_en_lineas(&bytes));
            assert!(is_pgp_encrypted(&raw), "{que}");
            assert_eq!(texto_abierto(abrir(&raw, &bob)), CLARO, "{que}");
        }
        // Control: 7bit con la armadura cruda sigue abriendo.
        let cruda = String::from_utf8(armado).unwrap();
        assert_eq!(
            texto_abierto(abrir(&correo_pgp_mime_con_cte("7bit", &cruda), &bob)),
            CLARO
        );
    }

    #[test]
    fn un_correo_que_cita_un_bloque_pgp_con_texto_alrededor_no_se_trata_como_cifrado() {
        let bob = clave_completa("Bob <bob@vasak.test>");
        let bloque = String::from_utf8(cifrar(CLARO.as_bytes(), &publica(&bob))).unwrap();
        let respuesta = correo_texto(&format!(
            "El jueves escribiste:\r\n\r\n{bloque}\r\nNo lo pude abrir, ¿lo mandás de nuevo?\r\n"
        ));
        assert!(!is_pgp_encrypted(&respuesta));
        assert!(matches!(abrir(&respuesta, &bob), Decryption::NotEncrypted));
        // Control: el mismo bloque como único contenido sí es un sobre.
        assert!(is_pgp_encrypted(&correo_texto(&bloque)));
    }

    #[test]
    fn is_pgp_signed_no_toma_por_firmado_lo_que_verify_no_ve_como_bloque_propio() {
        let alice = clave_completa("Alice <alice@vasak.test>");
        let bloque = cleartext_de("pago 100 pesos", &*alice.secret_subkeys[0]);
        let candidatas = [publica(&alice)];

        // El marcador está en el raw pero no en la región que `verify` escanea: sin
        // bloque propio completo, los dos coinciden en «no firmado».
        let sin_fin = bloque
            .split("-----BEGIN PGP SIGNATURE-----")
            .next()
            .unwrap();
        for (que, raw) in [
            // Sin línea en blanco de por medio, el texto y el marcador quedan como
            // «cabeceras» y el cuerpo no trae el bloque.
            (
                "texto pegado antes del marcador",
                format!("Mirá esto:\r\n{bloque}").into_bytes(),
            ),
            (
                "bloque sin fin, citado",
                correo_texto(&format!("mirá este mensaje:\r\n{sin_fin}")),
            ),
            (
                "marcador suelto en el texto",
                correo_texto("la armadura empieza con -----BEGIN PGP SIGNED MESSAGE-----"),
            ),
        ] {
            assert!(!is_pgp_signed(&raw), "{que}");
            assert_eq!(verify(&raw, &candidatas), Verification::NotSigned, "{que}");
        }

        // Controles positivos: el cuerpo ES el bloque (con cabeceras o pelado) y PGP/MIME.
        assert!(is_pgp_signed(&correo_texto(&bloque)));
        assert!(is_pgp_signed(bloque.as_bytes()));
        let firma = sign_detached(CONTENIDO.as_bytes(), &alice, &vacia()).unwrap();
        assert!(is_pgp_signed(&correo_firmado(CONTENIDO, &firma)));

        // Un bloque completo con texto alrededor sí «parece firmado» para ambos: `verify`
        // lo rechaza como no verificable (no como no firmado), y es el mismo criterio.
        let con_texto = correo_texto(&format!("Escribiste:\r\n{bloque}\r\nOk.\r\n"));
        assert!(is_pgp_signed(&con_texto));
        assert!(matches!(
            verify(&con_texto, &candidatas),
            Verification::Unverified(_)
        ));
    }
}
