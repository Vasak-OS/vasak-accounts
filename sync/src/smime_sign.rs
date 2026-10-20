//! Firmar y verificar correo S/MIME (SignedData / PKCS#7). vasak-mail#78.
//!
//! **Firmar** produce `multipart/signed` con firma separada
//! (`application/pkcs7-signature`): interoperable, y el cuerpo se lee aunque el
//! cliente no entienda S/MIME. La firma va sobre los bytes **exactos** de la
//! entidad de contenido ([`crate::compose::build_content_entity`]), tal como se
//! transmiten; lo que se firma y lo que se manda son los mismos bytes.
//!
//! **Verificar** acepta las dos formas que llegan: `multipart/signed` y el opaque
//! `application/pkcs7-mime; smime-type=signed-data`. Chequea, como validó el POC:
//! la firma (RSA PKCS#1 v1.5 o ECDSA P-256), los *signed attributes*
//! (`messageDigest` = SHA-256 del contenido, `contentType`), y que el certificado
//! del firmante **esté ligado al `From`**.
//!
//! **Pero NO declara ninguna firma «válida» todavía.** No hay validación de
//! confianza X.509 —cadena hasta una CA de confianza, ancla, vigencia,
//! revocación, ESS `signingCertificate`—, y sin eso un certificado **autofirmado**
//! con `SubjectAltName rfc822=ceo@víctima.com` y `From: ceo@víctima.com` pasaría
//! las cuatro comprobaciones de arriba: decir «válido» ahí sería una mentira en
//! un correo falsificado. Así que mientras falte la validación de confianza, lo
//! más que se dice es **«firmado, no verificado — <firmante>»**
//! ([`Verification::SignedUntrusted`]), nunca «válido» (decisión #2: lo no
//! implementado se ve «no disponible», nunca una mentira). El estado «válido»
//! queda reservado para el follow-up «validación de confianza X.509».

use base64::prelude::{Engine as _, BASE64_STANDARD};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::ContentInfo;
use cms::enveloped_data::{EnvelopedData, RecipientIdentifier, RecipientInfo};
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier};
use der::asn1::{ObjectIdentifier, OctetString, SetOfVec};
use der::{Decode, Encode};
use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigningKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Oaep, Pkcs1v15Encrypt, RsaPrivateKey};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use signature::Verifier;
use spki::{AlgorithmIdentifierOwned, SignatureBitStringEncoding};
use x509_cert::attr::Attribute;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::Certificate;
use zeroize::Zeroizing;

use crate::message::{
    as_latin1, from_latin1, parse_content_type, parse_sender, split_headers, split_parts,
};

const ID_DATA: ObjectIdentifier = const_oid::db::rfc5911::ID_DATA;
const ID_SIGNED_DATA: ObjectIdentifier = const_oid::db::rfc5911::ID_SIGNED_DATA;
const ID_ENVELOPED_DATA: ObjectIdentifier = const_oid::db::rfc5911::ID_ENVELOPED_DATA;
const ID_RSAES_OAEP: ObjectIdentifier = const_oid::db::rfc5912::ID_RSAES_OAEP;
const ID_AES_128_CBC: ObjectIdentifier = const_oid::db::rfc5911::ID_AES_128_CBC;
const ID_AES_192_CBC: ObjectIdentifier = const_oid::db::rfc5911::ID_AES_192_CBC;
const ID_AES_256_CBC: ObjectIdentifier = const_oid::db::rfc5911::ID_AES_256_CBC;
/// Los `protocol` de un `multipart/signed` que son S/MIME (no PGP).
const PKCS7_SIGNATURE_PROTOCOLS: [&str; 2] = [
    "application/pkcs7-signature",
    "application/x-pkcs7-signature",
];
const ID_SHA_256: ObjectIdentifier = const_oid::db::rfc5912::ID_SHA_256;
const ID_MESSAGE_DIGEST: ObjectIdentifier = const_oid::db::rfc5911::ID_MESSAGE_DIGEST;
const ID_CONTENT_TYPE: ObjectIdentifier = const_oid::db::rfc5911::ID_CONTENT_TYPE;
const RSA_ENCRYPTION: ObjectIdentifier = const_oid::db::rfc5912::RSA_ENCRYPTION;
const ID_EC_PUBLIC_KEY: ObjectIdentifier = const_oid::db::rfc5912::ID_EC_PUBLIC_KEY;
/// `emailAddress` (PKCS#9), por si el cert no trae SubjectAltName.
const EMAIL_ADDRESS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");
/// `id-ce-subjectAltName`.
const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

// ── Estado expuesto a la ventana ──────────────────────────────────────

/// El estado S/MIME de un mensaje, como lo ve quien lo lee. `None` quiere decir
/// que no venía ni firmado ni cifrado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SmimeStatus {
    /// La firma pasó la **validación de confianza X.509** (cadena hasta una CA,
    /// vigencia, revocación). Hoy **siempre `false`**: esa validación es un
    /// follow-up. Hasta entonces un correo firmado se ve «firmado, no verificado».
    pub valid: bool,
    /// El firmante (el correo del certificado) cuando la firma criptográfica, el
    /// digest y el binding al `From` cerraron, aunque todavía no se valide la
    /// confianza. `None` si la firma no se pudo comprobar.
    pub signer: Option<String>,
    /// El estado de cifrado: `None` si no venía cifrado. La ventana distingue un
    /// candado normal (`Opened`) de «cifrado, no se pudo abrir» (`Unavailable`,
    /// p. ej. destinatario ECC o sin nuestra clave).
    pub encryption: Option<Encryption>,
}

/// Cómo quedó un mensaje **cifrado** después de intentar abrirlo al bajarlo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Encryption {
    /// Cifrado y abierto: el cuerpo que se muestra es el descifrado.
    Opened,
    /// Cifrado pero no se pudo abrir (ECC, sin nuestra clave, cifrado no
    /// soportado). El cuerpo no está disponible; nunca «roto».
    Unavailable,
}

/// El resultado de verificar un mensaje entrante.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// No venía firmado.
    NotSigned,
    /// Firmado, con la firma criptográfica + digest + binding al `From` en orden,
    /// pero **sin** validar la confianza X.509 (follow-up). Trae el firmante. La
    /// ventana muestra «firmado, no verificado — <firmante>», **nunca «válido»**.
    SignedUntrusted(String),
    /// Firmado pero la firma no se pudo comprobar (rota, digest que no coincide,
    /// firmante que no liga al `From`). El motivo es para el diario.
    Unverified(String),
}

// ── Firmar ────────────────────────────────────────────────────────────

/// Lo que puede salir mal al firmar.
#[derive(Debug)]
pub enum SignError {
    /// No hay certificado/clave S/MIME para esta identidad.
    NoIdentity,
    /// La clave privada no es RSA ni ECDSA P-256.
    UnsupportedKey,
    /// El certificado del `.p12` no se pudo leer.
    BadCertificate(String),
    /// La cripto falló.
    Crypto(String),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::NoIdentity => f.write_str("no hay certificado S/MIME para esta dirección"),
            SignError::UnsupportedKey => f.write_str("la clave S/MIME no es RSA ni ECDSA P-256"),
            SignError::BadCertificate(d) => write!(f, "el certificado S/MIME no se pudo leer: {d}"),
            SignError::Crypto(d) => write!(f, "no se pudo firmar: {d}"),
        }
    }
}

impl std::error::Error for SignError {}

/// La clave con la que se firma, según su tipo. Vive un instante (se arma, se
/// firma, se suelta), así que la diferencia de tamaño entre RSA y ECDSA no
/// justifica una caja.
#[allow(clippy::large_enum_variant)]
enum SignerKey {
    Rsa(RsaSigningKey<Sha256>),
    P256(p256::ecdsa::SigningKey),
}

fn load_signer_key(pkcs8_der: &[u8]) -> Result<SignerKey, SignError> {
    if let Ok(rsa) = RsaPrivateKey::from_pkcs8_der(pkcs8_der) {
        return Ok(SignerKey::Rsa(RsaSigningKey::<Sha256>::new(rsa)));
    }
    if let Ok(ec) = p256::ecdsa::SigningKey::from_pkcs8_der(pkcs8_der) {
        return Ok(SignerKey::P256(ec));
    }
    Err(SignError::UnsupportedKey)
}

/// Firma `content` (los bytes exactos de la entidad de contenido) y devuelve el
/// PKCS#7 `SignedData` **separado** (sin el contenido adentro), con el cert del
/// firmante y su cadena embebidos, listo para la parte `smime.p7s`.
pub fn detached_signature(
    content: &[u8],
    key_pkcs8_der: &[u8],
    certs: &[Vec<u8>],
) -> Result<Vec<u8>, SignError> {
    let leaf_der = certs.first().ok_or(SignError::NoIdentity)?;
    let leaf =
        Certificate::from_der(leaf_der).map_err(|e| SignError::BadCertificate(e.to_string()))?;
    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: leaf.tbs_certificate.issuer.clone(),
        serial_number: leaf.tbs_certificate.serial_number.clone(),
    });

    let digest_algorithm = AlgorithmIdentifierOwned {
        oid: ID_SHA_256,
        parameters: None,
    };
    // Contenido externo (detached): el `eContent` va vacío y se pasa el digest.
    let eci = EncapsulatedContentInfo {
        econtent_type: ID_DATA,
        econtent: None,
    };
    let message_digest = Sha256::digest(content);

    let key = load_signer_key(key_pkcs8_der)?;
    let signed = match key {
        SignerKey::Rsa(signer) => build_signed_data::<_, RsaSignature>(
            &signer,
            sid,
            digest_algorithm,
            &eci,
            message_digest.as_slice(),
            certs,
        ),
        SignerKey::P256(signer) => build_signed_data::<_, p256::ecdsa::DerSignature>(
            &signer,
            sid,
            digest_algorithm,
            &eci,
            message_digest.as_slice(),
            certs,
        ),
    }?;
    Ok(signed)
}

#[allow(clippy::too_many_arguments)]
fn build_signed_data<S, Sig>(
    signer: &S,
    sid: SignerIdentifier,
    digest_algorithm: AlgorithmIdentifierOwned,
    eci: &EncapsulatedContentInfo,
    message_digest: &[u8],
    certs: &[Vec<u8>],
) -> Result<Vec<u8>, SignError>
where
    S: signature::Keypair + spki::DynSignatureAlgorithmIdentifier + signature::Signer<Sig>,
    Sig: SignatureBitStringEncoding,
{
    let signer_info = SignerInfoBuilder::new(
        signer,
        sid,
        digest_algorithm.clone(),
        eci,
        Some(message_digest),
    )
    .map_err(|e| SignError::Crypto(format!("signer info: {e}")))?;

    let mut builder = SignedDataBuilder::new(eci);
    builder
        .add_digest_algorithm(digest_algorithm)
        .map_err(|e| SignError::Crypto(e.to_string()))?;
    for cert_der in certs {
        let cert = Certificate::from_der(cert_der)
            .map_err(|e| SignError::BadCertificate(e.to_string()))?;
        builder
            .add_certificate(CertificateChoices::Certificate(cert))
            .map_err(|e| SignError::Crypto(e.to_string()))?;
    }
    builder
        .add_signer_info::<S, Sig>(signer_info)
        .map_err(|e| SignError::Crypto(format!("firma: {e}")))?;
    builder
        .build()
        .map_err(|e| SignError::Crypto(e.to_string()))?
        .to_der()
        .map_err(|e| SignError::Crypto(e.to_string()))
}

/// Arma el mensaje `multipart/signed`: las cabeceras de dirección, el
/// `Content-Type` de `multipart/signed`, la entidad de contenido (parte 1, firmada
/// byte a byte) y la firma separada (parte 2, `smime.p7s`).
pub fn build_signed_message(
    headers: &[String],
    content_entity: &str,
    signature_der: &[u8],
) -> String {
    // La frontera no puede aparecer en el contenido ni en la firma base64.
    let signature_b64 = BASE64_STANDARD.encode(signature_der);
    let boundary = crate::compose::boundary(&[content_entity, &signature_b64]);

    let mut out = headers.join("\r\n");
    out.push_str(&format!(
        "\r\nContent-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; \
         micalg=\"sha-256\"; boundary=\"{boundary}\"\r\n\r\n"
    ));
    // Parte 1: la entidad de contenido, exactamente lo que se firmó. El `\r\n`
    // que sigue es de la frontera, no del contenido.
    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str(content_entity);
    out.push_str("\r\n");
    // Parte 2: la firma separada.
    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str(
        "Content-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\n\
         Content-Transfer-Encoding: base64\r\n\
         Content-Disposition: attachment; filename=\"smime.p7s\"\r\n\r\n",
    );
    out.push_str(&crate::compose::wrap_base64(&signature_b64));
    out.push_str(&format!("\r\n--{boundary}--\r\n"));
    out
}

// ── Verificar ─────────────────────────────────────────────────────────

/// El `From` de un mensaje (sólo la dirección), para ligar el firmante. En un
/// sign-then-encrypt el `From` está en el **sobre de afuera**, no en el contenido
/// firmado de adentro; por eso se puede pasar aparte a [`verify_message_with_from`].
pub fn message_from(raw: &[u8]) -> String {
    let view = as_latin1(raw);
    let (headers, _) = split_headers(&view);
    headers
        .get("from")
        .map(parse_sender)
        .map(|(_, address)| address)
        .unwrap_or_default()
}

/// Verifica un mensaje entrante. `raw` es el RFC822 crudo (lo que hace falta: la
/// firma va sobre los bytes exactos, no sobre el cuerpo decodificado). El `From`
/// se toma del propio mensaje.
pub fn verify_message(raw: &[u8]) -> Verification {
    let from = message_from(raw);
    verify_message_with_from(raw, &from)
}

/// Como [`verify_message`], pero el `From` para ligar el firmante se pasa aparte:
/// al descifrar un sign-then-encrypt, el contenido firmado no trae `From` (está en
/// el sobre de afuera), así que se liga contra ése.
pub fn verify_message_with_from(raw: &[u8], from: &str) -> Verification {
    let view = as_latin1(raw);
    let (headers, body) = split_headers(&view);
    let content_type = headers
        .get("content-type")
        .map(parse_content_type)
        .unwrap_or_default();

    match content_type.media_type.as_str() {
        "multipart/signed" => {
            // El `protocol` tiene que ser el de S/MIME. Un `multipart/signed` de
            // PGP (`application/pgp-signature`) no es nuestro: `NotSigned`, para
            // no mostrarlo como «S/MIME firmado».
            let is_pkcs7 = content_type
                .protocol
                .as_deref()
                .is_some_and(|p| PKCS7_SIGNATURE_PROTOCOLS.contains(&p));
            if !is_pkcs7 {
                return Verification::NotSigned;
            }
            let Some(boundary) = content_type.boundary.as_deref() else {
                return Verification::Unverified("multipart/signed sin frontera".into());
            };
            let parts = split_parts(body, boundary);
            // RFC 1847: multipart/signed son **exactamente** dos partes (el
            // contenido y la firma). Con más, la vista podría mostrar una parte
            // que la firma no cubre, así que se rechaza.
            if parts.len() != 2 {
                return Verification::Unverified(
                    "multipart/signed no tiene exactamente dos partes".into(),
                );
            }
            // Parte 1: el contenido firmado, sin el CRLF que pertenece a la
            // frontera. Parte 2: la firma (`application/pkcs7-signature`, base64).
            let signed_content = strip_one_trailing_crlf(from_latin1(parts[0]));
            let signature_der = match signature_part(parts[1]) {
                Some(der) => der,
                None => return Verification::Unverified("firma pkcs7 ilegible".into()),
            };
            verify_signed_data(&signature_der, Some(&signed_content), from)
        }
        "application/pkcs7-mime" | "application/x-pkcs7-mime" => {
            // Opaque: el cuerpo base64 es el `ContentInfo`. El tipo real lo dice
            // el OID del CMS, no el parámetro del header: `signed-data` se
            // verifica; `enveloped-data` (cifrado) es `NotSigned` hasta PR4.
            let der = match BASE64_STANDARD.decode(strip_whitespace(&from_latin1(body))) {
                Ok(der) => der,
                Err(_) => return Verification::Unverified("pkcs7-mime base64 ilegible".into()),
            };
            match ContentInfo::from_der(&der).map(|ci| ci.content_type) {
                Ok(oid) if oid == ID_SIGNED_DATA => verify_signed_data(&der, None, from),
                Ok(oid) if oid == ID_ENVELOPED_DATA => Verification::NotSigned,
                Ok(_) => Verification::NotSigned,
                Err(e) => Verification::Unverified(format!("pkcs7-mime ilegible: {e}")),
            }
        }
        _ => Verification::NotSigned,
    }
}

/// El contenido (eContent) de un `pkcs7-mime` opaque **firmado**, para poder
/// mostrarlo: en el opaque el cuerpo real va dentro del PKCS#7, no en el crudo.
/// `None` si no es opaque firmado (el `multipart/signed` ya trae el contenido
/// como parte normal, y el `enveloped-data` es cifrado —PR4—).
pub fn opaque_signed_content(raw: &[u8]) -> Option<Vec<u8>> {
    let view = as_latin1(raw);
    let (headers, body) = split_headers(&view);
    let content_type = headers
        .get("content-type")
        .map(parse_content_type)
        .unwrap_or_default();
    if !matches!(
        content_type.media_type.as_str(),
        "application/pkcs7-mime" | "application/x-pkcs7-mime"
    ) {
        return None;
    }
    let der = BASE64_STANDARD
        .decode(strip_whitespace(&from_latin1(body)))
        .ok()?;
    let ci = ContentInfo::from_der(&der).ok()?;
    if ci.content_type != ID_SIGNED_DATA {
        return None;
    }
    let sd = ci
        .content
        .to_der()
        .ok()
        .and_then(|d| SignedData::from_der(&d).ok())?;
    Some(sd.encap_content_info.econtent?.value().to_vec())
}

/// El DER de la firma de la parte `application/pkcs7-signature` (su cuerpo base64
/// decodificado).
fn signature_part(part: &str) -> Option<Vec<u8>> {
    let (_headers, body) = split_headers(part);
    BASE64_STANDARD
        .decode(strip_whitespace(body.as_bytes()))
        .ok()
}

/// El `SignedData`, con el contenido externo (`multipart/signed`) o embebido
/// (opaque), ligando el firmante a `from`.
fn verify_signed_data(der: &[u8], external: Option<&[u8]>, from: &str) -> Verification {
    let ci = match ContentInfo::from_der(der) {
        Ok(ci) => ci,
        Err(e) => return Verification::Unverified(format!("ContentInfo: {e}")),
    };
    if ci.content_type != ID_SIGNED_DATA {
        return Verification::Unverified("no es signed-data".into());
    }
    let sd = match ci.content.to_der().and_then(|d| SignedData::from_der(&d)) {
        Ok(sd) => sd,
        Err(e) => return Verification::Unverified(format!("SignedData: {e}")),
    };

    // El contenido sobre el que se calcula el digest: externo o el embebido.
    let embedded;
    let content: &[u8] = match external {
        Some(content) => content,
        None => match sd.encap_content_info.econtent.as_ref() {
            Some(any) => {
                embedded = any.value().to_vec();
                &embedded
            }
            None => return Verification::Unverified("signed-data sin contenido".into()),
        },
    };

    let Some(signer_info) = sd.signer_infos.0.iter().next() else {
        return Verification::Unverified("sin SignerInfo".into());
    };
    let Some(signed_attrs) = signer_info.signed_attrs.as_ref() else {
        // S/MIME siempre lleva signed attributes.
        return Verification::Unverified("sin signed attributes".into());
    };

    // El cert del firmante, elegido por el sid entre los embebidos.
    let cert = match signer_certificate(&sd, &signer_info.sid) {
        Some(cert) => cert,
        None => return Verification::Unverified("no está el cert del firmante".into()),
    };

    // 1) La firma sobre los signed-attrs (SET OF), con la clave del cert.
    let signed_attrs_der = match signed_attrs.to_der() {
        Ok(der) => der,
        Err(e) => return Verification::Unverified(format!("signed-attrs: {e}")),
    };
    if let Err(reason) =
        verify_signature(&cert, &signed_attrs_der, signer_info.signature.as_bytes())
    {
        return Verification::Unverified(reason);
    }

    // 2) El messageDigest firmado es el SHA-256 del contenido.
    match signed_attribute(signed_attrs, ID_MESSAGE_DIGEST)
        .and_then(|v| OctetString::from_der(&v).ok())
    {
        Some(md) if md.as_bytes() == Sha256::digest(content).as_slice() => {}
        Some(_) => return Verification::Unverified("messageDigest no coincide".into()),
        None => return Verification::Unverified("sin messageDigest".into()),
    }

    // 3) El contentType firmado tiene que estar (lo exige RFC 5652 con attrs).
    if signed_attribute(signed_attrs, ID_CONTENT_TYPE).is_none() {
        return Verification::Unverified("sin contentType".into());
    }

    // 4) El cert del firmante tiene que estar ligado al `From`. Con los dos lados
    // vacíos `"" == ""` ligaría cualquier cosa, así que se exige que el `From` y
    // el correo del cert **no** estén vacíos.
    let from = from.trim();
    let emails = certificate_emails(&cert);
    let bound = !from.is_empty()
        && emails
            .iter()
            .any(|e| !e.trim().is_empty() && e.trim().eq_ignore_ascii_case(from));
    if !bound {
        return Verification::Unverified("el firmante no coincide con el From".into());
    }

    // Todo lo criptográfico cerró, pero sin validación de confianza X.509 esto NO
    // es «válido»: lo más que se afirma es «firmado, no verificado — <firmante>».
    // Ver el doc del módulo y `Verification::SignedUntrusted`.
    Verification::SignedUntrusted(from.to_string())
}

/// El cert embebido cuyo emisor+serie coincide con el `sid` del firmante.
fn signer_certificate(sd: &SignedData, sid: &SignerIdentifier) -> Option<Certificate> {
    let certs = sd.certificates.as_ref()?;
    certs.0.iter().find_map(|choice| match choice {
        CertificateChoices::Certificate(cert) => {
            let this = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: cert.tbs_certificate.issuer.clone(),
                serial_number: cert.tbs_certificate.serial_number.clone(),
            });
            (this == *sid).then(|| cert.clone())
        }
        _ => None,
    })
}

/// Verifica la firma de los signed-attrs con la clave pública del cert, según
/// sea RSA o ECDSA P-256 (lo dice el algoritmo del SPKI del cert).
fn verify_signature(cert: &Certificate, message: &[u8], signature: &[u8]) -> Result<(), String> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let spki_der = spki.to_der().map_err(|e| e.to_string())?;
    match spki.algorithm.oid {
        RSA_ENCRYPTION => {
            use rsa::pkcs1v15::VerifyingKey;
            use rsa::pkcs8::DecodePublicKey;
            let key = rsa::RsaPublicKey::from_public_key_der(&spki_der)
                .map_err(|e| format!("clave RSA: {e}"))?;
            let sig = RsaSignature::try_from(signature).map_err(|e| format!("firma RSA: {e}"))?;
            VerifyingKey::<Sha256>::new(key)
                .verify(message, &sig)
                .map_err(|_| "firma RSA inválida".to_string())
        }
        ID_EC_PUBLIC_KEY => {
            use p256::ecdsa::{DerSignature, VerifyingKey};
            use p256::pkcs8::DecodePublicKey;
            let key = VerifyingKey::from_public_key_der(&spki_der)
                .map_err(|e| format!("clave ECDSA: {e}"))?;
            let sig = DerSignature::try_from(signature).map_err(|e| format!("firma ECDSA: {e}"))?;
            key.verify(message, &sig)
                .map_err(|_| "firma ECDSA inválida".to_string())
        }
        other => Err(format!("algoritmo de firma no soportado: {other}")),
    }
}

/// El valor (DER) del primer signed-attribute con ese OID.
fn signed_attribute(attrs: &SetOfVec<Attribute>, oid: ObjectIdentifier) -> Option<Vec<u8>> {
    let attr = attrs.iter().find(|a| a.oid == oid)?;
    let value = attr.values.iter().next()?;
    value.to_der().ok()
}

/// Los correos que declara un certificado: del SubjectAltName (rfc822Name) y del
/// `emailAddress` del subject.
fn certificate_emails(cert: &Certificate) -> Vec<String> {
    let mut emails = Vec::new();

    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions {
            if ext.extn_id == SUBJECT_ALT_NAME {
                if let Ok(san) = SubjectAltName::from_der(ext.extn_value.as_bytes()) {
                    for name in san.0 {
                        if let GeneralName::Rfc822Name(email) = name {
                            emails.push(email.as_str().to_string());
                        }
                    }
                }
            }
        }
    }

    for rdn in cert.tbs_certificate.subject.0.iter() {
        for atv in rdn.0.iter() {
            if atv.oid == EMAIL_ADDRESS {
                if let Ok(s) = std::str::from_utf8(atv.value.value()) {
                    emails.push(s.to_string());
                }
            }
        }
    }

    emails
}

fn strip_one_trailing_crlf(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.ends_with(b"\r\n") {
        bytes.truncate(bytes.len() - 2);
    } else if bytes.ends_with(b"\n") {
        bytes.truncate(bytes.len() - 1);
    }
    bytes
}

fn strip_whitespace(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect()
}

// ── Descifrar (EnvelopedData) ──────────────────────────────────────────

/// El resultado de intentar descifrar un mensaje entrante.
#[derive(Debug)]
pub enum Decryption {
    /// No venía cifrado.
    NotEncrypted,
    /// Cifrado y abierto: el contenido descifrado (una entidad MIME, que puede
    /// venir firmada adentro —sign-then-encrypt—). Se borra al soltarlo.
    Opened(Zeroizing<Vec<u8>>),
    /// Cifrado pero no se pudo abrir: destinatario por acuerdo de clave (ECC/ECDH),
    /// cifrado no soportado (p. ej. AES-GCM / AuthEnvelopedData), falta nuestra
    /// clave, o el descifrado falló. El motivo es para el diario; a la ventana se
    /// le dice «cifrado, no se pudo abrir». **El resultado es uniforme** (todos
    /// los fallos caen acá) para no darle un oráculo a quien manda ciphertexts.
    Unavailable(String),
}

/// Descifra un `pkcs7-mime; smime-type=enveloped-data` con **nuestra** clave
/// privada (`our_key_pkcs8`) y nuestro certificado (`our_cert_der`), los dos del
/// llavero por nuestra dirección. Nunca entra en pánico sobre la entrada.
pub fn decrypt_message(raw: &[u8], our_key_pkcs8: &[u8], our_cert_der: &[u8]) -> Decryption {
    let view = as_latin1(raw);
    let (headers, body) = split_headers(&view);
    let content_type = headers
        .get("content-type")
        .map(parse_content_type)
        .unwrap_or_default();
    if !matches!(
        content_type.media_type.as_str(),
        "application/pkcs7-mime" | "application/x-pkcs7-mime"
    ) {
        return Decryption::NotEncrypted;
    }
    // Si el header dice que es un sobre cifrado, un blob que no parsea (manipulado)
    // es «cifrado, no se pudo abrir», no «no cifrado»: no lo ignoramos en silencio.
    let claims_enveloped = content_type.smime_type.as_deref() == Some("enveloped-data");
    let not_parseable = |reason: &str| {
        if claims_enveloped {
            Decryption::Unavailable(reason.to_string())
        } else {
            Decryption::NotEncrypted
        }
    };
    let der = match BASE64_STANDARD.decode(strip_whitespace(&from_latin1(body))) {
        Ok(der) => der,
        Err(_) => return not_parseable("pkcs7-mime base64 ilegible"),
    };
    let ci = match ContentInfo::from_der(&der) {
        Ok(ci) => ci,
        Err(_) => return not_parseable("pkcs7-mime ContentInfo ilegible"),
    };
    if ci.content_type != ID_ENVELOPED_DATA {
        // signed-data u otro: no es un sobre cifrado.
        return Decryption::NotEncrypted;
    }
    let ed = match ci
        .content
        .to_der()
        .and_then(|d| EnvelopedData::from_der(&d))
    {
        Ok(ed) => ed,
        Err(e) => return Decryption::Unavailable(format!("EnvelopedData: {e}")),
    };

    let key = match RsaPrivateKey::from_pkcs8_der(our_key_pkcs8) {
        Ok(key) => key,
        Err(_) => return Decryption::Unavailable("nuestra clave S/MIME no es RSA".into()),
    };
    let our_rid = match recipient_id(our_cert_der) {
        Some(rid) => rid,
        None => return Decryption::Unavailable("nuestro certificado no se pudo leer".into()),
    };

    // Buscamos el `RecipientInfo` de transporte de clave (RSA) que es para
    // nosotros. Un destinatario por acuerdo de clave (ECC/ECDH, `Kari`) u otro
    // esquema no lo soportamos → «no se pudo abrir».
    let mut cek: Option<Zeroizing<Vec<u8>>> = None;
    let mut saw_unsupported = false;
    for recipient in ed.recip_infos.0.iter() {
        match recipient {
            RecipientInfo::Ktri(ktri) if ktri.rid == our_rid => {
                cek = unwrap_cek(&key, &ktri.key_enc_alg, ktri.enc_key.as_bytes());
                break;
            }
            _ => saw_unsupported = true,
        }
    }
    let cek = match cek {
        Some(cek) => cek,
        None => {
            return Decryption::Unavailable(if saw_unsupported {
                "no somos destinatario por transporte de clave RSA (¿ECC?)".into()
            } else {
                "no se pudo recuperar la clave de contenido".into()
            })
        }
    };

    let eci = ed.encrypted_content;
    let ciphertext = match eci.encrypted_content.as_ref() {
        Some(octets) => octets,
        None => return Decryption::Unavailable("el sobre no trae contenido cifrado".into()),
    };
    match aes_cbc_decrypt(&eci.content_enc_alg, &cek, ciphertext.as_bytes()) {
        Some(plaintext) => Decryption::Opened(plaintext),
        None => Decryption::Unavailable("no se pudo descifrar el contenido".into()),
    }
}

/// Si un mensaje es un sobre cifrado S/MIME (`pkcs7-mime; enveloped-data`), sin
/// intentar abrirlo. Para marcar «cifrado, no se pudo abrir» cuando no tenemos la
/// clave (no hay con qué descifrar).
pub fn is_enveloped(raw: &[u8]) -> bool {
    let view = as_latin1(raw);
    let (headers, body) = split_headers(&view);
    let content_type = headers
        .get("content-type")
        .map(parse_content_type)
        .unwrap_or_default();
    if !matches!(
        content_type.media_type.as_str(),
        "application/pkcs7-mime" | "application/x-pkcs7-mime"
    ) {
        return false;
    }
    // Por el OID del CMS; o, si no parsea (manipulado), por el `smime-type` del
    // header: un sobre cifrado que no se puede leer igual es «cifrado».
    if content_type.smime_type.as_deref() == Some("enveloped-data") {
        return true;
    }
    BASE64_STANDARD
        .decode(strip_whitespace(&from_latin1(body)))
        .ok()
        .and_then(|der| ContentInfo::from_der(&der).ok())
        .is_some_and(|ci| ci.content_type == ID_ENVELOPED_DATA)
}

/// El `RecipientIdentifier` (emisor+serie) de nuestro certificado, para encontrar
/// el `RecipientInfo` que nos corresponde.
fn recipient_id(cert_der: &[u8]) -> Option<RecipientIdentifier> {
    let cert = Certificate::from_der(cert_der).ok()?;
    Some(RecipientIdentifier::IssuerAndSerialNumber(
        IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        },
    ))
}

/// Desenvuelve la clave de contenido (CEK) cifrada con nuestra clave RSA, según
/// el esquema de transporte: RSAES-PKCS1-v1_5 o RSAES-OAEP (SHA-256 o SHA-1).
///
/// **Nota de seguridad (RUSTSEC-2023-0071, Marvin/Bleichenbacher).** El crate
/// `rsa` no descifra PKCS#1 v1.5 en tiempo constante, y no hay alternativa en
/// Rust puro. El modelo de amenaza acá es **descifrado local al abrir un correo,
/// sin oráculo de auto-respuesta**: no respondemos ni rebotamos automáticamente,
/// así que un atacante no puede medir el resultado de muchos ciphertexts
/// elegidos. Y del lado nuestro el fallo es **uniforme**: unpad de RSA, unpad de
/// CBC y destinatario equivocado terminan todos en `Decryption::Unavailable`
/// («cifrado, no se pudo abrir»), sin distinguir el motivo hacia afuera. La
/// revisión de seguridad firma esta aceptación. (OAEP no es vulnerable a
/// Bleichenbacher; se prueban SHA-256 y SHA-1, que son los que emite el correo.)
fn unwrap_cek(
    key: &RsaPrivateKey,
    key_enc_alg: &AlgorithmIdentifierOwned,
    enc_key: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    match key_enc_alg.oid {
        RSA_ENCRYPTION => key
            .decrypt(Pkcs1v15Encrypt, enc_key)
            .ok()
            .map(Zeroizing::new),
        ID_RSAES_OAEP => key
            .decrypt(Oaep::new::<Sha256>(), enc_key)
            .ok()
            .or_else(|| key.decrypt(Oaep::new::<Sha1>(), enc_key).ok())
            .map(Zeroizing::new),
        _ => None,
    }
}

/// Descifra el contenido AES-CBC (128/192/256) con la CEK y el IV de los
/// parámetros. El relleno PKCS#7 que no cierra es `None` (→ uniforme, arriba).
fn aes_cbc_decrypt(
    content_enc_alg: &AlgorithmIdentifierOwned,
    cek: &[u8],
    ciphertext: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let iv_der = content_enc_alg.parameters.as_ref()?.to_der().ok()?;
    let iv = OctetString::from_der(&iv_der).ok()?;
    let iv = iv.as_bytes();

    let plaintext = match content_enc_alg.oid {
        ID_AES_128_CBC if cek.len() == 16 => {
            cbc::Decryptor::<aes::Aes128>::new_from_slices(cek, iv)
                .ok()?
                .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
                .ok()?
        }
        ID_AES_192_CBC if cek.len() == 24 => {
            cbc::Decryptor::<aes::Aes192>::new_from_slices(cek, iv)
                .ok()?
                .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
                .ok()?
        }
        ID_AES_256_CBC if cek.len() == 32 => {
            cbc::Decryptor::<aes::Aes256>::new_from_slices(cek, iv)
                .ok()?
                .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
                .ok()?
        }
        _ => return None,
    };
    Some(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod edge_cases;
#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod round_trip {
    //! Prueba de ida y vuelta: se firma con este código y se verifica con este
    //! código. Es lo que ata la canonicalización —los bytes que se firman tienen
    //! que ser idénticos a los que se transmiten—. qa suma los bordes (adjuntos,
    //! From que no liga, firma manipulada entrante, opaque, truncado).
    use super::*;
    use crate::compose::Draft;
    use crate::store::smime_key::parse_pkcs12;

    const PASSWORD: &[u8] = b"vasak-test";
    const RSA_P12: &[u8] = include_bytes!("../tests/fixtures/smime/rsa-pbes2.p12");
    const EC_P12: &[u8] = include_bytes!("../tests/fixtures/smime/ec-p256.p12");

    fn draft(from: &str, body: &str) -> Draft {
        Draft {
            from: from.into(),
            to: vec!["dest@otro.test".into()],
            subject: "Prueba firmada".into(),
            body: body.into(),
            ..Default::default()
        }
    }

    fn sign(p12: &[u8], from: &str, body: &str) -> String {
        let id = parse_pkcs12(p12, PASSWORD).expect("el .p12 de prueba parsea");
        let draft = draft(from, body);
        let headers = crate::compose::build_message_headers(
            &draft,
            "<x@y>",
            "Thu, 10 Sep 2026 12:00:00 +0000",
        )
        .expect("headers");
        let content = crate::compose::build_content_entity(&draft);
        let sig = detached_signature(content.as_bytes(), &id.private_key_pkcs8, &id.certs)
            .expect("firma");
        build_signed_message(&headers, &content, &sig)
    }

    // Con un fixture **autofirmado** (sin cadena de confianza), lo máximo que se
    // puede afirmar es `SignedUntrusted(firmante)`: nunca «válido». Eso prueba la
    // canonicalización (los bytes firmados == los transmitidos) sin mentir sobre
    // la confianza. El estado «válido» llega con la validación de confianza X.509.
    #[test]
    fn rsa_firma_y_verifica_en_ida_y_vuelta_pero_sin_confianza_no_es_valido() {
        let message = sign(RSA_P12, "prueba@vasak.test", "hola con RSA");
        assert!(message.contains("multipart/signed"), "{message}");
        assert_eq!(
            verify_message(message.as_bytes()),
            Verification::SignedUntrusted("prueba@vasak.test".into())
        );
    }

    #[test]
    fn ecdsa_firma_y_verifica_en_ida_y_vuelta_pero_sin_confianza_no_es_valido() {
        let message = sign(EC_P12, "ec@vasak.test", "hola con ECDSA");
        assert_eq!(
            verify_message(message.as_bytes()),
            Verification::SignedUntrusted("ec@vasak.test".into())
        );
    }

    #[test]
    fn un_byte_cambiado_en_el_contenido_no_verifica() {
        let message = sign(RSA_P12, "prueba@vasak.test", "texto a proteger");
        let mut bytes = message.into_bytes();
        // Cambiar un byte del cuerpo (está después de las cabeceras).
        let pos = bytes
            .windows(16)
            .position(|w| w == b"texto a proteger")
            .unwrap();
        bytes[pos] ^= 0xff;
        // Ni «válido» ni «firmado»: una firma sobre contenido manipulado no liga.
        assert!(
            matches!(verify_message(&bytes), Verification::Unverified(_)),
            "una firma sobre contenido manipulado no puede dar SignedUntrusted"
        );
    }

    #[test]
    fn un_mensaje_sin_firma_no_es_smime() {
        let draft = draft("alguien@otro.test", "texto plano");
        let plain =
            crate::compose::build_message(&draft, "<x@y>", "Thu, 10 Sep 2026 12:00:00 +0000")
                .unwrap();
        assert_eq!(verify_message(plain.as_bytes()), Verification::NotSigned);
    }
}

#[cfg(test)]
mod decrypt_smoke {
    //! Prueba de que el descifrado cierra contra sobres reales de openssl (los
    //! ciframos a nuestro cert de prueba). qa suma los bordes (manipulado,
    //! sign-then-encrypt, 192, más variantes). «Nuestra» clave sale del `.p12`.
    use super::*;
    use crate::store::smime_key::parse_pkcs12;

    fn our_key_and_cert() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
        let id = parse_pkcs12(
            include_bytes!("../tests/fixtures/smime/rsa-pbes2.p12"),
            b"vasak-test",
        )
        .expect("el .p12 de prueba parsea");
        (id.private_key_pkcs8, id.certs[0].clone())
    }

    fn opened(fixture: &[u8]) -> Vec<u8> {
        let (key, cert) = our_key_and_cert();
        match decrypt_message(fixture, &key, &cert) {
            Decryption::Opened(pt) => pt.to_vec(),
            other => panic!("se esperaba Opened, dio {other:?}"),
        }
    }

    #[test]
    fn rsa_pkcs1v15_aes256_se_descifra() {
        let pt = opened(include_bytes!("../tests/fixtures/smime/enc-rsa-aes256.eml"));
        assert!(
            String::from_utf8_lossy(&pt).contains("mensaje secreto"),
            "{:?}",
            String::from_utf8_lossy(&pt)
        );
    }

    #[test]
    fn rsa_pkcs1v15_aes128_se_descifra() {
        let pt = opened(include_bytes!("../tests/fixtures/smime/enc-rsa-aes128.eml"));
        assert!(String::from_utf8_lossy(&pt).contains("mensaje secreto"));
    }

    #[test]
    fn rsa_oaep_se_descifra() {
        let pt = opened(include_bytes!("../tests/fixtures/smime/enc-rsa-oaep.eml"));
        assert!(String::from_utf8_lossy(&pt).contains("mensaje secreto"));
    }

    #[test]
    fn destinatario_ecc_cae_a_no_disponible_sin_panico() {
        let (key, cert) = our_key_and_cert();
        let out = decrypt_message(
            include_bytes!("../tests/fixtures/smime/enc-ecc-recipient.eml"),
            &key,
            &cert,
        );
        assert!(matches!(out, Decryption::Unavailable(_)), "dio {out:?}");
    }

    #[test]
    fn un_sobre_firmado_adentro_se_descifra_y_la_firma_se_ve() {
        // sign-then-encrypt: descifrar da el contenido firmado; verificarlo da el
        // firmante (sin confianza, SignedUntrusted). Resuelve el orden solo.
        let pt = opened(include_bytes!(
            "../tests/fixtures/smime/enc-rsa-firmado.eml"
        ));
        // El From va del sobre de afuera (el contenido firmado no lo trae).
        assert_eq!(
            verify_message_with_from(&pt, "prueba@vasak.test"),
            Verification::SignedUntrusted("prueba@vasak.test".into())
        );
    }

    #[test]
    fn un_sobre_manipulado_no_se_abre() {
        let (key, cert) = our_key_and_cert();
        let out = decrypt_message(
            include_bytes!("../tests/fixtures/smime/enc-rsa-manipulado.eml"),
            &key,
            &cert,
        );
        assert!(matches!(out, Decryption::Unavailable(_)), "dio {out:?}");
    }

    #[test]
    fn un_mensaje_en_claro_no_esta_cifrado() {
        let (key, cert) = our_key_and_cert();
        assert!(matches!(
            decrypt_message(b"From: a@b.test\r\n\r\nhola", &key, &cert),
            Decryption::NotEncrypted
        ));
    }
}
