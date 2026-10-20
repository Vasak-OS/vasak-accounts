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
//! del firmante **esté ligado al `From`**. **No** valida cadena contra una CA, ni
//! vigencia, ni revocación (eso es un follow-up, «validación de confianza
//! X.509»): un cert vencido o sin cadena se muestra «firmado, no verificado»,
//! nunca «roto» (decisión #2).

use base64::prelude::{Engine as _, BASE64_STANDARD};
use cms::builder::{SignedDataBuilder, SignerInfoBuilder};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::ContentInfo;
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier};
use der::asn1::{ObjectIdentifier, OctetString, SetOfVec};
use der::{Decode, Encode};
use rsa::pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigningKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use serde::Serialize;
use sha2::{Digest, Sha256};
use signature::Verifier;
use spki::{AlgorithmIdentifierOwned, SignatureBitStringEncoding};
use x509_cert::attr::Attribute;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::Certificate;

use crate::message::{
    as_latin1, from_latin1, parse_content_type, parse_sender, split_headers, split_parts,
};

const ID_DATA: ObjectIdentifier = const_oid::db::rfc5911::ID_DATA;
const ID_SIGNED_DATA: ObjectIdentifier = const_oid::db::rfc5911::ID_SIGNED_DATA;
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

/// El estado S/MIME de un mensaje firmado, como lo ve quien lo lee. `None` en el
/// mensaje quiere decir que no venía firmado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SmimeStatus {
    /// La firma se verificó (cripto + signed-attrs + cert ligado al `From`).
    pub valid: bool,
    /// El firmante (el correo del certificado), presente cuando `valid`.
    pub signer: Option<String>,
}

/// El resultado de verificar un mensaje entrante.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// No venía firmado.
    NotSigned,
    /// Firmado y verificado; trae el correo del firmante.
    Valid(String),
    /// Firmado pero no se pudo verificar; el motivo es para el diario, no para
    /// la ventana (que muestra «firmado, no verificado» a secas).
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

/// Verifica un mensaje entrante. `raw` es el RFC822 crudo (lo que hace falta: la
/// firma va sobre los bytes exactos, no sobre el cuerpo decodificado).
pub fn verify_message(raw: &[u8]) -> Verification {
    let view = as_latin1(raw);
    let (headers, body) = split_headers(&view);
    let content_type = headers
        .get("content-type")
        .map(parse_content_type)
        .unwrap_or_default();
    let from = headers
        .get("from")
        .map(parse_sender)
        .map(|(_, address)| address)
        .unwrap_or_default();

    match content_type.media_type.as_str() {
        "multipart/signed" => {
            let Some(boundary) = content_type.boundary.as_deref() else {
                return Verification::Unverified("multipart/signed sin frontera".into());
            };
            let parts = split_parts(body, boundary);
            if parts.len() < 2 {
                return Verification::Unverified("multipart/signed sin las dos partes".into());
            }
            // Parte 1: el contenido firmado, sin el CRLF que pertenece a la
            // frontera. Parte 2: la firma (`application/pkcs7-signature`, base64).
            let signed_content = strip_one_trailing_crlf(from_latin1(parts[0]));
            let signature_der = match signature_part(parts[1]) {
                Some(der) => der,
                None => return Verification::Unverified("firma pkcs7 ilegible".into()),
            };
            verify_signed_data(&signature_der, Some(&signed_content), &from)
        }
        "application/pkcs7-mime" | "application/x-pkcs7-mime" => {
            // Opaque: el cuerpo base64 es el `ContentInfo` y el contenido va
            // adentro del `SignedData`. (El enveloped —cifrado— es PR4.)
            let der = match BASE64_STANDARD.decode(strip_whitespace(&from_latin1(body))) {
                Ok(der) => der,
                Err(_) => return Verification::Unverified("pkcs7-mime base64 ilegible".into()),
            };
            verify_signed_data(&der, None, &from)
        }
        _ => Verification::NotSigned,
    }
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

    // 4) El cert del firmante tiene que estar ligado al `From`.
    let emails = certificate_emails(&cert);
    let bound = emails.iter().any(|e| e.eq_ignore_ascii_case(from.trim()));
    if !bound {
        return Verification::Unverified("el firmante no coincide con el From".into());
    }

    Verification::Valid(from.trim().to_string())
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

    #[test]
    fn rsa_firma_y_verifica_en_ida_y_vuelta() {
        let message = sign(RSA_P12, "prueba@vasak.test", "hola con RSA");
        assert!(message.contains("multipart/signed"), "{message}");
        assert_eq!(
            verify_message(message.as_bytes()),
            Verification::Valid("prueba@vasak.test".into())
        );
    }

    #[test]
    fn ecdsa_firma_y_verifica_en_ida_y_vuelta() {
        let message = sign(EC_P12, "ec@vasak.test", "hola con ECDSA");
        assert_eq!(
            verify_message(message.as_bytes()),
            Verification::Valid("ec@vasak.test".into())
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
        assert!(
            !matches!(verify_message(&bytes), Verification::Valid(_)),
            "una firma sobre contenido manipulado no puede dar Valid"
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
