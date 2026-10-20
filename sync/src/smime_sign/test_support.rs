//! Lo que comparten las pruebas de S/MIME: armar mensajes firmados con los
//! `.p12` de `tests/fixtures/smime/`, en las dos formas que llegan.

use super::*;
use crate::compose::{Attachment, Draft};
use crate::store::smime_key::parse_pkcs12;

pub(crate) const PASSWORD: &[u8] = b"vasak-test";
pub(crate) const RSA_P12: &[u8] = include_bytes!("../../tests/fixtures/smime/rsa-pbes2.p12");
pub(crate) const EC_P12: &[u8] = include_bytes!("../../tests/fixtures/smime/ec-p256.p12");
/// ECDSA sin SubjectAltName: el correo (`subject@vasak.test`) sólo está en el
/// `emailAddress` del subject.
pub(crate) const EC_SUBJECT_P12: &[u8] =
    include_bytes!("../../tests/fixtures/smime/ec-email-en-subject.p12");
/// ECDSA con la vigencia de 2020: ya vencido (`vencido@vasak.test`).
pub(crate) const EC_EXPIRED_P12: &[u8] =
    include_bytes!("../../tests/fixtures/smime/ec-vencido.p12");

/// ECDSA cuyo SubjectAltName trae un `rfc822Name` **vacío** (generado a mano: un
/// cert así no sale de openssl). Con el `From` vacío, `"" == ""` ligaría todo.
pub(crate) const EC_EMPTY_EMAIL_P12: &[u8] =
    include_bytes!("../../tests/fixtures/smime/ec-correo-vacio.p12");

pub(crate) const RSA_ADDRESS: &str = "prueba@vasak.test";
pub(crate) const EC_ADDRESS: &str = "ec@vasak.test";

pub(crate) const MESSAGE_ID: &str = "<x@y>";
pub(crate) const DATE: &str = "Thu, 10 Sep 2026 12:00:00 +0000";

pub(crate) fn draft(from: &str, body: &str) -> Draft {
    Draft {
        from: from.into(),
        to: vec!["dest@otro.test".into()],
        subject: "Prueba firmada".into(),
        body: body.into(),
        sign: true,
        ..Default::default()
    }
}

/// Un borrador con dos adjuntos: uno binario largo (más de una línea de base64) y
/// uno con el nombre fuera del ASCII.
pub(crate) fn draft_with_attachments(from: &str) -> Draft {
    let binary: Vec<u8> = (0..=255u8).cycle().take(900).collect();
    Draft {
        attachments: vec![
            Attachment {
                name: "datos.bin".into(),
                content_type: "application/octet-stream".into(),
                content: BASE64_STANDARD.encode(binary),
            },
            Attachment {
                name: "informe ñandú.pdf".into(),
                content_type: String::new(),
                content: BASE64_STANDARD.encode(b"%PDF-1.4 de mentira"),
            },
        ],
        ..draft(from, "Va el informe.\n\nSaludos.")
    }
}

/// Lo que sale de firmar: las partes y el mensaje armado.
pub(crate) struct Signed {
    pub headers: Vec<String>,
    /// La entidad de contenido, tal como se le pasó a firmar.
    pub content: String,
    pub signature: Vec<u8>,
    /// El `multipart/signed` completo, como se transmite.
    pub message: String,
}

pub(crate) fn sign(p12: &[u8], draft: &Draft) -> Signed {
    let identity = parse_pkcs12(p12, PASSWORD).expect("el .p12 de prueba parsea");
    let headers = crate::compose::build_message_headers(draft, MESSAGE_ID, DATE).expect("headers");
    let content = crate::compose::build_content_entity(draft);
    let signature = detached_signature(
        content.as_bytes(),
        &identity.private_key_pkcs8,
        &identity.certs,
    )
    .expect("firma");
    let message = build_signed_message(&headers, &content, &signature);
    Signed {
        headers,
        content,
        signature,
        message,
    }
}

/// La forma opaca (`application/pkcs7-mime; smime-type=signed-data`): el mismo
/// `SignedData`, con el contenido **adentro**. Los atributos firmados no cambian
/// (el digest es el mismo), así que la firma sigue valiendo.
pub(crate) fn opaque(signed: &Signed, media_type: &str) -> String {
    let content_info = ContentInfo::from_der(&signed.signature).expect("ContentInfo");
    let mut signed_data: SignedData = content_info
        .content
        .to_der()
        .and_then(|der| SignedData::from_der(&der))
        .expect("SignedData");
    signed_data.encap_content_info.econtent = Some(
        der::Any::new(der::Tag::OctetString, signed.content.as_bytes())
            .expect("el contenido entra en un OCTET STRING"),
    );
    let content_info = ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: der::Any::encode_from(&signed_data).expect("SignedData a DER"),
    };
    let der = content_info.to_der().expect("ContentInfo a DER");
    opaque_from_der(&signed.headers, media_type, &der)
}

/// Un mensaje opaco con este `ContentInfo` ya armado.
pub(crate) fn opaque_from_der(headers: &[String], media_type: &str, der: &[u8]) -> String {
    let mut out = headers.join("\r\n");
    out.push_str(&format!(
        "\r\nContent-Type: {media_type}; smime-type=signed-data; name=\"smime.p7m\"\r\n\
         Content-Transfer-Encoding: base64\r\n\
         Content-Disposition: attachment; filename=\"smime.p7m\"\r\n\r\n"
    ));
    out.push_str(&crate::compose::wrap_base64(&BASE64_STANDARD.encode(der)));
    out.push_str("\r\n");
    out
}

/// Lo que dice `Unverified`, para comprobar que falla **por el motivo
/// correcto** y no por otro.
pub(crate) fn unverified_reason(verification: Verification) -> String {
    match verification {
        Verification::Unverified(reason) => reason,
        other => panic!("se esperaba «firmado, no verificado», dio {other:?}"),
    }
}
