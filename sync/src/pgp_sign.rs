//! Firmar correo saliente con PGP/MIME (RFC 3156). El espejo de
//! [`crate::smime_sign::build_signed_message`], pero con el `protocol` de PGP y la
//! firma **armada** (ASCII) tal cual la devuelve [`crate::pgp::sign_detached`]: el
//! armor ya es ASCII transportable, así que la parte de la firma va `7bit`, no
//! base64.
//!
//! La firma cubre **sólo** la entidad de contenido
//! ([`crate::compose::build_content_entity`]), byte a byte como se transmite; las
//! cabeceras de dirección van en el mensaje de afuera, sin firmar.

/// Arma el mensaje `multipart/signed` de PGP/MIME: las cabeceras de dirección, el
/// `Content-Type` de `multipart/signed` con el `protocol` de PGP, la entidad de
/// contenido (parte 1, firmada byte a byte) y la firma separada (parte 2,
/// `application/pgp-signature`, el armor tal cual).
pub fn build_signed_message(
    headers: &[String],
    content_entity: &str,
    armored_signature: &str,
) -> String {
    // La frontera no puede aparecer ni en el contenido ni en la firma armada.
    let boundary = crate::compose::boundary(&[content_entity, armored_signature]);

    let mut out = headers.join("\r\n");
    out.push_str(&format!(
        "\r\nContent-Type: multipart/signed; protocol=\"application/pgp-signature\"; \
         micalg=\"pgp-sha256\"; boundary=\"{boundary}\"\r\n\r\n"
    ));
    // Parte 1: la entidad de contenido, exactamente lo que se firmó. El `\r\n`
    // que sigue es de la frontera, no del contenido.
    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str(content_entity);
    out.push_str("\r\n");
    // Parte 2: la firma separada, el armor ASCII tal cual (no se recodifica).
    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str(
        "Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n\
         Content-Disposition: attachment; filename=\"signature.asc\"\r\n\
         Content-Transfer-Encoding: 7bit\r\n\r\n",
    );
    out.push_str(armored_signature);
    out.push_str(&format!("\r\n--{boundary}--\r\n"));
    out
}
