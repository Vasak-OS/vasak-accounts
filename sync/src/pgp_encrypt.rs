//! Cifrar correo saliente con PGP/MIME (RFC 3156 §4). El espejo de
//! [`crate::pgp_sign`], pero armando un `multipart/encrypted` en vez de un
//! `multipart/signed`.
//!
//! El sobre son **dos** partes:
//!
//! 1. `application/pgp-encrypted`, cuerpo fijo `Version: 1` (la versión del
//!    protocolo PGP/MIME, no de nada nuestro).
//! 2. `application/octet-stream` con el bloque OpenPGP **ASCII-armado** tal cual lo
//!    devuelve [`crate::pgp::encrypt_to_keys`]. El armor ya es ASCII transportable,
//!    así que la parte va sin `Content-Transfer-Encoding` (es `7bit` por omisión).
//!
//! Qué se cifra lo decide quien llama ([`crate::encrypt_outgoing_pgp`]):
//! **sign-then-encrypt**. Si además se firma, se cifra el `multipart/signed` entero
//! (la firma queda adentro del sobre, no a la vista); si sólo se cifra, se cifra la
//! entidad de contenido directa. Este módulo sólo arma el `multipart/encrypted`
//! alrededor del bloque armado que ya se le pasa.

/// Arma el mensaje `multipart/encrypted` de PGP/MIME: las cabeceras de dirección, el
/// `Content-Type` de `multipart/encrypted` con el `protocol` de PGP, la parte de
/// control (`Version: 1`) y la parte del sobre (`application/octet-stream`, el armor
/// tal cual). `armored_message` es el bloque `-----BEGIN PGP MESSAGE-----` de
/// [`crate::pgp::encrypt_to_keys`].
pub fn build_encrypted_message(headers: &[String], armored_message: &str) -> String {
    // La parte de control es fija; la frontera no puede aparecer ni en ella ni en el
    // sobre armado.
    const VERSION: &str = "Version: 1";
    let boundary = crate::compose::boundary(&[VERSION, armored_message]);

    let mut out = headers.join("\r\n");
    out.push_str(&format!(
        "\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; \
         boundary=\"{boundary}\"\r\n\r\n"
    ));
    // Parte 1: el control. `application/pgp-encrypted`, cuerpo `Version: 1`. El `\r\n`
    // que sigue al cuerpo es de la frontera.
    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str("Content-Type: application/pgp-encrypted\r\n\r\n");
    out.push_str(VERSION);
    out.push_str("\r\n");
    // Parte 2: el sobre, `application/octet-stream`, el armor ASCII tal cual (ya es
    // transportable, no se recodifica).
    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str(
        "Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\n\
         Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n",
    );
    out.push_str(armored_message);
    out.push_str(&format!("\r\n--{boundary}--\r\n"));
    out
}
