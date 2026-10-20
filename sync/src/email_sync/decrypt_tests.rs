//! Lo que se guarda de un correo cifrado al bajarlo (`opened_rows_decrypting`):
//! el cuerpo descifrado, el estado de cifrado (`smime_encrypted`: NULL / 1 / 2) y,
//! en un sign-then-encrypt, el estado de la firma de **adentro**. El descifrado en
//! sí se prueba en `smime_sign/decrypt_tests.rs`.

use super::*;
use crate::smime_sign::test_support::*;
use crate::store::key::tests::fake_keyring;
use crate::store::smime_key::{import_pkcs12, parse_pkcs12};

const AES256: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-aes256.eml");
const AES192: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-aes192.eml");
const AES128: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-aes128.eml");
const OAEP_SHA1: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-oaep.eml");
const OAEP_SHA256: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-oaep-sha256.eml");
const MULTI: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-multi.eml");
const ECC: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-ecc-recipient.eml");
const TAMPERED: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-manipulado.eml");
const TRIPLE_DES: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-3des.eml");
const OTHER_RECIPIENT: &[u8] =
    include_bytes!("../../tests/fixtures/smime/enc-rsa-otro-destinatario.eml");
const SIGNED_AND_ENCRYPTED: &[u8] =
    include_bytes!("../../tests/fixtures/smime/enc-rsa-firmado.eml");

fn material() -> SmimeMaterial {
    let id = parse_pkcs12(RSA_P12, PASSWORD).expect("el .p12 de prueba parsea");
    SmimeMaterial {
        key: id.private_key_pkcs8,
        cert: id.certs[0].clone(),
    }
}

fn rows(raw: &[u8], smime: Option<&SmimeMaterial>) -> MessageBodyRow {
    opened_rows_decrypting(1, raw, false, smime).0
}

fn text(body: &MessageBodyRow) -> String {
    body.text_body.clone().unwrap_or_default()
}

// ── 1 y 2. Cifrado y abierto ───────────────────────────────────────────

#[test]
fn un_correo_cifrado_se_guarda_descifrado_y_marcado_abierto() {
    let material = material();
    for (name, raw, secret) in [
        ("rsa + aes-128", AES128, "mensaje secreto para descifrar"),
        ("rsa + aes-192", AES192, "mensaje secreto de prueba"),
        ("rsa + aes-256", AES256, "mensaje secreto para descifrar"),
        ("oaep sha-1", OAEP_SHA1, "mensaje secreto para descifrar"),
        ("oaep sha-256", OAEP_SHA256, "mensaje secreto de prueba"),
        ("varios destinatarios", MULTI, "mensaje secreto de prueba"),
    ] {
        let body = rows(raw, Some(&material));
        assert_eq!(body.smime_encrypted, Some(1), "{name}");
        assert!(text(&body).contains(secret), "{name}: {:?}", body.text_body);
        // Lo que se guarda es el texto, no el blob base64 del sobre.
        assert!(
            !text(&body).contains("MIIB"),
            "{name}: {:?}",
            body.text_body
        );
        // Y no se firmó nada.
        assert_eq!(
            (body.smime_status, body.smime_signer.clone()),
            (None, None),
            "{name}"
        );
    }
}

// ── 3. sign-then-encrypt ───────────────────────────────────────────────

#[test]
fn cifrado_y_firmado_se_abre_y_la_firma_de_adentro_queda_sin_confianza_nunca_valida() {
    let body = rows(SIGNED_AND_ENCRYPTED, Some(&material()));
    assert_eq!(body.smime_encrypted, Some(1));
    assert!(
        text(&body).contains("cifrado y firmado"),
        "{:?}",
        body.text_body
    );
    // Firmado, no verificado (0) y con el firmante ligado al From del sobre de
    // afuera. **Nunca** 1 (válida): falta la validación de confianza X.509.
    assert_eq!(body.smime_status, Some(0));
    assert_eq!(body.smime_signer.as_deref(), Some(RSA_ADDRESS));
}

#[test]
fn la_firma_de_adentro_se_liga_al_from_de_afuera_y_no_a_cualquiera() {
    let raw = String::from_utf8(SIGNED_AND_ENCRYPTED.to_vec()).unwrap();
    assert!(raw.starts_with("From: prueba@vasak.test"));
    let other = raw.replacen("From: prueba@vasak.test", "From: atacante@otro.test", 1);
    let none: String = raw
        .split_inclusive('\n')
        .filter(|line| !line.starts_with("From:"))
        .collect();
    assert!(!none.contains("From:"));
    for (what, raw) in [("otro From", other), ("sin From", none)] {
        let body = rows(raw.as_bytes(), Some(&material()));
        // Se abre igual (el cifrado no depende del From), pero no se dice «firmado».
        assert_eq!(body.smime_encrypted, Some(1), "{what}");
        assert_eq!(
            (body.smime_status, body.smime_signer),
            (None, None),
            "{what}"
        );
    }
}

// ── 4, 5, 6 y 8. Lo que no se abre queda marcado 2, con el cuerpo vacío ──

#[test]
fn lo_que_no_se_puede_abrir_queda_marcado_2_y_sin_cuerpo() {
    let material = material();
    let truncated = &AES256[..AES256.len() - 40];
    let other_recipient = OTHER_RECIPIENT;
    for (what, raw) in [
        ("destinatario ECC", ECC),
        ("sobre manipulado", TAMPERED),
        ("3DES", TRIPLE_DES),
        ("otro destinatario RSA", other_recipient),
        ("truncado", truncated),
    ] {
        let body = rows(raw, Some(&material));
        assert_eq!(body.smime_encrypted, Some(2), "{what}");
        assert_eq!(
            (body.smime_status, body.smime_signer.clone()),
            (None, None),
            "{what}"
        );
        assert_eq!(body.html_body, None, "{what}");
        // Ni rastro del blob base64 del sobre como si fuera el texto del correo.
        let shown = text(&body);
        assert!(
            !shown.contains("MIIB") && shown.trim().is_empty(),
            "{what}: {shown:?}"
        );
    }
}

#[test]
fn sin_nuestra_clave_un_sobre_queda_marcado_2_y_lo_que_no_es_sobre_no() {
    // Sin material (la cuenta no tiene identidad S/MIME, o no hay llavero).
    for (what, raw) in [("aes-256", AES256), ("ECC", ECC), ("manipulado", TAMPERED)] {
        let body = rows(raw, None);
        assert_eq!(body.smime_encrypted, Some(2), "{what}");
        assert!(
            text(&body).trim().is_empty(),
            "{what}: {:?}",
            body.text_body
        );
    }
    assert_eq!(
        rows(b"From: a@b.test\r\n\r\nhola\r\n", None).smime_encrypted,
        None
    );
}

/// El mismo camino que `smime_material`: buscar en el llavero, por nuestra
/// dirección, la clave y el certificado. (Lo que `smime_material` suma —la
/// dirección de la config de la cuenta y el bus de sesión— no se prueba sin D-Bus.)
async fn material_from_keyring(
    keys: &crate::store::key::SecretServiceKeys,
    address: &str,
) -> Option<SmimeMaterial> {
    let key = keys.find_smime_private_key(address).await.ok()??;
    let cert = keys
        .find_smime_certs(address)
        .await
        .ok()??
        .into_iter()
        .next()?;
    Some(SmimeMaterial { key, cert })
}

#[tokio::test]
async fn con_la_clave_en_el_llavero_abre_y_sin_clave_para_esa_direccion_queda_marcado_2() {
    let (keys, _server, _shared) = fake_keyring().await;
    import_pkcs12(&keys, "yo@vasak.test", RSA_P12, PASSWORD)
        .await
        .expect("importa el .p12");

    let ours = material_from_keyring(&keys, "yo@vasak.test")
        .await
        .expect("hay clave para nuestra dirección");
    let body = rows(AES256, Some(&ours));
    assert_eq!(body.smime_encrypted, Some(1));
    assert!(text(&body).contains("mensaje secreto"));

    // Otra dirección: el llavero no tiene nada, no hay material, y el sobre queda
    // «cifrado, no se pudo abrir» sin pánico ni espera.
    let missing = material_from_keyring(&keys, "otra@vasak.test").await;
    assert!(missing.is_none());
    let body = rows(AES256, missing.as_ref());
    assert_eq!(body.smime_encrypted, Some(2));

    // Y con la clave de una identidad que no es la del sobre (un EC bajo nuestra
    // dirección): no abre, queda 2.
    let (keys, _server, _shared) = fake_keyring().await;
    import_pkcs12(&keys, "yo@vasak.test", EC_P12, PASSWORD)
        .await
        .expect("importa el .p12 EC");
    let wrong = material_from_keyring(&keys, "yo@vasak.test").await;
    assert_eq!(rows(AES256, wrong.as_ref()).smime_encrypted, Some(2));
}

// ── 12. Lo que no viene cifrado no cambia ──────────────────────────────

#[test]
fn un_correo_no_cifrado_sigue_sin_marca_de_cifrado_con_o_sin_clave() {
    let plain = b"From: ana@x.com\r\nContent-Type: text/plain\r\n\r\nhola\r\n";
    let signed = sign(RSA_P12, &draft(RSA_ADDRESS, "hola firmado"));
    let opaque_signed = opaque(&signed, "application/pkcs7-mime");
    let material = material();

    for (what, raw) in [
        ("texto plano", plain.to_vec()),
        ("multipart/signed", signed.message.clone().into_bytes()),
        ("pkcs7-mime firmado", opaque_signed.into_bytes()),
    ] {
        let with = rows(&raw, Some(&material));
        let without = rows(&raw, None);
        assert_eq!(with.smime_encrypted, None, "{what}");
        assert_eq!(without.smime_encrypted, None, "{what}");
        // Tener clave no cambia nada de lo demás.
        assert_eq!(with, without, "{what}");
    }

    // Y la firma sigue leyéndose como antes: firmado, no verificado, con firmante.
    let body = rows(signed.message.as_bytes(), Some(&material));
    assert_eq!(body.smime_status, Some(0));
    assert_eq!(body.smime_signer.as_deref(), Some(RSA_ADDRESS));
    assert!(text(&body).contains("hola firmado"));
}
