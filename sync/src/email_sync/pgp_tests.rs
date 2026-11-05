//! Lo que se guarda de un correo con OpenPGP al bajarlo (`opened_rows_decrypting`):
//! el cuerpo descifrado, el estado de cifrado (`pgp_encrypted`: NULL / 1 / 2) y el de
//! la firma (`pgp_status`: NULL / 0 conocida / 1 desconocida / 2 no verificable), y
//! que S/MIME y PGP no se pisen. El núcleo criptográfico se prueba en `pgp.rs`; la
//! ingesta y el peerstate, en `tests.rs`. Las claves se generan con rPGP: nada de
//! fixtures opacos.

use super::*;
use crate::pgp::tests::{
    cifrar, clave_completa, cleartext_de, correo_inline, correo_pgp_mime, generar, manipular,
    publica, subclave_de_cifrado, subclave_de_firma, vacia,
};
use crate::smime_sign::test_support::*;
use crate::store::smime_key::parse_pkcs12;
use pgp::composed::{SignedPublicKey, SignedSecretKey};
use pgp::types::KeyDetails;

const AES256: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-aes256.eml");

const SECRETO: &str = "SECRETO-PGP: el lince cena a las ocho";
const CLARO: &str =
    "Content-Type: text/plain; charset=utf-8\r\n\r\nSECRETO-PGP: el lince cena a las ocho";

fn material(secret: &SignedSecretKey) -> PgpMaterial {
    PgpMaterial {
        secret_key: secret.clone(),
        passphrase: vacia(),
    }
}

fn smime_material() -> SmimeMaterial {
    let id = parse_pkcs12(RSA_P12, PASSWORD).expect("el .p12 de prueba parsea");
    SmimeMaterial {
        key: id.private_key_pkcs8,
        cert: id.certs[0].clone(),
    }
}

fn rows(raw: &[u8], pgp: Option<&PgpMaterial>, candidates: &[SignedPublicKey]) -> MessageBodyRow {
    opened_rows_decrypting(1, raw, false, None, pgp, candidates).0
}

fn text(body: &MessageBodyRow) -> String {
    body.text_body.clone().unwrap_or_default()
}

fn huella(secret: &SignedSecretKey) -> String {
    secret.primary_key.fingerprint().to_string()
}

/// PGP/MIME firmado por `firmante` sobre `contenido` (una parte MIME entera, con
/// sus cabeceras), con el `From` y las cabeceras extra (`Autocrypt: ...\r\n`) que se
/// pidan.
pub(super) fn firmado_mime_de(
    from: &str,
    extra: &str,
    firmante: &SignedSecretKey,
    contenido: &str,
) -> Vec<u8> {
    let firma = crate::pgp::sign_detached(contenido.as_bytes(), firmante, &vacia()).unwrap();
    let mut out = format!(
        "From: {from}\r\nTo: yo@vasak.test\r\nSubject: s\r\n{extra}Content-Type: multipart/signed; \
protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"S\"\r\n\r\n\
--S\r\n{contenido}\r\n--S\r\nContent-Type: application/pgp-signature\r\n\r\n"
    )
    .into_bytes();
    out.extend_from_slice(&firma);
    out.extend_from_slice(b"\r\n--S--\r\n");
    out
}

/// PGP/MIME firmado por `firmante` con un texto simple.
fn firmado_mime(from: &str, firmante: &SignedSecretKey, texto: &str) -> Vec<u8> {
    let contenido = format!("Content-Type: text/plain; charset=utf-8\r\n\r\n{texto}");
    firmado_mime_de(from, "", firmante, &contenido)
}

/// Cleartext firmado inline por `firmante`.
fn firmado_inline(from: &str, firmante: &SignedSecretKey, texto: &str) -> Vec<u8> {
    let bloque = cleartext_de(texto, &*firmante.secret_subkeys[0]);
    format!("From: {from}\r\nContent-Type: text/plain\r\n\r\n{bloque}").into_bytes()
}

// ── Cifrado entrante ───────────────────────────────────────────────────

#[test]
fn un_correo_pgp_cifrado_inline_o_mime_se_guarda_descifrado_y_marcado_abierto() {
    let yo = clave_completa("Yo <yo@vasak.test>");
    let armado = cifrar(CLARO.as_bytes(), &publica(&yo));
    for (que, raw) in [
        ("inline", correo_inline(&armado)),
        ("pgp/mime", correo_pgp_mime(&armado)),
    ] {
        let body = rows(&raw, Some(&material(&yo)), &[]);
        assert_eq!(body.pgp_encrypted, Some(1), "{que}");
        assert!(text(&body).contains(SECRETO), "{que}: {:?}", body.text_body);
        // Lo que se guarda es el texto, no la armadura del sobre.
        assert!(!text(&body).contains("BEGIN PGP"), "{que}");
        // No venía firmado, y no es S/MIME.
        assert_eq!(
            (body.pgp_status, body.pgp_signer.clone()),
            (None, None),
            "{que}"
        );
        assert_eq!(body.smime_encrypted, None, "{que}");
    }
}

/// Lo que **nunca** puede pasar con un cifrado que no se pudo abrir: que el claro
/// aparezca en el cuerpo guardado (el fallo-abierto). Va en todos los casos.
fn assert_sin_claro(que: &str, body: &MessageBodyRow) {
    let shown = text(body);
    assert!(
        !shown.contains(SECRETO),
        "{que}: el claro de un cifrado no abierto no puede guardarse: {shown:?}"
    );
    assert_eq!(body.html_body, None, "{que}");
}

/// Lo que dice el contrato de la V15: el cuerpo de un cifrado no abierto queda
/// **vacío**, ni el sobre (la armadura) tomado por texto.
fn assert_cuerpo_vacio(que: &str, body: &MessageBodyRow) {
    let shown = text(body);
    assert!(
        !shown.contains("BEGIN PGP") && shown.trim().is_empty(),
        "{que}: el cuerpo de un cifrado no abierto tiene que quedar vacío: {shown:?}"
    );
}

#[test]
fn lo_que_no_se_puede_abrir_queda_no_disponible_y_nunca_se_guarda_crudo() {
    let yo = clave_completa("Yo <yo@vasak.test>");
    let otro = clave_completa("Otro <otro@vasak.test>");
    let armado = cifrar(CLARO.as_bytes(), &publica(&yo));
    // Control: sin tocar, abre. Si no, los «no disponible» de abajo serían vacíos.
    assert_eq!(
        rows(&correo_inline(&armado), Some(&material(&yo)), &[]).pgp_encrypted,
        Some(1)
    );

    // Manipulado: el último byte (cae en el MDC), uno del cuerpo, y cortado.
    let mdc_roto = manipular(&armado, |b| *b.last_mut().unwrap() ^= 0x01);
    let cuerpo_roto = manipular(&armado, |b| {
        let medio = b.len() / 2;
        b[medio] ^= 0x01;
    });
    let cortado = manipular(&armado, |b| b.truncate(b.len() - 20));

    for (que, armado) in [
        ("MDC roto", &mdc_roto),
        ("cuerpo manipulado", &cuerpo_roto),
        ("cortado", &cortado),
    ] {
        for (via, raw) in [
            ("inline", correo_inline(armado)),
            ("pgp/mime", correo_pgp_mime(armado)),
        ] {
            let body = rows(&raw, Some(&material(&yo)), &[]);
            let etiqueta = format!("{que} / {via}");
            assert_eq!(body.pgp_encrypted, Some(2), "{etiqueta}");
            assert_sin_claro(&etiqueta, &body);
            if via == "pgp/mime" {
                assert_cuerpo_vacio(&etiqueta, &body);
            }
        }
    }

    // Sin nuestra clave (la cuenta no tiene identidad PGP), y con la clave de otro.
    for (via, raw) in [
        ("inline", correo_inline(&armado)),
        ("pgp/mime", correo_pgp_mime(&armado)),
    ] {
        let sin_clave = rows(&raw, None, &[]);
        assert_eq!(sin_clave.pgp_encrypted, Some(2), "sin clave / {via}");
        assert_sin_claro(&format!("sin clave / {via}"), &sin_clave);

        let ajena = rows(&raw, Some(&material(&otro)), &[]);
        assert_eq!(ajena.pgp_encrypted, Some(2), "clave ajena / {via}");
        assert_sin_claro(&format!("clave ajena / {via}"), &ajena);
    }
}

/// Hallazgo de QA sobre PR4: en un PGP **inline** que no se puede abrir, el cuerpo
/// guardado es la **armadura del sobre** (el texto del mensaje es el blob cifrado).
/// No filtra el claro, pero contradice lo que dicen la V15 y el doc de
/// `opened_rows_decrypting` («el cuerpo queda vacío, nunca roto»), a diferencia de
/// S/MIME y de PGP/MIME, donde el sobre no es una parte de texto. Se deja `ignore`
/// hasta decidir el arreglo; al arreglarlo se le quita el `ignore`.
#[test]
#[ignore = "hallazgo PR4: el inline no abierto guarda la armadura como cuerpo"]
fn un_pgp_inline_que_no_se_pudo_abrir_queda_con_el_cuerpo_vacio() {
    let yo = clave_completa("Yo <yo@vasak.test>");
    let otro = clave_completa("Otro <otro@vasak.test>");
    let raw = correo_inline(&cifrar(CLARO.as_bytes(), &publica(&yo)));
    for (que, pgp) in [("sin clave", None), ("clave ajena", Some(material(&otro)))] {
        let body = rows(&raw, pgp.as_ref(), &[]);
        assert_eq!(body.pgp_encrypted, Some(2), "{que}");
        assert_cuerpo_vacio(que, &body);
    }
}

// ── Firma y TOFU ───────────────────────────────────────────────────────

#[test]
fn la_firma_que_cierra_contra_la_clave_conocida_del_from_queda_conocida_con_su_huella() {
    let alice = clave_completa("Alice <alice@vasak.test>");
    for (via, raw) in [
        ("pgp/mime", firmado_mime("alice@vasak.test", &alice, "hola")),
        ("inline", firmado_inline("alice@vasak.test", &alice, "hola")),
    ] {
        let body = rows(&raw, None, &[publica(&alice)]);
        assert_eq!(body.pgp_status, Some(0), "{via}");
        assert_eq!(body.pgp_signer, Some(huella(&alice)), "{via}");
        assert_eq!(body.pgp_encrypted, None, "{via}");
    }
}

#[test]
fn firmado_sin_ninguna_clave_para_el_from_queda_desconocido_y_sin_firmante() {
    let alice = clave_completa("Alice <alice@vasak.test>");
    for (via, raw) in [
        ("pgp/mime", firmado_mime("alice@vasak.test", &alice, "hola")),
        ("inline", firmado_inline("alice@vasak.test", &alice, "hola")),
    ] {
        let body = rows(&raw, None, &[]);
        assert_eq!((body.pgp_status, body.pgp_signer), (Some(1), None), "{via}");
    }
}

#[test]
fn con_una_clave_del_from_que_no_liga_la_firma_queda_no_verificable_sin_firmante() {
    let alice = clave_completa("Alice <alice@vasak.test>");
    let mallory = clave_completa("Mallory <mallory@vasak.test>");
    // From spoofeado: dice ser alice (de quien tenemos la clave) pero lo firmó mallory.
    for (via, raw) in [
        (
            "pgp/mime",
            firmado_mime("alice@vasak.test", &mallory, "pagá ya"),
        ),
        (
            "inline",
            firmado_inline("alice@vasak.test", &mallory, "pagá ya"),
        ),
    ] {
        let body = rows(&raw, None, &[publica(&alice)]);
        assert_eq!(
            (body.pgp_status, body.pgp_signer),
            (Some(2), None),
            "spoof {via}"
        );
    }

    // Firma rota: el contenido cambió después de firmar.
    let firmado = String::from_utf8(firmado_mime("alice@vasak.test", &alice, "pago 100")).unwrap();
    let roto = firmado.replace("pago 100", "pago 900");
    let body = rows(roto.as_bytes(), None, &[publica(&alice)]);
    assert_eq!(
        (body.pgp_status, body.pgp_signer),
        (Some(2), None),
        "firma rota"
    );
}

#[test]
fn un_correo_sin_firma_ni_cifrado_pgp_no_lleva_ninguna_marca_pgp() {
    let alice = clave_completa("Alice <alice@vasak.test>");
    let plano = b"From: alice@vasak.test\r\nContent-Type: text/plain\r\n\r\nhola\r\n";
    for (que, pgp, candidatas) in [
        ("sin nada", None, vec![]),
        (
            "con clave y candidatas",
            Some(material(&alice)),
            vec![publica(&alice)],
        ),
    ] {
        let body = rows(plano, pgp.as_ref(), &candidatas);
        assert_eq!(
            (body.pgp_status, body.pgp_signer.clone(), body.pgp_encrypted),
            (None, None, None),
            "{que}"
        );
        assert!(text(&body).contains("hola"), "{que}");
    }
}

#[test]
fn cifrado_y_firmado_se_abre_y_la_firma_de_adentro_se_verifica_contra_el_from() {
    let yo = clave_completa("Yo <yo@vasak.test>");
    let alice = clave_completa("Alice <alice@vasak.test>");
    // sign-then-encrypt: un cleartext firmado por alice, y todo cifrado a yo.
    let interior = cleartext_de(SECRETO, &*alice.secret_subkeys[0]);
    let armado = cifrar(interior.as_bytes(), &publica(&yo));
    let raw = correo_inline(&armado);

    let con_clave = rows(&raw, Some(&material(&yo)), &[publica(&alice)]);
    assert_eq!(con_clave.pgp_encrypted, Some(1));
    assert!(text(&con_clave).contains(SECRETO));
    assert_eq!(con_clave.pgp_status, Some(0));
    assert_eq!(con_clave.pgp_signer, Some(huella(&alice)));

    // Sin la clave de alice: abre igual, pero la firma es de clave desconocida.
    let sin_alice = rows(&raw, Some(&material(&yo)), &[]);
    assert_eq!(sin_alice.pgp_encrypted, Some(1));
    assert_eq!(
        (sin_alice.pgp_status, sin_alice.pgp_signer),
        (Some(1), None)
    );
}

// ── Ortogonalidad con S/MIME ───────────────────────────────────────────

#[test]
fn un_mensaje_smime_no_toca_los_campos_pgp_aunque_haya_material_y_candidatas() {
    let yo = clave_completa("Yo <yo@vasak.test>");
    let alice = clave_completa("Alice <alice@vasak.test>");
    let firmado = sign(RSA_P12, &draft(RSA_ADDRESS, "hola firmado"))
        .message
        .into_bytes();
    let pgp = material(&yo);
    let candidatas = [publica(&alice)];

    // S/MIME firmado.
    let (body, _) = opened_rows_decrypting(
        1,
        &firmado,
        false,
        Some(&smime_material()),
        Some(&pgp),
        &candidatas,
    );
    assert_eq!(body.smime_status, Some(0));
    assert_eq!(
        (body.pgp_status, body.pgp_signer, body.pgp_encrypted),
        (None, None, None)
    );

    // S/MIME cifrado.
    let (body, _) = opened_rows_decrypting(
        1,
        AES256,
        false,
        Some(&smime_material()),
        Some(&pgp),
        &candidatas,
    );
    assert_eq!(body.smime_encrypted, Some(1));
    assert!(text(&body).contains("mensaje secreto"));
    assert_eq!(
        (body.pgp_status, body.pgp_signer, body.pgp_encrypted),
        (None, None, None)
    );
}

#[test]
fn un_mensaje_pgp_no_toca_los_campos_smime_aunque_haya_material_smime() {
    let yo = clave_completa("Yo <yo@vasak.test>");
    let alice = clave_completa("Alice <alice@vasak.test>");
    let smime = smime_material();

    let firmado = firmado_mime("alice@vasak.test", &alice, "hola");
    let (body, _) = opened_rows_decrypting(
        1,
        &firmado,
        false,
        Some(&smime),
        Some(&material(&yo)),
        &[publica(&alice)],
    );
    assert_eq!(body.pgp_status, Some(0));
    assert_eq!(
        (body.smime_status, body.smime_signer, body.smime_encrypted),
        (None, None, None)
    );

    let cifrado = correo_inline(&cifrar(CLARO.as_bytes(), &publica(&yo)));
    let (body, _) =
        opened_rows_decrypting(1, &cifrado, false, Some(&smime), Some(&material(&yo)), &[]);
    assert_eq!(body.pgp_encrypted, Some(1));
    assert!(text(&body).contains(SECRETO));
    assert_eq!(
        (body.smime_status, body.smime_signer, body.smime_encrypted),
        (None, None, None)
    );
}

#[test]
fn un_correo_comun_rinde_lo_mismo_con_o_sin_material_y_candidatas_pgp() {
    // Un correo común rinde lo mismo con o sin material y candidatas PGP: tener
    // clave no cambia nada de lo demás.
    let yo = generar(
        "Yo <yo@vasak.test>",
        vec![subclave_de_firma(), subclave_de_cifrado(None)],
    );
    let plano = b"From: ana@x.com\r\nContent-Type: text/plain\r\n\r\nhola\r\n";
    let con = rows(plano, Some(&material(&yo)), &[publica(&yo)]);
    let sin = rows(plano, None, &[]);
    assert_eq!(con, sin);
}
