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
/// S/MIME y de PGP/MIME, donde el sobre no es una parte de texto.
#[test]
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

// ── Hallazgos de revisión (PR4) ────────────────────────────────────────

const SMIME_CON_FIRMA_PGP: &[u8] =
    include_bytes!("../../tests/fixtures/pgp/smime-enveloped-con-firma-pgp.eml");
const FIRMANTE_PGP_PUB: &[u8] = include_bytes!("../../tests/fixtures/pgp/firmante.pub.asc");

#[test]
fn una_firma_pgp_dentro_de_un_sobre_smime_abierto_se_verifica() {
    let firmante = crate::pgp::parse_public_key(FIRMANTE_PGP_PUB).expect("la clave de prueba");
    let huella = firmante.primary_key.fingerprint().to_string();

    // Con la clave del firmante como candidata, la firma de adentro cierra.
    let (body, _) = opened_rows_decrypting(
        1,
        SMIME_CON_FIRMA_PGP,
        false,
        Some(&smime_material()),
        None,
        std::slice::from_ref(&firmante),
    );
    assert_eq!(body.smime_encrypted, Some(1), "el sobre S/MIME se abrió");
    assert!(
        text(&body).contains("SECRETO-PGP-EN-S-MIME"),
        "{:?}",
        body.text_body
    );
    assert_eq!(
        body.pgp_status,
        Some(0),
        "la firma PGP de adentro se verificó"
    );
    assert_eq!(body.pgp_signer, Some(huella));
    // Es PGP dentro de S/MIME: el estado S/MIME de la firma no se toca.
    assert_eq!(body.smime_status, None);

    // Sin candidatas la firma se ve, pero de clave desconocida (no «no chequeada»).
    let (sin_clave, _) = opened_rows_decrypting(
        1,
        SMIME_CON_FIRMA_PGP,
        false,
        Some(&smime_material()),
        None,
        &[],
    );
    assert_eq!(
        (sin_clave.pgp_status, sin_clave.pgp_signer),
        (Some(1), None)
    );
}

/// Un multipart con un adjunto, como contenido (con sus propias cabeceras).
const MULTIPART_CON_ADJUNTO: &str = "Content-Type: multipart/mixed; boundary=\"M\"\r\n\r\n\
--M\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSECRETO-PGP: con adjunto\r\n\
--M\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"informe.pdf\"\r\n\r\ndatos\r\n\
--M--\r\n";

#[test]
fn un_sobre_pgp_abierto_no_lista_adjuntos_con_numeros_del_arbol_descifrado() {
    let yo = clave_completa("Yo <yo@vasak.test>");
    // Control: el mismo multipart **sin cifrar** sí lista el adjunto (si no, el
    // «vacío» de abajo no probaría nada).
    let plano = format!("From: ana@x.com\r\n{MULTIPART_CON_ADJUNTO}");
    let (_, adjuntos) = opened_rows_decrypting(7, plano.as_bytes(), false, None, None, &[]);
    assert_eq!(adjuntos.len(), 1);
    assert_eq!(adjuntos[0].part_number, "2");

    // Cifrado (inline y PGP/MIME): se abre y se muestra, pero los números de parte del
    // árbol descifrado no son secciones IMAP del mensaje cifrado, así que no se listan.
    let armado = cifrar(MULTIPART_CON_ADJUNTO.as_bytes(), &publica(&yo));
    for (via, raw) in [
        ("inline", correo_inline(&armado)),
        ("pgp/mime", correo_pgp_mime(&armado)),
    ] {
        let (body, adjuntos) =
            opened_rows_decrypting(7, &raw, false, None, Some(&material(&yo)), &[]);
        assert_eq!(body.pgp_encrypted, Some(1), "{via}");
        assert!(text(&body).contains("SECRETO-PGP: con adjunto"), "{via}");
        assert!(
            adjuntos.is_empty(),
            "{via}: no se emiten filas con números del árbol descifrado: {adjuntos:?}"
        );
    }
}

// ── La identidad que se importa es la que lee el descifrado ─────────────

/// **Regresión load-bearing.** `ImportPgpIdentity` guarda por `account_id` y
/// `pgp_material` lee por `account_id`: si una de las dos puntas cambiara de
/// clave (la dirección, por ejemplo), la identidad quedaría partida —firmar la
/// vería y descifrar no, o al revés— sin ningún síntoma. Se importa por D-Bus, de
/// verdad, y se lee con la función real del descifrado.
#[tokio::test]
async fn lo_que_importa_el_import_es_lo_que_lee_el_descifrado_por_el_mismo_account_id() {
    use crate::pgp_ipc_tests::import;
    use crate::pgp_send_tests::{armored, fingerprint, protected_key};

    let f = crate::test_bus::Fixture::start(&[("cta", "ana@vasak.test")]).await;
    let key = protected_key("Ana <ana@vasak.test>", "frase-de-paso-de-prueba");
    import(&f, "cta", &armored(&key), b"frase-de-paso-de-prueba")
        .await
        .unwrap();

    // `pgp_material` abre el bus de sesión: se lo apunta al bus privado de la
    // prueba (el mismo donde vive el llavero falso). El `Fixture` serializa las
    // pruebas que lo usan.
    std::env::set_var(
        "DBUS_SESSION_BUS_ADDRESS",
        std::env::var("DBUS_SYSTEM_BUS_ADDRESS").unwrap(),
    );
    let material = pgp_material("cta")
        .await
        .expect("el descifrado no ve la identidad que se importó");

    assert_eq!(
        material.secret_key.primary_key.fingerprint().to_string(),
        fingerprint(&key)
    );
    // La contraseña que leyó abre la clave: firma con ella.
    crate::pgp::sign_detached(b"x", &material.secret_key, &material.passphrase)
        .expect("la contraseña que lee el descifrado no abre la clave");
    // Y bajo la dirección no hay identidad: no hay una segunda copia escondida.
    assert!(pgp_material("ana@vasak.test").await.is_none());
}

// ── La clave que se guarda es la saneada ────────────────────────────────

/// Importa `key` (armada, sin contraseña) por D-Bus en la cuenta `cta` y devuelve
/// el material que lee el descifrado, o `None` si no lo ve.
async fn material_after_import(key: &[u8]) -> Option<PgpMaterial> {
    use crate::pgp_ipc_tests::import;
    let f = crate::test_bus::Fixture::start(&[("cta", "ana@vasak.test")]).await;
    import(&f, "cta", key, b"").await.unwrap();
    std::env::set_var(
        "DBUS_SESSION_BUS_ADDRESS",
        std::env::var("DBUS_SYSTEM_BUS_ADDRESS").unwrap(),
    );
    pgp_material("cta").await
}

fn can_sign(material: &PgpMaterial) -> bool {
    crate::pgp::sign_detached(b"x", &material.secret_key, &material.passphrase).is_ok()
}

#[tokio::test]
async fn una_revocacion_de_primaria_forjada_no_vuelve_al_leer_la_identidad_importada() {
    use crate::pgp::tests::{clave_vieja, con_primaria_revocada};
    use crate::pgp_send_tests::armored;
    let alice = clave_vieja("Ana <ana@vasak.test>");
    let mallory = clave_vieja("Mallory <mallory@vasak.test>");
    // La revocación de la primaria de Mallory pegada a la clave de Ana: no cierra
    // contra la primaria de Ana, es forjada.
    let mut forged = alice.clone();
    forged.details.revocation_signatures.extend(
        con_primaria_revocada(&mallory)
            .details
            .revocation_signatures,
    );
    let blob = armored(&forged);

    // Sin sanear, la clave parece revocada y no firmaría: el escenario es real.
    let unsanitized = crate::pgp::parse_secret_key(&blob).unwrap();
    assert!(!crate::pgp::can_sign_now(&unsanitized));

    // Importada y releída por el camino del descifrado, firma.
    let material = material_after_import(&blob)
        .await
        .expect("el descifrado no ve la identidad");
    assert!(can_sign(&material));
}

#[tokio::test]
async fn una_auto_revocacion_valida_de_la_primaria_sobrevive_al_saneo() {
    use crate::pgp::tests::{clave_vieja, con_primaria_muerta, con_primaria_revocada};
    use crate::pgp_send_tests::armored;
    let vivo = clave_vieja("Ana <ana@vasak.test>");
    let revocada = con_primaria_muerta(&vivo, con_primaria_revocada(&vivo));

    let material = material_after_import(&armored(&revocada))
        .await
        .expect("el descifrado no ve la identidad");

    // Genuinamente revocada: se guarda revocada y no firma.
    assert!(!can_sign(&material));
}

#[tokio::test]
async fn los_bytes_saneados_que_se_guardan_se_releen_como_la_misma_clave() {
    use crate::pgp::tests::clave_vieja;
    use crate::pgp_send_tests::armored;
    let key = clave_vieja("Ana <ana@vasak.test>");

    let material = material_after_import(&armored(&key))
        .await
        .expect("el descifrado no ve la identidad");

    assert_eq!(
        material.secret_key.primary_key.fingerprint().to_string(),
        key.primary_key.fingerprint().to_string()
    );
    assert!(can_sign(&material));
}
