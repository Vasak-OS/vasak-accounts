//! El anuncio de la cabecera `Autocrypt:` propia en los salientes (`vasak-accounts#21`,
//! PR8): presente con identidad OpenPGP en los cuatro caminos (plano, firmado PGP,
//! firmado S/MIME, cifrado), ausente sin identidad, simétrica con el parseo entrante,
//! sin `prefer-encrypt`, sin inyección de cabeceras y con la clave **pública**.
//! Va contra el llavero falso de `store::key`.

use crate::compose::{self, Draft, EncryptMethod, SignMethod};
use crate::message::Headers;
use crate::pgp::tests::{clave_completa, publica};
use crate::pgp_import::parse_autocrypt_header;
use crate::pgp_send_tests::{armored, ACCOUNT, ADDRESS};
use crate::smime_sign::test_support::{
    self as smime, DATE, MESSAGE_ID, PASSWORD, RSA_ADDRESS, RSA_P12,
};
use crate::store::key::tests::fake_keyring;
use crate::store::key::SecretServiceKeys;
use crate::store::smime_key::import_pkcs12;
use crate::wkd::{WkdError, WkdKey};
use crate::wkd_ipc_tests::{manager, CUENTA};
use pgp::composed::{SignedPublicKey, SignedSecretKey};
use pgp::ser::Serialize;
use pgp::types::KeyDetails;

fn plain_draft() -> Draft {
    Draft {
        from: ADDRESS.into(),
        to: vec!["dest@otro.test".into()],
        subject: "Hola".into(),
        body: "cuerpo".into(),
        ..Default::default()
    }
}

async fn with_identity() -> (SecretServiceKeys, SignedSecretKey) {
    let (keys, server, shared) = fake_keyring().await;
    // El servidor y el estado compartido tienen que vivir lo que dure la prueba.
    std::mem::forget((server, shared));
    let key = clave_completa("Ana <ana@vasak.test>");
    keys.store_pgp_identity(ACCOUNT, &armored(&key), b"")
        .await
        .unwrap();
    (keys, key)
}

async fn send(keys: &SecretServiceKeys, draft: &Draft) -> String {
    crate::compose_outgoing(keys, draft, ACCOUNT, MESSAGE_ID, DATE)
        .await
        .unwrap()
}

/// Las cabeceras `Autocrypt` del sobre externo, ya desplegadas como las lee el lector.
fn autocrypt_of(message: &str) -> Vec<String> {
    let head = message.split_once("\r\n\r\n").unwrap().0;
    Headers::parse(head)
        .get_all("autocrypt")
        .map(str::to_string)
        .collect()
}

fn single(message: &str) -> String {
    let mut all = autocrypt_of(message);
    assert_eq!(all.len(), 1, "debe haber exactamente una Autocrypt");
    all.remove(0)
}

fn public_bytes(key: &SignedSecretKey) -> Vec<u8> {
    publica(key).to_bytes().unwrap()
}

/// Verifica la simetría: el lector la parsea y la clave es la de la identidad.
fn assert_announces(message: &str, key: &SignedSecretKey, from: &str) {
    let parsed = parse_autocrypt_header(&single(message)).expect("la cabecera no parsea");
    assert_eq!(parsed.addr, from);
    let announced = crate::pgp::parse_public_key(&parsed.key).unwrap();
    assert_eq!(
        announced.primary_key.fingerprint(),
        key.primary_key.fingerprint()
    );
}

// ── 1. Presente con identidad, en los cuatro caminos ────────────────────

#[tokio::test]
async fn el_mensaje_plano_con_identidad_anuncia_la_clave() {
    let (keys, key) = with_identity().await;
    let message = send(&keys, &plain_draft()).await;
    assert_announces(&message, &key, ADDRESS);
}

#[tokio::test]
async fn el_mensaje_firmado_con_pgp_anuncia_la_clave() {
    let (keys, key) = with_identity().await;
    let draft = Draft {
        sign_method: Some(SignMethod::Pgp),
        ..plain_draft()
    };
    let message = send(&keys, &draft).await;
    assert!(message.contains("multipart/signed"));
    assert_announces(&message, &key, ADDRESS);
}

#[tokio::test]
async fn el_mensaje_firmado_con_smime_y_con_identidad_pgp_anuncia_la_clave() {
    let (keys, key) = with_identity().await;
    import_pkcs12(&keys, RSA_ADDRESS, RSA_P12, PASSWORD)
        .await
        .unwrap();
    let draft = smime::draft(RSA_ADDRESS, "hola");

    let message = send(&keys, &draft).await;

    assert!(message.contains("multipart/signed"));
    assert_announces(&message, &key, RSA_ADDRESS);
}

#[tokio::test]
async fn el_firmado_con_smime_sin_identidad_pgp_sale_sin_autocrypt() {
    let (keys, _server, _shared) = fake_keyring().await;
    import_pkcs12(&keys, RSA_ADDRESS, RSA_P12, PASSWORD)
        .await
        .unwrap();

    let message = send(&keys, &smime::draft(RSA_ADDRESS, "hola")).await;

    assert!(message.contains("multipart/signed"));
    assert!(autocrypt_of(&message).is_empty());
}

/// Cifra a `peer` (resuelto por un WKD inyectado) desde la cuenta `CUENTA`, con o sin
/// identidad propia guardada.
async fn encrypted(
    keys: &SecretServiceKeys,
    own: Option<&SignedSecretKey>,
    peer: &SignedSecretKey,
) -> String {
    let (_t, m) = manager("autocrypt-enc").await;
    if let Some(own) = own {
        keys.store_pgp_identity(CUENTA, &armored(own), b"")
            .await
            .unwrap();
    }
    let draft = Draft {
        encrypt_method: Some(EncryptMethod::Pgp),
        ..plain_draft()
    };
    let peer_public = publica(peer);
    let fetch = move |_: String| {
        std::future::ready(Ok::<Option<WkdKey>, WkdError>(Some(WkdKey {
            bytes: peer_public.to_bytes().unwrap(),
            fingerprint: crate::pgp::fingerprint(&peer_public),
        })))
    };
    crate::encrypt_outgoing_pgp(&m, keys, &draft, CUENTA, MESSAGE_ID, DATE, fetch)
        .await
        .unwrap()
}

#[tokio::test]
async fn el_cifrado_anuncia_la_clave_en_el_sobre_externo_y_no_dentro_del_cifrado() {
    let (keys, _server, _shared) = fake_keyring().await;
    let own = clave_completa("Ana <ana@vasak.test>");
    let peer = clave_completa("Dest <dest@otro.test>");

    let message = encrypted(&keys, Some(&own), &peer).await;

    assert!(message.contains("multipart/encrypted"));
    assert_announces(&message, &own, ADDRESS);
    // Va en claro, antes del `multipart/encrypted`.
    let head = message.split_once("\r\n\r\n").unwrap().0;
    assert!(head.find("Autocrypt: ") < head.find("Content-Type: multipart/encrypted"));
    // Y NO dentro del texto cifrado.
    match crate::pgp::decrypt(message.as_bytes(), &peer, &crate::pgp::tests::vacia()) {
        crate::pgp::Decryption::Opened(inner) => {
            let inner = String::from_utf8(inner.to_vec()).unwrap();
            assert!(!inner.to_ascii_lowercase().contains("autocrypt"), "{inner}");
        }
        other => panic!("se esperaba Opened, salió {other:?}"),
    }
}

// ── 2. Ausente sin identidad ────────────────────────────────────────────

#[tokio::test]
async fn sin_identidad_el_mensaje_sale_igual_y_sin_autocrypt() {
    let (keys, _server, _shared) = fake_keyring().await;
    let message = send(&keys, &plain_draft()).await;
    assert!(autocrypt_of(&message).is_empty());
    assert!(message.contains("Subject: Hola"));
}

#[tokio::test]
async fn con_la_identidad_corrupta_no_se_anuncia_nada_y_el_mensaje_sale() {
    let (keys, _server, _shared) = fake_keyring().await;
    keys.store_pgp_identity(ACCOUNT, b"esto no es una clave", b"")
        .await
        .unwrap();
    let message = send(&keys, &plain_draft()).await;
    assert!(autocrypt_of(&message).is_empty());
}

#[tokio::test]
async fn el_cifrado_sin_identidad_propia_sale_sin_autocrypt() {
    let (keys, _server, _shared) = fake_keyring().await;
    let peer = clave_completa("Dest <dest@otro.test>");
    let message = encrypted(&keys, None, &peer).await;
    assert!(message.contains("multipart/encrypted"));
    assert!(autocrypt_of(&message).is_empty());
}

#[tokio::test]
async fn el_cifrado_con_identidad_corrupta_sale_sin_autocrypt() {
    let (keys, _server, _shared) = fake_keyring().await;
    keys.store_pgp_identity(CUENTA, b"esto no es una clave", b"")
        .await
        .unwrap();
    let peer = clave_completa("Dest <dest@otro.test>");
    let message = encrypted(&keys, None, &peer).await;
    assert!(autocrypt_of(&message).is_empty());
}

// ── 3. Simetría con el parseo entrante ──────────────────────────────────

#[test]
fn lo_que_se_emite_lo_parsea_el_lector_y_devuelve_la_misma_huella() {
    let key = clave_completa("Ana <ana@vasak.test>");
    let message = compose::build_message_with_autocrypt(
        &plain_draft(),
        MESSAGE_ID,
        DATE,
        Some(&compose::autocrypt_header(ADDRESS, &public_bytes(&key))),
    )
    .unwrap();

    // `Headers::parse` despliega las continuaciones como el lector real.
    assert_announces(&message, &key, ADDRESS);
    // El keydata es largo: se plegó (hay al menos un renglón de continuación).
    assert!(message.split_once("\r\n\r\n").unwrap().0.contains("\r\n "));
}

// ── 4. addr == From ─────────────────────────────────────────────────────

#[tokio::test]
async fn el_addr_es_el_from_de_la_cuenta() {
    let (keys, _key) = with_identity().await;
    let message = send(&keys, &plain_draft()).await;
    let parsed = parse_autocrypt_header(&single(&message)).unwrap();
    assert_eq!(parsed.addr, plain_draft().from);
    let head = message.split_once("\r\n\r\n").unwrap().0;
    assert_eq!(Headers::parse(head).get("from"), Some(parsed.addr.as_str()));
}

// ── 5. Sin prefer-encrypt ───────────────────────────────────────────────

#[tokio::test]
async fn la_cabecera_no_lleva_prefer_encrypt() {
    let (keys, _key) = with_identity().await;
    let header = single(&send(&keys, &plain_draft()).await);
    assert!(!header.contains("prefer-encrypt"), "{header}");
    assert!(header.starts_with("addr="), "{header}");
}

// ── 6. No inyecta cabeceras ─────────────────────────────────────────────

#[test]
fn un_addr_con_crlf_no_abre_otra_cabecera() {
    let key = clave_completa("Ana <ana@vasak.test>");
    let header =
        compose::autocrypt_header("ana@vasak.test\r\nBcc: evil@x.test", &public_bytes(&key));

    // Todo salto de línea es una continuación (`\r\n` + espacio): ninguno abre otra cabecera.
    for (i, line) in header.split("\r\n").enumerate() {
        assert!(
            i == 0 || line.starts_with(' '),
            "línea que abriría una cabecera: {line:?}"
        );
    }
    assert!(!header.contains('\n') || header.contains("\r\n "));
    // Leído como un mensaje, hay una sola cabecera y ninguna `Bcc`.
    let parsed = Headers::parse(&format!("{header}\r\nSubject: x\r\n\r\n"));
    assert_eq!(parsed.get_all("autocrypt").count(), 1);
    assert_eq!(parsed.get("bcc"), None);
}

#[test]
fn el_plegado_nunca_parte_la_direccion_ni_mete_otra_cosa_que_continuaciones() {
    let key = clave_completa("Ana <ana@vasak.test>");
    let header = compose::autocrypt_header(ADDRESS, &public_bytes(&key));
    let first = header.split("\r\n").next().unwrap();
    assert!(first.starts_with(&format!("Autocrypt: addr={ADDRESS}; keydata=")));
    for line in header.split("\r\n").skip(1) {
        assert!(line.starts_with(' '));
        assert!(
            line.len() <= 78 + 1,
            "renglón demasiado largo: {}",
            line.len()
        );
        assert!(line[1..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c)));
    }
}

// ── 7. Es la pública, no la secreta ─────────────────────────────────────

#[test]
fn el_keydata_es_la_clave_publica_y_no_trae_material_secreto() {
    let key = clave_completa("Ana <ana@vasak.test>");
    let header = crate::autocrypt_from_secret(ADDRESS, &key).unwrap();
    let value = Headers::parse(&header)
        .get("autocrypt")
        .unwrap()
        .to_string();
    let parsed = parse_autocrypt_header(&value).unwrap();

    assert!(crate::pgp::parse_public_key(&parsed.key).is_ok());
    assert!(
        crate::pgp::parse_secret_key(&parsed.key).is_err(),
        "el keydata parsea como clave secreta"
    );
    // Es exactamente la serialización de la pública, byte a byte.
    assert_eq!(parsed.key, public_bytes(&key));
    // El secreto serializado no aparece contenido en el anunciado.
    assert!(parsed.key.len() < key.to_bytes().unwrap().len());
}

// ── build_message_with_autocrypt ────────────────────────────────────────

#[test]
fn sin_autocrypt_build_message_con_autocrypt_es_build_message() {
    let draft = plain_draft();
    assert_eq!(
        compose::build_message_with_autocrypt(&draft, MESSAGE_ID, DATE, None).unwrap(),
        compose::build_message(&draft, MESSAGE_ID, DATE).unwrap()
    );
}

#[test]
fn con_autocrypt_la_cabecera_va_en_las_de_nivel_superior() {
    let message = compose::build_message_with_autocrypt(
        &plain_draft(),
        MESSAGE_ID,
        DATE,
        Some("Autocrypt: addr=ana@vasak.test; keydata=AAAA"),
    )
    .unwrap();
    let head = message.split_once("\r\n\r\n").unwrap().0;
    assert!(head.contains("\r\nAutocrypt: addr=ana@vasak.test; keydata=AAAA"));
}
