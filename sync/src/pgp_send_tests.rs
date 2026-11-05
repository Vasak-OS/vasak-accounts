//! El camino de envío con PGP/MIME: el método que pide el borrador manda, pedir
//! firma y no poder firmar **falla** (no sale sin firmar), y lo que sale lo
//! verifica el propio verificador de PGP. Va contra el llavero falso de
//! `store::key`. Calca `smime_send_tests`.
//!
//! También guarda los ayudantes de claves que comparte `pgp_ipc_tests`.

use crate::compose::{self, Draft, SignMethod};
use crate::pgp::tests::{
    clave_completa, clave_vieja, con_primaria_con_vencimiento_en_el_uid, con_primaria_muerta,
    con_primaria_revocada, publica,
};
use crate::pgp::Verification as PgpVerification;
use crate::smime_sign::test_support::{
    self as smime, DATE, EC_ADDRESS, EC_P12, MESSAGE_ID, PASSWORD as SMIME_PASSWORD, RSA_ADDRESS,
    RSA_P12,
};
use crate::smime_sign::{verify_message, Verification as SmimeVerification};
use crate::smtp::SmtpError;
use crate::store::key::tests::{fake_keyring, lock_and_announce};
use crate::store::smime_key::import_pkcs12;
use pgp::composed::{
    EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::types::KeyDetails;
use rand::rngs::OsRng;

pub(crate) const ACCOUNT: &str = "cta";
pub(crate) const ADDRESS: &str = "ana@vasak.test";
pub(crate) const PASSPHRASE: &[u8] = b"frase-de-paso-de-prueba";

/// Una clave con la primaria y la subclave de firma protegidas por `passphrase`:
/// firmar exige la contraseña, como una clave real de una persona.
pub(crate) fn protected_key(uid: &str, passphrase: &str) -> SignedSecretKey {
    let mut sub = SubkeyParamsBuilder::default();
    sub.key_type(KeyType::Ed25519Legacy)
        .can_sign(true)
        .can_encrypt(EncryptionCaps::None)
        .can_authenticate(false)
        .passphrase(Some(passphrase.into()));
    let mut key = SecretKeyParamsBuilder::default();
    key.key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(false)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id(uid.into())
        .passphrase(Some(passphrase.into()))
        .subkeys(vec![sub.build().unwrap()]);
    key.build().unwrap().generate(OsRng).unwrap()
}

/// La clave tal cual la exporta un cliente: armor ASCII.
pub(crate) fn armored(key: &SignedSecretKey) -> Vec<u8> {
    key.to_armored_bytes(Default::default()).unwrap()
}

pub(crate) fn fingerprint(key: &SignedSecretKey) -> String {
    key.primary_key.fingerprint().to_string()
}

/// Un borrador que pide este método de firma, sin tocar el viejo `firmar`.
fn draft_with(method: Option<SignMethod>) -> Draft {
    Draft {
        sign: false,
        sign_method: method,
        ..smime::draft(ADDRESS, "hola")
    }
}

fn pgp_draft() -> Draft {
    draft_with(Some(SignMethod::Pgp))
}

fn permanent(result: Result<String, SmtpError>) -> String {
    match result {
        Err(SmtpError::Permanent(detail)) => detail,
        other => {
            let _ = other;
            panic!("se esperaba un fallo permanente")
        }
    }
}

async fn compose(
    keys: &crate::store::key::SecretServiceKeys,
    draft: &Draft,
) -> Result<String, SmtpError> {
    crate::compose_outgoing(keys, draft, ACCOUNT, MESSAGE_ID, DATE).await
}

type Keyring = (
    crate::store::key::SecretServiceKeys,
    zbus::Connection,
    crate::store::key::tests::Shared,
);

/// Un llavero falso con la identidad PGP protegida de la cuenta de prueba.
async fn keyring_with_identity() -> (Keyring, SignedSecretKey) {
    let keyring = fake_keyring().await;
    let key = protected_key("Ana <ana@vasak.test>", "frase-de-paso-de-prueba");
    store_identity(&keyring.0, &key).await;
    (keyring, key)
}

async fn store_identity(keys: &crate::store::key::SecretServiceKeys, key: &SignedSecretKey) {
    keys.store_pgp_identity(ACCOUNT, &armored(key), PASSPHRASE)
        .await
        .unwrap();
}

/// Dos claves de la misma persona con la primaria muerta: revocada y expirada.
pub(crate) fn dead_keys(uid: &str) -> [(&'static str, SignedSecretKey); 2] {
    let vivo = clave_vieja(uid);
    let revocada = con_primaria_muerta(&vivo, con_primaria_revocada(&vivo));
    let expirada = con_primaria_muerta(
        &vivo,
        con_primaria_con_vencimiento_en_el_uid(&vivo, 24 * 3600),
    );
    [("revocada", revocada), ("expirada", expirada)]
}

fn parse_draft(json: &str) -> Draft {
    serde_json::from_str(json).unwrap()
}

fn assert_detail(detail: &str, needle: &str) {
    assert!(
        detail.contains(needle),
        "el detalle del error no es el esperado"
    );
}

fn assert_part(part: &str, needle: &str) {
    assert!(
        part.contains(needle),
        "la parte de la firma no es la esperada"
    );
}

// ── Qué método pide el borrador ─────────────────────────────────────────

#[test]
fn un_borrador_viejo_con_firmar_y_sin_metodo_firma_con_smime() {
    let viejo = parse_draft(r#"{"para": [], "firmar": true}"#);
    assert_eq!(viejo.sign_method, None);
    assert_eq!(viejo.effective_sign_method(), SignMethod::Smime);
}

#[test]
fn un_borrador_sin_firmar_ni_metodo_no_firma() {
    let plano = parse_draft(r#"{"para": []}"#);
    assert_eq!(plano.effective_sign_method(), SignMethod::None);
}

#[test]
fn el_metodo_explicito_manda_sobre_el_firmar_viejo() {
    let pgp = parse_draft(r#"{"para": [], "metodo_firma": "pgp"}"#);
    assert_eq!(pgp.effective_sign_method(), SignMethod::Pgp);
    // Con el viejo `firmar` en true, el campo nuevo gana.
    let pgp = parse_draft(r#"{"para": [], "firmar": true, "metodo_firma": "pgp"}"#);
    assert_eq!(pgp.effective_sign_method(), SignMethod::Pgp);
    // «none» explícito es no firmar, aunque `firmar` diga que sí.
    let none = parse_draft(r#"{"para": [], "firmar": true, "metodo_firma": "none"}"#);
    assert_eq!(none.effective_sign_method(), SignMethod::None);
    let smime = parse_draft(r#"{"para": [], "metodo_firma": "smime"}"#);
    assert_eq!(smime.effective_sign_method(), SignMethod::Smime);
}

#[test]
fn el_metodo_ausente_no_se_serializa_y_el_presente_si() {
    let json = serde_json::to_value(Draft::default()).unwrap();
    assert!(json.get("metodo_firma").is_none(), "{json}");
    let json = serde_json::to_value(pgp_draft()).unwrap();
    assert_eq!(json["metodo_firma"], "pgp");
}

// ── Firmar con la identidad de la cuenta ────────────────────────────────

#[tokio::test]
async fn pedir_firma_pgp_sin_identidad_falla_con_un_error_claro() {
    let (keys, _server, _shared) = fake_keyring().await;

    let detail = permanent(compose(&keys, &pgp_draft()).await);

    // No se manda sin firmar: dice qué falta, y de qué cuenta.
    assert_detail(&detail, "OpenPGP");
    assert_detail(&detail, ACCOUNT);
}

#[tokio::test]
async fn la_identidad_de_otra_cuenta_no_sirve_para_firmar_desde_esta() {
    let (keys, _server, _shared) = fake_keyring().await;
    let key = protected_key("Ana <ana@vasak.test>", "x");
    keys.store_pgp_identity("otra", &armored(&key), b"x")
        .await
        .unwrap();

    let detail = permanent(compose(&keys, &pgp_draft()).await);

    assert_detail(&detail, ACCOUNT);
}

#[tokio::test]
async fn con_identidad_el_mensaje_sale_firmado_y_la_firma_verifica() {
    let ((keys, _server, _shared), key) = keyring_with_identity().await;

    let draft = pgp_draft();
    let message = compose(&keys, &draft).await.unwrap();

    // Verifica contra la clave de la cuenta: se firmó con ella y con la
    // contraseña guardada.
    assert_eq!(
        crate::pgp::verify(message.as_bytes(), &[publica(&key)]),
        PgpVerification::SignedUntrusted(fingerprint(&key))
    );
    // Y no es una firma S/MIME.
    assert_eq!(
        verify_message(message.as_bytes()),
        SmimeVerification::NotSigned
    );

    // La estructura de RFC 3156: dos partes; la 1ª es la entidad de contenido tal
    // cual se firmó, la 2ª `application/pgp-signature` con el armor en 7bit.
    let (head, _) = message.split_once("\r\n\r\n").unwrap();
    assert!(
        head.contains(
            "multipart/signed; protocol=\"application/pgp-signature\"; micalg=\"pgp-sha256\""
        ),
        "la cabecera no es la esperada"
    );
    let boundary = head
        .split("boundary=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("la frontera");
    let delimiter = format!("--{boundary}");
    let body = message.split_once("\r\n\r\n").unwrap().1;
    let parts: Vec<&str> = body.split(delimiter.as_str()).collect();
    // Antes de la 1ª frontera, las dos partes, y el cierre `--`.
    assert_eq!(parts.len(), 4, "las partes no son dos");
    assert!(parts[3].starts_with("--"), "el cierre no es `--`");
    let content = compose::build_content_entity(&draft);
    assert_eq!(parts[1], format!("\r\n{content}\r\n"));
    let signature = parts[2];
    assert_part(signature, "Content-Type: application/pgp-signature");
    assert_part(signature, "Content-Transfer-Encoding: 7bit");
    assert!(
        !signature.to_ascii_lowercase().contains("base64"),
        "la parte de la firma no es la esperada"
    );
    assert_part(signature, "-----BEGIN PGP SIGNATURE-----");
    assert_part(signature, "-----END PGP SIGNATURE-----");
}

#[tokio::test]
async fn la_firma_pgp_no_verifica_contra_otra_clave_ni_con_el_contenido_cambiado() {
    let ((keys, _server, _shared), key) = keyring_with_identity().await;
    let message = compose(&keys, &pgp_draft()).await.unwrap();

    let otra = clave_completa("Mallory <mallory@vasak.test>");
    assert!(matches!(
        crate::pgp::verify(message.as_bytes(), &[publica(&otra)]),
        PgpVerification::Unverified(_)
    ));
    // Si el cuerpo cambia en tránsito, deja de verificar.
    let tampered = message.replace("hola", "chau");
    assert_ne!(tampered, message);
    assert!(matches!(
        crate::pgp::verify(tampered.as_bytes(), &[publica(&key)]),
        PgpVerification::Unverified(_)
    ));
}

#[tokio::test]
async fn con_la_primaria_muerta_el_envio_falla_y_no_sale_sin_firmar() {
    for (what, key) in dead_keys("Ana <ana@vasak.test>") {
        let (keys, _server, _shared) = fake_keyring().await;
        keys.store_pgp_identity(ACCOUNT, &armored(&key), b"")
            .await
            .unwrap();

        let detail = permanent(compose(&keys, &pgp_draft()).await);

        // Es `NoSigningKey`, no un mensaje armado a medias.
        assert!(
            detail.to_lowercase().contains("firma") || detail.contains("sign"),
            "{what}: el detalle del error no es el esperado"
        );
    }
}

#[tokio::test]
async fn con_el_llavero_bloqueado_el_envio_firmado_con_pgp_se_reintenta() {
    let ((keys, server, shared), _key) = keyring_with_identity().await;
    lock_and_announce(&server, &shared).await.unwrap();

    let result = compose(&keys, &pgp_draft()).await;

    // Bloqueado no es «no hay identidad»: se desbloquea y sale.
    assert!(
        matches!(result, Err(SmtpError::Temporary(_))),
        "no se pidió reintentar"
    );
}

// ── Lo que no pide firma no paga nada ───────────────────────────────────

#[tokio::test]
async fn sin_pedir_firma_el_mensaje_sale_como_siempre_haya_o_no_identidad() {
    let plain = draft_with(None);
    let expected = compose::build_message(&plain, MESSAGE_ID, DATE).unwrap();

    let (empty, _server, _shared) = fake_keyring().await;
    let (loaded, _server2, _shared2) = fake_keyring().await;
    let key = protected_key("Ana <ana@vasak.test>", "frase-de-paso-de-prueba");
    store_identity(&loaded, &key).await;
    import_pkcs12(&loaded, ADDRESS, RSA_P12, SMIME_PASSWORD)
        .await
        .unwrap();

    for keys in [&empty, &loaded] {
        for draft in [&plain, &draft_with(Some(SignMethod::None))] {
            let message = compose(keys, draft).await.unwrap();
            assert_eq!(message, expected);
            assert_eq!(
                crate::pgp::verify(message.as_bytes(), &[publica(&key)]),
                PgpVerification::NotSigned
            );
        }
    }
}

// ── Si la cuenta tiene las dos identidades, manda el método pedido ──────

#[tokio::test]
async fn con_las_dos_identidades_se_firma_con_el_metodo_pedido_y_no_con_el_que_haya() {
    let (keys, _server, _shared) = fake_keyring().await;
    // La dirección del certificado S/MIME de prueba es `RSA_ADDRESS`; la misma
    // cuenta guarda también una identidad PGP.
    let key = protected_key(&format!("Ana <{RSA_ADDRESS}>"), "frase-de-paso-de-prueba");
    keys.store_pgp_identity(ACCOUNT, &armored(&key), PASSPHRASE)
        .await
        .unwrap();
    import_pkcs12(&keys, RSA_ADDRESS, RSA_P12, SMIME_PASSWORD)
        .await
        .unwrap();
    // Y una más de S/MIME de otra dirección, que no debe colarse.
    import_pkcs12(&keys, EC_ADDRESS, EC_P12, SMIME_PASSWORD)
        .await
        .unwrap();
    let draft = |method| Draft {
        from: RSA_ADDRESS.into(),
        ..draft_with(Some(method))
    };

    let pgp = compose(&keys, &draft(SignMethod::Pgp)).await.unwrap();
    assert_eq!(
        crate::pgp::verify(pgp.as_bytes(), &[publica(&key)]),
        PgpVerification::SignedUntrusted(fingerprint(&key))
    );
    assert_eq!(verify_message(pgp.as_bytes()), SmimeVerification::NotSigned);

    let smime_message = compose(&keys, &draft(SignMethod::Smime)).await.unwrap();
    assert_eq!(
        verify_message(smime_message.as_bytes()),
        SmimeVerification::SignedUntrusted(RSA_ADDRESS.into())
    );
    assert_eq!(
        crate::pgp::verify(smime_message.as_bytes(), &[publica(&key)]),
        PgpVerification::NotSigned
    );

    // El viejo `firmar: true` sin método sigue siendo S/MIME aunque haya PGP.
    let viejo = Draft {
        sign_method: None,
        sign: true,
        ..draft(SignMethod::None)
    };
    let message = compose(&keys, &viejo).await.unwrap();
    assert_eq!(
        verify_message(message.as_bytes()),
        SmimeVerification::SignedUntrusted(RSA_ADDRESS.into())
    );
}
