//! Cifrado saliente con PGP/MIME (`vasak-accounts#21`, PR7): el sobre `multipart/encrypted`
//! de RFC 3156 §4, la elección de claves de destinatario (peerstate → WKD, sólo claves
//! vivas con subclave de cifrado), y el fallar cerrado cuando falta una clave. Usa el seam
//! `encrypt_outgoing_pgp` con un almacén real, un llavero falso y un WKD inyectado.
//!
//! Lo que **no** se ejerce: la validación al encolar con clave faltante por el bus
//! (`send_message` toma el almacén de `live_store()`, un global que sólo fija el arranque
//! del servicio); se cubre por las piezas —`resolve_recipient_encryption_key` acá— y el
//! rechazo de S/MIME y del almacén ausente por el bus.

use crate::compose::{self, Draft, EncryptMethod, SignMethod};
use crate::pgp::tests::{
    clave_completa, clave_vieja, con_primaria_con_vencimiento_en_el_uid, con_primaria_revocada,
    con_subclave_reatada, generar, publica, subclave_de_cifrado, subclave_de_firma, vacia,
};
use crate::pgp::{Decryption, Verification};
use crate::pgp_send_tests::{armored, ACCOUNT, ADDRESS};
use crate::smime_sign::test_support::{DATE, MESSAGE_ID};
use crate::smtp::SmtpError;
use crate::store::key::fake::FakeKeys;
use crate::store::key::tests::fake_keyring;
use crate::store::key::SecretServiceKeys;
use crate::store::lifecycle::StoreManager;
use crate::test_bus::{error_of, Fixture};
use crate::wkd::{WkdError, WkdKey};
use crate::wkd_ipc_tests::{manager, CUENTA};
use pgp::composed::{SignedPublicKey, SignedSecretKey};
use pgp::ser::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const BETO: &str = "beto@vasak.test";
const CARLA: &str = "carla@vasak.test";

fn bytes_of(key: &SignedPublicKey) -> Vec<u8> {
    key.to_bytes().unwrap()
}

fn wkd_key(key: &SignedPublicKey) -> WkdKey {
    WkdKey {
        bytes: bytes_of(key),
        fingerprint: crate::pgp::fingerprint(key),
    }
}

/// Un WKD falso: responde con la clave de `table` para esa dirección (o «no hay») y cuenta
/// las llamadas.
struct FakeWkd {
    table: HashMap<String, SignedPublicKey>,
    calls: Arc<AtomicUsize>,
}

impl FakeWkd {
    fn new(table: &[(&str, &SignedPublicKey)]) -> Self {
        Self {
            table: table
                .iter()
                .map(|(a, k)| (a.to_string(), (*k).clone()))
                .collect(),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn fetch(
        &self,
    ) -> impl Fn(String) -> std::future::Ready<Result<Option<WkdKey>, WkdError>> + '_ {
        move |addr| {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(self.table.get(&addr).map(wkd_key)))
        }
    }
}

fn encrypted_draft(to: &[&str]) -> Draft {
    Draft {
        from: ADDRESS.into(),
        to: to.iter().map(|s| s.to_string()).collect(),
        subject: "Secreto".into(),
        body: "El lince cena a las ocho.".into(),
        encrypt_method: Some(EncryptMethod::Pgp),
        ..Default::default()
    }
}

async fn encrypt(
    m: &StoreManager<FakeKeys>,
    keys: &SecretServiceKeys,
    draft: &Draft,
    wkd: &FakeWkd,
) -> Result<String, SmtpError> {
    crate::encrypt_outgoing_pgp(m, keys, draft, CUENTA, MESSAGE_ID, DATE, wkd.fetch()).await
}

fn permanent(result: Result<String, SmtpError>) -> String {
    match result {
        Err(SmtpError::Permanent(detail)) => detail,
        other => panic!("se esperaba un fallo permanente, salió {other:?}"),
    }
}

fn opened(message: &str, key: &SignedSecretKey) -> String {
    match crate::pgp::decrypt(message.as_bytes(), key, &vacia()) {
        Decryption::Opened(bytes) => String::from_utf8(bytes.to_vec()).unwrap(),
        other => panic!("se esperaba Opened, salió {other:?}"),
    }
}

fn cannot_open(message: &str, key: &SignedSecretKey) -> bool {
    matches!(
        crate::pgp::decrypt(message.as_bytes(), key, &vacia()),
        Decryption::Unavailable(_)
    )
}

async fn store_peer(m: &StoreManager<FakeKeys>, address: &str, key: &SignedPublicKey) {
    let (address, bytes) = (address.to_string(), bytes_of(key));
    m.with_store(CUENTA, move |s| {
        crate::pgp_import::ingest_peer_key(s, &address, &bytes, 1_000).unwrap();
        Ok::<(), crate::store::StoreError>(())
    })
    .await
    .unwrap();
}

async fn store_own_identity(keys: &SecretServiceKeys, key: &SignedSecretKey) {
    keys.store_pgp_identity(CUENTA, &armored(key), b"")
        .await
        .unwrap();
}

// ── 1. Cifra y se descifra ──────────────────────────────────────────────

#[tokio::test]
async fn el_mensaje_sale_como_multipart_encrypted_y_el_destinatario_lo_abre() {
    let (_t, m) = manager("enc-ok").await;
    let (keys, _s, _sh) = fake_keyring().await;
    let beto = clave_completa("Beto <beto@vasak.test>");
    let wkd = FakeWkd::new(&[(BETO, &publica(&beto))]);
    let draft = encrypted_draft(&[BETO]);

    let message = encrypt(&m, &keys, &draft, &wkd).await.unwrap();

    // RFC 3156 §4: control `Version: 1` y sobre `application/octet-stream` con armor.
    let (head, body) = message.split_once("\r\n\r\n").unwrap();
    assert!(
        head.contains("multipart/encrypted; protocol=\"application/pgp-encrypted\""),
        "{head}"
    );
    assert!(
        head.contains("To: "),
        "las cabeceras de dirección quedan a la vista"
    );
    let boundary = head
        .split("boundary=\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .expect("la frontera");
    let parts: Vec<&str> = body.split(format!("--{boundary}").as_str()).collect();
    assert_eq!(parts.len(), 4, "dos partes y el cierre");
    assert!(parts[1].contains("Content-Type: application/pgp-encrypted"));
    assert!(parts[1].trim_end().ends_with("Version: 1"));
    assert!(parts[2].contains("Content-Type: application/octet-stream"));
    assert!(parts[2].contains("-----BEGIN PGP MESSAGE-----"));
    assert!(parts[3].starts_with("--"));

    // El claro no viaja a la vista, y el destinatario lo abre con su clave.
    assert!(!message.contains("lince"));
    assert_eq!(
        opened(&message, &beto),
        compose::build_content_entity(&draft)
    );
}

#[tokio::test]
async fn el_sobre_abre_con_la_clave_de_cada_destinatario_to_y_cc_y_con_ninguna_otra() {
    let (_t, m) = manager("enc-multi").await;
    let (keys, _s, _sh) = fake_keyring().await;
    let beto = clave_completa("Beto <beto@vasak.test>");
    let carla = clave_completa("Carla <carla@vasak.test>");
    let mallory = clave_completa("Mallory <mallory@vasak.test>");
    let wkd = FakeWkd::new(&[(BETO, &publica(&beto)), (CARLA, &publica(&carla))]);
    let draft = Draft {
        cc: vec![CARLA.into()],
        ..encrypted_draft(&[BETO])
    };

    let message = encrypt(&m, &keys, &draft, &wkd).await.unwrap();

    let claro = compose::build_content_entity(&draft);
    assert_eq!(opened(&message, &beto), claro);
    assert_eq!(opened(&message, &carla), claro);
    assert!(cannot_open(&message, &mallory));
}

// ── 2. (SEGURIDAD) falta una clave: error permanente, jamás en claro ────

#[tokio::test]
async fn si_a_un_destinatario_le_falta_la_clave_falla_permanente_nombrandolo_y_no_sale_nada() {
    let (_t, m) = manager("enc-falta").await;
    let (keys, _s, _sh) = fake_keyring().await;
    let beto = clave_completa("Beto <beto@vasak.test>");
    // Carla no está ni en el peerstate ni en WKD.
    let wkd = FakeWkd::new(&[(BETO, &publica(&beto))]);
    let draft = encrypted_draft(&[BETO, CARLA]);

    let result = encrypt(&m, &keys, &draft, &wkd).await;

    match result {
        Err(SmtpError::Permanent(detail)) => {
            assert!(detail.contains(CARLA), "no nombra a quién falta: {detail}");
            assert!(
                !detail.contains(BETO),
                "nombra a quien sí tiene clave: {detail}"
            );
        }
        Ok(message) => panic!("salió un mensaje sin cifrar a todos: {message}"),
        other => panic!("se esperaba un fallo permanente, salió {other:?}"),
    }
}

#[tokio::test]
async fn con_la_clave_solo_de_firma_o_sin_subclave_de_cifrado_no_hay_clave() {
    let (_t, m) = manager("enc-sin-subclave").await;
    let (keys, _s, _sh) = fake_keyring().await;
    let solo_firma = generar("Beto <beto@vasak.test>", vec![subclave_de_firma()]);
    let wkd = FakeWkd::new(&[(BETO, &publica(&solo_firma))]);

    let detail = permanent(encrypt(&m, &keys, &encrypted_draft(&[BETO]), &wkd).await);

    assert!(detail.contains(BETO), "{detail}");
}

// ── 3. También a la propia clave ────────────────────────────────────────

#[tokio::test]
async fn con_identidad_propia_el_sobre_abre_tambien_con_la_clave_de_la_cuenta() {
    let (_t, m) = manager("enc-propia").await;
    let (keys, _s, _sh) = fake_keyring().await;
    let beto = clave_completa("Beto <beto@vasak.test>");
    let ana = clave_completa("Ana <ana@vasak.test>");
    store_own_identity(&keys, &ana).await;
    let wkd = FakeWkd::new(&[(BETO, &publica(&beto))]);
    let draft = encrypted_draft(&[BETO]);

    let message = encrypt(&m, &keys, &draft, &wkd).await.unwrap();

    let claro = compose::build_content_entity(&draft);
    assert_eq!(
        opened(&message, &ana),
        claro,
        "Enviados tiene que ser legible"
    );
    assert_eq!(opened(&message, &beto), claro);
}

#[tokio::test]
async fn sin_identidad_propia_igual_cifra_a_los_destinatarios() {
    let (_t, m) = manager("enc-sin-propia").await;
    let (keys, _s, _sh) = fake_keyring().await;
    let beto = clave_completa("Beto <beto@vasak.test>");
    let wkd = FakeWkd::new(&[(BETO, &publica(&beto))]);
    let draft = encrypted_draft(&[BETO]);

    let message = encrypt(&m, &keys, &draft, &wkd).await.unwrap();

    assert_eq!(
        opened(&message, &beto),
        compose::build_content_entity(&draft)
    );
}

#[tokio::test]
async fn una_identidad_propia_sin_subclave_de_cifrado_no_bloquea_el_envio() {
    let (_t, m) = manager("enc-propia-solo-firma").await;
    let (keys, _s, _sh) = fake_keyring().await;
    let beto = clave_completa("Beto <beto@vasak.test>");
    let ana = generar("Ana <ana@vasak.test>", vec![subclave_de_firma()]);
    store_own_identity(&keys, &ana).await;
    let wkd = FakeWkd::new(&[(BETO, &publica(&beto))]);
    let draft = encrypted_draft(&[BETO]);

    let message = encrypt(&m, &keys, &draft, &wkd).await.unwrap();

    assert_eq!(
        opened(&message, &beto),
        compose::build_content_entity(&draft)
    );
    assert!(cannot_open(&message, &ana));
}

// ── 4. sign-then-encrypt ────────────────────────────────────────────────

#[tokio::test]
async fn firmar_y_cifrar_deja_la_firma_adentro_del_sobre_y_verifica() {
    let (_t, m) = manager("enc-firma").await;
    let (keys, _s, _sh) = fake_keyring().await;
    let beto = clave_completa("Beto <beto@vasak.test>");
    let ana = clave_completa("Ana <ana@vasak.test>");
    store_own_identity(&keys, &ana).await;
    let wkd = FakeWkd::new(&[(BETO, &publica(&beto))]);
    let draft = Draft {
        sign_method: Some(SignMethod::Pgp),
        ..encrypted_draft(&[BETO])
    };

    let message = encrypt(&m, &keys, &draft, &wkd).await.unwrap();

    // Por fuera sólo hay sobre: la firma no se ve.
    assert!(!message.contains("multipart/signed"));
    assert!(!message.contains("BEGIN PGP SIGNATURE"));
    // Adentro, un `multipart/signed` que verifica con la clave de la cuenta.
    let inner = opened(&message, &beto);
    assert!(
        inner.starts_with("Content-Type: multipart/signed"),
        "{inner}"
    );
    assert!(matches!(
        crate::pgp::verify(inner.as_bytes(), &[publica(&ana)]),
        Verification::SignedUntrusted(_)
    ));
    assert!(matches!(
        crate::pgp::verify(inner.as_bytes(), &[publica(&beto)]),
        Verification::Unverified(_)
    ));
}

#[tokio::test]
async fn firmar_y_cifrar_sin_identidad_propia_falla_permanente_y_no_sale_sin_firmar() {
    let (_t, m) = manager("enc-firma-sin-id").await;
    let (keys, _s, _sh) = fake_keyring().await;
    let beto = clave_completa("Beto <beto@vasak.test>");
    let wkd = FakeWkd::new(&[(BETO, &publica(&beto))]);
    let draft = Draft {
        sign_method: Some(SignMethod::Pgp),
        ..encrypted_draft(&[BETO])
    };

    let detail = permanent(encrypt(&m, &keys, &draft, &wkd).await);

    assert!(detail.contains("OpenPGP"), "{detail}");
}

// ── 5. Subclave de cifrado, no la primaria ──────────────────────────────

#[tokio::test]
async fn se_cifra_a_la_subclave_de_cifrado_porque_la_primaria_no_cifra() {
    let (_t, m) = manager("enc-subclave").await;
    let (keys, _s, _sh) = fake_keyring().await;
    // Primaria sólo de certificar (sin cifrado) + subclave de cifrado.
    let beto = generar("Beto <beto@vasak.test>", vec![subclave_de_cifrado(None)]);
    let wkd = FakeWkd::new(&[(BETO, &publica(&beto))]);
    let draft = encrypted_draft(&[BETO]);

    let message = encrypt(&m, &keys, &draft, &wkd).await.unwrap();

    assert_eq!(
        opened(&message, &beto),
        compose::build_content_entity(&draft)
    );
}

// ── 6. (SEGURIDAD) clave muerta del destinatario = sin clave ────────────

fn hace_un_ano() -> pgp::types::Timestamp {
    pgp::types::Timestamp::from_secs(pgp::types::Timestamp::now().as_secs() - 365 * 24 * 3600)
}

/// Claves de Beto muertas de distintas maneras, cada una con su descripción.
fn dead_recipient_keys() -> Vec<(&'static str, SignedPublicKey)> {
    let con_subclave_vieja = generar(
        "Beto <beto@vasak.test>",
        vec![
            subclave_de_firma(),
            subclave_de_cifrado(Some(hace_un_ano())),
        ],
    );
    let vivo = clave_vieja("Beto <beto@vasak.test>");
    vec![
        (
            "subclave de cifrado expirada",
            con_subclave_reatada(&con_subclave_vieja, 1, Some(24 * 3600), false),
        ),
        (
            "subclave de cifrado revocada",
            con_subclave_reatada(&con_subclave_vieja, 1, None, true),
        ),
        ("primaria revocada", con_primaria_revocada(&vivo)),
        (
            "primaria expirada",
            con_primaria_con_vencimiento_en_el_uid(&vivo, 24 * 3600),
        ),
    ]
}

#[tokio::test]
async fn una_clave_muerta_del_destinatario_cuenta_como_sin_clave_y_no_se_cifra_a_ella() {
    for (what, dead) in dead_recipient_keys() {
        let (_t, m) = manager("enc-muerta").await;
        let (keys, _s, _sh) = fake_keyring().await;
        let wkd = FakeWkd::new(&[(BETO, &dead)]);

        let result = encrypt(&m, &keys, &encrypted_draft(&[BETO]), &wkd).await;

        match result {
            Err(SmtpError::Permanent(detail)) => {
                assert!(
                    detail.contains(BETO),
                    "{what}: no nombra al destinatario: {detail}"
                );
            }
            Ok(_) => panic!("{what}: se cifró a una clave muerta"),
            other => panic!("{what}: se esperaba permanente, salió {other:?}"),
        }
    }
}

#[tokio::test]
async fn el_resolvedor_devuelve_la_clave_viva_y_nada_para_la_muerta_o_la_solo_de_firma() {
    let viva = publica(&clave_completa("Beto <beto@vasak.test>"));
    let solo_firma = publica(&generar(
        "Beto <beto@vasak.test>",
        vec![subclave_de_firma()],
    ));
    let mut casos = dead_recipient_keys();
    casos.push(("solo de firma", solo_firma));
    casos.push(("viva", viva));

    for (what, key) in casos {
        let (_t, m) = manager("enc-resolvedor").await;
        let wkd = FakeWkd::new(&[(BETO, &key)]);

        let found = crate::resolve_recipient_encryption_key(&m, CUENTA, BETO, wkd.fetch())
            .await
            .unwrap();

        assert_eq!(found.is_some(), what == "viva", "{what}");
    }
}

#[tokio::test]
async fn una_clave_muerta_ya_guardada_en_el_peerstate_tampoco_se_usa_ni_se_reemplaza_por_wkd() {
    let vivo = clave_vieja("Beto <beto@vasak.test>");
    let muerta = con_primaria_revocada(&vivo);
    let (_t, m) = manager("enc-muerta-peer").await;
    let (keys, _s, _sh) = fake_keyring().await;
    store_peer(&m, BETO, &muerta).await;
    // WKD tendría una clave viva, pero el peerstate manda.
    let wkd = FakeWkd::new(&[(BETO, &publica(&vivo))]);

    let result = encrypt(&m, &keys, &encrypted_draft(&[BETO]), &wkd).await;

    assert!(matches!(result, Err(SmtpError::Permanent(_))), "{result:?}");
    assert_eq!(wkd.calls(), 0);
}

// ── 7. peerstate manda sobre WKD ────────────────────────────────────────

#[tokio::test]
async fn el_peerstate_manda_sobre_wkd_y_no_se_sale_a_la_red() {
    let (_t, m) = manager("enc-peer").await;
    let (keys, _s, _sh) = fake_keyring().await;
    let beto = clave_completa("Beto <beto@vasak.test>");
    let otra = clave_completa("Beto <beto@vasak.test>");
    store_peer(&m, BETO, &publica(&beto)).await;
    let wkd = FakeWkd::new(&[(BETO, &publica(&otra))]);
    let draft = encrypted_draft(&[BETO]);

    let message = encrypt(&m, &keys, &draft, &wkd).await.unwrap();

    assert_eq!(wkd.calls(), 0, "con peerstate no se consulta WKD");
    assert_eq!(
        opened(&message, &beto),
        compose::build_content_entity(&draft)
    );
    assert!(cannot_open(&message, &otra), "se cifró a la clave de WKD");
}

#[tokio::test]
async fn un_acierto_de_wkd_se_guarda_y_el_segundo_envio_ya_no_sale_a_la_red() {
    let (_t, m) = manager("enc-wkd-guarda").await;
    let (keys, _s, _sh) = fake_keyring().await;
    let beto = clave_completa("Beto <beto@vasak.test>");
    let wkd = FakeWkd::new(&[(BETO, &publica(&beto))]);
    let draft = encrypted_draft(&[BETO]);

    encrypt(&m, &keys, &draft, &wkd).await.unwrap();
    assert_eq!(wkd.calls(), 1);
    let peer = m
        .with_store(CUENTA, |s| s.find_peer(BETO))
        .await
        .unwrap()
        .expect("la clave de WKD quedó en el peerstate");
    assert_eq!(peer.fingerprint, crate::pgp::fingerprint(&publica(&beto)));

    encrypt(&m, &keys, &draft, &wkd).await.unwrap();
    assert_eq!(wkd.calls(), 1, "la segunda vez lo ve como peerstate");
}

#[tokio::test]
async fn un_fallo_de_wkd_es_sin_clave_y_no_cifra() {
    let (_t, m) = manager("enc-wkd-error").await;
    let (keys, _s, _sh) = fake_keyring().await;
    let draft = encrypted_draft(&[BETO]);
    let failing =
        |_: String| std::future::ready(Err::<Option<WkdKey>, _>(WkdError::Network("caído".into())));

    let result =
        crate::encrypt_outgoing_pgp(&m, &keys, &draft, CUENTA, MESSAGE_ID, DATE, failing).await;

    let detail = permanent(result);
    assert!(detail.contains(BETO), "{detail}");
    assert!(!detail.contains("caído"), "no se filtra el motivo de red");
}

#[tokio::test]
async fn una_cuenta_sin_almacen_falla_temporal_y_no_sale_en_claro() {
    let (_t, m) = manager("enc-sin-almacen").await;
    let (keys, _s, _sh) = fake_keyring().await;
    let wkd = FakeWkd::new(&[]);
    let draft = encrypted_draft(&[BETO]);

    let result = crate::encrypt_outgoing_pgp(
        &m,
        &keys,
        &draft,
        "no-existe",
        MESSAGE_ID,
        DATE,
        wkd.fetch(),
    )
    .await;

    assert!(matches!(result, Err(SmtpError::Temporary(_))), "{result:?}");
    assert_eq!(wkd.calls(), 0);
}

// ── 8a. Validación al encolar: la primera dirección sin clave ───────────

async fn missing_key(
    m: &StoreManager<FakeKeys>,
    recipients: &[&str],
    wkd: &FakeWkd,
) -> Option<String> {
    let recipients: Vec<String> = recipients.iter().map(|s| s.to_string()).collect();
    // Captura sólo referencias: es `Copy`, como pide `first_recipient_without_key`.
    let fetch = |addr: String| {
        wkd.calls.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(wkd.table.get(&addr).map(wkd_key)))
    };
    crate::first_recipient_without_key(m, CUENTA, &recipients, fetch)
        .await
        .unwrap()
}

#[tokio::test]
async fn si_todos_tienen_clave_en_el_peerstate_nadie_falta() {
    let (_t, m) = manager("enc-encolar-todos").await;
    store_peer(
        &m,
        BETO,
        &publica(&clave_completa("Beto <beto@vasak.test>")),
    )
    .await;
    store_peer(
        &m,
        CARLA,
        &publica(&clave_completa("Carla <carla@vasak.test>")),
    )
    .await;
    let wkd = FakeWkd::new(&[]);

    assert_eq!(missing_key(&m, &[BETO, CARLA], &wkd).await, None);
    assert_eq!(wkd.calls(), 0);
}

#[tokio::test]
async fn si_a_uno_le_falta_la_clave_devuelve_la_direccion_de_ese_y_no_la_del_que_tiene() {
    let (_t, m) = manager("enc-encolar-falta").await;
    store_peer(
        &m,
        BETO,
        &publica(&clave_completa("Beto <beto@vasak.test>")),
    )
    .await;
    let wkd = FakeWkd::new(&[]);

    assert_eq!(
        missing_key(&m, &[BETO, CARLA], &wkd).await.as_deref(),
        Some(CARLA)
    );
    // El orden no cambia quién falta.
    assert_eq!(
        missing_key(&m, &[CARLA, BETO], &wkd).await.as_deref(),
        Some(CARLA)
    );
}

#[tokio::test]
async fn una_clave_muerta_en_el_peerstate_cuenta_como_faltante_al_encolar() {
    let (_t, m) = manager("enc-encolar-muerta").await;
    let vivo = clave_vieja("Beto <beto@vasak.test>");
    store_peer(&m, BETO, &con_primaria_revocada(&vivo)).await;
    let wkd = FakeWkd::new(&[]);

    assert_eq!(missing_key(&m, &[BETO], &wkd).await.as_deref(), Some(BETO));
}

#[tokio::test]
async fn sin_destinatarios_nadie_falta_y_un_acierto_de_wkd_cuenta_como_tener_clave() {
    let (_t, m) = manager("enc-encolar-wkd").await;
    let beto = publica(&clave_completa("Beto <beto@vasak.test>"));
    let wkd = FakeWkd::new(&[(BETO, &beto)]);

    assert_eq!(missing_key(&m, &[], &wkd).await, None);
    assert_eq!(missing_key(&m, &[BETO], &wkd).await, None);
    assert_eq!(wkd.calls(), 1);
}

#[tokio::test]
async fn un_almacen_ausente_al_encolar_es_error_y_no_pasa_por_alto() {
    let (_t, m) = manager("enc-encolar-sin-almacen").await;
    let wkd = FakeWkd::new(&[]);
    let recipients = vec![BETO.to_string()];
    let fetch = |addr: String| std::future::ready(Ok(wkd.table.get(&addr).map(wkd_key)));

    let result = crate::first_recipient_without_key(&m, "no-existe", &recipients, fetch).await;

    assert!(result.is_err());
}

// ── 8. Validación al encolar, por el bus ────────────────────────────────

const ACCOUNT_ID: &str = ACCOUNT;

async fn send_with(f: &Fixture, method: &str) -> zbus::Result<zbus::Message> {
    let draft = serde_json::json!({
        "para": ["dest@otro.test"], "asunto": "Hola", "cuerpo": "x",
        "metodo_cifrado": method,
    });
    f.call("SendMessage", &(ACCOUNT_ID, draft.to_string(), ""))
        .await
}

async fn outbox_len(f: &Fixture) -> usize {
    let reply: String = f
        .call("ListOutbox", &())
        .await
        .unwrap()
        .body()
        .deserialize()
        .unwrap();
    serde_json::from_str::<serde_json::Value>(&reply)
        .unwrap()
        .as_array()
        .unwrap()
        .len()
}

#[tokio::test]
async fn cifrar_con_smime_se_rechaza_al_encolar_con_invalidargs_no_disponible() {
    let f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;

    let (name, text) = error_of(send_with(&f, "smime").await);

    assert_eq!(name, "org.freedesktop.DBus.Error.InvalidArgs");
    assert!(text.contains("no está disponible"), "{text}");
    assert_eq!(outbox_len(&f).await, 0);
}

#[tokio::test]
async fn cifrar_con_pgp_sin_almacen_vivo_no_encola_nada() {
    // Falla cerrado: sin poder comprobar las claves, no se encola un mensaje que luego
    // no podría cifrarse.
    assert!(crate::store_api::live_store().is_none());
    let f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;

    let (name, _) = error_of(send_with(&f, "pgp").await);

    assert_eq!(name, "org.freedesktop.DBus.Error.Failed");
    assert_eq!(outbox_len(&f).await, 0);
}

#[tokio::test]
async fn sin_pedir_cifrado_se_encola_como_siempre() {
    let f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;

    send_with(&f, "none").await.unwrap();

    assert_eq!(outbox_len(&f).await, 1);
}

#[tokio::test]
async fn el_despachador_rechaza_el_cifrado_smime_permanente_sin_mandar_nada() {
    let (keys, _s, _sh) = fake_keyring().await;
    let draft = Draft {
        encrypt_method: Some(EncryptMethod::Smime),
        ..encrypted_draft(&[BETO])
    };

    let result = crate::compose_outgoing(&keys, &draft, CUENTA, MESSAGE_ID, DATE).await;

    assert!(
        permanent(result).contains("no está disponible"),
        "falta el motivo"
    );
}

// ── 9. Retrocompatibilidad de serde ─────────────────────────────────────

#[test]
fn un_borrador_sin_metodo_cifrado_no_cifra_y_el_vacio_no_lo_serializa() {
    let viejo: Draft = serde_json::from_str(r#"{"para": []}"#).unwrap();
    assert_eq!(viejo.encrypt_method, None);
    assert_eq!(viejo.effective_encrypt_method(), EncryptMethod::None);

    let json = serde_json::to_value(Draft::default()).unwrap();
    assert!(json.get("metodo_cifrado").is_none(), "{json}");
}

#[test]
fn el_metodo_de_cifrado_explicito_se_lee_y_se_serializa() {
    for (text, method) in [
        ("pgp", EncryptMethod::Pgp),
        ("smime", EncryptMethod::Smime),
        ("none", EncryptMethod::None),
    ] {
        let draft: Draft =
            serde_json::from_str(&format!(r#"{{"para": [], "metodo_cifrado": "{text}"}}"#))
                .unwrap();
        assert_eq!(draft.effective_encrypt_method(), method);
    }
    let json = serde_json::to_value(encrypted_draft(&[BETO])).unwrap();
    assert_eq!(json["metodo_cifrado"], "pgp");
}

// ── 10. Forma del sobre y de `signed_entity` ────────────────────────────

#[test]
fn build_encrypted_message_arma_el_sobre_de_rfc_3156_byte_a_byte() {
    let headers = vec!["From: a@b.test".to_string(), "To: c@d.test".to_string()];
    let armor = "-----BEGIN PGP MESSAGE-----\r\n\r\nAAAA\r\n-----END PGP MESSAGE-----";

    let message = crate::pgp_encrypt::build_encrypted_message(&headers, armor);

    let boundary = crate::compose::boundary(&["Version: 1", armor]);
    let expected = format!(
        "From: a@b.test\r\nTo: c@d.test\r\n\
Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{boundary}\"\r\n\r\n\
--{boundary}\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\
--{boundary}\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\n\
Content-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n{armor}\r\n--{boundary}--\r\n"
    );
    assert_eq!(message, expected);
}

#[test]
fn la_frontera_del_sobre_no_aparece_en_el_armor() {
    let armor = "=_vasak_0000000000000000 y mas";
    let boundary = crate::compose::boundary(&["Version: 1", armor]);
    assert!(!armor.contains(&boundary));
    let message = crate::pgp_encrypt::build_encrypted_message(&[], armor);
    assert!(message.contains(&format!("boundary=\"{boundary}\"")));
}

#[test]
fn signed_entity_es_el_mensaje_firmado_sin_cabeceras_de_direccion() {
    let content = "Content-Type: text/plain; charset=utf-8\r\n\r\nhola";
    let signature = "-----BEGIN PGP SIGNATURE-----\r\n\r\nAAAA\r\n-----END PGP SIGNATURE-----";
    let headers = vec!["From: a@b.test".to_string()];

    let entity = crate::pgp_sign::signed_entity(content, signature);
    let message = crate::pgp_sign::build_signed_message(&headers, content, signature);

    assert!(entity.starts_with("Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=\"pgp-sha256\"; boundary=\""));
    assert_eq!(message, format!("From: a@b.test\r\n{entity}"));
    assert!(entity.contains(content) && entity.contains(signature));
    assert!(entity.ends_with("--\r\n"));
}
