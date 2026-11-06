//! `ResolveRecipientKey` (`vasak-accounts#21`, PR6): la puerta de permisos y las
//! respuestas de error por D-Bus, de punta a punta (calca `pgp_ipc_tests`), y la
//! lógica pura que arma el estado de clave (`pgp_key_state`, `resolve_key_json`).
//!
//! Lo que **no** se ejerce por el bus: las ramas peerstate y WKD del método. El
//! almacén lo da `store_api::live_store()`, un global que sólo fija el arranque del
//! servicio, y el cliente WKD resuelve DNS y conecta por HTTPS (a loopback lo veta, a
//! propósito). Esas ramas se cubren por sus piezas: el estado y el JSON acá, el
//! peerstate con un almacén real, y el veto de red en `wkd::tests`.

use crate::access::tests::Answer;
use crate::ipc_test_support::short_name;
use crate::pgp::tests::{
    clave_completa, clave_vieja, con_primaria_con_vencimiento_en_el_uid, con_primaria_revocada,
    con_subclave_reatada, generar, publica, subclave_de_cifrado, subclave_de_firma,
};
use crate::pgp_send_tests::{ACCOUNT, ADDRESS};
use crate::store::key::fake::FakeKeys;
use crate::store::lifecycle::{AccountListing, ListedAccount, Locations, StoreManager, EMAIL_AREA};
use crate::store::paths::tests::TempDir;
use crate::test_bus::{error_of, Fixture};
use crate::wkd::{WkdError, WkdKey};
use crate::{pgp_key_state, resolve_key_json, resolve_key_with, PgpKeyState};
use pgp::ser::Serialize;

const DESTINATARIO: &str = "beto@vasak.test";

async fn resolve(f: &Fixture, address: &str) -> zbus::Result<zbus::Message> {
    f.call("ResolveRecipientKey", &(ACCOUNT, address)).await
}

fn bytes_of(key: &pgp::composed::SignedPublicKey) -> Vec<u8> {
    key.to_bytes().unwrap()
}

fn json(source: &str, state: PgpKeyState) -> serde_json::Value {
    serde_json::from_str(&resolve_key_json(source, state).unwrap()).unwrap()
}

// ── La puerta de permisos ───────────────────────────────────────────────

#[tokio::test]
async fn resolver_sin_permiso_da_accessdenied() {
    let f = Fixture::start_with_permission(&[(ACCOUNT, ADDRESS)], Answer::Deny).await;
    assert_eq!(short_name(resolve(&f, DESTINATARIO).await), "AccessDenied");
}

#[tokio::test]
async fn resolver_con_el_servicio_de_permisos_caido_da_accessdenied() {
    // Falla cerrado: no poder preguntar es no tener permiso.
    let f = Fixture::start_with_permission(&[(ACCOUNT, ADDRESS)], Answer::Fail).await;
    assert_eq!(short_name(resolve(&f, DESTINATARIO).await), "AccessDenied");
}

#[tokio::test]
async fn sin_permiso_no_se_llega_ni_a_validar_la_direccion() {
    // Una dirección vacía con permiso da `Failed`; sin permiso tiene que dar
    // `AccessDenied`: la puerta va antes que cualquier otra comprobación (y que la red).
    let f = Fixture::start_with_permission(&[(ACCOUNT, ADDRESS)], Answer::Deny).await;
    assert_eq!(short_name(resolve(&f, "   ").await), "AccessDenied");
}

// ── Lo que pasa con permiso ─────────────────────────────────────────────

#[tokio::test]
async fn una_direccion_vacia_tras_normalizar_da_failed() {
    let f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;
    let (name, text) = error_of(resolve(&f, "   ").await);
    assert_eq!(name.rsplit('.').next().unwrap(), "Failed");
    assert!(text.contains("vacía"), "{text}");
}

#[tokio::test]
async fn sin_almacen_vivo_da_failed_y_no_toca_la_red() {
    // En las pruebas `live_store()` es `None` (lo fija sólo el arranque).
    assert!(crate::store_api::live_store().is_none());
    let f = Fixture::start(&[(ACCOUNT, ADDRESS)]).await;
    let (name, text) = error_of(resolve(&f, DESTINATARIO).await);
    assert_eq!(name.rsplit('.').next().unwrap(), "Failed");
    assert!(text.contains("almacén"), "{text}");
}

// ── El estado de la clave ───────────────────────────────────────────────

#[test]
fn una_clave_con_subclave_de_cifrado_viva_esta_presente() {
    let secret = clave_completa("Beto <beto@vasak.test>");
    let key = publica(&secret);
    let state = pgp_key_state(&bytes_of(&key));
    assert!(state.present);
    assert!(!state.expired && !state.revoked);
    assert_eq!(
        state.fingerprint.as_deref(),
        Some(crate::pgp::fingerprint(&key).as_str())
    );
}

#[test]
fn una_clave_solo_de_firma_existe_pero_no_esta_presente() {
    let secret = generar("Beto <beto@vasak.test>", vec![subclave_de_firma()]);
    let key = publica(&secret);
    let state = pgp_key_state(&bytes_of(&key));
    assert!(!state.present, "no hay a qué cifrar");
    assert!(state.fingerprint.is_some());
    assert!(!state.expired && !state.revoked);
}

#[test]
fn una_clave_guardada_que_hoy_esta_expirada_no_esta_presente_y_dice_expired() {
    let vivo = clave_vieja("Beto <beto@vasak.test>");
    let key = con_primaria_con_vencimiento_en_el_uid(&vivo, 24 * 3600);
    let state = pgp_key_state(&bytes_of(&key));
    assert!(!state.present);
    assert!(state.expired);
    assert!(!state.revoked);
    assert!(state.fingerprint.is_some());
}

#[test]
fn una_clave_revocada_no_esta_presente_y_dice_revoked() {
    let vivo = clave_vieja("Beto <beto@vasak.test>");
    let key = con_primaria_revocada(&vivo);
    let state = pgp_key_state(&bytes_of(&key));
    assert!(!state.present);
    assert!(state.revoked);
    assert!(!state.expired, "revocada manda sobre expirada");
}

#[test]
fn bytes_que_no_son_una_clave_dan_sin_clave_sin_filtrar_el_motivo() {
    let state = pgp_key_state(b"esto no es una clave");
    assert!(!state.present && !state.expired && !state.revoked);
    assert!(state.fingerprint.is_none());
}

// ── El JSON ─────────────────────────────────────────────────────────────

#[test]
fn el_json_lleva_exactamente_los_cinco_campos_de_la_interfaz() {
    let v = json(
        "peerstate",
        PgpKeyState {
            present: true,
            fingerprint: Some("ABCD".into()),
            expired: false,
            revoked: false,
        },
    );
    let mut campos: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
    campos.sort();
    assert_eq!(
        campos,
        ["expired", "fingerprint", "present", "revoked", "source"]
    );
    assert_eq!(v["source"], "peerstate");
    assert_eq!(v["present"], true);
    assert_eq!(v["fingerprint"], "ABCD");
}

#[test]
fn sin_huella_la_fuente_se_degrada_a_none_y_la_huella_es_null() {
    // No decir «peerstate» o «wkd» cuando no hay clave que mostrar.
    for fuente in ["peerstate", "wkd", "none"] {
        let v = json(fuente, PgpKeyState::absent());
        assert_eq!(v["source"], "none", "{fuente}");
        assert_eq!(v["present"], false);
        assert!(v["fingerprint"].is_null());
        assert_eq!(v["expired"], false);
        assert_eq!(v["revoked"], false);
    }
}

#[test]
fn una_clave_muerta_conserva_la_fuente_y_la_huella() {
    let v = json(
        "peerstate",
        PgpKeyState {
            present: false,
            fingerprint: Some("ABCD".into()),
            expired: true,
            revoked: false,
        },
    );
    assert_eq!(v["source"], "peerstate");
    assert_eq!(v["present"], false);
    assert_eq!(v["expired"], true);
}

// ── Peerstate real: lo que guarda WKD lo ve la 2ª llamada como peerstate ─

#[test]
fn la_clave_guardada_por_wkd_se_relee_del_peerstate_con_la_misma_huella() {
    use crate::store::contacts::tests::open_store;
    use crate::store::paths::tests::TempDir;

    let temp = TempDir::new("wkd-peerstate");
    let store = open_store(&temp);
    let key = publica(&clave_completa("Beto <beto@vasak.test>"));
    let bytes = bytes_of(&key);

    // Lo mismo que hace el método tras un acierto de WKD.
    crate::pgp_import::ingest_peer_key(&store, DESTINATARIO, &bytes, 1_000).unwrap();

    let peer = store
        .find_peer(DESTINATARIO)
        .unwrap()
        .expect("quedó guardada");
    let v = json("peerstate", pgp_key_state(&peer.public_key));
    assert_eq!(v["source"], "peerstate");
    assert_eq!(v["present"], true);
    assert_eq!(v["fingerprint"], crate::pgp::fingerprint(&key));
}

// ── La cadena peerstate → WKD con un almacén real y un WKD falso ────────

pub(crate) const CUENTA: &str = "cuenta";

/// Un administrador de almacenes de verdad (llavero falso, disco temporal) con la base
/// de `CUENTA` abierta.
pub(crate) async fn manager(label: &str) -> (TempDir, StoreManager<FakeKeys>) {
    let temp = TempDir::new(label);
    let manager = StoreManager::new(
        FakeKeys::default(),
        Ok(Locations {
            stores: temp.0.join("stores"),
            settings: temp.0.join("stores.json"),
        }),
    );
    let account = ListedAccount {
        id: CUENTA.into(),
        display_name: "Cuenta".into(),
        capabilities: vec!["email".into()],
        needs_reauth: false,
    };
    manager
        .accounts_listed(
            AccountListing::Listed(vec![account]),
            std::time::Instant::now(),
        )
        .await;
    assert!(manager.prepare_for_sync(EMAIL_AREA, CUENTA).await);
    (temp, manager)
}

fn wkd_key(key: &pgp::composed::SignedPublicKey) -> WkdKey {
    WkdKey {
        bytes: bytes_of(key),
        fingerprint: crate::pgp::fingerprint(key),
    }
}

/// Un cliente WKD falso que cuenta cuántas veces lo llamaron.
fn fake_wkd(
    result: Result<Option<WkdKey>, WkdError>,
    calls: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> impl FnOnce(String) -> std::future::Ready<Result<Option<WkdKey>, WkdError>> {
    let calls = calls.clone();
    move |_| {
        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::future::ready(result)
    }
}

fn calls() -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
    std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0))
}

fn n(c: &std::sync::Arc<std::sync::atomic::AtomicUsize>) -> usize {
    c.load(std::sync::atomic::Ordering::SeqCst)
}

#[tokio::test]
async fn un_acierto_de_peerstate_no_consulta_wkd() {
    let (_t, m) = manager("wkd-chain-hit").await;
    let key = publica(&clave_completa("Beto <beto@vasak.test>"));
    let bytes = bytes_of(&key);
    m.with_store(CUENTA, move |s| {
        crate::pgp_import::ingest_peer_key(s, DESTINATARIO, &bytes, 1_000).unwrap();
        Ok::<(), crate::store::StoreError>(())
    })
    .await
    .unwrap();

    let c = calls();
    let (source, state) = resolve_key_with(&m, CUENTA, DESTINATARIO, fake_wkd(Ok(None), &c))
        .await
        .unwrap();
    assert_eq!(source, "peerstate");
    assert!(state.present);
    assert_eq!(state.fingerprint, Some(crate::pgp::fingerprint(&key)));
    assert_eq!(n(&c), 0, "no se va a la red si el peerstate ya la tiene");
}

#[tokio::test]
async fn una_clave_guardada_hoy_expirada_se_informa_expirada_desde_el_peerstate() {
    let (_t, m) = manager("wkd-chain-expired").await;
    let vivo = clave_vieja("Beto <beto@vasak.test>");
    let bytes = bytes_of(&con_primaria_con_vencimiento_en_el_uid(&vivo, 24 * 3600));
    m.with_store(CUENTA, move |s| {
        crate::pgp_import::ingest_peer_key(s, DESTINATARIO, &bytes, 1_000).unwrap();
        Ok::<(), crate::store::StoreError>(())
    })
    .await
    .unwrap();

    let c = calls();
    let (source, state) = resolve_key_with(&m, CUENTA, DESTINATARIO, fake_wkd(Ok(None), &c))
        .await
        .unwrap();
    assert_eq!(source, "peerstate");
    assert!(!state.present && state.expired && !state.revoked);
    assert_eq!(n(&c), 0);
}

#[tokio::test]
async fn un_acierto_de_wkd_se_guarda_y_la_segunda_llamada_lo_ve_como_peerstate() {
    let (_t, m) = manager("wkd-chain-upsert").await;
    let key = publica(&clave_completa("Beto <beto@vasak.test>"));
    let huella = crate::pgp::fingerprint(&key);

    let c = calls();
    let (source, state) = resolve_key_with(
        &m,
        CUENTA,
        DESTINATARIO,
        fake_wkd(Ok(Some(wkd_key(&key))), &c),
    )
    .await
    .unwrap();
    assert_eq!(source, "wkd");
    assert!(state.present && !state.expired && !state.revoked);
    assert_eq!(state.fingerprint.as_deref(), Some(huella.as_str()));
    assert_eq!(n(&c), 1);

    // Quedó upserteada en el peerstate, con la misma huella...
    let peer = m
        .with_store(CUENTA, |s| s.find_peer(DESTINATARIO))
        .await
        .unwrap()
        .expect("la clave de WKD quedó guardada");
    assert_eq!(peer.fingerprint, huella);

    // ...y la segunda llamada ya no sale a la red.
    let c2 = calls();
    let (source, state) = resolve_key_with(&m, CUENTA, DESTINATARIO, fake_wkd(Ok(None), &c2))
        .await
        .unwrap();
    assert_eq!(source, "peerstate");
    assert_eq!(state.fingerprint.as_deref(), Some(huella.as_str()));
    assert_eq!(n(&c2), 0);
}

#[tokio::test]
async fn sin_clave_en_wkd_la_fuente_es_none_y_no_se_guarda_nada() {
    let (_t, m) = manager("wkd-chain-none").await;
    let c = calls();
    let (source, state) = resolve_key_with(&m, CUENTA, DESTINATARIO, fake_wkd(Ok(None), &c))
        .await
        .unwrap();
    assert_eq!(source, "none");
    assert!(!state.present && state.fingerprint.is_none());
    assert_eq!(n(&c), 1);
    let peer = m
        .with_store(CUENTA, |s| s.find_peer(DESTINATARIO))
        .await
        .unwrap();
    assert!(peer.is_none());
}

#[tokio::test]
async fn un_fallo_de_wkd_es_none_sin_filtrar_el_motivo() {
    for error in [
        WkdError::Blocked,
        WkdError::Network("detalle-secreto-de-red".into()),
        WkdError::TooLarge,
        WkdError::BadAddress,
    ] {
        let (_t, m) = manager("wkd-chain-error").await;
        let c = calls();
        let (source, state) = resolve_key_with(&m, CUENTA, DESTINATARIO, fake_wkd(Err(error), &c))
            .await
            .unwrap();
        // Lo único que ve la ventana es el JSON: sin motivo, sin huella.
        let v: serde_json::Value =
            serde_json::from_str(&resolve_key_json(source, state).unwrap()).unwrap();
        assert_eq!(v["source"], "none");
        assert_eq!(v["present"], false);
        assert!(v["fingerprint"].is_null());
        assert!(!v.to_string().contains("secreto"));
        assert!(m
            .with_store(CUENTA, |s| s.find_peer(DESTINATARIO))
            .await
            .unwrap()
            .is_none());
    }
}

#[tokio::test]
async fn una_cuenta_sin_almacen_da_failed_y_no_consulta_wkd() {
    let (_t, m) = manager("wkd-chain-sin-almacen").await;
    let c = calls();
    let r = resolve_key_with(&m, "no-existe", DESTINATARIO, fake_wkd(Ok(None), &c)).await;
    assert!(matches!(r, Err(crate::SmimeIpcError::Failed(_))));
    assert_eq!(n(&c), 0);
}

// ── El estado del camino de cifrado: subclave muerta con la primaria viva ─

#[test]
fn una_subclave_de_cifrado_vencida_con_la_primaria_viva_dice_expired() {
    let hace_un_ano =
        pgp::types::Timestamp::from_secs(pgp::types::Timestamp::now().as_secs() - 365 * 24 * 3600);
    let bob = generar(
        "Bob <bob@vasak.test>",
        vec![subclave_de_firma(), subclave_de_cifrado(Some(hace_un_ano))],
    );
    let vencida = con_subclave_reatada(&bob, 1, Some(24 * 3600), false);
    let state = pgp_key_state(&bytes_of(&vencida));
    assert!(!state.present);
    assert!(state.expired, "venció la subclave de cifrado");
    assert!(!state.revoked);
    assert!(state.fingerprint.is_some());
}

#[test]
fn una_subclave_de_cifrado_revocada_con_la_primaria_viva_dice_revoked() {
    let bob = clave_completa("Bob <bob@vasak.test>");
    let revocada = con_subclave_reatada(&bob, 1, None, true);
    let state = pgp_key_state(&bytes_of(&revocada));
    assert!(!state.present);
    assert!(state.revoked, "se revocó la subclave de cifrado");
    assert!(!state.expired);
}

#[test]
fn una_subclave_de_firma_muerta_no_se_reporta_como_motivo_del_cifrado() {
    // Sólo la subclave de firma está revocada; la de cifrado sirve.
    let bob = clave_completa("Bob <bob@vasak.test>");
    let key = con_subclave_reatada(&bob, 0, None, true);
    let state = pgp_key_state(&bytes_of(&key));
    assert!(state.present);
    assert!(!state.revoked && !state.expired);
}

// ── Casing y huella retenida en la cadena ───────────────────────────────

#[tokio::test]
async fn a_wkd_se_le_pasa_la_direccion_original_y_el_peerstate_usa_la_normalizada() {
    let (_t, m) = manager("wkd-chain-casing").await;
    let key = publica(&clave_completa("Beto <beto@vasak.test>"));
    let original = "Beto.Doe@Vasak.Test";
    let recibida = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    let captura = recibida.clone();

    let (source, _) = resolve_key_with(&m, CUENTA, original, move |addr| {
        *captura.lock().unwrap() = Some(addr);
        std::future::ready(Ok(Some(wkd_key(&key))))
    })
    .await
    .unwrap();

    assert_eq!(source, "wkd");
    assert_eq!(recibida.lock().unwrap().as_deref(), Some(original));
    // El peerstate se llaveó por la dirección normalizada.
    let normalizada = "beto.doe@vasak.test";
    assert!(m
        .with_store(CUENTA, move |s| s.find_peer(normalizada))
        .await
        .unwrap()
        .is_some());
    // Y otra grafía de la misma dirección ya lo ve como peerstate.
    let c = calls();
    let (source, _) = resolve_key_with(&m, CUENTA, "BETO.DOE@vasak.test", fake_wkd(Ok(None), &c))
        .await
        .unwrap();
    assert_eq!(source, "peerstate");
    assert_eq!(n(&c), 0);
}

#[tokio::test]
async fn si_otra_clave_se_guardo_entre_el_miss_y_el_upsert_se_informa_la_retenida() {
    let (_t, m) = manager("wkd-chain-retenida").await;
    let de_wkd = publica(&clave_completa("Beto <beto@vasak.test>"));
    let retenida = publica(&clave_completa("Beto <beto@vasak.test>"));
    assert_ne!(
        crate::pgp::fingerprint(&de_wkd),
        crate::pgp::fingerprint(&retenida)
    );
    let retenida_bytes = bytes_of(&retenida);

    // La carrera: mientras WKD responde, un sync concurrente guarda OTRA clave.
    let (source, state) = resolve_key_with(&m, CUENTA, DESTINATARIO, |_| async {
        m.with_store(CUENTA, move |s| {
            crate::pgp_import::ingest_peer_key(s, DESTINATARIO, &retenida_bytes, 1_000).unwrap();
            Ok::<(), crate::store::StoreError>(())
        })
        .await
        .unwrap();
        Ok(Some(wkd_key(&de_wkd)))
    })
    .await
    .unwrap();

    assert_eq!(source, "peerstate", "TOFU conservó la otra");
    assert_eq!(
        state.fingerprint,
        Some(crate::pgp::fingerprint(&retenida)),
        "se informa la huella retenida, no la de WKD"
    );
    let peer = m
        .with_store(CUENTA, |s| s.find_peer(DESTINATARIO))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(peer.fingerprint, crate::pgp::fingerprint(&retenida));
}
